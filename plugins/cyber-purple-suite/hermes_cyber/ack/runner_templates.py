"""Supervisor runner and isolated TARGET loopback server source templates for ACK confinement."""

from __future__ import annotations

_CONFINED_RUNNER_SOURCE = '''\
"""Control-plane supervisor executing untrusted Red/Blue/Target artifacts with audit-hook FS/Net/Proc confinement."""

import json
import os
import runpy
import sys
from pathlib import Path

_POLICY = json.loads(os.environ.pop("ACK_CONFINE_POLICY", "{}"))
_ACTOR = str(_POLICY["actor"])
_UPPERDIR = Path(_POLICY["upperdir"]).resolve()
_RED_WRITABLE_UPPER_SUBDIR = (_UPPERDIR / "uploads").resolve()
_CANARY_VAULT = Path(_POLICY["canary_vault"]).resolve()
_ACTOR_ARTIFACTS = Path(_POLICY["actor_artifacts"]).resolve()
_BLUE_EXTRA_READ = Path(_POLICY["blue_extra_read"]).resolve() if _POLICY.get("blue_extra_read") else None
_NET_MODE = str(_POLICY.get("network_mode", "isolated_veth"))
_MAX_PROCS = max(1, int(_POLICY.get("max_procs", 1)))
_BLOCKED_PROC_EVENTS = frozenset({
    "os.system",
    "subprocess.Popen",
    "os.spawn",
    "os.fork",
    "os.posix_spawn",
    "ctypes.dlopen",
    "ctypes.dlsym",
})
_PY_ROOTS = [
    Path(p).resolve()
    for p in (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        getattr(sys, "base_exec_prefix", sys.exec_prefix),
        Path(os.__file__).resolve().parent,
        *(_POLICY.get("extra_py_roots") or []),
    )
    if p
]
_WRITE_FLAGS = (
    getattr(os, "O_WRONLY", 1)
    | getattr(os, "O_RDWR", 2)
    | getattr(os, "O_APPEND", 8)
    | getattr(os, "O_CREAT", 256)
    | getattr(os, "O_TRUNC", 512)
)
_STATE = {"active": False}


def _resolve_fs_path(raw):
    if raw is None or isinstance(raw, int):
        return None
    try:
        s = os.fsdecode(raw) if isinstance(raw, (bytes, bytearray)) else str(os.fspath(raw))
    except Exception:
        s = str(raw)
    if not s or s in ("nul", "/dev/null"):
        return None
    p = Path(s)
    if not p.is_absolute():
        p = _UPPERDIR / p
    return p.resolve(strict=False)


def _is_write_allowed(resolved):
    if resolved is None or resolved.is_relative_to(_CANARY_VAULT):
        return False
    if _ACTOR == "RED":
        return resolved.is_relative_to(_ACTOR_ARTIFACTS) or resolved.is_relative_to(_RED_WRITABLE_UPPER_SUBDIR)
    return resolved.is_relative_to(_UPPERDIR) or resolved.is_relative_to(_ACTOR_ARTIFACTS)


def _audit_hook(event, args):
    if not _STATE["active"]:
        return

    if event in _BLOCKED_PROC_EVENTS:
        raise PermissionError(f"Event {event!r} blocked in ACK DetonationChamber (single-process confinement)")

    if event in ("socket.connect", "socket.bind", "socket.sendto", "socket.getaddrinfo"):
        if _NET_MODE == "none":
            raise PermissionError(f"Network operation {event!r} blocked under network_mode=none")
        if event == "socket.getaddrinfo" and args:
            host = str(args[0] or "").lower()
            if host and host not in ("127.0.0.1", "::1", "localhost") and not host.startswith("10.200."):
                raise PermissionError(f"External DNS lookup {host!r} blocked under ACK {event}")
        elif len(args) >= 2 and isinstance(args[1], tuple) and len(args[1]) >= 1:
            host = str(args[1][0] or "").lower()
            if host and host not in ("127.0.0.1", "::1", "localhost") and not host.startswith("10.200."):
                raise PermissionError(f"External network target {host!r} blocked under ACK {_NET_MODE}")
        return

    if event == "os.symlink" and len(args) >= 2:
        dst = _resolve_fs_path(args[1])
        if dst is not None and not _is_write_allowed(dst):
            raise PermissionError(f"Symlink creation outside allowed path rejected for {_ACTOR}: {dst}")
        return

    if event in ("os.remove", "os.unlink", "os.rmdir", "os.rename", "os.replace", "os.mkdir"):
        for p_arg in args[:2]:
            p = _resolve_fs_path(p_arg)
            if p is not None and not _is_write_allowed(p):
                raise PermissionError(f"{_ACTOR} actor cannot modify target modules or protected path: {p}")
        return

    if event == "open" and len(args) >= 3:
        path_arg, mode, flags = args[0], args[1], args[2]
        resolved = _resolve_fs_path(path_arg)
        if resolved is None:
            return
        if mode is not None:
            is_write = any(ch in str(mode) for ch in ("w", "a", "x", "+"))
        else:
            is_write = bool(int(flags or 0) & _WRITE_FLAGS)

        if is_write:
            if not _is_write_allowed(resolved):
                raise PermissionError(f"{_ACTOR} write denied (protected target/host path): {resolved}")
            return

        # Read access checks: strict process boundary so only TARGET server process can ever read canary_vault
        if any(resolved.is_relative_to(r) for r in _PY_ROOTS):
            return
        if resolved.is_relative_to(_CANARY_VAULT):
            if _ACTOR != "TARGET":
                raise PermissionError(
                    "RED/BLUE actors cannot open canary_vault directly; only the isolated TARGET server process may read canary_vault"
                )
            return
        if resolved.is_relative_to(_UPPERDIR) or resolved.is_relative_to(_ACTOR_ARTIFACTS):
            return
        if _BLUE_EXTRA_READ is not None and resolved == _BLUE_EXTRA_READ:
            return
        raise PermissionError(f"Host path read denied by ACK DetonationChamber: {resolved}")


if __name__ == "__main__":
    script_path = sys.argv[1]
    sys.argv = [script_path, *sys.argv[2:]]
    sys.addaudithook(_audit_hook)
    _STATE["active"] = True
    runpy.run_path(script_path, run_name="__main__")
'''

_TARGET_SERVER_SOURCE = '''\
"""Isolated TARGET HTTP loopback server running inside its own confined process with exclusive canary_vault read."""

import importlib.util
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

upperdir = Path(os.environ["ACK_UPPERDIR"]).resolve()
sys.path.insert(0, str(upperdir))
target_path = (upperdir / sys.argv[1]).resolve()
handler_name = sys.argv[2]

spec = importlib.util.spec_from_file_location("_ack_target_mod", str(target_path))
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to load target module: {target_path}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
handler_fn = getattr(mod, handler_name)


class _AckTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def address_string(self):
        return str(self.client_address[0])

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
            status, body = handler_fn(payload)
        except Exception as exc:
            status, body = 500, {"error": str(exc)}
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    httpd = HTTPServer(("127.0.0.1", 0), _AckTargetHandler)
    print(f"ACK_LISTEN_PORT={httpd.server_address[1]}", flush=True)
    httpd.serve_forever()
'''
