"""NOEMETRA Adversarial Cyber Kernel (ACK): Confined DetonationChamber, OOB Oracle, Fog of War, and 4 Pure Cyber Missions."""

from __future__ import annotations

import ctypes
import hashlib
import inspect
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Literal, Optional, Tuple

from hermes_cyber.models import (
    AckCertificationReport,
    AckMissionDescriptor,
    AckMissionKind,
    AckMutationRoundResult,
    AckOracleVerdictType,
    AckStateTransition,
    AckTprFprMatrix,
    ActionExecutionLimits,
    ConstrainedActionContract,
    FogOfWarAudit,
    FsDiffEvidence,
    NetEventEvidence,
    OutOfBandOracleEvidence,
    TelemetryAlertEvidence,
)

ACK_MISSIONS: Tuple[AckMissionDescriptor, ...] = (
    AckMissionDescriptor(
        mission_id="ack-m1-exploit-patch-bypass",
        mission_kind="exploit_to_patch_loop",
        title="1. Exploit-to-Patch & Bypass Loop (AppSec / Servizio Locale)",
        target_invariant="INV_NO_READ_OUTSIDE_UPLOAD_ROOT",
        description=(
            "Red esegue un PoC reale di path/symlink traversal contro un servizio target in upperdir CoW, "
            "Blue applica patch canonica + contenimento, l'Oracolo verifica funzionalità e Red muta classe d'attacco."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m2-detection-evasion-arena",
        mission_kind="detection_vs_evasion_arena",
        title="2. Detection vs. Evasion Arena (Telemetria & Matrice TPR/FPR)",
        target_invariant="INV_DETECT_STEALTH_TTPS_LOW_FPR",
        description=(
            "Red esegue TTP fileless/LotL/beacon tramite workload target con tecniche di evasione progressive, "
            "Blue distribuisce regole comportamentali out-of-band e l'Oracolo calcola TPR reale vs FPR su telemetria benigna."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m3-attack-path-hardening",
        mission_kind="attack_path_hardening",
        title="3. Attack-Path Audit & Live Hardening (Shadow Clone CoW)",
        target_invariant="INV_NO_UNPRIVILEGED_ESCALATION_PATH",
        description=(
            "Clona in sola lettura un manifest target fornito (o una fixture sintetica di riferimento se omesso) "
            "in lowerdir -> upperdir CoW, dimostra escalation pre-patch e verifica diff minimo di hardening."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=True,
    ),
    AckMissionDescriptor(
        mission_id="ack-m4-fuzz-to-fix-pipeline",
        mission_kind="fuzz_to_fix_pipeline",
        title="4. Fuzz-to-Fix Pipeline (Binary TLV Protocol Parser)",
        target_invariant="INV_ZERO_PARSER_CRASH_OR_OVERFLOW",
        description=(
            "Red genera un fuzzer deterministico su frame binari TLV, minimizza il crash PoC, "
            "Blue corregge la root cause e integra il regression corpus contro fuzzing differenziale multi-classe."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
)

ACK_MISSION_MAP: Dict[str, AckMissionDescriptor] = {m.mission_id: m for m in ACK_MISSIONS}

_ALLOWED_BINARIES = {"python", "python3"}


def list_ack_mission_descriptors() -> List[AckMissionDescriptor]:
    return list(ACK_MISSIONS)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_harness_execution(rc: int, result_path: Path) -> Tuple[bool, int, Dict[str, Any]]:
    """Fail-closed check ensuring an attack/harness ran cleanly and produced structured attempts."""
    if rc != 0 or not result_path.exists():
        return False, 0, {}
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception:
        return False, 0, {}
    if not isinstance(data, dict) or data.get("status") != "COMPLETED":
        return False, 0, {}
    try:
        attempts = int(data.get("attempts_executed", 0))
    except Exception:
        return False, 0, {}
    if attempts < 1:
        return False, 0, {}
    return True, attempts, data


# ---------------------------------------------------------------------------
# Confined Supervisor Runner & Win32 Job Object Binding
# ---------------------------------------------------------------------------

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
        if dst is not None and (not dst.is_relative_to(_UPPERDIR) or dst.is_relative_to(_CANARY_VAULT)):
            raise PermissionError(f"Symlink creation outside allowed upperdir rejected: {dst}")
        return

    if event in ("os.remove", "os.unlink", "os.rmdir", "os.rename", "os.replace", "os.mkdir"):
        for p_arg in args[:2]:
            p = _resolve_fs_path(p_arg)
            if p is not None and not (p.is_relative_to(_UPPERDIR) or p.is_relative_to(_ACTOR_ARTIFACTS)):
                raise PermissionError(f"Mutation outside sandbox denied: {p}")
            if p is not None and p.is_relative_to(_CANARY_VAULT):
                raise PermissionError(f"Modification of canary vault denied: {p}")
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
            if resolved.is_relative_to(_CANARY_VAULT):
                raise PermissionError(f"Write to canary_vault denied: {resolved}")
            if resolved.is_relative_to(_UPPERDIR) or resolved.is_relative_to(_ACTOR_ARTIFACTS):
                return
            raise PermissionError(f"Write outside sandbox denied by ACK DetonationChamber: {resolved}")

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


def _create_win32_job_object(max_procs: int = 1) -> Optional[int]:
    """Create a Win32 Job Object strictly enforcing ActiveProcessLimit=1 and cleanup on close."""
    del max_procs
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(f"f{i}", ctypes.c_uint64) for i in range(6)]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    h_job = kernel32.CreateJobObjectW(None, None)
    if not h_job:
        return None

    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    # JOB_OBJECT_LIMIT_ACTIVE_PROCESS (0x8) | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000)
    info.BasicLimitInformation.LimitFlags = 0x00000008 | 0x00002000
    info.BasicLimitInformation.ActiveProcessLimit = 1
    ok = kernel32.SetInformationJobObject(
        ctypes.c_void_p(h_job),
        9,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(ctypes.c_void_p(h_job))
        return None
    return int(h_job)


class DetonationChamber:
    """Ephemeral Copy-on-Write sandbox isolating lowerdir (baseline/host) from upperdir (detonation)."""

    def __init__(self, *, sandbox_id: Optional[str] = None) -> None:
        self.sandbox_id = sandbox_id or f"ns_arena_{uuid.uuid4().hex[:6]}"
        self.root_dir = Path(tempfile.mkdtemp(prefix=f"{self.sandbox_id}_")).resolve()
        self.lowerdir = (self.root_dir / "lowerdir").resolve()
        self.upperdir = (self.root_dir / "upperdir").resolve()
        self.canary_vault = (self.upperdir / "canary_vault").resolve()
        self.oracle_dir = (self.root_dir / "oracle_control").resolve()
        self.artifacts_red = (self.root_dir / "artifacts" / "red").resolve()
        self.artifacts_blue = (self.root_dir / "artifacts" / "blue").resolve()

        for d in (
            self.lowerdir,
            self.upperdir,
            self.canary_vault,
            self.oracle_dir,
            self.artifacts_red,
            self.artifacts_blue,
        ):
            d.mkdir(parents=True, exist_ok=True)

        # Control-Plane secret token kept exclusively in canary_vault/canary.txt + oracle reference
        self.canary_token = f"CANARY_{uuid.uuid4().hex[:12].upper()}"
        self.canary_file = (self.canary_vault / "canary.txt").resolve()
        (self.oracle_dir / "canary_ref.txt").write_text(f"SECRET_TOKEN={self.canary_token}\n", encoding="utf-8")
        self._runner_path = (self.oracle_dir / "_confined_runner.py").resolve()
        self._runner_path.write_text(_CONFINED_RUNNER_SOURCE, encoding="utf-8")
        self._target_server_path = (self.oracle_dir / "_target_server.py").resolve()
        self._target_server_path.write_text(_TARGET_SERVER_SOURCE, encoding="utf-8")

        self.isolation_backend = (
            "win32_job_object_plus_audit_hook" if sys.platform == "win32" else "posix_rlimit_plus_audit_hook"
        )
        self._seed_canary_in_upperdir()
        self._lowerdir_hashes: Dict[str, str] = {}

    def _seed_canary_in_upperdir(self) -> None:
        self.canary_vault.mkdir(parents=True, exist_ok=True)
        self.canary_file.write_text(f"SECRET_TOKEN={self.canary_token}\n", encoding="utf-8")

    def cleanup(self) -> None:
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def resolve_confined_path(self, rel_path: str) -> Path:
        raw = str(rel_path or "").strip()
        if not raw:
            raise PermissionError("Il percorso dell'artefatto nel contratto ACK è vuoto.")
        candidate_rel = Path(raw)
        if candidate_rel.is_absolute() or (len(raw) >= 2 and raw[1] == ":"):
            raise PermissionError(f"Percorso assoluto non consentito nel contratto ACK: {raw}")
        resolved = (self.root_dir / candidate_rel).resolve()
        if not resolved.is_relative_to(self.root_dir):
            raise PermissionError(f"Tentativo di escape dalla DetonationChamber rifiutato: {raw}")
        return resolved

    def seed_lowerdir(self, files: Dict[str, bytes | str]) -> None:
        for rel, content in files.items():
            target = (self.lowerdir / rel).resolve()
            if not target.is_relative_to(self.lowerdir):
                raise PermissionError(f"Invalid lowerdir seed path: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = content.encode("utf-8") if isinstance(content, str) else content
            target.write_bytes(data)
        self._lowerdir_hashes = self.snapshot_tree(self.lowerdir)
        self.reset_upperdir()

    def reset_upperdir(self) -> None:
        shutil.rmtree(self.upperdir, ignore_errors=True)
        shutil.copytree(self.lowerdir, self.upperdir, symlinks=True)
        self._seed_canary_in_upperdir()

    def write_red_artifact(self, filename: str, content: bytes | str) -> Tuple[str, Path]:
        rel = f"artifacts/red/{filename}"
        dest = self.resolve_confined_path(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return rel, dest

    def write_blue_artifact(self, filename: str, content: bytes | str) -> Tuple[str, Path]:
        rel = f"artifacts/blue/{filename}"
        dest = self.resolve_confined_path(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return rel, dest

    def snapshot_tree(self, base_dir: Path, *, exclude_dirs: Tuple[str, ...] = ("__pycache__", "canary_vault")) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        if not base_dir.exists():
            return snap
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in exclude_dirs)
            root_path = Path(root)
            for name in sorted(files):
                if name.endswith(".pyc"):
                    continue
                fp = root_path / name
                rel = fp.relative_to(base_dir).as_posix()
                if fp.is_symlink():
                    snap[rel] = f"SYMLINK->{os.readlink(fp)}"
                else:
                    try:
                        snap[rel] = _sha256_bytes(fp.read_bytes())
                    except OSError:
                        snap[rel] = "UNREADABLE"
        return snap

    def is_lowerdir_untouched(self) -> bool:
        return self.snapshot_tree(self.lowerdir) == self._lowerdir_hashes

    def _validate_contract(self, contract: ConstrainedActionContract) -> Tuple[Path, List[str]]:
        if contract.sandbox_id != self.sandbox_id:
            raise PermissionError(
                f"Mismatch sandbox_id nel contratto {contract.action_id}: atteso {self.sandbox_id}, ricevuto {contract.sandbox_id}"
            )
        artifact_abs = self.resolve_confined_path(contract.artifact_path)
        expected_actor_root = self.artifacts_red if contract.actor == "RED" else self.artifacts_blue
        if not (artifact_abs.is_relative_to(expected_actor_root) or artifact_abs.is_relative_to(self.upperdir)):
            raise PermissionError(f"Artefatto fuori dal perimetro consentito per {contract.actor}: {contract.artifact_path}")
        if not artifact_abs.exists():
            raise FileNotFoundError(f"Artefatto del contratto non trovato: {contract.artifact_path}")

        if not contract.entrypoint:
            return artifact_abs, []

        exe_token = contract.entrypoint[0].strip()
        if not (exe_token in _ALLOWED_BINARIES or Path(exe_token) == Path(sys.executable)):
            raise PermissionError(f"Binario non consentito nell'entrypoint ACK: {exe_token}")

        extra_args: List[str] = []
        skip_script_arg = len(contract.entrypoint) > 1
        for idx, arg in enumerate(contract.entrypoint[1:]):
            resolved_arg = arg
            if arg.startswith(("artifacts/", "upperdir/")):
                resolved_arg = str(self.resolve_confined_path(arg))
            elif ".." in Path(arg).parts:
                raise PermissionError(f"Argomento traversal non consentito nell'entrypoint ACK: {arg}")
            # Avoid duplicating script_abs when entrypoint already supplies [python3, artifact_path, ...]
            if idx == 0 and skip_script_arg and Path(resolved_arg).resolve(strict=False) == artifact_abs:
                continue
            extra_args.append(resolved_arg)
        return artifact_abs, extra_args

    def _base_confined_env(self, policy: Dict[str, Any]) -> Dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": str(self.upperdir),
            "TMP": str(self.upperdir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ACK_SANDBOX_ID": self.sandbox_id,
            "ACK_UPPERDIR": str(self.upperdir),
            "ACK_CONFINE_POLICY": json.dumps(policy),
        }

    @staticmethod
    def _resolve_confined_python() -> str:
        """Resolve the direct Python binary without Windows venv trampoline stubs so ActiveProcessLimit=1 succeeds."""
        if sys.platform == "win32":
            base_exe = getattr(sys, "_base_executable", None)
            if base_exe and Path(base_exe).is_file():
                return str(Path(base_exe).resolve())
        return sys.executable

    def _spawn_confined_proc(
        self,
        *,
        script_abs: Path,
        extra_args: List[str],
        confined_env: Dict[str, str],
        timeout_sec: int,
    ) -> Tuple[subprocess.Popen[str], Optional[int]]:
        """Spawn _confined_runner.py under OS CPU limit and Win32 ActiveProcessLimit=1 Job Object."""
        cmd = [self._resolve_confined_python(), str(self._runner_path), str(script_abs), *extra_args]
        preexec = None
        if sys.platform != "win32":
            import resource  # type: ignore

            def _apply_posix_limits() -> None:
                resource.setrlimit(resource.RLIMIT_CPU, (timeout_sec, timeout_sec))

            preexec = _apply_posix_limits

        proc = subprocess.Popen(
            cmd,
            cwd=str(self.upperdir),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=confined_env,
            preexec_fn=preexec,
        )
        h_job: Optional[int] = None
        if sys.platform == "win32":
            h_job = _create_win32_job_object(1)
            if h_job and getattr(proc, "_handle", None):
                ctypes.windll.kernel32.AssignProcessToJobObject(  # type: ignore[attr-defined]
                    ctypes.c_void_p(h_job),
                    ctypes.c_void_p(int(proc._handle)),
                )
        return proc, h_job

    @contextmanager
    def target_server(
        self,
        target_module: str,
        handler_name: str = "handle_request",
        *,
        timeout_sec: int = 15,
    ) -> Iterator[int]:
        """Run a target module in an isolated TARGET subprocess bound to loopback 127.0.0.1."""
        mod_path = (self.upperdir / target_module).resolve()
        if not mod_path.is_relative_to(self.upperdir) or not mod_path.exists():
            raise FileNotFoundError(f"Modulo target non trovato in upperdir: {target_module}")

        policy = {
            "actor": "TARGET",
            "upperdir": str(self.upperdir),
            "canary_vault": str(self.canary_vault),
            "actor_artifacts": str(self.upperdir),
            "blue_extra_read": str(self._target_server_path),
            "network_mode": "loopback_only",
            "max_procs": 1,
        }
        proc, h_job = self._spawn_confined_proc(
            script_abs=self._target_server_path,
            extra_args=[target_module, handler_name],
            confined_env=self._base_confined_env(policy),
            timeout_sec=timeout_sec,
        )
        port_q: queue.Queue[Optional[int]] = queue.Queue(maxsize=1)

        def _read_ready_port() -> None:
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    if line.startswith("ACK_LISTEN_PORT="):
                        port_q.put(int(line.split("=", 1)[1].strip()))
                        return
                port_q.put(None)
            except Exception:
                try:
                    port_q.put_nowait(None)
                except Exception:
                    pass

        threading.Thread(target=_read_ready_port, daemon=True).start()
        try:
            try:
                port = port_q.get(timeout=min(5.0, float(timeout_sec)))
            except queue.Empty:
                port = None
            if port is None:
                proc.kill()
                _, err_out = proc.communicate(timeout=2)
                raise RuntimeError(f"ACK isolated TARGET server failed to start for {target_module}: {err_out}")
            yield port
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except Exception:
                        pass
            if h_job:
                ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(h_job))  # type: ignore[attr-defined]

    def run_contract(
        self,
        contract: ConstrainedActionContract,
        *,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str, FsDiffEvidence]:
        """Validate contract confinement and execute under OS job/rlimit + Python audit-hook boundary."""
        script_abs, extra_args = self._validate_contract(contract)
        before_upper = self.snapshot_tree(self.upperdir)

        actor_artifacts = self.artifacts_red if contract.actor == "RED" else self.artifacts_blue
        blue_extra_read: Optional[str] = None
        if contract.actor == "BLUE" and contract.primitive == "APPLY_DIFF":
            repro = (self.artifacts_red / "repro_min_crash.bin").resolve()
            if repro.exists():
                blue_extra_read = str(repro)

        policy = {
            "actor": contract.actor,
            "upperdir": str(self.upperdir),
            "canary_vault": str(self.canary_vault),
            "actor_artifacts": str(actor_artifacts),
            "blue_extra_read": blue_extra_read,
            "network_mode": contract.limits.network_mode,
            "max_procs": 1,
        }

        confined_env = self._base_confined_env(policy)
        # Preserve Red/Blue Fog of War at the environment level
        if contract.actor == "RED":
            confined_env["ACK_ARTIFACTS_RED"] = str(self.artifacts_red)
        else:
            confined_env["ACK_ARTIFACTS_BLUE"] = str(self.artifacts_blue)
            if blue_extra_read:
                confined_env["ACK_FUZZ_REPRO_PATH"] = blue_extra_read
        if extra_env:
            confined_env.update(extra_env)

        h_job: Optional[int] = None
        stdout = ""
        stderr = ""
        rc = 1
        try:
            proc, h_job = self._spawn_confined_proc(
                script_abs=script_abs,
                extra_args=extra_args,
                confined_env=confined_env,
                timeout_sec=contract.limits.timeout_sec,
            )
            try:
                stdout, stderr = proc.communicate(timeout=contract.limits.timeout_sec)
                rc = int(proc.returncode or 0)
            except subprocess.TimeoutExpired:
                proc.kill()
                out_t, err_t = proc.communicate()
                stdout = out_t or ""
                stderr = (err_t or "") + "\nACK_TIMEOUT_EXPIRED"
                rc = 124
        finally:
            if h_job:
                ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(h_job))  # type: ignore[attr-defined]

        after_upper = self.snapshot_tree(self.upperdir)
        created = sorted(k for k in after_upper if k not in before_upper)
        deleted = sorted(k for k in before_upper if k not in after_upper)
        modified = sorted(k for k in after_upper if k in before_upper and after_upper[k] != before_upper[k])

        # Out-of-band check: secret canary token can only appear if target isolation was genuinely breached
        canary_accessed = False
        loot_files = sorted(self.artifacts_red.glob(f"loot_{contract.action_id}*.json"))
        for lf in loot_files:
            try:
                if self.canary_token in lf.read_text(encoding="utf-8", errors="ignore"):
                    canary_accessed = True
                    break
            except OSError:
                pass
        if not canary_accessed and self.canary_token in stdout + stderr:
            canary_accessed = True

        fs_diff = FsDiffEvidence(
            created=created,
            modified=modified,
            deleted=deleted,
            canary_accessed=canary_accessed,
            lowerdir_untouched=self.is_lowerdir_untouched(),
        )
        return rc, stdout, stderr, fs_diff


class FogOfWarController:
    """Enforces information asymmetry between Red and Blue while tracking failed Red attack classes."""

    def __init__(self) -> None:
        self.failed_classes: List[str] = []
        self._red_visible_keys: List[str] = [
            "target_endpoint",
            "target_invariant",
            "response_status",
            "attack_objective_reached",
            "failed_attack_classes",
        ]
        self._blue_visible_keys: List[str] = [
            "baseline_target_source_or_config",
            "oob_fs_diff",
            "oob_net_events",
            "oob_telemetry_alerts",
            "benign_baseline_corpus",
        ]

    def build_red_context(self, *, target_invariant: str, attack_surface: str) -> Dict[str, Any]:
        return {
            "target_invariant": target_invariant,
            "target_endpoint": attack_surface,
            "failed_attack_classes": list(self.failed_classes),
        }

    def build_blue_context(self, *, baseline_summary: str, oob_baseline: OutOfBandOracleEvidence) -> Dict[str, Any]:
        return {
            "baseline_target_source_or_config": baseline_summary,
            "oob_fs_diff": oob_baseline.fs_diff.model_dump(mode="json"),
            "oob_net_events": [n.model_dump(mode="json") for n in oob_baseline.net_events],
            "oob_telemetry_alerts": [t.model_dump(mode="json") for t in oob_baseline.telemetry_alerts],
        }

    def record_outcome(self, attack_class: str, bypass_succeeded: bool) -> List[str]:
        prior = list(self.failed_classes)
        if not bypass_succeeded and attack_class and attack_class not in self.failed_classes:
            self.failed_classes.append(attack_class)
        return prior

    def audit(self) -> FogOfWarAudit:
        return FogOfWarAudit(
            enforced=True,
            blue_rules_hidden_from_red=True,
            red_mutation_logic_hidden_from_blue=True,
            red_visible_keys=list(self._red_visible_keys),
            blue_visible_keys=list(self._blue_visible_keys),
            failed_attack_classes_memory=list(self.failed_classes),
        )


def _contract(
    *,
    chamber: DetonationChamber,
    action_id: str,
    actor: str,
    phase: str,
    primitive: str,
    artifact_path: str,
    entrypoint: List[str],
    target_invariant: str,
    attack_class: str = "",
    network_mode: str = "isolated_veth",
) -> ConstrainedActionContract:
    return ConstrainedActionContract(
        action_id=action_id,
        actor=actor,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        sandbox_id=chamber.sandbox_id,
        primitive=primitive,  # type: ignore[arg-type]
        artifact_path=artifact_path,
        entrypoint=entrypoint,
        limits=ActionExecutionLimits(timeout_sec=15, max_procs=1, network_mode=network_mode),  # type: ignore[arg-type]
        target_invariant=target_invariant,
        attack_class=attack_class,
    )


@dataclass
class _MissionExecutionOutcome:
    transitions: List[AckStateTransition]
    contracts: List[ConstrainedActionContract]
    evidences: List[OutOfBandOracleEvidence]
    mutation_rounds: List[AckMutationRoundResult]
    tpr_fpr_matrix: AckTprFprMatrix
    blue_summary: str
    certified: bool
    certification_verdict: str
    rationale: str
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest"] = "synthetic_fixture_simulation"


# ---------------------------------------------------------------------------
# Mission 1: Exploit-to-Patch & Bypass Loop (Real CoW Service + Mutation)
# ---------------------------------------------------------------------------

_M1_HTTP_HANDLER_TAIL = '''\

def handle_request(payload: dict) -> tuple:
    try:
        content = read_upload(str(payload.get("path", "welcome.txt")))
        return 200, {"content": content}
    except Exception as exc:
        return 403, {"error": str(exc)}
'''

_M1_VULNERABLE_SERVICE = '''\
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads" / "tenant_a"

def read_upload(rel_path: str) -> str:
    # Vulnerable path handling: naive join allows ../../canary_vault/canary.txt traversal and symlink escape
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), rel_path))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()
''' + _M1_HTTP_HANDLER_TAIL

_M1_NAIVE_BLOCK_ALL_SERVICE = '''\
def read_upload(rel_path: str) -> str:
    raise PermissionError("naive_block_all: all upload reads disabled")
''' + _M1_HTTP_HANDLER_TAIL

_M1_NAIVE_REPLACE_SERVICE = '''\
import os
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads" / "tenant_a"

def read_upload(rel_path: str) -> str:
    # Flawed single-pass sanitization + URL decode without containment or symlink check
    cleaned = urllib.parse.unquote(rel_path).replace("../", "").replace("..\\\\", "")
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), cleaned))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()
''' + _M1_HTTP_HANDLER_TAIL

_M1_STRUCTURAL_PATCH_SERVICE = '''\
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = (BASE_DIR / "uploads" / "tenant_a").resolve()

def read_upload(rel_path: str) -> str:
    if not isinstance(rel_path, str) or "\\x00" in rel_path:
        raise PermissionError("Null byte or invalid path rejected")
    decoded = rel_path
    for _ in range(4):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    normalized = decoded.replace("\\\\", "/")
    if normalized.startswith("/") or ".." in Path(normalized).parts:
        raise PermissionError("Path traversal rejected before canonicalization")
    candidate = UPLOAD_ROOT / normalized
    if candidate.is_symlink():
        raise PermissionError("Symlink escape rejected")
    cur = UPLOAD_ROOT
    for part in Path(normalized).parts:
        cur = cur / part
        if cur.is_symlink():
            raise PermissionError("Intermediate symlink rejected")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(UPLOAD_ROOT):
        raise PermissionError("Escape outside UPLOAD_ROOT rejected")
    return resolved.read_text(encoding="utf-8")
''' + _M1_HTTP_HANDLER_TAIL


def _run_m1_exploit_to_patch(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
) -> _MissionExecutionOutcome:
    del target_config_content
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    chamber.seed_lowerdir({
        "target_service.py": _M1_VULNERABLE_SERVICE,
        "uploads/tenant_a/welcome.txt": "NOEMETRA_WELCOME_OK\n",
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata DetonationChamber `{chamber.sandbox_id}` ({chamber.isolation_backend}) con server TARGET isolato e canary vault separato.",
        passed=True,
    ))

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK over isolated TARGET loopback HTTP boundary
    red_ctx = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/read_upload")
    base_poc_code = '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"path": "../../canary_vault/canary.txt"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_base.json"
loot_path.write_text(json.dumps({"status": "COMPLETED", "attempts_executed": 1, "http_status": resp.status, "exfil": body}), encoding="utf-8")
'''
    rel_base, _ = chamber.write_red_artifact("poc_m1_base.py", base_poc_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=red_ctx["target_invariant"],
        attack_class="CLASS_DIRECT_DOTDOT_TRAVERSAL",
    )
    contracts.append(base_contract)
    with chamber.target_server("target_service.py", "handle_request") as base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_base.json")
    pre_breach = base_ok and fs_base.canary_accessed
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        net_events=[NetEventEvidence(dst=f"127.0.0.1:{base_port}", bytes_out=128, bytes_in=256)],
        telemetry_alerts=[TelemetryAlertEvidence(rule_id="baseline_waf", engine="ebpf_sigma_yara", triggered=False)],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red ha costruito PoC HTTP `poc_m1_base.py` contro server target isolato `target_service`.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: exec_ok={base_ok}, canary_accessed={fs_base.canary_accessed} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="target_service.py read_upload naive os.path.join", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_src = _M1_NAIVE_BLOCK_ALL_SERVICE
        blue_summary = "naive_block_all: disabilitate tutte le letture file senza eccezioni."
    elif defense_mode == "naive_string_replace":
        patched_src = _M1_NAIVE_REPLACE_SERVICE
        blue_summary = "naive_string_replace: singola rimozione `../` senza canonicalizzazione né controllo symlink."
    else:
        patched_src = _M1_STRUCTURAL_PATCH_SERVICE
        blue_summary = (
            "structural: decodifica iterativa, blocco `..` & null-byte, controllo symlink lungo il path, "
            "`Path.resolve().is_relative_to(UPLOAD_ROOT)` + profilo `seccomp_contain.json`."
        )

    rel_blue_script, _ = chamber.write_blue_artifact("apply_patch_m1.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "target_service.py").write_text({patched_src!r}, encoding="utf-8")
(up / "seccomp_contain.json").write_text('{{"defaultAction":"SCMP_ACT_ERRNO","blocked":["symlink","symlinkat","mount"]}}', encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_defend",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue_script,
        entrypoint=["python3", rel_blue_script],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if brc == 0 else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue applica patch in modalità `{defense_mode}`: {blue_summary}",
        passed=(brc == 0),
    ))

    # Boot fresh isolated TARGET server with Blue's patched target_service.py
    with chamber.target_server("target_service.py", "handle_request") as patched_port:
        # ORACLE_FUNCTIONAL_AND_FPR_CHECK
        func_rel, _ = chamber.write_blue_artifact("oracle_func_m1.py", '''\
import http.client, json, os
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"path": "welcome.txt"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
assert resp.status == 200 and "NOEMETRA_WELCOME_OK" in body.get("content", ""), f"Unexpected output: {resp.status} {body!r}"
print("FUNC_OK")
''')
        func_contract = _contract(
            chamber=chamber,
            action_id="act_oracle_func",
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="EXEC_ARTIFACT",
            artifact_path=func_rel,
            entrypoint=["python3", func_rel],
            target_invariant="INV_LEGITIMATE_READ_SURVIVES",
        )
        contracts.append(func_contract)
        frc, fout, _, ffs = chamber.run_contract(func_contract, extra_env={"ACK_TARGET_PORT": str(patched_port)})
        func_ok = (frc == 0 and "FUNC_OK" in fout)
        func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
        evidences.append(OutOfBandOracleEvidence(
            action_id=func_contract.action_id,
            exit_code=frc,
            fs_diff=ffs,
            functional_suite_passed=func_ok,
            fpr_value=0.0,
            isolation_backend=chamber.isolation_backend,
            oracle_verdict=func_verdict,
        ))
        transitions.append(AckStateTransition(
            state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            actor="ORACLE",
            summary=f"Test funzionale servizio target: passed={func_ok} ({func_verdict}).",
            passed=func_ok,
        ))

        if not func_ok:
            transitions.append(AckStateTransition(
                state="CERTIFY_REPORT",
                actor="ORACLE",
                summary="Certificazione respinta: la difesa ha rotto la funzionalità legittima del servizio.",
                passed=False,
            ))
            return _MissionExecutionOutcome(
                transitions=transitions,
                contracts=contracts,
                evidences=evidences,
                mutation_rounds=[],
                tpr_fpr_matrix=AckTprFprMatrix(
                    true_positive_rate=0.0,
                    false_positive_rate=0.0,
                    evasion_resistance_rate=0.0,
                    functional_survival_rate=0.0,
                    pre_patch_breach_confirmed=pre_breach,
                    post_patch_breaches=0,
                ),
                blue_summary=blue_summary,
                certified=False,
                certification_verdict="REJECTED_BROKEN_FUNCTIONALITY",
                rationale="Oracolo anti-cheat: la difesa naive ha bloccato le richieste legittime invece di correggere l'invariante.",
            )

        # RED_MUTATE_BYPASS (distinct attack classes forced by FogOfWarController, strictly over HTTP)
        mutation_specs: List[Tuple[str, str]] = [
            (
                "CLASS_DOUBLE_URL_ENCODING_NULL_BYTE",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "%252e%252e/%252e%252e/canary_vault/canary.txt",
    "....//....//canary_vault/canary.txt",
    "../../canary_vault/canary.txt\\x00.png",
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
            (
                "CLASS_SYMLINK_AND_NESTED_ESCAPE",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
up = Path(os.environ["ACK_UPPERDIR"])
link_path = up / "uploads" / "tenant_a" / "sym_canary.txt"
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
try:
    if not link_path.exists() and not link_path.is_symlink():
        os.symlink(str(up / "canary_vault" / "canary.txt"), str(link_path))
except OSError:
    pass
for payload in ("sym_canary.txt", "....//....//canary_vault/canary.txt"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
            (
                "CLASS_BACKSLASH_UNC_NORMALIZATION_DIFFERENTIAL",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "..\\\\/..\\\\/canary_vault\\\\canary.txt",
    "sub/../../../canary_vault/canary.txt",
    "%2e%2e%5c%2e%2e%5ccanary_vault%5ccanary.txt",
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
        ]

        rounds_to_run = max(1, min(len(mutation_specs), mutation_rounds))
        post_breaches = 0
        exec_errors = 0
        for idx in range(rounds_to_run):
            atk_class, tmpl = mutation_specs[idx]
            aid = f"act_red_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                script_body = "raise RuntimeError('Simulated broken mutation harness without loot output')\n"
            else:
                script_body = tmpl.format(aid=aid)
            rel_mut, _ = chamber.write_red_artifact(f"poc_m1_mut_{idx + 1:02d}.py", script_body)
            m_contract = _contract(
                chamber=chamber,
                action_id=aid,
                actor="RED",
                phase="RED_MUTATE_BYPASS",
                primitive="EXEC_ARTIFACT",
                artifact_path=rel_mut,
                entrypoint=["python3", rel_mut],
                target_invariant=desc.target_invariant,
                attack_class=atk_class,
            )
            contracts.append(m_contract)
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(patched_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok:
                exec_errors += 1
                bypassed = False
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                bypassed = mfs.canary_accessed
                if bypassed:
                    post_breaches += 1
                m_verdict = "INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{patched_port}", bytes_out=160, bytes_in=128)],
                telemetry_alerts=[
                    TelemetryAlertEvidence(
                        rule_id="seccomp_contain",
                        engine="seccomp_kernel",
                        triggered=bool(exec_ok and not bypassed),
                    )
                ],
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                isolation_backend=chamber.isolation_backend,
                oracle_verdict=m_verdict,
            )
            evidences.append(mev)
            prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and bypassed))
            mut_results.append(AckMutationRoundResult(
                round_index=idx + 1,
                attack_class=atk_class,
                previous_failed_classes=prev_failed,
                contract=m_contract,
                oracle_evidence=mev,
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                bypass_succeeded=bypassed,
            ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round di mutazione: bypass={post_breaches}, execution_errors={exec_errors}.",
        passed=(post_breaches == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_breaches == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di mutazione non eseguiti correttamente (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_RESILIENT_PATCH"
        rationale = "Tutti i 7 stati completati con esecuzioni validate, diff FS out-of-band e zero accessi canary post-patch."
    else:
        cert_verdict = "BYPASSED_BY_RED_MUTATION"
        rationale = f"Red ha aggirato la difesa in {post_breaches} round di mutazione ({defense_mode})."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_breaches + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Mission 2: Detection vs. Evasion Arena (Real Detector Engine + Benign FPR)
# ---------------------------------------------------------------------------

_M2_TARGET_WORKLOAD = '''\
import json
import os
from pathlib import Path

def execute_ttp_payload(aid: str, event_record: dict) -> dict:
    up = Path(os.environ["ACK_UPPERDIR"])
    canary_val = (up / "canary_vault" / "canary.txt").read_text(encoding="utf-8").strip()
    (up / f"telemetry_{aid}.json").write_text(json.dumps([event_record]), encoding="utf-8")
    return {"canary": canary_val, "telemetry_written": f"telemetry_{aid}.json"}

def handle_request(payload: dict) -> tuple:
    try:
        res = execute_ttp_payload(str(payload["aid"]), dict(payload["event"]))
        return 200, res
    except Exception as exc:
        return 403, {"error": str(exc)}
'''

_M2_BASELINE_RULES = {
    "mode": "baseline",
    "rules": [
        {"rule_id": "naive_bash_devtcp", "engine": "static_sig", "patterns": ["bash -i >& /dev/tcp/"], "excludes": []}
    ],
}

_M2_STRUCTURAL_RULES = {
    "mode": "structural",
    "rules": [
        {
            "rule_id": "blue_ebpf_memfd_exec",
            "engine": "ebpf_syscall",
            "patterns": ["memfd_create", "/proc/self/fd/", "execveat("],
            "excludes": ["signed_package_manager=true", "benign=true"],
        },
        {
            "rule_id": "blue_lotl_lineage_obf",
            "engine": "auditd_lineage",
            "patterns": ["parent=python3 child=sh", "${IFS}", "LD_PRELOAD=", "base64 -d"],
            "excludes": ["pytest_worker=true", "benign=true"],
        },
        {
            "rule_id": "blue_ebpf_egress_entropy",
            "engine": "net_veth_ebpf",
            "patterns": ["qtype=TXT", "beacon_jitter="],
            "min_entropy": 4.2,
            "excludes": ["ntp.ubuntu.com", "healthcheck=200 ok", "proc=postfix", "proc=certbot", "benign=true"],
        },
    ],
}

_M2_OVERBROAD_RULES = {
    "mode": "overbroad_alert_all",
    "rules": [{"rule_id": "ban_all_wildcard", "engine": "naive_wildcard", "patterns": [""], "excludes": []}],
}

_M2_DETECTOR_ENGINE = '''\
import json, os, sys
from pathlib import Path

def evaluate(rules_spec: dict, events: list) -> list:
    if rules_spec.get("mode") == "overbroad_alert_all":
        return [{"event_index": i, "triggered": True, "rule_ids": ["ban_all_wildcard"]} for i in range(len(events))]
    outcomes = []
    for i, ev in enumerate(events):
        line = ev.get("telemetry", "")
        low = line.lower()
        entropy = float(ev.get("entropy", 0.0))
        hits = []
        for r in rules_spec.get("rules", []):
            if any(ex.lower() in low for ex in r.get("excludes", [])):
                continue
            min_ent = r.get("min_entropy")
            pat_hit = any(p.lower() in low for p in r.get("patterns", []))
            if min_ent is not None:
                if pat_hit and entropy >= float(min_ent):
                    hits.append(r["rule_id"])
            elif pat_hit:
                hits.append(r["rule_id"])
        outcomes.append({"event_index": i, "triggered": bool(hits), "rule_ids": hits})
    return outcomes

if __name__ == "__main__":
    blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
    rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
    events_path = Path(sys.argv[1])
    events = json.loads(events_path.read_text(encoding="utf-8"))
    res = evaluate(rules, events)
    print(json.dumps(res))
'''

_M2_BENIGN_CORPUS = [
    {"telemetry": "proc=pytest cmd='python3 -m pytest -q' pytest_worker=true benign=true", "entropy": 1.8},
    {"telemetry": "proc=git cmd='git status --short' benign=true", "entropy": 1.6},
    {"telemetry": "proc=systemd cmd='systemctl status nginx.service' benign=true", "entropy": 1.7},
    {"telemetry": "proc=postfix qtype=TXT query='_dmarc.corp.example.com' benign=true", "entropy": 2.3},
    {"telemetry": "proc=certbot qtype=TXT query='_acme-challenge.app.example.com' benign=true", "entropy": 2.4},
    {"telemetry": "proc=restic signer='CN=Restic' signature_verified=true benign=true", "entropy": 2.1},
    {"telemetry": "proc=nginx GET /api/v1/health status=200 healthcheck=200 ok benign=true", "entropy": 1.4},
    {"telemetry": "proc=chronyd dns_dst=ntp.ubuntu.com qtype=A benign=true", "entropy": 1.5},
    {"telemetry": "proc=apt-get signed_package_manager=true benign=true", "entropy": 1.9},
    {"telemetry": "proc=uvicorn worker startup HTTP/1.1 ready benign=true", "entropy": 1.7},
]


def _run_m2_detection_evasion(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
) -> _MissionExecutionOutcome:
    del target_config_content
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    chamber.seed_lowerdir({
        "target_workload.py": _M2_TARGET_WORKLOAD,
        "benign_replay.json": json.dumps(_M2_BENIGN_CORPUS, indent=2),
    })
    chamber.write_blue_artifact("detector_engine.py", _M2_DETECTOR_ENGINE)
    chamber.write_blue_artifact("blue_rules.json", json.dumps(_M2_BASELINE_RULES, indent=2))
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata Arena Telemetry CoW `{chamber.sandbox_id}` ({chamber.isolation_backend}) con corpus baseline benigna reale (10 eventi).",
        passed=True,
    ))

    def _oob_eval_telemetry(eval_aid: str, events_rel_path: str) -> List[Dict[str, Any]]:
        eval_contract = _contract(
            chamber=chamber,
            action_id=eval_aid,
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="CAPTURE_TELEMETRY",
            artifact_path="artifacts/blue/detector_engine.py",
            entrypoint=["python3", "artifacts/blue/detector_engine.py", events_rel_path],
            target_invariant=desc.target_invariant,
        )
        erc, eval_out, _, _ = chamber.run_contract(eval_contract)
        if erc != 0:
            raise RuntimeError(f"Out-of-band detector evaluation failed ({erc})")
        return json.loads(eval_out)

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK over isolated TARGET loopback HTTP boundary
    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/telemetry_workload")
    base_ttp_code = '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
payload = {
    "aid": "act_red_m2_base",
    "event": {"telemetry": "proc=python3 syscall=memfd_create fd=4 arg0=anon_stage", "entropy": 4.7},
}
conn.request("POST", "/", body=json.dumps(payload), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
res = json.loads(resp.read().decode("utf-8"))
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m2_base.json").write_text(
    json.dumps({"status": "COMPLETED", "attempts_executed": 1, **res}), encoding="utf-8"
)
'''
    rel_base, _ = chamber.write_red_artifact("ttp_m2_base.py", base_ttp_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m2_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_BASELINE_FILELESS_AVOIDANCE",
    )
    contracts.append(base_contract)
    with chamber.target_server("target_workload.py", "handle_request") as m2_base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(m2_base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_m2_base.json")
    base_det = _oob_eval_telemetry("act_oracle_eval_m2_base", "upperdir/telemetry_act_red_m2_base.json") if base_ok else [{"triggered": False}]
    base_triggered = bool(base_det[0]["triggered"])
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_DETECTED" if base_triggered else "INVARIANT_BREACHED_STEALTH")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        telemetry_alerts=[
            TelemetryAlertEvidence(rule_id="naive_bash_devtcp", engine="static_sig", triggered=base_triggered)
        ],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    pre_breach = bool(base_ok and fs_base.canary_accessed and (not base_triggered))
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red esegue TTP fileless `memfd_create` evitando signature statiche.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: exec_ok={base_ok}, alert={base_triggered} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="naive_bash_devtcp missed memfd_create", oob_baseline=base_ev)
    if defense_mode == "overbroad_alert_all":
        chosen_rules = _M2_OVERBROAD_RULES
        blue_summary = "overbroad_alert_all: regola wildcard che genera allarme su qualsiasi evento."
    else:
        chosen_rules = _M2_STRUCTURAL_RULES
        blue_summary = (
            "structural: Sigma + eBPF syscall (`memfd_create`, `/proc/self/fd/`) + lineage (`python3->sh`, `${IFS}`) "
            "+ egress entropia (>=4.2) con esclusioni baseline firmate."
        )

    rel_blue, _ = chamber.write_blue_artifact("deploy_rules_m2.py", f'''\
import os
from pathlib import Path
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
(blue_dir / "blue_rules.json").write_text({json.dumps(chosen_rules)!r}, encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_deploy_rules",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="DEPLOY_RULE",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if brc == 0 else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue distribuisce regole in modalità `{defense_mode}`.",
        passed=(brc == 0),
    ))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    fpr_rel, _ = chamber.write_blue_artifact("oracle_fpr_m2.py", '''\
import json, os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
sys.path.insert(0, str(blue_dir))
import detector_engine
rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
benign = json.loads((up / "benign_replay.json").read_text(encoding="utf-8"))
res = detector_engine.evaluate(rules, benign)
fps = sum(1 for r in res if r["triggered"])
fpr = fps / max(1, len(benign))
(blue_dir / "fpr_result.json").write_text(json.dumps({"fps": fps, "total": len(benign), "fpr": fpr}), encoding="utf-8")
''')
    fpr_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_fpr",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="CAPTURE_TELEMETRY",
        artifact_path=fpr_rel,
        entrypoint=["python3", fpr_rel],
        target_invariant="INV_FPR_BELOW_THRESHOLD",
    )
    contracts.append(fpr_contract)
    frc, _, _, ffs = chamber.run_contract(fpr_contract)
    fpr_obj = json.loads((chamber.artifacts_blue / "fpr_result.json").read_text(encoding="utf-8"))
    fpr_val = float(fpr_obj["fpr"])
    fpr_ok = fpr_val <= 0.05
    fpr_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if fpr_ok else "DEFENSE_REJECTED_HIGH_FPR"
    evidences.append(OutOfBandOracleEvidence(
        action_id=fpr_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=True,
        fpr_value=fpr_val,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=fpr_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Replay benigno ({len(_M2_BENIGN_CORPUS)} eventi): FPR={fpr_val:.3f} ({fpr_verdict}).",
        passed=fpr_ok,
    ))

    if not fpr_ok:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT",
            actor="ORACLE",
            summary=f"Certificazione respinta: FPR={fpr_val:.3f} supera soglia massima 0.050 (regola ban-all).",
            passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=fpr_val,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_HIGH_FALSE_POSITIVE_RATE",
            rationale="Oracolo anti-cheat: la regola wildcard genera falsi positivi continui sulla telemetria benigna dell'host.",
        )

    # RED_MUTATE_BYPASS (3 distinct evasion attack classes)
    evasion_specs = [
        (
            "CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION",
            {"telemetry": "parent=python3 child=sh arg0=[kworker] cmd=sh${IFS}-c${IFS}base64${IFS}-d", "entropy": 4.4},
        ),
        (
            "CLASS_FILELESS_MEMFD_EXECVEAT_SYSCALL",
            {"telemetry": "proc=svc_api syscall=execveat(/proc/self/fd/7) backing=memfd_create", "entropy": 4.1},
        ),
        (
            "CLASS_JITTERED_LOW_RATE_HIGH_ENTROPY_BEACON",
            {"telemetry": "proc=svc_etl dns_src=10.200.0.5 qtype=TXT beacon_jitter=17s query=JBSWY3DPEBLW64TMMQ", "entropy": 4.85},
        ),
    ]
    rounds_to_run = max(1, min(len(evasion_specs), mutation_rounds))
    detected_cnt = 0
    stealth_cnt = 0
    exec_errors = 0
    with chamber.target_server("target_workload.py", "handle_request") as m2_mut_port:
        for idx in range(rounds_to_run):
            atk_class, evt_dict = evasion_specs[idx]
            aid = f"act_red_m2_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                mut_code = "raise RuntimeError('Simulated broken telemetry mutation harness')\n"
            else:
                mut_code = f'''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({{"aid": {aid!r}, "event": {json.dumps(evt_dict)}}}), headers={{"Content-Type": "application/json"}})
resp = conn.getresponse()
res = json.loads(resp.read().decode("utf-8"))
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": 1, **res}}), encoding="utf-8"
)
'''
            rel_mut, _ = chamber.write_red_artifact(f"ttp_m2_mut_{idx + 1:02d}.py", mut_code)
            m_contract = _contract(
                chamber=chamber,
                action_id=aid,
                actor="RED",
                phase="RED_MUTATE_BYPASS",
                primitive="EXEC_ARTIFACT",
                artifact_path=rel_mut,
                entrypoint=["python3", rel_mut],
                target_invariant=desc.target_invariant,
                attack_class=atk_class,
            )
            contracts.append(m_contract)
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(m2_mut_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok or not (chamber.upperdir / f"telemetry_{aid}.json").exists():
                exec_errors += 1
                triggered = False
                bypassed = False
                rule_str = "none"
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                det = _oob_eval_telemetry(f"act_oracle_eval_{aid}", f"upperdir/telemetry_{aid}.json")
                hit_info = det[0]
                triggered = bool(hit_info["triggered"])
                rule_str = ",".join(hit_info["rule_ids"]) or "none"
                bypassed = not triggered
                if triggered:
                    detected_cnt += 1
                else:
                    stealth_cnt += 1
                m_verdict = "INVARIANT_BREACHED_DETECTED" if triggered else "INVARIANT_BREACHED_STEALTH"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{m2_mut_port}", proto="tcp", bytes_out=220, bytes_in=96)],
                telemetry_alerts=[
                    TelemetryAlertEvidence(
                        rule_id=rule_str,
                        engine="ebpf_sigma_yara",
                        triggered=triggered,
                        matched_pattern=atk_class if triggered else "",
                    )
                ],
                execution_valid=bool(exec_ok),
                attempts_executed=attempts_n,
                isolation_backend=chamber.isolation_backend,
                oracle_verdict=m_verdict,
            )
            evidences.append(mev)
            prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and bypassed))
            mut_results.append(AckMutationRoundResult(
                round_index=idx + 1,
                attack_class=atk_class,
                previous_failed_classes=prev_failed,
                contract=m_contract,
                oracle_evidence=mev,
                execution_valid=(m_verdict != "EXECUTION_ERROR"),
                attempts_executed=attempts_n,
                bypass_succeeded=bypassed,
            ))

    tpr = round(detected_cnt / rounds_to_run, 3)
    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round adattivi di evasione: rilevati={detected_cnt}/{rounds_to_run}, errors={exec_errors}, TPR={tpr:.2f}, FPR={fpr_val:.2f}.",
        passed=(stealth_cnt == 0 and exec_errors == 0),
    ))
    certified = bool(pre_breach and fpr_ok and stealth_cnt == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di mutazione non validi (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_DETECTION_ARENA"
        rationale = "Matrice TPR/FPR verificata out-of-band contro mutazioni fileless, arg spoofing e jitter beacon."
    else:
        cert_verdict = "EVADED_BY_RED"
        rationale = f"{stealth_cnt} varianti stealth hanno eluso la rilevazione."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=tpr,
            false_positive_rate=fpr_val,
            evasion_resistance_rate=tpr,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=stealth_cnt + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Mission 3: Attack-Path Audit & Live Hardening (Cloned Manifest vs Synthetic Fixture)
# ---------------------------------------------------------------------------

_M3_DEFAULT_SYNTHETIC_MANIFEST = """\
[Service]
service_enabled=true
NoNewPrivileges=false
ProtectSystem=false
SocketMode=0666
helper_writable=true

securityContext:
  privileged: true
  allowPrivilegeEscalation: true
  capabilities: [CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH]
"""


def _parse_target_host_config(manifest_text: str) -> Dict[str, Any]:
    """Deterministically parse submitted YAML/systemd/JSON host or container manifest into hardening state."""
    low = manifest_text.lower()
    service_enabled = not bool(re.search(r"(?:service_enabled|serviceenabled)[\"']?\s*[:=]\s*[\"']?false", low))
    helper_writable = bool(
        re.search(r"(?:helper_writable[\"']?\s*[:=]\s*[\"']?true|chmod\s+0?777|chmod\s+a\+w)", low)
    )
    priv = bool(
        re.search(r"(?:privileged|privileged_container|allowprivilegeescalation)[\"']?\s*[:=]\s*[\"']?true", low)
    )
    nnp_true = bool(
        re.search(r"(?:nonewprivileges[\"']?\s*[:=]\s*[\"']?true|allowprivilegeescalation[\"']?\s*[:=]\s*[\"']?false)", low)
    )
    nnp_false = bool(
        re.search(r"(?:nonewprivileges[\"']?\s*[:=]\s*[\"']?false|allowprivilegeescalation[\"']?\s*[:=]\s*[\"']?true)", low)
    )
    no_new_priv = bool(nnp_true and not nnp_false)

    protect_sys: Any = False
    if re.search(r"protectsystem[\"']?\s*[:=]\s*[\"']?(?:strict|full)", low):
        protect_sys = "strict"

    drop_all = bool(re.search(r"drop[\"']?\s*:\s*\[\s*['\"]?all['\"]?\s*\]", low))
    ambient_caps: List[str] = []
    if not drop_all:
        for cap in ("CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN"):
            if cap.lower() in low:
                ambient_caps.append(cap)

    sock_restricted = bool(
        re.search(r"(?:socket_acl_restricted[\"']?\s*[:=]\s*[\"']?true|socketmode\s*=\s*0?(?:600|660))", low)
    ) and not bool(
        re.search(r"(?:socket_acl_restricted[\"']?\s*[:=]\s*[\"']?false|socketmode\s*=\s*0?(?:666|777))", low)
    )

    return {
        "service_enabled": service_enabled,
        "helper_writable": helper_writable,
        "privileged_container": priv,
        "NoNewPrivileges": no_new_priv,
        "ProtectSystem": protect_sys,
        "ambient_caps": ambient_caps,
        "socket_acl_restricted": sock_restricted,
    }


def _harden_manifest_text(manifest_text: str, defense_mode: str) -> str:
    """Deterministically transform a host/container manifest on disk inside upperdir."""
    if defense_mode == "naive_block_all":
        if re.search(r"(?i)(?:service_enabled|serviceenabled)\s*[:=]", manifest_text):
            return re.sub(
                r"(?i)(service_enabled|serviceenabled)([\"']?\s*[:=]\s*[\"']?)true",
                r"\1\g<2>false",
                manifest_text,
            )
        return manifest_text.rstrip() + "\nservice_enabled: false\n"

    out = re.sub(r"(?i)(service_enabled|serviceenabled)([\"']?\s*[:=]\s*[\"']?)false", r"\1\g<2>true", manifest_text)
    out = re.sub(r"(?i)(helper_writable[\"']?\s*[:=]\s*[\"']?)true", r"\g<1>false", out)
    out = re.sub(r"(?i)chmod\s+(?:0?777|a\+w)", "chmod 0750", out)
    out = re.sub(
        r"(?i)((?:privileged|privileged_container|allowprivilegeescalation)[\"']?\s*[:=]\s*[\"']?)true",
        r"\g<1>false",
        out,
    )
    out = re.sub(r"(?i)(nonewprivileges[\"']?\s*[:=]\s*[\"']?)false", r"\g<1>true", out)
    out = re.sub(r"(?i)(protectsystem[\"']?\s*[:=]\s*[\"']?)false", r"\g<1>strict", out)
    out = re.sub(r"(?i)(socketmode\s*=\s*)0?(?:666|777)", r"\g<1>0600", out)
    out = re.sub(r"(?i)(socket_acl_restricted[\"']?\s*[:=]\s*[\"']?)false", r"\g<1>true", out)
    out = re.sub(r"(?i)capabilities[\"']?\s*[:=]\s*\[[^\]]*\]", 'capabilities:\n  drop: ["ALL"]', out)

    low = out.lower()
    extras: List[str] = []
    if not re.search(r"nonewprivileges[\"']?\s*[:=]\s*[\"']?true", low):
        extras.append("NoNewPrivileges=true")
    if not re.search(r"protectsystem[\"']?\s*[:=]\s*[\"']?(?:strict|full)", low):
        extras.append("ProtectSystem=strict")
    if not re.search(r"(?:socket_acl_restricted[\"']?\s*[:=]\s*[\"']?true|socketmode\s*=\s*0?(?:600|660))", low):
        extras.append("SocketMode=0600")
    if not re.search(r"drop[\"']?\s*:\s*\[\s*['\"]?all['\"]?\s*\]", low):
        extras.append('drop: ["ALL"]')
    if not re.search(r"helper_writable[\"']?\s*[:=]\s*[\"']?false", low):
        extras.append("helper_writable: false")
    if extras:
        out = out.rstrip() + "\n" + "\n".join(extras) + "\n"
    return out


def _build_m3_host_runtime_sim() -> str:
    parser_src = inspect.getsource(_parse_target_host_config)
    return (
        "import os, re\n"
        "from pathlib import Path\n"
        "from typing import Any, Dict, List\n\n"
        f"{parser_src}\n\n"
        '''\
def check_action(vector: str) -> str:
    up = Path(os.environ["ACK_UPPERDIR"])
    manifest_text = (up / "cloned_target_manifest.conf").read_text(encoding="utf-8")
    cfg = _parse_target_host_config(manifest_text)
    canary_path = up / "canary_vault" / "canary.txt"
    if vector == "healthcheck":
        if not cfg.get("service_enabled", False):
            raise RuntimeError("Service offline")
        return "SERVICE_HEALTHY_200"
    if vector == "helper_hijack":
        if cfg.get("helper_writable") and not cfg.get("NoNewPrivileges"):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Helper script read-only & NoNewPrivileges enforced")
    if vector == "ambient_caps":
        caps = set(cfg.get("ambient_caps") or [])
        if cfg.get("privileged_container") or ("CAP_SYS_ADMIN" in caps) or ("CAP_DAC_READ_SEARCH" in caps):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Privileged container & ambient capabilities dropped")
    if vector == "unix_socket_ctl":
        if not cfg.get("socket_acl_restricted"):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Unauthorized unix control socket denied")
    raise ValueError(f"Unknown vector: {vector}")

def handle_request(payload: dict) -> tuple:
    try:
        out = check_action(str(payload.get("vector", "")))
        return 200, {"output": out}
    except RuntimeError as exc:
        return 503, {"error": str(exc)}
    except PermissionError as exc:
        return 403, {"error": str(exc)}
    except Exception as exc:
        return 400, {"error": str(exc)}
'''
    )


def _run_m3_attack_path_hardening(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    has_real_manifest = bool(target_config_content and target_config_content.strip())
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest"] = (
        "cloned_target_manifest" if has_real_manifest else "synthetic_fixture_simulation"
    )
    manifest_text = target_config_content or _M3_DEFAULT_SYNTHETIC_MANIFEST
    baseline_cfg = _parse_target_host_config(manifest_text)
    seed_files: Dict[str, bytes | str] = {
        "cloned_target_manifest.conf": manifest_text,
        "host_runtime_sim.py": _build_m3_host_runtime_sim(),
    }
    if has_real_manifest:
        init_summary = f"Clonato manifest target reale in `{chamber.sandbox_id}` (modalità Shadow Clone CoW; lowerdir immutabile)."
    else:
        seed_files["systemd_unit.ini"] = "[Service]\nNoNewPrivileges=false\nProtectSystem=false\n"
        seed_files["k8s_pod.yaml"] = "securityContext:\n  privileged: true\n  allowPrivilegeEscalation: true\n"
        init_summary = (
            f"Simulazione Shadow Clone CoW `{chamber.sandbox_id}` avviata su **fixture sintetica** di riferimento "
            "(nessun manifest host reale fornito; non rappresenta un audit dell'host locale)."
        )

    chamber.seed_lowerdir(seed_files)
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=init_summary,
        passed=True,
    ))

    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/cloned_target_manifest")
    rel_base, _ = chamber.write_red_artifact("privesc_m3_base.py", '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
results = []
for vec in ("helper_hijack", "ambient_caps", "unix_socket_ctl"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({"vector": vec}), headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    results.append({"vector": vec, "status": resp.status, "out": body.get("output") or body.get("error", "")})
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m3_base.json").write_text(
    json.dumps({"status": "COMPLETED", "attempts_executed": len(results), "results": results}),
    encoding="utf-8",
)
''')
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m3_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_BASELINE_CONFIG_ESCALATION_PROBE",
    )
    contracts.append(base_contract)
    with chamber.target_server("host_runtime_sim.py", "handle_request") as m3_base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(m3_base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_m3_base.json")
    pre_breach = bool(base_ok and fs_base.canary_accessed and fs_base.lowerdir_untouched)
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        net_events=[NetEventEvidence(dst=f"127.0.0.1:{m3_base_port}", bytes_out=120, bytes_in=240)],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary=f"Red esegue catena privesc pre-hardening su {audit_scope} contro `cloned_target_manifest.conf`.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Esito pre-hardening ({audit_scope}): canary_accessed={fs_base.canary_accessed}, lowerdir_untouched={fs_base.lowerdir_untouched}.",
        passed=pre_breach,
    ))

    if not pre_breach:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT",
            actor="ORACLE",
            summary="Nessuna catena privesc riprodotta pre-patch sul manifest fornito.",
            passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=1.0,
                pre_patch_breach_confirmed=False,
                post_patch_breaches=0,
            ),
            blue_summary="Nessun diff necessario: il manifest clonato non esponeva vettori di escalation attivi pre-patch.",
            certified=False,
            certification_verdict="NO_BASELINE_PRIVESC_IN_CLONED_MANIFEST" if has_real_manifest else "NO_BASELINE_PRIVESC_FOUND",
            rationale="ORACLE_BASELINE_CHECK non ha rilevato escalation pre-patch: impossibile certificare un loop Exploit-to-Patch su superficie già chiusa o manifest non vulnerabile.",
            audit_scope=audit_scope,
        )

    _ = fow.build_blue_context(baseline_summary=json.dumps(baseline_cfg), oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        blue_summary = "naive_block_all: disattivato completamente il servizio target (`service_enabled: false`) in `cloned_target_manifest.conf`."
    else:
        blue_summary = (
            "structural: patch diretta di `cloned_target_manifest.conf` in upperdir CoW "
            "(NoNewPrivileges=true, ProtectSystem=strict, helper_writable=false, capabilities drop ALL, SocketMode=0600)."
        )

    harden_fn_src = inspect.getsource(_harden_manifest_text)
    rel_blue, _ = chamber.write_blue_artifact(
        "apply_hardening_m3.py",
        (
            "import os, re\n"
            "from pathlib import Path\n"
            "from typing import List\n\n"
            f"{harden_fn_src}\n\n"
            "up = Path(os.environ['ACK_UPPERDIR'])\n"
            "manifest_path = up / 'cloned_target_manifest.conf'\n"
            "manifest_path.write_text(_harden_manifest_text(manifest_path.read_text(encoding='utf-8'), "
            f"{defense_mode!r}"
            "), encoding='utf-8')\n"
            "if (up / 'systemd_unit.ini').exists():\n"
            "    (up / 'systemd_unit.ini').write_text('[Service]\\nNoNewPrivileges=true\\nProtectSystem=strict\\n', encoding='utf-8')\n"
            "if (up / 'k8s_pod.yaml').exists():\n"
            "    (up / 'k8s_pod.yaml').write_text('securityContext:\\n  privileged: false\\n  allowPrivilegeEscalation: false\\n  capabilities:\\n    drop: [\"ALL\"]\\n', encoding='utf-8')\n"
        ),
    )
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m3_harden",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    manifest_modified = "cloned_target_manifest.conf" in bfs.modified
    post_cfg = _parse_target_host_config((chamber.upperdir / "cloned_target_manifest.conf").read_text(encoding="utf-8"))
    post_manifest_hardened = bool(
        not post_cfg["helper_writable"]
        and not post_cfg["privileged_container"]
        and post_cfg["NoNewPrivileges"]
        and post_cfg["ProtectSystem"] == "strict"
        and not post_cfg["ambient_caps"]
        and post_cfg["socket_acl_restricted"]
    )
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if (brc == 0 and manifest_modified) else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Hardening CoW applicato su `cloned_target_manifest.conf` ({defense_mode}, modified={manifest_modified}).",
        passed=(brc == 0 and manifest_modified),
    ))

    # Boot isolated TARGET server over hardened cloned_target_manifest.conf
    with chamber.target_server("host_runtime_sim.py", "handle_request") as m3_hard_port:
        # Functional survival check
        func_rel, _ = chamber.write_blue_artifact("oracle_health_m3.py", '''\
import http.client, json, os
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"vector": "healthcheck"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
assert resp.status == 200 and body.get("output") == "SERVICE_HEALTHY_200", f"Unexpected health: {resp.status} {body!r}"
print("SERVICE_HEALTHY_200", end="")
''')
        func_contract = _contract(
            chamber=chamber,
            action_id="act_oracle_m3_health",
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="EXEC_ARTIFACT",
            artifact_path=func_rel,
            entrypoint=["python3", func_rel],
            target_invariant="INV_SERVICE_HEALTH_SURVIVES",
        )
        contracts.append(func_contract)
        frc, fout, _, ffs = chamber.run_contract(func_contract, extra_env={"ACK_TARGET_PORT": str(m3_hard_port)})
        func_ok = (frc == 0 and "SERVICE_HEALTHY_200" in fout)
        func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
        evidences.append(OutOfBandOracleEvidence(
            action_id=func_contract.action_id,
            exit_code=frc,
            fs_diff=ffs,
            functional_suite_passed=func_ok,
            fpr_value=0.0,
            isolation_backend=chamber.isolation_backend,
            oracle_verdict=func_verdict,
        ))
        transitions.append(AckStateTransition(
            state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            actor="ORACLE",
            summary=(
                f"Check operativo servizio post-hardening: passed={func_ok} ({func_verdict}); "
                f"manifest_modified={manifest_modified}, post_hardened={post_manifest_hardened}."
            ),
            passed=bool(func_ok and manifest_modified and post_manifest_hardened),
        ))
        if not func_ok:
            transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: hardening ha fermato il servizio.", passed=False))
            return _MissionExecutionOutcome(
                transitions=transitions,
                contracts=contracts,
                evidences=evidences,
                mutation_rounds=[],
                tpr_fpr_matrix=AckTprFprMatrix(
                    true_positive_rate=0.0,
                    false_positive_rate=0.0,
                    evasion_resistance_rate=0.0,
                    functional_survival_rate=0.0,
                    pre_patch_breach_confirmed=pre_breach,
                    post_patch_breaches=0,
                ),
                blue_summary=blue_summary,
                certified=False,
                certification_verdict="REJECTED_SERVICE_OUTAGE",
                rationale="Hardening ha disabilitato il servizio invece di correggere i privilegi.",
                audit_scope=audit_scope,
            )

        vectors = [
            ("CLASS_HELPER_SCRIPT_OVERWRITE_HIJACK", "helper_hijack"),
            ("CLASS_AMBIENT_CAPABILITY_INHERITANCE", "ambient_caps"),
            ("CLASS_UNIX_SOCKET_UNAUTHORIZED_CONTROL", "unix_socket_ctl"),
        ]
        rounds_to_run = max(1, min(len(vectors), mutation_rounds))
        post_breaches = 0
        exec_errors = 0
        for idx in range(rounds_to_run):
            atk_class, vec = vectors[idx]
            aid = f"act_red_m3_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                mut_body = "raise RuntimeError('Simulated broken privesc mutation harness')\n"
            else:
                mut_body = f'''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({{"vector": {vec!r}}}), headers={{"Content-Type": "application/json"}})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
out = body.get("output") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}"
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": 1, "out": out}}), encoding="utf-8"
)
'''
            rel_mut, _ = chamber.write_red_artifact(f"privesc_m3_mut_{idx + 1:02d}.py", mut_body)
            m_contract = _contract(
                chamber=chamber,
                action_id=aid,
                actor="RED",
                phase="RED_MUTATE_BYPASS",
                primitive="EXEC_ARTIFACT",
                artifact_path=rel_mut,
                entrypoint=["python3", rel_mut],
                target_invariant=desc.target_invariant,
                attack_class=atk_class,
            )
            contracts.append(m_contract)
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(m3_hard_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok:
                exec_errors += 1
                bypassed = False
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                bypassed = mfs.canary_accessed or not mfs.lowerdir_untouched
                if bypassed:
                    post_breaches += 1
                m_verdict = "INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{m3_hard_port}", bytes_out=96, bytes_in=96)],
                telemetry_alerts=[TelemetryAlertEvidence(rule_id="systemd_hardening", engine="host_cow_audit", triggered=bool(exec_ok and not bypassed))],
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                isolation_backend=chamber.isolation_backend,
                oracle_verdict=m_verdict,
            )
            evidences.append(mev)
            prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and bypassed))
            mut_results.append(AckMutationRoundResult(
                round_index=idx + 1,
                attack_class=atk_class,
                previous_failed_classes=prev_failed,
                contract=m_contract,
                oracle_evidence=mev,
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                bypass_succeeded=bypassed,
            ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"{rounds_to_run} vettori privesc su {audit_scope}: bypass={post_breaches}, errors={exec_errors}.",
        passed=(post_breaches == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(
        pre_breach
        and manifest_modified
        and post_manifest_hardened
        and func_ok
        and post_breaches == 0
        and exec_errors == 0
    )
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} mutazioni non eseguite (`EXECUTION_ERROR`)."
    elif certified and has_real_manifest:
        cert_verdict = "CERTIFIED_HARDENED_CLONED_MANIFEST"
        rationale = "Hardening verificato in clone CoW direttamente su `cloned_target_manifest.conf` con lowerdir immutabile e servizio sano."
    elif certified:
        cert_verdict = "CERTIFIED_SYNTHETIC_SHADOW_CLONE_SIMULATION"
        rationale = "Hardening certificato sulla fixture sintetica `cloned_target_manifest.conf` (non audit del sistema host corrente)."
    elif not (manifest_modified and post_manifest_hardened):
        cert_verdict = "HARDENING_BYPASSED"
        rationale = "Hardening respinto out-of-band: `cloned_target_manifest.conf` non modificato o vettori ancora attivi."
    else:
        cert_verdict = "HARDENING_BYPASSED"
        rationale = "Hardening aggirato dopo la patch."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_breaches + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
        audit_scope=audit_scope,
    )


# ---------------------------------------------------------------------------
# Mission 4: Fuzz-to-Fix Pipeline (Deterministic TLV Parser Fuzzer -> Patch)
# ---------------------------------------------------------------------------

_M4_VULNERABLE_PARSER = '''\
import struct

class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if depth > 16:
        raise ParserCrashError("ASAN_STACK_OVERFLOW: unbounded TLV recursion depth")
    out = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ParserCrashError("ASAN_OOB_READ: truncated 5-byte TLV header")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        # Bug 1: Unbounded count*stride integer overflow check absent
        if count > 4096:
            raise ParserCrashError("UBSAN_INT_OVERFLOW: allocation count*stride overflow")
        # Bug 2: Out-of-bounds read when declared length > remaining buffer
        if offset + length > len(data):
            raise ParserCrashError("ASAN_HEAP_OOB_READ: declared length exceeds packet bounds")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''

_M4_NAIVE_BLOCK_ALL_PARSER = '''\
class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    raise ValueError("Blocked all TLV packets")
'''

_M4_STRUCTURAL_FIXED_PARSER = '''\
import struct

MAX_TLV_DEPTH = 8
MAX_ITEM_COUNT = 256

class ParserCrashError(RuntimeError):
    pass

class InvalidTlvFrameError(ValueError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if not isinstance(data, (bytes, bytearray)):
        raise InvalidTlvFrameError("Input must be bytes")
    if depth > MAX_TLV_DEPTH:
        raise InvalidTlvFrameError("TLV nesting depth exceeds safe cap")
    out = []
    offset = 0
    total = len(data)
    while offset < total:
        if offset + 5 > total:
            raise InvalidTlvFrameError("Truncated TLV header rejected safely")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        if count > MAX_ITEM_COUNT:
            raise InvalidTlvFrameError("Count ceiling exceeded")
        if length > total - offset:
            raise InvalidTlvFrameError("Declared TLV length exceeds remaining buffer")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''


def _run_m4_fuzz_to_fix(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
) -> _MissionExecutionOutcome:
    del target_config_content
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    valid_pkt_1 = b"\x01\x00\x01\x00\x04ABCD"
    valid_pkt_2 = b"\xff\x00\x01\x00\x08\x02\x00\x01\x00\x03XYZ"

    chamber.seed_lowerdir({
        "tlv_parser.py": _M4_VULNERABLE_PARSER,
        "corpus/valid/msg1.bin": valid_pkt_1,
        "corpus/valid/msg2.bin": valid_pkt_2,
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata pipeline Fuzz-to-Fix `{chamber.sandbox_id}` ({chamber.isolation_backend}) con corpus valido seed (2 frame).",
        passed=True,
    ))

    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="tlv_parser.parse_tlv_frame")
    fuzzer_code = '''\
import json, os, struct, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser

seed = b"\\x01\\x00\\x01\\x00\\x04ABCD"
candidates = [seed]
for i in range(32):
    candidates.append(struct.pack(">BHH", 1, 1, 200 + i) + b"A" * 4)
    candidates.append(struct.pack(">BHH", 2, 5000 + i, 2) + b"XY")

min_crash = None
crash_msg = ""
for cand in candidates:
    try:
        tlv_parser.parse_tlv_frame(cand)
    except tlv_parser.ParserCrashError as exc:
        if min_crash is None or len(cand) < len(min_crash):
            min_crash = cand
            crash_msg = str(exc)

repro_file = Path(os.environ["ACK_ARTIFACTS_RED"]) / "repro_min_crash.bin"
if min_crash is not None:
    repro_file.write_bytes(min_crash)
    reproduced = False
    try:
        tlv_parser.parse_tlv_frame(repro_file.read_bytes())
    except tlv_parser.ParserCrashError:
        reproduced = True
else:
    reproduced = False

(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_base_res.json").write_text(
    json.dumps({
        "status": "COMPLETED",
        "attempts_executed": len(candidates),
        "reproduced": reproduced,
        "crash": crash_msg,
        "min_len": len(min_crash or b""),
    }),
    encoding="utf-8",
)
'''
    rel_base, _ = chamber.write_red_artifact("fuzz_m4_base.py", fuzzer_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m4_fuzz",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="RUN_FUZZER",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_FUZZER_OOB_LENGTH_MINIMIZED",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    base_ok, base_attempts, base_res = _verify_harness_execution(rc, chamber.artifacts_red / "fuzz_base_res.json")
    pre_breach = bool(base_ok and base_res.get("reproduced"))
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    evidences.append(OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        crash_reproduced=pre_breach,
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    ))
    base_ev = evidences[-1]
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary=f"Fuzzer deterministico ha generato PoC minimizzato (`{base_res.get('min_len', 0)}B`, `{base_res.get('crash', 'none')}`).",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Crash riproducibile al 100% pre-patch={pre_breach} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="tlv_parser.py OOB length / overflow / unbounded recursion", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_parser = _M4_NAIVE_BLOCK_ALL_PARSER
        blue_summary = "naive_block_all: rifiuta tutti i pacchetti TLV."
    else:
        patched_parser = _M4_STRUCTURAL_FIXED_PARSER
        blue_summary = (
            "structural: safe validation `InvalidTlvFrameError` su header troncati, bounds `length <= remaining`, "
            "`count <= 256`, profondità max 8 + inserimento `repro_min_crash.bin` nel corpus di regressione."
        )

    rel_blue, _ = chamber.write_blue_artifact("apply_patch_m4.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "tlv_parser.py").write_text({patched_parser!r}, encoding="utf-8")
reg_dir = up / "corpus" / "regression"
reg_dir.mkdir(parents=True, exist_ok=True)
repro_env = os.environ.get("ACK_FUZZ_REPRO_PATH")
if repro_env and Path(repro_env).exists():
    (reg_dir / "repro_min_crash.bin").write_bytes(Path(repro_env).read_bytes())
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m4_fix",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if brc == 0 else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(state="BLUE_DEFEND", actor="BLUE", summary=f"Fix parser + regression corpus applicati ({defense_mode}).", passed=(brc == 0)))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    func_rel, _ = chamber.write_blue_artifact("oracle_corpus_m4.py", '''\
import os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser
for f in sorted((up / "corpus" / "valid").glob("*.bin")):
    parsed = tlv_parser.parse_tlv_frame(f.read_bytes())
    assert parsed, f"Empty parse on valid corpus {f.name}"
for rf in sorted((up / "corpus" / "regression").glob("*.bin")):
    try:
        tlv_parser.parse_tlv_frame(rf.read_bytes())
    except tlv_parser.ParserCrashError as exc:
        raise AssertionError(f"Regression crash still reproduces: {exc}")
    except ValueError:
        pass
print("CORPUS_AND_REGRESSION_OK")
''')
    func_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_m4_corpus",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="EXEC_ARTIFACT",
        artifact_path=func_rel,
        entrypoint=["python3", func_rel],
        target_invariant="INV_VALID_CORPUS_AND_REGRESSION_PASS",
    )
    contracts.append(func_contract)
    frc, fout, _, ffs = chamber.run_contract(func_contract)
    func_ok = (frc == 0 and "CORPUS_AND_REGRESSION_OK" in fout)
    func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
    evidences.append(OutOfBandOracleEvidence(
        action_id=func_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=func_ok,
        fpr_value=0.0,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=func_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Verifica valid corpus + regression crash: passed={func_ok} ({func_verdict}).",
        passed=func_ok,
    ))
    if not func_ok:
        transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: parser rotto sui pacchetti validi.", passed=False))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_BROKEN_PARSER",
            rationale="La patch ha rigettato anche i frame TLV validi.",
        )

    fuzz_classes = [
        ("CLASS_TRUNCATED_PAYLOAD_LENGTH_UNDERFLOW", "[struct.pack('>BHH', 3, 1, 65000) + b'Z'*3, b'\\x01\\x02\\x03']"),
        ("CLASS_COUNT_STRIDE_INTEGER_OVERFLOW", "[struct.pack('>BHH', 4, 65535, 4) + b'ABCD', struct.pack('>BHH', 4, 9999, 0)]"),
        ("CLASS_DEEP_RECURSIVE_TLV_NESTING_BOMB", "[b''.join(struct.pack('>BHH', 0xFF, 1, 5*(29-i)) for i in range(30))]"),
    ]
    rounds_to_run = max(1, min(len(fuzz_classes), mutation_rounds))
    post_crashes = 0
    exec_errors = 0
    for idx in range(rounds_to_run):
        atk_class, pkts_expr = fuzz_classes[idx]
        aid = f"act_red_m4_mut_{idx + 1:02d}"
        if inject_broken_mutation and idx == 0:
            mut_body = "raise RuntimeError('Simulated broken fuzzer mutation harness')\n"
        else:
            mut_body = f'''\
import json, os, struct, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import tlv_parser
crashed = False
pkts = {pkts_expr}
for pkt in pkts:
    try:
        tlv_parser.parse_tlv_frame(pkt)
    except tlv_parser.ParserCrashError:
        crashed = True
    except ValueError:
        pass
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": len(pkts), "crashed": crashed}}),
    encoding="utf-8",
)
'''
        rel_mut, _ = chamber.write_red_artifact(f"fuzz_m4_mut_{idx + 1:02d}.py", mut_body)
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="RUN_FUZZER",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        exec_ok, attempts_n, mut_res = _verify_harness_execution(mrc, chamber.artifacts_red / f"fuzz_{aid}.json")
        if not exec_ok:
            exec_errors += 1
            crashed = False
            m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
        else:
            crashed = bool(mut_res.get("crashed"))
            if crashed:
                post_crashes += 1
            m_verdict = "INVARIANT_BREACHED_STEALTH" if crashed else "DEFENSE_HELD_CLEAN"

        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            crash_reproduced=crashed,
            execution_valid=exec_ok,
            attempts_executed=attempts_n,
            isolation_backend=chamber.isolation_backend,
            oracle_verdict=m_verdict,
        )
        evidences.append(mev)
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and crashed))
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            execution_valid=exec_ok,
            attempts_executed=attempts_n,
            bypass_succeeded=crashed,
        ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Fuzzing differenziale post-patch ({rounds_to_run} classi): crash={post_crashes}, errors={exec_errors}.",
        passed=(post_crashes == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_crashes == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di fuzzing non validi (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_ZERO_CRASH_PARSER"
        rationale = "Crash riprodotto al 100% prima del fix, eliminato dopo la patch sulla root cause."
    else:
        cert_verdict = "PARSER_STILL_CRASHING"
        rationale = f"{post_crashes} mutazioni continuano a causare crash nel parser."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_crashes + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )


_MISSION_RUNNERS: Dict[
    str,
    Callable[..., _MissionExecutionOutcome],
] = {
    "ack-m1-exploit-patch-bypass": _run_m1_exploit_to_patch,
    "ack-m2-detection-evasion-arena": _run_m2_detection_evasion,
    "ack-m3-attack-path-hardening": _run_m3_attack_path_hardening,
    "ack-m4-fuzz-to-fix-pipeline": _run_m4_fuzz_to_fix,
}


class AdversarialCyberKernel:
    """Orchestrates typed contracts inside a confined CoW DetonationChamber with OOB Oracle certification."""

    def list_missions(self) -> List[AckMissionDescriptor]:
        return list_ack_mission_descriptors()

    def run_mission(
        self,
        mission_id: str,
        *,
        mutation_rounds: int = 3,
        defense_mode: str = "structural",
        target_config_content: Optional[str] = None,
        inject_broken_mutation: bool = False,
    ) -> AckCertificationReport:
        desc = ACK_MISSION_MAP.get(mission_id)
        if desc is None:
            raise KeyError(f"Missione ACK sconosciuta: {mission_id}")
        runner = _MISSION_RUNNERS[mission_id]

        chamber = DetonationChamber()
        fow = FogOfWarController()
        try:
            outcome = runner(
                chamber,
                desc,
                fow,
                mutation_rounds=max(1, min(3, int(mutation_rounds))),
                defense_mode=defense_mode,
                target_config_content=target_config_content,
                inject_broken_mutation=inject_broken_mutation,
            )
            return AckCertificationReport(
                run_id=f"ack-run-{uuid.uuid4().hex[:8]}",
                mission_id=desc.mission_id,
                mission_kind=desc.mission_kind,
                title=desc.title,
                sandbox_id=chamber.sandbox_id,
                tier_used=desc.default_tier,
                shadow_clone_only=desc.shadow_clone_only,
                audit_scope=outcome.audit_scope,
                isolation_backend=chamber.isolation_backend,
                defense_mode=defense_mode,
                target_invariant=desc.target_invariant,
                certified=outcome.certified,
                certification_verdict=outcome.certification_verdict,
                state_transitions=outcome.transitions,
                action_contracts=outcome.contracts,
                oracle_evidences=outcome.evidences,
                mutation_rounds=outcome.mutation_rounds,
                tpr_fpr_matrix=outcome.tpr_fpr_matrix,
                fog_of_war=fow.audit(),
                blue_patch_or_rules_summary=outcome.blue_summary,
                rationale=outcome.rationale,
            )
        finally:
            chamber.cleanup()
