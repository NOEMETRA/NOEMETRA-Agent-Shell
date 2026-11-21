"""Copy-on-Write DetonationChamber and OS Job/rlimit + audit-hook confinement boundary."""

from __future__ import annotations

import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from hermes_cyber.ack.catalog import _ALLOWED_BINARIES, _sha256_bytes
from hermes_cyber.ack.runner_templates import _CONFINED_RUNNER_SOURCE, _TARGET_SERVER_SOURCE
from hermes_cyber.models import ConstrainedActionContract, FsDiffEvidence


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
        self._trusted_upper_hashes: Dict[str, str] = {}

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
        self._trusted_upper_hashes = self.snapshot_tree(self.upperdir)

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
        enriched_policy = dict(policy)
        env: Dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": str(self.upperdir),
            "TMP": str(self.upperdir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ACK_SANDBOX_ID": self.sandbox_id,
            "ACK_UPPERDIR": str(self.upperdir),
        }
        if enriched_policy.get("actor") in ("BLUE", "TARGET"):
            site_dirs = list(dict.fromkeys(
                str(Path(p).resolve())
                for p in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"))
                if p and Path(p).is_dir()
            ))
            if site_dirs:
                enriched_policy["extra_py_roots"] = site_dirs
                env["PYTHONPATH"] = os.pathsep.join(site_dirs)
        env["ACK_CONFINE_POLICY"] = json.dumps(enriched_policy)
        return env

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
        raw_mod_path = self.upperdir / target_module
        if raw_mod_path.is_symlink():
            raise PermissionError(f"Target module cannot be a symlink: {target_module}")
        mod_path = raw_mod_path.resolve()
        if not mod_path.is_relative_to(self.upperdir) or not mod_path.exists():
            raise FileNotFoundError(f"Modulo target non trovato in upperdir: {target_module}")
        expected_hash = self._trusted_upper_hashes.get(target_module)
        actual_hash = _sha256_bytes(mod_path.read_bytes())
        if not expected_hash or actual_hash != expected_hash:
            raise PermissionError(
                f"Target module integrity check failed for {target_module}: untrusted modification detected"
            )

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
        if contract.actor == "BLUE" and contract.primitive == "APPLY_DIFF" and rc == 0:
            self._trusted_upper_hashes = after_upper
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
