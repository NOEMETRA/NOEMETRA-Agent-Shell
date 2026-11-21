"""ACK Workspace Mode: stage real PC Python parsers in isolated copy/git worktree & apply verified patches."""

from __future__ import annotations

import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.ack.catalog import _sha256_bytes
from hermes_cyber.models import AckWorkspaceModeType

_SKIP_COPY_DIRS = frozenset({
    "__pycache__", ".git", ".venv", "venv", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", "secrets", ".secrets",
})
_SENSITIVE_EXTS = frozenset({".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ppk", ".gpg", ".asc", ".age", ".secret"})
_SENSITIVE_FILENAMES = frozenset({
    ".netrc", ".pypirc", ".npmrc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml",
})
_MAX_STAGED_FILES = 2000
_MAX_STAGED_FILE_BYTES = 2 * 1024 * 1024
_MAX_STAGED_TOTAL_BYTES = 32 * 1024 * 1024


def is_sensitive_workspace_file(rel_path: Path) -> bool:
    """Return True if *rel_path* matches secret/key/credential files that must never be staged or persisted."""
    if any(part.lower() in _SKIP_COPY_DIRS for part in rel_path.parts[:-1]):
        return True
    name = rel_path.name
    low = name.lower()
    ext = rel_path.suffix.lower()
    if low == ".env" or (low.startswith(".env.") and not low.endswith((".example", ".sample", ".template"))):
        return True
    if low in _SENSITIVE_FILENAMES or ext in _SENSITIVE_EXTS:
        return True
    if (
        ("service_account" in low or "service-account" in low or "private_key" in low or "credentials" in low)
        and ext in (".json", ".yaml", ".yml", ".toml", ".txt", ".xml")
    ):
        return True
    return False


def _cleanup_git_worktree(repo_root: Optional[Path], wt_dir: Optional[Path]) -> None:
    if repo_root is not None and wt_dir is not None:
        try:
            subprocess.run(
                ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(wt_dir)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            pass
        shutil.rmtree(wt_dir, ignore_errors=True)
        try:
            subprocess.run(
                ["git", "-C", str(repo_root), "worktree", "prune"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            pass


@dataclass
class WorkspaceStagedTarget:
    target_file_path: str
    target_filename: str
    target_rel_path: str
    module_name: str
    target_function: str
    workspace_mode: AckWorkspaceModeType
    original_sha256: str
    original_source: str
    param_type_hint: str
    extra_files: Dict[str, bytes] = field(default_factory=dict)
    valid_corpus: List[Dict[str, Any]] = field(default_factory=list)
    user_supplied_corpus: bool = False
    worktree_repo_root: Optional[Path] = None
    worktree_dir: Optional[Path] = None

    def cleanup_staged_worktree(self) -> None:
        _cleanup_git_worktree(self.worktree_repo_root, self.worktree_dir)


def compute_unified_diff(original_text: str, patched_text: str, rel_path: str) -> str:
    """Compute a unified diff between original_text and patched_text for persistent patch.diff delivery."""
    diff_lines = difflib.unified_diff(
        original_text.splitlines(keepends=True),
        patched_text.splitlines(keepends=True),
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
    )
    return "".join(diff_lines)


def _infer_param_type_hint(source_code: str, target_function: str) -> str:
    """Inspect target_function signature and AST body to infer bytes vs str vs dict input expectations."""
    tree = ast.parse(source_code)
    fn_node: Optional[ast.FunctionDef] = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == target_function:
            fn_node = node
            break
    if fn_node is None:
        raise ValueError(f"Funzione '{target_function}' non trovata come funzione top-level nel file target.")

    pos_args = list(fn_node.args.posonlyargs) + list(fn_node.args.args)
    if not pos_args:
        raise ValueError(f"Funzione '{target_function}' deve accettare almeno un argomento di input.")
    first_arg = pos_args[0]
    if first_arg.annotation is not None:
        ann_text = ast.unparse(first_arg.annotation).lower()
        if "bytes" in ann_text or "bytearray" in ann_text:
            return "bytes"
        if "dict" in ann_text or "mapping" in ann_text:
            return "dict"
        if "str" in ann_text:
            return "str"

    fn_src = ast.get_source_segment(source_code, fn_node) or ""
    low = fn_src.lower()
    if "struct.unpack" in low or "memoryview" in low or "from_bytes" in low or "decode(" in low:
        return "bytes"
    if "json.loads" in low or ".split(" in low or ".splitlines(" in low:
        return "str"
    return "bytes" if "bytes" in first_arg.arg.lower() or "raw" in first_arg.arg.lower() else "str"


def _build_valid_corpus_entries(
    *,
    param_type_hint: str,
    valid_corpus_dir: Optional[str],
    valid_inputs: Optional[List[Any]],
) -> Tuple[List[Dict[str, Any]], bool]:
    entries: List[Dict[str, Any]] = []
    if valid_inputs is not None:
        for idx, item in enumerate(valid_inputs[:64]):
            if isinstance(item, dict) and item.get("encoding") == "hex" and isinstance(item.get("data"), str):
                entries.append({"name": f"input_{idx + 1}", "kind": "bytes", "data": item["data"]})
            elif isinstance(item, (bytes, bytearray)):
                entries.append({"name": f"input_{idx + 1}", "kind": "bytes", "data": bytes(item).hex()})
            elif param_type_hint == "bytes" and isinstance(item, str):
                entries.append({"name": f"input_{idx + 1}", "kind": "bytes", "data": item.encode("utf-8").hex()})
            else:
                entries.append({"name": f"input_{idx + 1}", "kind": "json", "data": item})
        return entries, True

    if valid_corpus_dir:
        cdir = Path(valid_corpus_dir).resolve()
        if not cdir.is_dir():
            raise FileNotFoundError(f"Directory valid_corpus_dir non trovata: {valid_corpus_dir}")
        files = sorted(p for p in cdir.iterdir() if p.is_file())[:32]
        for fpath in files:
            raw_bytes = fpath.read_bytes()
            if len(raw_bytes) > 512 * 1024:
                continue
            if param_type_hint == "bytes" or fpath.suffix.lower() in (".bin", ".dat", ".tlv", ".raw"):
                entries.append({"name": fpath.name, "kind": "bytes", "data": raw_bytes.hex()})
            elif fpath.suffix.lower() == ".json" and param_type_hint == "dict":
                try:
                    entries.append({"name": fpath.name, "kind": "json", "data": json.loads(raw_bytes.decode("utf-8"))})
                except Exception:
                    entries.append({"name": fpath.name, "kind": "json", "data": raw_bytes.decode("utf-8", errors="replace")})
            else:
                entries.append({"name": fpath.name, "kind": "json", "data": raw_bytes.decode("utf-8", errors="replace")})
        return entries, True

    return [], False


def stage_python_parser_workspace(
    target_file_path: str,
    target_function: str,
    *,
    valid_corpus_dir: Optional[str] = None,
    valid_inputs: Optional[List[Any]] = None,
    workspace_mode: AckWorkspaceModeType = "isolated_copy",
) -> WorkspaceStagedTarget:
    """Stage a real PC Python parser file in an isolated copy or git worktree without modifying the original."""
    if not str(target_file_path or "").strip():
        raise ValueError("Parametro 'target_file_path' richiesto in Workspace Mode.")
    if not str(target_function or "").strip() or not str(target_function).isidentifier():
        raise ValueError(f"Nome funzione parser non valido: {target_function!r}")

    src_path = Path(target_file_path).resolve()
    if not src_path.is_file():
        raise FileNotFoundError(f"File target Python non trovato: {target_file_path}")
    if src_path.suffix.lower() != ".py":
        raise ValueError(f"M4 Workspace Mode supporta file .py; ricevuto: {src_path.name}")

    raw_bytes = src_path.read_bytes()
    orig_sha = _sha256_bytes(raw_bytes)
    orig_text = raw_bytes.decode("utf-8")
    param_hint = _infer_param_type_hint(orig_text, str(target_function).strip())

    actual_mode: AckWorkspaceModeType = "isolated_copy"
    wt_repo_root: Optional[Path] = None
    wt_dir: Optional[Path] = None

    if workspace_mode == "git_worktree":
        try:
            rev = subprocess.run(
                ["git", "-C", str(src_path.parent), "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if rev.returncode == 0 and rev.stdout.strip():
                candidate_repo = Path(rev.stdout.strip()).resolve()
                head_chk = subprocess.run(
                    ["git", "-C", str(candidate_repo), "rev-parse", "--verify", "HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if head_chk.returncode == 0:
                    tmp_wt = Path(tempfile.mkdtemp(prefix="ack_wt_")).resolve()
                    shutil.rmtree(tmp_wt, ignore_errors=True)
                    add_wt = subprocess.run(
                        ["git", "-C", str(candidate_repo), "worktree", "add", "--detach", str(tmp_wt), "HEAD"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if add_wt.returncode == 0 and tmp_wt.exists():
                        actual_mode = "git_worktree"
                        wt_repo_root = candidate_repo
                        wt_dir = tmp_wt
        except Exception:
            actual_mode = "isolated_copy"

    try:
        # Stage project/package Python modules + non-.py resources preserving subdirectory layout,
        # and ensure git_worktree matches live workspace files cleanly.
        project_root = src_path.parent
        if wt_repo_root is not None and src_path.is_relative_to(wt_repo_root):
            project_root = wt_repo_root
        else:
            cur = src_path.parent
            while (cur / "__init__.py").is_file() and cur.parent != cur:
                project_root = cur.parent
                cur = cur.parent

        target_rel_path = src_path.relative_to(project_root).as_posix()
        extra_files: Dict[str, bytes] = {}
        total_bytes = len(raw_bytes)
        for root_s, dirs, files in os.walk(project_root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_COPY_DIRS)
            rpath = Path(root_s)
            for fname in sorted(files):
                fpath = rpath / fname
                if fpath == src_path or fpath.suffix.lower() == ".pyc" or not fpath.is_file():
                    continue
                rel_p = fpath.relative_to(project_root)
                if is_sensitive_workspace_file(rel_p):
                    continue
                rel_str = rel_p.as_posix()
                try:
                    content_b = fpath.read_bytes()
                except OSError as exc:
                    raise ValueError(f"Impossibile leggere dipendenza workspace '{rel_str}': {exc}") from exc
                if len(content_b) > _MAX_STAGED_FILE_BYTES:
                    raise ValueError(
                        f"File workspace '{rel_str}' supera il limite per staging isolato ({_MAX_STAGED_FILE_BYTES} byte)."
                    )
                if len(extra_files) + 1 > _MAX_STAGED_FILES or total_bytes + len(content_b) > _MAX_STAGED_TOTAL_BYTES:
                    raise ValueError(
                        f"Workspace '{project_root}' troppo grande per staging completo "
                        f"(limite: {_MAX_STAGED_FILES} file / {_MAX_STAGED_TOTAL_BYTES} byte)."
                    )
                extra_files[rel_str] = content_b
                total_bytes += len(content_b)

        if wt_dir is not None and wt_repo_root is not None:
            wt_target = wt_dir / target_rel_path
            wt_target.parent.mkdir(parents=True, exist_ok=True)
            wt_target.write_bytes(raw_bytes)
            for rel_str, res_bytes in extra_files.items():
                dest_h = wt_dir / rel_str
                dest_h.parent.mkdir(parents=True, exist_ok=True)
                dest_h.write_bytes(res_bytes)

        valid_corpus, user_supplied = _build_valid_corpus_entries(
            param_type_hint=param_hint,
            valid_corpus_dir=valid_corpus_dir,
            valid_inputs=valid_inputs,
        )

        return WorkspaceStagedTarget(
            target_file_path=str(src_path),
            target_filename=src_path.name,
            target_rel_path=target_rel_path,
            module_name=src_path.stem,
            target_function=str(target_function).strip(),
            workspace_mode=actual_mode,
            original_sha256=orig_sha,
            original_source=orig_text,
            param_type_hint=param_hint,
            extra_files=extra_files,
            valid_corpus=valid_corpus,
            user_supplied_corpus=user_supplied,
            worktree_repo_root=wt_repo_root,
            worktree_dir=wt_dir,
        )
    except BaseException:
        _cleanup_git_worktree(wt_repo_root, wt_dir)
        raise


def apply_ack_run_patch(
    runs_dir: Path,
    run_id: str,
    *,
    confirm_apply: bool = False,
) -> Dict[str, Any]:
    """Explicitly apply a verified Workspace Mode patch onto the original PC file after SHA-256 drift check."""
    if not re.match(r"^[A-Za-z0-9_-]+$", str(run_id or "")):
        raise ValueError(f"run_id ACK non valido: {run_id!r}")
    if confirm_apply is not True:
        raise PermissionError(
            "Modifica al progetto originale negata: è richiesta conferma esplicita (confirm_apply=True)."
        )

    runs_root = runs_dir.resolve()
    run_dir = (runs_root / run_id).resolve()
    if run_dir.parent != runs_root:
        raise ValueError(f"Percorso run_id non valido: {run_id!r}")
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest della run ACK non trovato: {run_id}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("run_id") != run_id:
        raise ValueError(f"Manifest run_id non corrispondente ({manifest.get('run_id')!r} != {run_id!r}).")
    if not manifest.get("certified"):
        raise ValueError(f"Impossibile applicare patch da una run non certificata ({manifest.get('certification_verdict')}).")

    ws = manifest.get("workspace_target")
    if not isinstance(ws, dict) or not ws.get("target_file_path"):
        raise ValueError("La run selezionata non ha un target Workspace Mode applicabile su disco.")

    patch_text = (run_dir / "patch.diff").read_text(encoding="utf-8") if (run_dir / "patch.diff").exists() else ""
    if not patch_text.strip():
        raise ValueError("patch.diff vuoto: nessuna modifica da applicare.")

    orig_path = Path(ws["target_file_path"]).resolve()
    if not orig_path.is_file():
        raise FileNotFoundError(f"File target originale non più presente: {orig_path}")

    patched_root = (run_dir / "patched_target").resolve()
    rel_snap_path = str(ws.get("target_rel_path") or orig_path.name).replace("\\", "/").lstrip("/")
    patched_snapshot = (patched_root / rel_snap_path).resolve()
    if not patched_snapshot.is_relative_to(patched_root) or not patched_snapshot.is_file():
        raise FileNotFoundError(f"Artefatto patched_target mancante in {run_dir}")

    sha_map = manifest.get("sha256")
    if not isinstance(sha_map, dict):
        raise ValueError("Manifest privo di mappa integrità SHA-256: applicazione annullata.")
    rel_patched_key = f"patched_target/{patched_snapshot.relative_to(patched_root).as_posix()}"
    expected_patched_sha = str(sha_map.get(rel_patched_key) or "")
    patched_bytes = patched_snapshot.read_bytes()
    patched_sha = _sha256_bytes(patched_bytes)
    if not expected_patched_sha or patched_sha != expected_patched_sha:
        raise ValueError(
            f"Integrità snapshot compromessa per {rel_patched_key}: SHA-256 attuale ({patched_sha[:12]}) "
            f"non corrisponde al manifest ({expected_patched_sha[:12]}). Applicazione annullata."
        )
    expected_diff_sha = str(sha_map.get("patch.diff") or "")
    if not expected_diff_sha or _sha256_bytes((run_dir / "patch.diff").read_bytes()) != expected_diff_sha:
        raise ValueError("Integrità compromessa o checksum mancante per patch.diff.")

    current_sha = _sha256_bytes(orig_path.read_bytes())
    expected_sha = str(ws.get("original_sha256") or "")
    if current_sha != expected_sha:
        raise ValueError(
            f"Drift rilevato sul file originale {orig_path.name}: SHA-256 attuale ({current_sha[:12]}) "
            f"non corrisponde allo stato iniziale ({expected_sha[:12]}). Applicazione annullata."
        )

    backup_dir = run_dir / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{orig_path.name}.orig"
    if not backup_path.exists():
        backup_path.write_bytes(orig_path.read_bytes())

    orig_path.write_bytes(patched_bytes)
    applied_at = datetime.now(timezone.utc).isoformat()

    ws["patch_applied"] = True
    ws["applied_at"] = applied_at
    ws["applied_sha256"] = patched_sha
    ws["backup_path"] = str(backup_path)
    manifest["workspace_target"] = ws
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    report_path = run_dir / "report.json"
    if report_path.exists():
        rep_obj = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(rep_obj.get("workspace_target"), dict):
            rep_obj["workspace_target"]["patch_applied"] = True
            rep_obj["workspace_target"]["applied_at"] = applied_at
            report_path.write_text(json.dumps(rep_obj, indent=2), encoding="utf-8")
            sha_map = manifest.get("sha256")
            if isinstance(sha_map, dict):
                sha_map["report.json"] = _sha256_bytes(report_path.read_bytes())
                manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "run_id": run_id,
        "target_file_path": str(orig_path),
        "patch_applied": True,
        "applied_at": applied_at,
        "original_sha256": expected_sha,
        "patched_sha256": patched_sha,
        "backup_path": str(backup_path),
    }
