"""ACK Workspace Mode: stage real PC Python parsers in isolated copy/git worktree & apply verified patches."""

from __future__ import annotations

import ast
import difflib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
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


class _OversizedStagedFileError(ValueError):
    """Raised when a regular file exceeds the bounded staging byte limit."""


def _read_bounded_regular_file(resolved: Path, max_bytes: int, label: str) -> bytes:
    """Stat-before-read + bounded read enforcing regular file type and max byte limit."""
    try:
        st = resolved.stat()
    except OSError as exc:
        raise ValueError(f"Impossibile accedere al file workspace '{label}': {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"File workspace '{label}' non è un file regolare.")
    if st.st_size > max_bytes:
        raise _OversizedStagedFileError(
            f"File workspace '{label}' supera il limite per staging isolato ({max_bytes} byte)."
        )
    try:
        with resolved.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ValueError(f"Impossibile leggere file workspace '{label}': {exc}") from exc
    if len(data) > max_bytes:
        raise _OversizedStagedFileError(
            f"File workspace '{label}' supera il limite per staging isolato ({max_bytes} byte)."
        )
    return data


def _resolve_in_perimeter_file(raw_path: Path, perimeter_root: Path, label: str) -> Path:
    """Resolve *raw_path* rejecting broken symlinks or resolved paths escaping *perimeter_root*."""
    root_res = perimeter_root.resolve()
    if raw_path.is_symlink():
        try:
            resolved = raw_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Symlink interrotto rifiutato in '{label}': {raw_path}") from exc
        if not resolved.is_relative_to(root_res):
            raise ValueError(f"Symlink fuori dal perimetro {label} rifiutato: '{raw_path}' -> '{resolved}'")
        return resolved
    resolved = raw_path.resolve()
    if not resolved.is_relative_to(root_res):
        raise ValueError(f"Percorso fuori dal perimetro {label} rifiutato: '{raw_path}' -> '{resolved}'")
    return resolved


@dataclass(frozen=True)
class AckSemanticTestCase:
    """Explicit opt-in wrapper pairing a valid parser input with its expected semantic output."""

    input: Any
    expected: Any


def _encode_valid_input_entry(name: str, raw_item: Any, param_type_hint: str) -> Dict[str, Any]:
    if isinstance(raw_item, AckSemanticTestCase):
        entry = _encode_valid_input_entry(name, raw_item.input, param_type_hint)
        entry["has_semantic_expected"] = True
        entry["expected_semantic"] = raw_item.expected
        return entry
    if isinstance(raw_item, dict) and raw_item.get("encoding") == "hex" and isinstance(raw_item.get("data"), str):
        return {"name": name, "kind": "bytes", "data": raw_item["data"]}
    if isinstance(raw_item, (bytes, bytearray)):
        return {"name": name, "kind": "bytes", "data": bytes(raw_item).hex()}
    if param_type_hint == "bytes" and isinstance(raw_item, str):
        return {"name": name, "kind": "bytes", "data": raw_item.encode("utf-8").hex()}
    return {"name": name, "kind": "json", "data": raw_item}


def _build_valid_corpus_entries(
    *,
    param_type_hint: str,
    valid_corpus_dir: Optional[str],
    valid_inputs: Optional[List[Any]],
) -> Tuple[List[Dict[str, Any]], bool]:
    entries: List[Dict[str, Any]] = []
    if valid_inputs is not None:
        for idx, item in enumerate(valid_inputs[:64]):
            entries.append(_encode_valid_input_entry(f"input_{idx + 1}", item, param_type_hint))
        return entries, True

    if valid_corpus_dir:
        raw_cdir = Path(valid_corpus_dir)
        if raw_cdir.is_symlink():
            raise ValueError(f"Directory corpus symlink non consentita: {valid_corpus_dir}")
        cdir = raw_cdir.resolve()
        if not cdir.is_dir():
            raise FileNotFoundError(f"Directory valid_corpus_dir non trovata: {valid_corpus_dir}")
        for fpath in sorted(cdir.iterdir()):
            if len(entries) >= 32:
                break
            if fpath.name.endswith(".expected.json"):
                continue
            rel_p = fpath.relative_to(cdir)
            resolved = _resolve_in_perimeter_file(fpath, cdir, "corpus")
            if is_sensitive_workspace_file(rel_p) or is_sensitive_workspace_file(resolved.relative_to(cdir)):
                continue
            if not resolved.is_file():
                continue
            try:
                raw_bytes = _read_bounded_regular_file(resolved, 512 * 1024, fpath.name)
            except _OversizedStagedFileError:
                continue
            if param_type_hint == "bytes" or fpath.suffix.lower() in (".bin", ".dat", ".tlv", ".raw"):
                entry: Dict[str, Any] = {"name": fpath.name, "kind": "bytes", "data": raw_bytes.hex()}
            elif fpath.suffix.lower() == ".json" and param_type_hint == "dict":
                try:
                    entry = {"name": fpath.name, "kind": "json", "data": json.loads(raw_bytes.decode("utf-8"))}
                except Exception:
                    entry = {"name": fpath.name, "kind": "json", "data": raw_bytes.decode("utf-8", errors="replace")}
            else:
                entry = {"name": fpath.name, "kind": "json", "data": raw_bytes.decode("utf-8", errors="replace")}

            sidecar = cdir / f"{fpath.stem}.expected.json"
            if sidecar.exists() or sidecar.is_symlink():
                side_res = _resolve_in_perimeter_file(sidecar, cdir, "corpus_sidecar")
                if not is_sensitive_workspace_file(side_res.relative_to(cdir)) and side_res.is_file():
                    side_bytes = _read_bounded_regular_file(side_res, 512 * 1024, sidecar.name)
                    entry["has_semantic_expected"] = True
                    entry["expected_semantic"] = json.loads(side_bytes.decode("utf-8"))
            entries.append(entry)
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

    raw_src = Path(target_file_path)
    if raw_src.is_symlink():
        raise ValueError(f"Target Workspace Mode symlink non consentito: {target_file_path}")
    src_path = raw_src.resolve()
    if not src_path.is_file():
        raise FileNotFoundError(f"File target Python non trovato: {target_file_path}")
    if src_path.suffix.lower() != ".py":
        raise ValueError(f"M4 Workspace Mode supporta file .py; ricevuto: {src_path.name}")

    raw_bytes = _read_bounded_regular_file(src_path, _MAX_STAGED_FILE_BYTES, src_path.name)
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
        project_root_res = project_root.resolve()
        for root_s, dirs, files in os.walk(project_root):
            kept_dirs: List[str] = []
            for d in sorted(dirs):
                if d in _SKIP_COPY_DIRS:
                    continue
                d_path = Path(root_s) / d
                if d_path.is_symlink():
                    try:
                        d_res = d_path.resolve(strict=True)
                    except OSError as exc:
                        raise ValueError(f"Symlink directory interrotta rifiutata: '{d_path}'") from exc
                    if not d_res.is_relative_to(project_root_res):
                        raise ValueError(f"Symlink directory fuori dal perimetro workspace rifiutata: '{d_path}' -> '{d_res}'")
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs
            rpath = Path(root_s)
            for fname in sorted(files):
                fpath = rpath / fname
                if fpath == src_path or fpath.suffix.lower() == ".pyc":
                    continue
                rel_p = fpath.relative_to(project_root)
                rel_str = rel_p.as_posix()
                resolved = _resolve_in_perimeter_file(fpath, project_root, "workspace")
                if is_sensitive_workspace_file(rel_p) or is_sensitive_workspace_file(resolved.relative_to(project_root_res)):
                    continue
                if not resolved.is_file():
                    continue
                try:
                    st_size = resolved.stat().st_size
                except OSError as exc:
                    raise ValueError(f"Impossibile accedere a dipendenza workspace '{rel_str}': {exc}") from exc
                if len(extra_files) + 1 > _MAX_STAGED_FILES or total_bytes + st_size > _MAX_STAGED_TOTAL_BYTES:
                    raise ValueError(
                        f"Workspace '{project_root}' troppo grande per staging completo "
                        f"(limite: {_MAX_STAGED_FILES} file / {_MAX_STAGED_TOTAL_BYTES} byte)."
                    )
                content_b = _read_bounded_regular_file(resolved, _MAX_STAGED_FILE_BYTES, rel_str)
                if total_bytes + len(content_b) > _MAX_STAGED_TOTAL_BYTES:
                    raise ValueError(
                        f"Workspace '{project_root}' troppo grande per staging completo "
                        f"(limite: {_MAX_STAGED_FILES} file / {_MAX_STAGED_TOTAL_BYTES} byte)."
                    )
                extra_files[rel_str] = content_b
                total_bytes += len(content_b)

        if wt_dir is not None and wt_repo_root is not None:
            wt_target = wt_dir / target_rel_path
            wt_target.parent.mkdir(parents=True, exist_ok=True)
            if wt_target.is_symlink():
                wt_target.unlink()
            wt_target.write_bytes(raw_bytes)
            for rel_str, res_bytes in extra_files.items():
                dest_h = wt_dir / rel_str
                dest_h.parent.mkdir(parents=True, exist_ok=True)
                if dest_h.is_symlink():
                    dest_h.unlink()
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
