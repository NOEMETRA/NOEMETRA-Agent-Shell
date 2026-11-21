"""Session-bound, single-use human approval tokens and integrity verification for ACK patch application."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_cyber.ack.catalog import _sha256_bytes
from hermes_cyber.ack.operator_confirm import prompt_interactive_operator_confirmation
from hermes_cyber.ack.workspace import _MAX_STAGED_FILE_BYTES, _read_bounded_regular_file


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_run_patch_integrity(runs_dir: Path, run_id: str) -> Dict[str, Any]:
    """Validate run manifest, snapshot checksums, non-symlink targets, and original file drift."""
    if not re.match(r"^[A-Za-z0-9_-]+$", str(run_id or "")):
        raise ValueError(f"run_id ACK non valido: {run_id!r}")
    runs_root = runs_dir.resolve()
    raw_run_dir = runs_root / run_id
    if raw_run_dir.is_symlink():
        raise PermissionError(f"Directory run symlink rifiutata: {run_id!r}")
    run_dir = raw_run_dir.resolve()
    if run_dir.parent != runs_root:
        raise ValueError(f"Percorso run_id non valido: {run_id!r}")
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.exists():
        raise FileNotFoundError(f"Manifest della run ACK non trovato: {run_id}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("run_id") != run_id:
        raise ValueError(f"Manifest run_id non corrispondente ({manifest.get('run_id')!r} != {run_id!r}).")
    if not (manifest.get("patch_applicable") is True or manifest.get("certified") is True):
        raise ValueError(
            f"Impossibile applicare patch da una run non applicabile ({manifest.get('certification_verdict')})."
        )

    ws = manifest.get("workspace_target")
    if not isinstance(ws, dict) or not ws.get("target_file_path"):
        raise ValueError("La run selezionata non ha un target Workspace Mode applicabile su disco.")

    diff_path = run_dir / "patch.diff"
    if diff_path.is_symlink() or not diff_path.exists():
        raise ValueError("patch.diff mancante o non valido: nessuna modifica da applicare.")
    diff_bytes = _read_bounded_regular_file(diff_path.resolve(), _MAX_STAGED_FILE_BYTES, "patch.diff")
    if not diff_bytes.decode("utf-8", errors="replace").strip():
        raise ValueError("patch.diff vuoto: nessuna modifica da applicare.")

    raw_orig = Path(ws["target_file_path"])
    if raw_orig.is_symlink():
        raise ValueError(f"File target originale symlink rifiutato: {raw_orig}")
    orig_path = raw_orig.resolve()
    if not orig_path.is_file():
        raise FileNotFoundError(f"File target originale non più presente: {orig_path}")

    patched_root = (run_dir / "patched_target").resolve()
    rel_snap_path = str(ws.get("target_rel_path") or orig_path.name).replace("\\", "/").lstrip("/")
    raw_snapshot = patched_root / rel_snap_path
    if raw_snapshot.is_symlink():
        raise ValueError(f"Artefatto patched_target symlink rifiutato: {raw_snapshot}")
    patched_snapshot = raw_snapshot.resolve()
    if not patched_snapshot.is_relative_to(patched_root) or not patched_snapshot.is_file():
        raise FileNotFoundError(f"Artefatto patched_target mancante in {run_dir}")

    sha_map = manifest.get("sha256")
    if not isinstance(sha_map, dict):
        raise ValueError("Manifest privo di mappa integrità SHA-256: applicazione annullata.")
    rel_patched_key = f"patched_target/{patched_snapshot.relative_to(patched_root).as_posix()}"
    expected_patched_sha = str(sha_map.get(rel_patched_key) or "")
    patched_bytes = _read_bounded_regular_file(patched_snapshot, _MAX_STAGED_FILE_BYTES, rel_patched_key)
    patched_sha = _sha256_bytes(patched_bytes)
    if not expected_patched_sha or patched_sha != expected_patched_sha:
        raise ValueError(
            f"Integrità snapshot compromessa per {rel_patched_key}: SHA-256 attuale ({patched_sha[:12]}) "
            f"non corrisponde al manifest ({expected_patched_sha[:12]}). Applicazione annullata."
        )
    diff_sha = _sha256_bytes(diff_bytes)
    expected_diff_sha = str(sha_map.get("patch.diff") or "")
    if not expected_diff_sha or diff_sha != expected_diff_sha:
        raise ValueError("Integrità compromessa o checksum mancante per patch.diff.")

    orig_bytes = _read_bounded_regular_file(orig_path, _MAX_STAGED_FILE_BYTES, orig_path.name)
    current_sha = _sha256_bytes(orig_bytes)
    expected_sha = str(ws.get("original_sha256") or "")
    if current_sha != expected_sha:
        raise ValueError(
            f"Drift rilevato sul file originale {orig_path.name}: SHA-256 attuale ({current_sha[:12]}) "
            f"non corrisponde allo stato iniziale ({expected_sha[:12]}). Applicazione annullata."
        )

    return {
        "run_dir": run_dir,
        "manifest_path": manifest_path,
        "manifest": manifest,
        "ws": ws,
        "orig_path": orig_path,
        "orig_bytes": orig_bytes,
        "original_sha256": expected_sha,
        "patch_diff_sha256": diff_sha,
        "patched_bytes": patched_bytes,
        "patched_target_sha256": patched_sha,
    }


@dataclass
class _PendingApproval:
    approval_id: str
    token_sha256: str
    run_id: str
    target_file_path: str
    original_sha256: str
    patch_diff_sha256: str
    patched_target_sha256: str
    patch_classification: str
    manual_review_required: bool
    session_id: str
    expires_monotonic: float
    expires_at: str
    operator_principal: str = ""
    consumed: bool = False


class AckPatchApprovalManager:
    """In-memory single-use human approval token issuer bound to run, target, hashes, and session."""

    def __init__(
        self,
        *,
        human_confirm_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._confirm_lock = threading.Lock()
        self._deny_cooldown_until: float = 0.0
        self._human_confirm_fn = human_confirm_fn
        self._pending: Dict[str, _PendingApproval] = {}

    def issue_approval(
        self,
        runs_dir: Path,
        run_id: str,
        *,
        session_id: str,
        expected_target_file_path: Optional[str] = None,
        acknowledge_manual_review: bool = False,
        remote_client: bool = False,
        operator_principal: str = "",
        ttl_seconds: int = 300,
    ) -> Dict[str, Any]:
        sess = str(session_id or "").strip()
        if not sess:
            raise PermissionError("Session identity mancante: impossibile emettere approvazione patch.")

        ctx = verify_run_patch_integrity(runs_dir, run_id)
        orig_path_str = str(ctx["orig_path"])
        if expected_target_file_path is not None and str(expected_target_file_path).strip():
            raw_exp = Path(expected_target_file_path)
            if raw_exp.is_symlink() or str(raw_exp.resolve()) != orig_path_str:
                raise PermissionError(
                    f"Target mismatch nell'approvazione: atteso '{orig_path_str}', ricevuto '{expected_target_file_path}'."
                )

        manifest = ctx["manifest"]
        manual_req = bool(manifest.get("manual_review_required"))
        reasons = list(manifest.get("manual_review_reasons") or [])
        patch_cls = str(manifest.get("patch_classification") or "none")
        if manual_req and acknowledge_manual_review is not True:
            raise PermissionError(
                f"Revisione manuale esplicita richiesta prima di approvare la patch ({patch_cls}): "
                f"{'; '.join(reasons) or 'semantiche o operazioni sensibili da verificare'}."
            )

        if not self._confirm_lock.acquire(blocking=False):
            raise PermissionError("Un'altra richiesta di conferma operatore è già in corso.")
        try:
            if self._human_confirm_fn is None:
                if remote_client:
                    raise PermissionError("Conferma interattiva locale non consentita per richieste remote o proxate.")
                if time.monotonic() < self._deny_cooldown_until:
                    raise PermissionError("Troppe conferme operatore rifiutate: attendere prima di riprovare.")

            principal_str = str(operator_principal or "")
            confirm_ctx: Dict[str, Any] = {
                "run_id": run_id,
                "target_file_path": orig_path_str,
                "original_sha256": ctx["original_sha256"],
                "patch_diff_sha256": ctx["patch_diff_sha256"],
                "patched_target_sha256": ctx["patched_target_sha256"],
                "patch_classification": patch_cls,
                "manual_review_required": manual_req,
                "manual_review_reasons": reasons,
                "session_id": sess,
                "remote_client": bool(remote_client),
                "operator_principal": principal_str,
            }
            confirm_fn = self._human_confirm_fn or prompt_interactive_operator_confirmation
            if confirm_fn(confirm_ctx) is not True:
                if self._human_confirm_fn is None:
                    self._deny_cooldown_until = time.monotonic() + 3.0
                raise PermissionError(
                    "Autorizzazione patch negata: conferma interattiva umana non ottenuta o canale interattivo non disponibile."
                )

            ctx_after = verify_run_patch_integrity(runs_dir, run_id)
            if (
                str(ctx_after["orig_path"]) != orig_path_str
                or ctx_after["original_sha256"] != ctx["original_sha256"]
                or ctx_after["patch_diff_sha256"] != ctx["patch_diff_sha256"]
                or ctx_after["patched_target_sha256"] != ctx["patched_target_sha256"]
            ):
                raise PermissionError(
                    "Integrità target o artefatti modificata durante la conferma operatore: autorizzazione annullata."
                )
        finally:
            self._confirm_lock.release()

        ttl = max(30, min(1800, int(ttl_seconds)))
        now_mono = time.monotonic()
        exp_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        approval_id = f"ack-appr-{secrets.token_hex(6)}"
        token = secrets.token_urlsafe(32)
        record = _PendingApproval(
            approval_id=approval_id,
            token_sha256=_sha256_text(token),
            run_id=run_id,
            target_file_path=orig_path_str,
            original_sha256=ctx["original_sha256"],
            patch_diff_sha256=ctx["patch_diff_sha256"],
            patched_target_sha256=ctx["patched_target_sha256"],
            patch_classification=patch_cls,
            manual_review_required=manual_req,
            session_id=sess,
            expires_monotonic=now_mono + ttl,
            expires_at=exp_dt.isoformat(),
            operator_principal=principal_str,
        )
        with self._lock:
            if len(self._pending) >= 256:
                stale = [
                    k for k, v in self._pending.items()
                    if v.consumed or v.expires_monotonic < now_mono
                ]
                for k in stale:
                    self._pending.pop(k, None)
            self._pending[approval_id] = record

        return {
            "approval_id": approval_id,
            "approval_token": token,
            "run_id": run_id,
            "target_file_path": orig_path_str,
            "original_sha256": ctx["original_sha256"],
            "patch_diff_sha256": ctx["patch_diff_sha256"],
            "patched_target_sha256": ctx["patched_target_sha256"],
            "patch_classification": patch_cls,
            "manual_review_required": manual_req,
            "manual_review_reasons": reasons,
            "session_id": sess,
            "expires_at": record.expires_at,
        }

    def consume_approval(
        self,
        approval_token: str,
        *,
        run_id: str,
        target_file_path: str,
        original_sha256: str,
        patch_diff_sha256: str,
        patched_target_sha256: str,
        session_id: str,
        operator_principal: str = "",
    ) -> Dict[str, Any]:
        tok = str(approval_token or "").strip()
        sess = str(session_id or "").strip()
        if not tok or not sess:
            raise PermissionError("Token di approvazione o session_id mancante.")
        presented_digest = _sha256_text(tok)
        now_mono = time.monotonic()

        with self._lock:
            matched: Optional[_PendingApproval] = None
            for rec in self._pending.values():
                if hmac.compare_digest(rec.token_sha256, presented_digest):
                    matched = rec
                    break
            if matched is None:
                raise PermissionError("Token di approvazione patch non valido o sconosciuto.")
            if matched.consumed:
                raise PermissionError("Token di approvazione monouso già consumato.")
            if now_mono > matched.expires_monotonic:
                raise PermissionError("Token di approvazione scaduto.")
            if not hmac.compare_digest(matched.session_id, sess):
                raise PermissionError("Session mismatch: token legato a una sessione diversa.")
            if not hmac.compare_digest(matched.operator_principal, str(operator_principal or "")):
                raise PermissionError("Principal mismatch: token legato a un operatore diverso.")
            if matched.run_id != run_id or matched.target_file_path != target_file_path:
                raise PermissionError("Token di approvazione non valido per questo run_id o target_file_path.")
            if (
                matched.original_sha256 != original_sha256
                or matched.patch_diff_sha256 != patch_diff_sha256
                or matched.patched_target_sha256 != patched_target_sha256
            ):
                raise PermissionError("Integrità artefatti cambiata rispetto al token di approvazione emesso.")
            matched.consumed = True
            return {
                "approval_id": matched.approval_id,
                "approved_session_id": matched.session_id,
                "approved_at": datetime.now(timezone.utc).isoformat(),
            }


def apply_ack_run_patch(
    runs_dir: Path,
    run_id: str,
    *,
    confirm_apply: bool = False,
    approval_token: str = "",
    session_id: str = "",
    operator_principal: str = "",
    approval_manager: Optional[AckPatchApprovalManager] = None,
) -> Dict[str, Any]:
    """Explicitly apply a Workspace Mode patch after SHA-256 drift checks and single-use human approval."""
    if confirm_apply is not True:
        raise PermissionError(
            "Modifica al progetto originale negata: è richiesta conferma esplicita (confirm_apply=True)."
        )
    if approval_manager is None or not str(approval_token or "").strip() or not str(session_id or "").strip():
        raise PermissionError(
            "Modifica negata: `confirm_apply=True` programmatico non basta; "
            "è richiesto token di approvazione umana monouso vincolato a run, target e sessione."
        )

    ctx = verify_run_patch_integrity(runs_dir, run_id)
    approval_rec = approval_manager.consume_approval(
        approval_token,
        run_id=run_id,
        target_file_path=str(ctx["orig_path"]),
        original_sha256=ctx["original_sha256"],
        patch_diff_sha256=ctx["patch_diff_sha256"],
        patched_target_sha256=ctx["patched_target_sha256"],
        session_id=session_id,
        operator_principal=operator_principal,
    )

    run_dir: Path = ctx["run_dir"]
    manifest_path: Path = ctx["manifest_path"]
    manifest: Dict[str, Any] = ctx["manifest"]
    ws: Dict[str, Any] = ctx["ws"]
    orig_path: Path = ctx["orig_path"]

    backup_dir = run_dir / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{orig_path.name}.orig"
    if backup_path.is_symlink():
        raise PermissionError("Percorso backup symlink non consentito.")
    if not backup_path.exists():
        backup_path.write_bytes(ctx["orig_bytes"])

    orig_path.write_bytes(ctx["patched_bytes"])
    applied_at = datetime.now(timezone.utc).isoformat()

    ws["patch_applied"] = True
    ws["applied_at"] = applied_at
    ws["applied_sha256"] = ctx["patched_target_sha256"]
    ws["backup_path"] = str(backup_path)
    ws["approval_id"] = approval_rec["approval_id"]
    ws["approved_session_id"] = approval_rec["approved_session_id"]
    manifest["workspace_target"] = ws
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    report_path = run_dir / "report.json"
    if report_path.exists() and not report_path.is_symlink():
        rep_obj = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(rep_obj.get("workspace_target"), dict):
            rep_obj["workspace_target"]["patch_applied"] = True
            rep_obj["workspace_target"]["applied_at"] = applied_at
            rep_obj["workspace_target"]["approval_id"] = approval_rec["approval_id"]
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
        "approval_id": approval_rec["approval_id"],
        "approved_session_id": approval_rec["approved_session_id"],
        "original_sha256": ctx["original_sha256"],
        "patched_sha256": ctx["patched_target_sha256"],
        "backup_path": str(backup_path),
    }
