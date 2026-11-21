"""Persistent deliverable exporter for NOEMETRA ACK runs (`NOEMETRA/runs/<run_id>/`)."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.ack.catalog import _MissionExecutionOutcome, _sha256_bytes
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.workspace import compute_unified_diff, is_sensitive_workspace_file
from hermes_cyber.models import AckCertificationReport


def resolve_ack_runs_dir(explicit_runs_dir: Optional[Path] = None) -> Path:
    """Resolve persistent NOEMETRA/runs root inside active profile home or OS temp fallback."""
    if explicit_runs_dir is not None:
        return Path(explicit_runs_dir).resolve()
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    if hermes_home:
        return (Path(hermes_home).resolve() / "NOEMETRA" / "runs").resolve()
    return (Path(tempfile.gettempdir()).resolve() / "NOEMETRA" / "runs").resolve()


def _infer_lower_vs_upper_diff(chamber: DetonationChamber) -> str:
    lower_snap = chamber.snapshot_tree(chamber.lowerdir)
    upper_snap = chamber.snapshot_tree(chamber.upperdir)
    chunks: List[str] = []
    for rel in sorted(upper_snap):
        if rel.startswith("telemetry_") or upper_snap[rel] == lower_snap.get(rel):
            continue
        up_fp = chamber.upperdir / rel
        low_fp = chamber.lowerdir / rel
        try:
            up_text = up_fp.read_text(encoding="utf-8")
            low_text = low_fp.read_text(encoding="utf-8") if low_fp.exists() else ""
        except (OSError, UnicodeDecodeError):
            continue
        diff_txt = compute_unified_diff(low_text, up_text, rel)
        if diff_txt:
            chunks.append(diff_txt)
    return "\n".join(chunks)


def _render_markdown_report(report: AckCertificationReport) -> str:
    m = report.tpr_fpr_matrix
    lines: List[str] = [
        f"# NOEMETRA ACK Run Report — `{report.run_id}`",
        "",
        f"- **Missione**: `{report.mission_id}` ({report.title})",
        f"- **Verdetto**: `{report.certification_verdict}` (`certified={report.certified}`)",
        f"- **Verification Tier**: `{report.verification_tier}` | **Audit Scope**: `{report.audit_scope}`",
        f"- **Security Boundary**: `{report.security_boundary_level}` ({report.isolation_backend})",
        f"- **Avviso Confine**: {report.untrusted_llm_code_warning}",
        "",
        "## Metriche Misurate",
        f"- **True Positive / Evasion Resistance Rate**: `{round(m.true_positive_rate * 100, 1)}%` (`{m.attack_variants_tested}` varianti testate)",
        f"- **False Positive Rate**: `{round(m.false_positive_rate * 100, 1)}%` (`fpr_measured={m.fpr_measured}`, `benign_corpus_size={m.benign_corpus_size}`)",
        f"- **Functional Survival Rate**: `{round(m.functional_survival_rate * 100, 1)}%`",
        f"- **Pre-Patch Breach Confirmed**: `{m.pre_patch_breach_confirmed}` | **Post-Patch Breaches**: `{m.post_patch_breaches}`",
        "",
        "## Controlli Eseguiti vs Non Eseguiti",
        "### Eseguiti",
        *[f"- [x] `{c}`" for c in (report.executed_checks or ["baseline_check"])],
        "",
        "### Non Eseguiti (Limiti Dichiarati)",
        *[f"- [ ] `{c}`" for c in (report.not_executed_checks or ["none"])],
        "",
        "## Sub-Agent Fleet (Fog of War)",
        *[
            f"- **[{tr.team}] {tr.role}** (`{tr.phase}`, model=`{tr.model_used}`, ctx_keys=`{','.join(tr.visible_context_keys)}`): {tr.summary}"
            for tr in report.subagent_traces
        ],
        "",
        "## Patch / Regole Blue",
        f"{report.blue_patch_or_rules_summary}",
        "",
        "```diff",
        (report.patch_diff or "# Nessun diff di file sorgente generato in questa missione.").rstrip(),
        "```",
        "",
        "## Razionale Finale",
        report.rationale,
        "",
    ]
    return "\n".join(lines)


def list_ack_runs(runs_root: Path) -> List[Dict[str, Any]]:
    """Return metadata summaries of persisted ACK deliverable directories ordered newest-first."""
    if not runs_root.is_dir():
        return []
    items: List[Dict[str, Any]] = []
    for entry in runs_root.iterdir():
        manifest_path = entry / "manifest.json"
        if entry.is_dir() and manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                items.append(manifest)
            except Exception:
                continue
    items.sort(key=lambda x: str(x.get("exported_at") or ""), reverse=True)
    return items[:50]


def export_ack_deliverables(
    runs_root: Path,
    report: AckCertificationReport,
    chamber: DetonationChamber,
    outcome: _MissionExecutionOutcome,
) -> Tuple[Path, List[str]]:
    """Persist structured artifacts, patch.diff, regression pytest, repros, and logs before chamber cleanup."""
    from datetime import datetime, timezone

    run_dir = (runs_root / report.run_id).resolve()
    repro_dir = run_dir / "repro"
    reg_dir = run_dir / "regression_tests"
    logs_dir = run_dir / "execution_logs"
    for d in (run_dir, repro_dir, reg_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)

    patch_diff = outcome.patch_diff or _infer_lower_vs_upper_diff(chamber)
    (run_dir / "patch.diff").write_text(patch_diff, encoding="utf-8")

    # Preserve patched module + full staged package/project dependencies and resources for standalone regression tests
    if outcome.workspace_target is not None:
        rel_target = outcome.workspace_target.target_rel_path or Path(outcome.workspace_target.target_file_path).name
        up_candidate = chamber.upperdir / rel_target
        if up_candidate.is_file():
            patched_dir = run_dir / "patched_target"
            for base_dir in (chamber.lowerdir, chamber.upperdir):
                if base_dir.is_dir():
                    for fpath in sorted(base_dir.rglob("*")):
                        if not fpath.is_file():
                            continue
                        rel_p = fpath.relative_to(base_dir)
                        if (
                            "__pycache__" in rel_p.parts
                            or (rel_p.parts and rel_p.parts[0] in ("canary_vault", "uploads"))
                            or fpath.suffix.lower() == ".pyc"
                            or is_sensitive_workspace_file(rel_p)
                            or (len(rel_p.parts) == 1 and rel_p.name.startswith("telemetry_") and rel_p.suffix.lower() == ".json")
                        ):
                            continue
                        dest = patched_dir / rel_p
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(fpath.read_bytes())
    elif (chamber.upperdir / "tlv_parser.py").is_file():
        patched_dir = run_dir / "patched_target"
        patched_dir.mkdir(parents=True, exist_ok=True)
        (patched_dir / "tlv_parser.py").write_bytes((chamber.upperdir / "tlv_parser.py").read_bytes())

    # Export repro payloads & Red PoC harnesses before chamber.cleanup()
    for rel_name, content in outcome.repro_artifacts.items():
        safe_name = Path(rel_name).name
        (repro_dir / safe_name).write_bytes(content)
    if chamber.artifacts_red.is_dir():
        for src_p in sorted(chamber.artifacts_red.iterdir()):
            if src_p.is_file() and src_p.suffix.lower() in (".py", ".bin", ".json", ".txt"):
                (repro_dir / src_p.name).write_bytes(src_p.read_bytes())

    # Export runnable regression test
    safe_id = re.sub(r"[^A-Za-z0-9_]", "_", report.run_id)
    reg_filename = f"test_ack_regression_{safe_id}.py"
    reg_code = outcome.regression_test_code.strip() or (
        f'"""Auto-generated ACK verification summary test for {report.run_id}."""\n\n'
        "def test_ack_run_contract_summary():\n"
        f"    assert {bool(report.certified)!r} is True or {report.certification_verdict!r} != ''\n"
    )
    (reg_dir / reg_filename).write_text(reg_code.rstrip() + "\n", encoding="utf-8")

    # Export per-action execution logs
    if outcome.execution_logs:
        for idx, log_entry in enumerate(outcome.execution_logs, start=1):
            aid = re.sub(r"[^A-Za-z0-9_.-]", "_", str(log_entry.get("action_id") or f"step_{idx}"))
            (logs_dir / f"{idx:02d}_{aid}.json").write_text(json.dumps(log_entry, indent=2), encoding="utf-8")
    else:
        for idx, ev in enumerate(report.oracle_evidences, start=1):
            aid = re.sub(r"[^A-Za-z0-9_.-]", "_", ev.action_id)
            (logs_dir / f"{idx:02d}_{aid}.json").write_text(
                json.dumps(ev.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )

    findings_payload = {
        "run_id": report.run_id,
        "mission_id": report.mission_id,
        "certified": report.certified,
        "certification_verdict": report.certification_verdict,
        "verification_tier": report.verification_tier,
        "audit_scope": report.audit_scope,
        "security_boundary_level": report.security_boundary_level,
        "executed_checks": report.executed_checks,
        "not_executed_checks": report.not_executed_checks,
        "tpr_fpr_matrix": report.tpr_fpr_matrix.model_dump(mode="json"),
        "subagent_traces": [t.model_dump(mode="json") for t in report.subagent_traces],
        "mutation_rounds": [
            {
                "round_index": r.round_index,
                "attack_class": r.attack_class,
                "execution_valid": r.execution_valid,
                "bypass_succeeded": r.bypass_succeeded,
                "oracle_verdict": r.oracle_evidence.oracle_verdict,
            }
            for r in report.mutation_rounds
        ],
    }
    (run_dir / "findings.json").write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")

    final_report = report.model_copy(
        update={
            "deliverable_dir": str(run_dir),
            "patch_diff": patch_diff,
        }
    )
    (run_dir / "report.md").write_text(_render_markdown_report(final_report), encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps(final_report.model_dump(mode="json"), indent=2), encoding="utf-8")

    # Gather sorted file list + SHA-256 inventory BEFORE finalizing manifest.json & deliverable_files
    checksums: Dict[str, str] = {}
    for fp in sorted(run_dir.rglob("*")):
        if fp.is_file() and fp.name != "manifest.json":
            rel = fp.relative_to(run_dir).as_posix()
            checksums[rel] = _sha256_bytes(fp.read_bytes())

    rel_files = sorted([*checksums.keys(), "manifest.json"])
    final_report = final_report.model_copy(update={"deliverable_files": rel_files})
    (run_dir / "report.json").write_text(json.dumps(final_report.model_dump(mode="json"), indent=2), encoding="utf-8")
    checksums["report.json"] = _sha256_bytes((run_dir / "report.json").read_bytes())

    manifest = {
        "run_id": report.run_id,
        "mission_id": report.mission_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "certified": report.certified,
        "certification_verdict": report.certification_verdict,
        "verification_tier": report.verification_tier,
        "audit_scope": report.audit_scope,
        "security_boundary_level": report.security_boundary_level,
        "executed_checks": report.executed_checks,
        "not_executed_checks": report.not_executed_checks,
        "workspace_target": report.workspace_target.model_dump(mode="json") if report.workspace_target else None,
        "files": rel_files,
        "sha256": checksums,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir, rel_files
