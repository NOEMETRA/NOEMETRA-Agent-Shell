"""Incremental evidence re-analysis and static post-remediation patch verification."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal

from hermes_cyber.models import (
    AnalyticalClaim,
    CyberAnalysisReport,
    RemediationVerificationSummary,
    VerdictType,
)
from hermes_cyber.patch_analysis import (
    _claims_semantically_match,
    _is_claim_remediated_by_patch,
    _retain_unresolved_claim_surfaces,
)
from hermes_cyber.verifier import (
    build_simulation_summary,
    classify_supported_verdict,
    determine_analysis_mode,
    run_purple_replay,
    summarize_claim_priorities,
)


def execute_case_verification_update(
    assistant: Any,
    case_id: str,
    content: str,
    mode: Literal["append_evidence", "verify_patch"] = "verify_patch",
) -> CyberAnalysisReport:
    """Close open investigations with additional evidence or verify remediated/patched artifacts."""
    if mode not in ("append_evidence", "verify_patch"):
        raise ValueError("Il parametro 'mode' deve essere 'append_evidence' o 'verify_patch'.")
    clean_addition = str(content or "").strip()
    if not clean_addition:
        raise ValueError("Il contenuto di verifica/evidenza non può essere vuoto.")

    orig_report = assistant.get_case(case_id)
    if mode == "append_evidence":
        orig_raw = "\n".join(ev.raw_content for ev in orig_report.ingestion.evidences)
        orig_ids = {ev.evidence_id for ev in orig_report.ingestion.evidences}
        updated = assistant._analyze_ingested(
            f"{orig_raw}\n{clean_addition}",
            title=orig_report.title,
            source_kind=orig_report.ingestion.source_kind,
            scenario_id=orig_report.scenario_id,
            preserve_case_id=case_id,
        )
        added_eids = [ev.evidence_id for ev in updated.ingestion.evidences if ev.evidence_id not in orig_ids]
        orig_open_claims = [c for c in orig_report.red_report.claims if c.status == "open"]
        new_claims = updated.red_report.claims
        resolved: List[str] = []
        still_open: List[str] = []

        for orig_c in orig_open_claims:
            matched_new = next((nc for nc in new_claims if _claims_semantically_match(orig_c, nc)), None)
            if matched_new is not None:
                if matched_new.status in ("supported", "refuted"):
                    resolved.append(orig_c.claim_id)
                elif matched_new.claim_id not in still_open:
                    still_open.append(matched_new.claim_id)
            elif orig_c.claim_id not in still_open:
                still_open.append(orig_c.claim_id)

        for nc in new_claims:
            if nc.status == "open" and nc.claim_id not in still_open:
                still_open.append(nc.claim_id)

        rem_summary = RemediationVerificationSummary(
            status="EVIDENCE_UPDATED",
            verification_level="incremental_evidence_reanalysis",
            verified_at=datetime.now(timezone.utc).isoformat(),
            verification_source="append_evidence",
            added_evidence_ids=added_eids,
            resolved_claim_ids=resolved,
            remaining_open_claim_ids=still_open,
            before_verdict=orig_report.verdict.verdict,
            after_verdict=updated.verdict.verdict,
            operational_caveat=(
                "Rivalutazione basata sulle nuove evidenze aggiunte al caso; "
                "lo stato riflette la coerenza dei record citati rispetto alle condizioni mancanti."
            ),
            summary=(
                f"Appended {len(added_eids)} evidence record(s); resolved={len(resolved)} claim(s), "
                f"open={len(still_open)}; verdict {orig_report.verdict.verdict.value} -> {updated.verdict.verdict.value}."
            ),
        )
    else:
        candidate = assistant._run_transient_analysis(
            clean_addition,
            title=f"{orig_report.title} (Post-Remediation)",
            source_kind=orig_report.ingestion.source_kind,
            scenario_id=orig_report.scenario_id,
            preserve_case_id=case_id,
        )
        orig_active = [c for c in orig_report.red_report.claims if c.status in ("supported", "open")]
        new_active = [c for c in candidate.red_report.claims if c.status in ("supported", "open")]

        resolved_ids = [
            orig_c.claim_id
            for orig_c in orig_active
            if _is_claim_remediated_by_patch(orig_c, orig_report.ingestion, candidate.ingestion, new_active)
        ]
        unresolved_orig = [c for c in orig_active if c.claim_id not in resolved_ids]

        if orig_active and len(resolved_ids) == len(orig_active) and len(new_active) == 0:
            rem_status = "VERIFIED_FIXED"
            updated = candidate
            added_ids = [ev.evidence_id for ev in candidate.ingestion.evidences]
            remaining_ids = []
        else:
            rem_status = "PARTIALLY_MITIGATED" if resolved_ids else "STILL_VULNERABLE"
            unmatched_unresolved: List[AnalyticalClaim] = []
            for orig_c in unresolved_orig:
                retained_c = _retain_unresolved_claim_surfaces(
                    orig_c, orig_report.ingestion, candidate.ingestion, new_active
                )
                if retained_c is not None:
                    unmatched_unresolved.append(retained_c)

            orig_evs = list(orig_report.ingestion.evidences)
            base_seq = len(orig_evs)
            cand_eid_map: Dict[str, str] = {}
            appended_evs = []
            for offset, cev in enumerate(candidate.ingestion.evidences, start=1):
                new_eid = f"EV-{base_seq + offset:04d}"
                cand_eid_map[cev.evidence_id] = new_eid
                # Preserve cev.line_or_seq so line 1 marks candidate boundary in surface blocks
                appended_evs.append(cev.model_copy(update={"evidence_id": new_eid}))

            merged_ingestion = orig_report.ingestion.model_copy(
                update={
                    "total_records": len(orig_evs) + len(appended_evs),
                    "evidences": [*orig_evs, *appended_evs],
                }
            )
            added_ids = [cev.evidence_id for cev in appended_evs]

            cand_cid_map: Dict[str, str] = {}
            shifted_cand_claims: List[AnalyticalClaim] = []
            used_cids = {c.claim_id for c in unmatched_unresolved}
            next_idx = 1
            cand_claims_to_keep = list(candidate.red_report.claims) if new_active else []
            for nc in cand_claims_to_keep:
                old_cid = nc.claim_id
                cid = old_cid
                while not cid or cid in used_cids:
                    cid = f"CLM-{next_idx:02d}"
                    next_idx += 1
                used_cids.add(cid)
                if old_cid:
                    cand_cid_map[old_cid] = cid
                shifted_cand_claims.append(
                    nc.model_copy(
                        update={
                            "claim_id": cid,
                            "evidence_ids": [cand_eid_map.get(eid, eid) for eid in nc.evidence_ids],
                        }
                    )
                )

            combined_claims = [*shifted_cand_claims, *unmatched_unresolved]
            all_combined_cids = {c.claim_id for c in combined_claims}
            remaining_ids = [c.claim_id for c in combined_claims if c.status in ("supported", "open")]
            sup_ids = [c.claim_id for c in combined_claims if c.status == "supported"]
            open_ids = [c.claim_id for c in combined_claims if c.status == "open"]
            refuted_ids = [c.claim_id for c in combined_claims if c.status == "refuted"]

            base_verdict_source = candidate if new_active else orig_report
            has_code = (
                orig_report.ingestion.source_kind in ("code", "config")
                or candidate.ingestion.source_kind in ("code", "config")
            )
            supported_ev_count = len({
                eid for c in combined_claims if c.status == "supported" for eid in c.evidence_ids
            })
            if sup_ids:
                eff_verdict = classify_supported_verdict(
                    "code" if has_code else "log",
                    len(sup_ids),
                    supported_ev_count,
                )
                diag_status = "CONFIRMED_THREAT"
            elif open_ids:
                eff_verdict = VerdictType.INSUFFICIENT_EVIDENCE
                diag_status = "OPEN_HYPOTHESIS"
            else:
                eff_verdict = base_verdict_source.verdict.verdict
                diag_status = "OPEN_HYPOTHESIS"

            retained_orig_cids = {c.claim_id for c in unmatched_unresolved}
            retained_orig_by_cid = {c.claim_id: c for c in unmatched_unresolved}
            remapped_steps = []
            if new_active:
                for step in candidate.red_report.kill_chain:
                    mapped_cid = cand_cid_map.get(step.claim_id, step.claim_id)
                    if mapped_cid in all_combined_cids:
                        remapped_steps.append(
                            step.model_copy(
                                update={
                                    "claim_id": mapped_cid,
                                    "evidence_ids": [cand_eid_map.get(eid, eid) for eid in step.evidence_ids],
                                }
                            )
                        )
            for step in orig_report.red_report.kill_chain:
                if step.claim_id in retained_orig_cids:
                    rc = retained_orig_by_cid[step.claim_id]
                    remapped_steps.append(
                        step.model_copy(
                            update={
                                "evidence_ids": list(rc.evidence_ids),
                                "observed_fact": rc.observed_fact,
                            }
                        )
                    )

            remapped_sims = []
            cand_new_cids = set(cand_cid_map.values())
            if new_active:
                for sim in candidate.red_report.simulated_events:
                    new_scid = cand_cid_map.get(sim.claim_id, sim.claim_id)
                    if not sim.claim_id or new_scid in cand_new_cids:
                        remapped_sims.append(
                            sim.model_copy(
                                update={
                                    "event_id": f"SIM-RED-{len(remapped_sims) + 1:02d}",
                                    "claim_id": new_scid,
                                }
                            )
                        )
            for sim in orig_report.red_report.simulated_events:
                if sim.claim_id in retained_orig_cids or (not new_active and not sim.claim_id):
                    remapped_sims.append(
                        sim.model_copy(update={"event_id": f"SIM-RED-{len(remapped_sims) + 1:02d}"})
                    )

            red_cited = list(dict.fromkeys([eid for c in combined_claims for eid in c.evidence_ids]))
            merged_red = base_verdict_source.red_report.model_copy(
                update={
                    "kill_chain": remapped_steps,
                    "claims": combined_claims,
                    "simulated_events": remapped_sims,
                    "cited_evidence_ids": red_cited,
                }
            )

            remapped_contras = []
            if new_active:
                for contra in candidate.blue_report.contradictions:
                    mapped_tcid = (
                        cand_cid_map.get(contra.target_claim_id, contra.target_claim_id)
                        if contra.target_claim_id
                        else None
                    )
                    if contra.target_claim_id and mapped_tcid not in all_combined_cids:
                        mapped_tcid = None
                    remapped_contras.append(
                        contra.model_copy(
                            update={
                                "target_claim_id": mapped_tcid,
                                "target_evidence_ids": [cand_eid_map.get(e, e) for e in contra.target_evidence_ids],
                                "contradicting_evidence_ids": [
                                    cand_eid_map.get(e, e) for e in contra.contradicting_evidence_ids
                                ],
                            }
                        )
                    )
                blue_cited_base = [cand_eid_map.get(e, e) for e in candidate.blue_report.cited_evidence_ids]
            else:
                blue_cited_base = list(orig_report.blue_report.cited_evidence_ids)

            seen_contras = {(c.claim_challenged, tuple(c.contradicting_evidence_ids)) for c in remapped_contras}
            for contra in orig_report.blue_report.contradictions:
                if not new_active or contra.target_claim_id in retained_orig_cids:
                    sig = (contra.claim_challenged, tuple(contra.contradicting_evidence_ids))
                    if sig not in seen_contras:
                        seen_contras.add(sig)
                        remapped_contras.append(contra)
                        for eid in contra.contradicting_evidence_ids:
                            if eid not in blue_cited_base:
                                blue_cited_base.append(eid)

            merged_blue = base_verdict_source.blue_report.model_copy(
                update={
                    "contradictions": remapped_contras,
                    "cited_evidence_ids": list(dict.fromkeys(blue_cited_base)),
                }
            )

            refuted_cids = set(refuted_ids)
            merged_replay = run_purple_replay(
                merged_ingestion,
                merged_red,
                merged_blue,
                skip_claim_ids=refuted_cids if (sup_ids and refuted_cids) else None,
            )
            merged_sim_summary = build_simulation_summary(merged_replay)
            merged_verified = list(dict.fromkeys([*merged_red.cited_evidence_ids, *merged_blue.cited_evidence_ids]))

            m_mode, m_label, m_scope = determine_analysis_mode(merged_ingestion)
            m_breakdown, m_high_open, m_proofs, m_sorted_open = summarize_claim_priorities(combined_claims)
            m_missing = list(dict.fromkeys([m for c in m_sorted_open for m in c.missing_conditions]))
            merged_diag = base_verdict_source.verdict.diagnosis.model_copy(
                update={
                    "status": diag_status,
                    "analysis_mode": m_mode,
                    "analysis_mode_label": m_label,
                    "epistemic_scope": m_scope,
                    "supported_claims_count": len(sup_ids),
                    "open_claims_count": len(open_ids),
                    "refuted_claims_count": len(refuted_ids),
                    "supported_claim_ids": sup_ids,
                    "open_claim_ids": open_ids,
                    "refuted_claim_ids": refuted_ids,
                    "high_priority_open_claim_ids": m_high_open,
                    "priority_breakdown": m_breakdown,
                    "missing_conditions_summary": m_missing,
                    "next_required_proofs": m_proofs or base_verdict_source.verdict.diagnosis.next_required_proofs,
                    "summary": (
                        f"{len(remaining_ids)} unresolved/new active threat claim(s) remain after patch check."
                    ),
                }
            )
            updated = base_verdict_source.model_copy(
                update={
                    "ingestion": merged_ingestion,
                    "red_report": merged_red,
                    "blue_report": merged_blue,
                    "verdict": base_verdict_source.verdict.model_copy(
                        update={
                            "verdict": eff_verdict,
                            "verified_citations": merged_verified,
                            "replay": merged_replay,
                            "simulation": merged_sim_summary,
                            "diagnosis": merged_diag,
                        }
                    ),
                }
            )

        after_v = updated.verdict.verdict
        rem_summary = RemediationVerificationSummary(
            status=rem_status,  # type: ignore[arg-type]
            verification_level="static_artifact_comparison",
            verified_at=datetime.now(timezone.utc).isoformat(),
            verification_source="verify_patch",
            added_evidence_ids=added_ids,
            resolved_claim_ids=resolved_ids,
            remaining_open_claim_ids=remaining_ids,
            before_verdict=orig_report.verdict.verdict,
            after_verdict=after_v,
            operational_caveat=(
                "Il controllo statico del nuovo artefatto verifica la presenza dei controlli difensivi attesi sulle superfici esposte; "
                "la conferma operativa richiede una verifica sul comportamento effettivo a runtime (es. probe safe-audit o telemetria post-deploy)."
            ),
            summary=(
                f"Post-remediation check: {rem_status} ({len(resolved_ids)}/{len(orig_active)} original claims verified fixed; "
                f"verdict {orig_report.verdict.verdict.value} -> {after_v.value})."
            ),
        )

    final_report = updated.model_copy(
        update={"verdict": updated.verdict.model_copy(update={"remediation_verification": rem_summary})}
    )
    assistant._cases[case_id] = final_report
    assistant._active_case_id = case_id
    assistant._save_cases()
    return final_report
