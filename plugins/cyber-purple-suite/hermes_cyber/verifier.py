"""Deterministic Purple Verifier: Citation Grounding, Entity Coherence, Claim Evaluation, and Verdict Arbiter."""

from __future__ import annotations

from typing import List, Set, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    DiagnosisSummary,
    PurpleVerdict,
    RedOperationPlan,
    RemediationVerificationSummary,
    VerdictType,
)
from hermes_cyber.replay_engine import build_simulation_summary, run_purple_replay
from hermes_cyber.verdict_policy import (
    _collect_entity_sets,
    _is_contradiction_entity_coherent,
    _resolve_target_claims,
    classify_supported_verdict,
    determine_analysis_mode,
    summarize_claim_priorities,
)


class PurpleVerifier:
    """Deterministic arbiter verifying citation grounding, entity coherence, claim validity, and 3-stage outputs."""

    def verify(
        self,
        ingestion: ArtifactIngestionResult,
        red_report: RedOperationPlan,
        blue_report: BlueInvestigationReport,
    ) -> Tuple[RedOperationPlan, BlueInvestigationReport, PurpleVerdict]:
        ev_by_id = {ev.evidence_id: ev for ev in ingestion.evidences}
        valid_ids = set(ev_by_id.keys())
        removed: List[str] = []
        verified: List[str] = []

        def _filter_ids(ids: List[str]) -> List[str]:
            clean: List[str] = []
            for eid in ids:
                if eid in valid_ids:
                    if eid not in clean:
                        clean.append(eid)
                    if eid not in verified:
                        verified.append(eid)
                elif eid and eid not in removed:
                    removed.append(eid)
            return clean

        cleaned_steps = [
            step.model_copy(update={"evidence_ids": _filter_ids(step.evidence_ids)})
            for step in red_report.kill_chain
        ]

        # Build / synchronize structured AnalyticalClaims from Red's claims or kill_chain fallback
        if red_report.claims:
            cleaned_claims = [
                clm.model_copy(update={"evidence_ids": _filter_ids(clm.evidence_ids)})
                for clm in red_report.claims
            ]
        else:
            cleaned_claims = [
                AnalyticalClaim(
                    claim_id=step.claim_id or f"CLM-{idx + 1:02d}",
                    step_index=idx,
                    tactic=step.tactic,
                    technique_id=step.technique_id,
                    observed_fact=step.observed_fact or step.reachability_proof or step.description,
                    evidence_ids=list(step.evidence_ids),
                    proposed_interpretation=step.proposed_interpretation or step.description,
                    missing_conditions=list(step.missing_conditions),
                    confirming_or_refuting_proof=step.confirming_or_refuting_proof or step.reachability_proof,
                    status=step.status,
                )
                for idx, step in enumerate(cleaned_steps)
            ]

        # Filter Blue contradictions & validate entity coherence
        incoherent_rejected: List[str] = []
        cleaned_contras: List[ContradictionItem] = []
        refuted_claim_ids: Set[str] = set()
        weakened_claim_ids: Set[str] = set()

        for raw_c in blue_report.contradictions:
            c_eids = _filter_ids(raw_c.contradicting_evidence_ids)
            t_eids = _filter_ids(raw_c.target_evidence_ids)
            c_filtered = raw_c.model_copy(update={
                "contradicting_evidence_ids": c_eids,
                "target_evidence_ids": t_eids,
            })
            targets = _resolve_target_claims(c_filtered, cleaned_claims, ev_by_id)
            is_coherent = _is_contradiction_entity_coherent(c_filtered, targets, ev_by_id)
            c_checked = c_filtered.model_copy(update={"entity_coherent": is_coherent})
            cleaned_contras.append(c_checked)

            if not is_coherent:
                incoherent_rejected.append(f"{c_checked.claim_challenged} ({','.join(c_eids) or 'no-ev'})")
                continue

            if c_checked.impact_on_hypothesis == "refutes":
                for tc in targets:
                    refuted_claim_ids.add(tc.claim_id)
            elif c_checked.impact_on_hypothesis == "weakens":
                for tc in targets:
                    weakened_claim_ids.add(tc.claim_id)

        # Evaluate final status per claim (refuted -> open -> supported)
        final_claims: List[AnalyticalClaim] = []
        for clm in cleaned_claims:
            if clm.claim_id in refuted_claim_ids:
                final_claims.append(
                    clm.model_copy(
                        update={
                            "status": "refuted",
                            "priority": "low",
                            "priority_rationale": "Affermazione confutata da controlli difensivi coerenti per entità.",
                        }
                    )
                )
            elif (not clm.evidence_ids) or bool(clm.missing_conditions) or (clm.claim_id in weakened_claim_ids):
                prio = clm.priority
                prat = clm.priority_rationale
                if clm.claim_id in weakened_claim_ids and prio == "critical":
                    prio = "medium"
                    prat = "Ipotesi indebolita da evidenza difensiva o gap di telemetria; necessaria prova discriminante."
                final_claims.append(
                    clm.model_copy(
                        update={
                            "status": "open",
                            "priority": prio,
                            "priority_rationale": prat,
                        }
                    )
                )
            else:
                final_claims.append(clm.model_copy(update={"status": "supported"}))

        claim_by_id = {c.claim_id: c for c in final_claims}
        final_steps = []
        for idx, step in enumerate(cleaned_steps):
            cid = step.claim_id or f"CLM-{idx + 1:02d}"
            paired = claim_by_id.get(cid)
            if paired:
                final_steps.append(step.model_copy(update={"claim_id": cid, "status": paired.status}))
            else:
                final_steps.append(step)

        clean_red = red_report.model_copy(update={
            "kill_chain": final_steps,
            "claims": final_claims,
            "cited_evidence_ids": _filter_ids(red_report.cited_evidence_ids),
        })
        clean_blue = blue_report.model_copy(update={
            "contradictions": cleaned_contras,
            "cited_evidence_ids": _filter_ids(blue_report.cited_evidence_ids),
        })

        coherent_refutes = sum(
            1 for c in cleaned_contras if c.entity_coherent and c.impact_on_hypothesis == "refutes" and c.contradicting_evidence_ids
        )
        coherent_weakens = sum(
            1 for c in cleaned_contras if c.entity_coherent and c.impact_on_hypothesis == "weakens" and c.contradicting_evidence_ids
        )

        supported_claims = [c for c in final_claims if c.status == "supported"]
        open_claims = [c for c in final_claims if c.status == "open"]
        refuted_claims = [c for c in final_claims if c.status == "refuted"]

        # On mixed multi-host logs with both confirmed threats and refuted benign claims,
        # replay measures detection coverage over active threat simulations without penalizing ignored refuted hosts.
        skip_claims = refuted_claim_ids if (supported_claims and refuted_claim_ids) else None
        replay = run_purple_replay(ingestion, clean_red, clean_blue, skip_claim_ids=skip_claims)
        sim_summary = build_simulation_summary(replay)

        independent_ev_count = len(verified)
        sup_a = round(min(0.97, max(0.05, clean_red.confidence - 0.25 * (coherent_refutes if not supported_claims else 0) - 0.15 * coherent_weakens)), 3)
        sup_b = round(min(0.97, max(0.05, clean_blue.confidence + 0.10 * coherent_refutes)), 3)

        analysis_mode, analysis_mode_label, epistemic_scope = determine_analysis_mode(ingestion)
        priority_breakdown, high_open_ids, next_proofs, sorted_open_claims = summarize_claim_priorities(final_claims)
        missing_summary = list(dict.fromkeys([m for c in sorted_open_claims for m in c.missing_conditions]))

        if len(final_claims) == 0:
            verdict = VerdictType.INSUFFICIENT_EVIDENCE
            winning = "INSUFFICIENT_EVIDENCE — No unmitigated offensive kill-chain, exploit sink, or hostile indicator verified in submitted records."
            confidence = 0.25
            disc_test = (
                "Provide additional process creation, authentication, DNS, or application handler telemetry if investigating a suspected incident."
            )
            rationale = "No unmitigated threat pattern matched submitted records; pipeline abstained cleanly."
            diag_status = "NO_THREAT_EVIDENCE"
            diag_summary = "Zero active threat claims constructed from submitted evidence."
        elif supported_claims:
            supported_ev_count = len({eid for c in supported_claims for eid in c.evidence_ids})
            verdict = classify_supported_verdict(ingestion.source_kind, len(supported_claims), supported_ev_count)
            if verdict == VerdictType.EXPLOITABLE_CHAIN:
                winning = clean_red.primary_hypothesis
                confidence = round(min(0.96, sup_a), 3)
                probe_cmd = clean_red.probes[0].payload_or_command if clean_red.probes else "Execute safe-audit reachability probe"
                disc_test = f"Run controlled safe-audit probe (`{probe_cmd}`) and submit patched code to verify fix."
                rationale = (
                    f"{len(supported_claims)} supported attack step(s) across {supported_ev_count} verified record(s); "
                    f"Purple Replay detection coverage is {int(replay.detection_coverage * 100)}%."
                )
            else:
                winning = clean_red.primary_hypothesis
                confidence = round(min(0.95, sup_a), 3)
                probe_cmd = clean_red.probes[0].payload_or_command if clean_red.probes else "Audit process lineage & egress"
                disc_test = f"Verify IOC elimination after remediation via `{probe_cmd}` and confirm Sigma coverage stays 100%."
                rationale = (
                    f"{len(supported_claims)} supported attack claim(s) verified"
                    + (f" ({len(refuted_claims)} unrelated claim(s) refuted)" if refuted_claims else "")
                    + f" across {independent_ev_count} citation(s); Purple Replay caught {replay.attack_events_detected}/{replay.attack_events_total} simulated events."
                )
            diag_status = "CONFIRMED_THREAT"
            diag_summary = (
                f"{len(supported_claims)} supported claim(s), {len(open_claims)} open, {len(refuted_claims)} refuted."
            )
        elif refuted_claims and not open_claims and coherent_refutes >= 1:
            verdict = VerdictType.FALSE_POSITIVE_BENIGN
            winning = clean_blue.competing_hypothesis
            confidence = round(min(0.96, sup_b), 3)
            disc_test = (
                "Verify trusted binary signature / secret rotation ticket referenced in contradicting evidence "
                f"({', '.join(eid for c in cleaned_contras if c.entity_coherent and c.impact_on_hypothesis == 'refutes' for eid in c.contradicting_evidence_ids[:3])})."
            )
            rationale = (
                f"{coherent_refutes} entity-coherent contradiction(s) refute every red threat claim; "
                f"Purple Replay verified {int(replay.false_positive_rate * 100)}% baseline false-positive rate."
            )
            diag_status = "REFUTED_FALSE_POSITIVE"
            diag_summary = f"All {len(refuted_claims)} red threat claim(s) refuted by entity-coherent defensive controls."
        else:
            verdict = VerdictType.INSUFFICIENT_EVIDENCE
            winning = (
                "INSUFFICIENT_EVIDENCE — Open investigative hypotheses remain due to missing conditions or uncorroborated single indicators."
            )
            confidence = round(min(0.60, 0.35 + 0.05 * len(verified)), 3)
            disc_test = (
                next_proofs[0]
                if next_proofs
                else "Append corroborating telemetry (process lineage, auth LogonType, or input sanitization trace) to resolve open claims."
            )
            rationale = (
                f"{len(open_claims)} open claim(s) await verification of missing conditions"
                + (f": {'; '.join(missing_summary[:2])}" if missing_summary else ".")
            )
            diag_status = "OPEN_HYPOTHESIS"
            diag_summary = (
                f"{len(open_claims)} open claim(s) require additional evidence before escalation or closure."
            )

        diagnosis_summary = DiagnosisSummary(
            status=diag_status,  # type: ignore[arg-type]
            analysis_mode=analysis_mode,  # type: ignore[arg-type]
            analysis_mode_label=analysis_mode_label,
            epistemic_scope=epistemic_scope,
            supported_claims_count=len(supported_claims),
            open_claims_count=len(open_claims),
            refuted_claims_count=len(refuted_claims),
            supported_claim_ids=[c.claim_id for c in supported_claims],
            open_claim_ids=[c.claim_id for c in open_claims],
            refuted_claim_ids=[c.claim_id for c in refuted_claims],
            high_priority_open_claim_ids=high_open_ids,
            priority_breakdown=priority_breakdown,
            missing_conditions_summary=missing_summary,
            next_required_proofs=next_proofs or [disc_test],
            summary=diag_summary,
        )

        pv = PurpleVerdict(
            verdict=verdict,
            winning_hypothesis=winning,
            confidence_score=confidence,
            hypothesis_a_support=sup_a,
            hypothesis_b_support=sup_b,
            verified_citations=verified,
            hallucinated_citations_removed=removed,
            incoherent_contradictions_rejected=incoherent_rejected,
            discriminating_test=disc_test,
            rationale=rationale,
            replay=replay,
            diagnosis=diagnosis_summary,
            simulation=sim_summary,
            remediation_verification=RemediationVerificationSummary(),
        )
        return clean_red, clean_blue, pv


__all__ = [
    "PurpleVerifier",
    "_collect_entity_sets",
    "_is_contradiction_entity_coherent",
    "_resolve_target_claims",
    "build_simulation_summary",
    "classify_supported_verdict",
    "determine_analysis_mode",
    "run_purple_replay",
    "summarize_claim_priorities",
]
