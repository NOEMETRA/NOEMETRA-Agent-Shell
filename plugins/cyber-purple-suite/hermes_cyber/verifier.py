"""Deterministic Purple Verifier: Citation Grounding, Entity Coherence, Claim Evaluation, Replay, and Verdict Arbiter."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    DiagnosisSummary,
    EvidenceRecord,
    PurpleReplayReport,
    PurpleVerdict,
    RedOperationPlan,
    RemediationVerificationSummary,
    ReplayEventResult,
    SigmaRuleSpec,
    SimulationSummary,
    VerdictType,
    YaraRuleSpec,
)


def _match_sigma(raw_text: str, sigma: SigmaRuleSpec) -> Tuple[bool, List[str]]:
    low = raw_text.lower()
    for exc_vals in sigma.exclude_fields.values():
        for val in exc_vals:
            if val and val.lower() in low:
                return False, []

    matched_kws: List[str] = []
    for kw in sigma.detection_keywords:
        if kw and kw.lower() in low:
            matched_kws.append(kw)

    field_match = False
    for vals in sigma.detection_fields.values():
        if vals and all(v.lower() in low for v in vals):
            field_match = True

    return (bool(matched_kws) or field_match), matched_kws


def _match_yara(raw_text: str, yara: YaraRuleSpec) -> bool:
    low = raw_text.lower()
    hits = [s for s in yara.strings if s and s.lower() in low]
    if not yara.strings:
        return False
    if "all" in (yara.condition or "").lower():
        return len(hits) == len(yara.strings)
    return len(hits) > 0


def run_purple_replay(
    ingestion: ArtifactIngestionResult,
    red_report: RedOperationPlan,
    blue_report: BlueInvestigationReport,
    *,
    custom_keywords: Optional[List[str]] = None,
    custom_excludes: Optional[List[str]] = None,
    skip_claim_ids: Optional[Set[str]] = None,
) -> PurpleReplayReport:
    """Execute Blue Team Sigma + YARA rules against Red simulated attacks, evasion probes, and benign baseline."""
    sigma = blue_report.sigma_rule.model_copy(deep=True)
    if custom_keywords is not None:
        sigma.detection_keywords = [k.strip() for k in custom_keywords if k.strip()]
    if custom_excludes is not None:
        sigma.exclude_fields = {"custom_filter": [x.strip() for x in custom_excludes if x.strip()]}

    yara = blue_report.yara_rule
    eval_yara = custom_keywords is None
    results: List[ReplayEventResult] = []
    gaps: List[str] = []

    atk_total = 0
    atk_det = 0
    eva_total = 0
    eva_det = 0
    ben_total = 0
    fp_count = 0

    for sim in red_report.simulated_events:
        if skip_claim_ids and sim.claim_id and sim.claim_id in skip_claim_ids:
            continue
        m_sig, kws = _match_sigma(sim.log_line, sigma)
        m_yar = _match_yara(sim.log_line, yara) if eval_yara else False
        detected = m_sig or m_yar
        results.append(ReplayEventResult(
            event_id=sim.event_id,
            variant=sim.variant,
            matched_sigma=m_sig,
            matched_yara=m_yar,
            matched_keywords=kws,
        ))
        atk_total += 1
        if detected:
            atk_det += 1
        else:
            gaps.append(f"Missed Red simulation `{sim.event_id}` ({sim.variant}): {sim.log_line[:90]}")

        if sim.variant == "evasion_variant":
            eva_total += 1
            if detected:
                eva_det += 1

    for ev in ingestion.evidences:
        if ev.is_benign_baseline:
            ben_total += 1
            m_sig, kws = _match_sigma(ev.raw_content, sigma)
            m_yar = _match_yara(ev.raw_content, yara) if eval_yara else False
            if m_sig or m_yar:
                fp_count += 1
                gaps.append(f"False positive triggered on baseline `{ev.evidence_id}`.")
            results.append(ReplayEventResult(
                event_id=ev.evidence_id,
                variant="benign_baseline",
                matched_sigma=m_sig,
                matched_yara=m_yar,
                matched_keywords=kws,
            ))

    coverage = round(atk_det / atk_total, 3) if atk_total > 0 else 1.0
    evasion_rate = round(eva_det / eva_total, 3) if eva_total > 0 else coverage
    fpr = round(fp_count / ben_total, 3) if ben_total > 0 else 0.0

    return PurpleReplayReport(
        attack_events_total=atk_total,
        attack_events_detected=atk_det,
        evasion_events_total=eva_total,
        evasion_events_detected=eva_det,
        benign_events_tested=ben_total,
        false_positives_count=fp_count,
        detection_coverage=coverage,
        evasion_caught_rate=evasion_rate,
        false_positive_rate=fpr,
        event_results=results,
        defense_gaps=gaps,
    )


def _collect_entity_sets(eids: List[str], ev_by_id: Dict[str, EvidenceRecord]) -> Dict[str, Set[str]]:
    keys = ("hosts", "ips", "users", "processes", "endpoints")
    out: Dict[str, Set[str]] = {k: set() for k in keys}
    for eid in eids:
        ev = ev_by_id.get(eid)
        if not ev:
            continue
        for k in keys:
            for val in ev.entities.get(k, []):
                if val:
                    out[k].add(val.lower())
    return out


def _is_contradiction_entity_coherent(
    contra: ContradictionItem,
    target_claims: List[AnalyticalClaim],
    ev_by_id: Dict[str, EvidenceRecord],
) -> bool:
    if not contra.contradicting_evidence_ids:
        return False

    c_ents = _collect_entity_sets(contra.contradicting_evidence_ids, ev_by_id)
    target_eids: List[str] = list(contra.target_evidence_ids)
    for tc in target_claims:
        target_eids.extend(tc.evidence_ids)
    t_ents = _collect_entity_sets(target_eids, ev_by_id)
    # Include subject_entities attached directly on claims in case custom claims supply entities directly
    for tc in target_claims:
        for k in ("hosts", "ips", "users", "processes", "endpoints"):
            for val in tc.subject_entities.get(k, []):
                if val:
                    t_ents[k].add(val.lower())

    # Strict cross-host rejection: evidence from Host A cannot refute/weaken a claim on distinct Host B,
    # even if both hosts happen to use the same service account or IP address.
    if c_ents["hosts"] and t_ents["hosts"] and c_ents["hosts"].isdisjoint(t_ents["hosts"]):
        return False

    shared_user = bool(c_ents["users"] and t_ents["users"] and (c_ents["users"] & t_ents["users"]))

    # Reject refutations/weakenings between disjoint IPs or disjoint user accounts when hosts do not bridge them
    if contra.impact_on_hypothesis in ("refutes", "weakens") and not (c_ents["hosts"] & t_ents["hosts"]):
        if c_ents["ips"] and t_ents["ips"] and c_ents["ips"].isdisjoint(t_ents["ips"]) and not shared_user:
            return False
        if not c_ents["ips"] and not t_ents["ips"] and c_ents["users"] and t_ents["users"] and c_ents["users"].isdisjoint(t_ents["users"]):
            return False

    return True


def _resolve_target_claims(
    contra: ContradictionItem,
    claims: List[AnalyticalClaim],
    ev_by_id: Dict[str, EvidenceRecord],
) -> List[AnalyticalClaim]:
    if not claims:
        return []
    if contra.target_claim_id:
        matched = [c for c in claims if c.claim_id == contra.target_claim_id]
        if matched:
            return matched

    if contra.target_evidence_ids:
        t_set = set(contra.target_evidence_ids)
        matched = [c for c in claims if set(c.evidence_ids) & t_set]
        if matched:
            return matched

    if len(claims) == 1:
        return [claims[0]]

    # Match claims sharing entities with contradicting evidence when target ID wasn't explicitly specified
    c_ents = _collect_entity_sets(contra.contradicting_evidence_ids, ev_by_id)
    matched: List[AnalyticalClaim] = []
    for clm in claims:
        clm_ents = _collect_entity_sets(clm.evidence_ids, ev_by_id)
        for k in ("hosts", "ips", "users", "endpoints"):
            if c_ents[k] and clm_ents[k] and (c_ents[k] & clm_ents[k]):
                matched.append(clm)
                break
    return matched


def build_simulation_summary(replay: PurpleReplayReport) -> SimulationSummary:
    if replay.attack_events_total == 0 and replay.benign_events_tested == 0:
        return SimulationSummary(
            status="NOT_APPLICABLE",
            detection_coverage=replay.detection_coverage,
            evasion_caught_rate=replay.evasion_caught_rate,
            false_positive_rate=replay.false_positive_rate,
            summary="No simulated attack events or benign baseline records to evaluate.",
        )
    if replay.false_positive_rate > 0.0:
        status = "FALSE_POSITIVE_RISK"
    elif replay.detection_coverage >= 1.0:
        status = "COVERAGE_COMPLETE"
    else:
        status = "COVERAGE_PARTIAL"
    return SimulationSummary(
        status=status,  # type: ignore[arg-type]
        detection_coverage=replay.detection_coverage,
        evasion_caught_rate=replay.evasion_caught_rate,
        false_positive_rate=replay.false_positive_rate,
        summary=(
            f"Rules caught {replay.attack_events_detected}/{replay.attack_events_total} synthetic events "
            f"(coverage {int(replay.detection_coverage * 100)}%) with {replay.false_positives_count}/{replay.benign_events_tested} "
            f"baseline false positives ({int(replay.false_positive_rate * 100)}% FPR)."
        ),
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
                c_status = "refuted"
            elif (not clm.evidence_ids) or bool(clm.missing_conditions) or (clm.claim_id in weakened_claim_ids):
                c_status = "open"
            else:
                c_status = "supported"
            final_claims.append(clm.model_copy(update={"status": c_status}))

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

        has_code_or_config = ingestion.source_kind in ("code", "config")
        independent_ev_count = len(verified)
        sup_a = round(min(0.97, max(0.05, clean_red.confidence - 0.25 * (coherent_refutes if not supported_claims else 0) - 0.15 * coherent_weakens)), 3)
        sup_b = round(min(0.97, max(0.05, clean_blue.confidence + 0.10 * coherent_refutes)), 3)

        missing_summary = list(dict.fromkeys([m for c in open_claims for m in c.missing_conditions]))
        next_proofs = list(dict.fromkeys([c.confirming_or_refuting_proof for c in open_claims if c.confirming_or_refuting_proof]))

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
            if has_code_or_config and len(supported_claims) >= 2 and independent_ev_count >= 2:
                verdict = VerdictType.EXPLOITABLE_CHAIN
                winning = clean_red.primary_hypothesis
                confidence = round(min(0.96, sup_a), 3)
                probe_cmd = clean_red.probes[0].payload_or_command if clean_red.probes else "Execute safe-audit reachability probe"
                disc_test = f"Run controlled safe-audit probe (`{probe_cmd}`) and submit patched code to verify fix."
                rationale = (
                    f"{len(supported_claims)} supported attack step(s) across {independent_ev_count} verified record(s); "
                    f"Purple Replay detection coverage is {int(replay.detection_coverage * 100)}%."
                )
            else:
                verdict = VerdictType.CONFIRMED_ATTACK
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
            supported_claims_count=len(supported_claims),
            open_claims_count=len(open_claims),
            refuted_claims_count=len(refuted_claims),
            supported_claim_ids=[c.claim_id for c in supported_claims],
            open_claim_ids=[c.claim_id for c in open_claims],
            refuted_claim_ids=[c.claim_id for c in refuted_claims],
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
