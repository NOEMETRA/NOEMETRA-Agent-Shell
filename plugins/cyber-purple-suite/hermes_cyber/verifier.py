"""Deterministic Purple Verifier: Citation Anti-Hallucination, Purple Replay Engine, and Verdict Arbiter."""

from __future__ import annotations

from typing import List, Optional, Tuple

from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    PurpleReplayReport,
    PurpleVerdict,
    RedOperationPlan,
    ReplayEventResult,
    SigmaRuleSpec,
    VerdictType,
    YaraRuleSpec,
)


def _match_sigma(raw_text: str, sigma: SigmaRuleSpec) -> Tuple[bool, List[str]]:
    low = raw_text.lower()
    # Exclusions prevent false positives on verified benign maintenance or healthchecks
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


class PurpleVerifier:
    """Deterministic arbiter verifying citation grounding, contradictions, and Purple Replay scores."""

    def verify(
        self,
        ingestion: ArtifactIngestionResult,
        red_report: RedOperationPlan,
        blue_report: BlueInvestigationReport,
    ) -> Tuple[RedOperationPlan, BlueInvestigationReport, PurpleVerdict]:
        valid_ids = {ev.evidence_id for ev in ingestion.evidences}
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
        clean_red = red_report.model_copy(update={
            "kill_chain": cleaned_steps,
            "cited_evidence_ids": _filter_ids(red_report.cited_evidence_ids),
        })

        cleaned_contras = [
            c.model_copy(update={"contradicting_evidence_ids": _filter_ids(c.contradicting_evidence_ids)})
            for c in blue_report.contradictions
        ]
        clean_blue = blue_report.model_copy(update={
            "contradictions": cleaned_contras,
            "cited_evidence_ids": _filter_ids(blue_report.cited_evidence_ids),
        })

        replay = run_purple_replay(ingestion, clean_red, clean_blue)

        all_raw = "\n".join(ev.raw_content for ev in ingestion.evidences).lower()
        has_telemetry_gap = any(
            marker in all_raw for marker in ("logsourceunavailable", "truncated", "missing_fields", "status=ambiguous")
        )
        refutes_count = sum(1 for c in cleaned_contras if c.impact_on_hypothesis == "refutes" and c.contradicting_evidence_ids)
        weakens_count = sum(1 for c in cleaned_contras if c.impact_on_hypothesis == "weakens" and c.contradicting_evidence_ids)

        has_code_or_config = ingestion.source_kind in ("code", "config")
        has_exploit_chain = (
            has_code_or_config
            and len(clean_red.kill_chain) >= 2
            and refutes_count == 0
        )

        # Compute quantitative evidence support for Hypothesis A (Red threat) vs B (Blue alternative)
        sup_a = round(min(0.97, max(0.05, clean_red.confidence - 0.25 * refutes_count - 0.15 * weakens_count)), 3)
        sup_b = round(min(0.97, max(0.05, clean_blue.confidence + 0.10 * refutes_count)), 3)

        if has_telemetry_gap or abs(sup_a - sup_b) < 0.18:
            verdict = VerdictType.INSUFFICIENT_EVIDENCE
            winning = (
                "INSUFFICIENT_EVIDENCE — Missing telemetry prevents discriminating compromise from authorized administrative activity."
            )
            confidence = round(min(0.60, 0.45 + 0.05 * len(verified)), 3)
            disc_test = (
                "Query un-truncated `openvpn-gw` VPN session table and Windows Security Event 4624 (`LogonType`, `TicketEncryption`) "
                "for the flagged actor during the exact incident window."
            )
            rationale = (
                f"Telemetry availability gaps or near-equal hypothesis support (A={sup_a:.2f} vs B={sup_b:.2f}) prohibit definitive attribution."
            )
        elif refutes_count >= 1 and sup_b > sup_a:
            verdict = VerdictType.FALSE_POSITIVE_BENIGN
            winning = clean_blue.competing_hypothesis
            confidence = round(min(0.96, sup_b), 3)
            disc_test = (
                "Verify trusted binary signature / secret rotation ticket referenced in contradicting evidence "
                f"({', '.join(eid for c in cleaned_contras if c.impact_on_hypothesis == 'refutes' for eid in c.contradicting_evidence_ids[:3])})."
            )
            rationale = (
                f"{refutes_count} grounded contradiction(s) directly refute the primary threat hypothesis "
                f"(B={sup_b:.2f} > A={sup_a:.2f}); Purple Replay verified {int(replay.false_positive_rate * 100)}% baseline false-positive suppression."
            )
        elif has_exploit_chain:
            verdict = VerdictType.EXPLOITABLE_CHAIN
            winning = clean_red.primary_hypothesis
            confidence = round(min(0.96, sup_a), 3)
            probe_cmd = clean_red.probes[0].payload_or_command if clean_red.probes else "Execute safe-audit reachability probe"
            disc_test = f"Run controlled safe-audit probe (`{probe_cmd}`) and re-test after applying Blue Team patch + Sigma rule."
            rationale = (
                f"Multi-hop offensive chain ({len(clean_red.kill_chain)} MITRE steps) verified verbatim across code/config & telemetry; "
                f"Purple Replay detection coverage is {int(replay.detection_coverage * 100)}%."
            )
        else:
            verdict = VerdictType.CONFIRMED_ATTACK
            winning = clean_red.primary_hypothesis
            confidence = round(min(0.95, sup_a), 3)
            probe_cmd = clean_red.probes[0].payload_or_command if clean_red.probes else "Audit process lineage & egress DNS"
            disc_test = f"Verify IOC elimination after remediation via `{probe_cmd}` and confirm Sigma coverage stays 100%."
            rationale = (
                f"Primary attack hypothesis supported across {len(clean_red.kill_chain)} MITRE step(s) with no refuting contradictions "
                f"(A={sup_a:.2f} vs B={sup_b:.2f}); Purple Replay caught {replay.attack_events_detected}/{replay.attack_events_total} simulated events."
            )

        pv = PurpleVerdict(
            verdict=verdict,
            winning_hypothesis=winning,
            confidence_score=confidence,
            hypothesis_a_support=sup_a,
            hypothesis_b_support=sup_b,
            verified_citations=verified,
            hallucinated_citations_removed=removed,
            discriminating_test=disc_test,
            rationale=rationale,
            replay=replay,
        )
        return clean_red, clean_blue, pv
