"""Deterministic Sigma/YARA replay engine and simulation summary builder."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    PurpleReplayReport,
    RedOperationPlan,
    ReplayEventResult,
    SigmaRuleSpec,
    SimulationSummary,
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
