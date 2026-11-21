"""Penetrating Red Operator & Attack Emulation Agent with structured observed-vs-hypothesized claims."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    MitreStep,
    RedOperationPlan,
    RedProbe,
    SimulatedAttackEvent,
)
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.red_claims import (
    RedPlanBuilder,
    _collect_subject_entities,
    _format_evidence_bundle,
    _format_observed_fact,
    _has_any,
    _infer_claim_priority,
)
from hermes_cyber.red_tracks_appsec import (
    run_track1_code_ssrf,
    run_track2_dns_exfil,
    run_track2b_waf_deser,
)
from hermes_cyber.red_tracks_host import (
    run_track3_ransomware,
    run_track3b_bruteforce,
    run_track4_lateral,
    run_track4b_fallback_sinks,
)
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


def _synthesize_deterministic_red_plan(ingestion: ArtifactIngestionResult) -> RedOperationPlan:
    """Analyze ingested artifacts per phenomenon/entity into structured observed-vs-hypothesized claims."""
    builder = RedPlanBuilder(ingestion)
    run_track1_code_ssrf(builder)
    run_track2_dns_exfil(builder)
    run_track2b_waf_deser(builder)
    run_track3_ransomware(builder)
    run_track3b_bruteforce(builder)
    run_track4_lateral(builder)
    run_track4b_fallback_sinks(builder)
    return builder.build_plan()


class RedOperatorAgent:
    """Offensive Red Team agent constructing MITRE chains, structured claims, safe probes, and simulations."""

    def analyze(
        self,
        ingestion: ArtifactIngestionResult,
        router: Optional[ModelRouter] = None,
    ) -> Tuple[RedOperationPlan, bool, Dict[str, int]]:
        base_plan = _synthesize_deterministic_red_plan(ingestion)
        if router is None:
            return base_plan, False, {"private_ips": 0, "secrets": 0, "emails": 0}

        sys_prompt = (
            "You are the RED OPERATOR in a Purple Team cyber audit. Analyze ONLY the cited [EV-xxxx] records. "
            "Separate OBSERVED FACTS from HYPOTHESIZED INTERPRETATIONS and MISSING CONDITIONS. "
            "Reply strictly with JSON keys: primary_hypothesis (string), confidence (0..1), "
            "kill_chain (optional list of {tactic, technique_id, technique_name, observed_fact, proposed_interpretation, "
            "missing_conditions, confirming_or_refuting_proof, evidence_ids, reachability_proof}), "
            "simulated_events (optional list of {variant, log_line, mitre_technique_id}), "
            "blind_spots (list of strings), extra_probes (list of {title, payload_or_command, expected_ioc}), "
            "and cited_evidence_ids (list of EV-xxxx IDs)."
        )
        user_prompt = (
            f"Artifact Title: {ingestion.title}\nKind: {ingestion.source_kind}\nRecords:\n"
            f"{_format_evidence_bundle(ingestion)}"
        )
        parsed, model_label, scrubbed, scrub_stats = invoke_router_json(
            router,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            scrubber=PrivacyScrubber(),
        )
        if not parsed:
            return base_plan, scrubbed, scrub_stats

        ev_by_id = {ev.evidence_id: ev for ev in ingestion.evidences}
        valid_ids = set(ev_by_id.keys())
        llm_cited = [str(eid) for eid in (parsed.get("cited_evidence_ids") or []) if str(eid) in valid_ids]

        hyp = str(parsed.get("primary_hypothesis") or "").strip() or base_plan.primary_hypothesis
        try:
            conf = max(0.0, min(1.0, float(parsed.get("confidence", base_plan.confidence))))
        except Exception:
            conf = base_plan.confidence

        llm_chain_raw = parsed.get("kill_chain")
        full_chain_override = isinstance(llm_chain_raw, list) and len(llm_chain_raw) > 0

        if full_chain_override:
            new_steps: List[MitreStep] = []
            new_claims: List[AnalyticalClaim] = []
            for idx, item in enumerate(llm_chain_raw):
                if not isinstance(item, dict):
                    continue
                step_eids = [str(e) for e in (item.get("evidence_ids") or []) if str(e) in valid_ids]
                obs = str(item.get("observed_fact") or item.get("description") or hyp).strip()
                interp = str(item.get("proposed_interpretation") or item.get("description") or hyp).strip()
                missing = [str(m).strip() for m in (item.get("missing_conditions") or []) if str(m).strip()]
                proof = str(item.get("confirming_or_refuting_proof") or "Verify referenced evidence independently.").strip()
                cid = f"CLM-{idx + 1:02d}"
                status = "open" if (missing or not step_eids) else "supported"
                new_steps.append(MitreStep(
                    tactic=str(item.get("tactic") or "Execution"),
                    technique_id=str(item.get("technique_id") or "T1059"),
                    technique_name=str(item.get("technique_name") or "LLM Revised Step"),
                    description=interp,
                    evidence_ids=step_eids,
                    reachability_proof=str(item.get("reachability_proof") or obs),
                    claim_id=cid,
                    observed_fact=obs,
                    proposed_interpretation=interp,
                    missing_conditions=missing,
                    confirming_or_refuting_proof=proof,
                    status=status,  # type: ignore[arg-type]
                ))
                inferred_prio, inferred_rat = _infer_claim_priority(missing, new_steps[-1].tactic, new_steps[-1].technique_id)
                raw_prio = str(item.get("priority") or "").lower().strip()
                final_prio = raw_prio if raw_prio in ("critical", "high", "medium", "low") else inferred_prio
                final_rat = str(item.get("priority_rationale") or "").strip() or inferred_rat
                new_claims.append(AnalyticalClaim(
                    claim_id=cid,
                    step_index=idx,
                    tactic=new_steps[-1].tactic,
                    technique_id=new_steps[-1].technique_id,
                    observed_fact=obs,
                    evidence_ids=step_eids,
                    subject_entities=_collect_subject_entities(ev_by_id, step_eids),
                    proposed_interpretation=interp,
                    missing_conditions=missing,
                    confirming_or_refuting_proof=proof,
                    status=status,  # type: ignore[arg-type]
                    priority=final_prio,  # type: ignore[arg-type]
                    priority_rationale=final_rat,
                ))
            final_chain = new_steps
            final_claims = new_claims
            merged_cited = list(dict.fromkeys([*llm_cited, *(eid for s in final_chain for eid in s.evidence_ids)]))
            final_conf = round(conf, 3)
        else:
            final_chain = list(base_plan.kill_chain)
            final_claims = [c.model_copy(deep=True) for c in base_plan.claims]
            merged_cited = list(dict.fromkeys([*base_plan.cited_evidence_ids, *llm_cited]))
            final_conf = round((base_plan.confidence + conf) / 2.0, 3)

        llm_sims_raw = parsed.get("simulated_events")
        if isinstance(llm_sims_raw, list) and len(llm_sims_raw) > 0:
            final_sims: List[SimulatedAttackEvent] = []
            for idx, se in enumerate(llm_sims_raw, start=1):
                if isinstance(se, dict) and se.get("log_line"):
                    var = str(se.get("variant") or "baseline_attack")
                    if var not in ("baseline_attack", "evasion_variant"):
                        var = "baseline_attack"
                    final_sims.append(SimulatedAttackEvent(
                        event_id=f"SIM-RED-{idx:02d}",
                        variant=var,  # type: ignore[arg-type]
                        log_line=str(se["log_line"]),
                        mitre_technique_id=str(se.get("mitre_technique_id") or ""),
                    ))
            if not final_sims:
                final_sims = list(base_plan.simulated_events)
        else:
            final_sims = list(base_plan.simulated_events)

        extra_blind = [str(b).strip() for b in (parsed.get("blind_spots") or []) if str(b).strip()]
        merged_blind = (
            extra_blind[:6]
            if full_chain_override and extra_blind
            else list(dict.fromkeys([*base_plan.blind_spots, *extra_blind]))[:6]
        )

        base_probes = [] if full_chain_override else list(base_plan.probes)
        extra_probes: List[RedProbe] = list(base_probes)
        for idx, p in enumerate(parsed.get("extra_probes") or [], start=len(extra_probes) + 1):
            if isinstance(p, dict) and p.get("payload_or_command"):
                extra_probes.append(RedProbe(
                    probe_id=f"RED-LLM-{idx:02d}",
                    title=str(p.get("title") or "LLM Audit Probe"),
                    target_surface=str(p.get("target_surface") or ingestion.title),
                    method_or_vector="LLM-suggested safe-audit",
                    payload_or_command=str(p["payload_or_command"]),
                    expected_ioc=str(p.get("expected_ioc") or "Inspect response telemetry"),
                ))

        enriched = base_plan.model_copy(update={
            "primary_hypothesis": hyp,
            "confidence": final_conf,
            "kill_chain": final_chain,
            "claims": final_claims,
            "blind_spots": merged_blind,
            "probes": extra_probes[:6],
            "simulated_events": final_sims,
            "cited_evidence_ids": merged_cited,
            "model_used": model_label,
        })
        return enriched, scrubbed, scrub_stats


__all__ = [
    "RedOperatorAgent",
    "_collect_subject_entities",
    "_format_observed_fact",
    "_has_any",
    "_infer_claim_priority",
    "_synthesize_deterministic_red_plan",
]
