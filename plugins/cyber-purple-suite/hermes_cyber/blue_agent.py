"""Defensive Blue Investigator, Contradiction Critic, and Detection/Patch Synthesis Agent."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from hermes_cyber.blue_cases_controls import evaluate_blue_control_contradictions
from hermes_cyber.blue_cases_threats import evaluate_blue_threat_cases
from hermes_cyber.blue_rules import _build_sigma_yaml, _build_yara_text
from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    RedOperationPlan,
)
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


def _synthesize_deterministic_blue_report(
    ingestion: ArtifactIngestionResult,
    red_plan: RedOperationPlan,
) -> BlueInvestigationReport:
    all_raw = "\n".join(ev.raw_content for ev in ingestion.evidences)
    contradictions: List[ContradictionItem] = []
    cited: List[str] = []
    refuted_claim_ids: set[str] = set()

    ctrl_report = evaluate_blue_control_contradictions(
        ingestion,
        red_plan,
        cited,
        contradictions,
        refuted_claim_ids,
    )
    if ctrl_report is not None:
        return ctrl_report

    return evaluate_blue_threat_cases(
        ingestion,
        red_plan,
        all_raw,
        cited,
        contradictions,
        refuted_claim_ids,
    )


class BlueInvestigatorAgent:
    """Defensive Critic searching for entity-coherent contradictions, Sigma/YARA rules, and remediation patches."""

    def analyze(
        self,
        ingestion: ArtifactIngestionResult,
        red_plan: RedOperationPlan,
        router: Optional[ModelRouter] = None,
    ) -> Tuple[BlueInvestigationReport, bool, Dict[str, int]]:
        base_report = _synthesize_deterministic_blue_report(ingestion, red_plan)
        if router is None:
            return base_report, False, {"private_ips": 0, "secrets": 0, "emails": 0}

        sys_prompt = (
            "You are the BLUE INVESTIGATOR & ADVERSARIAL CRITIC. Your duty is to hunt for ENTITY-COHERENT CONTRADICTIONS "
            "against specific Red claims (`CLM-xx`) using ONLY [EV-xxxx] records that match the same host/user/process/window. "
            "Reply strictly with JSON: competing_hypothesis, confidence (0..1), replace_contradictions (optional bool), "
            "contradictions or extra_contradictions ([{claim_challenged, target_claim_id, target_evidence_ids, "
            "contradicting_evidence_ids, explanation, impact_on_hypothesis}]), "
            "detection_keywords (optional full replacement list) or extra_detection_keywords (list), "
            "remediation_patch (optional string), extra_hardening (list), cited_evidence_ids."
        )
        claims_summary = "\n".join(
            f"- {c.claim_id} ({c.tactic}, entities={c.subject_entities}): {c.observed_fact} | Interp: {c.proposed_interpretation}"
            for c in red_plan.claims
        ) or "(none)"
        ev_bundle = "\n".join(f"[{e.evidence_id}] {e.raw_content}" for e in ingestion.evidences)
        user_prompt = (
            f"Red Hypothesis: {red_plan.primary_hypothesis}\n"
            f"Red Claims:\n{claims_summary}\n"
            f"Red Blind Spots: {red_plan.blind_spots}\n"
            f"Evidence Records:\n{ev_bundle}"
        )
        parsed, model_label, scrubbed, scrub_stats = invoke_router_json(
            router,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            scrubber=PrivacyScrubber(),
        )
        if not parsed:
            return base_report, scrubbed, scrub_stats

        valid_ids = {ev.evidence_id for ev in ingestion.evidences}
        llm_cited = [str(eid) for eid in (parsed.get("cited_evidence_ids") or []) if str(eid) in valid_ids]

        replace_contras = bool(parsed.get("replace_contradictions")) or isinstance(parsed.get("contradictions"), list)
        raw_contras = parsed.get("contradictions") if isinstance(parsed.get("contradictions"), list) else parsed.get("extra_contradictions")
        contradictions: List[ContradictionItem] = [] if replace_contras else list(base_report.contradictions)

        for item in raw_contras or []:
            if isinstance(item, dict) and item.get("explanation"):
                c_ids = [str(eid) for eid in (item.get("contradicting_evidence_ids") or []) if str(eid) in valid_ids]
                t_eids = [str(eid) for eid in (item.get("target_evidence_ids") or []) if str(eid) in valid_ids]
                t_cid = str(item.get("target_claim_id") or "").strip() or None
                impact = str(item.get("impact_on_hypothesis") or "contextualizes")
                if impact not in ("refutes", "weakens", "contextualizes"):
                    impact = "contextualizes"
                contradictions.append(ContradictionItem(
                    claim_challenged=str(item.get("claim_challenged") or red_plan.primary_hypothesis),
                    target_claim_id=t_cid,
                    target_evidence_ids=t_eids,
                    contradicting_evidence_ids=c_ids,
                    explanation=str(item["explanation"]),
                    impact_on_hypothesis=impact,  # type: ignore[arg-type]
                    entity_coherent=True,
                ))

        merged_cited = (
            list(dict.fromkeys([*llm_cited, *(eid for c in contradictions for eid in c.contradicting_evidence_ids)]))
            if replace_contras
            else list(dict.fromkeys([*base_report.cited_evidence_ids, *llm_cited]))
        )

        sigma = base_report.sigma_rule.model_copy(deep=True)
        if isinstance(parsed.get("detection_keywords"), list) and parsed["detection_keywords"]:
            sigma.detection_keywords = [str(k).strip() for k in parsed["detection_keywords"] if str(k).strip()]
        else:
            extra_kws = [str(k).strip() for k in (parsed.get("extra_detection_keywords") or []) if str(k).strip()]
            sigma.detection_keywords = list(dict.fromkeys([*sigma.detection_keywords, *extra_kws]))
        sigma.yaml_text = _build_sigma_yaml(sigma)

        extra_hard = [str(h).strip() for h in (parsed.get("extra_hardening") or []) if str(h).strip()]
        hardening = list(dict.fromkeys([*base_report.hardening_steps, *extra_hard]))

        comp = str(parsed.get("competing_hypothesis") or "").strip() or base_report.competing_hypothesis
        patch = str(parsed.get("remediation_patch") or "").strip() or base_report.remediation_patch
        try:
            conf = max(0.0, min(1.0, float(parsed.get("confidence", base_report.confidence))))
        except Exception:
            conf = base_report.confidence

        final_conf = round(conf, 3) if replace_contras else round((base_report.confidence + conf) / 2.0, 3)

        enriched = base_report.model_copy(update={
            "competing_hypothesis": comp,
            "confidence": final_conf,
            "contradictions": contradictions[:8],
            "sigma_rule": sigma,
            "remediation_patch": patch,
            "hardening_steps": hardening[:6],
            "cited_evidence_ids": merged_cited,
            "model_used": model_label,
        })
        return enriched, scrubbed, scrub_stats


__all__ = [
    "BlueInvestigatorAgent",
    "_build_sigma_yaml",
    "_build_yara_text",
    "_synthesize_deterministic_blue_report",
]
