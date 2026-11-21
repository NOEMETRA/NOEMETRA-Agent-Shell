"""Shared Red claim/entity helpers and mutable RedPlanBuilder state for attack tracks."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    EvidenceRecord,
    MitreStep,
    RedOperationPlan,
    RedProbe,
    SimulatedAttackEvent,
)


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(n in low for n in needles)


def _infer_claim_priority(
    missing_conditions: List[str],
    tactic: str = "",
    technique_id: str = "",
) -> Tuple[str, str]:
    """Classify investigative priority of a claim based on completeness and tactical severity."""
    if not missing_conditions:
        is_critical = (
            tactic in ("Exfiltration", "Impact", "Privilege Escalation", "Initial Access")
            or technique_id in ("T1190", "T1552.005", "T1611", "T1048.003", "T1490", "T1059.004")
        )
        return (
            "critical" if is_critical else "high",
            "Tutte le condizioni di raggiungibilità o esecuzione risultano presenti nei record citati; richiesta verifica o contenimento immediato.",
        )
    if len(missing_conditions) == 1:
        return (
            "high",
            "Una singola prova discriminante separa l'ipotesi di compromissione/esposizione da un'attività ordinaria.",
        )
    if len(missing_conditions) == 2:
        return (
            "medium",
            "Indicatore parziale con più precondizioni non verificate; raccogliere telemetria di processo o volume prima di escalare.",
        )
    return (
        "low",
        "Indicatore singolo isolato privo di volume, processo originante e correlazione; bassa priorità finché non emergono anomalie.",
    )


def _format_evidence_bundle(ingestion: ArtifactIngestionResult) -> str:
    return "\n".join(f"[{ev.evidence_id}] ({ev.source_type}) {ev.raw_content}" for ev in ingestion.evidences)


def _is_unmitigated_sink_record(ev: EvidenceRecord) -> bool:
    sinks = ev.entities.get("sinks", [])
    controls = ev.entities.get("controls", [])
    if not sinks:
        return False
    for sink in sinks:
        if sink == "ssrf_fetch" and "url_allowlist" in controls:
            continue
        return True
    return False


def _collect_subject_entities(ev_by_id: Dict[str, EvidenceRecord], evidence_ids: List[str]) -> Dict[str, List[str]]:
    keys = ("hosts", "ips", "users", "processes", "endpoints")
    agg: Dict[str, List[str]] = {k: [] for k in keys}
    for eid in evidence_ids:
        ev = ev_by_id.get(eid)
        if not ev:
            continue
        for k in keys:
            for item in ev.entities.get(k, []):
                if item and item not in agg[k]:
                    agg[k].append(item)
    return agg


def _format_observed_fact(ev_by_id: Dict[str, EvidenceRecord], evidence_ids: List[str], summary_prefix: str = "") -> str:
    snippets: List[str] = []
    for eid in evidence_ids[:2]:
        ev = ev_by_id.get(eid)
        if ev:
            snippets.append(f"[{eid}] {ev.raw_content.strip()[:140]}")
    joined = " | ".join(snippets) if snippets else "No matching record snippet."
    return f"{summary_prefix} {joined}".strip() if summary_prefix else joined


def _group_records_by_host(records: List[EvidenceRecord]) -> List[Tuple[Optional[str], List[EvidenceRecord]]]:
    distinct_hosts: List[str] = []
    for r in records:
        for h in r.entities.get("hosts", []):
            if h not in distinct_hosts:
                distinct_hosts.append(h)
    if len(distinct_hosts) <= 1:
        return [(distinct_hosts[0] if distinct_hosts else None, records)]

    grouped: Dict[str, List[EvidenceRecord]] = {h: [] for h in distinct_hosts}
    unscoped: List[EvidenceRecord] = []
    for r in records:
        hs = r.entities.get("hosts", [])
        if hs:
            grouped[hs[0]].append(r)
        else:
            unscoped.append(r)
    out: List[Tuple[Optional[str], List[EvidenceRecord]]] = [(h, recs) for h, recs in grouped.items() if recs]
    if unscoped and out:
        out[0][1].extend(unscoped)
    elif unscoped:
        out.append((None, unscoped))
    return out


class RedPlanBuilder:
    """Mutable accumulator shared sequentially across deterministic Red attack tracks."""

    def __init__(self, ingestion: ArtifactIngestionResult) -> None:
        self.ingestion = ingestion
        self.threat_evs = [ev for ev in ingestion.evidences if not ev.is_benign_baseline]
        self.ev_by_id = {ev.evidence_id: ev for ev in ingestion.evidences}
        self.all_raw = "\n".join(ev.raw_content for ev in self.threat_evs)

        self.cited: List[str] = []
        self.kill_chain: List[MitreStep] = []
        self.claims: List[AnalyticalClaim] = []
        self.probes: List[RedProbe] = []
        self.sim_events: List[SimulatedAttackEvent] = []
        self.blind_spots: List[str] = []
        self.hypotheses: List[str] = []
        self.confidences: List[float] = []
        self.covered_eids: set[str] = set()

    def cite(self, eids: List[str]) -> None:
        for eid in eids:
            if eid not in self.cited:
                self.cited.append(eid)

    def add_step_and_claim(
        self,
        *,
        tactic: str,
        technique_id: str,
        technique_name: str,
        observed_fact: str,
        proposed_interpretation: str,
        evidence_ids: List[str],
        reachability_proof: str,
        missing_conditions: Optional[List[str]] = None,
        confirming_or_refuting_proof: str = "",
        priority: Optional[str] = None,
        priority_rationale: Optional[str] = None,
    ) -> None:
        missing = [m for m in (missing_conditions or []) if m]
        status = "open" if missing else "supported"
        inferred_prio, inferred_rationale = _infer_claim_priority(missing, tactic, technique_id)
        final_prio = priority if priority in ("critical", "high", "medium", "low") else inferred_prio
        final_rationale = priority_rationale or inferred_rationale
        step_idx = len(self.kill_chain)
        claim_id = f"CLM-{step_idx + 1:02d}"
        subj = _collect_subject_entities(self.ev_by_id, evidence_ids)
        self.cite(evidence_ids)
        self.covered_eids.update(evidence_ids)
        self.kill_chain.append(MitreStep(
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
            description=proposed_interpretation,
            evidence_ids=list(evidence_ids),
            reachability_proof=reachability_proof,
            claim_id=claim_id,
            observed_fact=observed_fact,
            proposed_interpretation=proposed_interpretation,
            missing_conditions=missing,
            confirming_or_refuting_proof=confirming_or_refuting_proof,
            status=status,  # type: ignore[arg-type]
        ))
        self.claims.append(AnalyticalClaim(
            claim_id=claim_id,
            step_index=step_idx,
            tactic=tactic,
            technique_id=technique_id,
            observed_fact=observed_fact,
            evidence_ids=list(evidence_ids),
            subject_entities=subj,
            proposed_interpretation=proposed_interpretation,
            missing_conditions=missing,
            confirming_or_refuting_proof=confirming_or_refuting_proof,
            status=status,  # type: ignore[arg-type]
            priority=final_prio,  # type: ignore[arg-type]
            priority_rationale=final_rationale,
        ))

    def add_sim(
        self,
        *,
        variant: str,
        log_line: str,
        mitre_technique_id: str,
        claim_id: str = "",
    ) -> None:
        self.sim_events.append(SimulatedAttackEvent(
            event_id=f"SIM-RED-{len(self.sim_events) + 1:02d}",
            variant=variant,  # type: ignore[arg-type]
            log_line=log_line,
            mitre_technique_id=mitre_technique_id,
            claim_id=claim_id or (self.claims[-1].claim_id if self.claims else ""),
        ))

    def next_probe_id(self) -> str:
        return f"RED-PRB-{len(self.probes) + 1:02d}"

    def build_plan(self) -> RedOperationPlan:
        if self.claims:
            primary_hyp = " | ".join(self.hypotheses) if len(self.hypotheses) > 1 else self.hypotheses[0]
            return RedOperationPlan(
                primary_hypothesis=primary_hyp,
                confidence=round(max(self.confidences), 3) if self.confidences else 0.50,
                kill_chain=self.kill_chain,
                claims=self.claims,
                blind_spots=list(dict.fromkeys(self.blind_spots))[:6],
                probes=self.probes[:6],
                simulated_events=self.sim_events,
                cited_evidence_ids=self.cited,
                model_used="deterministic",
            )

        return RedOperationPlan(
            primary_hypothesis="No unmitigated offensive kill-chain or exploit indicator identified in submitted records.",
            confidence=0.12,
            kill_chain=[],
            claims=[],
            blind_spots=["Telemetry contains no unmitigated exploit sinks, error anomalies, or lateral-movement indicators."],
            probes=[],
            simulated_events=[],
            cited_evidence_ids=[],
            model_used="deterministic",
        )
