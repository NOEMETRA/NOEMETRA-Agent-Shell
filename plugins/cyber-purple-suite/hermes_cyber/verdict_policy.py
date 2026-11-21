"""Entity coherence checks, verdict classification, analysis mode, and claim priority policies."""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    ContradictionItem,
    EvidenceRecord,
    VerdictType,
)

_PRIO_RANK: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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


def classify_supported_verdict(
    source_kind: str,
    supported_claims_count: int,
    independent_evidence_count: int,
) -> VerdictType:
    """Apply the uniform verifier threshold before escalating CONFIRMED_ATTACK to EXPLOITABLE_CHAIN."""
    has_code_or_config = source_kind in ("code", "config")
    if has_code_or_config and supported_claims_count >= 2 and independent_evidence_count >= 2:
        return VerdictType.EXPLOITABLE_CHAIN
    return VerdictType.CONFIRMED_ATTACK


def determine_analysis_mode(
    ingestion: ArtifactIngestionResult,
) -> Tuple[str, str, str]:
    """Classify the investigation workflow as event-driven, static artifact review, or hybrid."""
    non_base = [ev for ev in ingestion.evidences if not ev.is_benign_baseline] or list(ingestion.evidences)
    src_types = {ev.source_type for ev in non_base} if non_base else {ingestion.source_kind}
    has_static = bool(src_types & {"code", "config"})
    has_runtime = bool(src_types & {"log", "http"})
    if has_static and has_runtime:
        return (
            "hybrid_investigation",
            "Indagine Ibrida (Eventi Runtime + Codice/Config)",
            "Correlazione ibrida tra codice/configurazione e tracce runtime: verifica sia la superficie statica sia l'evidenza osservata.",
        )
    if has_static or ingestion.source_kind in ("code", "config"):
        return (
            "artifact_review",
            "Revisione Statica di Codice e Configurazioni",
            "Revisione statica di codice/configurazione: individua superfici esposte e controlli assenti; richiede verifica runtime post-modifica.",
        )
    return (
        "event_investigation",
        "Indagine su Eventi (Log / Tracce HTTP)",
        "Valutazione forense su eventi e tracce HTTP: stabilisce cosa è accaduto nei record disponibili e quali prove mancano.",
    )


def summarize_claim_priorities(
    claims: List[AnalyticalClaim],
) -> Tuple[Dict[str, int], List[str], List[str], List[AnalyticalClaim]]:
    """Compute priority counts, high-priority open claim IDs, and prioritized open proofs."""
    breakdown: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in claims:
        key = c.priority if c.priority in breakdown else "medium"
        breakdown[key] += 1

    open_claims = [c for c in claims if c.status == "open"]
    sorted_open = sorted(open_claims, key=lambda c: (_PRIO_RANK.get(c.priority, 2), c.step_index))
    high_open_ids = [c.claim_id for c in sorted_open if c.priority in ("critical", "high")]
    ordered_proofs = list(dict.fromkeys([c.confirming_or_refuting_proof for c in sorted_open if c.confirming_or_refuting_proof]))
    return breakdown, high_open_ids, ordered_proofs, sorted_open
