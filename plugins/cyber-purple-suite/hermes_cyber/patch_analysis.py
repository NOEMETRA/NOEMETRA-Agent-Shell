"""Surface-block partitioning, semantic claim matching, and remediation diff verification helpers."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from hermes_cyber.models import AnalyticalClaim, ArtifactIngestionResult, VerdictType
from hermes_cyber.red_agent import _collect_subject_entities, _format_observed_fact


def _claims_semantically_match(c1: AnalyticalClaim, c2: AnalyticalClaim) -> bool:
    """Match two claims across re-analysis by tactic, technique family, and shared entities rather than ordinal ID."""
    if c1.tactic.strip().lower() != c2.tactic.strip().lower():
        return False
    id1 = c1.technique_id.strip().upper()
    id2 = c2.technique_id.strip().upper()
    if id1 != id2 and id1.split(".")[0] != id2.split(".")[0]:
        return False

    h1 = {h.lower() for h in c1.subject_entities.get("hosts", []) if h}
    h2 = {h.lower() for h in c2.subject_entities.get("hosts", []) if h}
    if h1 and h2 and h1.isdisjoint(h2):
        return False

    e1 = {x.split("?", 1)[0].lower() for x in c1.subject_entities.get("endpoints", []) if x}
    e2 = {x.split("?", 1)[0].lower() for x in c2.subject_entities.get("endpoints", []) if x}
    if e1 and e2 and e1.isdisjoint(e2):
        return False

    if not (h1 and h2):
        i1 = {x.lower() for x in c1.subject_entities.get("ips", []) if x}
        i2 = {x.lower() for x in c2.subject_entities.get("ips", []) if x}
        u1 = {x.lower() for x in c1.subject_entities.get("users", []) if x}
        u2 = {x.lower() for x in c2.subject_entities.get("users", []) if x}
        if i1 and i2 and i1.isdisjoint(i2) and not (u1 & u2) and not (e1 & e2):
            return False
        if u1 and u2 and u1.isdisjoint(u2) and not (e1 & e2) and not (i1 & i2):
            return False

    return True


def _extract_func_defs(ing: ArtifactIngestionResult) -> Set[str]:
    defs: Set[str] = set()
    for ev in ing.evidences:
        if ev.is_benign_baseline:
            continue
        m = re.search(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", ev.raw_content)
        if m:
            defs.add(m.group(1).lower())
    return defs


def _map_evidence_to_surface_blocks(
    ing: ArtifactIngestionResult,
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """Partition artifact evidences into logical route/function/config/host surface blocks."""
    ev_to_block: Dict[str, int] = {}
    blocks: List[Dict[str, Any]] = []

    def _new_block(kind: str = "generic") -> int:
        idx = len(blocks)
        blocks.append({
            "kind": kind,
            "routes": set(),
            "funcs": set(),
            "hosts": set(),
            "controls": set(),
            "sinks": set(),
        })
        return idx

    cur_idx = _new_block()
    has_func_in_cur = False

    for ev in ing.evidences:
        if ev.is_benign_baseline:
            continue
        raw = ev.raw_content.strip()
        low = raw.lower()
        routes = {ep.split("?", 1)[0] for ep in ev.entities.get("endpoints", []) if ep.startswith("/")}
        func_m = re.search(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", raw)
        is_decorator = raw.startswith("@")
        is_config_line = ev.source_type == "config" or low.startswith(("apiversion:", "kind:", "# deploy/", "privileged:", "allowprivilegeescalation:"))

        if ev.line_or_seq == 1 and ev_to_block:
            cur_idx = _new_block("config" if is_config_line else ("code" if (is_decorator or func_m or ev.source_type == "code") else ev.source_type))
            has_func_in_cur = False
        elif is_decorator and has_func_in_cur:
            cur_idx = _new_block("code")
            has_func_in_cur = False
        elif func_m and has_func_in_cur:
            cur_idx = _new_block("code")
            has_func_in_cur = False
        elif is_config_line and blocks[cur_idx]["kind"] != "config":
            cur_idx = _new_block("config")
            has_func_in_cur = False
        elif not is_config_line and blocks[cur_idx]["kind"] == "config":
            cur_idx = _new_block(ev.source_type)
            has_func_in_cur = False
        elif low.startswith(("apiversion:", "kind:")):
            if blocks[cur_idx]["controls"] or blocks[cur_idx]["sinks"]:
                cur_idx = _new_block("config")
                has_func_in_cur = False

        blk = blocks[cur_idx]
        if is_config_line:
            blk["kind"] = "config"
        elif is_decorator or func_m or ev.source_type == "code":
            if blk["kind"] == "generic":
                blk["kind"] = "code"

        blk["routes"].update(routes)
        if func_m:
            blk["funcs"].add(func_m.group(1).lower())
            has_func_in_cur = True
        for h in ev.entities.get("hosts", []):
            if h:
                blk["hosts"].add(h.lower())
        blk["controls"].update(ev.entities.get("controls", []))
        blk["sinks"].update(ev.entities.get("sinks", []))
        ev_to_block[ev.evidence_id] = cur_idx

    return ev_to_block, blocks


def _block_is_mitigated_in_patched(
    orig_claim: AnalyticalClaim,
    blk: Optional[Dict[str, Any]],
    expected_sinks: Set[str],
    patched_blocks: List[Dict[str, Any]],
    claim_hosts: Set[str],
) -> bool:
    """Verify whether a specific original surface block has matching surface and required controls in patched_blocks."""
    required_for_sink = {
        "sql_concat": "parameterized_sql",
        "ssrf_fetch": "url_allowlist",
        "container_priv": "privilege_dropped",
        "cmd_exec": "input_validation",
        "deserialization": "input_validation",
    }
    blk_routes = blk["routes"] if blk else set()
    blk_funcs = blk["funcs"] if blk else set()
    blk_hosts = (blk["hosts"] if blk else set()) | claim_hosts
    is_container_blk = "container_priv" in expected_sinks or orig_claim.technique_id == "T1611"

    matched_patched: List[Dict[str, Any]] = []
    for p_blk in patched_blocks:
        if not (p_blk["controls"] or p_blk["sinks"] or p_blk["routes"] or p_blk["funcs"] or p_blk["hosts"]):
            continue
        if blk_hosts and p_blk["hosts"] and blk_hosts.isdisjoint(p_blk["hosts"]):
            continue
        if is_container_blk:
            if p_blk["kind"] == "config" or "privilege_dropped" in p_blk["controls"]:
                matched_patched.append(p_blk)
            continue
        if blk_routes or blk_funcs or blk_hosts:
            route_hit = bool(blk_routes and (blk_routes & p_blk["routes"]))
            func_hit = bool(blk_funcs and (blk_funcs & p_blk["funcs"]))
            host_hit = bool(blk_hosts and (blk_hosts & p_blk["hosts"]))
            if route_hit or func_hit or host_hit:
                matched_patched.append(p_blk)
        else:
            matched_patched.append(p_blk)

    if not matched_patched:
        return False

    local_controls: Set[str] = {ctrl for pb in matched_patched for ctrl in pb["controls"]}
    if expected_sinks:
        return all(required_for_sink[s] in local_controls for s in expected_sinks if s in required_for_sink)
    if orig_claim.technique_id == "T1552.005":
        return "url_allowlist" in local_controls
    if orig_claim.technique_id == "T1611":
        return "privilege_dropped" in local_controls
    if orig_claim.technique_id == "T1190":
        return "parameterized_sql" in local_controls or "input_validation" in local_controls
    return bool(local_controls)


def _retain_unresolved_claim_surfaces(
    orig_claim: AnalyticalClaim,
    orig_ing: ArtifactIngestionResult,
    patched_ing: ArtifactIngestionResult,
    new_active: List[AnalyticalClaim],
) -> Optional[AnalyticalClaim]:
    """Keep only the subset of blocks/evidences from orig_claim that were neither mitigated nor covered in new_active."""
    orig_ev_by_id = {ev.evidence_id: ev for ev in orig_ing.evidences}
    orig_ev_to_blk, orig_blocks = _map_evidence_to_surface_blocks(orig_ing)
    cand_ev_to_blk, patched_blocks = _map_evidence_to_surface_blocks(patched_ing)

    claim_evs = [orig_ev_by_id[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_by_id]
    claim_sinks = {s for ev in claim_evs for s in ev.entities.get("sinks", [])}
    claim_blk_ids = sorted({orig_ev_to_blk[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_to_blk})
    claim_hosts = {h.lower() for h in orig_claim.subject_entities.get("hosts", []) if h}

    if not claim_blk_ids:
        if _block_is_mitigated_in_patched(orig_claim, None, claim_sinks, patched_blocks, claim_hosts):
            return None
        if any(_claims_semantically_match(orig_claim, nc) for nc in new_active):
            return None
        return orig_claim

    matching_cand_claims = [nc for nc in new_active if _claims_semantically_match(orig_claim, nc)]
    cand_claim_surfaces: List[Tuple[Set[str], Set[str], Set[str], bool]] = []
    for nc in matching_cand_claims:
        nc_blk_ids = {cand_ev_to_blk[eid] for eid in nc.evidence_ids if eid in cand_ev_to_blk}
        nc_routes: Set[str] = {ep.split("?", 1)[0].lower() for ep in nc.subject_entities.get("endpoints", []) if ep.startswith("/")}
        nc_funcs: Set[str] = set()
        nc_hosts: Set[str] = {h.lower() for h in nc.subject_entities.get("hosts", []) if h}
        nc_is_config = False
        for nbid in nc_blk_ids:
            nb = patched_blocks[nbid]
            nc_routes.update(r.lower() for r in nb["routes"])
            nc_funcs.update(nb["funcs"])
            nc_hosts.update(nb["hosts"])
            if nb["kind"] == "config":
                nc_is_config = True
        cand_claim_surfaces.append((nc_routes, nc_funcs, nc_hosts, nc_is_config))

    retained_eids: List[str] = []
    retained_routes: List[str] = []
    for bid in claim_blk_ids:
        blk = orig_blocks[bid]
        blk_eids = [eid for eid in orig_claim.evidence_ids if orig_ev_to_blk.get(eid) == bid]
        blk_evs = [orig_ev_by_id[eid] for eid in blk_eids if eid in orig_ev_by_id]
        blk_sinks = {s for ev in blk_evs for s in ev.entities.get("sinks", [])}
        expected_sinks = blk_sinks or (claim_sinks if len(claim_blk_ids) == 1 else set())

        if _block_is_mitigated_in_patched(orig_claim, blk, expected_sinks, patched_blocks, claim_hosts):
            continue

        blk_routes_low = {r.lower() for r in blk["routes"]}
        blk_funcs = set(blk["funcs"])
        blk_hosts = set(blk["hosts"]) | claim_hosts
        blk_is_config = blk["kind"] == "config" or "container_priv" in expected_sinks

        covered_by_new = False
        for nc_routes, nc_funcs, nc_hosts, nc_is_cfg in cand_claim_surfaces:
            if blk_is_config and nc_is_cfg:
                if not (blk_hosts and nc_hosts and blk_hosts.isdisjoint(nc_hosts)):
                    covered_by_new = True
                    break
            if blk_routes_low or blk_funcs or blk_hosts:
                routes_ok = (not blk_routes_low) or (blk_routes_low <= nc_routes)
                funcs_ok = (not blk_funcs) or (blk_funcs <= nc_funcs)
                hosts_ok = (not blk_hosts) or (blk_hosts <= nc_hosts)
                if routes_ok and funcs_ok and hosts_ok and ((blk_routes_low & nc_routes) or (blk_funcs & nc_funcs) or (blk_hosts & nc_hosts)):
                    covered_by_new = True
                    break
            elif matching_cand_claims:
                covered_by_new = True
                break

        if not covered_by_new:
            for eid in blk_eids:
                if eid not in retained_eids:
                    retained_eids.append(eid)
            for rt in blk["routes"]:
                if rt not in retained_routes:
                    retained_routes.append(rt)

    if not retained_eids:
        return None
    if len(retained_eids) == len(orig_claim.evidence_ids):
        return orig_claim

    subj = _collect_subject_entities(orig_ev_by_id, retained_eids)
    for rt in retained_routes:
        if rt not in subj["endpoints"]:
            subj["endpoints"].append(rt)
    obs = _format_observed_fact(orig_ev_by_id, retained_eids, "Unresolved omitted/unmitigated surface:")
    return orig_claim.model_copy(
        update={
            "evidence_ids": retained_eids,
            "subject_entities": subj,
            "observed_fact": obs,
        }
    )


def _is_claim_remediated_by_patch(
    orig_claim: AnalyticalClaim,
    orig_ing: ArtifactIngestionResult,
    patched_ing: ArtifactIngestionResult,
    new_active: List[AnalyticalClaim],
) -> bool:
    """Confirm every surface block cited by an original claim is absent from new_active and mitigated on its own block."""
    if any(_claims_semantically_match(orig_claim, nc) for nc in new_active):
        return False

    orig_ev_to_blk, orig_blocks = _map_evidence_to_surface_blocks(orig_ing)
    _, patched_blocks = _map_evidence_to_surface_blocks(patched_ing)

    claim_evs = [ev for ev in orig_ing.evidences if ev.evidence_id in orig_claim.evidence_ids]
    claim_sinks = {s for ev in claim_evs for s in ev.entities.get("sinks", [])}
    claim_blk_ids = sorted({orig_ev_to_blk[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_to_blk})
    claim_hosts = {h.lower() for h in orig_claim.subject_entities.get("hosts", []) if h}

    if claim_blk_ids:
        for bid in claim_blk_ids:
            blk = orig_blocks[bid]
            blk_evs = [ev for ev in claim_evs if orig_ev_to_blk.get(ev.evidence_id) == bid]
            blk_sinks = {s for ev in blk_evs for s in ev.entities.get("sinks", [])}
            expected_sinks = blk_sinks or (claim_sinks if len(claim_blk_ids) == 1 else set())
            if blk_evs and not _block_is_mitigated_in_patched(orig_claim, blk, expected_sinks, patched_blocks, claim_hosts):
                return False
        return True

    return _block_is_mitigated_in_patched(orig_claim, None, claim_sinks, patched_blocks, claim_hosts)


def _naive_single_agent_verdict(artifact_text: str) -> VerdictType:
    """Baseline simulating a linear single-agent alert triager without contradiction search or abstention."""
    low = artifact_text.lower()
    if "writes_enc_ext" in low or "vssadmin" in low or "auth=failed" in low or "wmic" in low:
        return VerdictType.CONFIRMED_ATTACK
    if "select " in low and "requests.get" in low:
        return VerdictType.EXPLOITABLE_CHAIN
    if "alert=\"http flood" in low:
        return VerdictType.CONFIRMED_ATTACK
    if "sh -c" in low or "pickle.loads" in low:
        return VerdictType.CONFIRMED_ATTACK
    return VerdictType.CONFIRMED_ATTACK
