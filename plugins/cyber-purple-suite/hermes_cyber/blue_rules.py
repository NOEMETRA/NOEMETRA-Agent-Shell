"""Sigma/YARA formatting helpers and Blue claim/entity matching utilities."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    EvidenceRecord,
    RedOperationPlan,
    SigmaRuleSpec,
    YaraRuleSpec,
)


def _yaml_scalar(value: str) -> str:
    """Format a string safely as a single-line YAML scalar."""
    s = str(value)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in s):
        return json.dumps(s, ensure_ascii=False)
    return "'" + s.replace("'", "''") + "'"


def _yara_escape(value: str) -> str:
    """Escape backslashes, double quotes, and control chars for YARA double-quoted strings."""
    out: List[str] = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32 or ord(ch) == 127:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _build_sigma_yaml(spec: SigmaRuleSpec) -> str:
    kw_lines = "\n".join(f"      - {_yaml_scalar(k)}" for k in spec.detection_keywords) or "      - 'suspicious'"
    exc_lines = ""
    if spec.exclude_fields:
        flat_exc = [v for vals in spec.exclude_fields.values() for v in vals]
        if flat_exc:
            exc_items = "\n".join(f"      - {_yaml_scalar(v)}" for v in flat_exc)
            exc_lines = f"  filter_verified:\n    raw|contains:\n{exc_items}\n"
            cond = "selection_keywords and not filter_verified"
        else:
            cond = "selection_keywords"
    else:
        cond = "selection_keywords"

    category = spec.logsource.get("category", "application")
    product = spec.logsource.get("product", "noemetra")
    return (
        f"title: {_yaml_scalar(spec.title)}\n"
        f"id: {_yaml_scalar(spec.id)}\n"
        f"status: {_yaml_scalar(spec.status)}\n"
        f"description: {_yaml_scalar(spec.description)}\n"
        f"logsource:\n"
        f"  category: {_yaml_scalar(category)}\n"
        f"  product: {_yaml_scalar(product)}\n"
        f"detection:\n"
        f"  selection_keywords:\n"
        f"    raw|contains:\n"
        f"{kw_lines}\n"
        f"{exc_lines}"
        f"  condition: {cond}\n"
        f"level: {_yaml_scalar(spec.level)}\n"
    )


def _build_yara_text(rule: YaraRuleSpec) -> str:
    safe_strings = rule.strings or ["suspicious"]
    str_defs = "\n".join(
        f'        $s{i} = "{_yara_escape(s)}" nocase'
        for i, s in enumerate(safe_strings, start=1)
    )
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", str(rule.rule_name or "Custom_Rule"))
    if safe_name and safe_name[0].isdigit():
        safe_name = f"Rule_{safe_name}"
    return (
        f"rule {safe_name} {{\n"
        f"    meta:\n"
        f'        description = "{_yara_escape(rule.description)}"\n'
        f"    strings:\n"
        f"{str_defs}\n"
        f"    condition:\n"
        f"        {rule.condition}\n"
        f"}}\n"
    )


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(n in low for n in needles)


def _is_unmitigated_sink_ev(ev: EvidenceRecord) -> bool:
    sinks = ev.entities.get("sinks", [])
    controls = ev.entities.get("controls", [])
    for sink in sinks:
        if sink == "ssrf_fetch" and "url_allowlist" in controls:
            continue
        return True
    return False


def _collect_entities_from_evs(evs: List[EvidenceRecord]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"hosts": [], "ips": [], "users": [], "processes": [], "endpoints": []}
    for ev in evs:
        for k in out:
            for item in ev.entities.get(k, []):
                if item and item not in out[k]:
                    out[k].append(item)
    return out


def _cite_into(cited: List[str], eids: List[str]) -> List[str]:
    for eid in eids:
        if eid not in cited:
            cited.append(eid)
    return eids


def _find_matching_claim(
    red_plan: RedOperationPlan,
    ev_by_id: Dict[str, EvidenceRecord],
    contra_eids: List[str],
    preferred_tactics: Tuple[str, ...] = (),
) -> Tuple[Optional[str], List[str]]:
    claims = red_plan.claims
    if not claims:
        return None, []
    contra_entities = _collect_entities_from_evs([ev_by_id[eid] for eid in contra_eids if eid in ev_by_id])
    c_hosts = set(contra_entities["hosts"])
    c_ips = set(contra_entities["ips"])
    c_users = set(contra_entities["users"])
    c_set = set(contra_eids)

    best_claim: Optional[AnalyticalClaim] = None
    best_score = -1
    for clm in claims:
        clm_hosts = set(clm.subject_entities.get("hosts", []))
        # Never match across two conflicting non-empty hosts
        if c_hosts and clm_hosts and c_hosts.isdisjoint(clm_hosts):
            continue
        score = 0
        if c_hosts and clm_hosts & c_hosts:
            score += 10
        if c_ips and set(clm.subject_entities.get("ips", [])) & c_ips:
            score += 4
        if c_users and set(clm.subject_entities.get("users", [])) & c_users:
            score += 4
        if c_set & set(clm.evidence_ids):
            score += 3
        if preferred_tactics and clm.tactic in preferred_tactics:
            score += 2
        if score > best_score:
            best_score = score
            best_claim = clm

    if best_claim is not None:
        return best_claim.claim_id, list(best_claim.evidence_ids)
    return None, []
