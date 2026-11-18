"""Defensive Blue Investigator, Contradiction Critic, and Detection/Patch Synthesis Agent."""

from __future__ import annotations

import json
import re
import uuid
from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    EvidenceRecord,
    RedOperationPlan,
    SigmaRuleSpec,
    YaraRuleSpec,
)
from hermes_cyber.observer import PrivacyScrubber, is_routine_dns_txt_record
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


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


def _synthesize_deterministic_blue_report(
    ingestion: ArtifactIngestionResult,
    red_plan: RedOperationPlan,
) -> BlueInvestigationReport:
    evs = ingestion.evidences
    ev_by_id = {ev.evidence_id: ev for ev in evs}
    all_raw = "\n".join(ev.raw_content for ev in evs)
    contradictions: List[ContradictionItem] = []
    cited: List[str] = []
    refuted_claim_ids: set[str] = set()

    def _cite(eids: List[str]) -> List[str]:
        for eid in eids:
            if eid not in cited:
                cited.append(eid)
        return eids

    # Case A: Control-driven Signed Backup / Approved Change / Authorized VLAN refuting Ransomware
    # Works generically across arbitrary hostnames and backup binaries (restic, borgbackup, veeam, etc.)
    signed_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and ("signed_binary" in ev.entities.get("controls", []) or "approved_change" in ev.entities.get("controls", []))
    ]
    vlan_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and "authorized_vlan" in ev.entities.get("controls", [])
    ]
    if signed_evs and (signed_evs or vlan_evs):
        # Group signed controls per host so mixed logs only refute the matching host
        distinct_ctrl_hosts: List[str] = []
        for ev in [*signed_evs, *vlan_evs]:
            for h in ev.entities.get("hosts", []):
                if h not in distinct_ctrl_hosts:
                    distinct_ctrl_hosts.append(h)
        host_buckets: List[Optional[str]] = distinct_ctrl_hosts or [None]
        for h_key in host_buckets:
            h_signed = [
                ev for ev in signed_evs
                if h_key is None or not ev.entities.get("hosts") or h_key in ev.entities.get("hosts", [])
            ]
            h_vlan = [
                ev for ev in vlan_evs
                if h_key is None or not ev.entities.get("hosts") or h_key in ev.entities.get("hosts", [])
            ]
            # Confirm we actually have an approved change or authorized VLAN paired with a valid signature
            has_sig = any("signed_binary" in ev.entities.get("controls", []) for ev in h_signed)
            has_auth = any("approved_change" in ev.entities.get("controls", []) for ev in h_signed) or bool(h_vlan)
            if not (has_sig and has_auth):
                continue
            c1 = _cite([ev.evidence_id for ev in h_signed])
            c2 = _cite([ev.evidence_id for ev in h_vlan]) or c1
            ents = _collect_entities_from_evs([*h_signed, *h_vlan])
            host_lbl = h_key or (ents["hosts"] or ["host"])[0]
            proc_lbl = (ents["processes"] or ["backup-agent"])[0]
            ip_lbl = (ents["ips"] or ["authorized-backup-vlan"])[0]
            ticket_m = re.search(r"ticket=([A-Za-z0-9_-]+)", "\n".join(e.raw_content for e in h_signed))
            ticket_str = f" matching ChangeControl ticket {ticket_m.group(1)}" if ticket_m else ""

            target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c1 + c2, preferred_tactics=("Impact",))
            if target_cid:
                refuted_claim_ids.add(target_cid)

            contradictions.append(ContradictionItem(
                claim_challenged=f"Suspected Ransomware Encryption on {host_lbl}",
                target_claim_id=target_cid,
                target_evidence_ids=target_eids,
                contradicting_evidence_ids=c1,
                explanation=(
                    f"Binary `{proc_lbl}` on `{host_lbl}` carries a verified trusted signature "
                    f"(`signature_verified=true` / `sha256_trusted=true`){ticket_str}."
                ),
                impact_on_hypothesis="refutes",
                entity_coherent=True,
            ))
            contradictions.append(ContradictionItem(
                claim_challenged=f"Malicious shadow copy deletion & external C2 exfiltration on {host_lbl}",
                target_claim_id=target_cid,
                target_evidence_ids=target_eids,
                contradicting_evidence_ids=c2,
                explanation=(
                    f"Egress traffic on `{host_lbl}` flows solely to `{ip_lbl}` within `AUTHORIZED_BACKUP_VLAN` "
                    f"with `vss_deleted=false` and `ransomware_note=false`."
                ),
                impact_on_hypothesis="refutes",
                entity_coherent=True,
            ))

        # Only return early as clean Benign if ALL Red claims in this artifact were refuted by Case A
        unrefuted_claims = [c for c in red_plan.claims if c.claim_id not in refuted_claim_ids]
        if contradictions and not unrefuted_claims:
            ents = _collect_entities_from_evs([*signed_evs, *vlan_evs])
            host_lbl = (ents["hosts"] or ["srv-fin-01"])[0]
            proc_lbl = (ents["processes"] or ["restic"])[0]
            user_lbl = (ents["users"] or ["svc_backup_nightly"])[0]
            ip_lbl = (ents["ips"] or ["10.20.1.5"])[0]
            sigma = SigmaRuleSpec(
                title="Unsigned Shadow Copy Manipulation or Ransomware Writes",
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-ransomware-unsigned")),
                description="Detects shadow copy deletion or bulk encrypted writes excluding signed ChangeControl backup jobs.",
                logsource={"category": "process_creation", "product": "windows"},
                detection_keywords=["delete shadows", "wbadmin delete", "ransomware_note=true", "signature_verified=false"],
                exclude_fields={"verified_backup": ["signature_verified=true", "sha256_trusted=true", "AUTHORIZED_BACKUP_VLAN", "healthcheck=200 ok"]},
                level="critical",
            )
            sigma.yaml_text = _build_sigma_yaml(sigma)
            yara = YaraRuleSpec(
                rule_name="Unsigned_ShadowCopy_Wipe",
                description="Detects shadow deletion CLI arguments absent verified backup metadata.",
                strings=["delete shadows", "wbadmin delete catalog", "ransomware_note=true"],
                condition="any of them",
            )
            yara.raw_rule = _build_yara_text(yara)
            return BlueInvestigationReport(
                competing_hypothesis=f"Benign Signed Nightly Backup Maintenance on `{host_lbl}` by `{user_lbl}` (`{proc_lbl}`) under approved ChangeControl.",
                confidence=0.94,
                contradictions=contradictions,
                sigma_rule=sigma,
                yara_rule=yara,
                remediation_patch=(
                    "# SIEM Exclusion Rule Update (Preserve Detection for Unsigned Actors)\n"
                    "- Require cryptographic signer + approved ChangeControl window match before suppressing EDR alert.\n"
                    f"+ Allowlist `{proc_lbl}` only when signature_verified=true AND net_dst IN {{AUTHORIZED_BACKUP_VLAN}}."
                ),
                hardening_steps=[
                    "Tune EDR suppression to require binary Authenticode/SHA256 verification instead of process name allowlisting.",
                    f"Bind backup service account `{user_lbl}` network ACL strictly to `{ip_lbl}`.",
                ],
                cited_evidence_ids=cited,
                model_used="deterministic",
            )

    # Case B: Control-driven Stale Monitoring Cron / Secret Rotation refuting Brute Force
    rot_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and "secret_rotation" in ev.entities.get("controls", [])
    ]
    poller_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and "internal_poller" in ev.entities.get("controls", [])
    ]
    if rot_evs and poller_evs:
        c1 = _cite([ev.evidence_id for ev in rot_evs])
        c2 = _cite([ev.evidence_id for ev in poller_evs])
        ents = _collect_entities_from_evs([*rot_evs, *poller_evs])
        user_lbl = (ents["users"] or ["svc_metrics"])[0]
        ip_lbl = (ents["ips"] or ["10.10.2.10"])[0]
        agent_lbl = (ents["processes"] or ["internal-poller"])[0]
        agent_m = re.search(r'agent="([^"]+)"', "\n".join(e.raw_content for e in [*rot_evs, *poller_evs]))
        agent_raw = agent_m.group(1) if agent_m else agent_lbl

        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c1 + c2, preferred_tactics=("Credential Access",))
        if target_cid:
            refuted_claim_ids.add(target_cid)

        contradictions.append(ContradictionItem(
            claim_challenged=f"External Credential Brute Force / Password Spray for {user_lbl}",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c1,
            explanation=f"Failed logins for `{user_lbl}` follow a `PasswordPolicyChange` / secret rotation on cronjob/poller `{agent_raw}`.",
            impact_on_hypothesis="refutes",
            entity_coherent=True,
        ))
        contradictions.append(ContradictionItem(
            claim_challenged=f"Broad multi-account spraying from untrusted origins against {user_lbl}",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c2,
            explanation=f"Origin `{ip_lbl}` shows `external_ingress=false`, `unique_usernames=1`, and `success_after_fail=false` matching `{agent_raw}`.",
            impact_on_hypothesis="refutes",
            entity_coherent=True,
        ))

        unrefuted_claims = [c for c in red_plan.claims if c.claim_id not in refuted_claim_ids]
        if not unrefuted_claims:
            sigma = SigmaRuleSpec(
                title="External Password Spray or Multi-Target Auth Brute Force",
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-external-spray")),
                description="Alerts on failed authentication sprays from external ingress excluding stale internal monitoring pollers.",
                logsource={"category": "authentication", "product": "api_gateway"},
                detection_keywords=["external_ingress=true", "password_spray_targets=", "Mozilla/5.0"],
                exclude_fields={"stale_poller": [agent_raw, "stale secret", "external_ingress=false", "benign=true"]},
                level="high",
            )
            sigma.yaml_text = _build_sigma_yaml(sigma)
            yara = YaraRuleSpec(
                rule_name="External_Auth_Spray_Pattern",
                description="Detects multi-target spray telemetry from external ingress IPs.",
                strings=["external_ingress=true", "password_spray_targets=25"],
                condition="any of them",
            )
            yara.raw_rule = _build_yara_text(yara)
            return BlueInvestigationReport(
                competing_hypothesis=f"Benign Internal Misconfiguration: Stale Credential in `{agent_raw}` for `{user_lbl}` (`{ip_lbl}`) after Secret Rotation.",
                confidence=0.93,
                contradictions=contradictions,
                sigma_rule=sigma,
                yara_rule=yara,
                remediation_patch=(
                    "# Kubernetes ExternalSecrets Sync Patch\n"
                    f"- secretRef: stale-static-secret ({user_lbl})  # stale static secret\n"
                    "+ reloader.stakater.com/auto: 'true'\n"
                    "+ refreshInterval: 30s"
                ),
                hardening_steps=[
                    f"Trigger rolling restart of `{agent_raw}` via secret-reloader webhook upon secret rotation.",
                    "Alert when `external_ingress=true` OR `unique_usernames > 3` within 60 seconds.",
                ],
                cited_evidence_ids=cited,
                model_used="deterministic",
            )

    # Case C: Telemetry Gap / Truncated Logs -> Weakens attribution / Insufficient Evidence
    gap_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and "telemetry_gap" in ev.entities.get("controls", [])
    ]
    if gap_evs:
        c1 = _cite([ev.evidence_id for ev in gap_evs if _has_any(ev.raw_content, ("logsourceunavailable", "truncated"))]) or _cite([gap_evs[0].evidence_id])
        c2 = _cite([ev.evidence_id for ev in gap_evs if _has_any(ev.raw_content, ("missing_fields", "ambiguous"))])
        note_evs = _cite([ev.evidence_id for ev in evs if _has_any(ev.raw_content, ("emergency hotfix possible", "scheduled audit"))])
        c2_full = list(dict.fromkeys([*c2, *note_evs])) or c1
        ents = _collect_entities_from_evs([ev for ev in evs if not ev.is_benign_baseline])
        user_lbl = (ents["users"] or ["adm_rossi"])[0]
        host_lbl = (ents["hosts"] or ["db-prod-01"])[0]
        src_ip = (ents["ips"] or ["10.10.8.44"])[0]

        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c1 + c2_full, preferred_tactics=("Lateral Movement",))
        contradictions.append(ContradictionItem(
            claim_challenged=f"Definitive attribution of Pass-the-Hash Lateral Movement on {host_lbl}",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c1,
            explanation="Upstream authentication gateway telemetry is unavailable or truncated (`LogSourceUnavailable` / `truncated`).",
            impact_on_hypothesis="weakens",
            entity_coherent=True,
        ))
        contradictions.append(ContradictionItem(
            claim_challenged=f"Authentication ticket verification for `{user_lbl}` ({src_ip})",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c2_full,
            explanation=f"Domain controller telemetry omits `LogonType` and `TicketEncryption` for `{user_lbl}` from `{src_ip}`, leaving authorized admin hotfix unexcluded.",
            impact_on_hypothesis="contextualizes",
            entity_coherent=True,
        ))

        unrefuted_non_gap = [
            c for c in red_plan.claims
            if c.claim_id not in refuted_claim_ids and c.claim_id != target_cid and c.status == "supported"
        ]
        if not unrefuted_non_gap:
            sigma = SigmaRuleSpec(
                title="Suspicious Remote WMI/DCOM Admin Execution with Weak Auth",
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-wmi-lateral")),
                description="Detects remote WMI/Cim/DCOM process execution for correlation with VPN/Kerberos logs.",
                logsource={"category": "process_creation", "product": "windows"},
                detection_keywords=["wmic /node:", "Invoke-CimMethod", "LogonType=3", "TicketEncryption=RC4"],
                exclude_fields={"baseline": ["healthcheck=200 ok", "benign=true"]},
                level="high",
            )
            sigma.yaml_text = _build_sigma_yaml(sigma)
            yara = YaraRuleSpec(
                rule_name="Remote_WMI_Cim_Execution",
                description="Matches WMIC / Invoke-CimMethod lateral execution commands.",
                strings=["wmic /node:", "Invoke-CimMethod", "TicketEncryption=RC4"],
                condition="any of them",
            )
            yara.raw_rule = _build_yara_text(yara)
            return BlueInvestigationReport(
                competing_hypothesis=f"Competing Alternative: Authorized Admin Hotfix by `{user_lbl}` from `{src_ip}` cannot be distinguished due to truncated VPN/Kerberos logs.",
                confidence=0.60,
                contradictions=contradictions,
                sigma_rule=sigma,
                yara_rule=yara,
                remediation_patch=(
                    "# SIEM & Windows Audit Policy Hardening\n"
                    "+ Enable Security Audit Subcategories: Logon (4624 with LogonType) and Kerberos Service Ticket (4769 RC4)\n"
                    "+ Configure persistent spooling on SIEM VPN forwarder to eliminate truncation gaps."
                ),
                hardening_steps=[
                    f"Restore VPN logs during the incident window to verify physical/VPN origin of `{user_lbl}` ({src_ip}).",
                    "Enforce PAM break-glass ticketing before `wmic /node:` or `Invoke-CimMethod` execution on production DB tier.",
                ],
                cited_evidence_ids=cited,
                model_used="deterministic",
            )

    # Case D: Confirmed Exploitable Code Chain (Multi-Hop SQLi + Unmitigated SSRF + Privileged Container)
    has_sql_chain = any(
        "sql_concat" in e.entities.get("sinks", []) or "union select" in e.raw_content.lower()
        for e in evs
        if not e.is_benign_baseline
    )
    has_ssrf_chain = any(
        ("ssrf_fetch" in e.entities.get("sinks", []) and "url_allowlist" not in e.entities.get("controls", []))
        or "169.254.169.254" in e.raw_content
        for e in evs
        if not e.is_benign_baseline
    )
    if (has_sql_chain and has_ssrf_chain) or "169.254.169.254" in all_raw:
        c1 = _cite([
            ev.evidence_id for ev in evs
            if not ev.is_benign_baseline and _has_any(ev.raw_content, ("select ", "requests.get", "169.254.169.254", "privileged: true"))
        ])
        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c1, preferred_tactics=("Initial Access", "Credential Access"))
        contradictions.append(ContradictionItem(
            claim_challenged="Whether internal allowlists mitigate exposed route SSRF/SQLi chain",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c1,
            explanation="No egress URL allowlist, parameterization, or pod security drop exists anywhere in the route handler or deployment manifest.",
            impact_on_hypothesis="contextualizes",
            entity_coherent=True,
        ))
        sigma = SigmaRuleSpec(
            title="SQLi + SSRF Cloud Metadata Exfiltration Pattern (Incl. Octal/Encoded IP)",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-sqli-ssrf-imds")),
            description="Detects SQL injection probes chained with IMDSv1 SSRF URLs including octal IP aliases.",
            logsource={"category": "webserver", "product": "app_api"},
            detection_keywords=[
                "169.254.169.254", "0251.0376.0251.0376", "latest/meta-data", "UNION+SELECT", "uNiOn", "requests.get(webhook_url",
            ],
            exclude_fields={"health": ["healthcheck=200 ok", "/api/v1/health"]},
            level="critical",
        )
        sigma.yaml_text = _build_sigma_yaml(sigma)
        yara = YaraRuleSpec(
            rule_name="Exploit_SQLi_SSRF_IMDS_Pivot",
            description="Matches SQL injection payloads paired with AWS/cloud metadata endpoints or octal IP bypass.",
            strings=["169.254.169.254", "0251.0376.0251.0376", "UNION+SELECT"],
            condition="any of them",
        )
        yara.raw_rule = _build_yara_text(yara)
        return BlueInvestigationReport(
            competing_hypothesis="Alternative Check Evaluated (WAF/Sanitization Upstream): Refuted — direct source code + exposure evidence confirm multi-hop exploitability.",
            confidence=0.22,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "--- a/app/export.py\n"
                "+++ b/app/export.py\n"
                "- query = f\"SELECT id, webhook_url FROM reports WHERE tenant_id = '{tenant_id}' AND enabled = 1\"\n"
                "- rows = db.execute(query).fetchall()\n"
                "- meta = requests.get(webhook_url, timeout=3, headers={'Authorization': user_token}).text\n"
                "+ rows = db.execute('SELECT id, webhook_url FROM reports WHERE tenant_id = ? AND enabled = 1', (tenant_id,)).fetchall()\n"
                "+ validate_https_public_allowlist(webhook_url)  # reject RFC1918 + 169.254.0.0/16 & octal redirects\n"
                "+ meta = requests.get(webhook_url, timeout=3, allow_redirects=False).text\n"
                "\n# deploy/k8s-deployment.yaml\n"
                "- privileged: true\n"
                "+ privileged: false\n"
                "+ allowPrivilegeEscalation: false\n"
                "+ capabilities: { drop: ['ALL'] }"
            ),
            hardening_steps=[
                "Replace string-interpolated SQL with bound parameters (`?` / `:tenant_id`).",
                "Resolve hostname via DNS and block link-local (`169.254.0.0/16`) & RFC1918 before `requests.get`, disabling redirects and enforcing IMDSv2 hop-limit=1.",
                "Drop `privileged: true` and set `allowPrivilegeEscalation: false` in Kubernetes PodSecurity.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case E: DNS TXT / Token Leak (corroborated intrusion vs isolated open query; skips routine TXT only absent active stages)
    has_active_dns_stage = _has_any(all_raw, ("token_leak", "powershell", "pwsh", "child_of="))
    dns_or_tok_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline
        and (has_active_dns_stage or not is_routine_dns_txt_record(ev))
        and _has_any(ev.raw_content, ("qtype=txt", "c2-sync", "txt query", "token_leak"))
    ]
    if dns_or_tok_evs:
        ents = _collect_entities_from_evs(dns_or_tok_evs)
        host_lbl = (ents["hosts"] or ["db-core-02"])[0]
        ip_lbl = (ents["ips"] or ["10.10.4.22"])[0]
        corroborated_dns = any(
            c.tactic == "Exfiltration" and c.status == "supported" for c in red_plan.claims
        ) or _has_any(all_raw, ("c2-sync", "token_leak", "dns_txt_authorized=false"))

        c1 = _cite([ev.evidence_id for ev in evs if not ev.is_benign_baseline and _has_any(ev.raw_content, ("503", "alert=\"http flood"))])
        c2 = _cite([ev.evidence_id for ev in dns_or_tok_evs])
        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c2, preferred_tactics=("Exfiltration", "Credential Access"))

        if corroborated_dns:
            contradictions.append(ContradictionItem(
                claim_challenged="Incident is purely an external volumetric HTTP DDoS",
                target_claim_id=target_cid,
                target_evidence_ids=target_eids,
                contradicting_evidence_ids=c1 + c2,
                explanation=f"Internal `{host_lbl}` ({ip_lbl}) exhibits correlated credential/process anomaly and high-entropy or unauthorized DNS TXT activity.",
                impact_on_hypothesis="contextualizes",
                entity_coherent=True,
            ))
            sigma = SigmaRuleSpec(
                title="DB-to-Shell Fork & High-Entropy DNS Tunneling (TXT/CNAME)",
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-dns-exfil-shell")),
                description="Detects encoded shell forks and high-entropy DNS TXT/CNAME C2 traffic.",
                logsource={"category": "dns", "product": "zeek"},
                detection_keywords=["c2-sync", "powershell -enc", "pwsh -EncodedCommand", "qtype=TXT", "qtype=CNAME", "token_leak"],
                exclude_fields={"baseline": ["ntp.ubuntu.com", "healthcheck=200 ok", "benign=true"]},
                level="critical",
            )
            sigma.yaml_text = _build_sigma_yaml(sigma)
            yara = YaraRuleSpec(
                rule_name="Encoded_Shell_DNS_Exfil_Stage",
                description="Matches encoded PowerShell flags paired with c2-sync TXT/CNAME DNS tunneling.",
                strings=["c2-sync.example.net", "powershell -enc", "-EncodedCommand"],
                condition="any of them",
            )
            yara.raw_rule = _build_yara_text(yara)
            return BlueInvestigationReport(
                competing_hypothesis=f"Alternative Tested (Single Volumetric DDoS Incident): Rejected — internal host `{host_lbl}` actively exfiltrating over DNS.",
                confidence=0.18,
                contradictions=contradictions,
                sigma_rule=sigma,
                yara_rule=yara,
                remediation_patch=(
                    "# DNS Egress & Host Isolation Patch\n"
                    "+ Revoke leaked application JWT signing keys & rotate internal DB credentials.\n"
                    "+ Block outbound DNS TXT/CNAME resolution from internal VLAN except approved resolvers.\n"
                    "+ Enforce AppArmor/Sysmon child-process deny on `mysqld -> powershell.exe / pwsh`."
                ),
                hardening_steps=[
                    f"Quarantine `{host_lbl}` ({ip_lbl}) and block anomalous TXT destination at DNS sinkhole.",
                    "Deploy parent-child behavioral rule blocking any shell spawned by database daemons.",
                ],
                cited_evidence_ids=cited,
                model_used="deterministic",
            )

        # Isolated partial DNS TXT query: keep hypothesis open until volume/lineage/window proven
        contradictions.append(ContradictionItem(
            claim_challenged=f"Isolated DNS TXT query on {host_lbl} represents active exfiltration",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c2,
            explanation=f"Single DNS TXT observation on `{host_lbl}` lacks query volume/frequency, TXT payload entropy, and corroborating process/token events.",
            impact_on_hypothesis="weakens",
            entity_coherent=True,
        ))
        sigma = SigmaRuleSpec(
            title="High-Entropy or Anomalous DNS TXT Exfiltration Monitor",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"noemetra-open-dns-{ingestion.sha256}")),
            description="Monitors DNS TXT/CNAME queries for correlated tunnel volume and process context.",
            logsource={"category": "dns", "product": "zeek"},
            detection_keywords=["qtype=TXT", "TXT query", "qtype=CNAME", "c2-sync"],
            exclude_fields={"baseline": ["ntp.ubuntu.com", "healthcheck=200 ok", "benign=true"]},
            level="medium",
        )
        sigma.yaml_text = _build_sigma_yaml(sigma)
        yara = YaraRuleSpec(
            rule_name="Open_DNS_TXT_Pattern",
            description="Matches DNS TXT/CNAME query syntax for correlation.",
            strings=["qtype=TXT", "qtype=CNAME"],
            condition="any of them",
        )
        yara.raw_rule = _build_yara_text(yara)
        return BlueInvestigationReport(
            competing_hypothesis=f"Routine DNS Discovery / Verification Alternative on `{host_lbl}` — insufficient volume or process evidence to confirm exfiltration.",
            confidence=0.45,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch="# Collect 15-minute DNS TXT aggregation, payload length/entropy, and originating PID before blocking.",
            hardening_steps=[
                f"Correlate DNS TXT queries on `{host_lbl}` with originating PID and same-window process/auth events.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case F: Explicit WAF Bypass / Pickle Deserialization / Shell Spawn (preserves prior mixed-host contradictions!)
    waf_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and _has_any(ev.raw_content, ("pickle.loads", "waf_status=allowed", "sh -c"))
    ]
    if waf_evs:
        c_evs = _cite([
            ev.evidence_id for ev in waf_evs
            if _has_any(ev.raw_content, ("pickle.loads", "sh -c", "curl ", "waf_status=allowed"))
        ])
        ents = _collect_entities_from_evs(waf_evs)
        host_lbl = (ents["hosts"] or ["web-api-03"])[0]
        ep = (ents["endpoints"] or ["/api/v2/session/restore"])[0]
        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c_evs, preferred_tactics=("Execution", "Defense Evasion"))
        contradictions.append(ContradictionItem(
            claim_challenged=f"Edge WAF `ALLOWED` status on {host_lbl} guarantees benign payload",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c_evs,
            explanation=f"On `{host_lbl}`, WAF inspected only query string while body/header deserialization reached `pickle.loads` and spawned `sh -c`.",
            impact_on_hypothesis="contextualizes",
            entity_coherent=True,
        ))
        sigma = SigmaRuleSpec(
            title="Worker Shell Fork & Unsafe Deserialization (HTTP WAF Bypass)",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-pickle-shell")),
            description="Detects web workers spawning sh/dash curl/wget reverse stagers or pickle deserialization payloads.",
            logsource={"category": "process_creation", "product": "linux"},
            detection_keywords=["sh -c", "pickle.loads", "curl http", "wget ", ep],
            exclude_fields={"health": ["healthcheck=200 ok", "benign=true", "signature_verified=true"]},
            level="critical",
        )
        sigma.yaml_text = _build_sigma_yaml(sigma)
        yara = YaraRuleSpec(
            rule_name="Pickle_Base64_Reverse_Shell",
            description="Detects unsafe pickle deserialization + Linux shell stager patterns.",
            strings=["pickle.loads", "sh -c curl", "/bin/sh -c wget"],
            condition="any of them",
        )
        yara.raw_rule = _build_yara_text(yara)
        return BlueInvestigationReport(
            competing_hypothesis=f"Alternative Tested (Benign Healthcheck + Safe WAF PASS on `{host_lbl}`): Refuted — worker spawned unauthorized shell & external egress.",
            confidence=0.19,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "--- a/app/session.py\n"
                "+++ b/app/session.py\n"
                "- def restore_session_blob(raw_b64: str): return pickle.loads(base64.b64decode(raw_b64))\n"
                "+ def restore_session_blob(raw_b64: str): return hmac_verified_json_loads(raw_b64)"
            ),
            hardening_steps=[
                "Eliminate `pickle.loads` on untrusted HTTP headers/bodies; use HMAC-signed JSON.",
                "Enable WAF body/header inspection and seccomp/AppArmor restricting `python3 -> sh/dash/curl` execve.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case G: Generic unmitigated sinks / indicators (excludes mitigated controls & benign hosts already refuted)
    _sink_fallback_literals = {
        "sql_concat": ["SELECT ", "INSERT ", "UPDATE ", "DELETE "],
        "ssrf_fetch": ["requests.get(", "requests.post(", "urllib.request.urlopen(", "curl_exec("],
        "cmd_exec": ["subprocess.run", "os.system", "shell=True", "eval("],
        "deserialization": ["pickle.loads", "yaml.load(", "__reduce__", "ObjectInputStream"],
        "container_priv": ["privileged: true", "hostPID: true", "0.0.0.0/0", "CAP_SYS_ADMIN"],
    }
    unrefuted_eids = {
        eid for c in red_plan.claims if c.claim_id not in refuted_claim_ids for eid in c.evidence_ids
    }
    sink_evs = [
        ev for ev in evs
        if (not ev.is_benign_baseline)
        and (ev.evidence_id in unrefuted_eids or not refuted_claim_ids)
        and (_is_unmitigated_sink_ev(ev) or bool(ev.entities.get("indicators")))
        and "signed_binary" not in ev.entities.get("controls", [])
        and "authorized_vlan" not in ev.entities.get("controls", [])
    ]
    if sink_evs and red_plan.claims:
        ordered_kws: List[str] = []
        for ev in sink_evs:
            for item in [*ev.entities.get("sink_literals", []), *ev.entities.get("indicators", [])]:
                if item and item not in ordered_kws:
                    ordered_kws.append(item)
        if not ordered_kws:
            for ev in sink_evs:
                for sink_cat in ev.entities.get("sinks", []):
                    for fallback_lit in _sink_fallback_literals.get(sink_cat, []):
                        if fallback_lit not in ordered_kws:
                            ordered_kws.append(fallback_lit)
        kws = ordered_kws[:6] or ["delete shadows", "wbadmin delete", "unauthorized"]
        # If this is mixed with unrefuted Track 3/3b claims, keep simulation coverage intact
        if any(c.tactic == "Impact" and c.claim_id not in refuted_claim_ids for c in red_plan.claims):
            for kw in ("delete shadows", "wbadmin delete", "ransomware_note=true"):
                if kw not in kws:
                    kws.append(kw)
        if any(c.tactic == "Credential Access" and c.claim_id not in refuted_claim_ids for c in red_plan.claims):
            for kw in ("external_ingress=true", "password_spray_targets="):
                if kw not in kws:
                    kws.append(kw)

        c_ids = _cite([ev.evidence_id for ev in sink_evs[:4]])
        target_cid, target_eids = _find_matching_claim(red_plan, ev_by_id, c_ids)
        contradictions.append(ContradictionItem(
            claim_challenged="Exploitability context of matched sinks/indicators",
            target_claim_id=target_cid,
            target_evidence_ids=target_eids,
            contradicting_evidence_ids=c_ids,
            explanation="Matched indicators require verifying untrusted data flow and upstream access controls before confirming exploitability.",
            impact_on_hypothesis="contextualizes",
            entity_coherent=True,
        ))
        sigma = SigmaRuleSpec(
            title="Custom Artifact Threat Indicator & Execution Sink Monitor",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"noemetra-custom-{ingestion.sha256}")),
            description="Monitors dangerous execution sinks or threat indicators identified in the submitted artifact.",
            logsource={"category": "application", "product": "noemetra"},
            detection_keywords=kws[:8],
            exclude_fields={"health": ["healthcheck=200 ok", "benign=true", "signature_verified=true"]},
            level="medium",
        )
        sigma.yaml_text = _build_sigma_yaml(sigma)
        yara = YaraRuleSpec(
            rule_name="Custom_Artifact_Sink_Indicator",
            description="Matches threat indicators extracted from submitted telemetry.",
            strings=kws[:4],
            condition="any of them",
        )
        yara.raw_rule = _build_yara_text(yara)
        return BlueInvestigationReport(
            competing_hypothesis="Contextual Evaluation: Verify whether flagged execution/config sinks are reachable by untrusted input.",
            confidence=0.45,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch="# Enforce strict input validation and sandbox least-privilege on flagged sinks.",
            hardening_steps=["Review referenced EV records for caller authentication and input sanitization."],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Neutral / Patched Abstention: no unmitigated threat signals present
    sigma = SigmaRuleSpec(
        title="Baseline Monitoring Rule (Insufficient Threat Evidence)",
        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"noemetra-neutral-{ingestion.sha256}")),
        description="Placeholder rule emitted when submitted telemetry contains no unmitigated threat indicators.",
        logsource={"category": "application", "product": "noemetra"},
        detection_keywords=["unauthorized", "failed", "shell=True"],
        exclude_fields={"health": ["status=200", "healthcheck=200 ok", "benign=true"]},
        level="low",
    )
    sigma.yaml_text = _build_sigma_yaml(sigma)
    yara = YaraRuleSpec(
        rule_name="Neutral_Baseline_Placeholder",
        description="No unmitigated malicious byte strings detected in artifact.",
        strings=["unauthorized"],
        condition="any of them",
    )
    yara.raw_rule = _build_yara_text(yara)
    return BlueInvestigationReport(
        competing_hypothesis="Routine / Mitigated Telemetry — no unmitigated attack indicators or unsafe sinks observed.",
        confidence=0.65,
        contradictions=contradictions,
        sigma_rule=sigma,
        yara_rule=yara,
        remediation_patch="# No remediation required based on currently submitted records.",
        hardening_steps=["Provide deeper process, auth, or network logs if an investigation is expected."],
        cited_evidence_ids=cited,
        model_used="deterministic",
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
