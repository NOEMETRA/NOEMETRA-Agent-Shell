"""Blue control-driven contradiction cases (signed backups, secret rotation, telemetry gaps)."""

from __future__ import annotations

import re
import uuid
from typing import List, Optional, Set

from hermes_cyber.blue_rules import (
    _build_sigma_yaml,
    _build_yara_text,
    _cite_into,
    _collect_entities_from_evs,
    _find_matching_claim,
    _has_any,
)
from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    RedOperationPlan,
    SigmaRuleSpec,
    YaraRuleSpec,
)


def evaluate_blue_control_contradictions(
    ingestion: ArtifactIngestionResult,
    red_plan: RedOperationPlan,
    cited: List[str],
    contradictions: List[ContradictionItem],
    refuted_claim_ids: Set[str],
) -> Optional[BlueInvestigationReport]:
    """Evaluate signed-backup (Case A), stale-poller (Case B), and telemetry-gap (Case C) contradictions."""
    evs = ingestion.evidences
    ev_by_id = {ev.evidence_id: ev for ev in evs}

    # Case A: Control-driven Signed Backup / Approved Change / Authorized VLAN refuting Ransomware
    signed_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and ("signed_binary" in ev.entities.get("controls", []) or "approved_change" in ev.entities.get("controls", []))
    ]
    vlan_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and "authorized_vlan" in ev.entities.get("controls", [])
    ]
    if signed_evs and (signed_evs or vlan_evs):
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
            has_sig = any("signed_binary" in ev.entities.get("controls", []) for ev in h_signed)
            has_auth = any("approved_change" in ev.entities.get("controls", []) for ev in h_signed) or bool(h_vlan)
            if not (has_sig and has_auth):
                continue
            c1 = _cite_into(cited, [ev.evidence_id for ev in h_signed])
            c2 = _cite_into(cited, [ev.evidence_id for ev in h_vlan]) or c1
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
        c1 = _cite_into(cited, [ev.evidence_id for ev in rot_evs])
        c2 = _cite_into(cited, [ev.evidence_id for ev in poller_evs])
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
        c1 = _cite_into(cited, [ev.evidence_id for ev in gap_evs if _has_any(ev.raw_content, ("logsourceunavailable", "truncated"))]) or _cite_into(cited, [gap_evs[0].evidence_id])
        c2 = _cite_into(cited, [ev.evidence_id for ev in gap_evs if _has_any(ev.raw_content, ("missing_fields", "ambiguous"))])
        note_evs = _cite_into(cited, [ev.evidence_id for ev in evs if _has_any(ev.raw_content, ("emergency hotfix possible", "scheduled audit"))])
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

    return None
