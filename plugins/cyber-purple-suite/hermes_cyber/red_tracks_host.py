"""Red attack tracks for host recovery/ransomware, brute force, lateral movement, and fallback sinks."""

from __future__ import annotations

from typing import List

from hermes_cyber.models import RedProbe
from hermes_cyber.observer import is_routine_dns_txt_record
from hermes_cyber.red_claims import (
    RedPlanBuilder,
    _collect_subject_entities,
    _format_observed_fact,
    _group_records_by_host,
    _has_any,
    _is_unmitigated_sink_record,
)


def run_track3_ransomware(b: RedPlanBuilder) -> None:
    """Track 3: Ransomware-like / Shadow Copy / Mass Encrypted Writes — scoped PER HOST."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    covered_eids = b.covered_eids

    r_records = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("vssadmin", "writes_enc_ext", "encrypted"))
    ]
    if not r_records:
        return

    for host_key, h_recs in _group_records_by_host(r_records):
        host_evs = list(h_recs)
        if host_key:
            for e in threat_evs:
                if e not in host_evs and host_key in e.entities.get("hosts", []):
                    host_evs.append(e)
        r_ids = [e.evidence_id for e in host_evs]
        grp_subj = _collect_subject_entities(ev_by_id, [r.evidence_id for r in h_recs])
        host_lbl = host_key or (grp_subj["hosts"] or ["srv-fin-01"])[0]
        proc_lbl = (grp_subj["processes"] or ["vssadmin.exe"])[0]
        user_lbl = (grp_subj["users"] or ["service_account"])[0]
        has_shadow_del = any("delete shadows" in r.raw_content.lower() or "vss_deleted=true" in r.raw_content.lower() for r in h_recs)

        b.add_step_and_claim(
            tactic="Impact",
            technique_id="T1490",
            technique_name="Inhibit System Recovery / Suspect Bulk Encryption",
            observed_fact=_format_observed_fact(ev_by_id, [r.evidence_id for r in h_recs], f"Shadow query / encrypted-extension write telemetry on `{host_lbl}` by `{user_lbl}` ({proc_lbl}):"),
            proposed_interpretation=f"Suspected Ransomware Encryption & Shadow Copy Manipulation on `{host_lbl}` via `{proc_lbl}`.",
            evidence_ids=r_ids,
            reachability_proof=f"Telemetry on `{host_lbl}` records shadow enumeration and/or `.enc` file writes.",
            missing_conditions=[],
            confirming_or_refuting_proof=f"Verify binary release signature, authorized VLAN destination, and ChangeControl approval for `{proc_lbl}` on `{host_lbl}`.",
        )
        b.probes.append(RedProbe(
            probe_id=b.next_probe_id(),
            title=f"Shadow Copy & Binary Provenance Audit ({host_lbl})",
            target_surface=f"{host_lbl} process {proc_lbl}",
            method_or_vector="Read-only binary signature & change ticket cross-check",
            payload_or_command="Get-AuthenticodeSignature / vssadmin list shadows provenance",
            expected_ioc="Unverified unsigned binary or missing CHG ticket confirms ransomware; trusted signer refutes it",
        ))
        b.add_sim(
            variant="baseline_attack",
            log_line=f'host={host_lbl} proc=vssadmin.exe cmd="vssadmin delete shadows /all /quiet" ransomware_note=true writes_enc_ext=2500',
            mitre_technique_id="T1486",
        )
        b.add_sim(
            variant="evasion_variant",
            log_line=f'host={host_lbl} proc=wbadmin.exe cmd="wbadmin delete catalog -quiet" vss_deleted=true writes_enc_ext=980 signature_verified=false',
            mitre_technique_id="T1490",
        )
        b.blind_spots.append("Process-only alerts cannot distinguish ransomware from signed Change-Control backups without signer/VLAN checks.")
        b.hypotheses.append(f"Suspected Ransomware / Shadow Copy Manipulation on `{host_lbl}`.")
        b.confidences.append(0.84 if has_shadow_del else 0.68)


def run_track3b_bruteforce(b: RedPlanBuilder) -> None:
    """Track 3b: Brute Force / Failed Auth — scoped cleanly per host/account."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    covered_eids = b.covered_eids

    bf_records = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("auth=failed", "bruteforce"))
    ]
    if not bf_records:
        return

    for host_key, h_recs in _group_records_by_host(bf_records):
        grp_subj = _collect_subject_entities(ev_by_id, [r.evidence_id for r in h_recs])
        grp_ips = set(grp_subj["ips"])
        grp_users = set(grp_subj["users"])
        host_evs = list(h_recs)
        for e in threat_evs:
            if e in host_evs or e.evidence_id in covered_eids:
                continue
            if (
                (host_key and host_key in e.entities.get("hosts", []))
                or (grp_ips and set(e.entities.get("ips", [])) & grp_ips)
                or (grp_users and set(e.entities.get("users", [])) & grp_users)
            ):
                host_evs.append(e)

        bf_ids = [e.evidence_id for e in host_evs]
        ep = (grp_subj["endpoints"] or ["/api/v1/metrics"])[0]
        user_lbl = (grp_subj["users"] or ["svc_metrics"])[0]
        has_volume_proof = len(h_recs) >= 2 or _has_any(
            " ".join(r.raw_content for r in h_recs),
            ("total_attempts=", "bruteforce", "password_spray_targets="),
        )
        bf_missing = [] if has_volume_proof else [
            "Single failed login lacks burst volume, source diversity, or multi-account spray evidence."
        ]
        b.add_step_and_claim(
            tactic="Credential Access",
            technique_id="T1110",
            technique_name="Brute Force / High-Frequency Failed Logins",
            observed_fact=_format_observed_fact(ev_by_id, [r.evidence_id for r in h_recs], f"Failed authentication events on `{ep}` for `{user_lbl}`:"),
            proposed_interpretation=f"Suspected Credential Brute Force targeting `{user_lbl}` on `{ep}`.",
            evidence_ids=bf_ids,
            reachability_proof=f"Failed authentication events recorded against `{ep}` for `{user_lbl}`.",
            missing_conditions=bf_missing,
            confirming_or_refuting_proof="Cross-check source IP/agent origin, unique targeted usernames, and recent credential rotation records.",
        )
        b.probes.append(RedProbe(
            probe_id=b.next_probe_id(),
            title="Service Principal Lockout & Rate-Limit Resilience Check",
            target_surface=ep,
            method_or_vector="Auth policy & rate-limit configuration inspection",
            payload_or_command=f"Inspect failed_auth threshold & password rotation sync for {user_lbl}",
            expected_ioc="External IP spray or multi-user failures confirm attack; stale internal poller after rotation refutes brute force",
        ))
        b.add_sim(
            variant="baseline_attack",
            log_line=f'src=185.220.101.4 endpoint={ep} auth=FAILED user=admin password_spray_targets=25 external_ingress=true',
            mitre_technique_id="T1110",
        )
        b.add_sim(
            variant="evasion_variant",
            log_line=f'src=185.220.101.9 endpoint={ep} auth=FAILED user={user_lbl} agent="Mozilla/5.0" external_ingress=true',
            mitre_technique_id="T1110.003",
        )
        b.blind_spots.append("Threshold SIEM rules trigger blindly without correlating internal password rotation events.")
        b.hypotheses.append(f"Suspected Credential Brute Force targeting `{user_lbl}` on `{ep}`.")
        b.confidences.append(0.64 if has_volume_proof else 0.40)


def run_track4_lateral(b: RedPlanBuilder) -> None:
    """Track 4: WMI/SMB Lateral Movement Telemetry."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    all_raw = b.all_raw
    covered_eids = b.covered_eids

    lat_evs = [
        e.evidence_id
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("smb", "wmi", "wmic", "4624", "pass-the-hash"))
    ]
    if not lat_evs:
        return

    lat_subj = _collect_subject_entities(ev_by_id, lat_evs)
    host_lbl = (lat_subj["hosts"] or ["db-prod-01"])[0]
    user_lbl = (lat_subj["users"] or ["adm_rossi"])[0]
    src_ip = (lat_subj["ips"] or ["10.10.8.44"])[0]
    has_gap = _has_any(all_raw, ("logsourceunavailable", "truncated", "missing_fields", "status=ambiguous"))
    has_auth_detail = "logontype=" in all_raw.lower() and "ticketencryption=" in all_raw.lower()
    lat_missing: List[str] = []
    if has_gap or not has_auth_detail:
        lat_missing.append(
            "VPN authentication logs are unavailable/truncated and Kerberos LogonType/TicketEncryption provenance cannot distinguish Pass-the-Hash from authorized administration."
        )

    b.add_step_and_claim(
        tactic="Lateral Movement",
        technique_id="T1047",
        technique_name="Windows Management Instrumentation / Admin Pivot",
        observed_fact=_format_observed_fact(ev_by_id, lat_evs, f"Remote WMI/SMB activity observed involving `{user_lbl}` (`{src_ip}`) -> `{host_lbl}`:"),
        proposed_interpretation=f"Suspected Privileged Lateral Movement via WMI/SMB telemetry (`{user_lbl}` -> `{host_lbl}`).",
        evidence_ids=lat_evs,
        reachability_proof=f"Host session / remote WMI command telemetry observed for `{user_lbl}` targeting `{host_lbl}`.",
        missing_conditions=lat_missing,
        confirming_or_refuting_proof=f"Query un-truncated VPN session logs and Event 4624 LogonType/TicketEncryption for `{user_lbl}` ({src_ip}).",
    )
    b.probes.append(RedProbe(
        probe_id=b.next_probe_id(),
        title="Admin Session Provenance & LogonType Discrimination",
        target_surface="auth / kerberos / vpn-gw",
        method_or_vector="Cross-log authentication verification",
        payload_or_command="Query Security Event 4624 LogonType + TicketEncryption + VPN session table",
        expected_ioc="RC4 NTLM LogonType=3 without VPN session confirms Pass-the-Hash compromise",
    ))
    b.add_sim(
        variant="baseline_attack",
        log_line=f'host={host_lbl} proto=SMB proc=wmic cmd="wmic /node:{host_lbl} process call create" TicketEncryption=RC4 LogonType=3',
        mitre_technique_id="T1047",
    )
    b.add_sim(
        variant="evasion_variant",
        log_line=f'host={host_lbl} proto=DCOM proc=powershell.exe cmd="Invoke-CimMethod -ClassName Win32_Process" LogonType=3',
        mitre_technique_id="T1021",
    )
    b.blind_spots.append("Missing VPN/Kerberos logon correlation leaves legitimate emergency admin vs stolen token indistinguishable.")
    b.hypotheses.append(f"Suspected Privileged Lateral Movement via WMI/SMB telemetry (`{user_lbl}` -> `{host_lbl}`).")
    b.confidences.append(0.62)


def run_track4b_fallback_sinks(b: RedPlanBuilder) -> None:
    """Track 4b: Fallback unmitigated code/config sinks or isolated threat indicators."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    covered_eids = b.covered_eids
    claims = b.claims

    claimed_hosts = {h for c in claims for h in c.subject_entities.get("hosts", [])}
    uncovered_sinks = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids
        and not e.raw_content.lstrip().startswith("#")
        and "telemetry_gap" not in e.entities.get("controls", [])
        and not is_routine_dns_txt_record(e)
        and (
            _is_unmitigated_sink_record(e)
            or (not claims and bool(e.entities.get("indicators")))
        )
        and (
            not claims
            or any(h not in claimed_hosts for h in e.entities.get("hosts", []))
        )
    ]
    if not uncovered_sinks:
        return

    sink_ids = [e.evidence_id for e in uncovered_sinks]
    has_live_http = any(e.source_type == "http" or "status=200" in e.raw_content.lower() for e in uncovered_sinks)
    sink_missing = [] if has_live_http else [
        "Upstream caller authentication, untrusted input reachability into the sink, and absence of sanitization are not demonstrated in the submitted snippet."
    ]
    b.add_step_and_claim(
        tactic="Execution",
        technique_id="T1059",
        technique_name="Potentially Unsafe Sink / Threat Indicator Detected",
        observed_fact=_format_observed_fact(ev_by_id, sink_ids, "Potentially unsafe sink or security indicator matched verbatim:"),
        proposed_interpretation="Submitted artifact contains an unguarded dangerous sink or threat indicator potentially reachable by untrusted data.",
        evidence_ids=sink_ids,
        reachability_proof=f"Matched concrete sinks/indicators verbatim in {', '.join(sink_ids[:4])}.",
        missing_conditions=sink_missing,
        confirming_or_refuting_proof=f"Verify caller data-flow/sanitization into flagged sink in {', '.join(sink_ids[:3])} or execute controlled input check.",
    )
    b.probes.append(RedProbe(
        probe_id=b.next_probe_id(),
        title="Controlled Sink Reachability & Validation Audit",
        target_surface=b.ingestion.title,
        method_or_vector="Safe boundary input validation check",
        payload_or_command=f"Inspect data-flow into sinks recorded in {', '.join(sink_ids[:3])}",
        expected_ioc="Unhandled untrusted data reaching sink confirms exploitability",
    ))
    b.add_sim(
        variant="baseline_attack",
        log_line=uncovered_sinks[0].raw_content,
        mitre_technique_id="T1059",
    )
    b.blind_spots.append("Static sink match alone requires upstream data-flow validation to distinguish dead/sanitized code from exploitable paths.")
    b.hypotheses.append("Open Hypothesis: Potentially unsafe execution/config sink requires reachability and sanitization verification.")
    b.confidences.append(0.50 if sink_missing else 0.78)
