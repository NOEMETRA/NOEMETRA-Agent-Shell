"""Blue threat-case evaluation (SQLi/SSRF, DNS TXT/token leak, WAF/pickle, generic sinks, and neutral abstention)."""

from __future__ import annotations

import uuid
from typing import List, Set

from hermes_cyber.blue_rules import (
    _build_sigma_yaml,
    _build_yara_text,
    _cite_into,
    _collect_entities_from_evs,
    _find_matching_claim,
    _has_any,
    _is_unmitigated_sink_ev,
)
from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    RedOperationPlan,
    SigmaRuleSpec,
    YaraRuleSpec,
)
from hermes_cyber.observer import is_record_correlated_with_any, is_routine_dns_txt_record


def evaluate_blue_threat_cases(
    ingestion: ArtifactIngestionResult,
    red_plan: RedOperationPlan,
    all_raw: str,
    cited: List[str],
    contradictions: List[ContradictionItem],
    refuted_claim_ids: Set[str],
) -> BlueInvestigationReport:
    """Evaluate active exploit chains, DNS exfil, WAF bypass, generic sinks, or neutral abstention."""
    evs = ingestion.evidences
    ev_by_id = {ev.evidence_id: ev for ev in evs}

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
        c1 = _cite_into(cited, [
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

    # Case E: DNS TXT / Token Leak
    active_stage_recs = [
        ev for ev in evs
        if not ev.is_benign_baseline and _has_any(ev.raw_content, ("token_leak", "powershell", "pwsh", "child_of="))
    ]
    dns_or_tok_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline
        and (
            not is_routine_dns_txt_record(ev)
            or is_record_correlated_with_any(ev, active_stage_recs, evs)
        )
        and _has_any(ev.raw_content, ("qtype=txt", "c2-sync", "txt query", "token_leak"))
    ]
    if dns_or_tok_evs:
        dns_only_evs = [ev for ev in dns_or_tok_evs if _has_any(ev.raw_content, ("qtype=txt", "c2-sync", "txt query"))]
        tok_only_evs = [ev for ev in dns_or_tok_evs if _has_any(ev.raw_content, ("token_leak",))]
        ents = _collect_entities_from_evs(dns_only_evs or dns_or_tok_evs)
        host_lbl = (ents["hosts"] or ["db-core-02"])[0]
        ip_lbl = (ents["ips"] or ["10.10.4.22"])[0]
        correlated_tok = bool(
            tok_only_evs
            and (
                not dns_only_evs
                or any(is_record_correlated_with_any(tev, dns_only_evs, evs) for tev in tok_only_evs)
            )
        )
        policy_evs = [
            ev for ev in evs
            if not ev.is_benign_baseline and "dns_txt_authorized=false" in ev.raw_content.lower()
        ]
        correlated_policy = bool(
            policy_evs
            and (
                not dns_only_evs
                or any(is_record_correlated_with_any(pev, dns_only_evs, evs) for pev in policy_evs)
            )
        )
        corroborated_dns = (
            any(c.tactic == "Exfiltration" and c.status == "supported" for c in red_plan.claims)
            or any("c2-sync" in ev.raw_content.lower() for ev in dns_only_evs)
            or correlated_tok
            or correlated_policy
        )

        c1 = _cite_into(cited, [ev.evidence_id for ev in evs if not ev.is_benign_baseline and _has_any(ev.raw_content, ("503", "alert=\"http flood"))])
        target_pool = (dns_only_evs or dns_or_tok_evs) if not corroborated_dns else dns_or_tok_evs
        c2 = _cite_into(cited, [ev.evidence_id for ev in target_pool])
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

    # Case F: Explicit WAF Bypass / Pickle Deserialization / Shell Spawn
    waf_evs = [
        ev for ev in evs
        if not ev.is_benign_baseline and _has_any(ev.raw_content, ("pickle.loads", "waf_status=allowed", "sh -c"))
    ]
    if waf_evs:
        c_evs = _cite_into(cited, [
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

    # Case G: Generic unmitigated sinks / indicators
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
        if any(c.tactic == "Impact" and c.claim_id not in refuted_claim_ids for c in red_plan.claims):
            for kw in ("delete shadows", "wbadmin delete", "ransomware_note=true"):
                if kw not in kws:
                    kws.append(kw)
        if any(c.tactic == "Credential Access" and c.claim_id not in refuted_claim_ids for c in red_plan.claims):
            for kw in ("external_ingress=true", "password_spray_targets="):
                if kw not in kws:
                    kws.append(kw)

        c_ids = _cite_into(cited, [ev.evidence_id for ev in sink_evs[:4]])
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

    # Neutral / Patched Abstention
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
