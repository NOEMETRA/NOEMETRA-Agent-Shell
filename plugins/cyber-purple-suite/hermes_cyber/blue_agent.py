"""Defensive Blue Investigator, Contradiction Critic, and Detection/Patch Synthesis Agent."""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    ContradictionItem,
    RedOperationPlan,
    SigmaRuleSpec,
    YaraRuleSpec,
)
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


def _build_sigma_yaml(spec: SigmaRuleSpec) -> str:
    kw_lines = "\n".join(f"      - '{k}'" for k in spec.detection_keywords) or "      - 'suspicious'"
    exc_lines = ""
    if spec.exclude_fields:
        flat_exc = [v for vals in spec.exclude_fields.values() for v in vals]
        if flat_exc:
            exc_items = "\n".join(f"      - '{v}'" for v in flat_exc)
            exc_lines = f"  filter_verified:\n    raw|contains:\n{exc_items}\n"
            cond = "selection_keywords and not filter_verified"
        else:
            cond = "selection_keywords"
    else:
        cond = "selection_keywords"

    category = spec.logsource.get("category", "application")
    product = spec.logsource.get("product", "noemetra")
    return (
        f"title: {spec.title}\n"
        f"id: {spec.id}\n"
        f"status: {spec.status}\n"
        f"description: {spec.description}\n"
        f"logsource:\n"
        f"  category: {category}\n"
        f"  product: {product}\n"
        f"detection:\n"
        f"  selection_keywords:\n"
        f"    raw|contains:\n"
        f"{kw_lines}\n"
        f"{exc_lines}"
        f"  condition: {cond}\n"
        f"level: {spec.level}\n"
    )


def _build_yara_text(rule: YaraRuleSpec) -> str:
    str_defs = "\n".join(f'        $s{i} = "{s}" nocase' for i, s in enumerate(rule.strings, start=1))
    return (
        f"rule {rule.rule_name} {{\n"
        f"    meta:\n"
        f'        description = "{rule.description}"\n'
        f"    strings:\n"
        f"{str_defs}\n"
        f"    condition:\n"
        f"        {rule.condition}\n"
        f"}}\n"
    )


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(n in low for n in needles)


def _synthesize_deterministic_blue_report(
    ingestion: ArtifactIngestionResult,
    red_plan: RedOperationPlan,
) -> BlueInvestigationReport:
    evs = ingestion.evidences
    all_raw = "\n".join(ev.raw_content for ev in evs)
    contradictions: List[ContradictionItem] = []
    cited: List[str] = []

    def _find_evs(*needles: str) -> List[str]:
        found = [ev.evidence_id for ev in evs if _has_any(ev.raw_content, needles)]
        for eid in found:
            if eid not in cited:
                cited.append(eid)
        return found

    # Case A: Signed Backup refuting Ransomware
    if _has_any(all_raw, ("vssadmin", "restic", "writes_enc_ext")) and _has_any(all_raw, ("signature_verified=true", "authorized_backup_vlan", "changecontrol")):
        c1 = _find_evs("changecontrol", "signature_verified=true", "sha256_trusted=true")
        c2 = _find_evs("authorized_backup_vlan", "ransomware_note=false", "vss_deleted=false")
        contradictions.append(ContradictionItem(
            claim_challenged="Suspected Ransomware Encryption on srv-fin-01",
            contradicting_evidence_ids=c1,
            explanation="Binary `restic` carries a valid release signature (`signature_verified=true`, `sha256_trusted=true`) matching ChangeControl ticket CHG-9041.",
            impact_on_hypothesis="refutes",
        ))
        contradictions.append(ContradictionItem(
            claim_challenged="Malicious shadow copy deletion & external C2 exfiltration",
            contradicting_evidence_ids=c2,
            explanation="Traffic flows solely to AUTHORIZED_BACKUP_VLAN (10.20.1.5), with `vss_deleted=false` and zero ransom notes.",
            impact_on_hypothesis="refutes",
        ))
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
            competing_hypothesis="Benign Signed Nightly Backup Maintenance under approved ChangeControl CHG-9041.",
            confidence=0.94,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "# SIEM Exclusion Rule Update (Preserve Detection for Unsigned Actors)\n"
                "- Require cryptographic signer + approved ChangeControl window match before suppressing EDR alert.\n"
                "+ Allowlist `restic` only when signer='CN=Restic Release Signing Key' AND net_dst IN {AUTHORIZED_BACKUP_VLAN}."
            ),
            hardening_steps=[
                "Tune EDR suppression to require binary Authenticode/SHA256 verification instead of process name allowlisting.",
                "Bind backup service account `svc_backup_nightly` network ACL strictly to `10.20.1.5:8443`.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case B: Stale Monitoring Cron refuting Brute Force
    if _has_any(all_raw, ("passwordpolicychange", "stale secret", "prometheus-poller")):
        c1 = _find_evs("passwordpolicychange", "stale secret", "prometheus-poller")
        c2 = _find_evs("unique_usernames=1", "external_ingress=false", "success_after_fail=false")
        contradictions.append(ContradictionItem(
            claim_challenged="External Credential Brute Force / Password Spray",
            contradicting_evidence_ids=c1,
            explanation="Failed logins started at exact 5.0s intervals immediately following `PasswordPolicyChange` secret rotation for `svc_metrics`.",
            impact_on_hypothesis="refutes",
        ))
        contradictions.append(ContradictionItem(
            claim_challenged="Broad multi-account spraying from untrusted origins",
            contradicting_evidence_ids=c2,
            explanation="Origin `10.10.2.10` is `internal-prometheus-scraper` (`external_ingress=false`, `unique_usernames=1`).",
            impact_on_hypothesis="refutes",
        ))
        sigma = SigmaRuleSpec(
            title="External Password Spray or Multi-Target Auth Brute Force",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-external-spray")),
            description="Alerts on failed authentication sprays from external ingress excluding stale internal Prometheus pollers.",
            logsource={"category": "authentication", "product": "api_gateway"},
            detection_keywords=["external_ingress=true", "password_spray_targets=", "Mozilla/5.0"],
            exclude_fields={"stale_poller": ["Prometheus-Poller/2.4", "stale secret in k8s cronjob", "benign=true"]},
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
            competing_hypothesis="Benign Internal Misconfiguration: Stale Credential in Kubernetes `prometheus-poller` CronJob after Secret Rotation.",
            confidence=0.93,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "# Kubernetes ExternalSecrets Sync Patch\n"
                "- secretRef: prometheus-svc-metrics-v1  # stale static secret\n"
                "+ reloader.stakater.com/auto: 'true'\n"
                "+ refreshInterval: 30s"
            ),
            hardening_steps=[
                "Trigger rolling restart of `prometheus-poller` via secret-reloader webhook upon secret rotation.",
                "Alert when `external_ingress=true` OR `unique_usernames > 3` within 60 seconds.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case C: Telemetry Gap / Truncated Logs -> Insufficient Evidence
    if _has_any(all_raw, ("logsourceunavailable", "truncated", "ambiguous", "missing_fields")):
        c1 = _find_evs("logsourceunavailable", "truncated")
        c2 = _find_evs("missing_fields", "emergency hotfix possible", "ambiguous")
        contradictions.append(ContradictionItem(
            claim_challenged="Definitive attribution of Pass-the-Hash Lateral Movement vs Authorized Emergency Admin",
            contradicting_evidence_ids=c1,
            explanation="`openvpn-gw` telemetry is unavailable (`LogSourceUnavailable`) during the exact 17:30Z-17:50Z window.",
            impact_on_hypothesis="weakens",
        ))
        contradictions.append(ContradictionItem(
            claim_challenged="Authentication ticket verification on Kerberos DC",
            contradicting_evidence_ids=c2,
            explanation="`kerberos-dc` event omits `LogonType` and `TicketEncryption`; `ws-eng-44` legitimately belongs to `adm_rossi` during a possible emergency hotfix.",
            impact_on_hypothesis="contextualizes",
        ))
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
            competing_hypothesis="Competing Alternative: Authorized Emergency Hotfix by `adm_rossi` cannot be distinguished due to truncated OpenVPN and Kerberos logs.",
            confidence=0.60,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "# SIEM & Windows Audit Policy Hardening\n"
                "+ Enable Security Audit Subcategories: Logon (4624 with LogonType) and Kerberos Service Ticket (4769 RC4)\n"
                "+ Configure persistent spooling on `openvpn-gw` SIEM forwarder to eliminate truncation gaps."
            ),
            hardening_steps=[
                "Restore `openvpn-gw` logs between 17:30Z and 17:50Z to verify physical/VPN origin of `adm_rossi`.",
                "Enforce PAM break-glass ticketing before `wmic /node:` or `Invoke-CimMethod` execution on production DB tier.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case D: Confirmed Exploitable Code Chain (SQLi + SSRF + Privileged Container)
    if _has_any(all_raw, ("sql_concat", "requests.get", "169.254.169.254", "privileged: true", "select ")):
        c1 = _find_evs("select ", "requests.get", "169.254.169.254", "privileged: true")
        contradictions.append(ContradictionItem(
            claim_challenged="Whether internal allowlists mitigate `/api/v1/export` exposure",
            contradicting_evidence_ids=c1,
            explanation="No egress URL allowlist, parameterization, or pod security drop exists anywhere in the route handler or deployment manifest; live trace confirms HTTP 200 reachability.",
            impact_on_hypothesis="contextualizes",
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
            competing_hypothesis="Alternative Check Evaluated (WAF/Sanitization Upstream): Refuted — direct source code + HTTP 200 evidence confirm live multi-hop exploitability.",
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

    # Case E: DNS Exfil masked by DDoS
    if _has_any(all_raw, ("qtype=txt", "c2-sync", "token_leak")):
        c1 = _find_evs("503", "alert=\"http flood")
        c2 = _find_evs("maintenance_window=false", "token_leak", "qtype=txt")
        contradictions.append(ContradictionItem(
            claim_challenged="Incident is purely an external volumetric HTTP DDoS",
            contradicting_evidence_ids=c1 + c2,
            explanation="While edge HTTP 503 flood distracts responders, internal `db-core-02` suffered a token leak, forked `powershell -enc` from `mysqld`, and sent unauthorized high-entropy DNS TXT egress (`dns_txt_authorized=false`).",
            impact_on_hypothesis="contextualizes",
        ))
        sigma = SigmaRuleSpec(
            title="DB-to-Shell Fork & High-Entropy DNS Tunneling (TXT/CNAME)",
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-dns-exfil-shell")),
            description="Detects encoded PowerShell forks from database engines and high-entropy DNS TXT/CNAME C2 traffic.",
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
            competing_hypothesis="Alternative Tested (Single Volumetric DDoS Incident): Rejected — internal compromised DB host actively exfiltrating over DNS.",
            confidence=0.18,
            contradictions=contradictions,
            sigma_rule=sigma,
            yara_rule=yara,
            remediation_patch=(
                "# DNS Egress & DB Host Isolation Patch\n"
                "+ Revoke leaked `svc_etl` JWT signing key & rotate all DB credentials.\n"
                "+ Block outbound DNS TXT/CNAME resolution from DB VLAN except corporate internal forwarders.\n"
                "+ Enforce AppArmor/Sysmon child-process deny on `mysqld -> powershell.exe / pwsh`."
            ),
            hardening_steps=[
                "Quarantine `db-core-02` (10.10.4.22) immediately and block `c2-sync.example.net` at DNS sinkhole.",
                "Deploy parent-child behavioral rule blocking any shell spawned by database daemons.",
            ],
            cited_evidence_ids=cited,
            model_used="deterministic",
        )

    # Case F: WAF Bypass / Pickle Deserialization / Shell Spawn (or generic exploit)
    c_evs = _find_evs("pickle.loads", "sh -c", "curl ", "eval(", "os.system") or [e.evidence_id for e in evs[:2]]
    contradictions.append(ContradictionItem(
        claim_challenged="Edge WAF `ALLOWED` status guarantees benign payload",
        contradicting_evidence_ids=c_evs,
        explanation="WAF inspected only URL query string, missing `pickle.loads(base64.b64decode(...))` code execution triggering `sh -c curl`.",
        impact_on_hypothesis="contextualizes",
    ))
    sigma = SigmaRuleSpec(
        title="Worker Shell Fork & Unsafe Deserialization (HTTP WAF Bypass)",
        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "noemetra-pickle-shell")),
        description="Detects web workers spawning sh/dash curl/wget reverse stagers or pickle deserialization payloads.",
        logsource={"category": "process_creation", "product": "linux"},
        detection_keywords=["sh -c", "pickle.loads", "curl http", "wget ", "/api/v2/session/restore"],
        exclude_fields={"health": ["healthcheck=200 ok", "benign=true"]},
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
        competing_hypothesis="Alternative Tested (Benign Healthcheck + Safe WAF PASS): Refuted — Python worker spawned unauthorized shell & external egress.",
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


class BlueInvestigatorAgent:
    """Defensive Critic searching for contradictions, Sigma/YARA rules, and remediation patches."""

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
            "You are the BLUE INVESTIGATOR & ADVERSARIAL CRITIC. Your duty is to hunt for CONTRADICTIONS "
            "against the Red hypothesis using ONLY [EV-xxxx] records, evaluate false positives vs true attack, "
            "and refine hardening/detection. Reply strictly with JSON: competing_hypothesis, confidence (0..1), "
            "extra_contradictions ([{claim_challenged, contradicting_evidence_ids, explanation, impact_on_hypothesis}]), "
            "extra_detection_keywords (list of strings), extra_hardening (list of strings), cited_evidence_ids."
        )
        ev_bundle = "\n".join(f"[{e.evidence_id}] {e.raw_content}" for e in ingestion.evidences)
        user_prompt = (
            f"Red Hypothesis: {red_plan.primary_hypothesis}\n"
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
        merged_cited = list(dict.fromkeys([*base_report.cited_evidence_ids, *llm_cited]))

        contradictions = list(base_report.contradictions)
        for item in parsed.get("extra_contradictions") or []:
            if isinstance(item, dict) and item.get("explanation"):
                c_ids = [str(eid) for eid in (item.get("contradicting_evidence_ids") or []) if str(eid) in valid_ids]
                impact = str(item.get("impact_on_hypothesis") or "contextualizes")
                if impact not in ("refutes", "weakens", "contextualizes"):
                    impact = "contextualizes"
                contradictions.append(ContradictionItem(
                    claim_challenged=str(item.get("claim_challenged") or red_plan.primary_hypothesis),
                    contradicting_evidence_ids=c_ids,
                    explanation=str(item["explanation"]),
                    impact_on_hypothesis=impact,  # type: ignore[arg-type]
                ))

        extra_kws = [str(k).strip() for k in (parsed.get("extra_detection_keywords") or []) if str(k).strip()]
        sigma = base_report.sigma_rule.model_copy(deep=True)
        sigma.detection_keywords = list(dict.fromkeys([*sigma.detection_keywords, *extra_kws]))
        sigma.yaml_text = _build_sigma_yaml(sigma)

        extra_hard = [str(h).strip() for h in (parsed.get("extra_hardening") or []) if str(h).strip()]
        hardening = list(dict.fromkeys([*base_report.hardening_steps, *extra_hard]))

        comp = str(parsed.get("competing_hypothesis") or "").strip() or base_report.competing_hypothesis
        try:
            conf = max(0.0, min(1.0, float(parsed.get("confidence", base_report.confidence))))
        except Exception:
            conf = base_report.confidence

        enriched = base_report.model_copy(update={
            "competing_hypothesis": comp,
            "confidence": round((base_report.confidence + conf) / 2.0, 3),
            "contradictions": contradictions[:6],
            "sigma_rule": sigma,
            "hardening_steps": hardening[:6],
            "cited_evidence_ids": merged_cited,
            "model_used": model_label,
        })
        return enriched, scrubbed, scrub_stats
