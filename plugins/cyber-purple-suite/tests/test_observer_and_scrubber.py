"""Tests for CyberObserver deterministic ingestion and PrivacyScrubber."""

from hermes_cyber.observer import CyberObserver, PrivacyScrubber


def test_privacy_scrubber_masks_and_restores_private_ips_secrets_and_emails():
    scrubber = PrivacyScrubber()
    raw = (
        '2026-11-16T11:10:05Z src=10.10.4.22 dst=192.168.1.50 pub=8.8.8.8 '
        'user=alice@corp.internal password="SuperSecretPassword!" '
        'token="Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdHBheWxvYWQ.c2lnbg" api_key=sk-proj-abc123456789xyz'
    )
    scrubbed, stats = scrubber.scrub(raw)

    assert "10.10.4.22" not in scrubbed
    assert "192.168.1.50" not in scrubbed
    assert "<INT_IP_01>" in scrubbed
    assert "<INT_IP_02>" in scrubbed
    # Public IP 8.8.8.8 stays intact for threat correlation
    assert "8.8.8.8" in scrubbed
    assert "SuperSecretPassword!" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiJ9" not in scrubbed
    assert "sk-proj-abc123456789xyz" not in scrubbed
    assert "alice@corp.internal" not in scrubbed
    assert stats["private_ips"] == 2
    assert stats["secrets"] >= 3
    assert stats["emails"] == 1

    restored = scrubber.unscrub(f"Detected traffic from <INT_IP_01> by <EMAIL_01> using <REDACTED_SECRET_01>.")
    assert "10.10.4.22" in restored
    assert "alice@corp.internal" in restored


def test_cyber_observer_ingests_mixed_code_iac_and_baseline_verbatim():
    observer = CyberObserver()
    sample = "\n".join([
        '@app.get("/api/v1/export")',
        'def export(tenant_id: str, url: str): query = f"SELECT * FROM t WHERE id={tenant_id}"; return requests.get(url).text',
        'securityContext: privileged: true',
        '[BASELINE] 2026-11-16T14:20:00Z src=10.10.0.10 method=GET /health status=200 healthcheck=200 ok',
    ])
    result = observer.ingest_text(sample, title="API Export Audit", source_kind="auto")

    assert result.total_records == 4
    assert result.evidences[0].evidence_id == "EV-0001"
    assert "/api/v1/export" in result.evidences[0].entities["endpoints"]
    assert "sql_concat" in result.evidences[1].entities["sinks"]
    assert "ssrf_fetch" in result.evidences[1].entities["sinks"]
    assert "container_priv" in result.evidences[2].entities["sinks"]
    assert result.evidences[3].is_benign_baseline is True
    assert result.summary_stats["benign_baseline_records"] == 1
