"""FastAPI REST API tests for NOEMETRA Cyber Purple Suite."""

import pytest
from fastapi.testclient import TestClient

from hermes_cyber.server.standalone import app
from hermes_cyber.server.state import reset_cyber_assistants


@pytest.fixture(autouse=True)
def isolated_hermes_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
    reset_cyber_assistants()
    yield
    reset_cyber_assistants()


client = TestClient(app)


def test_cyber_api_status_scenarios_analyze_replay_and_benchmark():
    st = client.get("/api/plugins/cyber-purple-suite/status")
    assert st.status_code == 200
    assert st.json()["allow_remote"] is False

    sc = client.get("/api/plugins/cyber-purple-suite/scenarios")
    assert sc.status_code == 200
    scenarios = sc.json()["scenarios"]
    assert len(scenarios) == 6

    an = client.post(
        "/api/plugins/cyber-purple-suite/analyze/scenario",
        json={"scenario_id": "scen-01-ransomware-vs-backup"},
    )
    assert an.status_code == 200
    rep = an.json()
    assert rep["verdict"]["verdict"] == "FALSE_POSITIVE_BENIGN"
    case_id = rep["case_id"]

    # Interactive replay rerun endpoint + persisted Sigma rule verification
    rp = client.post(
        "/api/plugins/cyber-purple-suite/replay",
        json={
            "case_id": case_id,
            "detection_keywords": ["delete shadows", "wbadmin delete"],
            "exclude_values": ["healthcheck=200 ok"],
        },
    )
    assert rp.status_code == 200
    assert rp.json()["detection_coverage"] == 1.0

    fetched = client.get(f"/api/plugins/cyber-purple-suite/cases/{case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["blue_report"]["sigma_rule"]["detection_keywords"] == ["delete shadows", "wbadmin delete"]
    assert "wbadmin delete" in fetched.json()["blue_report"]["sigma_rule"]["yaml_text"]

    # Benchmark endpoint
    bm = client.post("/api/plugins/cyber-purple-suite/benchmark")
    assert bm.status_code == 200
    assert bm.json()["purple_multi_agent_accuracy"] == 1.0


def test_cyber_api_dual_model_arena_config_and_custom_artifact():
    cfg = client.post(
        "/api/plugins/cyber-purple-suite/config",
        json={
            "allow_remote": True,
            "red_provider": "openai-codex",
            "red_model": "gpt-6.1-sol",
            "blue_provider": "opencode-free",
            "blue_model": "opencode/mimo-v2.6-flash-free",
        },
    )
    assert cfg.status_code == 200
    data = cfg.json()
    assert data["allow_remote"] is True
    assert data["red_provider"] == "openai-codex"
    assert data["red_model"] == "gpt-6.1-sol"
    assert data["blue_provider"] == "opencode-free"
    assert data["blue_model"] == "opencode/mimo-v2.6-flash-free"

    cust = client.post(
        "/api/plugins/cyber-purple-suite/analyze/custom",
        json={
            "title": "Custom SSRF Handler",
            "source_kind": "code",
            "content": (
                '@app.get("/api/v1/export")\n'
                'def run(tenant_id, webhook_url): query = f"SELECT * FROM t WHERE id={tenant_id}"; return requests.get(webhook_url).text\n'
                'privileged: true'
            ),
        },
    )
    assert cust.status_code == 200
    assert cust.json()["verdict"]["verdict"] == "EXPLOITABLE_CHAIN"
