"""Tests for NOEMETRA Adversarial Cyber Kernel (ACK): CoW DetonationChamber, OOB Oracle, Fog of War, and 4 Missions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyber_hermes_plugin.cyber_plugin import TOOLS, cyber_run_ack_mission
from hermes_cyber.ack_arena import AdversarialCyberKernel, DetonationChamber
from hermes_cyber.models import ActionExecutionLimits, ConstrainedActionContract
from hermes_cyber.server.standalone import app
from hermes_cyber.server.state import reset_cyber_assistants


EXPECTED_7_STATES = [
    "INIT_ARENA",
    "RED_WEAPONIZE",
    "ORACLE_BASELINE_CHECK",
    "BLUE_DEFEND",
    "ORACLE_FUNCTIONAL_AND_FPR_CHECK",
    "RED_MUTATE_BYPASS",
    "CERTIFY_REPORT",
]


@pytest.mark.parametrize(
    "mission_id,expected_shadow_clone",
    [
        ("ack-m1-exploit-patch-bypass", False),
        ("ack-m2-detection-evasion-arena", False),
        ("ack-m3-attack-path-hardening", True),
        ("ack-m4-fuzz-to-fix-pipeline", False),
    ],
)
def test_all_four_ack_missions_structural_pass_seven_states_and_oob_invariants(mission_id, expected_shadow_clone):
    kernel = AdversarialCyberKernel()
    rep = kernel.run_mission(mission_id, mutation_rounds=3, defense_mode="structural")

    assert rep.certified is True
    assert rep.shadow_clone_only is expected_shadow_clone
    assert [t.state for t in rep.state_transitions] == EXPECTED_7_STATES
    assert all(t.passed for t in rep.state_transitions)

    # Pre-patch breach must be confirmed by out-of-band oracle before Blue intervention
    assert rep.tpr_fpr_matrix.pre_patch_breach_confirmed is True
    assert rep.tpr_fpr_matrix.post_patch_breaches == 0
    assert rep.tpr_fpr_matrix.false_positive_rate <= rep.tpr_fpr_matrix.max_allowed_fpr
    assert rep.tpr_fpr_matrix.evasion_resistance_rate == 1.0
    assert rep.tpr_fpr_matrix.functional_survival_rate == 1.0

    # Fog of War and forced attack-class switching across Red mutation rounds
    assert rep.fog_of_war.enforced is True
    assert rep.fog_of_war.blue_rules_hidden_from_red is True
    assert rep.fog_of_war.red_mutation_logic_hidden_from_blue is True
    assert len(rep.mutation_rounds) == 3
    classes = [r.attack_class for r in rep.mutation_rounds]
    assert len(set(classes)) == 3, f"Red must change attack class every round, got {classes}"

    # Out-of-band FS checks must confirm lowerdir immutability and no post-patch bypasses
    assert all(ev.fs_diff.lowerdir_untouched for ev in rep.oracle_evidences)
    assert all(not r.bypass_succeeded for r in rep.mutation_rounds)


def test_ack_oracle_anti_cheating_and_bypass_rejection(tmp_path):
    kernel = AdversarialCyberKernel()

    # 1) Mission 1: naive_block_all breaks legitimate service functionality -> REJECTED by OOB functional oracle
    rep_block = kernel.run_mission("ack-m1-exploit-patch-bypass", mutation_rounds=3, defense_mode="naive_block_all")
    assert rep_block.certified is False
    assert rep_block.tpr_fpr_matrix.functional_survival_rate == 0.0
    assert any(ev.oracle_verdict == "DEFENSE_REJECTED_BROKEN_FUNC" for ev in rep_block.oracle_evidences)
    assert rep_block.mutation_rounds == []

    # 2) Mission 1: naive_string_replace survives functional check, then gets bypassed by Red mutations
    rep_replace = kernel.run_mission("ack-m1-exploit-patch-bypass", mutation_rounds=3, defense_mode="naive_string_replace")
    assert rep_replace.certified is False
    assert rep_replace.tpr_fpr_matrix.functional_survival_rate == 1.0
    assert rep_replace.tpr_fpr_matrix.post_patch_breaches >= 1
    assert any(r.bypass_succeeded for r in rep_replace.mutation_rounds)

    # 3) Mission 2: overbroad wildcard rule fails real benign host telemetry FPR gate -> REJECTED
    rep_fpr = kernel.run_mission("ack-m2-detection-evasion-arena", mutation_rounds=3, defense_mode="overbroad_alert_all")
    assert rep_fpr.certified is False
    assert rep_fpr.tpr_fpr_matrix.false_positive_rate > 0.05
    assert any(ev.oracle_verdict == "DEFENSE_REJECTED_HIGH_FPR" for ev in rep_fpr.oracle_evidences)


def test_ack_detonation_chamber_confinement_blocks_host_escape():
    chamber = DetonationChamber()
    try:
        outside_contract = ConstrainedActionContract(
            action_id="act_escape_test",
            actor="RED",
            phase="RED_WEAPONIZE",
            sandbox_id=chamber.sandbox_id,
            primitive="EXEC_ARTIFACT",
            artifact_path="../outside_host_file.py",
            entrypoint=["python3", "../outside_host_file.py"],
            limits=ActionExecutionLimits(timeout_sec=5, max_procs=4, network_mode="none"),
            target_invariant="INV_SANDBOX_CONFINEMENT",
        )
        with pytest.raises(PermissionError):
            chamber.run_contract(outside_contract)
    finally:
        chamber.cleanup()
    assert not chamber.root_dir.exists()


def test_ack_rest_api_hermes_tool_and_ui_sync(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir(parents=True, exist_ok=True)
    reset_cyber_assistants()
    client = TestClient(app)

    r_missions = client.get("/api/plugins/cyber-purple-suite/ack/missions")
    assert r_missions.status_code == 200
    missions = r_missions.json()["missions"]
    assert len(missions) == 4

    r_run = client.post(
        "/api/plugins/cyber-purple-suite/ack/run",
        json={"mission_id": "ack-m4-fuzz-to-fix-pipeline", "mutation_rounds": 3, "defense_mode": "structural"},
    )
    assert r_run.status_code == 200
    body = r_run.json()
    assert body["certified"] is True
    assert body["tpr_fpr_matrix"]["post_patch_breaches"] == 0

    r_status = client.get("/api/plugins/cyber-purple-suite/status")
    assert r_status.status_code == 200
    assert r_status.json()["last_ack_report"]["mission_id"] == "ack-m4-fuzz-to-fix-pipeline"

    # Hermes tool contract compliance and execution
    assert any(t["name"] == "cyber_run_ack_mission" for t in TOOLS)
    tool_res = json.loads(cyber_run_ack_mission({"mission_id": "ack-m1-exploit-patch-bypass", "mutation_rounds": 3}))
    assert tool_res["certified"] is True

    # Desktop & Web UI sync verification
    suite_root = Path(__file__).resolve().parents[1]
    repo_root = suite_root.parents[1]
    desk = (suite_root / "desktop" / "plugin.js").read_text(encoding="utf-8")
    app_js = (repo_root / "apps" / "desktop" / "src" / "plugins" / "cyber-purple-suite" / "plugin.js").read_text(encoding="utf-8")
    web_html = (suite_root / "hermes_cyber" / "server" / "static" / "index.html").read_text(encoding="utf-8")

    assert desk == app_js
    for marker in ("/ack/run", "ack-m1-exploit-patch-bypass", "tpr_fpr_matrix", "fog_of_war", "mutation_rounds"):
        assert marker in desk
        assert marker in web_html
