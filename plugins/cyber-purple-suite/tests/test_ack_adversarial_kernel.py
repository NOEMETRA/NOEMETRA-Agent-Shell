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

    # Out-of-band FS checks must confirm lowerdir immutability, valid executions, and no post-patch bypasses
    assert all(ev.fs_diff.lowerdir_untouched for ev in rep.oracle_evidences)
    assert all(r.execution_valid and r.attempts_executed >= 1 and not r.bypass_succeeded for r in rep.mutation_rounds)


def test_ack_confinement_blocks_host_file_read_direct_canary_read_and_external_network(tmp_path):
    host_secret = tmp_path / "host_sensitive.txt"
    host_secret.write_text("HOST_SECRET_DO_NOT_READ", encoding="utf-8")

    chamber = DetonationChamber()
    try:
        chamber.seed_lowerdir({"target_service.py": "def noop(): return 'ok'\n"})
        chamber.write_blue_artifact("blue_secret.txt", "BLUE_SECRET_RULE")

        # 1) Attempting to read an external host file outside DetonationChamber must fail with PermissionError
        _, _ = chamber.write_red_artifact(
            "rogue_host_read.py",
            f"print(open({str(host_secret)!r}, encoding='utf-8').read())\n",
        )
        c_host = ConstrainedActionContract(
            action_id="act_rogue_host",
            actor="RED",
            phase="RED_WEAPONIZE",
            sandbox_id=chamber.sandbox_id,
            primitive="EXEC_ARTIFACT",
            artifact_path="artifacts/red/rogue_host_read.py",
            entrypoint=["python3", "artifacts/red/rogue_host_read.py"],
            limits=ActionExecutionLimits(timeout_sec=10, max_procs=4, network_mode="none"),
            target_invariant="INV_HOST_CONFINEMENT",
        )
        rc_h, out_h, err_h, _ = chamber.run_contract(c_host)
        assert rc_h != 0
        assert "HOST_SECRET_DO_NOT_READ" not in out_h
        assert "PermissionError" in err_h

        # 2) Red artifact attempting direct canary read (without going through target_service) must be blocked
        _, _ = chamber.write_red_artifact(
            "rogue_direct_canary.py",
            "import os; from pathlib import Path; print((Path(os.environ['ACK_UPPERDIR']) / 'canary_vault' / 'canary.txt').read_text())\n",
        )
        c_can = c_host.model_copy(
            update={
                "action_id": "act_rogue_canary",
                "artifact_path": "artifacts/red/rogue_direct_canary.py",
                "entrypoint": ["python3", "artifacts/red/rogue_direct_canary.py"],
            }
        )
        rc_c, out_c, err_c, fs_c = chamber.run_contract(c_can)
        assert rc_c != 0
        assert fs_c.canary_accessed is False
        assert "PermissionError" in err_c

        # 3) External DNS / socket connection blocked under network_mode="none"
        _, _ = chamber.write_red_artifact(
            "rogue_net.py",
            "import socket; s = socket.socket(); s.connect(('8.8.8.8', 53))\n",
        )
        c_net = c_host.model_copy(
            update={
                "action_id": "act_rogue_net",
                "artifact_path": "artifacts/red/rogue_net.py",
                "entrypoint": ["python3", "artifacts/red/rogue_net.py"],
            }
        )
        rc_n, _, err_n, _ = chamber.run_contract(c_net)
        assert rc_n != 0
        assert "PermissionError" in err_n

        # 4) Child process spawning (subprocess.Popen) must be unconditionally blocked to prevent audit-hook escape
        _, _ = chamber.write_red_artifact(
            "rogue_proc.py",
            "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'print(\"ESCAPED\")'])\n",
        )
        c_proc = c_host.model_copy(
            update={
                "action_id": "act_rogue_proc",
                "artifact_path": "artifacts/red/rogue_proc.py",
                "entrypoint": ["python3", "artifacts/red/rogue_proc.py"],
                "limits": ActionExecutionLimits(timeout_sec=10, max_procs=1, network_mode="none"),
            }
        )
        rc_p, out_p, err_p, _ = chamber.run_contract(c_proc)
        assert rc_p != 0
        assert "ESCAPED" not in out_p
        assert "PermissionError" in err_p

        # 5) Spoofing frame co_filename via compile() must NEVER bypass process-level canary isolation
        spoof_target = str(chamber.upperdir / "target_service.py")
        _, _ = chamber.write_red_artifact(
            "rogue_compile_spoof.py",
            (
                "import os\nfrom pathlib import Path\n"
                f"code = compile(\"print((Path(os.environ['ACK_UPPERDIR']) / 'canary_vault' / 'canary.txt').read_text())\", {spoof_target!r}, 'exec')\n"
                "exec(code)\n"
            ),
        )
        c_spoof = c_host.model_copy(
            update={
                "action_id": "act_rogue_spoof",
                "artifact_path": "artifacts/red/rogue_compile_spoof.py",
                "entrypoint": ["python3", "artifacts/red/rogue_compile_spoof.py"],
                "limits": ActionExecutionLimits(timeout_sec=10, max_procs=1, network_mode="none"),
            }
        )
        rc_s, out_s, err_s, fs_s = chamber.run_contract(c_spoof)
        assert rc_s != 0
        assert fs_s.canary_accessed is False
        assert chamber.canary_token not in out_s
        assert "PermissionError" in err_s

        # 6) Red must NEVER overwrite target modules in upperdir, and target_server rejects any untrusted change
        _, _ = chamber.write_red_artifact(
            "rogue_tamper_target.py",
            "import os\nfrom pathlib import Path\n(Path(os.environ['ACK_UPPERDIR']) / 'target_service.py').write_text('print(open(\"canary_vault/canary.txt\").read())')\n",
        )
        c_tamper = c_host.model_copy(
            update={
                "action_id": "act_rogue_tamper",
                "artifact_path": "artifacts/red/rogue_tamper_target.py",
                "entrypoint": ["python3", "artifacts/red/rogue_tamper_target.py"],
                "limits": ActionExecutionLimits(timeout_sec=10, max_procs=1, network_mode="none"),
            }
        )
        rc_t, _, err_t, _ = chamber.run_contract(c_tamper)
        assert rc_t != 0
        assert "PermissionError" in err_t

        # Even if a target module is altered externally on disk, target_server refuses to load it as TARGET
        (chamber.upperdir / "target_service.py").write_text("def tampered(): pass\n", encoding="utf-8")
        with pytest.raises(PermissionError):
            with chamber.target_server("target_service.py", "tampered"):
                pass
    finally:
        chamber.cleanup()


def test_ack_failed_mutation_execution_is_never_certified_as_defended():
    kernel = AdversarialCyberKernel()
    rep = kernel.run_mission(
        "ack-m1-exploit-patch-bypass",
        mutation_rounds=3,
        defense_mode="structural",
        inject_broken_mutation=True,
    )
    assert rep.certified is False
    assert rep.certification_verdict == "REJECTED_MUTATION_EXECUTION_ERROR"
    assert rep.mutation_rounds[0].execution_valid is False
    assert rep.mutation_rounds[0].oracle_evidence.oracle_verdict == "EXECUTION_ERROR"
    assert rep.mutation_rounds[0].oracle_evidence.execution_valid is False


def test_ack_m3_distinguishes_synthetic_fixture_from_cloned_target_manifest():
    kernel = AdversarialCyberKernel()

    # 1) Default invocation without manifest explicitly marks synthetic_fixture_simulation (systemd INI)
    rep_syn = kernel.run_mission("ack-m3-attack-path-hardening", mutation_rounds=3, defense_mode="structural")
    assert rep_syn.audit_scope == "synthetic_fixture_simulation"
    assert "SYNTHETIC" in rep_syn.certification_verdict
    assert rep_syn.certified is True

    # 2) Valid pure Kubernetes Pod YAML, pure systemd INI, and pure JSON all harden cleanly preserving format
    vuln_yaml_manifest = "\n".join([
        "apiVersion: v1",
        "kind: Pod",
        "metadata:",
        "  name: api-worker",
        "spec:",
        "  containers:",
        "    - name: worker",
        "      image: python:3.12-slim",
        "      securityContext:",
        "        privileged: true",
        "        allowPrivilegeEscalation: true",
        "        capabilities:",
        "          add:",
        "            - CAP_SYS_ADMIN",
    ])
    vuln_ini_manifest = "\n".join([
        "[Service]",
        "NoNewPrivileges=false",
        "ProtectSystem=false",
        "HelperWritable=true",
        "AmbientCapabilities=CAP_SYS_ADMIN",
        "[Socket]",
        "SocketMode=0666",
    ])
    vuln_json_manifest = json.dumps({
        "service_enabled": True,
        "helper_writable": True,
        "privileged_container": True,
        "NoNewPrivileges": False,
        "ProtectSystem": False,
        "ambient_caps": ["CAP_SYS_ADMIN"],
        "socket_acl_restricted": False,
    }, indent=2)

    for manifest in (vuln_yaml_manifest, vuln_ini_manifest, vuln_json_manifest):
        rep_vuln_clone = kernel.run_mission(
            "ack-m3-attack-path-hardening",
            mutation_rounds=3,
            defense_mode="structural",
            target_config_content=manifest,
        )
        assert rep_vuln_clone.audit_scope == "cloned_target_manifest"
        assert rep_vuln_clone.certification_verdict == "CERTIFIED_HARDENED_CLONED_MANIFEST"
        assert rep_vuln_clone.certified is True
        assert rep_vuln_clone.tpr_fpr_matrix.pre_patch_breach_confirmed is True
        assert ActionExecutionLimits().max_procs == 1
        blue_m3_ev = next(ev for ev in rep_vuln_clone.oracle_evidences if ev.action_id == "act_blue_m3_harden")
        assert "cloned_target_manifest.conf" in blue_m3_ev.fs_diff.modified
        assert blue_m3_ev.fs_diff.lowerdir_untouched is True

    # 3) Already hardened YAML manifest must NOT claim a fake pre-patch escalation
    hardened_yaml_manifest = "\n".join([
        "apiVersion: v1",
        "kind: Pod",
        "metadata:",
        "  name: api-worker-hardened",
        "spec:",
        "  containers:",
        "    - name: worker",
        "      image: python:3.12-slim",
        "      securityContext:",
        "        privileged: false",
        "        allowPrivilegeEscalation: false",
        "        readOnlyRootFilesystem: true",
        "        capabilities:",
        "          drop:",
        "            - ALL",
    ])
    rep_hardened_clone = kernel.run_mission(
        "ack-m3-attack-path-hardening",
        mutation_rounds=3,
        defense_mode="structural",
        target_config_content=hardened_yaml_manifest,
    )
    assert rep_hardened_clone.audit_scope == "cloned_target_manifest"
    assert rep_hardened_clone.tpr_fpr_matrix.pre_patch_breach_confirmed is False
    assert rep_hardened_clone.certified is False
    assert rep_hardened_clone.certification_verdict == "NO_BASELINE_PRIVESC_IN_CLONED_MANIFEST"

    # 4) Mixed INI+YAML invalid document must be rejected rather than certified
    mixed_invalid = "[Service]\nNoNewPrivileges=false\nsecurityContext:\n  privileged: true\n"
    rep_invalid = kernel.run_mission(
        "ack-m3-attack-path-hardening",
        mutation_rounds=3,
        defense_mode="structural",
        target_config_content=mixed_invalid,
    )
    assert rep_invalid.certified is False
    assert rep_invalid.certification_verdict == "INVALID_MANIFEST_FORMAT"


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
