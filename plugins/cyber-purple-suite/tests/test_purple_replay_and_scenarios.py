"""End-to-end tests across all 6 dialectical scenarios, Purple Replay, and Benchmark."""

from hermes_cyber.models import VerdictType
from hermes_cyber.pipeline import CyberPurpleAssistant
from hermes_cyber.scenarios import _SCENARIOS


def test_all_six_scenarios_expected_verdicts_and_zero_baseline_fpr(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    for scen in _SCENARIOS:
        report = assistant.analyze_scenario(scen.scenario_id)
        assert report.verdict.verdict == scen.expected_verdict, (
            f"{scen.scenario_id}: got {report.verdict.verdict}, expected {scen.expected_verdict}"
        )
        assert len(report.red_report.probes) >= 1
        assert len(report.blue_report.sigma_rule.detection_keywords) >= 2
        assert "title:" in report.blue_report.sigma_rule.yaml_text
        assert report.verdict.discriminating_test.strip() != ""
        # Baseline clean traffic must never generate false positives
        assert report.verdict.replay.false_positive_rate == 0.0
        # Blue Sigma+YARA defenses must catch Red's simulated attack & evasion variants
        assert report.verdict.replay.detection_coverage == 1.0


def test_benchmark_proves_multi_agent_purple_outperforms_single_agent(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)
    bench = assistant.run_benchmark()

    assert bench.total_scenarios == 6
    assert bench.purple_multi_agent_accuracy == 1.0
    assert bench.purple_multi_agent_accuracy > bench.single_agent_accuracy
    assert bench.purple_fpr == 0.0
    assert bench.single_agent_fpr > bench.purple_fpr
    assert bench.abstention_accuracy == 1.0
    assert bench.contradiction_recall == 1.0
    assert bench.avg_detection_coverage == 1.0


def test_interactive_replay_tuning_detects_missed_evasion_when_weakened(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)
    report = assistant.analyze_scenario("scen-03-sqli-ssrf-code-chain")

    # Strip octal IP & evasion keywords -> replay must expose evasion gap
    weak_replay = assistant.rerun_replay(
        case_id=report.case_id,
        detection_keywords=["169.254.169.254"],
        exclude_values=["/api/v1/health"],
    )
    assert weak_replay.evasion_caught_rate < 1.0
    assert len(weak_replay.defense_gaps) >= 1

    # Add octal IP / SQL evasion token back -> coverage returns to 100% with 0 FP
    tuned_replay = assistant.rerun_replay(
        case_id=report.case_id,
        detection_keywords=["169.254.169.254", "0251.0376.0251.0376"],
        exclude_values=["/api/v1/health"],
    )
    assert tuned_replay.detection_coverage == 1.0
    assert tuned_replay.evasion_caught_rate == 1.0
    assert tuned_replay.false_positive_rate == 0.0

    # Verify tuned Sigma configuration & YAML are persisted onto the saved case
    reloaded = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False).get_case(report.case_id)
    assert reloaded.blue_report.sigma_rule.detection_keywords == ["169.254.169.254", "0251.0376.0251.0376"]
    assert "0251.0376.0251.0376" in reloaded.blue_report.sigma_rule.yaml_text
    assert reloaded.verdict.replay.detection_coverage == 1.0


def test_benign_or_neutral_custom_telemetry_abstains_without_fake_attack(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)
    report = assistant.analyze_custom(title="Routine Healthcheck", content="GET /health status=200", source_kind="http")
    assert report.verdict.verdict == VerdictType.INSUFFICIENT_EVIDENCE
    assert report.red_report.kill_chain == []
    assert "adm_rossi" not in report.red_report.primary_hypothesis
    assert "pickle" not in report.blue_report.competing_hypothesis.lower()


def test_generic_sink_with_benign_prefix_generates_literal_rules_and_full_replay_coverage(tmp_path):
    assistant = CyberPurpleAssistant(home_dir=tmp_path, allow_remote=False, use_llm=False)

    for label, sink_line, expected_sub in [
        ("subprocess", "application started\nsubprocess.run(user_input, shell=True)", "subprocess.run"),
        ("os_system", "application started\nos.system(user_input)", "os.system"),
    ]:
        report = assistant.analyze_custom(title=f"Generic {label}", content=sink_line, source_kind="code")
        assert len(report.red_report.kill_chain) >= 1
        assert report.red_report.simulated_events[0].log_line != "application started"
        assert expected_sub in report.red_report.simulated_events[0].log_line
        kws = report.blue_report.sigma_rule.detection_keywords
        assert "cmd_exec" not in kws
        assert expected_sub in kws
        assert all(s != "cmd_exec" for s in report.blue_report.yara_rule.strings)
        assert report.verdict.replay.detection_coverage == 1.0


