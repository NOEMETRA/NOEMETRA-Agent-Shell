"""Focused regression suite verifying all 6 ACK audit findings end-to-end."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from hermes_cyber.ack import (
    AckSemanticTestCase,
    AdversarialCyberKernel,
    audit_llm_patch_ast,
    inspect_function_sensitive_ops,
    stage_python_parser_workspace,
)
from hermes_cyber.ack.workspace import _MAX_STAGED_FILE_BYTES, _read_bounded_regular_file


class _MockRouter:
    """Offline mock matching the ModelRouter interface used by ACK sub-agents."""

    def __init__(self, provider: str, model: str, replies: List[str]) -> None:
        self.default_provider = provider
        self.ollama_model = model
        self.last_model_used = model
        self._replies = list(replies)
        self.calls: List[Dict[str, str]] = []

    def is_active_endpoint_local(self) -> bool:
        return True

    def generate(self, *, prompt: str, system_prompt: str = "", temperature: float = 0.1, max_tokens: int = 900) -> str:
        del temperature, max_tokens
        self.calls.append({"system_prompt": system_prompt, "prompt": prompt})
        if self._replies:
            return self._replies.pop(0)
        return "{}"


_BUGGY_SRC = '''\
import struct


def parse_packet(data: bytes) -> dict:
    magic, length = struct.unpack(">HH", data[:4])
    body = data[4 : 4 + length]
    return {"magic": magic, "body_len": len(body), "first": body[0]}
'''

_SAFE_ROOT_CAUSE_PATCH = '''\
import struct


def parse_packet(data: bytes) -> dict:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 5:
        raise ValueError("packet too short")
    magic, length = struct.unpack(">HH", data[:4])
    if length < 1 or 4 + length > len(data):
        raise ValueError("invalid payload bounds")
    body = data[4 : 4 + length]
    return {"magic": magic, "body_len": len(body), "first": body[0]}
'''


def test_finding1_three_tier_patch_classification_and_semantic_assertions(tmp_path: Path):
    kernel = AdversarialCyberKernel()
    runs_dir = tmp_path / "runs"

    pfile = tmp_path / "pkt_parser.py"
    pfile.write_text(_BUGGY_SRC, encoding="utf-8")

    # 1) Deterministic AST wrapper without LLM -> exception containment only (never VERIFIED / certified)
    rep_wrap = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(pfile),
        target_function="parse_packet",
        valid_inputs=[AckSemanticTestCase(input=b"\x00\x01\x00\x02AB", expected={"magic": 1, "body_len": 2, "first": 65})],
        runs_dir=runs_dir,
    )
    assert rep_wrap.certified is False
    assert rep_wrap.patch_applicable is True
    assert rep_wrap.patch_classification == "exception_containment_only"
    assert rep_wrap.certification_verdict == "CONTAINED_WORKSPACE_PARSER_EXCEPTIONS"
    assert rep_wrap.manual_review_required is True

    # 2) Safe LLM root-cause patch WITHOUT external semantic expectations -> unverified semantics (certified=False)
    blue_no_sem = _MockRouter(
        "ollama",
        "blue-root",
        [json.dumps({"patched_source": _SAFE_ROOT_CAUSE_PATCH, "summary": "root bounds check"})],
    )
    rep_unver = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(pfile),
        target_function="parse_packet",
        valid_inputs=[b"\x00\x01\x00\x02AB"],
        blue_router=blue_no_sem,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_unver.certified is False
    assert rep_unver.patch_applicable is True
    assert rep_unver.patch_classification == "root_cause_patch_unverified_semantics"
    assert rep_unver.certification_verdict == "PATCHED_WORKSPACE_UNVERIFIED_SEMANTICS"
    assert rep_unver.manual_review_required is True
    assert rep_unver.tpr_fpr_matrix.semantic_assertions_count == 0

    # 3) Safe LLM root-cause patch WITH `.expected.json` sidecars -> full semantic certification (certified=True)
    corpus_dir = tmp_path / "sem_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "ok1.bin").write_bytes(b"\x00\x01\x00\x02AB")
    (corpus_dir / "ok1.expected.json").write_text(json.dumps({"magic": 1, "body_len": 2, "first": 65}), encoding="utf-8")

    blue_sem = _MockRouter(
        "ollama",
        "blue-root",
        [json.dumps({"patched_source": _SAFE_ROOT_CAUSE_PATCH, "summary": "root bounds check"})],
    )
    rep_ver = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(pfile),
        target_function="parse_packet",
        valid_corpus_dir=str(corpus_dir),
        blue_router=blue_sem,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_ver.certified is True
    assert rep_ver.patch_applicable is True
    assert rep_ver.patch_classification == "semantically_verified_patch"
    assert rep_ver.certification_verdict == "VERIFIED_WORKSPACE_PARSER_PATCH"
    assert rep_ver.manual_review_required is False
    assert rep_ver.tpr_fpr_matrix.semantic_assertions_count == 1
    assert rep_ver.tpr_fpr_matrix.semantic_assertion_pass_rate == 1.0
    reg_file = list((Path(rep_ver.deliverable_dir) / "regression_tests").glob("test_ack_regression_*.py"))[0]
    proc = subprocess.run([sys.executable, "-m", "pytest", str(reg_file), "-q"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"Semantic regression pytest failed:\n{proc.stdout}\n{proc.stderr}"

    # 4) Wrong semantic assertion MUST reject certification cleanly
    blue_bad_sem = _MockRouter(
        "ollama",
        "blue-root",
        [json.dumps({"patched_source": _SAFE_ROOT_CAUSE_PATCH, "summary": "root bounds check"})],
    )
    rep_wrong = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(pfile),
        target_function="parse_packet",
        valid_inputs=[AckSemanticTestCase(input=b"\x00\x01\x00\x02AB", expected={"magic": 999, "body_len": 2, "first": 65})],
        blue_router=blue_bad_sem,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_wrong.certified is False
    assert rep_wrong.certification_verdict == "REJECTED_BROKEN_PARSER"

    # 5) Patch fixing an incorrect pre-patch output to match supplied `expected_semantic` MUST succeed
    buggy_sem_file = tmp_path / "buggy_sem_parser.py"
    buggy_sem_file.write_text(
        "import struct\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    magic, length = struct.unpack('>HH', data[:4])\n"
        "    body = data[4 : 4 + length]\n"
        "    return {'magic': magic + 1, 'body_len': len(body), 'first': body[0]}\n",
        encoding="utf-8",
    )
    blue_fix_sem = _MockRouter(
        "ollama",
        "blue-root",
        [json.dumps({"patched_source": _SAFE_ROOT_CAUSE_PATCH, "summary": "fix off-by-one magic + bounds"})],
    )
    rep_fixed_sem = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(buggy_sem_file),
        target_function="parse_packet",
        valid_inputs=[AckSemanticTestCase(input=b"\x00\x01\x00\x02AB", expected={"magic": 1, "body_len": 2, "first": 65})],
        blue_router=blue_fix_sem,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_fixed_sem.certified is True
    assert rep_fixed_sem.patch_classification == "semantically_verified_patch"
    assert rep_fixed_sem.tpr_fpr_matrix.valid_output_mismatch_rate == 0.0
    assert rep_fixed_sem.tpr_fpr_matrix.semantic_assertion_pass_rate == 1.0
    assert rep_fixed_sem.tpr_fpr_matrix.functional_survival_rate == 1.0
    sem_reg = list((Path(rep_fixed_sem.deliverable_dir) / "regression_tests").glob("test_ack_regression_*.py"))[0]
    sem_proc = subprocess.run([sys.executable, "-m", "pytest", str(sem_reg), "-q"], capture_output=True, text=True, check=False)
    assert sem_proc.returncode == 0, f"Fixed semantic regression failed:\n{sem_proc.stdout}\n{sem_proc.stderr}"

    # 6) Mismatching semantic output differing from BOTH baseline and expected must NOT double-count mismatch_count
    blue_nodbl = _MockRouter(
        "ollama",
        "blue-root",
        [json.dumps({"patched_source": _SAFE_ROOT_CAUSE_PATCH, "summary": "fix off-by-one + bounds"})],
    )
    rep_nodbl = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(buggy_sem_file),
        target_function="parse_packet",
        valid_inputs=[
            AckSemanticTestCase(input=b"\x00\x01\x00\x02AB", expected={"magic": 1, "body_len": 2, "first": 65}),
            AckSemanticTestCase(input=b"\x00\x01\x00\x02AB", expected={"magic": 999, "body_len": 2, "first": 65}),
        ],
        blue_router=blue_nodbl,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_nodbl.certified is False
    assert rep_nodbl.certification_verdict == "REJECTED_BROKEN_PARSER"
    assert rep_nodbl.tpr_fpr_matrix.valid_output_mismatch_rate == 0.5
    assert rep_nodbl.tpr_fpr_matrix.functional_survival_rate == 0.5

    # 7) Ordinary dict-valued valid inputs with "input" and "expected" keys MUST remain intact (unwrapped),
    # whereas AckSemanticTestCase opts in explicitly without colliding with dict-valued parsers.
    dict_parser = tmp_path / "dict_record_parser.py"
    dict_parser.write_text(
        "def parse_cfg(record: dict) -> dict:\n"
        "    return {'in': record['input'], 'exp': record['expected']}\n",
        encoding="utf-8",
    )
    staged_plain_dict = stage_python_parser_workspace(
        str(dict_parser),
        "parse_cfg",
        valid_inputs=[{"input": "abc", "expected": "xyz"}],
    )
    plain_entry = staged_plain_dict.valid_corpus[0]
    assert plain_entry["kind"] == "json"
    assert plain_entry["data"] == {"input": "abc", "expected": "xyz"}
    assert "has_semantic_expected" not in plain_entry

    staged_sem_dict = stage_python_parser_workspace(
        str(dict_parser),
        "parse_cfg",
        valid_inputs=[AckSemanticTestCase(input={"input": "abc", "expected": "xyz"}, expected={"ok": True})],
    )
    sem_entry = staged_sem_dict.valid_corpus[0]
    assert sem_entry["kind"] == "json"
    assert sem_entry["data"] == {"input": "abc", "expected": "xyz"}
    assert sem_entry["has_semantic_expected"] is True
    assert sem_entry["expected_semantic"] == {"ok": True}


def test_finding2_ast_preexisting_sensitive_op_and_arg_mutation_blocked(tmp_path: Path):
    # Pre-existing `open(...)` in target_function MUST prevent automatic LLM patching
    orig_sensitive = (
        "def parse_cfg(path_str: str) -> dict:\n"
        "    with open(path_str, 'r', encoding='utf-8') as fh:\n"
        "        txt = fh.read()\n"
        "    return {'ch': txt[0]}\n"
    )
    mutated_open_arg = (
        "def parse_cfg(path_str: str) -> dict:\n"
        "    with open('/etc/passwd', 'r', encoding='utf-8') as fh:\n"
        "        txt = fh.read()\n"
        "    return {'ch': txt[0]}\n"
    )
    sens_ops, non_allow = inspect_function_sensitive_ops(orig_sensitive, "parse_cfg")
    assert any("open" in s for s in sens_ops)
    assert non_allow == []
    res_sens = audit_llm_patch_ast(orig_sensitive, mutated_open_arg, "parse_cfg")
    assert res_sens.safe is False
    assert res_sens.manual_review_required is True
    assert any("Pre-existing sensitive operations" in r for r in res_sens.rejection_reasons)

    # Custom helper call `read_hdr(data)`: changing args to `read_hdr(data[1:])` MUST fail exact call-AST equality,
    # whereas preserving `read_hdr(data)` untouched and adding length check MUST pass.
    orig_helper = (
        "from hdr_helper import read_hdr\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    magic, length = read_hdr(data)\n"
        "    return {'magic': magic, 'first': data[4]}\n"
    )
    mutated_helper_arg = (
        "from hdr_helper import read_hdr\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    magic, length = read_hdr(data[1:])\n"
        "    return {'magic': magic, 'first': data[4]}\n"
    )
    preserved_helper = (
        "from hdr_helper import read_hdr\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    if len(data) < 5:\n"
        "        raise ValueError('short')\n"
        "    magic, length = read_hdr(data)\n"
        "    return {'magic': magic, 'first': data[4]}\n"
    )
    assert audit_llm_patch_ast(orig_helper, mutated_helper_arg, "parse_packet").safe is False
    ok_audit = audit_llm_patch_ast(orig_helper, preserved_helper, "parse_packet")
    assert ok_audit.safe is True
    assert ok_audit.non_allowlisted_calls_in_original == ["read_hdr"]

    # End-to-end M4 run on function containing pre-existing sensitive `open`: LLM patch blocked, ops surfaced
    cfg_dir = tmp_path / "cfg_proj"
    cfg_dir.mkdir()
    pfile = cfg_dir / "cfg_parser.py"
    pfile.write_text(orig_sensitive, encoding="utf-8")
    (cfg_dir / "good.cfg").write_text("OK", encoding="utf-8")
    blue_try = _MockRouter("ollama", "blue-m", [json.dumps({"patched_source": mutated_open_arg, "summary": "try"})])
    rep = AdversarialCyberKernel().run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(pfile),
        target_function="parse_cfg",
        valid_inputs=["good.cfg"],
        blue_router=blue_try,  # type: ignore[arg-type]
        runs_dir=tmp_path / "runs",
    )
    assert rep.certified is False
    assert rep.manual_review_required is True
    assert rep.workspace_target is not None
    assert any("open" in s for s in rep.workspace_target.sensitive_ops_in_original)
    assert any("fallback_ast_guard" in tr.model_used for tr in rep.subagent_traces if tr.team == "BLUE")

    # End-to-end M4 run with unchanged non-allowlisted call (`read_hdr(data)`) + passing semantic assertions:
    # must certify semantically BUT still require manual_review_required=True before approval issuance.
    helper_dir = tmp_path / "helper_proj"
    helper_dir.mkdir()
    (helper_dir / "hdr_helper.py").write_text(
        "import struct\n"
        "def read_hdr(data: bytes):\n"
        "    if len(data) < 4:\n"
        "        raise ValueError('short header')\n"
        "    return struct.unpack('>HH', data[:4])\n",
        encoding="utf-8",
    )
    helper_parser = helper_dir / "pkt_with_helper.py"
    helper_parser.write_text(orig_helper, encoding="utf-8")
    blue_helper = _MockRouter(
        "ollama",
        "blue-helper",
        [json.dumps({"patched_source": preserved_helper, "summary": "keep read_hdr + bounds check"})],
    )
    confirm_kernel = AdversarialCyberKernel(human_confirm_fn=lambda _ctx: True)
    runs_helper = tmp_path / "runs_helper"
    rep_helper = confirm_kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(helper_parser),
        target_function="parse_packet",
        valid_inputs=[AckSemanticTestCase(input=b"\x00\x07\x00\x01Z", expected={"magic": 7, "first": 90})],
        blue_router=blue_helper,  # type: ignore[arg-type]
        runs_dir=runs_helper,
    )
    assert rep_helper.certified is True
    assert rep_helper.patch_classification == "semantically_verified_patch"
    assert rep_helper.manual_review_required is True
    assert any("read_hdr" in r for r in rep_helper.manual_review_reasons)
    with pytest.raises(PermissionError, match="Revisione manuale"):
        confirm_kernel.issue_patch_approval(
            rep_helper.run_id,
            session_id="sess-h1",
            expected_target_file_path=str(helper_parser),
            acknowledge_manual_review=False,
            runs_dir=runs_helper,
        )
    ok_helper_appr = confirm_kernel.issue_patch_approval(
        rep_helper.run_id,
        session_id="sess-h1",
        expected_target_file_path=str(helper_parser),
        acknowledge_manual_review=True,
        runs_dir=runs_helper,
    )
    assert ok_helper_appr["manual_review_required"] is True


def test_finding3_symlink_perimeter_and_stat_before_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET_OUTSIDE", encoding="utf-8")

    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir()
    parser_p = ws_dir / "parser.py"
    parser_p.write_text(_BUGGY_SRC, encoding="utf-8")

    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "ok.bin").write_bytes(b"\x00\x01\x00\x02hi")

    def _make_symlink_or_mock(link_p: Path, target_p: Path) -> None:
        try:
            os.symlink(str(target_p), str(link_p))
        except OSError:
            link_p.write_text("placeholder", encoding="utf-8")
            orig_is_sym = Path.is_symlink
            orig_resolve = Path.resolve
            monkeypatch.setattr(Path, "is_symlink", lambda self: True if self == link_p else orig_is_sym(self))
            monkeypatch.setattr(Path, "resolve", lambda self, strict=False: target_p if self == link_p else orig_resolve(self, strict=strict))

    # 1) Escaping symlink file in workspace MUST raise ValueError
    esc_link = ws_dir / "leak.txt"
    _make_symlink_or_mock(esc_link, outside_secret)
    with pytest.raises(ValueError, match="fuori dal perimetro workspace"):
        stage_python_parser_workspace(str(parser_p), "parse_packet", valid_corpus_dir=str(corpus_dir))
    monkeypatch.undo()
    esc_link.unlink(missing_ok=True)

    # 2) Escaping symlink inside corpus_dir MUST raise ValueError
    corpus_link = corpus_dir / "esc.bin"
    _make_symlink_or_mock(corpus_link, outside_secret)
    with pytest.raises(ValueError, match="fuori dal perimetro corpus"):
        stage_python_parser_workspace(str(parser_p), "parse_packet", valid_corpus_dir=str(corpus_dir))
    monkeypatch.undo()
    corpus_link.unlink(missing_ok=True)

    # 3) Internal symlink inside workspace pointing to `.env` MUST be excluded
    env_file = ws_dir / ".env"
    env_file.write_text("SECRET=123", encoding="utf-8")
    env_alias = ws_dir / "alias.txt"
    _make_symlink_or_mock(env_alias, env_file)
    staged = stage_python_parser_workspace(str(parser_p), "parse_packet", valid_corpus_dir=str(corpus_dir))
    assert "alias.txt" not in staged.extra_files
    assert ".env" not in staged.extra_files
    monkeypatch.undo()

    # 3b) Oversized corpus entry (> 512 KiB) MUST be skipped without aborting valid corpus inputs
    oversized_corpus = corpus_dir / "oversized.bin"
    oversized_corpus.write_bytes(b"B" * (512 * 1024 + 64))
    staged_with_oversized = stage_python_parser_workspace(str(parser_p), "parse_packet", valid_corpus_dir=str(corpus_dir))
    staged_names = [entry["name"] for entry in staged_with_oversized.valid_corpus]
    assert "ok.bin" in staged_names
    assert "oversized.bin" not in staged_names
    oversized_corpus.unlink(missing_ok=True)

    # 4) Stat-before-read rejects oversized file BEFORE opening
    big_file = ws_dir / "huge.bin"
    big_file.write_bytes(b"A" * 10)
    fake_stat = os.stat_result((0o100644, 0, 0, 1, 0, 0, _MAX_STAGED_FILE_BYTES + 100, 0, 0, 0))
    orig_stat = Path.stat
    orig_open = Path.open
    opened: List[Path] = []

    monkeypatch.setattr(Path, "stat", lambda self, **kw: fake_stat if self == big_file.resolve() else orig_stat(self, **kw))
    monkeypatch.setattr(Path, "open", lambda self, *a, **kw: (opened.append(self), orig_open(self, *a, **kw))[1])
    with pytest.raises(ValueError, match="supera il limite"):
        _read_bounded_regular_file(big_file.resolve(), _MAX_STAGED_FILE_BYTES, "huge.bin")
    assert big_file.resolve() not in opened


def test_finding5_m1_m2_m3_executable_llm_proposals_and_metrics(tmp_path: Path):
    kernel = AdversarialCyberKernel()
    runs_dir = tmp_path / "runs"

    # M1: LLM proposes executable HTTP probe path actually executed in round 1
    red_m1 = _MockRouter("ollama", "red-m1", [json.dumps({"extra_http_paths": ["/canary_vault/llm_probe.txt"]})])
    rep_m1 = kernel.run_mission("ack-m1-exploit-patch-bypass", mutation_rounds=1, red_router=red_m1, runs_dir=runs_dir)  # type: ignore[arg-type]
    assert rep_m1.certified is True
    assert rep_m1.subagent_execution_architecture == "llm_guided_role_pipeline"
    assert rep_m1.mutation_rounds[0].attempts_executed == 4
    assert any(tr.role == "RedBypassMutatorSubAgent" and tr.execution_kind == "llm_executable_proposal" and tr.contributed_payloads_or_patch for tr in rep_m1.subagent_traces)
    assert rep_m1.tpr_fpr_matrix.metric_kind == "exploit_patch_verification"
    assert rep_m1.tpr_fpr_matrix.detector_metrics_applicable is False
    assert rep_m1.tpr_fpr_matrix.true_positive_rate is None
    assert rep_m1.tpr_fpr_matrix.false_positive_rate is None

    # M2: LLM Red proposes executable event + LLM Blue proposes executable rule merged into blue_rules.json
    # All 3 fixed baseline evasion classes MUST remain executed alongside the LLM-proposed event (total=4)
    red_m2 = _MockRouter("ollama", "red-m2", [json.dumps({"extra_telemetry_events": [{"telemetry": "proc=custom_llm_evader memfd_create", "entropy": 4.5}]})])
    blue_m2 = _MockRouter("ollama", "blue-m2", [json.dumps({"extra_patterns": ["custom_llm_evader"]})])
    rep_m2 = kernel.run_mission("ack-m2-detection-evasion-arena", mutation_rounds=3, red_router=red_m2, blue_router=blue_m2, runs_dir=runs_dir)  # type: ignore[arg-type]
    assert rep_m2.certified is True
    assert len(rep_m2.mutation_rounds) == 4
    assert rep_m2.tpr_fpr_matrix.attack_variants_tested == 4
    m2_classes = [mr.attack_class for mr in rep_m2.mutation_rounds]
    assert "CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION" in m2_classes
    assert "CLASS_LLM_PROPOSED_EVASION_1" in m2_classes
    assert rep_m2.tpr_fpr_matrix.metric_kind == "detector_tpr_fpr"
    assert rep_m2.tpr_fpr_matrix.detector_metrics_applicable is True
    assert rep_m2.tpr_fpr_matrix.true_positive_rate == 1.0
    assert rep_m2.tpr_fpr_matrix.false_positive_rate == 0.0
    assert "custom_llm_evader" in rep_m2.patch_diff
    assert "ebpf" not in rep_m2.blue_patch_or_rules_summary.lower()

    # M2 stealth check: novel Red LLM event NOT covered by structural Blue rules must cause EVADED_BY_RED
    # while fixed CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION continues to be tested and detected
    red_m2_stealth = _MockRouter(
        "ollama",
        "red-m2-stealth",
        [json.dumps({"extra_telemetry_events": [{"telemetry": "proc=novel_stealth_benign_looking_evt", "entropy": 1.2}]})],
    )
    rep_m2_evaded = kernel.run_mission(
        "ack-m2-detection-evasion-arena",
        mutation_rounds=3,
        red_router=red_m2_stealth,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_m2_evaded.certified is False
    assert rep_m2_evaded.certification_verdict == "EVADED_BY_RED"
    cli_round = next(mr for mr in rep_m2_evaded.mutation_rounds if mr.attack_class == "CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION")
    llm_round = next(mr for mr in rep_m2_evaded.mutation_rounds if mr.attack_class == "CLASS_LLM_PROPOSED_EVASION_1")
    assert cli_round.bypass_succeeded is False
    assert llm_round.bypass_succeeded is True
    assert rep_m2_evaded.tpr_fpr_matrix.true_positive_rate == 0.75

    # M3: LLM Blue proposes hardened manifest validated syntactically & scored by simulator
    llm_manifest = "\n".join([
        "[Unit]",
        "Description=NOEMETRA LLM Hardened Helper",
        "[Service]",
        "ServiceEnabled=true",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "HelperWritable=false",
        "AmbientCapabilities=",
        "[Socket]",
        "SocketMode=0600",
    ])
    blue_m3 = _MockRouter("ollama", "blue-m3", [json.dumps({"hardened_manifest": llm_manifest})])
    rep_m3 = kernel.run_mission("ack-m3-attack-path-hardening", mutation_rounds=2, blue_router=blue_m3, runs_dir=runs_dir)  # type: ignore[arg-type]
    assert rep_m3.certified is True
    assert rep_m3.tpr_fpr_matrix.metric_kind == "config_hardening_verification"
    assert rep_m3.tpr_fpr_matrix.detector_metrics_applicable is False
    assert rep_m3.tpr_fpr_matrix.true_positive_rate is None
    assert rep_m3.tpr_fpr_matrix.exploit_mitigation_rate == 1.0
    assert "NOEMETRA LLM Hardened Helper" in rep_m3.patch_diff
    assert any(tr.team == "BLUE" and tr.execution_kind == "llm_executable_proposal" and tr.contributed_payloads_or_patch for tr in rep_m3.subagent_traces)
