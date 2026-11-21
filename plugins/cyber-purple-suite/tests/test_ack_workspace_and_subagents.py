"""Verification suite for ACK honest boundaries, deliverables, M4 Workspace Mode, sub-agents, and UI sync."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cyber_hermes_plugin.cyber_plugin import TOOLS, cyber_apply_ack_patch, cyber_get_status
from hermes_cyber.ack import (
    AdversarialCyberKernel,
    FogOfWarController,
    prompt_interactive_operator_confirmation,
)
from hermes_cyber.ack.blue_subagents import _is_llm_patch_ast_safe
from hermes_cyber.pipeline import CyberPurpleAssistant
from hermes_cyber.server import api as cyber_api
from hermes_cyber.server.api import router as cyber_router

_STALE_FAKE_LABELS = (
    "seccomp_kernel",
    "seccomp_contain",
    "ebpf_sigma_yara",
    "ebpf_syscall",
    "auditd_lineage",
    "net_veth_ebpf",
    "host_cow_audit",
    "ASAN_",
    "UBSAN_",
)

_BUGGY_PARSER_SOURCE = '''\
import struct


def parse_packet(data: bytes) -> dict:
    magic, length = struct.unpack(">HH", data[:4])
    body = data[4 : 4 + length]
    if magic == 0xFFFF:
        return {"nested": parse_packet(body), "magic": magic}
    return {"magic": magic, "body_len": len(body), "first": body[0]}
'''


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _FakeLLMRouter:
    """Offline mock matching the subset of ModelRouter used by invoke_router_json."""

    def __init__(self, provider: str, model: str, replies: List[str]) -> None:
        self.default_provider = provider
        self.ollama_model = model
        self.last_model_used = model
        self._replies = list(replies)
        self.calls: List[Dict[str, str]] = []

    def is_active_endpoint_local(self) -> bool:
        return True

    def generate(
        self,
        *,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 900,
    ) -> str:
        del temperature, max_tokens
        self.calls.append({"system_prompt": system_prompt, "prompt": prompt})
        if self._replies:
            return self._replies.pop(0)
        return "{}"


def test_ack_honest_boundaries_metrics_and_no_fake_labels(tmp_path: Path):
    kernel = AdversarialCyberKernel()
    runs_dir = tmp_path / "runs"

    for mid in (
        "ack-m1-exploit-patch-bypass",
        "ack-m2-detection-evasion-arena",
        "ack-m3-attack-path-hardening",
        "ack-m4-fuzz-to-fix-pipeline",
    ):
        report = kernel.run_mission(mid, mutation_rounds=2, runs_dir=runs_dir)
        assert report.security_boundary_level == "process_confinement_not_untrusted_sandbox"
        assert "untrusted LLM code" in report.untrusted_llm_code_warning
        assert len(report.executed_checks) >= 2
        assert "autonomous_shell_tool_agent_team" in report.not_executed_checks
        assert report.subagent_execution_architecture == "in_process_role_pipeline"

        dumped = json.dumps(report.model_dump(mode="json"))
        for bad in _STALE_FAKE_LABELS:
            assert bad not in dumped, f"Stale misleading label {bad!r} leaked in {mid}"

        if mid in ("ack-m1-exploit-patch-bypass", "ack-m3-attack-path-hardening"):
            assert report.tpr_fpr_matrix.detector_metrics_applicable is False
            assert report.tpr_fpr_matrix.true_positive_rate is None
            assert report.tpr_fpr_matrix.false_positive_rate is None
            assert report.tpr_fpr_matrix.fpr_measured is False
            assert report.tpr_fpr_matrix.benign_corpus_size == 0
            assert report.tpr_fpr_matrix.exploit_mitigation_rate == 1.0
        elif mid == "ack-m2-detection-evasion-arena":
            assert report.tpr_fpr_matrix.metric_kind == "detector_tpr_fpr"
            assert report.tpr_fpr_matrix.detector_metrics_applicable is True
            assert report.tpr_fpr_matrix.fpr_measured is True
            assert report.tpr_fpr_matrix.benign_corpus_size == 10
            assert "ebpf" not in report.blue_patch_or_rules_summary.lower()
        else:
            assert report.tpr_fpr_matrix.metric_kind == "parser_fuzz_verification"
            assert report.tpr_fpr_matrix.detector_metrics_applicable is False
            assert report.tpr_fpr_matrix.true_positive_rate is None
            assert report.tpr_fpr_matrix.false_positive_rate is None
            assert report.tpr_fpr_matrix.fpr_measured is False
            assert report.tpr_fpr_matrix.benign_corpus_size == 2
            assert report.tpr_fpr_matrix.semantic_assertions_count == 2
            assert report.tpr_fpr_matrix.semantic_assertion_pass_rate == 1.0


def test_ack_persistent_deliverables_survive_cleanup_and_match_sha256(tmp_path: Path):
    kernel = AdversarialCyberKernel()
    runs_dir = tmp_path / "runs"

    for mid in ("ack-m1-exploit-patch-bypass", "ack-m4-fuzz-to-fix-pipeline"):
        report = kernel.run_mission(mid, mutation_rounds=2, runs_dir=runs_dir)
        assert report.deliverable_dir
        deliv_dir = Path(report.deliverable_dir)
        assert deliv_dir.is_dir()

        for expected in ("report.json", "report.md", "findings.json", "patch.diff", "manifest.json"):
            assert (deliv_dir / expected).is_file(), f"Missing {expected} in {deliv_dir}"
        for subdir in ("repro", "regression_tests", "execution_logs"):
            assert (deliv_dir / subdir).is_dir()

        manifest = json.loads((deliv_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["run_id"] == report.run_id
        for rel_path, expected_hex in manifest["sha256"].items():
            target_file = deliv_dir / rel_path
            assert target_file.is_file(), f"Checksummed file missing: {rel_path}"
            assert _sha256_file(target_file) == expected_hex


def test_ack_m4_workspace_mode_isolated_copy_and_git_worktree_with_standalone_pytest(tmp_path: Path):
    kernel = AdversarialCyberKernel()
    runs_dir = tmp_path / "runs"

    # 1. isolated_copy mode over a real PC Python file importing a sibling helper module + valid binary corpus
    iso_dir = tmp_path / "iso_proj"
    iso_dir.mkdir()
    (iso_dir / "hdr_helper.py").write_text(
        "import struct\n\ndef read_hdr(buf: bytes) -> tuple:\n    return struct.unpack('>HH', buf[:4])\n",
        encoding="utf-8",
    )
    iso_parser = iso_dir / "pkt_parser.py"
    iso_parser.write_text(
        "from hdr_helper import read_hdr\n\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    magic, length = read_hdr(data)\n"
        "    body = data[4 : 4 + length]\n"
        "    if magic == 0xFFFF:\n"
        "        return {'nested': parse_packet(body), 'magic': magic}\n"
        "    return {'magic': magic, 'body_len': len(body), 'first': body[0]}\n",
        encoding="utf-8",
    )
    iso_orig_bytes = iso_parser.read_bytes()

    corpus_dir = tmp_path / "valid_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "pkt1.bin").write_bytes(b"\x00\x01\x00\x02OK")
    (corpus_dir / "pkt2.bin").write_bytes(b"\x00\x02\x00\x03XYZ")

    rep_iso = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(iso_parser),
        target_function="parse_packet",
        valid_corpus_dir=str(corpus_dir),
        workspace_mode="isolated_copy",
        runs_dir=runs_dir,
    )
    assert rep_iso.audit_scope == "workspace_target_file"
    assert rep_iso.verification_tier == "workspace_target_verification"
    # Deterministic AST exception wrapper alone certifies ONLY as exception containment, not full fix
    assert rep_iso.certified is False
    assert rep_iso.patch_applicable is True
    assert rep_iso.patch_classification == "exception_containment_only"
    assert rep_iso.certification_verdict == "CONTAINED_WORKSPACE_PARSER_EXCEPTIONS"
    assert rep_iso.manual_review_required is True
    assert rep_iso.tpr_fpr_matrix.detector_metrics_applicable is False
    assert rep_iso.tpr_fpr_matrix.true_positive_rate is None
    assert rep_iso.tpr_fpr_matrix.valid_input_rejection_rate == 0.0
    assert rep_iso.tpr_fpr_matrix.crash_mitigation_rate == 1.0
    assert rep_iso.workspace_target is not None
    assert rep_iso.workspace_target.workspace_mode == "isolated_copy"
    assert rep_iso.workspace_target.original_untouched is True
    assert iso_parser.read_bytes() == iso_orig_bytes
    assert "parse_packet" in rep_iso.patch_diff
    assert (Path(rep_iso.deliverable_dir) / "patched_target" / "hdr_helper.py").is_file()

    # Execute generated standalone pytest file directly against exported patched_target/ (including sibling helper!)
    reg_tests = list((Path(rep_iso.deliverable_dir) / "regression_tests").glob("test_ack_regression_*.py"))
    assert len(reg_tests) == 1
    assert "expected_snapshot" in reg_tests[0].read_text(encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(reg_tests[0]), "-q"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, f"Standalone generated pytest failed:\n{proc.stdout}\n{proc.stderr}"

    # 2. git_worktree mode over a repo with package relative import (`from .local_helper import ...`),
    # non-sibling nested dependency (`common/codec.py`), AND tracked non-.py JSON resource (`common/limits.json`).
    git_dir = tmp_path / "git_proj"
    (git_dir / "common").mkdir(parents=True)
    (git_dir / "parsers").mkdir(parents=True)
    (git_dir / "common" / "__init__.py").write_text("", encoding="utf-8")
    (git_dir / "common" / "limits.json").write_text('{"max_magic": 65535}', encoding="utf-8")
    (git_dir / "parsers" / "__init__.py").write_text("", encoding="utf-8")
    (git_dir / "parsers" / "local_helper.py").write_text(
        "def check_magic(val: int, ceiling: int) -> bool:\n    return 0 <= val <= ceiling\n",
        encoding="utf-8",
    )
    git_helper = git_dir / "common" / "codec.py"
    git_helper.write_text(
        "def read_hdr(buf: bytes) -> tuple:\n    return (0, 0)\n",
        encoding="utf-8",
    )
    # If the target project itself has `corpus/valid_cases.json`, M4 must NOT overwrite it with harness cases!
    (git_dir / "corpus").mkdir()
    (git_dir / "corpus" / "valid_cases.json").write_text('{"project_resource": true}', encoding="utf-8")
    git_parser = git_dir / "parsers" / "pkt_parser.py"
    git_parser.write_text(
        "import json\nfrom pathlib import Path\nfrom common.codec import read_hdr\nfrom .local_helper import check_magic\n\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    limits = json.loads((Path(__file__).resolve().parents[1] / 'common' / 'limits.json').read_text(encoding='utf-8'))\n"
        "    proj_corpus = json.loads((Path(__file__).resolve().parents[1] / 'corpus' / 'valid_cases.json').read_text(encoding='utf-8'))\n"
        "    assert proj_corpus == {'project_resource': True}\n"
        "    magic, length = read_hdr(data)\n"
        "    if not check_magic(magic, limits['max_magic']):\n"
        "        raise ValueError('bad magic')\n"
        "    body = data[4 : 4 + length]\n"
        "    if magic == 0xFFFF:\n"
        "        return {'nested': parse_packet(body), 'magic': magic}\n"
        "    return {'magic': magic, 'body_len': len(body), 'first': body[0]}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(git_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(git_dir), "config", "user.name", "Test"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(git_dir), "config", "user.email", "t@example.com"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(git_dir), "add", "common/__init__.py", "common/codec.py", "common/limits.json", "parsers/__init__.py", "parsers/local_helper.py", "parsers/pkt_parser.py"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(git_dir), "commit", "-m", "init"], check=True, capture_output=True)
    # Modify non-sibling dependency uncommitted after HEAD -> must be staged consistently with live target
    git_helper.write_text(
        "import struct\n\ndef read_hdr(buf: bytes) -> tuple:\n    return struct.unpack('>HH', buf[:4])\n",
        encoding="utf-8",
    )

    rep_wt = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(git_parser),
        target_function="parse_packet",
        valid_corpus_dir=str(corpus_dir),
        workspace_mode="git_worktree",
        runs_dir=runs_dir,
    )
    assert rep_wt.patch_applicable is True
    assert rep_wt.patch_classification == "exception_containment_only"
    assert rep_wt.workspace_target is not None
    assert rep_wt.workspace_target.workspace_mode == "git_worktree"
    assert rep_wt.workspace_target.target_rel_path == "parsers/pkt_parser.py"
    assert rep_wt.workspace_target.original_untouched is True
    assert "struct.unpack" in (Path(rep_wt.deliverable_dir) / "patched_target" / "common" / "codec.py").read_text(encoding="utf-8")
    assert (Path(rep_wt.deliverable_dir) / "patched_target" / "common" / "limits.json").is_file()
    wt_reg_tests = list((Path(rep_wt.deliverable_dir) / "regression_tests").glob("test_ack_regression_*.py"))
    assert len(wt_reg_tests) == 1
    wt_proc = subprocess.run([sys.executable, "-m", "pytest", str(wt_reg_tests[0]), "-q"], capture_output=True, text=True, timeout=20, check=False)
    assert wt_proc.returncode == 0, f"Worktree nested regression pytest failed:\n{wt_proc.stdout}\n{wt_proc.stderr}"

    # Custom object return values (whose default repr embeds process-specific hex memory addresses) must compare stably
    obj_parser = tmp_path / "obj_parser.py"
    obj_parser.write_text(
        "class ParsedPacket:\n"
        "    def __init__(self, code: int):\n"
        "        self.code = code\n\n"
        "def parse_obj(data: bytes) -> ParsedPacket:\n"
        "    if data[0] == 0:\n"
        "        raise ValueError('zero')\n"
        "    return ParsedPacket(data[1])\n",
        encoding="utf-8",
    )
    rep_obj = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(obj_parser),
        target_function="parse_obj",
        valid_inputs=[b"\x01\x09"],
        runs_dir=runs_dir,
    )
    assert rep_obj.patch_applicable is True
    assert rep_obj.patch_classification == "exception_containment_only"
    obj_reg = list((Path(rep_obj.deliverable_dir) / "regression_tests").glob("test_ack_regression_*.py"))[0]
    obj_proc = subprocess.run([sys.executable, "-m", "pytest", str(obj_reg), "-q"], capture_output=True, text=True, timeout=20, check=False)
    assert obj_proc.returncode == 0, f"Custom object snapshot regression failed:\n{obj_proc.stdout}\n{obj_proc.stderr}"

    # Per-case valid input rejection rate: rejecting 1 of 2 valid inputs reports 0.5 (not hardcoded 1.0),
    # and naive_block_all reports 1.0 without falsely labelling parser metrics as detector TPR/FPR.
    partial_parser = tmp_path / "partial_fpr.py"
    partial_parser.write_text(
        "def parse_txt(text: str) -> str:\n"
        "    return text[0] + text[1:].strip()\n",
        encoding="utf-8",
    )
    partial_blue = _FakeLLMRouter(
        "ollama",
        "blue-partial",
        [json.dumps({
            "patched_source": (
                "def parse_txt(text: str) -> str:\n"
                "    if not text or text == 'world':\n"
                "        raise ValueError('rejected')\n"
                "    return text[0] + text[1:].strip()\n"
            ),
            "summary": "partial over-reject",
        })],
    )
    rep_half = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        target_file_path=str(partial_parser),
        target_function="parse_txt",
        valid_inputs=["hello", "world"],
        blue_router=partial_blue,  # type: ignore[arg-type]
        runs_dir=runs_dir,
    )
    assert rep_half.certified is False
    assert rep_half.patch_applicable is False
    assert rep_half.tpr_fpr_matrix.detector_metrics_applicable is False
    assert rep_half.tpr_fpr_matrix.false_positive_rate is None
    assert rep_half.tpr_fpr_matrix.valid_input_rejection_rate == 0.5
    assert rep_half.tpr_fpr_matrix.functional_survival_rate == 0.5

    rep_fpr = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=1,
        defense_mode="naive_block_all",
        target_file_path=str(partial_parser),
        target_function="parse_txt",
        valid_inputs=["hello", "world"],
        runs_dir=runs_dir,
    )
    assert rep_fpr.certified is False
    assert rep_fpr.patch_applicable is False
    assert rep_fpr.tpr_fpr_matrix.detector_metrics_applicable is False
    assert rep_fpr.tpr_fpr_matrix.false_positive_rate is None
    assert rep_fpr.tpr_fpr_matrix.valid_input_rejection_rate == 1.0

    # Non-listed extension resource file inside workspace `tests/` directory must also be staged,
    # while secrets (.env, .pem, credentials.json, .ssh/) MUST be excluded from staging and deliverables!
    from hermes_cyber.ack.workspace import stage_python_parser_workspace
    (git_dir / "tests").mkdir(exist_ok=True)
    (git_dir / "tests" / "fixture.custombin").write_bytes(b"\x01\x02\x03")
    (git_dir / ".env").write_text("SECRET_API_KEY=do_not_leak", encoding="utf-8")
    (git_dir / "private.pem").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    (git_dir / "credentials.json").write_text('{"token":"secret"}', encoding="utf-8")
    staged_with_test_asset = stage_python_parser_workspace(
        str(git_parser),
        "parse_packet",
        valid_corpus_dir=str(corpus_dir),
        workspace_mode="git_worktree",
    )
    try:
        assert "tests/fixture.custombin" in staged_with_test_asset.extra_files
        assert ".env" not in staged_with_test_asset.extra_files
        assert "private.pem" not in staged_with_test_asset.extra_files
        assert "credentials.json" not in staged_with_test_asset.extra_files
    finally:
        staged_with_test_asset.cleanup_staged_worktree()

    # Also verify unannotated `def parse(data): return data[0]` aligns recon/mutation input_kind == "str"
    plain_str_parser = tmp_path / "plain_str.py"
    plain_str_parser.write_text(
        "def parse(data):\n"
        "    return data[0]\n",
        encoding="utf-8",
    )
    rep_plain = kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(plain_str_parser),
        target_function="parse",
        valid_inputs=["alpha", "beta"],
        runs_dir=runs_dir,
    )
    assert rep_plain.patch_applicable is True
    recon_trace = next(t for t in rep_plain.subagent_traces if t.role == "RedReconSubAgent")
    assert "input=str" in recon_trace.summary

    # Failed staging after git_worktree creation must clean up temp worktree registration cleanly
    with pytest.raises(FileNotFoundError):
        stage_python_parser_workspace(
            str(git_parser),
            "parse_packet",
            valid_corpus_dir=str(tmp_path / "does_not_exist"),
            workspace_mode="git_worktree",
        )
    wt_list = subprocess.run(["git", "-C", str(git_dir), "worktree", "list", "--porcelain"], capture_output=True, text=True, check=True)
    assert wt_list.stdout.count("worktree ") == 1


def test_ack_apply_patch_confirmation_drift_backup_and_manifest_refresh(tmp_path: Path):
    default_kernel = AdversarialCyberKernel()
    recorded_confirm: List[Dict[str, Any]] = []
    kernel = AdversarialCyberKernel(
        human_confirm_fn=lambda ctx: (recorded_confirm.append(dict(ctx)), True)[1]
    )
    runs_dir = tmp_path / "runs"

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    parser_file = app_dir / "my_parser.py"
    parser_file.write_text(_BUGGY_PARSER_SOURCE, encoding="utf-8")
    orig_bytes = parser_file.read_bytes()

    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "valid.bin").write_bytes(b"\x00\x01\x00\x02AB")

    report = default_kernel.run_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(parser_file),
        target_function="parse_packet",
        valid_corpus_dir=str(corpus_dir),
        runs_dir=runs_dir,
    )
    assert report.patch_applicable is True
    assert report.patch_classification == "exception_containment_only"
    assert report.manual_review_required is True

    # Default kernel without interactive human confirmation MUST fail closed
    with pytest.raises(PermissionError, match="conferma interattiva umana"):
        default_kernel.issue_patch_approval(
            report.run_id,
            session_id="sess-human-1",
            expected_target_file_path=str(parser_file),
            acknowledge_manual_review=True,
            runs_dir=runs_dir,
        )

    # Deny without explicit confirmation OR without single-use session-bound approval token
    with pytest.raises(PermissionError):
        kernel.apply_patch(report.run_id, confirm_apply=False, runs_dir=runs_dir)
    with pytest.raises(PermissionError, match="approvazione umana monouso"):
        kernel.apply_patch(report.run_id, confirm_apply=True, runs_dir=runs_dir)

    # Issuing approval without acknowledging manual_review_required must fail closed
    with pytest.raises(PermissionError, match="Revisione manuale"):
        kernel.issue_patch_approval(report.run_id, session_id="sess-human-1", runs_dir=runs_dir)

    approval = kernel.issue_patch_approval(
        report.run_id,
        session_id="sess-human-1",
        expected_target_file_path=str(parser_file),
        acknowledge_manual_review=True,
        runs_dir=runs_dir,
    )
    assert len(recorded_confirm) == 1
    assert recorded_confirm[0]["run_id"] == report.run_id
    assert recorded_confirm[0]["target_file_path"] == str(parser_file.resolve())
    assert recorded_confirm[0]["original_sha256"] == _sha256_file(parser_file)
    assert recorded_confirm[0]["patch_diff_sha256"] == approval["patch_diff_sha256"]
    assert recorded_confirm[0]["patched_target_sha256"] == approval["patched_target_sha256"]
    tok = approval["approval_token"]

    # Reject path-traversal run_id and wrong-session / wrong-run token binding
    with pytest.raises(ValueError):
        kernel.apply_patch("../escape", confirm_apply=True, approval_token=tok, session_id="sess-human-1", runs_dir=runs_dir)
    with pytest.raises(PermissionError, match="Session mismatch"):
        kernel.apply_patch(report.run_id, confirm_apply=True, approval_token=tok, session_id="sess-hijack", runs_dir=runs_dir)

    # Reject if target file drifted on disk before confirmation
    parser_file.write_bytes(orig_bytes + b"\n# external edit\n")
    with pytest.raises(ValueError, match="Drift"):
        kernel.apply_patch(report.run_id, confirm_apply=True, approval_token=tok, session_id="sess-human-1", runs_dir=runs_dir)
    parser_file.write_bytes(orig_bytes)

    # Reject if patched_target snapshot drifted / was tampered with after run export
    patched_snap = Path(report.deliverable_dir) / "patched_target" / parser_file.name
    snap_orig = patched_snap.read_bytes()
    patched_snap.write_bytes(snap_orig + b"\n# tampered post-certification\n")
    with pytest.raises(ValueError, match="Integrità snapshot compromessa"):
        kernel.apply_patch(report.run_id, confirm_apply=True, approval_token=tok, session_id="sess-human-1", runs_dir=runs_dir)
    patched_snap.write_bytes(snap_orig)

    # Succeed ONCE on clean original file and verified snapshot with valid one-time session-bound token
    applied = kernel.apply_patch(
        report.run_id,
        confirm_apply=True,
        approval_token=tok,
        session_id="sess-human-1",
        runs_dir=runs_dir,
    )
    assert applied["patch_applied"] is True
    assert applied["approval_id"] == approval["approval_id"]
    backup_path = Path(applied["backup_path"])
    assert backup_path.is_file()
    assert backup_path.read_bytes() == orig_bytes
    assert parser_file.read_bytes() != orig_bytes

    # Replaying the exact same single-use approval token MUST fail
    parser_file.write_bytes(orig_bytes)
    with pytest.raises(PermissionError, match="già consumato"):
        kernel.apply_patch(report.run_id, confirm_apply=True, approval_token=tok, session_id="sess-human-1", runs_dir=runs_dir)
    parser_file.write_bytes((Path(report.deliverable_dir) / "patched_target" / parser_file.name).read_bytes())

    manifest = json.loads((Path(report.deliverable_dir) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["workspace_target"]["patch_applied"] is True
    assert manifest["workspace_target"]["approval_id"] == approval["approval_id"]
    rep_disk = Path(report.deliverable_dir) / "report.json"
    assert manifest["sha256"]["report.json"] == _sha256_file(rep_disk)

    # Workspace Mode without any valid corpus must fail closed and refuse approval & patch application
    empty_parser = tmp_path / "empty_corpus_parser.py"
    empty_parser.write_text(_BUGGY_PARSER_SOURCE, encoding="utf-8")
    for mode in ("structural", "naive_block_all"):
        rep_nocorpus = kernel.run_mission(
            "ack-m4-fuzz-to-fix-pipeline",
            mutation_rounds=1,
            defense_mode=mode,
            target_file_path=str(empty_parser),
            target_function="parse_packet",
            runs_dir=runs_dir,
        )
        assert rep_nocorpus.certified is False
        assert rep_nocorpus.patch_applicable is False
        assert rep_nocorpus.certification_verdict == "REJECTED_NO_VALID_CORPUS"
        with pytest.raises(ValueError, match="non applicabile"):
            kernel.issue_patch_approval(
                rep_nocorpus.run_id, session_id="sess-human-1", acknowledge_manual_review=True, runs_dir=runs_dir
            )
        with pytest.raises(PermissionError):
            kernel.apply_patch(rep_nocorpus.run_id, confirm_apply=True, runs_dir=runs_dir)

    # Recursive depth guard on patched recursive parser must stop cleanly at depth > 64 (not bypass wrapper)
    ns: Dict[str, Any] = {}
    exec(compile(parser_file.read_text(encoding="utf-8"), str(parser_file), "exec"), ns)
    deep_pkt = b"\x00\x01\x00\x02OK"
    for _ in range(70):
        deep_pkt = b"\xff\xff" + len(deep_pkt).to_bytes(2, "big") + deep_pkt
    with pytest.raises(ValueError, match="Maximum parser nesting depth exceeded"):
        ns["parse_packet"](deep_pkt)

    # Default argument side-effect evaluation must occur ONCE (only on wrapper, never twice)
    from hermes_cyber.ack.blue_subagents import _apply_deterministic_ast_parser_hardening
    src_with_default = (
        "INIT_CALLS = 0\n"
        "def make_cache():\n"
        "    global INIT_CALLS\n"
        "    INIT_CALLS += 1\n"
        "    return {}\n\n"
        "def parse_cached(data: bytes, cache=make_cache()) -> int:\n"
        "    return len(data) + len(cache)\n"
    )
    hardened_default = _apply_deterministic_ast_parser_hardening(src_with_default, "parse_cached", "bytes")
    default_ns: Dict[str, Any] = {}
    exec(compile(hardened_default, "<default_test>", "exec"), default_ns)
    assert default_ns["INIT_CALLS"] == 1
    assert default_ns["parse_cached"](b"abc") == 3
    assert default_ns["INIT_CALLS"] == 1


def test_ack_independent_red_blue_subagents_llm_integration_and_ast_safety_gate(tmp_path: Path):
    # AST safety gate checks (must reject dangerous imports AND any unrelated modification outside target_function)
    unsafe_patch = "import subprocess\ndef parse_packet(data: bytes) -> dict:\n    subprocess.run(['id'])\n    return {}\n"
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, unsafe_patch, "parse_packet") is False
    src_with_helper = _BUGGY_PARSER_SOURCE + "\nAUTH_ENABLED = True\n"
    altered_unrelated = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    if not data:\n        raise ValueError('bad')\n"
        "    return {'magic': 1}\n"
        "\nAUTH_ENABLED = False\n"
    )
    assert _is_llm_patch_ast_safe(src_with_helper, altered_unrelated, "parse_packet") is False
    sig_orig = "def parse_packet(data: bytes, strict: bool = False) -> dict:\n    return {}\n"
    sig_broken = "def parse_packet(data: bytes) -> dict:\n    return {}\n"
    assert _is_llm_patch_ast_safe(sig_orig, sig_broken, "parse_packet") is False
    io_patch = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    open('evil.txt', 'w').write('x')\n"
        "    return {'magic': 1}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, io_patch, "parse_packet") is False
    attr_escape = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    getattr(__builtins__, 'open')('evil.txt', 'w')\n"
        "    return {}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, attr_escape, "parse_packet") is False
    dunder_escape = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    return {'t': str(().__class__.__bases__)}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, dunder_escape, "parse_packet") is False
    new_import_patch = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    import io\n"
        "    return {'len': len(data)}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, new_import_patch, "parse_packet") is False
    # Sibling helper using `os.system` must NOT permit `target_function` to newly introduce `os.system`
    src_helper_sys = (
        "import os\n"
        "def unrelated_helper():\n"
        "    os.system('echo hi')\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    return {'n': data[0]}\n"
    )
    patch_adding_sys = (
        "import os\n"
        "def unrelated_helper():\n"
        "    os.system('echo hi')\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    os.system('whoami')\n"
        "    return {'n': data[0]}\n"
    )
    assert _is_llm_patch_ast_safe(src_helper_sys, patch_adding_sys, "parse_packet") is False
    # Indirect builtin subscript & aliased builtin code-exec escapes MUST be rejected
    indirect_exec = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    __builtins__['exec']('import os')\n"
        "    return {'n': data[0]}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, indirect_exec, "parse_packet") is False
    aliased_open = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    f = open\n"
        "    return {'f': bool(f)}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, aliased_open, "parse_packet") is False
    # Calling an unrelated sibling helper (or defining a decorated nested function) MUST also be rejected
    sibling_call = (
        "import os\n"
        "def unrelated_helper():\n"
        "    os.system('echo hi')\n\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    unrelated_helper()\n"
        "    return {'n': data[0]}\n"
    )
    assert _is_llm_patch_ast_safe(src_helper_sys, sibling_call, "parse_packet") is False
    decorated_nested = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    @eval\n"
        "    def _x():\n"
        "        return 1\n"
        "    return {'n': _x()}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, decorated_nested, "parse_packet") is False
    # Import swap + unused nested shadow def (`from os import system` + nested `def system(): pass`) MUST be rejected
    src_inner_import = "def parse_packet(data: bytes) -> dict:\n    import os\n    return {'n': data[0]}\n"
    patch_import_swap = (
        "def parse_packet(data: bytes) -> dict:\n"
        "    from os import system\n"
        "    def _unused():\n"
        "        def system(): pass\n"
        "    system('whoami')\n"
        "    return {'n': data[0]}\n"
    )
    assert _is_llm_patch_ast_safe(src_inner_import, patch_import_swap, "parse_packet") is False
    # Unsafe receiver method call (`os.replace` when `os` already in scope) MUST be rejected
    src_with_os = "import os\ndef parse_packet(data: bytes) -> dict:\n    return {'n': data[0]}\n"
    patch_os_replace = "import os\ndef parse_packet(data: bytes) -> dict:\n    os.replace('a', 'b')\n    return {'n': data[0]}\n"
    assert _is_llm_patch_ast_safe(src_with_os, patch_os_replace, "parse_packet") is False

    # Context-local profile scope resolution must keep default ACK runs strictly separated per profile (AGENTS.md:13)
    from hermes_cyber.ack.deliverables import resolve_ack_runs_dir
    from hermes_cyber.router_bridge import bind_cyber_profile_scope
    home_a = tmp_path / "profile_alpha"
    home_b = tmp_path / "profile_beta"
    home_a.mkdir()
    home_b.mkdir()
    with bind_cyber_profile_scope(home_dir=home_a, profile="alpha"):
        dir_a = resolve_ack_runs_dir()
        rep_a = AdversarialCyberKernel().run_mission("ack-m1-exploit-patch-bypass", mutation_rounds=1)
        assert Path(rep_a.deliverable_dir).is_relative_to(dir_a)
        assert Path(rep_a.deliverable_dir).is_relative_to(home_a.resolve())
    with bind_cyber_profile_scope(home_dir=home_b, profile="beta"):
        dir_b = resolve_ack_runs_dir()
        assert dir_a != dir_b
        assert AdversarialCyberKernel().list_runs() == []

    # JSON corpus file for a `str`-typed parser must stay raw str text (not parsed into dict)
    from hermes_cyber.ack.workspace import _build_valid_corpus_entries
    json_str_dir = tmp_path / "json_str_corpus"
    json_str_dir.mkdir()
    (json_str_dir / "cfg.json").write_text('{"k": 1}', encoding="utf-8")
    str_entries, _ = _build_valid_corpus_entries(param_type_hint="str", valid_corpus_dir=str(json_str_dir), valid_inputs=None)
    assert isinstance(str_entries[0]["data"], str) and str_entries[0]["data"] == '{"k": 1}'
    dict_entries, _ = _build_valid_corpus_entries(param_type_hint="dict", valid_corpus_dir=str(json_str_dir), valid_inputs=None)
    assert dict_entries[0]["data"] == {"k": 1}
    safe_patch = (
        "import struct\n"
        "def parse_packet(data: bytes) -> dict:\n"
        "    if not isinstance(data, (bytes, bytearray)) or len(data) < 4:\n"
        "        raise ValueError('short packet')\n"
        "    magic, length = struct.unpack('>HH', data[:4])\n"
        "    if length == 0 or 4 + length > len(data):\n"
        "        raise ValueError('bad bounds')\n"
        "    body = data[4 : 4 + length]\n"
        "    return {'magic': magic, 'body_len': len(body), 'first': body[0]}\n"
    )
    assert _is_llm_patch_ast_safe(_BUGGY_PARSER_SOURCE, safe_patch, "parse_packet") is True

    app_dir = tmp_path / "llm_app"
    app_dir.mkdir()
    parser_file = app_dir / "pkt_parser.py"
    parser_file.write_text(_BUGGY_PARSER_SOURCE, encoding="utf-8")
    corpus_dir = tmp_path / "llm_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "ok.bin").write_bytes(b"\x00\x01\x00\x02hi")

    # Arena integration with use_llm=True + Fog of War isolation + AST fallback when Blue proposes unsafe code
    assistant = CyberPurpleAssistant(profile="ack_llm_test", home_dir=tmp_path, use_llm=True)
    red_mock = _FakeLLMRouter(
        "ollama",
        "red-test-model",
        [
            json.dumps({"hypothesis": "short hdr", "extra_hex_inputs": ["0001"], "extra_str_inputs": []}),
            json.dumps({"attack_class": "CLASS_LLM_CUSTOM_MUT", "hex_payloads": ["00010010", "ffff0004ffff0004"]}),
        ],
    )
    blue_mock = _FakeLLMRouter(
        "ollama",
        "blue-test-model",
        [json.dumps({"patched_source": unsafe_patch, "summary": "unsafe attempt"})],
    )
    assistant.red_router = red_mock  # type: ignore[assignment]
    assistant.blue_router = blue_mock  # type: ignore[assignment]

    rep = assistant.run_ack_mission(
        "ack-m4-fuzz-to-fix-pipeline",
        mutation_rounds=2,
        target_file_path=str(parser_file),
        target_function="parse_packet",
        valid_corpus_dir=str(corpus_dir),
    )
    assert rep.patch_applicable is True
    assert rep.patch_classification == "exception_containment_only"
    assert rep.certification_verdict == "CONTAINED_WORKSPACE_PARSER_EXCEPTIONS"
    assert rep.subagent_execution_architecture == "llm_guided_role_pipeline"
    assert FogOfWarController().verify_trace_isolation(rep.subagent_traces) is True
    assert len(red_mock.calls) >= 2
    assert len(blue_mock.calls) == 1
    assert any(tr.team == "RED" and tr.model_used == "ollama:red-test-model" for tr in rep.subagent_traces)
    assert any(tr.team == "BLUE" and "fallback_ast_guard" in tr.model_used for tr in rep.subagent_traces)

    # Fog of War verification: Red prompt never sees Blue corpus/rules; Blue prompt never sees Red mutation plan
    for rc in red_mock.calls:
        assert "benign_baseline_corpus" not in rc["prompt"]
        assert "blue_rules" not in rc["prompt"]
    for bc in blue_mock.calls:
        assert "failed_attack_classes" not in bc["prompt"]
        assert "red_mutation_plan" not in bc["prompt"]


def test_ack_runs_dir_strict_profile_isolation_and_explicit_runs_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import tempfile
    from hermes_constants import get_hermes_home
    from hermes_cyber.ack.deliverables import resolve_ack_runs_dir
    from hermes_cyber.router_bridge import bind_cyber_profile_scope

    fake_user_home = tmp_path / "user_home"
    fake_temp = tmp_path / "os_temp"
    legacy_runs_root = fake_temp / "NOEMETRA" / "runs"
    legacy_run = legacy_runs_root / "ack-run-legacy1"
    legacy_run.mkdir(parents=True)
    (legacy_run / "report.json").write_text(json.dumps({"run_id": "ack-run-legacy1", "deliverable_dir": str(legacy_run)}), encoding="utf-8")
    (legacy_run / "manifest.json").write_text(json.dumps({"run_id": "ack-run-legacy1", "exported_at": "2026-11-20T00:00:00Z", "sha256": {}}), encoding="utf-8")

    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(fake_user_home / "AppData" / "Local"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_temp))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_user_home))

    profile_a = tmp_path / "profile_a"
    profile_b = tmp_path / "profile_b"
    profile_a.mkdir()
    profile_b.mkdir()
    with bind_cyber_profile_scope(home_dir=profile_a, profile="alpha"):
        dir_a = resolve_ack_runs_dir()
        assert dir_a == (profile_a.resolve() / "NOEMETRA" / "runs").resolve()
        assert AdversarialCyberKernel().list_runs() == []
    with bind_cyber_profile_scope(home_dir=profile_b, profile="beta"):
        dir_b = resolve_ack_runs_dir()
        assert dir_b == (profile_b.resolve() / "NOEMETRA" / "runs").resolve()
        assert dir_b != dir_a
        assert AdversarialCyberKernel().list_runs() == []

    # Unscoped temp runs carry no profile ownership and are never auto-migrated into default home
    expected_default_home = get_hermes_home().resolve()
    expected_default_runs = (expected_default_home / "NOEMETRA" / "runs").resolve()
    assert expected_default_runs.is_relative_to(fake_user_home.resolve())
    assert resolve_ack_runs_dir() == expected_default_runs
    assert AdversarialCyberKernel().list_runs() == []
    assert legacy_run.is_dir()

    # Callers needing to inspect an explicit non-profile runs dir can pass runs_dir=...
    explicit_runs = AdversarialCyberKernel().list_runs(runs_dir=legacy_runs_root)
    assert any(r.get("run_id") == "ack-run-legacy1" for r in explicit_runs)


def test_ack_rest_api_runs_apply_patch_tool_and_ui_exposure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    recorded_prompts: List[Dict[str, Any]] = []
    confirm_state = {"decision": True, "mutate_toctou": False}

    parser_file = tmp_path / "api_parser.py"
    parser_file.write_text(_BUGGY_PARSER_SOURCE, encoding="utf-8")
    orig_api_bytes = parser_file.read_bytes()
    corpus_dir = tmp_path / "api_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "valid.bin").write_bytes(b"\x00\x01\x00\x02ZZ")

    def _human_confirm(ctx: Dict[str, Any]) -> bool:
        recorded_prompts.append(dict(ctx))
        if confirm_state["mutate_toctou"]:
            parser_file.write_bytes(orig_api_bytes + b"\n# toctou drift during human dialog\n")
        return bool(confirm_state["decision"])

    default_assistant = CyberPurpleAssistant(profile="ack_api_default", home_dir=tmp_path, use_llm=False)
    assistant = CyberPurpleAssistant(
        profile="ack_api_test",
        home_dir=tmp_path,
        use_llm=False,
        ack_human_confirm_fn=_human_confirm,
    )
    current_principal: Dict[str, Any] = {"native": {"profile_id": "opA"}, "hosted": None}
    current_assistant_ref = {"obj": default_assistant}
    monkeypatch.setattr(cyber_api, "_resolve_authorized_context", lambda _req: ("ack_api_test", tmp_path))
    monkeypatch.setattr(cyber_api, "_req_assistant", lambda _req: current_assistant_ref["obj"])

    app = FastAPI()

    @app.middleware("http")
    async def _inject_test_principal(request, call_next):
        if current_principal["native"] is not None:
            request.state.native_http_principal = current_principal["native"]
        if current_principal["hosted"] is not None:
            request.state.hosted_http_authenticated = current_principal["hosted"]
        return await call_next(request)

    app.include_router(cyber_router, prefix="/api/plugins/cyber-purple-suite")
    client = TestClient(app)

    # Default fail-closed assistant: an automated client reading /status + sending legacy "human-approval" MUST get 403
    def_status = client.get("/api/plugins/cyber-purple-suite/status")
    assert def_status.status_code == 200
    def_sess_id = def_status.json()["ack_session_id"]
    def_run = client.post(
        "/api/plugins/cyber-purple-suite/ack/run",
        json={
            "mission_id": "ack-m4-fuzz-to-fix-pipeline",
            "mutation_rounds": 1,
            "target_file_path": str(parser_file),
            "target_function": "parse_packet",
            "valid_corpus_dir": str(corpus_dir),
            "workspace_mode": "isolated_copy",
        },
    )
    assert def_run.status_code == 200
    r_forged = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        headers={"X-Noemetra-Operator-Confirm": "human-approval"},
        json={
            "run_id": def_run.json()["run_id"],
            "target_file_path": str(parser_file),
            "session_id": def_sess_id,
            "acknowledge_manual_review": True,
            "operator_confirm": "human-approval",
        },
    )
    assert r_forged.status_code == 403

    # Default OS confirm gate fails closed under pytest AND for remote clients, and HTTP seam rejects hosted=False
    assert prompt_interactive_operator_confirmation({"run_id": "r1"}) is False
    assert prompt_interactive_operator_confirmation({"run_id": "r1", "remote_client": True}) is False
    current_principal["native"] = None
    current_principal["hosted"] = False
    r_unauth = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        json={"run_id": def_run.json()["run_id"], "target_file_path": str(parser_file), "session_id": def_sess_id, "acknowledge_manual_review": True},
    )
    assert r_unauth.status_code == 401

    # Switch to interactive-human-confirm test assistant and principal opA
    current_principal["hosted"] = None
    current_principal["native"] = {"profile_id": "opA"}
    current_assistant_ref["obj"] = assistant

    r_status = client.get("/api/plugins/cyber-purple-suite/status")
    assert r_status.status_code == 200
    sess_id = r_status.json()["ack_session_id"]

    # Tool status must NOT leak ack_session_id to the LLM agent
    monkeypatch.setattr("cyber_hermes_plugin.cyber_plugin._get_cyber_assistant", lambda: assistant)
    tool_status = json.loads(cyber_get_status())
    assert "ack_session_id" not in tool_status

    r_run = client.post(
        "/api/plugins/cyber-purple-suite/ack/run",
        json={
            "mission_id": "ack-m4-fuzz-to-fix-pipeline",
            "mutation_rounds": 2,
            "target_file_path": str(parser_file),
            "target_function": "parse_packet",
            "valid_corpus_dir": str(corpus_dir),
            "workspace_mode": "isolated_copy",
        },
    )
    assert r_run.status_code == 200
    body = r_run.json()
    assert body["patch_applicable"] is True
    assert body["patch_classification"] == "exception_containment_only"
    assert body["certification_verdict"] == "CONTAINED_WORKSPACE_PARSER_EXCEPTIONS"
    run_id = body["run_id"]

    r_runs = client.get("/api/plugins/cyber-purple-suite/ack/runs")
    assert r_runs.status_code == 200
    assert any(item["run_id"] == run_id for item in r_runs.json()["runs"])

    r_deny = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-patch",
        json={"run_id": run_id, "confirm_apply": True},
    )
    assert r_deny.status_code == 403

    r_wrong_sess = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        json={
            "run_id": run_id,
            "target_file_path": str(parser_file),
            "session_id": "wrong-sess",
            "acknowledge_manual_review": True,
        },
    )
    assert r_wrong_sess.status_code == 403

    # Human operator clicks "No" -> 403
    confirm_state["decision"] = False
    r_human_deny = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        json={
            "run_id": run_id,
            "target_file_path": str(parser_file),
            "session_id": sess_id,
            "acknowledge_manual_review": True,
        },
    )
    assert r_human_deny.status_code == 403

    # TOCTOU drift during human confirmation -> aborted without minting a token, file restored after
    confirm_state["decision"] = True
    confirm_state["mutate_toctou"] = True
    r_toctou = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        json={
            "run_id": run_id,
            "target_file_path": str(parser_file),
            "session_id": sess_id,
            "acknowledge_manual_review": True,
        },
    )
    assert r_toctou.status_code in (400, 403)
    assert "approval_token" not in r_toctou.json()
    confirm_state["mutate_toctou"] = False
    parser_file.write_bytes(orig_api_bytes)

    r_appr = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-approval",
        json={
            "run_id": run_id,
            "target_file_path": str(parser_file),
            "session_id": sess_id,
            "acknowledge_manual_review": True,
        },
    )
    assert r_appr.status_code == 200
    tok = r_appr.json()["approval_token"]

    # Principal mismatch: token minted under opA MUST fail when applied by opB
    current_principal["native"] = {"profile_id": "opB"}
    r_wrong_principal = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-patch",
        json={"run_id": run_id, "confirm_apply": True, "approval_token": tok, "session_id": sess_id},
    )
    assert r_wrong_principal.status_code == 403
    current_principal["native"] = {"profile_id": "opA"}

    parser_file.write_bytes(orig_api_bytes)
    r_apply = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-patch",
        json={"run_id": run_id, "confirm_apply": True, "approval_token": tok, "session_id": sess_id},
    )
    assert r_apply.status_code == 200
    assert r_apply.json()["patch_applied"] is True
    assert r_apply.json()["approval_id"] == r_appr.json()["approval_id"]

    # Replay must be refused both after patch drift (400/403) and even if original bytes are restored (403 consumed)
    r_replay_drift = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-patch",
        json={"run_id": run_id, "confirm_apply": True, "approval_token": tok, "session_id": sess_id},
    )
    assert r_replay_drift.status_code in (400, 403)
    patched_bytes_on_disk = parser_file.read_bytes()
    parser_file.write_bytes(orig_api_bytes)
    r_replay_consumed = client.post(
        "/api/plugins/cyber-purple-suite/ack/apply-patch",
        json={"run_id": run_id, "confirm_apply": True, "approval_token": tok, "session_id": sess_id},
    )
    assert r_replay_consumed.status_code == 403
    parser_file.write_bytes(patched_bytes_on_disk)

    # Hermes tool registration: confirm_apply=True alone without human approval_token MUST fail, no minting tool exposed
    tool_names = [t["name"] for t in TOOLS]
    assert "cyber_apply_ack_patch" in tool_names
    assert not any("approval" in n for n in tool_names)
    tool_err = json.loads(cyber_apply_ack_patch({"run_id": run_id, "confirm_apply": True}))
    assert "error" in tool_err

    # Desktop & Web UI sync + feature parity markers (and removal of spoofable human-approval strings)
    suite_root = Path(__file__).resolve().parents[1]
    repo_root = suite_root.parents[1]
    desk = (suite_root / "desktop" / "plugin.js").read_text(encoding="utf-8")
    app_js = (repo_root / "apps" / "desktop" / "src" / "plugins" / "cyber-purple-suite" / "plugin.js").read_text(encoding="utf-8")
    web_html = (suite_root / "hermes_cyber" / "server" / "static" / "index.html").read_text(encoding="utf-8")

    assert desk == app_js
    for forbidden in ("human-approval", "X-Noemetra-Operator-Confirm"):
        assert forbidden not in desk
        assert forbidden not in web_html
    for marker in (
        "/ack/run",
        "/ack/apply-approval",
        "/ack/apply-patch",
        "ack_session_id",
        "target_config_content",
        "target_file_path",
        "target_function",
        "valid_corpus_dir",
        "workspace_mode",
        "verification_tier",
        "security_boundary_level",
        "untrusted_llm_code_warning",
        "patch_classification",
        "manual_review_required",
        "subagent_execution_architecture",
        "metric_kind",
        "crash_mitigation_rate",
        "valid_input_rejection_rate",
        "semantic_assertion_pass_rate",
        "subagent_traces",
        "executed_checks",
        "not_executed_checks",
        "patch_diff",
        "deliverable_dir",
    ):
        assert marker in desk, f"Missing UI marker {marker!r} in desktop plugin.js"
        assert marker in web_html, f"Missing UI marker {marker!r} in web index.html"
