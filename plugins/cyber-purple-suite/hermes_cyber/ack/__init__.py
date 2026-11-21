"""Modular NOEMETRA Adversarial Cyber Kernel (ACK) subpackage."""

from __future__ import annotations

from hermes_cyber.ack.approval import (
    AckPatchApprovalManager,
    apply_ack_run_patch,
    verify_run_patch_integrity,
)
from hermes_cyber.ack.ast_safety import (
    AstPatchAuditResult,
    audit_llm_patch_ast,
    inspect_function_sensitive_ops,
)
from hermes_cyber.ack.blue_subagents import (
    BluePatchArchitectSubAgent,
    BlueRegressionSubAgent,
    BlueTriageSubAgent,
)
from hermes_cyber.ack.catalog import (
    ACK_MISSIONS,
    ACK_MISSION_MAP,
    list_ack_mission_descriptors,
)
from hermes_cyber.ack.chamber import DetonationChamber, _create_win32_job_object
from hermes_cyber.ack.deliverables import (
    export_ack_deliverables,
    list_ack_runs,
    resolve_ack_runs_dir,
)
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.kernel import AdversarialCyberKernel
from hermes_cyber.ack.manifest_parser import _parse_target_host_config
from hermes_cyber.ack.manifest_patcher import (
    _harden_manifest_text,
    _validate_hardened_manifest_syntax,
)
from hermes_cyber.ack.operator_confirm import prompt_interactive_operator_confirmation
from hermes_cyber.ack.red_subagents import (
    RedBypassMutatorSubAgent,
    RedReconSubAgent,
    RedWeaponizerSubAgent,
)
from hermes_cyber.ack.workspace import (
    AckSemanticTestCase,
    compute_unified_diff,
    stage_python_parser_workspace,
)
from hermes_cyber.ack.yaml_compat import _yaml_safe_dump_compat, _yaml_safe_load_compat

__all__ = [
    "ACK_MISSIONS",
    "ACK_MISSION_MAP",
    "AckPatchApprovalManager",
    "AckSemanticTestCase",
    "AdversarialCyberKernel",
    "AstPatchAuditResult",
    "BluePatchArchitectSubAgent",
    "BlueRegressionSubAgent",
    "BlueTriageSubAgent",
    "DetonationChamber",
    "FogOfWarController",
    "RedBypassMutatorSubAgent",
    "RedReconSubAgent",
    "RedWeaponizerSubAgent",
    "_create_win32_job_object",
    "_harden_manifest_text",
    "_parse_target_host_config",
    "_validate_hardened_manifest_syntax",
    "_yaml_safe_dump_compat",
    "_yaml_safe_load_compat",
    "apply_ack_run_patch",
    "audit_llm_patch_ast",
    "compute_unified_diff",
    "export_ack_deliverables",
    "inspect_function_sensitive_ops",
    "list_ack_mission_descriptors",
    "list_ack_runs",
    "prompt_interactive_operator_confirmation",
    "resolve_ack_runs_dir",
    "stage_python_parser_workspace",
    "verify_run_patch_integrity",
]
