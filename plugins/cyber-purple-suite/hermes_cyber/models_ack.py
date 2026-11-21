"""NOEMETRA Adversarial Cyber Kernel (ACK) typed execution and oracle contracts."""

from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

AckStateType = Literal[
    "INIT_ARENA",
    "RED_WEAPONIZE",
    "ORACLE_BASELINE_CHECK",
    "BLUE_DEFEND",
    "ORACLE_FUNCTIONAL_AND_FPR_CHECK",
    "RED_MUTATE_BYPASS",
    "CERTIFY_REPORT",
]

AckPrimitiveType = Literal[
    "EXEC_ARTIFACT",
    "APPLY_DIFF",
    "DEPLOY_RULE",
    "RUN_FUZZER",
    "CAPTURE_TELEMETRY",
]

AckOracleVerdictType = Literal[
    "INVARIANT_BREACHED_STEALTH",
    "INVARIANT_BREACHED_DETECTED",
    "DEFENSE_HELD_CLEAN",
    "DEFENSE_REJECTED_BROKEN_FUNC",
    "DEFENSE_REJECTED_HIGH_FPR",
    "EXECUTION_ERROR",
]

AckDefenseModeType = Literal[
    "structural",
    "naive_string_replace",
    "naive_block_all",
    "overbroad_alert_all",
]

AckMissionKind = Literal[
    "exploit_to_patch_loop",
    "detection_vs_evasion_arena",
    "attack_path_hardening",
    "fuzz_to_fix_pipeline",
]

AckVerificationTierType = Literal[
    "lab_fixture_verification",
    "workspace_target_verification",
    "runtime_sandbox_certified",
]

AckSecurityBoundaryType = Literal[
    "process_confinement_not_untrusted_sandbox",
    "container_sandbox",
]

AckWorkspaceModeType = Literal["isolated_copy", "git_worktree"]


class ActionExecutionLimits(BaseModel):
    """Strict resource and network confinement bounds inside the Detonation Chamber."""

    timeout_sec: int = Field(default=15, ge=1, le=120)
    max_procs: int = Field(default=1, ge=1, le=256)
    network_mode: Literal["isolated_veth", "loopback_only", "none"] = "isolated_veth"


class ConstrainedActionContract(BaseModel):
    """Typed execution contract emitted by Red/Blue and validated by the runtime before execution."""

    action_id: str
    actor: Literal["RED", "BLUE"]
    phase: AckStateType
    sandbox_id: str
    primitive: AckPrimitiveType
    artifact_path: str
    entrypoint: List[str] = Field(default_factory=list)
    limits: ActionExecutionLimits = Field(default_factory=ActionExecutionLimits)
    target_invariant: str
    attack_class: str = ""


class FsDiffEvidence(BaseModel):
    """Out-of-band Copy-on-Write upperdir filesystem diff and lowerdir integrity check."""

    created: List[str] = Field(default_factory=list)
    modified: List[str] = Field(default_factory=list)
    deleted: List[str] = Field(default_factory=list)
    canary_accessed: bool = False
    lowerdir_untouched: bool = True


class NetEventEvidence(BaseModel):
    """Out-of-band virtual interface / loopback network observation."""

    dst: str
    proto: str = "tcp"
    bytes_out: int = 0
    bytes_in: int = 0
    blocked: bool = False


class TelemetryAlertEvidence(BaseModel):
    """Independent out-of-band rule/telemetry trigger observation."""

    rule_id: str
    engine: str = "python_rule_engine"
    triggered: bool = False
    matched_pattern: str = ""


class OutOfBandOracleEvidence(BaseModel):
    """Immutable out-of-band evidence produced by the Control Plane oracle (never editable by LLMs)."""

    action_id: str
    exit_code: int
    fs_diff: FsDiffEvidence = Field(default_factory=FsDiffEvidence)
    net_events: List[NetEventEvidence] = Field(default_factory=list)
    telemetry_alerts: List[TelemetryAlertEvidence] = Field(default_factory=list)
    functional_suite_passed: Optional[bool] = None
    fpr_value: Optional[float] = None
    crash_reproduced: bool = False
    execution_valid: bool = True
    attempts_executed: int = 0
    isolation_backend: str = "confined_supervisor_audit_hook"
    oracle_verdict: AckOracleVerdictType


class FogOfWarAudit(BaseModel):
    """Verification record ensuring asymmetrical Red/Blue contexts and forced attack-class switches."""

    enforced: bool = True
    blue_rules_hidden_from_red: bool = True
    red_mutation_logic_hidden_from_blue: bool = True
    red_visible_keys: List[str] = Field(default_factory=list)
    blue_visible_keys: List[str] = Field(default_factory=list)
    failed_attack_classes_memory: List[str] = Field(default_factory=list)


class AckTprFprMatrix(BaseModel):
    """Empirical detection, evasion-resistance, and functional-survival scorecard."""

    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    max_allowed_fpr: float = 0.05
    evasion_resistance_rate: float = 0.0
    functional_survival_rate: float = 0.0
    pre_patch_breach_confirmed: bool = False
    post_patch_breaches: int = 0
    fpr_measured: bool = False
    benign_corpus_size: int = 0
    attack_variants_tested: int = 0


class AckMutationRoundResult(BaseModel):
    """Outcome of one Red bypass mutation round after changing attack class."""

    round_index: int
    attack_class: str
    previous_failed_classes: List[str] = Field(default_factory=list)
    contract: ConstrainedActionContract
    oracle_evidence: OutOfBandOracleEvidence
    execution_valid: bool = True
    attempts_executed: int = 0
    bypass_succeeded: bool = False


class AckStateTransition(BaseModel):
    """Typed transition log for the deterministic 7-state ACK verification machine."""

    state: AckStateType
    actor: str
    summary: str
    passed: bool = True


class AckSubAgentTrace(BaseModel):
    """Trace record emitted by an independent Red or Blue sub-agent role under Fog of War."""

    team: Literal["RED", "BLUE"]
    role: str
    phase: AckStateType
    model_used: str = "deterministic"
    visible_context_keys: List[str] = Field(default_factory=list)
    summary: str
    artifacts: List[str] = Field(default_factory=list)


class AckWorkspaceTargetInfo(BaseModel):
    """Provenance and drift-verification metadata for an ACK Workspace Mode target file."""

    target_file_path: str
    target_function: str
    target_rel_path: Optional[str] = None
    workspace_mode: AckWorkspaceModeType = "isolated_copy"
    original_sha256: str
    original_untouched: bool = True
    valid_corpus_count: int = 0
    patch_applied: bool = False
    applied_at: Optional[str] = None


class AckMissionDescriptor(BaseModel):
    """Catalog metadata for the 4 pure-cyber Adversarial Cyber Kernel missions."""

    mission_id: str
    mission_kind: AckMissionKind
    title: str
    target_invariant: str
    description: str
    default_tier: str = "tier1_cow_arena"
    shadow_clone_only: bool = False


class AckCertificationReport(BaseModel):
    """Complete out-of-band verified Adversarial Cyber Kernel mission report."""

    run_id: str
    mission_id: str
    mission_kind: AckMissionKind
    title: str
    sandbox_id: str
    tier_used: str = "tier1_cow_arena"
    shadow_clone_only: bool = False
    audit_scope: Literal[
        "synthetic_fixture_simulation",
        "cloned_target_manifest",
        "workspace_target_file",
    ] = "synthetic_fixture_simulation"
    verification_tier: AckVerificationTierType = "lab_fixture_verification"
    security_boundary_level: AckSecurityBoundaryType = "process_confinement_not_untrusted_sandbox"
    untrusted_llm_code_warning: str = (
        "Process confinement + Python audit hooks protect controlled lab harnesses only; "
        "do not rely on this boundary to run arbitrary untrusted LLM code on the host."
    )
    isolation_backend: str = "confined_supervisor_audit_hook"
    defense_mode: str = "structural"
    target_invariant: str
    certified: bool
    certification_verdict: str
    executed_checks: List[str] = Field(default_factory=list)
    not_executed_checks: List[str] = Field(default_factory=list)
    state_transitions: List[AckStateTransition] = Field(default_factory=list)
    subagent_traces: List[AckSubAgentTrace] = Field(default_factory=list)
    action_contracts: List[ConstrainedActionContract] = Field(default_factory=list)
    oracle_evidences: List[OutOfBandOracleEvidence] = Field(default_factory=list)
    mutation_rounds: List[AckMutationRoundResult] = Field(default_factory=list)
    tpr_fpr_matrix: AckTprFprMatrix
    fog_of_war: FogOfWarAudit
    blue_patch_or_rules_summary: str = ""
    rationale: str = ""
    deliverable_dir: Optional[str] = None
    deliverable_files: List[str] = Field(default_factory=list)
    patch_diff: str = ""
    workspace_target: Optional[AckWorkspaceTargetInfo] = None
