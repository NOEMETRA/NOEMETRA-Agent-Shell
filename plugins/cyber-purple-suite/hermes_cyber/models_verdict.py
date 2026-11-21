"""Replay, diagnosis/simulation/remediation summaries, verdict, and benchmark contracts."""

from __future__ import annotations

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from hermes_cyber.models_claims import (
    ArtifactIngestionResult,
    BlueInvestigationReport,
    RedOperationPlan,
    VerdictType,
)


class ReplayEventResult(BaseModel):
    """Per-event outcome from running Blue Sigma/YARA defenses against Red & benign events."""

    event_id: str
    variant: Literal["real_threat", "baseline_attack", "evasion_variant", "benign_baseline"]
    matched_sigma: bool
    matched_yara: bool
    matched_keywords: List[str] = Field(default_factory=list)


class PurpleReplayReport(BaseModel):
    """Quantitative adversarial test measuring detection coverage and false positive rate."""

    attack_events_total: int = 0
    attack_events_detected: int = 0
    evasion_events_total: int = 0
    evasion_events_detected: int = 0
    benign_events_tested: int = 0
    false_positives_count: int = 0
    detection_coverage: float = 0.0
    evasion_caught_rate: float = 0.0
    false_positive_rate: float = 0.0
    event_results: List[ReplayEventResult] = Field(default_factory=list)
    defense_gaps: List[str] = Field(default_factory=list)


class DiagnosisSummary(BaseModel):
    """Explicit separation of clinical/forensic diagnosis from simulation and patch verification."""

    status: Literal["CONFIRMED_THREAT", "REFUTED_FALSE_POSITIVE", "OPEN_HYPOTHESIS", "NO_THREAT_EVIDENCE"] = "OPEN_HYPOTHESIS"
    analysis_mode: Literal["event_investigation", "artifact_review", "hybrid_investigation"] = "event_investigation"
    analysis_mode_label: str = "Indagine su Eventi (Log / Telemetria)"
    epistemic_scope: str = ""
    supported_claims_count: int = 0
    open_claims_count: int = 0
    refuted_claims_count: int = 0
    supported_claim_ids: List[str] = Field(default_factory=list)
    open_claim_ids: List[str] = Field(default_factory=list)
    refuted_claim_ids: List[str] = Field(default_factory=list)
    high_priority_open_claim_ids: List[str] = Field(default_factory=list)
    priority_breakdown: Dict[str, int] = Field(default_factory=dict)
    missing_conditions_summary: List[str] = Field(default_factory=list)
    next_required_proofs: List[str] = Field(default_factory=list)
    summary: str = ""


class SimulationSummary(BaseModel):
    """Detection simulation stage outcome evaluating rules against synthetic attacks and baselines."""

    status: Literal["COVERAGE_COMPLETE", "COVERAGE_PARTIAL", "FALSE_POSITIVE_RISK", "NOT_APPLICABLE"] = "NOT_APPLICABLE"
    detection_coverage: float = 0.0
    evasion_caught_rate: float = 0.0
    false_positive_rate: float = 0.0
    summary: str = ""


class RemediationVerificationSummary(BaseModel):
    """Post-remediation or incremental evidence update verification state."""

    status: Literal["UNVERIFIED", "VERIFIED_FIXED", "PARTIALLY_MITIGATED", "STILL_VULNERABLE", "EVIDENCE_UPDATED"] = "UNVERIFIED"
    verification_level: Literal["not_run", "static_artifact_comparison", "incremental_evidence_reanalysis"] = "not_run"
    verified_at: Optional[str] = None
    verification_source: str = ""
    added_evidence_ids: List[str] = Field(default_factory=list)
    resolved_claim_ids: List[str] = Field(default_factory=list)
    remaining_open_claim_ids: List[str] = Field(default_factory=list)
    before_verdict: Optional[VerdictType] = None
    after_verdict: Optional[VerdictType] = None
    operational_caveat: str = ""
    summary: str = "Pending post-remediation check or additional evidence submission."


class PurpleVerdict(BaseModel):
    """Final deterministic arbitration combining citation verification, contradictions, and replay."""

    verdict: VerdictType
    winning_hypothesis: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    hypothesis_a_support: float = Field(ge=0.0, le=1.0)
    hypothesis_b_support: float = Field(ge=0.0, le=1.0)
    verified_citations: List[str] = Field(default_factory=list)
    hallucinated_citations_removed: List[str] = Field(default_factory=list)
    incoherent_contradictions_rejected: List[str] = Field(default_factory=list)
    discriminating_test: str
    rationale: str
    replay: PurpleReplayReport
    diagnosis: DiagnosisSummary = Field(default_factory=DiagnosisSummary)
    simulation: SimulationSummary = Field(default_factory=SimulationSummary)
    remediation_verification: RemediationVerificationSummary = Field(default_factory=RemediationVerificationSummary)


class CyberAnalysisReport(BaseModel):
    """Complete end-to-end Purple Team analysis report."""

    case_id: str
    title: str
    created_at: str
    scenario_id: Optional[str] = None
    ingestion: ArtifactIngestionResult
    red_report: RedOperationPlan
    blue_report: BlueInvestigationReport
    verdict: PurpleVerdict
    privacy_scrubbed: bool = False
    scrub_stats: Dict[str, int] = Field(default_factory=dict)


class ScenarioDescriptor(BaseModel):
    """Summary metadata for a built-in dialectical scenario."""

    scenario_id: str
    title: str
    category: str
    description: str
    expected_verdict: VerdictType
    is_ambiguous: bool = False
    source_kind: str = "log"


class BenchmarkCaseResult(BaseModel):
    """Single scenario outcome comparing Single-Agent baseline vs Multi-Agent Purple Suite."""

    scenario_id: str
    title: str
    expected_verdict: VerdictType
    single_agent_verdict: VerdictType
    purple_multi_agent_verdict: VerdictType
    single_agent_correct: bool
    purple_correct: bool
    contradictions_found: int
    detection_coverage: float
    false_positive_rate: float


class BenchmarkComparisonReport(BaseModel):
    """Aggregated comparative metrics proving Multi-Agent Purple dialectics superiority."""

    total_scenarios: int
    single_agent_accuracy: float
    purple_multi_agent_accuracy: float
    single_agent_fpr: float
    purple_fpr: float
    contradiction_recall: float
    abstention_accuracy: float
    avg_detection_coverage: float
    results: List[BenchmarkCaseResult] = Field(default_factory=list)
