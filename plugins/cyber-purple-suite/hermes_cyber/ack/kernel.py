"""AdversarialCyberKernel orchestrating ACK missions inside DetonationChamber + Fog of War."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from hermes_cyber.ack.approval import AckPatchApprovalManager, apply_ack_run_patch
from hermes_cyber.ack.catalog import (
    ACK_MISSION_MAP,
    _MissionExecutionOutcome,
    list_ack_mission_descriptors,
)
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.deliverables import (
    export_ack_deliverables,
    list_ack_runs,
    resolve_ack_runs_dir,
)
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.mission_m1_appsec import _run_m1_exploit_to_patch
from hermes_cyber.ack.mission_m2_evasion import _run_m2_detection_evasion
from hermes_cyber.ack.mission_m3_hardening import _run_m3_attack_path_hardening
from hermes_cyber.ack.mission_m4_fuzzing import _run_m4_fuzz_to_fix
from hermes_cyber.models import (
    AckCertificationReport,
    AckMissionDescriptor,
    AckStateTransition,
    AckSubAgentArchitectureType,
    AckWorkspaceModeType,
)
from hermes_cyber.router_bridge import ModelRouter

_MISSION_RUNNERS: Dict[
    str,
    Callable[..., _MissionExecutionOutcome],
] = {
    "ack-m1-exploit-patch-bypass": _run_m1_exploit_to_patch,
    "ack-m2-detection-evasion-arena": _run_m2_detection_evasion,
    "ack-m3-attack-path-hardening": _run_m3_attack_path_hardening,
    "ack-m4-fuzz-to-fix-pipeline": _run_m4_fuzz_to_fix,
}


class AdversarialCyberKernel:
    """Orchestrates typed contracts inside a confined CoW DetonationChamber with OOB Oracle certification."""

    def __init__(
        self,
        *,
        human_confirm_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> None:
        self.approval_manager = AckPatchApprovalManager(human_confirm_fn=human_confirm_fn)

    def list_missions(self) -> List[AckMissionDescriptor]:
        return list_ack_mission_descriptors()

    def run_mission(
        self,
        mission_id: str,
        *,
        mutation_rounds: int = 3,
        defense_mode: str = "structural",
        target_config_content: Optional[str] = None,
        inject_broken_mutation: bool = False,
        target_file_path: Optional[str] = None,
        target_function: Optional[str] = None,
        valid_corpus_dir: Optional[str] = None,
        valid_inputs: Optional[List[str]] = None,
        workspace_mode: AckWorkspaceModeType = "isolated_copy",
        red_router: Optional[ModelRouter] = None,
        blue_router: Optional[ModelRouter] = None,
        runs_dir: Optional[Path] = None,
    ) -> AckCertificationReport:
        desc = ACK_MISSION_MAP.get(mission_id)
        if desc is None:
            raise KeyError(f"Missione ACK sconosciuta: {mission_id}")
        runner = _MISSION_RUNNERS[mission_id]

        chamber = DetonationChamber()
        fow = FogOfWarController()
        try:
            outcome = runner(
                chamber,
                desc,
                fow,
                mutation_rounds=max(1, min(3, int(mutation_rounds))),
                defense_mode=defense_mode,
                target_config_content=target_config_content,
                inject_broken_mutation=inject_broken_mutation,
                target_file_path=target_file_path,
                target_function=target_function,
                valid_corpus_dir=valid_corpus_dir,
                valid_inputs=valid_inputs,
                workspace_mode=workspace_mode,
                red_router=red_router,
                blue_router=blue_router,
            )
            isolation_ok = fow.verify_trace_isolation(outcome.subagent_traces)
            fow_audit = fow.audit()
            certified = outcome.certified
            cert_verdict = outcome.certification_verdict
            rationale = outcome.rationale
            transitions = list(outcome.transitions)
            if not isolation_ok:
                fow_audit = fow_audit.model_copy(update={"enforced": False})
                certified = False
                cert_verdict = "REJECTED_FOG_OF_WAR_VIOLATION"
                rationale = "Violazione Fog of War rilevata nelle tracce dei sub-agent Red/Blue."
                transitions.append(
                    AckStateTransition(
                        state="CERTIFY_REPORT",
                        actor="ORACLE",
                        summary=rationale,
                        passed=False,
                    )
                )

            subagent_arch: AckSubAgentArchitectureType = (
                "llm_guided_role_pipeline"
                if any(t.execution_kind != "deterministic_role" for t in outcome.subagent_traces)
                else "in_process_role_pipeline"
            )
            report = AckCertificationReport(
                run_id=f"ack-run-{uuid.uuid4().hex[:8]}",
                mission_id=desc.mission_id,
                mission_kind=desc.mission_kind,
                title=desc.title,
                sandbox_id=chamber.sandbox_id,
                tier_used=desc.default_tier,
                shadow_clone_only=desc.shadow_clone_only,
                audit_scope=outcome.audit_scope,
                verification_tier=outcome.verification_tier,
                isolation_backend=chamber.isolation_backend,
                defense_mode=defense_mode,
                target_invariant=desc.target_invariant,
                certified=certified,
                certification_verdict=cert_verdict,
                patch_classification=outcome.patch_classification,
                patch_applicable=outcome.patch_applicable if isolation_ok else False,
                subagent_execution_architecture=subagent_arch,
                manual_review_required=outcome.manual_review_required,
                manual_review_reasons=list(outcome.manual_review_reasons),
                executed_checks=outcome.executed_checks,
                not_executed_checks=outcome.not_executed_checks,
                state_transitions=transitions,
                subagent_traces=outcome.subagent_traces,
                action_contracts=outcome.contracts,
                oracle_evidences=outcome.evidences,
                mutation_rounds=outcome.mutation_rounds,
                tpr_fpr_matrix=outcome.tpr_fpr_matrix,
                fog_of_war=fow_audit,
                blue_patch_or_rules_summary=outcome.blue_summary,
                rationale=rationale,
                patch_diff=outcome.patch_diff,
                workspace_target=outcome.workspace_target,
            )
            runs_root = resolve_ack_runs_dir(runs_dir)
            deliv_dir, deliv_files = export_ack_deliverables(runs_root, report, chamber, outcome)
            return report.model_copy(
                update={
                    "deliverable_dir": str(deliv_dir),
                    "deliverable_files": deliv_files,
                }
            )
        finally:
            chamber.cleanup()

    def list_runs(self, *, runs_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        return list_ack_runs(resolve_ack_runs_dir(runs_dir))

    def issue_patch_approval(
        self,
        run_id: str,
        *,
        session_id: str,
        expected_target_file_path: Optional[str] = None,
        acknowledge_manual_review: bool = False,
        remote_client: bool = False,
        operator_principal: str = "",
        runs_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        return self.approval_manager.issue_approval(
            resolve_ack_runs_dir(runs_dir),
            run_id,
            session_id=session_id,
            expected_target_file_path=expected_target_file_path,
            acknowledge_manual_review=acknowledge_manual_review,
            remote_client=remote_client,
            operator_principal=operator_principal,
        )

    def apply_patch(
        self,
        run_id: str,
        *,
        confirm_apply: bool = False,
        approval_token: str = "",
        session_id: str = "",
        operator_principal: str = "",
        runs_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        return apply_ack_run_patch(
            resolve_ack_runs_dir(runs_dir),
            run_id,
            confirm_apply=confirm_apply,
            approval_token=approval_token,
            session_id=session_id,
            operator_principal=operator_principal,
            approval_manager=self.approval_manager,
        )
