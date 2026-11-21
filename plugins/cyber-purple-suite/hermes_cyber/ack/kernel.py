"""AdversarialCyberKernel orchestrating ACK missions inside DetonationChamber + Fog of War."""

from __future__ import annotations

import uuid
from typing import Callable, Dict, List, Optional

from hermes_cyber.ack.catalog import (
    ACK_MISSION_MAP,
    _MissionExecutionOutcome,
    list_ack_mission_descriptors,
)
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.mission_m1_appsec import _run_m1_exploit_to_patch
from hermes_cyber.ack.mission_m2_evasion import _run_m2_detection_evasion
from hermes_cyber.ack.mission_m3_hardening import _run_m3_attack_path_hardening
from hermes_cyber.ack.mission_m4_fuzzing import _run_m4_fuzz_to_fix
from hermes_cyber.models import AckCertificationReport, AckMissionDescriptor

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
            )
            return AckCertificationReport(
                run_id=f"ack-run-{uuid.uuid4().hex[:8]}",
                mission_id=desc.mission_id,
                mission_kind=desc.mission_kind,
                title=desc.title,
                sandbox_id=chamber.sandbox_id,
                tier_used=desc.default_tier,
                shadow_clone_only=desc.shadow_clone_only,
                audit_scope=outcome.audit_scope,
                isolation_backend=chamber.isolation_backend,
                defense_mode=defense_mode,
                target_invariant=desc.target_invariant,
                certified=outcome.certified,
                certification_verdict=outcome.certification_verdict,
                state_transitions=outcome.transitions,
                action_contracts=outcome.contracts,
                oracle_evidences=outcome.evidences,
                mutation_rounds=outcome.mutation_rounds,
                tpr_fpr_matrix=outcome.tpr_fpr_matrix,
                fog_of_war=fow.audit(),
                blue_patch_or_rules_summary=outcome.blue_summary,
                rationale=outcome.rationale,
            )
        finally:
            chamber.cleanup()
