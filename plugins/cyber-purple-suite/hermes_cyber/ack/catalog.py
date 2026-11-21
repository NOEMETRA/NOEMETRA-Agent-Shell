"""ACK mission catalog, shared action contract builder, and fail-closed harness helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Tuple

from hermes_cyber.models import (
    AckMissionDescriptor,
    AckMutationRoundResult,
    AckStateTransition,
    AckTprFprMatrix,
    ActionExecutionLimits,
    ConstrainedActionContract,
    OutOfBandOracleEvidence,
)

if TYPE_CHECKING:
    from hermes_cyber.ack.chamber import DetonationChamber

ACK_MISSIONS: Tuple[AckMissionDescriptor, ...] = (
    AckMissionDescriptor(
        mission_id="ack-m1-exploit-patch-bypass",
        mission_kind="exploit_to_patch_loop",
        title="1. Exploit-to-Patch & Bypass Loop (AppSec / Servizio Locale)",
        target_invariant="INV_NO_READ_OUTSIDE_UPLOAD_ROOT",
        description=(
            "Red esegue un PoC reale di path/symlink traversal contro un servizio target in upperdir CoW, "
            "Blue applica patch canonica + contenimento, l'Oracolo verifica funzionalità e Red muta classe d'attacco."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m2-detection-evasion-arena",
        mission_kind="detection_vs_evasion_arena",
        title="2. Detection vs. Evasion Arena (Telemetria & Matrice TPR/FPR)",
        target_invariant="INV_DETECT_STEALTH_TTPS_LOW_FPR",
        description=(
            "Red esegue TTP fileless/LotL/beacon tramite workload target con tecniche di evasione progressive, "
            "Blue distribuisce regole comportamentali out-of-band e l'Oracolo calcola TPR reale vs FPR su telemetria benigna."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m3-attack-path-hardening",
        mission_kind="attack_path_hardening",
        title="3. Attack-Path Audit & Live Hardening (Shadow Clone CoW)",
        target_invariant="INV_NO_UNPRIVILEGED_ESCALATION_PATH",
        description=(
            "Clona in sola lettura un manifest target fornito (o una fixture sintetica di riferimento se omesso) "
            "in lowerdir -> upperdir CoW, dimostra escalation pre-patch e verifica diff minimo di hardening."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=True,
    ),
    AckMissionDescriptor(
        mission_id="ack-m4-fuzz-to-fix-pipeline",
        mission_kind="fuzz_to_fix_pipeline",
        title="4. Fuzz-to-Fix Pipeline (Binary TLV Protocol Parser)",
        target_invariant="INV_ZERO_PARSER_CRASH_OR_OVERFLOW",
        description=(
            "Red genera un fuzzer deterministico su frame binari TLV, minimizza il crash PoC, "
            "Blue corregge la root cause e integra il regression corpus contro fuzzing differenziale multi-classe."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
)

ACK_MISSION_MAP: Dict[str, AckMissionDescriptor] = {m.mission_id: m for m in ACK_MISSIONS}

_ALLOWED_BINARIES = {"python", "python3"}


def list_ack_mission_descriptors() -> List[AckMissionDescriptor]:
    return list(ACK_MISSIONS)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_harness_execution(rc: int, result_path: Path) -> Tuple[bool, int, Dict[str, Any]]:
    """Fail-closed check ensuring an attack/harness ran cleanly and produced structured attempts."""
    if rc != 0 or not result_path.exists():
        return False, 0, {}
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception:
        return False, 0, {}
    if not isinstance(data, dict) or data.get("status") != "COMPLETED":
        return False, 0, {}
    try:
        attempts = int(data.get("attempts_executed", 0))
    except Exception:
        return False, 0, {}
    if attempts < 1:
        return False, 0, {}
    return True, attempts, data


def _contract(
    *,
    chamber: DetonationChamber,
    action_id: str,
    actor: str,
    phase: str,
    primitive: str,
    artifact_path: str,
    entrypoint: List[str],
    target_invariant: str,
    attack_class: str = "",
    network_mode: str = "isolated_veth",
) -> ConstrainedActionContract:
    return ConstrainedActionContract(
        action_id=action_id,
        actor=actor,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        sandbox_id=chamber.sandbox_id,
        primitive=primitive,  # type: ignore[arg-type]
        artifact_path=artifact_path,
        entrypoint=entrypoint,
        limits=ActionExecutionLimits(timeout_sec=15, max_procs=1, network_mode=network_mode),  # type: ignore[arg-type]
        target_invariant=target_invariant,
        attack_class=attack_class,
    )


@dataclass
class _MissionExecutionOutcome:
    transitions: List[AckStateTransition]
    contracts: List[ConstrainedActionContract]
    evidences: List[OutOfBandOracleEvidence]
    mutation_rounds: List[AckMutationRoundResult]
    tpr_fpr_matrix: AckTprFprMatrix
    blue_summary: str
    certified: bool
    certification_verdict: str
    rationale: str
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest"] = "synthetic_fixture_simulation"
