"""Backward-compatible facade re-exporting the modular NOEMETRA Adversarial Cyber Kernel (ACK)."""

from __future__ import annotations

from hermes_cyber.ack import (
    ACK_MISSIONS,
    ACK_MISSION_MAP,
    AdversarialCyberKernel,
    DetonationChamber,
    FogOfWarController,
    _create_win32_job_object,
    _harden_manifest_text,
    _parse_target_host_config,
    _validate_hardened_manifest_syntax,
    _yaml_safe_dump_compat,
    _yaml_safe_load_compat,
    list_ack_mission_descriptors,
)

__all__ = [
    "ACK_MISSIONS",
    "ACK_MISSION_MAP",
    "AdversarialCyberKernel",
    "DetonationChamber",
    "FogOfWarController",
    "_create_win32_job_object",
    "_harden_manifest_text",
    "_parse_target_host_config",
    "_validate_hardened_manifest_syntax",
    "_yaml_safe_dump_compat",
    "_yaml_safe_load_compat",
    "list_ack_mission_descriptors",
]
