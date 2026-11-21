"""Modular NOEMETRA Adversarial Cyber Kernel (ACK) subpackage."""

from __future__ import annotations

from hermes_cyber.ack.catalog import (
    ACK_MISSIONS,
    ACK_MISSION_MAP,
    list_ack_mission_descriptors,
)
from hermes_cyber.ack.chamber import DetonationChamber, _create_win32_job_object
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.kernel import AdversarialCyberKernel
from hermes_cyber.ack.manifest_parser import _parse_target_host_config
from hermes_cyber.ack.manifest_patcher import (
    _harden_manifest_text,
    _validate_hardened_manifest_syntax,
)
from hermes_cyber.ack.yaml_compat import _yaml_safe_dump_compat, _yaml_safe_load_compat

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
