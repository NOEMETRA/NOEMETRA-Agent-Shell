"""Information asymmetry (Fog of War) controller for Red and Blue ACK contexts."""

from __future__ import annotations

from typing import Any, Dict, List

from hermes_cyber.models import FogOfWarAudit, OutOfBandOracleEvidence


class FogOfWarController:
    """Enforces information asymmetry between Red and Blue while tracking failed Red attack classes."""

    def __init__(self) -> None:
        self.failed_classes: List[str] = []
        self._red_visible_keys: List[str] = [
            "target_endpoint",
            "target_invariant",
            "response_status",
            "attack_objective_reached",
            "failed_attack_classes",
        ]
        self._blue_visible_keys: List[str] = [
            "baseline_target_source_or_config",
            "oob_fs_diff",
            "oob_net_events",
            "oob_telemetry_alerts",
            "benign_baseline_corpus",
        ]

    def build_red_context(self, *, target_invariant: str, attack_surface: str) -> Dict[str, Any]:
        return {
            "target_invariant": target_invariant,
            "target_endpoint": attack_surface,
            "failed_attack_classes": list(self.failed_classes),
        }

    def build_blue_context(self, *, baseline_summary: str, oob_baseline: OutOfBandOracleEvidence) -> Dict[str, Any]:
        return {
            "baseline_target_source_or_config": baseline_summary,
            "oob_fs_diff": oob_baseline.fs_diff.model_dump(mode="json"),
            "oob_net_events": [n.model_dump(mode="json") for n in oob_baseline.net_events],
            "oob_telemetry_alerts": [t.model_dump(mode="json") for t in oob_baseline.telemetry_alerts],
        }

    def record_outcome(self, attack_class: str, bypass_succeeded: bool) -> List[str]:
        prior = list(self.failed_classes)
        if not bypass_succeeded and attack_class and attack_class not in self.failed_classes:
            self.failed_classes.append(attack_class)
        return prior

    def audit(self) -> FogOfWarAudit:
        return FogOfWarAudit(
            enforced=True,
            blue_rules_hidden_from_red=True,
            red_mutation_logic_hidden_from_blue=True,
            red_visible_keys=list(self._red_visible_keys),
            blue_visible_keys=list(self._blue_visible_keys),
            failed_attack_classes_memory=list(self.failed_classes),
        )
