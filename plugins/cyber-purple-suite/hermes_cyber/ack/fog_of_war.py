"""Information asymmetry (Fog of War) controller for Red and Blue ACK sub-agent teams."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from hermes_cyber.models import AckSubAgentTrace, FogOfWarAudit, OutOfBandOracleEvidence

_BLUE_ONLY_KEYS = frozenset({
    "oob_telemetry_alerts",
    "benign_baseline_corpus",
    "baseline_target_source_or_config",
    "blue_rules",
    "patch_strategy",
})
_RED_ONLY_KEYS = frozenset({
    "failed_attack_classes",
    "red_mutation_plan",
    "red_fuzz_strategy",
})


class FogOfWarController:
    """Enforces information asymmetry between Red and Blue sub-agents while tracking failed attack classes."""

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

    def build_red_context(
        self,
        *,
        target_invariant: str,
        attack_surface: str,
        target_signature: Optional[str] = None,
        surface_hints: Optional[List[str]] = None,
        last_observation: Optional[str] = None,
    ) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {
            "target_invariant": target_invariant,
            "target_endpoint": attack_surface,
            "failed_attack_classes": list(self.failed_classes),
        }
        if target_signature:
            ctx["target_signature"] = target_signature
        if surface_hints is not None:
            ctx["surface_hints"] = list(surface_hints)
        if last_observation:
            ctx["last_observation"] = last_observation
        for key in ctx:
            if key not in self._red_visible_keys:
                self._red_visible_keys.append(key)
        return ctx

    def build_blue_context(
        self,
        *,
        baseline_summary: str,
        oob_baseline: OutOfBandOracleEvidence,
        repro_summary: Optional[str] = None,
        valid_corpus_summary: Optional[str] = None,
        traceback_excerpt: Optional[str] = None,
    ) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {
            "baseline_target_source_or_config": baseline_summary,
            "oob_fs_diff": oob_baseline.fs_diff.model_dump(mode="json"),
            "oob_net_events": [n.model_dump(mode="json") for n in oob_baseline.net_events],
            "oob_telemetry_alerts": [t.model_dump(mode="json") for t in oob_baseline.telemetry_alerts],
        }
        if repro_summary:
            ctx["repro_summary"] = repro_summary
        if valid_corpus_summary:
            ctx["valid_corpus_summary"] = valid_corpus_summary
        if traceback_excerpt:
            ctx["traceback_excerpt"] = traceback_excerpt
        for key in ctx:
            if key not in self._blue_visible_keys:
                self._blue_visible_keys.append(key)
        return ctx

    def record_outcome(self, attack_class: str, bypass_succeeded: bool) -> List[str]:
        prior = list(self.failed_classes)
        if not bypass_succeeded and attack_class and attack_class not in self.failed_classes:
            self.failed_classes.append(attack_class)
        return prior

    def verify_trace_isolation(self, traces: List[AckSubAgentTrace]) -> bool:
        """Verify no RED sub-agent saw Blue-only keys and no BLUE sub-agent saw Red-only keys."""
        for tr in traces:
            keys = set(tr.visible_context_keys)
            if tr.team == "RED" and (keys & _BLUE_ONLY_KEYS):
                return False
            if tr.team == "BLUE" and (keys & _RED_ONLY_KEYS):
                return False
        return True

    def audit(self) -> FogOfWarAudit:
        return FogOfWarAudit(
            enforced=True,
            blue_rules_hidden_from_red=True,
            red_mutation_logic_hidden_from_blue=True,
            red_visible_keys=list(self._red_visible_keys),
            blue_visible_keys=list(self._blue_visible_keys),
            failed_attack_classes_memory=list(self.failed_classes),
        )
