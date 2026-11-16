"""NOEMETRA Cyber Purple Suite plugin package."""

from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_DIR = str(Path(__file__).resolve().parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from cyber_hermes_plugin.cyber_plugin import (
    TOOLS,
    cyber_analyze_artifact,
    cyber_analyze_scenario,
    cyber_get_status,
    cyber_run_purple_benchmark,
    register,
)

__all__ = [
    "TOOLS",
    "cyber_analyze_artifact",
    "cyber_analyze_scenario",
    "cyber_get_status",
    "cyber_run_purple_benchmark",
    "register",
]
