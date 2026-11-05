"""NOEMETRA Agent Shell Dashboard / Desktop plugin API backend mount.

Mounted by gateway at /api/plugins/voice-document-assistant/
reusing the persistent singleton hermes_voice engine.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_DIR = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from hermes_voice.server.api import router

__all__ = ["router"]

