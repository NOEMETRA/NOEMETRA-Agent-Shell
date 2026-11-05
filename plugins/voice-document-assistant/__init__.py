"""Voice Document Assistant plugin for NOEMETRA Agent Shell."""
from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_DIR = str(Path(__file__).resolve().parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from hermes_plugin.voice_plugin import (
    register,
    TOOLS,
    voice_load_document,
    voice_play_document,
    voice_pause_document,
    voice_resume_document,
    voice_stop_document,
    voice_seek_document,
    voice_ask_document,
    voice_get_status,
)

__all__ = [
    "register",
    "TOOLS",
    "voice_load_document",
    "voice_play_document",
    "voice_pause_document",
    "voice_resume_document",
    "voice_stop_document",
    "voice_seek_document",
    "voice_ask_document",
    "voice_get_status",
]

