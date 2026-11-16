"""NOEMETRA Cyber Purple Suite — Penetrating Red, Contradiction Forensics, and Verified Defense."""

from __future__ import annotations

import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
_VOICE_PLUGIN_ROOT = _PKG_ROOT.parent / "voice-document-assistant"

for _p in (_PKG_ROOT, _VOICE_PLUGIN_ROOT):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.append(str(_p))

__all__ = ["_PKG_ROOT", "_VOICE_PLUGIN_ROOT"]
