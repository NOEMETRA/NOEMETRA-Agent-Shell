"""Persistent assistant manager with strict profile isolation for HermesVoiceAssistant."""

from __future__ import annotations

import logging
import os
import threading
from typing import Dict, Optional

from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.profile import resolve_voice_profile_dir

logger = logging.getLogger(__name__)

_assistants: Dict[str, HermesVoiceAssistant] = {}
_lock = threading.Lock()


def get_assistant(profile: Optional[str] = None) -> HermesVoiceAssistant:
    """Return persistent assistant instance isolated by active profile (AGENTS.md:13)."""
    global _assistants
    prof_key = (profile or "").strip()
    if not prof_key:
        try:
            from hermes_cli.profiles import current_profile_name
            prof_key = current_profile_name() or "default"
        except Exception:
            prof_key = os.environ.get("HERMES_PROFILE_NAME") or os.environ.get("HERMES_PROFILE") or "default"

    with _lock:
        if prof_key not in _assistants:
            logger.info("Inizializzazione HermesVoiceAssistant per profilo '%s'...", prof_key)
            prof_dir = resolve_voice_profile_dir(prof_key)
            _assistants[prof_key] = HermesVoiceAssistant(
                bookmark_path=prof_dir / "reading_state.json",
                library_path=prof_dir / "voice_library.json",
                cache_dir=prof_dir / "audio_cache",
                profile=prof_key,
            )
        return _assistants[prof_key]


def reset_assistants(profile: Optional[str] = None) -> None:
    """Reset assistant instance(s) — useful for unit tests and profile switching."""
    global _assistants
    with _lock:
        if profile:
            prof_key = profile.strip()
            if prof_key in _assistants:
                try:
                    _assistants[prof_key].player.stop()
                except Exception:
                    pass
                del _assistants[prof_key]
        else:
            for ast in _assistants.values():
                try:
                    ast.player.stop()
                except Exception:
                    pass
            _assistants.clear()
