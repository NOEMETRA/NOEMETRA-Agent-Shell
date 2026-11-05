"""Persistent assistant manager with strict profile isolation for HermesVoiceAssistant."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Dict, Optional, Union

from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.profile import resolve_voice_profile_dir

logger = logging.getLogger(__name__)

_assistants: Dict[str, HermesVoiceAssistant] = {}
_lock = threading.Lock()


def get_assistant(
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
) -> HermesVoiceAssistant:
    """Return persistent assistant instance keyed consistently by canonical storage home (AGENTS.md:13)."""
    global _assistants
    prof_dir = resolve_voice_profile_dir(profile=profile, home_dir=home_dir)
    canonical_key = str(prof_dir.resolve())

    with _lock:
        if canonical_key not in _assistants:
            logger.info("Inizializzazione HermesVoiceAssistant per identità '%s'...", canonical_key)
            _assistants[canonical_key] = HermesVoiceAssistant(
                bookmark_path=prof_dir / "reading_state.json",
                library_path=prof_dir / "voice_library.json",
                cache_dir=prof_dir / "audio_cache",
                profile=profile or prof_dir.parent.name,
                home_dir=prof_dir.parent,
            )
        return _assistants[canonical_key]


def reset_assistants(profile: Optional[str] = None) -> None:
    """Reset assistant instance(s) — useful for unit tests and profile switching."""
    global _assistants
    with _lock:
        if profile:
            try:
                prof_dir = resolve_voice_profile_dir(profile)
                canon_key = str(prof_dir.resolve())
            except Exception:
                canon_key = profile.strip()
            if canon_key in _assistants:
                try:
                    _assistants[canon_key].player.stop()
                except Exception:
                    pass
                del _assistants[canon_key]
        else:
            for ast in _assistants.values():
                try:
                    ast.player.stop()
                except Exception:
                    pass
            _assistants.clear()
            _assistants.clear()
