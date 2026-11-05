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
    """Return persistent assistant instance isolated by active profile or authorized home (AGENTS.md:13)."""
    global _assistants
    if home_dir is not None:
        resolved_home = str(Path(home_dir).resolve())
        prof_key = f"home:{resolved_home}"
    else:
        prof_key = (profile or "").strip()
        if not prof_key:
            try:
                from hermes_constants import get_hermes_home_override
                home_override = get_hermes_home_override()
                if home_override:
                    ov_path = Path(home_override).resolve()
                    if "profiles" not in ov_path.parts:
                        resolved_home = str(ov_path)
                        prof_key = f"home:{resolved_home}"
                        home_dir = ov_path
            except Exception:
                pass
        if not prof_key:
            try:
                from hermes_cli.profiles import current_profile_name
                prof_key = current_profile_name() or "default"
            except Exception:
                prof_key = os.environ.get("HERMES_PROFILE_NAME") or os.environ.get("HERMES_PROFILE") or "default"

    with _lock:
        if prof_key not in _assistants:
            logger.info("Inizializzazione HermesVoiceAssistant per identità '%s'...", prof_key)
            prof_dir = resolve_voice_profile_dir(profile=profile, home_dir=home_dir)
            _assistants[prof_key] = HermesVoiceAssistant(
                bookmark_path=prof_dir / "reading_state.json",
                library_path=prof_dir / "voice_library.json",
                cache_dir=prof_dir / "audio_cache",
                profile=profile or (Path(home_dir).name if home_dir else prof_key),
                home_dir=home_dir,
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
