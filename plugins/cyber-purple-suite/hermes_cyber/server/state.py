"""Persistent CyberPurpleAssistant manager with strict profile isolation."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Dict, Optional, Union

from hermes_cyber.pipeline import CyberPurpleAssistant
from hermes_cyber.router_bridge import (
    assert_voice_home_live,
    bind_cyber_profile_scope,
    resolve_cyber_profile_dir,
)

logger = logging.getLogger(__name__)

_assistants: Dict[str, CyberPurpleAssistant] = {}
_lock = threading.Lock()


def _evict_dead_assistants() -> None:
    with _lock:
        dead_keys = []
        for k in list(_assistants.keys()):
            try:
                assert_voice_home_live(Path(k))
            except FileNotFoundError:
                dead_keys.append(k)
        for k in dead_keys:
            _assistants.pop(k, None)


def get_cyber_assistant(
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
) -> CyberPurpleAssistant:
    global _assistants
    try:
        cyber_dir = resolve_cyber_profile_dir(profile=profile, home_dir=home_dir)
    except FileNotFoundError:
        _evict_dead_assistants()
        raise
    canonical_key = str(cyber_dir.resolve())

    resolved_profile = (profile or "").strip().lower()
    if not resolved_profile:
        resolved_profile = (
            os.environ.get("HERMES_PROFILE_NAME")
            or os.environ.get("HERMES_PROFILE")
            or "default"
        ).strip().lower()

    with _lock:
        if canonical_key not in _assistants:
            logger.info("Inizializzazione CyberPurpleAssistant per '%s' (profilo: %s)", canonical_key, resolved_profile)
            with bind_cyber_profile_scope(home_dir=cyber_dir.parent, profile=resolved_profile):
                _assistants[canonical_key] = CyberPurpleAssistant(
                    profile=resolved_profile,
                    home_dir=cyber_dir.parent,
                )
        return _assistants[canonical_key]


def reset_cyber_assistants(profile: Optional[str] = None) -> None:
    global _assistants
    with _lock:
        if profile:
            prof_dir = str(resolve_cyber_profile_dir(profile=profile).resolve())
            _assistants.pop(prof_dir, None)
        else:
            _assistants.clear()
