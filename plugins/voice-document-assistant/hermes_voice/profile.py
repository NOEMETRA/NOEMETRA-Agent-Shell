"""Profile resolution and filesystem isolation helpers for Hermes Voice Assistant."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional


def resolve_voice_profile_dir(profile: Optional[str] = None) -> Path:
    """Resolve the storage directory for the given or current Hermes profile.

    Guarantees strict isolation of persisted assistant files, reading states,
    and voice libraries across multiple Hermes profiles (AGENTS.md:13).
    """
    prof = (profile or "").strip()
    if not prof:
        try:
            from hermes_cli.profiles import current_profile_name
            prof = current_profile_name() or "default"
        except Exception:
            prof = os.environ.get("HERMES_PROFILE_NAME") or os.environ.get("HERMES_PROFILE") or "default"

    clean_prof = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", prof)
    try:
        from hermes_cli.profiles import get_profile_dir
        base_dir = get_profile_dir(clean_prof)
    except Exception:
        hermes_home = os.environ.get("HERMES_HOME")
        if hermes_home and (clean_prof == "default" or not clean_prof):
            base_dir = Path(hermes_home)
        elif clean_prof and clean_prof != "default":
            base_dir = Path.home() / ".hermes" / "profiles" / clean_prof
        else:
            base_dir = Path.home() / ".hermes"

    target_dir = base_dir / "voice_assistant"
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir
