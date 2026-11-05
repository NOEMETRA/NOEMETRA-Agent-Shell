"""Profile resolution and filesystem isolation helpers for Hermes Voice Assistant."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def resolve_voice_profile_dir(profile: Optional[str] = None) -> Path:
    """Resolve the storage directory for the given or current Hermes profile.

    Guarantees strict isolation of persisted assistant files, reading states,
    and voice libraries across multiple Hermes profiles (AGENTS.md:13).
    Rejects invalid profile names (e.g. traversal tokens like '..').
    """
    prof = (profile or "").strip()
    if not prof:
        try:
            from hermes_cli.profiles import current_profile_name
            prof = current_profile_name() or "default"
        except Exception:
            prof = os.environ.get("HERMES_PROFILE_NAME") or os.environ.get("HERMES_PROFILE") or "default"

    prof = prof.strip().lower()
    if not PROFILE_ID_RE.match(prof):
        raise ValueError(
            f"Invalid profile name {profile!r}: must match ^[a-z0-9][a-z0-9_-]{{0,63}}$"
        )

    # Use canonical get_profile_dir when available
    try:
        from hermes_cli.profiles import get_profile_dir
        base_dir = get_profile_dir(prof)
    except (ImportError, ModuleNotFoundError):
        hermes_home = os.environ.get("HERMES_HOME")
        if hermes_home and prof == "default":
            base_dir = Path(hermes_home)
        elif prof != "default":
            base_dir = Path.home() / ".hermes" / "profiles" / prof
        else:
            base_dir = Path.home() / ".hermes"

    target_dir = base_dir / "voice_assistant"
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir
