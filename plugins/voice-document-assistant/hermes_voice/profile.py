"""Profile resolution and filesystem isolation helpers for Hermes Voice Assistant."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional, Union

PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

_REGISTERED_SERVED_HOMES: dict[Path, str] = {}


def register_served_profile_home(home: Union[str, Path], name: Optional[str] = None) -> None:
    """Register an active or served profile home directory for cross-profile boundary checks."""
    if not home:
        return
    try:
        p = Path(home).resolve()
        _REGISTERED_SERVED_HOMES[p] = (name or p.name).strip().lower() or "custom_home"
    except Exception:
        pass


def clear_registered_served_profile_homes() -> None:
    """Clear registered custom profile homes (useful for isolated tests)."""
    _REGISTERED_SERVED_HOMES.clear()


def resolve_voice_profile_dir(
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """Resolve the storage directory for the given profile or authorized home directory.

    Guarantees strict isolation of persisted assistant files, reading states,
    and voice libraries across multiple Hermes profiles and custom HERMES_HOME locations (AGENTS.md:13).
    When home_dir is specified (e.g. from an authorized native ticket or home override),
    it is preserved directly as the storage identity rather than routing through the profiles root.
    Rejects invalid profile names (e.g. traversal tokens like '..').
    """
    if home_dir is not None:
        base_dir = Path(home_dir).resolve()
        target_dir = base_dir / "voice_assistant"
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    prof = (profile or "").strip()
    if not prof:
        try:
            from hermes_constants import get_hermes_home_override
            home_override = get_hermes_home_override()
            if home_override:
                target_dir = Path(home_override).resolve() / "voice_assistant"
                target_dir.mkdir(parents=True, exist_ok=True)
                return target_dir
        except Exception:
            pass

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


def validate_path_profile_ownership(
    file_path: Union[str, Path],
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
    served_homes: Optional[Union[dict[str, Path], list[Path], set[Path]]] = None,
) -> None:
    """Validate that the given file_path belongs to or is accessible by the specified profile (AGENTS.md:13).

    Strictly rejects access to files located in another profile's home directory or storage,
    including default home, named profiles, and other custom HERMES_HOME directories.
    Excludes the named-profiles subtree from default-home checks so named profiles can load their own files.
    Raises PermissionError if the path belongs to a different profile.
    """
    p = Path(file_path).resolve()
    prof_name = (profile or "").strip().lower() or "default"

    try:
        from hermes_cli.profiles import _get_default_hermes_home, _get_profiles_root, get_profile_dir, list_profile_names
        default_home = _get_default_hermes_home().resolve()
        profiles_root = _get_profiles_root().resolve()
        all_profile_homes: dict[str, Path] = {"default": default_home}
        for pname in list_profile_names():
            try:
                all_profile_homes[pname.lower()] = get_profile_dir(pname).resolve()
            except Exception:
                pass
    except Exception:
        default_home = (Path.home() / ".hermes").resolve()
        profiles_root = (default_home / "profiles").resolve()
        all_profile_homes = {"default": default_home}

    # Add all registered served custom homes
    for sh, sname in _REGISTERED_SERVED_HOMES.items():
        if sname not in all_profile_homes and sh != default_home:
            all_profile_homes[sname] = sh

    # Add served_homes if explicitly provided
    if served_homes:
        if isinstance(served_homes, dict):
            for sname, sh in served_homes.items():
                try:
                    all_profile_homes[str(sname).lower()] = Path(sh).resolve()
                except Exception:
                    pass
        elif isinstance(served_homes, (list, tuple, set)):
            for idx, sh in enumerate(served_homes):
                try:
                    sh_path = Path(sh).resolve()
                    all_profile_homes[f"served_home_{idx}"] = sh_path
                except Exception:
                    pass

    # Inspect running gateway runtime session authorities if available in the current process
    try:
        from hermes_constants import get_hermes_home
        current_proc_home = get_hermes_home().resolve()
        if current_proc_home != default_home and "process_home" not in all_profile_homes:
            all_profile_homes["process_home"] = current_proc_home
    except Exception:
        pass

    if home_dir:
        caller_home = Path(home_dir).resolve()
    elif prof_name == "default":
        caller_home = default_home
    else:
        caller_home = all_profile_homes.get(prof_name, (profiles_root / prof_name).resolve())

    is_cross_profile = False
    conflicting_profile = None

    # 1. Check if path is under named profiles directory
    try:
        if p.is_relative_to(profiles_root):
            rel = p.relative_to(profiles_root)
            if rel.parts:
                owner_profile = rel.parts[0].lower()
                expected_home = all_profile_homes.get(owner_profile, (profiles_root / owner_profile).resolve())
                if caller_home:
                    if caller_home != expected_home:
                        is_cross_profile = True
                        conflicting_profile = owner_profile
                elif owner_profile != prof_name:
                    is_cross_profile = True
                    conflicting_profile = owner_profile
    except AttributeError:
        if str(p).startswith(str(profiles_root)):
            rel_parts = p.relative_to(profiles_root).parts
            if rel_parts:
                owner_profile = rel_parts[0].lower()
                expected_home = all_profile_homes.get(owner_profile, (profiles_root / owner_profile).resolve())
                if caller_home:
                    if caller_home != expected_home:
                        is_cross_profile = True
                        conflicting_profile = owner_profile
                elif owner_profile != prof_name:
                    is_cross_profile = True
                    conflicting_profile = owner_profile

    # 2. Check if caller is not the default profile home and attempting to access default profile home (outside profiles_root)
    if not is_cross_profile:
        try:
            if p.is_relative_to(default_home) and not p.is_relative_to(profiles_root):
                if caller_home != default_home:
                    is_cross_profile = True
                    conflicting_profile = "default"
        except Exception:
            pass

    # 3. Check against known registered profile homes outside profiles_root (e.g. custom home overrides or other served homes)
    if not is_cross_profile:
        for other_name, other_home in all_profile_homes.items():
            if other_name == "default":
                continue  # Handled above with profiles_root exclusion
            try:
                if other_home.is_relative_to(profiles_root):
                    continue  # Handled above under profiles_root
            except Exception:
                pass
            if other_home != caller_home:
                other_voice_dir = other_home / "voice_assistant"
                if p == other_home or other_home in p.parents or p == other_voice_dir or other_voice_dir in p.parents:
                    is_cross_profile = True
                    conflicting_profile = other_name
                    break

    # 4. Check if path resides inside another profile's voice_assistant directory
    if not is_cross_profile:
        for parent in p.parents:
            if parent.name == "voice_assistant":
                potential_home = parent.parent.resolve()
                if potential_home != caller_home:
                    is_cross_profile = True
                    conflicting_profile = potential_home.name or "foreign_voice_assistant"
                    break

    # 5. Check if under another custom HERMES_HOME override
    if not is_cross_profile:
        try:
            from hermes_constants import get_hermes_home_override
            env_override = get_hermes_home_override()
            if env_override:
                env_home = Path(env_override).resolve()
                if env_home != caller_home and (p == env_home or env_home in p.parents):
                    is_cross_profile = True
                    conflicting_profile = "custom_home"
        except Exception:
            pass

    if is_cross_profile:
        raise PermissionError(
            f"file_path '{file_path}' belongs to profile {conflicting_profile!r} and is outside the authorized home directory."
        )
