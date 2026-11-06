"""Profile resolution and filesystem isolation helpers for Hermes Voice Assistant."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Union

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


def assert_voice_home_live(path: Union[str, Path]) -> None:
    """Refuse missing or tombstoned named profile homes."""
    target = Path(path)
    try:
        from hermes_constants import assert_named_profile_home_live
        has_guard = True
    except (ImportError, ModuleNotFoundError):
        has_guard = False

    if has_guard:
        assert_named_profile_home_live(target)
        return

    # Standalone fallback when running outside full Hermes runtime
    for candidate in (target, *target.parents):
        if candidate.parent.name == "profiles" and not candidate.name.startswith("."):
            root = candidate.parent.parent
            is_profiles_root = (
                root.name == ".hermes"
                or (candidate.parent / ".deleted").is_dir()
                or any((root / m).exists() for m in ("config.yaml", ".env", "state.db"))
            )
            if is_profiles_root:
                tombstone = candidate.parent / ".deleted" / candidate.name
                if tombstone.exists() or not candidate.exists():
                    raise FileNotFoundError(
                        f"Named profile home does not exist: {candidate}. "
                        "Create the profile explicitly before using it."
                    )
                break
        if candidate.name == ".hermes":
            break


def ensure_voice_dir(path: Union[str, Path]) -> Path:
    """Create *path* via the profile-aware guard so deleted/missing named profiles are never recreated."""
    target = Path(path)
    try:
        from hermes_constants import mkdir_under_hermes_home
        has_mkdir_guard = True
    except (ImportError, ModuleNotFoundError):
        has_mkdir_guard = False

    if has_mkdir_guard:
        return mkdir_under_hermes_home(target)

    assert_voice_home_live(target)
    target.mkdir(parents=True, exist_ok=True)
    return target


@contextmanager
def bind_voice_profile_scope(
    home_dir: Optional[Union[str, Path]] = None,
    profile: Optional[str] = None,
) -> Iterator[Path]:
    """Bind the authorized profile's HERMES_HOME override and secret scope for the active context.

    Ensures load_config() and agent.secret_scope.get_secret() strictly read the authorized
    profile's configuration and credentials rather than borrowing from the gateway's launch
    profile (AGENTS.md:13, plugins/AGENTS.md:104-110).
    """
    if home_dir is not None:
        target_home = Path(home_dir).resolve()
        assert_voice_home_live(target_home)
    else:
        target_home = resolve_voice_profile_dir(profile=profile).parent.resolve()

    home_token = None
    mux_token = None
    secret_token = None
    try:
        try:
            from hermes_constants import reset_hermes_home_override, set_hermes_home_override
            has_home_override = True
        except (ImportError, ModuleNotFoundError):
            has_home_override = False

        if has_home_override:
            home_token = set_hermes_home_override(str(target_home))

        try:
            from agent.secret_scope import (
                _is_process_home,
                build_profile_secret_scope,
                current_secret_scope,
                current_secret_scope_home,
                reset_multiplex_context,
                reset_secret_scope,
                set_multiplex_context,
                set_secret_scope,
            )
            has_secret_scope = True
        except (ImportError, ModuleNotFoundError):
            has_secret_scope = False

        if has_secret_scope:
            is_routed = not _is_process_home(target_home)
            if is_routed:
                mux_token = set_multiplex_context(True)

            already_bound_home = current_secret_scope_home()
            already_matches = False
            if current_secret_scope() is not None and already_bound_home:
                try:
                    already_matches = Path(already_bound_home).resolve() == target_home
                except OSError:
                    already_matches = False

            if not already_matches:
                if is_routed:
                    try:
                        from hermes_cli.env_loader import hydrate_profile_secret_sources
                        hydrate_profile_secret_sources(target_home)
                    except Exception:
                        pass
                    secrets = build_profile_secret_scope(target_home)
                else:
                    try:
                        from tui_gateway.launch_profile_policy import owner_secret_scope
                        secrets = owner_secret_scope(target_home)
                    except Exception:
                        secrets = build_profile_secret_scope(target_home)
                secret_token = set_secret_scope(secrets, profile_home=str(target_home))

        yield target_home
    finally:
        if secret_token is not None:
            reset_secret_scope(secret_token)
        if mux_token is not None:
            reset_multiplex_context(mux_token)
        if home_token is not None:
            reset_hermes_home_override(home_token)


def resolve_voice_profile_dir(
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """Resolve the storage directory for the given profile or authorized home directory.

    Guarantees strict isolation of persisted assistant files, reading states,
    and voice libraries across multiple Hermes profiles and custom HERMES_HOME locations (AGENTS.md:13).
    When home_dir is specified (e.g. from an authorized native ticket or home override),
    it is preserved directly as the storage identity rather than routing through the profiles root.
    Refuses to recreate deleted or missing named profile homes.
    Rejects invalid profile names (e.g. traversal tokens like '..').
    """
    if home_dir is not None:
        base_dir = Path(home_dir).resolve()
        target_dir = base_dir / "voice_assistant"
        return ensure_voice_dir(target_dir)

    prof = (profile or "").strip()
    if not prof:
        # Implicit storage resolution from the active Hermes home path (AGENTS.md:13)
        try:
            from hermes_constants import get_hermes_home
            has_hermes_constants = True
        except (ImportError, ModuleNotFoundError):
            has_hermes_constants = False

        if has_hermes_constants:
            active_home = get_hermes_home().resolve()
            target_dir = active_home / "voice_assistant"
            return ensure_voice_dir(target_dir)

        hermes_home = os.environ.get("HERMES_HOME")
        if hermes_home and hermes_home.strip():
            target_dir = Path(hermes_home).resolve() / "voice_assistant"
            return ensure_voice_dir(target_dir)

        target_dir = (Path.home() / ".hermes" / "voice_assistant").resolve()
        return ensure_voice_dir(target_dir)

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
    return ensure_voice_dir(target_dir)


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
        named_profile_homes: dict[str, Path] = {"default": default_home}
        all_homes_by_path: dict[Path, str] = {default_home: "default"}
        for pname in list_profile_names():
            try:
                p_dir = get_profile_dir(pname).resolve()
                p_key = pname.lower()
                named_profile_homes[p_key] = p_dir
                all_homes_by_path[p_dir] = p_key
            except Exception:
                pass
    except Exception:
        default_home = (Path.home() / ".hermes").resolve()
        profiles_root = (default_home / "profiles").resolve()
        named_profile_homes = {"default": default_home}
        all_homes_by_path = {default_home: "default"}

    # Add all registered served custom homes by canonical path to avoid name collisions
    for sh, sname in _REGISTERED_SERVED_HOMES.items():
        try:
            sh_resolved = Path(sh).resolve()
            if sh_resolved not in all_homes_by_path:
                all_homes_by_path[sh_resolved] = sname or sh_resolved.name.lower() or "served_home"
        except Exception:
            pass

    # Add served_homes if explicitly provided, tracking by canonical path to prevent discarding name collisions
    if served_homes:
        if isinstance(served_homes, dict):
            for k, v in served_homes.items():
                if isinstance(v, (str, Path)):
                    try:
                        p_val = Path(v).resolve()
                        all_homes_by_path[p_val] = str(k).lower()
                    except Exception:
                        pass
                elif isinstance(k, (str, Path)):
                    try:
                        p_key = Path(k).resolve()
                        all_homes_by_path[p_key] = str(v).lower()
                    except Exception:
                        pass
        elif isinstance(served_homes, Iterable):
            for sh in served_homes:
                try:
                    sh_path = Path(sh).resolve()
                    if sh_path not in all_homes_by_path:
                        all_homes_by_path[sh_path] = sh_path.name.lower() or "served_home"
                except Exception:
                    pass

    # Inspect running gateway runtime session authorities if available in the current process
    try:
        from hermes_constants import get_hermes_home
        current_proc_home = get_hermes_home().resolve()
        if current_proc_home not in all_homes_by_path:
            all_homes_by_path[current_proc_home] = "process_home"
    except Exception:
        pass

    if home_dir:
        caller_home = Path(home_dir).resolve()
    elif prof_name == "default":
        caller_home = default_home
    else:
        caller_home = named_profile_homes.get(prof_name, (profiles_root / prof_name).resolve())

    is_cross_profile = False
    conflicting_profile = None

    # 1. Check if path is under named profiles directory
    try:
        if p.is_relative_to(profiles_root):
            rel = p.relative_to(profiles_root)
            if rel.parts:
                owner_profile = rel.parts[0].lower()
                expected_home = named_profile_homes.get(owner_profile, (profiles_root / owner_profile).resolve())
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
                expected_home = named_profile_homes.get(owner_profile, (profiles_root / owner_profile).resolve())
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

    # 3. Check against all known served profile homes outside profiles_root (every home preserved by Path)
    if not is_cross_profile:
        for other_home, other_name in all_homes_by_path.items():
            if other_home == default_home:
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
