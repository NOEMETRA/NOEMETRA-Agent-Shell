"""Shared ModelRouter, profile isolation, and PrivacyScrubber LLM invocation helpers."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple, Union

from hermes_cyber import _PKG_ROOT  # noqa: F401 - ensures voice paths resolved
from hermes_cyber.observer import PrivacyScrubber

try:
    from hermes_voice.model_router import ModelRouter
    from hermes_voice.local_discovery import discover_local_servers, get_model_scan_dirs, scan_local_gguf_models
    from hermes_voice.profile import (
        PROFILE_ID_RE,
        assert_voice_home_live,
        bind_voice_profile_scope,
        compute_home_fingerprint,
        ensure_voice_dir,
        get_gateway_served_profile_homes,
        register_served_profile_home,
        resolve_voice_profile_dir,
        validate_path_profile_ownership,
    )
except ImportError as exc:  # pragma: no cover - sibling plugin always present in repo
    raise ImportError("voice-document-assistant (hermes_voice) richiesto per ModelRouter e profilo.") from exc


def resolve_cyber_profile_dir(
    profile: Optional[str] = None,
    home_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """Resolve isolated cyber_purple directory inside the active Hermes profile home."""
    base_voice_dir = resolve_voice_profile_dir(profile=profile, home_dir=home_dir)
    # Place cyber storage cleanly alongside voice_assistant inside the SAME profile home
    cyber_dir = (base_voice_dir.parent / "cyber_purple").resolve()
    ensure_voice_dir(cyber_dir)
    return cyber_dir


@contextmanager
def bind_cyber_profile_scope(
    home_dir: Optional[Union[str, Path]] = None,
    profile: Optional[str] = None,
) -> Iterator[None]:
    with bind_voice_profile_scope(home_dir=home_dir, profile=profile):
        yield


def _extract_json_block(raw_text: str) -> Optional[Dict[str, Any]]:
    text = (raw_text or "").strip()
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    if not candidate.startswith("{"):
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end > start:
            candidate = candidate[start : end + 1]
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def invoke_router_json(
    router: ModelRouter,
    *,
    system_prompt: str,
    user_prompt: str,
    scrubber: Optional[PrivacyScrubber] = None,
    force_scrub: bool = False,
) -> Tuple[Optional[Dict[str, Any]], str, bool, Dict[str, int]]:
    """Call *router.generate* safely, scrubbing private IPs/secrets/emails before any remote endpoint."""
    is_remote = not router.is_active_endpoint_local()
    should_scrub = is_remote or force_scrub
    active_scrubber = scrubber or PrivacyScrubber()

    sys_payload = system_prompt
    usr_payload = user_prompt
    if should_scrub:
        sys_payload, _ = active_scrubber.scrub(system_prompt)
        usr_payload, _ = active_scrubber.scrub(user_prompt)

    try:
        raw_reply = router.generate(
            prompt=usr_payload,
            system_prompt=sys_payload,
            temperature=0.1,
            max_tokens=900,
        )
        restored = active_scrubber.unscrub(raw_reply) if should_scrub else raw_reply
        parsed = _extract_json_block(restored)
        model_label = f"{router.default_provider}:{getattr(router, 'last_model_used', None) or router.ollama_model}"
        return parsed, model_label, should_scrub, active_scrubber.stats
    except Exception:
        return None, "deterministic", should_scrub, active_scrubber.stats


__all__ = [
    "ModelRouter",
    "PROFILE_ID_RE",
    "assert_voice_home_live",
    "bind_cyber_profile_scope",
    "compute_home_fingerprint",
    "discover_local_servers",
    "ensure_voice_dir",
    "get_gateway_served_profile_homes",
    "get_model_scan_dirs",
    "invoke_router_json",
    "register_served_profile_home",
    "resolve_cyber_profile_dir",
    "scan_local_gguf_models",
    "validate_path_profile_ownership",
]
