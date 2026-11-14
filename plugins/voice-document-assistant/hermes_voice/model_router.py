"""Model router supporting local Ollama (default), Codex, and optional remote APIs.

Strict constraint: Local-first by default.
No document data is sent to remote endpoints without explicit user consent.
This applies to Ollama, Codex, and all OpenAI-compatible / remote providers.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import nullcontext, suppress
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse
import requests

from hermes_voice.local_discovery import (
    LOCAL_RUNTIME_DEFAULT_URLS,
    LocalGGUFRunner,
    discover_local_servers,
    find_llama_server_binary,
    get_model_scan_dirs,
    scan_local_gguf_models,
)
from hermes_voice.profile import bind_voice_profile_scope

logger = logging.getLogger(__name__)


def is_local_endpoint(url: str) -> bool:
    """Check if URL targets loopback/localhost."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host in ("127.0.0.1", "localhost", "0.0.0.0", "::1")
    except Exception:
        return False


_PLACEHOLDER_SECRETS = frozenset({
    "*", "**", "***", "changeme", "your_api_key", "your_api_key_here",
    "your-api-key", "placeholder", "example", "dummy", "null", "none",
})


def _is_usable_secret(value: Optional[str]) -> bool:
    """Return True when *value* is a non-empty credential rather than a template placeholder."""
    if value is None or not isinstance(value, str):
        return False
    cleaned = value.strip()
    if not cleaned:
        return False
    lowered = cleaned.lower()
    if lowered in _PLACEHOLDER_SECRETS:
        return False
    if lowered.startswith("your_") and lowered.endswith("_here"):
        return False
    for prefix in ("sk-", "ghp_", "hf_"):
        if lowered.startswith(prefix):
            tail = lowered[len(prefix):]
            if tail and all(ch == "x" for ch in tail):
                return False
    return True


def _url_origin_tuple(url: Optional[str]) -> Optional[tuple[str, str]]:
    if not url or not str(url).strip():
        return None
    try:
        parsed = urlparse(str(url).strip())
        if parsed.scheme and parsed.netloc:
            return (parsed.scheme.lower(), parsed.netloc.lower())
    except Exception:
        pass
    return None


def _host_matches_domain(url: Optional[str], domain: str) -> bool:
    try:
        host = (urlparse(str(url or "").strip()).hostname or "").lower()
    except Exception:
        return False
    dom = domain.lower().lstrip(".")
    return bool(host) and (host == dom or host.endswith(f".{dom}"))


def _get_profile_scoped_secret(name: str) -> Optional[str]:
    """Resolve a credential within the active profile's secret scope (AGENTS.md:104-110).

    Strictly avoids reading ambient os.environ directly when multiplexing profiles,
    preventing cross-profile credential leaks in multi-tenant gateways.
    """
    if not name or not str(name).strip():
        return None
    key_name = str(name).strip()
    try:
        from agent.secret_scope import get_secret
        has_scope_mod = True
    except (ImportError, ModuleNotFoundError):
        has_scope_mod = False

    if has_scope_mod:
        try:
            val = get_secret(key_name)
            if val is not None and _is_usable_secret(str(val)):
                return str(val).strip()
        except Exception:
            pass
        return None

    val = os.environ.get(key_name)
    if val is not None and _is_usable_secret(str(val)):
        return str(val).strip()
    return None



def _is_entry_enabled(entry: Dict[str, Any]) -> bool:
    enabled = entry.get("enabled", True)
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, str):
        return enabled.strip().lower() not in ("false", "0", "no", "off")
    return bool(enabled)


def _match_custom_provider_entry(
    cfg: Dict[str, Any],
    raw_provider: str,
    cfg_base_url: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Locate an enabled custom provider entry in config.yaml matching provider name or base_url."""
    if not isinstance(cfg, dict):
        return None

    prov_norm = (raw_provider or "").strip().lower()
    prov_slug = prov_norm.split(":", 1)[1].strip() if prov_norm.startswith("custom:") else prov_norm
    prov_slug_dashed = prov_slug.replace(" ", "-")
    norm_url = (cfg_base_url or "").strip().rstrip("/")
    allow_url_match = prov_norm in ("custom", "openai_compatible", "lmstudio", "vllm", "codex") and bool(norm_url)

    def _extract(entry: Dict[str, Any], key_hint: str = "") -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict) or not _is_entry_enabled(entry):
            return None
        entry_url = str(entry.get("base_url") or entry.get("url") or entry.get("api") or "").strip()
        if not entry_url:
            return None
        names = set()
        for candidate in (key_hint, entry.get("provider_key"), entry.get("name")):
            if isinstance(candidate, str) and candidate.strip():
                c_low = candidate.strip().lower()
                names.add(c_low)
                names.add(c_low.replace(" ", "-"))
        matched_by_name = bool(prov_slug) and (prov_slug in names or prov_slug_dashed in names)
        matched_by_url = allow_url_match and entry_url.rstrip("/") == norm_url
        if not (matched_by_name or matched_by_url):
            return None
        key_env = str(entry.get("key_env") or entry.get("api_key_env") or "").strip()
        api_key = str(entry.get("api_key") or "").strip()
        key_cmd = str(entry.get("key_cmd") or "").strip()
        model_name = str(entry.get("default_model") or entry.get("model") or "").strip()
        return {
            "base_url": entry_url,
            "model": model_name,
            "api_key": api_key,
            "key_env": key_env,
            "declares_credential": bool(api_key or key_env or key_cmd),
        }

    providers_map = cfg.get("providers")
    if isinstance(providers_map, dict):
        for ep_key, entry in providers_map.items():
            found = _extract(entry, str(ep_key))
            if found is not None:
                return found

    legacy_list = cfg.get("custom_providers")
    if isinstance(legacy_list, list):
        for entry in legacy_list:
            found = _extract(entry)
            if found is not None:
                return found

    return None


_OPENAI_COMPAT_LOCAL_ALIASES = frozenset({
    "custom", "lmstudio", "vllm", "openai_compatible", "codex", "local", "jan", "koboldcpp", "unsloth_studio", "unsloth",
})
_DIRECT_REMOTE_ALIASES = frozenset({
    "remote", "api", "openai", "anthropic", "openrouter",
})
_LLAMACPP_LOCAL_ALIASES = frozenset({
    "llamacpp", "llama.cpp", "llama-cpp",
})
_CODEX_OAUTH_ALIASES = frozenset({
    "openai-codex", "chatgpt", "chatgpt-codex",
})
_OLLAMA_CLOUD_ALIASES = frozenset({
    "ollama-cloud", "ollama_cloud",
})
_GGUF_LOCAL_ALIASES = frozenset({
    "gguf", "llamacpp-file",
})

_OPENROUTER_FREE_FALLBACK: List[str] = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-coder:free",
    "google/gemma-3-27b-it:free",
    "deepseek/deepseek-r1-0528:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
]

_OLLAMA_CLOUD_FALLBACK: List[str] = [
    "gpt-oss:120b-cloud",
    "qwen3-coder:480b-cloud",
    "deepseek-v3.1:671b-cloud",
    "glm-4.6:cloud",
]

_CODEX_MODELS_FALLBACK: List[str] = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-luna",
    "gpt-5.6-terra",
]

_CLOUD_CATALOG_CACHE: Dict[str, tuple[float, Any]] = {}
_CLOUD_CATALOG_TTL_SECONDS = 600.0


def _fetch_openrouter_catalog(refresh: bool = False) -> Dict[str, List[str]]:
    """Fetch OpenRouter free models (and top catalog entries) with TTL cache and offline fallback."""
    cache_key = "openrouter"
    now = time.monotonic()
    cached = _CLOUD_CATALOG_CACHE.get(cache_key)
    if not refresh and cached and (now - cached[0]) < _CLOUD_CATALOG_TTL_SECONDS:
        return cached[1]

    free_models: List[str] = []
    all_models: List[str] = []

    if refresh:
        try:
            resp = requests.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Accept": "application/json"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        mid = str(item.get("id") or "").strip()
                        if not mid:
                            continue
                        pricing = item.get("pricing") if isinstance(item.get("pricing"), dict) else {}
                        is_zero = (
                            str(pricing.get("prompt", "")).strip() == "0"
                            and str(pricing.get("completion", "")).strip() == "0"
                        )
                        if mid.endswith(":free") or is_zero:
                            if mid not in free_models:
                                free_models.append(mid)
                        if len(all_models) < 120 and mid not in all_models:
                            all_models.append(mid)
        except Exception as exc:
            logger.debug("Fetch catalogo OpenRouter fallito: %s", exc)

    if not free_models:
        # Read Hermes cached/curated OpenRouter list if present locally before static fallback
        with suppress(Exception):
            from hermes_cli.models import fetch_openrouter_models

            curated = fetch_openrouter_models(cache_only=True)
            for row in curated or []:
                mid = str(row[0] if isinstance(row, (list, tuple)) else row).strip()
                if mid and mid.endswith(":free") and mid not in free_models:
                    free_models.append(mid)
                if mid and len(all_models) < 60 and mid not in all_models:
                    all_models.append(mid)

    for fallback_id in _OPENROUTER_FREE_FALLBACK:
        if fallback_id not in free_models:
            free_models.append(fallback_id)
        if fallback_id not in all_models:
            all_models.append(fallback_id)

    result = {"free_models": free_models[:60], "models": all_models[:120]}
    _CLOUD_CATALOG_CACHE[cache_key] = (now, result)
    return result


def _fetch_ollama_cloud_catalog(api_key: str = "", refresh: bool = False) -> List[str]:
    """Resolve Ollama Cloud models using Hermes cache/live API with safe fallback."""
    cache_key = "ollama_cloud"
    now = time.monotonic()
    cached = _CLOUD_CATALOG_CACHE.get(cache_key)
    if not refresh and cached and (now - cached[0]) < _CLOUD_CATALOG_TTL_SECONDS:
        return list(cached[1])

    models: List[str] = []
    with suppress(Exception):
        from hermes_cli.models_local import fetch_ollama_cloud_models

        fetched = fetch_ollama_cloud_models(
            api_key=api_key or None,
            force_refresh=refresh,
            cache_only=not refresh,
        )
        for m in fetched or []:
            ms = str(m or "").strip()
            if ms and ms not in models:
                models.append(ms)

    if refresh and api_key and not models:
        try:
            resp = requests.get(
                "https://ollama.com/v1/models",
                headers={"Accept": "application/json", "Authorization": f"Bearer {api_key}"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    mid = str((item or {}).get("id") or "").strip() if isinstance(item, dict) else ""
                    if mid and mid not in models:
                        models.append(mid)
        except Exception as exc:
            logger.debug("Fetch catalogo Ollama Cloud fallito: %s", exc)

    if not models:
        models = list(_OLLAMA_CLOUD_FALLBACK)

    _CLOUD_CATALOG_CACHE[cache_key] = (now, models)
    return list(models)


def _fetch_codex_oauth_catalog(refresh: bool = False) -> List[str]:
    """Resolve ChatGPT Codex models available for the signed-in OAuth account."""
    cache_key = "openai_codex"
    now = time.monotonic()
    cached = _CLOUD_CATALOG_CACHE.get(cache_key)
    if not refresh and cached and (now - cached[0]) < _CLOUD_CATALOG_TTL_SECONDS:
        return list(cached[1])

    models: List[str] = []
    with suppress(Exception):
        from hermes_cli.auth import _codex_access_token_is_expiring, resolve_codex_runtime_credentials
        from hermes_cli.codex_models import DEFAULT_CODEX_MODELS, get_codex_model_ids

        access_token = None
        base_url = None
        if refresh:
            creds = resolve_codex_runtime_credentials(read_only=True)
            tok = creds.get("api_key")
            base_url = creds.get("base_url")
            if tok and not _codex_access_token_is_expiring(tok, 0):
                access_token = tok
        if access_token:
            models = list(get_codex_model_ids(access_token=access_token, base_url=base_url) or [])
        else:
            models = list(DEFAULT_CODEX_MODELS)

    if not models:
        models = list(_CODEX_MODELS_FALLBACK)

    _CLOUD_CATALOG_CACHE[cache_key] = (now, models)
    return list(models)


def _resolve_hermes_provider_id(provider_name: Optional[str]) -> Optional[str]:
    """Return canonical Hermes provider id when *provider_name* is a supported Hermes runtime provider."""
    norm = (provider_name or "").strip().lower()
    if (
        not norm
        or norm in ("auto", "default", "ollama")
        or norm in _OPENAI_COMPAT_LOCAL_ALIASES
        or norm in _GGUF_LOCAL_ALIASES
        or norm.startswith("custom:")
        or norm in ("remote", "api")
    ):
        return None
    if norm in _CODEX_OAUTH_ALIASES:
        return "openai-codex"
    if norm in _OLLAMA_CLOUD_ALIASES:
        return "ollama-cloud"
    if norm in _LLAMACPP_LOCAL_ALIASES or norm == "moa":
        return norm
    try:
        from hermes_cli.auth import resolve_provider

        resolved = resolve_provider(norm)
        if resolved and resolved not in ("auto", "custom"):
            return resolved
    except Exception:
        return None
    return None


def _is_foreign_builtin_endpoint(canonical_provider: str, url: Optional[str]) -> bool:
    """Return True when *url* belongs to a different built-in provider (e.g. leftover openrouter.ai default)."""
    if not url or not str(url).strip():
        return False
    if canonical_provider != "openrouter" and _host_matches_domain(url, "openrouter.ai"):
        return True
    try:
        from hermes_cli.runtime_provider import is_foreign_provider_endpoint

        return bool(is_foreign_provider_endpoint(canonical_provider, url))
    except Exception:
        return False


def _is_codex_cli_logged_in() -> bool:
    """Check read-only whether the official `codex` CLI binary and auth session exist (never extracts tokens)."""
    try:
        if not shutil.which("codex"):
            return False
        codex_home = os.getenv("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
        auth_path = Path(codex_home).expanduser() / "auth.json"
        if not auth_path.is_file():
            return False
        data = json.loads(auth_path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return False
        if isinstance(data.get("tokens"), dict) and bool(data["tokens"].get("refresh_token")):
            return True
        return bool(data.get("OPENAI_API_KEY"))
    except Exception:
        return False


def _is_hermes_provider_configured_offline(canonical_provider: str) -> bool:
    """Check whether a Hermes provider has credentials configured without making network requests."""
    if not canonical_provider:
        return False
    try:
        from hermes_cli import auth as auth_mod

        if canonical_provider == "nous":
            return bool(auth_mod.get_nous_auth_status_local().get("logged_in"))
        if canonical_provider == "bedrock":
            from agent.bedrock_adapter import has_aws_credentials

            return bool(has_aws_credentials(instance_metadata=False))
        if canonical_provider == "vertex":
            return bool(
                _get_profile_scoped_secret("GOOGLE_APPLICATION_CREDENTIALS")
                or _get_profile_scoped_secret("VERTEX_CREDENTIALS_PATH")
            )
        if bool(auth_mod.get_auth_status(canonical_provider).get("logged_in")):
            return True
        if canonical_provider == "openai-codex":
            return _is_codex_cli_logged_in()
        return False
    except Exception:
        return False


class ModelRouter:
    """Routes LLM generation requests with local-first privacy enforcement."""

    def __init__(
        self,
        default_provider: Optional[str] = None,
        ollama_base_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
        codex_base_url: Optional[str] = None,
        codex_api_key: Optional[str] = None,
        remote_base_url: Optional[str] = None,
        remote_api_key: Optional[str] = None,
        allow_remote: bool = False,
        home_dir: Optional[Union[str, Path]] = None,
        local_model_dirs: Optional[List[str]] = None,
    ):
        self.home_dir = Path(home_dir).resolve() if home_dir is not None else None
        with (bind_voice_profile_scope(home_dir=self.home_dir) if self.home_dir is not None else nullcontext()):
            self._init_from_profile_scope(
                default_provider=default_provider,
                ollama_base_url=ollama_base_url,
                ollama_model=ollama_model,
                codex_base_url=codex_base_url,
                codex_api_key=codex_api_key,
                remote_base_url=remote_base_url,
                remote_api_key=remote_api_key,
                allow_remote=allow_remote,
                local_model_dirs=local_model_dirs,
            )

    def _profile_scope(self):
        return bind_voice_profile_scope(home_dir=self.home_dir) if self.home_dir is not None else nullcontext()

    def _init_from_profile_scope(
        self,
        default_provider: Optional[str] = None,
        ollama_base_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
        codex_base_url: Optional[str] = None,
        codex_api_key: Optional[str] = None,
        remote_base_url: Optional[str] = None,
        remote_api_key: Optional[str] = None,
        allow_remote: bool = False,
        local_model_dirs: Optional[List[str]] = None,
    ) -> None:
        # Resolve model, provider and endpoint from hermes config if not explicitly provided
        cfg: Dict[str, Any] = {}
        cfg_model: Any = None
        cfg_provider: Optional[str] = None
        cfg_base_url: Optional[str] = None
        cfg_api_key: Optional[str] = None
        cfg_key_env: Optional[str] = None
        try:
            from hermes_cli.config import load_config
            loaded = load_config()
            if isinstance(loaded, dict):
                cfg = loaded
            model_cfg = cfg.get("model")
            if isinstance(model_cfg, dict):
                raw_default = model_cfg.get("default") or model_cfg.get("name") or model_cfg.get("model") or ""
                if isinstance(raw_default, dict):
                    cfg_model = raw_default.get("model") or raw_default.get("name") or raw_default.get("default") or ""
                    cfg_provider = model_cfg.get("provider") or raw_default.get("provider")
                else:
                    cfg_model = raw_default
                    cfg_provider = model_cfg.get("provider")
                cfg_base_url = model_cfg.get("base_url") or model_cfg.get("endpoint") or model_cfg.get("api_base")
                cfg_api_key = model_cfg.get("api_key")
                cfg_key_env = model_cfg.get("key_env") or model_cfg.get("api_key_env")
            elif isinstance(model_cfg, str):
                cfg_model = model_cfg
        except Exception:
            pass

        # Resolve provider
        env_inf_prov = _get_profile_scoped_secret("HERMES_INFERENCE_PROVIDER")
        if default_provider is not None and default_provider.lower().strip() not in ("auto", "default", ""):
            raw_provider = default_provider.lower().strip()
        elif cfg_provider and str(cfg_provider).lower().strip() not in ("auto", "default", ""):
            raw_provider = str(cfg_provider).lower().strip()
        elif env_inf_prov and env_inf_prov.lower().strip() not in ("auto", "default", ""):
            raw_provider = env_inf_prov.lower().strip()
        else:
            raw_provider = "ollama"

        # Prevent config fields from an unrelated provider in config.yaml from bleeding into an overridden provider
        cfg_prov_norm = str(cfg_provider or "").strip().lower()
        if default_provider is not None and default_provider.lower().strip() not in ("auto", "default", ""):
            same_cfg_prov = (
                bool(cfg_prov_norm)
                and cfg_prov_norm not in ("auto", "default")
                and (
                    raw_provider == cfg_prov_norm
                    or (
                        _resolve_hermes_provider_id(raw_provider) is not None
                        and _resolve_hermes_provider_id(raw_provider) == _resolve_hermes_provider_id(cfg_prov_norm)
                    )
                )
            )
            if not same_cfg_prov:
                cfg_model = None
                cfg_base_url = None
                cfg_api_key = None
                cfg_key_env = None
        elif raw_provider != "ollama" and cfg_prov_norm in ("auto", "default"):
            cfg_model = None
            cfg_base_url = None

        hermes_provider_id = _resolve_hermes_provider_id(raw_provider)
        matched_custom = None
        if (
            raw_provider in _OPENAI_COMPAT_LOCAL_ALIASES
            or raw_provider.startswith("custom:")
            or (raw_provider not in ("ollama", *_DIRECT_REMOTE_ALIASES) and hermes_provider_id is None)
        ):
            matched_custom = _match_custom_provider_entry(cfg, raw_provider, cfg_base_url)
            if matched_custom is not None:
                if not cfg_base_url and matched_custom.get("base_url"):
                    cfg_base_url = matched_custom["base_url"]
                if not cfg_model and matched_custom.get("model"):
                    cfg_model = matched_custom["model"]

        if (
            raw_provider in _OPENAI_COMPAT_LOCAL_ALIASES
            or raw_provider.startswith("custom:")
            or matched_custom is not None
        ):
            resolved_provider = "openai_compatible"
        else:
            resolved_provider = raw_provider

        self._raw_provider = raw_provider
        self._explicit_codex_api_key = (
            codex_api_key.strip()
            if isinstance(codex_api_key, str) and _is_usable_secret(codex_api_key)
            else None
        )
        self._explicit_remote_base_url = (
            remote_base_url.strip()
            if isinstance(remote_base_url, str) and remote_base_url.strip()
            else None
        )
        self._explicit_remote_api_key = (
            remote_api_key.strip()
            if isinstance(remote_api_key, str) and _is_usable_secret(remote_api_key)
            else None
        )
        self._cfg_base_url = (
            str(cfg_base_url).strip()
            if isinstance(cfg_base_url, str) and str(cfg_base_url).strip()
            else None
        )
        self._cfg_api_key = (
            cfg_api_key.strip()
            if isinstance(cfg_api_key, str) and _is_usable_secret(cfg_api_key)
            else None
        )
        self._cfg_key_env = (
            str(cfg_key_env).strip()
            if isinstance(cfg_key_env, str) and str(cfg_key_env).strip()
            else None
        )
        self._custom_entry = matched_custom
        self.default_provider = resolved_provider

        # Resolve Ollama endpoint
        if ollama_base_url is not None:
            self.ollama_base_url = ollama_base_url.rstrip("/")
        elif cfg_base_url and (cfg_provider and str(cfg_provider).lower().strip() == "ollama"):
            endpoint = str(cfg_base_url)
            if endpoint.endswith("/v1"):
                endpoint = endpoint[:-3]
            self.ollama_base_url = endpoint.rstrip("/")
        elif cfg_base_url and self.default_provider == "ollama" and is_local_endpoint(str(cfg_base_url)):
            endpoint = str(cfg_base_url)
            if endpoint.endswith("/v1"):
                endpoint = endpoint[:-3]
            self.ollama_base_url = endpoint.rstrip("/")
        else:
            self.ollama_base_url = "http://127.0.0.1:11434"

        # Resolve model name
        raw_ollama_model = str(ollama_model or "").strip()
        raw_cfg_model = str(cfg_model or "").strip()
        self._has_explicit_model: bool = bool(raw_ollama_model)
        if resolved_provider == "ollama" and not raw_ollama_model and "/" in raw_cfg_model:
            # Global/Hermes configs may hold a cloud slug (e.g. "anthropic/claude-opus-4.6");
            # never adopt a remote provider/model slug as Ollama's active local tag.
            raw_cfg_model = ""
        resolved_model = str(raw_ollama_model or raw_cfg_model).strip()
        self._configured_model: Optional[str] = resolved_model or None
        self.ollama_model = resolved_model or "gemma4:12b"
        self.last_model_used: Optional[str] = None

        # Resolve OpenAI-compatible / local server endpoint (LM Studio, vLLM, Codex)
        self._has_explicit_codex_base_url = codex_base_url is not None
        if codex_base_url is not None:
            self.codex_base_url = codex_base_url
        elif cfg_base_url and self.default_provider in ("openai_compatible", "codex"):
            self.codex_base_url = str(cfg_base_url)
        elif raw_provider == "lmstudio":
            self.codex_base_url = _get_profile_scoped_secret("LM_BASE_URL") or "http://127.0.0.1:1234/v1"
        elif raw_provider in LOCAL_RUNTIME_DEFAULT_URLS:
            self.codex_base_url = LOCAL_RUNTIME_DEFAULT_URLS[raw_provider]
        elif raw_provider == "custom":
            self.codex_base_url = _get_profile_scoped_secret("CUSTOM_BASE_URL") or "http://127.0.0.1:8000/v1"
        else:
            self.codex_base_url = "http://127.0.0.1:8000/v1"

        self.codex_api_key = self._resolve_openai_compatible_api_key(
            provider_hint=raw_provider,
            target_url=self.codex_base_url,
        )
        self._initial_codex_api_key = self.codex_api_key

        # Resolve remote provider settings (OpenAI, Anthropic, OpenRouter, Remote, and Hermes runtime providers)
        if remote_base_url is not None:
            self.remote_base_url = remote_base_url
        elif cfg_base_url and self.default_provider in _DIRECT_REMOTE_ALIASES:
            self.remote_base_url = cfg_base_url
        elif self.default_provider == "openrouter":
            self.remote_base_url = _get_profile_scoped_secret("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
        elif self.default_provider == "anthropic":
            self.remote_base_url = _get_profile_scoped_secret("ANTHROPIC_BASE_URL") or "https://api.anthropic.com/v1"
        elif self.default_provider in ("openai", "remote", "api"):
            self.remote_base_url = _get_profile_scoped_secret("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        elif hermes_provider_id and hermes_provider_id not in _LLAMACPP_LOCAL_ALIASES:
            if cfg_base_url and not _is_foreign_builtin_endpoint(hermes_provider_id, str(cfg_base_url)):
                self.remote_base_url = str(cfg_base_url)
            else:
                self.remote_base_url = None
                try:
                    from hermes_cli.auth import PROVIDER_REGISTRY

                    pconfig = PROVIDER_REGISTRY.get(hermes_provider_id)
                    if pconfig is not None:
                        env_url = (
                            _get_profile_scoped_secret(pconfig.base_url_env_var)
                            if getattr(pconfig, "base_url_env_var", "")
                            else None
                        )
                        self.remote_base_url = env_url or pconfig.inference_base_url or pconfig.portal_base_url or None
                except Exception:
                    pass
        else:
            self.remote_base_url = None

        if remote_api_key is not None:
            self.remote_api_key = remote_api_key
        elif cfg_api_key and _is_usable_secret(str(cfg_api_key)):
            self.remote_api_key = str(cfg_api_key).strip()
        elif self._cfg_key_env and (self.default_provider in _DIRECT_REMOTE_ALIASES or hermes_provider_id is not None):
            self.remote_api_key = _get_profile_scoped_secret(self._cfg_key_env) or ""
        else:
            resolved_key = ""
            if hermes_provider_id is not None and self.default_provider not in _DIRECT_REMOTE_ALIASES:
                try:
                    from hermes_cli.auth import PROVIDER_REGISTRY

                    pconfig = PROVIDER_REGISTRY.get(hermes_provider_id)
                    if pconfig is not None and pconfig.auth_type == "api_key":
                        for var_name in getattr(pconfig, "api_key_env_vars", ()):
                            candidate = _get_profile_scoped_secret(var_name)
                            if candidate:
                                resolved_key = candidate
                                break
                except Exception:
                    pass
            if not resolved_key:
                if self.default_provider in ("openai", "anthropic", "openrouter"):
                    resolved_key = _get_profile_scoped_secret(f"{self.default_provider.upper()}_API_KEY") or ""
                elif self.default_provider in ("remote", "api"):
                    resolved_key = (
                        _get_profile_scoped_secret("REMOTE_API_KEY")
                        or _get_profile_scoped_secret("OPENAI_API_KEY")
                        or ""
                    )
            self.remote_api_key = resolved_key

        self.allow_remote = allow_remote
        self._initial_provider = resolved_provider
        self._runtime_override_url: Optional[str] = None
        self._discovered_local_urls: Dict[str, str] = {}
        self._gguf_runner = LocalGGUFRunner()

        cfg_voice = cfg.get("voice") if isinstance(cfg.get("voice"), dict) else {}
        cfg_dirs = cfg_voice.get("local_model_dirs") if isinstance(cfg_voice.get("local_model_dirs"), list) else []
        raw_dirs = local_model_dirs if local_model_dirs is not None else cfg_dirs
        self.local_model_dirs: List[str] = [str(d).strip() for d in raw_dirs if str(d or "").strip()]

    def close(self) -> None:
        """Stop any owned on-demand local runtime processes."""
        runner = getattr(self, "_gguf_runner", None)
        if runner is not None:
            runner.stop()

    def _resolve_openai_compatible_api_key(
        self,
        provider_hint: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> str:
        """Resolve bearer credential for an OpenAI-compatible endpoint via profile-scoped secrets."""
        if self._explicit_codex_api_key:
            return self._explicit_codex_api_key

        norm_target = (target_url or "").strip().rstrip("/")
        norm_cfg = (self._cfg_base_url or "").strip().rstrip("/")
        same_cfg_url = (not norm_cfg) or (norm_target == norm_cfg)

        if same_cfg_url and self._cfg_api_key:
            return self._cfg_api_key

        if same_cfg_url and self._cfg_key_env:
            scoped = _get_profile_scoped_secret(self._cfg_key_env)
            return scoped or "local"

        entry = self._custom_entry
        if isinstance(entry, dict):
            entry_url = str(entry.get("base_url") or "").strip().rstrip("/")
            if not entry_url or entry_url == norm_target:
                if entry.get("key_env"):
                    scoped = _get_profile_scoped_secret(entry["key_env"])
                    if scoped:
                        return scoped
                if entry.get("api_key") and _is_usable_secret(entry["api_key"]):
                    return str(entry["api_key"]).strip()
                if entry.get("declares_credential"):
                    return "local"

        # Guard against forwarding OpenAI/custom keys to rival built-in cloud domains
        if _host_matches_domain(target_url, "openrouter.ai"):
            return _get_profile_scoped_secret("OPENROUTER_API_KEY") or "local"
        if _host_matches_domain(target_url, "anthropic.com") or _host_matches_domain(target_url, "claude.com"):
            return _get_profile_scoped_secret("ANTHROPIC_API_KEY") or "local"

        hint = (provider_hint or self._raw_provider or "").strip().lower()
        env_candidates: List[str] = []
        if hint.startswith("custom:"):
            slug = "".join(ch if ch.isalnum() else "_" for ch in hint.split(":", 1)[1]).strip("_").upper()
            if slug:
                env_candidates.append(f"HERMES_CUSTOM_{slug}_API_KEY")
            env_candidates.append("CUSTOM_API_KEY")
        elif hint == "lmstudio":
            env_candidates.append("LM_API_KEY")
        elif hint == "vllm":
            env_candidates.append("VLLM_API_KEY")
        elif hint == "codex":
            env_candidates.append("CODEX_API_KEY")
        elif hint in ("custom", "openai_compatible"):
            env_candidates.append("CUSTOM_API_KEY")

        for var_name in env_candidates:
            scoped_val = _get_profile_scoped_secret(var_name)
            if scoped_val:
                return scoped_val

        openai_key = _get_profile_scoped_secret("OPENAI_API_KEY")
        if openai_key:
            env_openai_base = _get_profile_scoped_secret("OPENAI_BASE_URL")
            bound_origin = _url_origin_tuple(env_openai_base)
            target_origin = _url_origin_tuple(target_url)
            if bound_origin is None or (target_origin is not None and bound_origin == target_origin):
                return openai_key

        return "local"

    def set_allow_remote(self, allowed: bool) -> None:
        """Update explicit user authorization for remote network transmission."""
        self.allow_remote = bool(allowed)
        logger.info(f"Autorizzazione provider remoti aggiornata a: {self.allow_remote}")

    def set_model(self, model_name: str) -> None:
        """Explicitly switch the model used for question answering."""
        if model_name and model_name.strip():
            self.ollama_model = model_name.strip()
            self._configured_model = self.ollama_model
            self._has_explicit_model = True
            logger.info("Modello aggiornato a: %s", self.ollama_model)

    def set_local_model_dirs(self, dirs: List[str]) -> List[str]:
        """Replace the configured custom local GGUF/Unsloth directories."""
        cleaned: List[str] = []
        seen = set()
        for d in dirs or []:
            val = str(d or "").strip()
            if val and val not in seen:
                seen.add(val)
                cleaned.append(val)
        self.local_model_dirs = cleaned
        return list(self.local_model_dirs)

    def set_provider(self, provider_name: str, base_url: Optional[str] = None) -> None:
        """Explicitly switch the LLM provider used for question answering."""
        if not provider_name or not provider_name.strip():
            return
        raw = provider_name.strip().lower()
        self._raw_provider = raw
        if base_url and str(base_url).strip():
            self._runtime_override_url = str(base_url).strip()
        elif raw in self._discovered_local_urls:
            self._runtime_override_url = self._discovered_local_urls[raw]
        elif raw in LOCAL_RUNTIME_DEFAULT_URLS:
            self._runtime_override_url = LOCAL_RUNTIME_DEFAULT_URLS[raw]
        else:
            self._runtime_override_url = None

        if raw in _CODEX_OAUTH_ALIASES:
            self.default_provider = "openai-codex"
        elif raw in _OLLAMA_CLOUD_ALIASES:
            self.default_provider = "ollama-cloud"
        elif raw in _GGUF_LOCAL_ALIASES:
            self.default_provider = "gguf"
        elif raw in _OPENAI_COMPAT_LOCAL_ALIASES or raw.startswith("custom:"):
            self.default_provider = "openai_compatible"
        else:
            self.default_provider = raw
            if raw == "ollama" and base_url and str(base_url).strip():
                clean_ollama_url = str(base_url).strip().rstrip("/")
                if clean_ollama_url.endswith("/v1"):
                    clean_ollama_url = clean_ollama_url[:-3].rstrip("/")
                if is_local_endpoint(clean_ollama_url) or self.allow_remote:
                    self.ollama_base_url = clean_ollama_url
        if self.default_provider != "gguf" and getattr(self, "_gguf_runner", None) is not None:
            self._gguf_runner.stop()
        logger.info("Provider aggiornato a: %s (raw=%s)", self.default_provider, self._raw_provider)

    def is_active_endpoint_local(self) -> bool:
        """Return True if the currently selected provider + endpoint routes strictly to loopback/local disk."""
        prov = self.default_provider
        if prov == "gguf":
            return True
        if prov == "ollama":
            return is_local_endpoint(self.ollama_base_url)
        if prov == "openai_compatible":
            candidate = (
                self._runtime_override_url
                or self.codex_base_url
                or self._discovered_local_urls.get(self._raw_provider)
                or LOCAL_RUNTIME_DEFAULT_URLS.get(self._raw_provider)
                or "http://127.0.0.1:8000/v1"
            )
            return is_local_endpoint(str(candidate))
        if prov in _CODEX_OAUTH_ALIASES or prov in _OLLAMA_CLOUD_ALIASES or prov in ("openrouter", "openai", "anthropic", "remote", "api"):
            if prov in ("remote", "api") and self.remote_base_url:
                return is_local_endpoint(self.remote_base_url)
            if prov == self._initial_provider and self.remote_base_url:
                return is_local_endpoint(self.remote_base_url)
            return False
        # Named Hermes runtime provider (e.g. llamacpp, vllm, etc.)
        if self._runtime_override_url:
            return is_local_endpoint(self._runtime_override_url)
        if self._explicit_remote_base_url and (prov == self._initial_provider or self._raw_provider == self._initial_provider):
            return is_local_endpoint(self._explicit_remote_base_url)
        canonical = _resolve_hermes_provider_id(prov)
        if canonical in _LLAMACPP_LOCAL_ALIASES:
            cfg_local_url = (
                self._cfg_base_url
                if self._cfg_base_url and not _is_foreign_builtin_endpoint(canonical, self._cfg_base_url)
                else None
            )
            url = cfg_local_url or self._discovered_local_urls.get("llamacpp") or LOCAL_RUNTIME_DEFAULT_URLS["llamacpp"]
            return is_local_endpoint(url)
        return bool(self._cfg_base_url and is_local_endpoint(self._cfg_base_url))

    def select_installed_model(self) -> str:
        """Autodetect and select an installed Ollama model if the configured target model is missing."""
        if self.default_provider != "ollama":
            return self.ollama_model

        health = self.check_ollama_health()
        if health.get("status") == "online":
            available = health.get("available_models", [])
            if available:
                if not any(self.ollama_model in m for m in available):
                    logger.info(
                        "Modello configurato '%s' non trovato in Ollama. Selezione automatica del modello disponibile '%s'",
                        self.ollama_model,
                        available[0],
                    )
                    self.ollama_model = available[0]
        return self.ollama_model

    def check_ollama_health(self) -> Dict[str, Any]:
        """Verify Ollama server connection and list available models with retry resilience."""
        if not is_local_endpoint(self.ollama_base_url) and not self.allow_remote:
            return {
                "status": "remote_unauthorized",
                "error": "L'endpoint Ollama configurato è remoto e richiede il consenso esplicito dell'utente (allow_remote=True).",
                "available_models": [],
                "target_model_installed": False,
            }

        last_err = None
        for attempt in range(3):
            try:
                resp = requests.get(f"{self.ollama_base_url}/api/tags", timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    return {
                        "status": "online",
                        "available_models": models,
                        "target_model_installed": any(self.ollama_model in m for m in models),
                    }
                else:
                    last_err = f"HTTP {resp.status_code}"
            except Exception as e:
                last_err = str(e)
            if attempt < 2:
                time.sleep(0.5)

        return {"status": "offline", "error": last_err or "Unknown error", "available_models": []}

    def get_providers_status(self, refresh: bool = False) -> Dict[str, Any]:
        """Return status, discovered local runtimes/GGUFs, cloud free catalogs, and privacy posture."""
        with self._profile_scope():
            ollama_health = self.check_ollama_health()
            avail_ollama = ollama_health.get("available_models") or []
            if (
                self.default_provider == "ollama"
                and ollama_health.get("status") == "online"
                and avail_ollama
                and not getattr(self, "_has_explicit_model", True)
                and self.ollama_model not in avail_ollama
                and (self.ollama_model == "gemma4:12b" or "/" in str(self.ollama_model))
            ):
                self.ollama_model = str(avail_ollama[0])
                self._configured_model = self.ollama_model
            has_remote_key = bool(self.remote_api_key)
            hermes_id = _resolve_hermes_provider_id(self.default_provider)
            if not has_remote_key and self.default_provider in _DIRECT_REMOTE_ALIASES:
                if self.default_provider in ("remote", "api"):
                    has_remote_key = bool(
                        _get_profile_scoped_secret("REMOTE_API_KEY")
                        or _get_profile_scoped_secret("OPENAI_API_KEY")
                    )
                else:
                    has_remote_key = bool(
                        _get_profile_scoped_secret(f"{self.default_provider.upper()}_API_KEY")
                        or (hermes_id and _is_hermes_provider_configured_offline(hermes_id))
                    )
            elif not has_remote_key and hermes_id and hermes_id not in _LLAMACPP_LOCAL_ALIASES:
                has_remote_key = _is_hermes_provider_configured_offline(hermes_id)

            custom_local_eps: List[Dict[str, str]] = []
            if self.codex_base_url and is_local_endpoint(self.codex_base_url):
                custom_id = self._raw_provider if self._raw_provider in ("lmstudio", "vllm", "jan", "koboldcpp", "unsloth_studio") else "custom"
                custom_local_eps.append({"id": custom_id, "label": custom_id, "base_url": self.codex_base_url})
            if (
                getattr(self, "_runtime_override_url", None)
                and is_local_endpoint(str(self._runtime_override_url))
                and self.default_provider == "openai_compatible"
            ):
                override_id = self._raw_provider if self._raw_provider in ("lmstudio", "vllm", "jan", "koboldcpp", "unsloth_studio") else "custom"
                custom_local_eps.append({"id": override_id, "label": override_id, "base_url": str(self._runtime_override_url)})

            local_runtimes = discover_local_servers(custom_endpoints=custom_local_eps)
            for rid, info in local_runtimes.items():
                if info.get("status") == "online" and info.get("url"):
                    self._discovered_local_urls[rid] = str(info["url"])

            custom_dirs = list(getattr(self, "local_model_dirs", []) or [])
            scan_dirs = [str(p) for p in get_model_scan_dirs(extra_dirs=custom_dirs, include_missing=False)]
            gguf_models = scan_local_gguf_models(extra_dirs=custom_dirs)
            llama_bin_ready = bool(find_llama_server_binary())

            remote_refresh = bool(refresh and self.allow_remote)

            codex_oauth_configured = _is_hermes_provider_configured_offline("openai-codex")
            codex_oauth_models = _fetch_codex_oauth_catalog(
                refresh=remote_refresh and codex_oauth_configured
            )

            openrouter_key = _get_profile_scoped_secret("OPENROUTER_API_KEY") or ""
            openrouter_configured = bool(
                openrouter_key
                or _is_hermes_provider_configured_offline("openrouter")
                or (self.default_provider == "openrouter" and self.remote_api_key)
            )
            openrouter_cat = _fetch_openrouter_catalog(refresh=remote_refresh)

            ollama_cloud_key = _get_profile_scoped_secret("OLLAMA_API_KEY") or ""
            ollama_cloud_configured = bool(
                ollama_cloud_key
                or _is_hermes_provider_configured_offline("ollama-cloud")
                or (self.default_provider == "ollama-cloud" and self.remote_api_key)
            )
            ollama_cloud_models = _fetch_ollama_cloud_catalog(
                api_key=ollama_cloud_key,
                refresh=remote_refresh and ollama_cloud_configured,
            )

            openai_configured = bool(
                _get_profile_scoped_secret("OPENAI_API_KEY")
                or _is_hermes_provider_configured_offline("openai-api")
                or (self.default_provider in ("openai", "remote", "api") and self.remote_api_key)
            )
            anthropic_configured = bool(
                _get_profile_scoped_secret("ANTHROPIC_API_KEY")
                or _is_hermes_provider_configured_offline("anthropic")
                or (self.default_provider == "anthropic" and self.remote_api_key)
            )

            remote_configured = bool(
                (self.remote_base_url and has_remote_key)
                or (hermes_id and hermes_id not in _LLAMACPP_LOCAL_ALIASES and has_remote_key)
                or codex_oauth_configured
                or openrouter_configured
                or ollama_cloud_configured
                or openai_configured
                or anthropic_configured
            )
            return {
                "default_provider": self.default_provider,
                "raw_provider": getattr(self, "_raw_provider", self.default_provider),
                "allow_remote": self.allow_remote,
                "ollama": {
                    "url": self.ollama_base_url,
                    "model": self.ollama_model,
                    "status": ollama_health.get("status", "unknown"),
                    "models": ollama_health.get("available_models", []),
                    "is_local": is_local_endpoint(self.ollama_base_url),
                    "authorized": self.allow_remote or is_local_endpoint(self.ollama_base_url),
                },
                "codex": {
                    "configured": bool(self.codex_base_url),
                    "url": self.codex_base_url or "http://127.0.0.1:8000/v1",
                    "is_local": is_local_endpoint(self.codex_base_url or "http://127.0.0.1:8000/v1"),
                },
                "remote_api": {
                    "configured": remote_configured,
                    "url": self.remote_base_url,
                    "is_local": False,
                    "authorized": self.allow_remote,
                },
                "local_runtimes": local_runtimes,
                "local_gguf": {
                    "scan_dirs": scan_dirs,
                    "custom_dirs": custom_dirs,
                    "llama_server_available": llama_bin_ready,
                    "models": gguf_models,
                },
                "codex_oauth": {
                    "configured": codex_oauth_configured,
                    "auth_mode": "chatgpt",
                    "models": codex_oauth_models,
                    "is_local": False,
                    "authorized": self.allow_remote,
                },
                "cloud_providers": {
                    "openrouter": {
                        "configured": openrouter_configured,
                        "free_models": openrouter_cat.get("free_models", []),
                        "models": openrouter_cat.get("models", []),
                        "is_local": False,
                        "authorized": self.allow_remote,
                    },
                    "ollama_cloud": {
                        "configured": ollama_cloud_configured,
                        "models": ollama_cloud_models,
                        "is_local": False,
                        "authorized": self.allow_remote,
                    },
                    "openai": {
                        "configured": openai_configured,
                        "models": ["gpt-4o-mini", "gpt-4.1", "gpt-5.4-mini", "gpt-5.4"],
                        "is_local": False,
                        "authorized": self.allow_remote,
                    },
                    "anthropic": {
                        "configured": anthropic_configured,
                        "models": [
                            "claude-3-5-sonnet-20241022",
                            "claude-haiku-4-5-20251001",
                            "claude-sonnet-4-6",
                        ],
                        "is_local": False,
                        "authorized": self.allow_remote,
                    },
                },
            }

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.2,
    ) -> str:
        """Generate response via selected provider while enforcing privacy controls."""
        with self._profile_scope():
            return self._generate_scoped(
                prompt=prompt,
                system_prompt=system_prompt,
                provider=provider,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

    def _generate_scoped(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.2,
    ) -> str:
        selected_provider = (provider or self.default_provider).lower().strip()

        if selected_provider == "ollama":
            if not is_local_endpoint(self.ollama_base_url) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint Ollama '{self.ollama_base_url}' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Abilitare esplicitamente allow_remote con il consenso dell'utente."
                )
            target_model = model or self.select_installed_model()
            self.last_model_used = target_model
            return self._call_ollama(
                prompt=prompt,
                system_prompt=system_prompt,
                model=target_model,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        if selected_provider in _GGUF_LOCAL_ALIASES:
            requested_ref = str(model or self.ollama_model or "").strip()
            candidate_path = Path(requested_ref).expanduser() if requested_ref else None
            if not candidate_path or not candidate_path.is_file():
                # Look up by model_id or name in scanned GGUFs
                matches = scan_local_gguf_models(extra_dirs=getattr(self, "local_model_dirs", []))
                found = next(
                    (
                        m for m in matches
                        if requested_ref in (m.get("id"), m.get("path"), m.get("model_id"), m.get("name"), m.get("file_name"))
                    ),
                    None,
                )
                if found:
                    candidate_path = Path(found["path"])
            if not candidate_path or not candidate_path.is_file():
                raise FileNotFoundError(
                    f"Modello GGUF '{requested_ref}' non trovato nelle cartelle locali configurate."
                )
            base_url, served_model = self._gguf_runner.ensure_running(candidate_path)
            self.last_model_used = candidate_path.stem
            return self._call_openai_compatible(
                base_url=base_url,
                api_key="local",
                model=served_model,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        elif (
            selected_provider in _OPENAI_COMPAT_LOCAL_ALIASES
            or selected_provider.startswith("custom:")
        ):
            raw_hint = (provider or self._raw_provider or selected_provider).lower().strip()
            if self._runtime_override_url and raw_hint == self._raw_provider:
                target_url = self._runtime_override_url
            elif self._has_explicit_codex_base_url or raw_hint == self._initial_provider or raw_hint in ("codex", "custom", "openai_compatible"):
                target_url = self.codex_base_url or LOCAL_RUNTIME_DEFAULT_URLS.get(raw_hint, "http://127.0.0.1:8000/v1")
            else:
                target_url = (
                    self._discovered_local_urls.get(raw_hint)
                    or LOCAL_RUNTIME_DEFAULT_URLS.get(raw_hint)
                    or self.codex_base_url
                    or "http://127.0.0.1:8000/v1"
                )
            if not is_local_endpoint(target_url) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint '{target_url}' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Abilitare esplicitamente allow_remote con il consenso dell'utente."
                )

            if self.codex_api_key != getattr(self, "_initial_codex_api_key", self.codex_api_key):
                effective_key = self.codex_api_key
            else:
                effective_key = self._resolve_openai_compatible_api_key(
                    provider_hint=provider or self._raw_provider or selected_provider,
                    target_url=target_url,
                )

            target_model = model or self.ollama_model or "local-model"
            self.last_model_used = target_model
            return self._call_openai_compatible(
                base_url=target_url,
                api_key=effective_key or "local",
                model=target_model,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        elif selected_provider in _DIRECT_REMOTE_ALIASES:
            if not self.allow_remote:
                raise PermissionError(
                    "VIOLAZIONE VINCOLO PRIVACY: L'invio di dati documentali a provider remoti "
                    "è bloccato per impostazione predefinita. Per abilitarlo, impostare esplicitamente "
                    "allow_remote=True con il consenso dell'utente."
                )

            use_explicit_remote = (
                self.remote_base_url
                and (
                    selected_provider in ("remote", "api")
                    or selected_provider == self._initial_provider
                    or (selected_provider == "openrouter" and _host_matches_domain(self.remote_base_url, "openrouter.ai"))
                    or (selected_provider == "anthropic" and _host_matches_domain(self.remote_base_url, "anthropic.com"))
                    or (selected_provider == "openai" and _host_matches_domain(self.remote_base_url, "openai.com"))
                )
            )
            target_url = self.remote_base_url if use_explicit_remote else None
            if not target_url:
                if selected_provider == "openrouter":
                    target_url = _get_profile_scoped_secret("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
                elif selected_provider == "anthropic":
                    target_url = _get_profile_scoped_secret("ANTHROPIC_BASE_URL") or "https://api.anthropic.com/v1"
                else:
                    target_url = _get_profile_scoped_secret("OPENAI_BASE_URL") or "https://api.openai.com/v1"

            target_key = ""
            allow_explicit_key = bool(
                use_explicit_remote
                or (
                    self._explicit_remote_api_key
                    and (
                        selected_provider == self._initial_provider
                        or (
                            selected_provider in ("remote", "api")
                            and self._initial_provider in ("remote", "api", "ollama", "openai")
                        )
                    )
                )
                or (
                    self._initial_provider == "ollama"
                    and not self.remote_base_url
                    and selected_provider in ("remote", "api", "openai")
                )
            )
            if self.remote_api_key and allow_explicit_key:
                target_key = self.remote_api_key

            if not target_key:
                prov_key = f"{selected_provider.upper()}_API_KEY" if selected_provider else None
                if prov_key:
                    target_key = _get_profile_scoped_secret(prov_key) or ""
                if not target_key and selected_provider in ("remote", "api"):
                    target_key = (
                        _get_profile_scoped_secret("REMOTE_API_KEY")
                        or _get_profile_scoped_secret("OPENAI_API_KEY")
                        or ""
                    )

            if not target_key and selected_provider in ("openai", "anthropic", "openrouter"):
                canonical_direct = _resolve_hermes_provider_id(selected_provider)
                if canonical_direct and _is_hermes_provider_configured_offline(canonical_direct):
                    return self._call_hermes_runtime_provider(
                        provider_name=selected_provider,
                        canonical_provider=canonical_direct,
                        prompt=prompt,
                        system_prompt=system_prompt,
                        model=model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                raise ValueError(
                    f"Nessuna credenziale trovata per il provider '{selected_provider}'. "
                    f"Configurare {selected_provider.upper()}_API_KEY nel profilo per procedere."
                )

            target_model = model or self.ollama_model
            is_local_placeholder = (
                not target_model
                or target_model == "gemma4:12b"
                or str(target_model).lower().endswith(".gguf")
            )
            if is_local_placeholder:
                if selected_provider == "anthropic":
                    target_model = "claude-3-5-sonnet-20241022"
                elif selected_provider == "openrouter":
                    target_model = _OPENROUTER_FREE_FALLBACK[0]
                else:
                    target_model = "gpt-4o-mini"

            self.last_model_used = target_model
            if selected_provider == "anthropic" or "anthropic.com" in target_url:
                return self._call_anthropic(
                    base_url=target_url,
                    api_key=target_key,
                    model=target_model,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

            return self._call_openai_compatible(
                base_url=target_url,
                api_key=target_key,
                model=target_model,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        elif selected_provider in _OLLAMA_CLOUD_ALIASES:
            if not self.allow_remote:
                raise PermissionError(
                    "VIOLAZIONE VINCOLO PRIVACY: Il provider 'ollama-cloud' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Per abilitarlo, impostare esplicitamente allow_remote=True con il consenso dell'utente."
                )
            allow_ollama_cloud_explicit = bool(
                self._explicit_remote_api_key
                and (
                    self._initial_provider in _OLLAMA_CLOUD_ALIASES
                    or _host_matches_domain(self.remote_base_url or "", "ollama.com")
                )
            )
            cloud_key = _get_profile_scoped_secret("OLLAMA_API_KEY") or (
                self._explicit_remote_api_key if allow_ollama_cloud_explicit else ""
            ) or ""
            target_model = model or self.ollama_model
            if not target_model or target_model == "gemma4:12b" or str(target_model).lower().endswith(".gguf"):
                target_model = _OLLAMA_CLOUD_FALLBACK[0]
            try:
                return self._call_hermes_runtime_provider(
                    provider_name="ollama-cloud",
                    canonical_provider="ollama-cloud",
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=target_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    explicit_base_url=_get_profile_scoped_secret("OLLAMA_BASE_URL") or "https://ollama.com/v1",
                )
            except Exception as exc:
                if cloud_key:
                    cloud_url = _get_profile_scoped_secret("OLLAMA_BASE_URL") or "https://ollama.com/v1"
                    self.last_model_used = target_model
                    return self._call_openai_compatible(
                        base_url=cloud_url,
                        api_key=cloud_key,
                        model=target_model,
                        prompt=prompt,
                        system_prompt=system_prompt,
                        temperature=temperature,
                    )
                raise exc

        else:
            canonical_hermes = _resolve_hermes_provider_id(selected_provider)
            if canonical_hermes is not None:
                is_active_selection = (
                    selected_provider == self.default_provider
                    or selected_provider == self._raw_provider
                    or canonical_hermes == _resolve_hermes_provider_id(self.default_provider)
                )
                override_url = self._runtime_override_url if (is_active_selection and self._runtime_override_url) else None
                candidate_url = (
                    override_url
                    or (
                        self._explicit_remote_base_url
                        if self._explicit_remote_base_url and selected_provider == self.default_provider
                        else (
                            self._cfg_base_url
                            if self._cfg_base_url
                            and is_active_selection
                            and not _is_foreign_builtin_endpoint(canonical_hermes, self._cfg_base_url)
                            else None
                        )
                    )
                )
                default_local_check = (
                    self._discovered_local_urls.get("llamacpp") or LOCAL_RUNTIME_DEFAULT_URLS["llamacpp"]
                    if canonical_hermes in _LLAMACPP_LOCAL_ALIASES
                    else None
                )
                effective_url = candidate_url or default_local_check
                is_local_runtime = bool(effective_url and is_local_endpoint(effective_url))
                if not is_local_runtime and not self.allow_remote:
                    raise PermissionError(
                        f"VIOLAZIONE VINCOLO PRIVACY: Il provider '{selected_provider}' è remoto. "
                        "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                        "Per abilitarlo, impostare esplicitamente allow_remote=True con il consenso dell'utente."
                    )
                try:
                    return self._call_hermes_runtime_provider(
                        provider_name=selected_provider,
                        canonical_provider=canonical_hermes,
                        prompt=prompt,
                        system_prompt=system_prompt,
                        model=model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        explicit_base_url=candidate_url,
                    )
                except RuntimeError as exc:
                    # Standalone fallback for running local llama.cpp server when Hermes core is absent
                    if canonical_hermes in _LLAMACPP_LOCAL_ALIASES:
                        fallback_url = (
                            candidate_url
                            or self._discovered_local_urls.get("llamacpp")
                            or LOCAL_RUNTIME_DEFAULT_URLS["llamacpp"]
                        )
                        if not is_local_endpoint(fallback_url) and not self.allow_remote:
                            raise PermissionError(
                                f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint '{fallback_url}' per il provider '{selected_provider}' è remoto. "
                                "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
                            )
                        target_model = model or self.ollama_model or "local-model"
                        self.last_model_used = target_model
                        return self._call_openai_compatible(
                            base_url=fallback_url,
                            api_key="local",
                            model=target_model,
                            prompt=prompt,
                            system_prompt=system_prompt,
                            temperature=temperature,
                        )
                    raise exc

            raise ValueError(f"Provider sconosciuto: {selected_provider}")

    def _call_codex_cli_exec(
        self,
        *,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
    ) -> str:
        """Execute a one-shot query via the official `codex exec` CLI using Codex's own auth session."""
        if not self.allow_remote:
            raise PermissionError(
                "VIOLAZIONE VINCOLO PRIVACY: ChatGPT Codex CLI usa endpoint remoti OpenAI/ChatGPT. "
                "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
            )
        codex_bin = shutil.which("codex")
        if not codex_bin:
            raise RuntimeError("Binario `codex` CLI non trovato nel PATH.")

        target_model = str(model or "gpt-5.4").strip()
        if not target_model or target_model == "gemma4:12b" or target_model.lower().endswith(".gguf"):
            target_model = "gpt-5.4"

        combined_prompt = (
            f"Istruzioni di sistema:\n{system_prompt.strip()}\n\nRichiesta:\n{prompt}"
            if system_prompt and system_prompt.strip()
            else prompt
        )

        with tempfile.TemporaryDirectory(prefix="hv_codex_") as tmpdir:
            out_file = Path(tmpdir) / "last_message.txt"
            cmd = [
                codex_bin,
                "exec",
                "-s", "read-only",
                "--ephemeral",
                "--skip-git-repo-check",
                "--ignore-user-config",
                "--ignore-rules",
                "-C", tmpdir,
                "-o", str(out_file),
                "-m", target_model,
                "-",
            ]
            proc = subprocess.run(
                cmd,
                input=combined_prompt,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=max(30, int(getattr(self, "timeout", 120) or 120)),
            )
            if proc.returncode != 0:
                err_msg = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
                raise RuntimeError(f"Errore Codex CLI (`codex exec`): {err_msg[:300]}")
            text = out_file.read_text(encoding="utf-8").strip() if out_file.is_file() else (proc.stdout or "").strip()
            self.last_model_used = target_model
            return text

    def _call_hermes_runtime_provider(
        self,
        provider_name: str,
        canonical_provider: str,
        prompt: str,
        system_prompt: Optional[str],
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        explicit_base_url: Optional[str] = None,
    ) -> str:
        """Execute generation via Hermes's official provider runtime (API key / OAuth / cloud SDK)."""
        try:
            from agent import auxiliary_client as aux_mod
        except (ImportError, ModuleNotFoundError) as exc:
            raise RuntimeError(
                f"Il runtime del provider '{provider_name}' non è disponibile senza i moduli core di Hermes."
            ) from exc

        same_default = (
            provider_name == self.default_provider
            or canonical_provider == _resolve_hermes_provider_id(self.default_provider)
        )
        requested_model = model or (self._configured_model if same_default else None)
        if canonical_provider in ("openai-codex", "ollama-cloud", "openrouter") and (
            not requested_model
            or requested_model == "gemma4:12b"
            or str(requested_model).lower().endswith(".gguf")
        ):
            if canonical_provider == "openai-codex":
                requested_model = (_fetch_codex_oauth_catalog(refresh=False) or _CODEX_MODELS_FALLBACK)[0]
            elif canonical_provider == "ollama-cloud":
                requested_model = _OLLAMA_CLOUD_FALLBACK[0]
            elif canonical_provider == "openrouter":
                requested_model = _OPENROUTER_FREE_FALLBACK[0]

        explicit_key: Optional[str] = None
        if same_default:
            if self._explicit_remote_api_key:
                explicit_key = self._explicit_remote_api_key
            elif self._cfg_api_key:
                explicit_key = self._cfg_api_key
            elif self._cfg_key_env:
                explicit_key = _get_profile_scoped_secret(self._cfg_key_env)

        client, resolved_model = aux_mod.resolve_provider_client(
            canonical_provider or provider_name,
            model=requested_model,
            explicit_base_url=explicit_base_url,
            explicit_api_key=explicit_key,
        )
        if client is None and canonical_provider == "openai-codex" and _is_codex_cli_logged_in():
            return self._call_codex_cli_exec(
                prompt=prompt,
                system_prompt=system_prompt,
                model=requested_model,
            )
        if client is None:
            raise ValueError(
                f"Nessuna credenziale valida trovata per il provider '{provider_name}'. "
                "Configurare l'autenticazione ufficiale del provider in Hermes (`hermes auth` / `hermes model`) o accedere con `codex login`."
            )

        client_base_url = str(getattr(client, "base_url", "") or explicit_base_url or "")
        if (
            client_base_url.startswith(("http://", "https://"))
            and not is_local_endpoint(client_base_url)
            and not self.allow_remote
        ):
            raise PermissionError(
                f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint '{client_base_url}' per il provider '{provider_name}' è remoto. "
                "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
            )

        final_model = str(resolved_model or requested_model or "").strip()
        if not final_model:
            raise ValueError(
                f"Nessun modello configurato o risolto per il provider '{provider_name}'."
            )

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        codex_cls = getattr(aux_mod, "CodexAuxiliaryClient", ())
        no_progress_timeout = (
            aux_mod._get_task_no_progress_timeout(None)
            if codex_cls and isinstance(client, codex_cls)
            else None
        )
        call_kwargs = aux_mod._build_call_kwargs(
            canonical_provider,
            final_model,
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=60.0,
            base_url=client_base_url or None,
            no_progress_timeout=no_progress_timeout,
        )
        response = client.chat.completions.create(**call_kwargs)
        validated = aux_mod._validate_llm_response(
            response,
            task="voice_document_qa",
            provider=canonical_provider,
            base_url=client_base_url or None,
        )
        self.last_model_used = final_model
        msg = validated.choices[0].message
        content = getattr(msg, "content", None)
        if isinstance(content, list):
            parts = [
                b.get("text", "") if isinstance(b, dict) else str(getattr(b, "text", ""))
                for b in content
            ]
            return "".join(parts).strip()
        return str(content or "").strip()

    def _call_ollama(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        temperature: float,
        max_tokens: int = 400,
    ) -> str:
        """Call local Ollama instance with think:false to suppress reasoning delay."""
        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        url = f"{self.ollama_base_url}/api/generate"
        try:
            t0 = time.perf_counter()
            resp = requests.post(url, json=payload, timeout=180.0, allow_redirects=False)
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                redirect_target = urljoin(url, resp.headers.get("Location", ""))
                orig_parsed = urlparse(url)
                target_parsed = urlparse(redirect_target)
                orig_origin = (orig_parsed.scheme.lower(), orig_parsed.netloc.lower())
                target_origin = (target_parsed.scheme.lower(), target_parsed.netloc.lower())

                if not is_local_endpoint(redirect_target) and not self.allow_remote:
                    raise PermissionError(
                        f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint Ollama ha tentato un reindirizzamento remoto verso '{redirect_target}'. "
                        "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
                    )
                if orig_origin != target_origin and not self.allow_remote:
                    raise PermissionError(
                        f"Reindirizzamento verso un host diverso '{target_parsed.netloc}' bloccato in modalità locale."
                    )
                resp = requests.post(redirect_target, json=payload, timeout=180.0, allow_redirects=False)

            elapsed = time.perf_counter() - t0

            if resp.status_code != 200:
                raise RuntimeError(f"Ollama API errore {resp.status_code}: {resp.text}")

            result = resp.json()
            response_text = result.get("response", "").strip()

            # Fallback if reasoning model emitted thoughts
            if not response_text and result.get("thinking"):
                thinking = result.get("thinking", "").strip()
                lines = [line.strip().strip('"') for line in thinking.splitlines() if line.strip()]
                if lines:
                    response_text = lines[-1]

            eval_count = result.get("eval_count", 0)
            eval_dur_s = (result.get("eval_duration", 0) / 1e9)
            tok_per_sec = (eval_count / eval_dur_s) if eval_dur_s > 0 else 0.0

            logger.info(
                f"Ollama ({model}) completato in {elapsed:.2f}s "
                f"({eval_count} token, {tok_per_sec:.2f} t/s)"
            )
            return response_text

        except requests.ConnectionError:
            raise ConnectionError(
                f"Impossibile connettersi ad Ollama su {url}. "
                "Assicurarsi che Ollama sia in esecuzione ('ollama serve')."
            )

    def _call_openai_compatible(
        self,
        base_url: str,
        api_key: str,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
    ) -> str:
        """Call any OpenAI-compatible API endpoint."""
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=60.0, allow_redirects=False)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            redirect_target = urljoin(url, resp.headers.get("Location", ""))
            orig_parsed = urlparse(url)
            target_parsed = urlparse(redirect_target)
            orig_origin = (orig_parsed.scheme.lower(), orig_parsed.netloc.lower())
            target_origin = (target_parsed.scheme.lower(), target_parsed.netloc.lower())

            if not is_local_endpoint(redirect_target) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint ha tentato un reindirizzamento remoto verso '{redirect_target}'. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
                )
            if orig_origin != target_origin:
                raise PermissionError(
                    f"Reindirizzamento verso un'origine diversa '{target_parsed.netloc}' bloccato per prevenire "
                    "la diffusione di credenziali di autorizzazione e contenuti documentali."
                )
            resp = requests.post(redirect_target, headers=headers, json=payload, timeout=60.0, allow_redirects=False)
        if resp.status_code != 200:
            raise RuntimeError(f"API Error {resp.status_code}: {resp.text}")

        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()

    def _call_anthropic(
        self,
        base_url: str,
        api_key: str,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int = 1024,
    ) -> str:
        """Call Anthropic native Messages API endpoint."""
        clean_url = base_url.rstrip("/")
        if clean_url.endswith("/messages"):
            url = clean_url
        elif clean_url.endswith("/v1"):
            url = f"{clean_url}/messages"
        else:
            url = f"{clean_url}/v1/messages"

        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        payload: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }
        if system_prompt:
            payload["system"] = system_prompt

        resp = requests.post(url, headers=headers, json=payload, timeout=60.0, allow_redirects=False)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            redirect_target = urljoin(url, resp.headers.get("Location", ""))
            orig_parsed = urlparse(url)
            target_parsed = urlparse(redirect_target)
            orig_origin = (orig_parsed.scheme.lower(), orig_parsed.netloc.lower())
            target_origin = (target_parsed.scheme.lower(), target_parsed.netloc.lower())

            if not is_local_endpoint(redirect_target) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint ha tentato un reindirizzamento remoto verso '{redirect_target}'. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita."
                )
            if orig_origin != target_origin:
                raise PermissionError(
                    f"Reindirizzamento verso un'origine diversa '{target_parsed.netloc}' bloccato per prevenire "
                    "la diffusione di credenziali di autorizzazione e contenuti documentali."
                )
            resp = requests.post(redirect_target, headers=headers, json=payload, timeout=60.0, allow_redirects=False)

        if resp.status_code != 200:
            raise RuntimeError(f"Anthropic API Error {resp.status_code}: {resp.text}")

        data = resp.json()
        content = data.get("content", [])
        if isinstance(content, list):
            text_parts = [
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            return "".join(text_parts).strip()
        elif isinstance(content, str):
            return content.strip()
        return ""
