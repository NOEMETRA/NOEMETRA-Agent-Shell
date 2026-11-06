"""Model router supporting local Ollama (default), Codex, and optional remote APIs.

Strict constraint: Local-first by default.
No document data is sent to remote endpoints without explicit user consent.
This applies to Ollama, Codex, and all OpenAI-compatible / remote providers.
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse
import requests

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
        if default_provider is not None:
            raw_provider = default_provider.lower().strip()
        elif cfg_provider and str(cfg_provider).lower().strip() not in ("auto", "default", ""):
            raw_provider = str(cfg_provider).lower().strip()
        else:
            raw_provider = "ollama"

        matched_custom = None
        if raw_provider not in ("ollama", "remote", "api", "openai", "anthropic", "openrouter"):
            matched_custom = _match_custom_provider_entry(cfg, raw_provider, cfg_base_url)
            if matched_custom is not None:
                if not cfg_base_url and matched_custom.get("base_url"):
                    cfg_base_url = matched_custom["base_url"]
                if not cfg_model and matched_custom.get("model"):
                    cfg_model = matched_custom["model"]

        if (
            raw_provider in ("custom", "lmstudio", "vllm", "openai_compatible", "codex")
            or raw_provider.startswith("custom:")
            or matched_custom is not None
        ):
            resolved_provider = "openai_compatible"
        elif raw_provider not in ("remote", "api", "openai", "anthropic", "openrouter"):
            resolved_provider = "ollama"
        else:
            resolved_provider = raw_provider

        self._raw_provider = raw_provider
        self._explicit_codex_api_key = (
            codex_api_key.strip()
            if isinstance(codex_api_key, str) and _is_usable_secret(codex_api_key)
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
        resolved_model = str(ollama_model or cfg_model or "").strip()
        self.ollama_model = resolved_model or "gemma4:12b"

        # Resolve OpenAI-compatible / local server endpoint (LM Studio, vLLM, Codex)
        if codex_base_url is not None:
            self.codex_base_url = codex_base_url
        elif cfg_base_url and self.default_provider in ("openai_compatible", "codex"):
            self.codex_base_url = str(cfg_base_url)
        elif raw_provider == "lmstudio":
            self.codex_base_url = _get_profile_scoped_secret("LM_BASE_URL") or "http://127.0.0.1:1234/v1"
        elif raw_provider == "custom":
            self.codex_base_url = _get_profile_scoped_secret("CUSTOM_BASE_URL") or "http://127.0.0.1:8000/v1"
        else:
            self.codex_base_url = "http://127.0.0.1:8000/v1"

        self.codex_api_key = self._resolve_openai_compatible_api_key(
            provider_hint=raw_provider,
            target_url=self.codex_base_url,
        )
        self._initial_codex_api_key = self.codex_api_key

        # Resolve remote provider settings (OpenAI, Anthropic, OpenRouter, Remote)
        if remote_base_url is not None:
            self.remote_base_url = remote_base_url
        elif cfg_base_url and self.default_provider in ("remote", "api", "openai", "anthropic", "openrouter"):
            self.remote_base_url = cfg_base_url
        elif self.default_provider == "openrouter":
            self.remote_base_url = _get_profile_scoped_secret("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
        elif self.default_provider == "anthropic":
            self.remote_base_url = _get_profile_scoped_secret("ANTHROPIC_BASE_URL") or "https://api.anthropic.com/v1"
        elif self.default_provider in ("openai", "remote", "api"):
            self.remote_base_url = _get_profile_scoped_secret("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        else:
            self.remote_base_url = None

        if remote_api_key is not None:
            self.remote_api_key = remote_api_key
        elif cfg_api_key:
            self.remote_api_key = cfg_api_key
        else:
            prov_key = f"{self.default_provider.upper()}_API_KEY" if self.default_provider else None
            if prov_key and prov_key not in ("OLLAMA_API_KEY", "OPENAI_COMPATIBLE_API_KEY"):
                self.remote_api_key = _get_profile_scoped_secret(prov_key) or ""
            elif self.default_provider in ("remote", "api"):
                self.remote_api_key = (
                    _get_profile_scoped_secret("REMOTE_API_KEY")
                    or _get_profile_scoped_secret("OPENAI_API_KEY")
                    or ""
                )
            else:
                self.remote_api_key = ""

        self.allow_remote = allow_remote

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
        """Explicitly switch the local model used for question answering."""
        if model_name and model_name.strip():
            self.ollama_model = model_name.strip()
            logger.info("Modello Ollama aggiornato a: %s", self.ollama_model)

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

    def get_providers_status(self) -> Dict[str, Any]:
        """Return status and privacy posture for all configured providers."""
        with self._profile_scope():
            ollama_health = self.check_ollama_health()
            has_remote_key = bool(self.remote_api_key)
            if not has_remote_key and self.default_provider in ("openai", "anthropic", "openrouter", "remote", "api"):
                if self.default_provider in ("remote", "api"):
                    has_remote_key = bool(
                        _get_profile_scoped_secret("REMOTE_API_KEY")
                        or _get_profile_scoped_secret("OPENAI_API_KEY")
                    )
                else:
                    has_remote_key = bool(_get_profile_scoped_secret(f"{self.default_provider.upper()}_API_KEY"))
            return {
                "default_provider": self.default_provider,
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
                    "configured": bool(self.remote_base_url and has_remote_key),
                    "url": self.remote_base_url,
                    "is_local": False,
                    "authorized": self.allow_remote,
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
        selected_provider = (provider or self.default_provider).lower()

        if selected_provider == "ollama":
            if not is_local_endpoint(self.ollama_base_url) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint Ollama '{self.ollama_base_url}' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Abilitare esplicitamente allow_remote con il consenso dell'utente."
                )
            target_model = model or self.select_installed_model()
            return self._call_ollama(
                prompt=prompt,
                system_prompt=system_prompt,
                model=target_model,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        elif (
            selected_provider in ("codex", "openai_compatible", "custom", "lmstudio", "vllm")
            or selected_provider.startswith("custom:")
        ):
            target_url = self.codex_base_url or "http://127.0.0.1:8000/v1"
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

            return self._call_openai_compatible(
                base_url=target_url,
                api_key=effective_key or "local",
                model=model or self.ollama_model or "local-model",
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        elif selected_provider in ("remote", "api", "openai", "anthropic", "openrouter"):
            if not self.allow_remote:
                raise PermissionError(
                    "VIOLAZIONE VINCOLO PRIVACY: L'invio di dati documentali a provider remoti "
                    "è bloccato per impostazione predefinita. Per abilitarlo, impostare esplicitamente "
                    "allow_remote=True con il consenso dell'utente."
                )

            target_url = self.remote_base_url
            if not target_url:
                if selected_provider == "openrouter":
                    target_url = "https://openrouter.ai/api/v1"
                elif selected_provider == "anthropic":
                    target_url = "https://api.anthropic.com/v1"
                else:
                    target_url = "https://api.openai.com/v1"

            target_key = ""
            if self.remote_api_key and self.default_provider in (selected_provider, "remote", "api"):
                target_key = self.remote_api_key
            elif self.remote_api_key and self.default_provider == "ollama":
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
                raise ValueError(
                    f"Nessuna credenziale trovata per il provider '{selected_provider}'. "
                    f"Configurare {selected_provider.upper()}_API_KEY nel profilo per procedere."
                )

            target_model = model or self.ollama_model
            if not target_model or target_model == "gemma4:12b":
                if selected_provider == "anthropic":
                    target_model = "claude-3-5-sonnet-20241022"
                elif selected_provider == "openrouter":
                    target_model = "anthropic/claude-3.5-sonnet"
                else:
                    target_model = "gpt-4o-mini"

            if selected_provider == "anthropic" or "anthropic.com" in target_url:
                return self._call_anthropic(
                    base_url=target_url,
                    api_key=target_key,
                    model=target_model,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                )

            return self._call_openai_compatible(
                base_url=target_url,
                api_key=target_key,
                model=target_model,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        else:
            raise ValueError(f"Provider sconosciuto: {selected_provider}")

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
