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
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import requests

logger = logging.getLogger(__name__)


def is_local_endpoint(url: str) -> bool:
    """Check if URL targets loopback/localhost."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host in ("127.0.0.1", "localhost", "0.0.0.0", "::1")
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
    ):
        # Resolve model, provider and endpoint from hermes config if not explicitly provided
        cfg_model = None
        cfg_provider = None
        cfg_base_url = None
        cfg_api_key = None
        try:
            from hermes_cli.config import load_config
            cfg = load_config()
            model_cfg = cfg.get("model")
            if isinstance(model_cfg, dict):
                cfg_model = model_cfg.get("default") or model_cfg.get("name") or ""
                cfg_provider = model_cfg.get("provider")
                cfg_base_url = model_cfg.get("base_url") or model_cfg.get("endpoint") or model_cfg.get("api_base")
                cfg_api_key = model_cfg.get("api_key")
            elif isinstance(model_cfg, str):
                cfg_model = model_cfg
        except Exception:
            pass

        # Resolve provider
        if default_provider is not None:
            resolved_provider = default_provider.lower().strip()
        elif cfg_provider and cfg_provider.lower().strip() not in ("auto", "default", ""):
            resolved_provider = cfg_provider.lower().strip()
        else:
            resolved_provider = "ollama"

        if resolved_provider in ("custom", "lmstudio", "vllm", "openai_compatible", "codex"):
            resolved_provider = "openai_compatible"
        elif resolved_provider not in ("remote", "api", "openai", "anthropic", "openrouter"):
            resolved_provider = "ollama"

        self.default_provider = resolved_provider

        # Resolve Ollama endpoint
        if ollama_base_url is not None:
            self.ollama_base_url = ollama_base_url.rstrip("/")
        elif cfg_base_url and self.default_provider == "ollama" and is_local_endpoint(cfg_base_url):
            endpoint = cfg_base_url
            if endpoint.endswith("/v1"):
                endpoint = endpoint[:-3]
            self.ollama_base_url = endpoint.rstrip("/")
        else:
            self.ollama_base_url = "http://127.0.0.1:11434"

        # Resolve model name
        resolved_model = (ollama_model or cfg_model or "").strip()
        self.ollama_model = resolved_model or "gemma4:12b"

        # Resolve OpenAI-compatible / local server endpoint (LM Studio, vLLM, Codex)
        if codex_base_url is not None:
            self.codex_base_url = codex_base_url
        elif cfg_base_url and self.default_provider in ("openai_compatible", "codex"):
            self.codex_base_url = cfg_base_url
        else:
            self.codex_base_url = "http://127.0.0.1:8000/v1"

        self.codex_api_key = codex_api_key or cfg_api_key or "local"

        # Resolve remote provider settings (OpenAI, Anthropic, OpenRouter, Remote)
        if remote_base_url is not None:
            self.remote_base_url = remote_base_url
        elif cfg_base_url and self.default_provider in ("remote", "api", "openai", "anthropic", "openrouter"):
            self.remote_base_url = cfg_base_url
        elif self.default_provider == "openrouter":
            self.remote_base_url = os.environ.get("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
        elif self.default_provider == "anthropic":
            self.remote_base_url = os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com/v1"
        elif self.default_provider in ("openai", "remote", "api"):
            self.remote_base_url = os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        else:
            self.remote_base_url = None

        if remote_api_key is not None:
            self.remote_api_key = remote_api_key
        elif cfg_api_key:
            self.remote_api_key = cfg_api_key
        else:
            self.remote_api_key = (
                os.environ.get(f"{self.default_provider.upper()}_API_KEY")
                or os.environ.get("OPENROUTER_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("ANTHROPIC_API_KEY")
                or ""
            )

        self.allow_remote = allow_remote

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
        ollama_health = self.check_ollama_health()
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
                "configured": bool(self.remote_base_url and self.remote_api_key),
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

        elif selected_provider in ("codex", "openai_compatible", "custom", "lmstudio", "vllm"):
            target_url = self.codex_base_url or "http://127.0.0.1:8000/v1"
            if not is_local_endpoint(target_url) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint '{target_url}' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Abilitare esplicitamente allow_remote con il consenso dell'utente."
                )

            return self._call_openai_compatible(
                base_url=target_url,
                api_key=self.codex_api_key or "local",
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

            target_key = self.remote_api_key
            if not target_key:
                target_key = (
                    os.environ.get(f"{selected_provider.upper()}_API_KEY")
                    or os.environ.get("OPENROUTER_API_KEY")
                    or os.environ.get("OPENAI_API_KEY")
                    or os.environ.get("ANTHROPIC_API_KEY")
                    or ""
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
