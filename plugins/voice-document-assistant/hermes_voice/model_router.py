"""Model router supporting local Ollama (default), Codex, and optional remote APIs.

Strict constraint: Local-first by default.
No document data is sent to remote endpoints without explicit user consent.
This applies to Ollama, Codex, and all OpenAI-compatible / remote providers.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
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
        default_provider: str = "ollama",
        ollama_base_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "gemma4:12b",
        codex_base_url: Optional[str] = None,
        codex_api_key: Optional[str] = None,
        remote_base_url: Optional[str] = None,
        remote_api_key: Optional[str] = None,
        allow_remote: bool = False,
    ):
        self.default_provider = default_provider.lower()
        self.ollama_base_url = ollama_base_url.rstrip("/")
        self.ollama_model = ollama_model
        self.codex_base_url = codex_base_url
        self.codex_api_key = codex_api_key
        self.remote_base_url = remote_base_url
        self.remote_api_key = remote_api_key
        self.allow_remote = allow_remote

    def set_allow_remote(self, allowed: bool) -> None:
        """Update explicit user authorization for remote network transmission."""
        self.allow_remote = bool(allowed)
        logger.info(f"Autorizzazione provider remoti aggiornata a: {self.allow_remote}")

    def check_ollama_health(self) -> Dict[str, Any]:
        """Verify Ollama server connection and list available models."""
        try:
            resp = requests.get(f"{self.ollama_base_url}/api/tags", timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "status": "online",
                    "available_models": models,
                    "target_model_installed": any(self.ollama_model in m for m in models),
                }
        except Exception as e:
            return {"status": "offline", "error": str(e), "available_models": []}

        return {"status": "error", "available_models": []}

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
                "is_local": True,
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
            return self._call_ollama(
                prompt=prompt,
                system_prompt=system_prompt,
                model=model or self.ollama_model,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        elif selected_provider in ("codex", "openai_compatible"):
            target_url = self.codex_base_url or "http://127.0.0.1:8000/v1"
            if not is_local_endpoint(target_url) and not self.allow_remote:
                raise PermissionError(
                    f"VIOLAZIONE VINCOLO PRIVACY: L'endpoint Codex '{target_url}' è remoto. "
                    "L'invio di dati documentali a provider remoti è bloccato per impostazione predefinita. "
                    "Abilitare esplicitamente allow_remote con il consenso dell'utente."
                )

            return self._call_openai_compatible(
                base_url=target_url,
                api_key=self.codex_api_key or "local",
                model=model or "codex",
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
            )

        elif selected_provider in ("remote", "api", "openai", "anthropic"):
            if not self.allow_remote:
                raise PermissionError(
                    "VIOLAZIONE VINCOLO PRIVACY: L'invio di dati documentali a provider remoti "
                    "è bloccato per impostazione predefinita. Per abilitarlo, impostare esplicitamente "
                    "allow_remote=True con il consenso dell'utente."
                )
            return self._call_openai_compatible(
                base_url=self.remote_base_url or "https://api.openai.com/v1",
                api_key=self.remote_api_key or "",
                model=model or "gpt-4o-mini",
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
            resp = requests.post(url, json=payload, timeout=180.0)
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

        resp = requests.post(url, headers=headers, json=payload, timeout=60.0)
        if resp.status_code != 200:
            raise RuntimeError(f"API Error {resp.status_code}: {resp.text}")

        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
