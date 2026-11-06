"""Tests for ModelRouter and privacy boundary enforcement."""

import pytest
from hermes_voice.model_router import ModelRouter


def test_privacy_guard_blocks_unauthorized_remote_calls():
    router = ModelRouter(allow_remote=False)

    # Calling remote provider without allow_remote must raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        router.generate(
            prompt="Test prompt",
            provider="remote",
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)


def test_privacy_guard_blocks_remote_codex_endpoint():
    """Privacy guard must apply to non-localhost Codex endpoints as well."""
    router = ModelRouter(
        allow_remote=False,
        codex_base_url="https://api.external-codex.com/v1",
    )

    with pytest.raises(PermissionError) as exc_info:
        router.generate(
            prompt="Test prompt",
            provider="codex",
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)
    assert "remoto" in str(exc_info.value)


def test_privacy_guard_blocks_remote_ollama_endpoint():
    """Privacy guard must apply to remote Ollama endpoints as well."""
    router = ModelRouter(
        allow_remote=False,
        ollama_base_url="https://remote-ollama.example.com",
    )

    with pytest.raises(PermissionError) as exc_info:
        router.generate(
            prompt="Test prompt",
            provider="ollama",
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)
    assert "remoto" in str(exc_info.value)


def test_privacy_guard_allows_remote_only_with_explicit_consent(monkeypatch):
    router = ModelRouter(allow_remote=True)

    # Mock _call_openai_compatible
    monkeypatch.setattr(
        router,
        "_call_openai_compatible",
        lambda **kwargs: "Mocked response from authorized remote",
    )

    res = router.generate(prompt="Test prompt", provider="remote")
    assert res == "Mocked response from authorized remote"


def test_ollama_health_check():
    router = ModelRouter(ollama_base_url="http://127.0.0.1:11434")
    health = router.check_ollama_health()
    # Since Ollama is running, it should report online
    assert health["status"] == "online"
    assert "gemma4:12b" in health["available_models"]


def test_model_router_resolves_and_switches_model(monkeypatch):
    """Verify ModelRouter initializes from config and supports explicit switching and autoselection."""
    # Test explicit switching
    router = ModelRouter()
    assert router.ollama_model is not None

    router.set_model("llama3.2:latest")
    assert router.ollama_model == "llama3.2:latest"

    # Test autoselection when target model is not in available models
    monkeypatch.setattr(
        router,
        "check_ollama_health",
        lambda: {"status": "online", "available_models": ["gemma4:12b", "phi3:mini"]},
    )
    selected = router.select_installed_model()
    assert selected == "gemma4:12b"
    assert router.ollama_model == "gemma4:12b"


def test_model_router_honors_configured_custom_local_endpoint(monkeypatch):
    """Verify ModelRouter honors custom local OpenAI-compatible endpoints (LM Studio, vLLM)."""
    fake_config = {
        "model": {
            "provider": "custom",
            "base_url": "http://127.0.0.1:1234/v1",
            "name": "qwen2.5:14b",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter()
    assert router.default_provider == "openai_compatible"
    assert router.codex_base_url == "http://127.0.0.1:1234/v1"
    assert router.ollama_model == "qwen2.5:14b"
    assert router.select_installed_model() == "qwen2.5:14b"

    captured_call = {}

    def mock_openai_compatible(**kwargs):
        captured_call.update(kwargs)
        return "LM Studio Answer"

    monkeypatch.setattr(router, "_call_openai_compatible", mock_openai_compatible)
    res = router.generate(prompt="Document question")
    assert res == "LM Studio Answer"
    assert captured_call["base_url"] == "http://127.0.0.1:1234/v1"
    assert captured_call["model"] == "qwen2.5:14b"


def test_model_router_honors_configured_custom_ollama_port(monkeypatch):
    """Verify ModelRouter honors custom Ollama server ports configured in setup."""
    fake_config = {
        "model": {
            "provider": "ollama",
            "base_url": "http://127.0.0.1:11435",
            "name": "mistral:latest",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter()
    assert router.default_provider == "ollama"
    assert router.ollama_base_url == "http://127.0.0.1:11435"
    assert router.ollama_model == "mistral:latest"


def test_privacy_guard_blocks_remote_redirect_from_local_ollama(monkeypatch):
    """Verify that requests.post redirect to remote host is intercepted and blocked."""
    router = ModelRouter(allow_remote=False)

    class MockRedirectResponse:
        is_redirect = True
        status_code = 307
        headers = {"Location": "https://malicious-external-sink.com/api/steal"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRedirectResponse())

    with pytest.raises(PermissionError) as exc_info:
        router._call_ollama(
            prompt="Sensitive document text",
            system_prompt=None,
            model="gemma4:12b",
            temperature=0.2,
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)
    assert "reindirizzamento remoto" in str(exc_info.value)


def test_privacy_guard_blocks_remote_redirect_from_local_openai_compatible(monkeypatch):
    """Verify that OpenAI-compatible endpoint redirect to remote host is intercepted and blocked."""
    router = ModelRouter(allow_remote=False)

    class MockRedirectResponse:
        is_redirect = True
        status_code = 308
        headers = {"Location": "https://malicious-external-sink.com/chat/completions"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRedirectResponse())

    with pytest.raises(PermissionError) as exc_info:
        router._call_openai_compatible(
            base_url="http://127.0.0.1:8000/v1",
            api_key="local",
            model="local-model",
            prompt="Sensitive text",
            system_prompt=None,
            temperature=0.2,
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)
    assert "reindirizzamento remoto" in str(exc_info.value)


def test_remote_provider_settings_populated_from_config(monkeypatch):
    """Verify ModelRouter populates and uses configured remote endpoint, credentials and model."""
    fake_config = {
        "model": {
            "provider": "anthropic",
            "base_url": "https://api.custom-anthropic.com/v1",
            "api_key": "sk-ant-test-key-12345",
            "name": "claude-3-5-sonnet-20241022",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter(allow_remote=True)
    assert router.default_provider == "anthropic"
    assert router.remote_base_url == "https://api.custom-anthropic.com/v1"
    assert router.remote_api_key == "sk-ant-test-key-12345"

    captured = {}

    def mock_call(base_url, api_key, model, prompt, **kwargs):
        captured["base_url"] = base_url
        captured["api_key"] = api_key
        captured["model"] = model
        captured["prompt"] = prompt
        return "Anthropic Response"

    monkeypatch.setattr(router, "_call_anthropic", mock_call)
    res = router.generate(prompt="What is the summary?")
    assert res == "Anthropic Response"
    assert captured["base_url"] == "https://api.custom-anthropic.com/v1"
    assert captured["api_key"] == "sk-ant-test-key-12345"
    assert captured["model"] == "claude-3-5-sonnet-20241022"


def test_call_anthropic_payload_and_headers(monkeypatch):
    """Verify _call_anthropic sends required Anthropic Messages API headers and payload format."""
    router = ModelRouter(allow_remote=True)

    sent_requests = []

    class MockAnthropicResponse:
        is_redirect = False
        status_code = 200

        def json(self):
            return {
                "id": "msg_0123",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Anthropic document answer."}
                ],
            }

    def mock_post(url, headers=None, json=None, **kwargs):
        sent_requests.append({"url": url, "headers": headers, "json": json})
        return MockAnthropicResponse()

    monkeypatch.setattr("requests.post", mock_post)

    result = router._call_anthropic(
        base_url="https://api.anthropic.com",
        api_key="sk-ant-api03-test",
        model="claude-3-5-sonnet-20241022",
        prompt="Spiega il documento",
        system_prompt="Sei un assistente documentale preciso.",
        temperature=0.3,
    )

    assert result == "Anthropic document answer."
    assert len(sent_requests) == 1
    req = sent_requests[0]
    assert req["url"] == "https://api.anthropic.com/v1/messages"
    assert req["headers"]["x-api-key"] == "sk-ant-api03-test"
    assert req["headers"]["anthropic-version"] == "2023-06-01"
    assert req["headers"]["Content-Type"] == "application/json"
    assert req["json"]["model"] == "claude-3-5-sonnet-20241022"
    assert req["json"]["system"] == "Sei un assistente documentale preciso."
    assert req["json"]["messages"] == [{"role": "user", "content": "Spiega il documento"}]
    assert req["json"]["temperature"] == 0.3
    assert req["json"]["max_tokens"] == 1024


def test_privacy_guard_blocks_remote_redirect_from_anthropic(monkeypatch):
    """Verify that Anthropic endpoint redirect to remote host is intercepted and blocked."""
    router = ModelRouter(allow_remote=False)

    class MockRedirectResponse:
        is_redirect = True
        status_code = 308
        headers = {"Location": "https://malicious-external-sink.com/messages"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRedirectResponse())

    with pytest.raises(PermissionError) as exc_info:
        router._call_anthropic(
            base_url="http://127.0.0.1:8000/v1",
            api_key="local-key",
            model="local-claude",
            prompt="Sensitive document text",
            system_prompt=None,
            temperature=0.2,
        )
    assert "VIOLAZIONE VINCOLO PRIVACY" in str(exc_info.value)
    assert "reindirizzamento remoto" in str(exc_info.value)


def test_openai_blocks_cross_origin_redirect_even_when_remote_allowed(monkeypatch):
    """Verify that OpenAI-compatible endpoint blocks cross-origin redirect to prevent credential leakage."""
    router = ModelRouter(allow_remote=True)

    class MockRedirectResponse:
        is_redirect = True
        status_code = 307
        headers = {"Location": "https://malicious-host.com/v1/chat/completions"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRedirectResponse())

    with pytest.raises(PermissionError) as exc_info:
        router._call_openai_compatible(
            base_url="https://api.openai.com/v1",
            api_key="sk-secret-openai-token",
            model="gpt-4o",
            prompt="Confidential report text",
            system_prompt=None,
            temperature=0.2,
        )
    assert "origine diversa" in str(exc_info.value)
    assert "malicious-host.com" in str(exc_info.value)


def test_anthropic_blocks_cross_origin_redirect_even_when_remote_allowed(monkeypatch):
    """Verify that Anthropic endpoint blocks cross-origin redirect to prevent x-api-key leakage."""
    router = ModelRouter(allow_remote=True)

    class MockRedirectResponse:
        is_redirect = True
        status_code = 308
        headers = {"Location": "https://attacker-origin.net/v1/messages"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: MockRedirectResponse())

    with pytest.raises(PermissionError) as exc_info:
        router._call_anthropic(
            base_url="https://api.anthropic.com",
            api_key="sk-ant-sensitive-api-key",
            model="claude-3-5-sonnet-20241022",
            prompt="Confidential prompt",
            system_prompt=None,
            temperature=0.2,
        )
    assert "origine diversa" in str(exc_info.value)
    assert "attacker-origin.net" in str(exc_info.value)


def test_model_router_resolves_credentials_from_secret_scope_not_os_environ(monkeypatch):
    """Verify ModelRouter uses profile-aware secret API and does not read raw os.environ (AGENTS.md:104-110)."""
    # Simulate an ambient process env with another profile's key
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret-from-other-profile")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-ant-secret")

    # Mock get_secret to simulate an active profile that does NOT have the key set
    monkeypatch.setattr("agent.secret_scope.get_secret", lambda name, default=None: None)

    fake_config = {
        "model": {
            "provider": "openai",
            "name": "gpt-4o",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter(allow_remote=True)
    # The router must NOT pick up the ambient environment variable
    assert router.remote_api_key == ""

    # Now simulate get_secret returning the served profile's key
    monkeypatch.setattr(
        "agent.secret_scope.get_secret",
        lambda name, default=None: "scoped-profile-key" if name == "OPENAI_API_KEY" else None,
    )
    router2 = ModelRouter(allow_remote=True)
    assert router2.remote_api_key == "scoped-profile-key"


def test_provider_credentials_remain_strictly_scoped_to_intended_provider(monkeypatch):
    """Verify that credentials from one provider are never forwarded to another provider (P1)."""
    # Only OPENAI_API_KEY is configured in profile secrets
    monkeypatch.setattr(
        "agent.secret_scope.get_secret",
        lambda name, default=None: "sk-openai-secret-token" if name == "OPENAI_API_KEY" else None,
    )
    fake_config = {
        "model": {
            "provider": "openrouter",
            "name": "anthropic/claude-3.5-sonnet",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter(allow_remote=True)
    # The router must NOT fall back to OpenAI's key when provider is openrouter
    assert router.remote_api_key == ""

    # Invoking generate for openrouter without OPENROUTER_API_KEY must raise ValueError rather than leak OpenAI key
    with pytest.raises(ValueError, match="Nessuna credenziale trovata per il provider 'openrouter'"):
        router.generate(prompt="Explain document", provider="openrouter")

    # Invoking generate for anthropic without ANTHROPIC_API_KEY must raise ValueError rather than leak OpenAI key
    with pytest.raises(ValueError, match="Nessuna credenziale trovata per il provider 'anthropic'"):
        router.generate(prompt="Explain document", provider="anthropic")


def test_configured_non_loopback_ollama_endpoint_preserved(monkeypatch):
    """Verify that configured non-loopback Ollama base URL is preserved and requires remote consent (P2)."""
    fake_config = {
        "model": {
            "provider": "ollama",
            "base_url": "http://192.168.1.100:11434",
            "name": "gemma4:12b",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter()
    # Non-loopback endpoint must NOT be discarded or replaced with 127.0.0.1:11434
    assert router.ollama_base_url == "http://192.168.1.100:11434"

    # Default allow_remote=False must block remote Ollama call with PermissionError
    with pytest.raises(PermissionError, match="VIOLAZIONE VINCOLO PRIVACY: L'endpoint Ollama"):
        router.generate(prompt="Test prompt", provider="ollama")

    # When user grants consent allow_remote=True, the configured endpoint is targeted
    router.set_allow_remote(True)
    captured_url = []

    class MockOllamaResponse:
        is_redirect = False
        status_code = 200

        def json(self):
            return {"response": "Answer from remote Ollama server"}

    def mock_post(url, **kwargs):
        captured_url.append(url)
        return MockOllamaResponse()

    monkeypatch.setattr("requests.post", mock_post)
    res = router.generate(prompt="Test prompt", provider="ollama")
    assert res == "Answer from remote Ollama server"
    assert captured_url == ["http://192.168.1.100:11434/api/generate"]


def test_remote_consent_guard_blocks_remote_ollama_health_checks(monkeypatch):
    """Verify check_ollama_health does not probe external network when endpoint is remote and allow_remote is false (P2)."""
    fake_config = {
        "model": {
            "provider": "ollama",
            "base_url": "http://192.168.1.100:11434",
            "name": "gemma4:12b",
        }
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: fake_config)

    router = ModelRouter()
    probed_urls = []

    def mock_get(url, **kwargs):
        probed_urls.append(url)
        raise AssertionError("Remote endpoint was probed without consent!")

    monkeypatch.setattr("requests.get", mock_get)

    health = router.check_ollama_health()
    assert health["status"] == "remote_unauthorized"
    assert len(probed_urls) == 0

    # Once remote access is explicitly authorized, probe is allowed
    router.set_allow_remote(True)

    class MockResp:
        status_code = 200

        def json(self):
            return {"models": [{"name": "gemma4:12b"}]}

    monkeypatch.setattr("requests.get", lambda url, **kwargs: MockResp())
    authorized_health = router.check_ollama_health()
    assert authorized_health["status"] == "online"
    assert authorized_health["target_model_installed"] is True


def test_authenticated_custom_and_lmstudio_endpoints_resolve_scoped_credentials(monkeypatch):
    """Verify authenticated LM Studio, vLLM, and custom endpoints resolve profile-scoped secrets before falling back to 'local' (P2)."""
    # 1. Custom / vLLM endpoint with credential stored in profile-scoped OPENAI_API_KEY
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-other-profile-secret")
    scoped_secrets = {"OPENAI_API_KEY": "sk-custom-vllm-scoped-token"}
    monkeypatch.setattr(
        "agent.secret_scope.get_secret",
        lambda name, default=None: scoped_secrets.get(name, default),
    )
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "model": {
                "provider": "vllm",
                "base_url": "http://127.0.0.1:8000/v1",
                "name": "Qwen/Qwen2.5-14B-Instruct",
            }
        },
    )

    router_vllm = ModelRouter()
    assert router_vllm.default_provider == "openai_compatible"
    assert router_vllm.codex_api_key == "sk-custom-vllm-scoped-token"

    sent_headers = []

    class MockChatResp:
        is_redirect = False
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": "Authenticated vLLM response"}}]}

    def mock_post(url, headers=None, **kwargs):
        sent_headers.append((url, dict(headers or {})))
        return MockChatResp()

    monkeypatch.setattr("requests.post", mock_post)
    out = router_vllm.generate(prompt="Verifica autenticazione endpoint custom")
    assert out == "Authenticated vLLM response"
    assert sent_headers[-1][0] == "http://127.0.0.1:8000/v1/chat/completions"
    assert sent_headers[-1][1]["Authorization"] == "Bearer sk-custom-vllm-scoped-token"

    # 2. LM Studio endpoint prefers LM_API_KEY when present, else falls back to OPENAI_API_KEY
    scoped_secrets["LM_API_KEY"] = "lmstudio-bearer-secret"
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "model": {
                "provider": "lmstudio",
                "base_url": "http://127.0.0.1:1234/v1",
                "name": "gemma-4-12b-it",
            }
        },
    )
    router_lms = ModelRouter()
    assert router_lms.codex_api_key == "lmstudio-bearer-secret"
    router_lms.generate(prompt="Domanda LM Studio")
    assert sent_headers[-1][1]["Authorization"] == "Bearer lmstudio-bearer-secret"

    # 3. Named custom provider entry declaring key_env resolves that profile-scoped secret
    scoped_secrets["HERMES_CUSTOM_CORP_VLLM_API_KEY"] = "corp-vllm-dedicated-key"
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "model": {
                "provider": "custom:corp-vllm",
            },
            "providers": {
                "corp-vllm": {
                    "base_url": "http://127.0.0.1:8081/v1",
                    "default_model": "llama-3.3-70b",
                    "key_env": "HERMES_CUSTOM_CORP_VLLM_API_KEY",
                }
            },
        },
    )
    router_named = ModelRouter()
    assert router_named.default_provider == "openai_compatible"
    assert router_named.codex_base_url == "http://127.0.0.1:8081/v1"
    assert router_named.ollama_model == "llama-3.3-70b"
    assert router_named.codex_api_key == "corp-vllm-dedicated-key"

    # 4. Keyless profile falls back cleanly to 'local' without reading ambient os.environ
    scoped_secrets.clear()
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "model": {
                "provider": "custom",
                "base_url": "http://127.0.0.1:8000/v1",
                "name": "local-open-model",
            }
        },
    )
    router_keyless = ModelRouter()
    assert router_keyless.codex_api_key == "local"


def test_configured_hermes_providers_nous_and_gemini_preserved_and_routed_via_runtime(monkeypatch):
    """Verify supported Hermes providers outside legacy hardcoded list (Nous, Gemini) do not fall back to Ollama (P2)."""
    from types import SimpleNamespace

    resolve_calls = []

    class MockCompletions:
        def create(self, **kwargs):
            resolve_calls.append(("create", kwargs))
            return SimpleNamespace(
                model=kwargs["model"],
                choices=[SimpleNamespace(message=SimpleNamespace(content="Risposta da provider ufficiale Hermes [Pagina 1]."))],
            )

    class MockRuntimeClient:
        def __init__(self, base_url: str):
            self.base_url = base_url
            self.chat = SimpleNamespace(completions=MockCompletions())

    def mock_resolve_provider_client(provider, model=None, explicit_base_url=None, explicit_api_key=None, **kwargs):
        resolve_calls.append(("resolve", provider, model, explicit_base_url, explicit_api_key))
        if provider == "nous":
            return MockRuntimeClient("https://inference-api.nousresearch.com/v1"), model or "hermes-4-405b"
        if provider == "gemini":
            return MockRuntimeClient("https://generativelanguage.googleapis.com/v1beta"), model or "gemini-2.5-flash"
        return None, None

    monkeypatch.setattr("agent.auxiliary_client.resolve_provider_client", mock_resolve_provider_client)

    # 1. Nous configured in config.yaml: preserved as default_provider (never silently overwritten with 'ollama')
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {"model": {"provider": "nous", "default": "hermes-4-405b"}},
    )
    router_nous = ModelRouter(allow_remote=False)
    assert router_nous.default_provider == "nous"

    # Privacy guard blocks BEFORE resolving credentials or exchanging OAuth tokens
    with pytest.raises(PermissionError, match="VIOLAZIONE VINCOLO PRIVACY"):
        router_nous.generate(prompt="Domanda riservata")
    assert len(resolve_calls) == 0

    router_nous.set_allow_remote(True)
    ans_nous = router_nous.generate(prompt="Sintetizza il paragrafo", system_prompt="Istruzioni analista")
    assert "Risposta da provider ufficiale Hermes" in ans_nous
    assert router_nous.last_model_used == "hermes-4-405b"
    assert resolve_calls[0][:3] == ("resolve", "nous", "hermes-4-405b")

    # 2. Gemini configured in config.yaml (with leftover openrouter base_url ignored)
    resolve_calls.clear()
    monkeypatch.setattr(
        "hermes_cli.config.load_config",
        lambda: {
            "model": {
                "provider": "gemini",
                "default": "gemini-2.5-pro",
                "base_url": "https://openrouter.ai/api/v1",
            }
        },
    )
    router_gemini = ModelRouter(allow_remote=True)
    assert router_gemini.default_provider == "gemini"
    ans_gemini = router_gemini.generate(prompt="Domanda Gemini")
    assert "Risposta da provider ufficiale Hermes" in ans_gemini
    assert router_gemini.last_model_used == "gemini-2.5-pro"
    assert resolve_calls[0] == ("resolve", "gemini", "gemini-2.5-pro", None, None)

    # 3. Unknown provider names still fail deterministically rather than falling back to Ollama
    with pytest.raises(ValueError, match="Provider sconosciuto"):
        router_gemini.generate(prompt="Test", provider="invalid_nonexistent_xyz")










