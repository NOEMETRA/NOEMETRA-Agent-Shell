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





