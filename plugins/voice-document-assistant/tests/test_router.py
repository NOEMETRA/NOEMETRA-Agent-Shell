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

