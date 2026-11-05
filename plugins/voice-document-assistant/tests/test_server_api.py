"""Tests for backend FastAPI REST API routes."""

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.models import Citation, GroundedAnswer
from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.server.standalone import app
from hermes_voice.server.state import get_assistant

client = TestClient(app)


def test_api_status_endpoint():
    res = client.get("/api/plugins/voice-document-assistant/status")
    assert res.status_code == 200
    data = res.json()
    assert "state" in data
    assert "current_page" in data
    assert "agents" in data


def test_api_upload_and_library():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test_api.pdf"
        create_sample_italian_pdf(pdf_path)

        # Upload via file path JSON
        res = client.post(
            "/api/plugins/voice-document-assistant/upload",
            json={"file_path": str(pdf_path)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        doc = data["document"]
        assert doc["total_pages"] == 3
        assert len(doc["all_sentences"]) > 0

        # Check library
        res_lib = client.get("/api/plugins/voice-document-assistant/library")
        assert res_lib.status_code == 200
        lib_data = res_lib.json()
        assert any(d["doc_id"] == doc["doc_id"] for d in lib_data["documents"])


def test_api_playback_flow():
    assistant = get_assistant()
    assistant.player.virtual_playback = True

    # Ensure document is loaded
    if not assistant.current_document:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "test_doc.pdf"
            create_sample_italian_pdf(pdf_path)
            assistant.load_document(pdf_path)

    # Play
    res_play = client.post("/api/plugins/voice-document-assistant/playback/play")
    assert res_play.status_code == 200

    # Pause
    res_pause = client.post("/api/plugins/voice-document-assistant/playback/pause")
    assert res_pause.status_code == 200
    assert res_pause.json()["bookmark"]["state"] == "paused"

    # Resume
    res_resume = client.post("/api/plugins/voice-document-assistant/playback/resume")
    assert res_resume.status_code == 200

    # Stop
    res_stop = client.post("/api/plugins/voice-document-assistant/playback/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["bookmark"]["state"] == "stopped"


def test_api_playback_config():
    res = client.post(
        "/api/plugins/voice-document-assistant/playback/config",
        json={"tts_model": "italian_24l", "speed": 1.25, "allow_remote": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["tts_model"] == "italian_24l"
    assert data["speed"] == 1.25
    assert data["allow_remote"] is False


def test_api_ask_question(monkeypatch):
    assistant = get_assistant()

    # Ensure document is loaded
    if not assistant.current_document:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "test_doc.pdf"
            create_sample_italian_pdf(pdf_path)
            assistant.load_document(pdf_path)

    # Mock analyst response with verifiable quote on Page 1
    mock_ans = GroundedAnswer(
        question="Che processore viene utilizzato?",
        answer="Il sistema adotta un processore Intel Core Ultra 7 con 16 gigabyte di memoria RAM [Pagina 1].",
        citations=[
            Citation(
                page_number=1,
                verbatim_quote="processore Intel Core Ultra 7 con 16 gigabyte di memoria RAM",
                confidence=1.0,
            )
        ],
        model_used="mock-gemma",
        latency_seconds=0.1,
    )
    monkeypatch.setattr(assistant.analyst, "answer_question", lambda q, excerpts: mock_ans)

    res = client.post(
        "/api/plugins/voice-document-assistant/ask",
        json={"question": "Che processore viene utilizzato?"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert len(data["citations"]) > 0
    assert data["citations"][0]["page_number"] == 1
    assert data["verification"]["is_valid"] is True


def test_api_get_document_does_not_switch_active():
    """Verify that fetching document details does not alter active document or playback."""
    assistant = get_assistant()
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_a = Path(tmpdir) / "doc_a.pdf"
        pdf_b = Path(tmpdir) / "doc_b.pdf"
        create_sample_italian_pdf(pdf_a)
        create_sample_italian_pdf(pdf_b)

        doc_a = assistant.load_document(pdf_a)
        doc_b = assistant.load_document(pdf_b)
        active_doc_id = assistant.current_document.doc_id
        assert active_doc_id == doc_b.doc_id

        # Fetch doc A details
        res = client.get(f"/api/plugins/voice-document-assistant/document/{doc_a.doc_id}")
        assert res.status_code == 200
        assert res.json()["doc_id"] == doc_a.doc_id

        # Verify active document is still B
        assert assistant.current_document.doc_id == active_doc_id


def test_cross_profile_access_rejected_with_403():
    """Verify that attempting to access a different profile than the gateway-bound scope returns 403."""
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    from hermes_voice.profile import resolve_voice_profile_dir

    prof_dir = resolve_voice_profile_dir("alpha_profile")
    token = set_hermes_home_override(str(prof_dir.parent.parent / "profiles" / "alpha_profile"))
    try:
        # Request specifying beta_profile when bound to alpha_profile must be rejected
        res = client.get(
            "/api/plugins/voice-document-assistant/status",
            headers={"X-Hermes-Profile": "beta_profile"},
        )
        assert res.status_code == 403
        assert "Access denied" in res.json()["detail"]

        # Request matching authorized profile succeeds
        res_ok = client.get(
            "/api/plugins/voice-document-assistant/status",
            headers={"X-Hermes-Profile": "alpha_profile"},
        )
        assert res_ok.status_code == 200
    finally:
        reset_hermes_home_override(token)


def test_audio_sentence_stream_endpoint():
    """Verify generated sentence audio is delivered to desktop client as standard WAV."""
    assistant = get_assistant()
    if not assistant.current_document:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "doc.pdf"
            create_sample_italian_pdf(pdf_path)
            assistant.load_document(pdf_path)

    res = client.get("/api/plugins/voice-document-assistant/audio/sentence/0")
    assert res.status_code == 200
    assert "audio/wav" in res.headers["content-type"]
    assert res.content.startswith(b"RIFF")
    assert b"WAVE" in res.content[:16]


def test_api_playback_config_llm_model():
    """Verify playback config supports selecting the LLM model."""
    res = client.post(
        "/api/plugins/voice-document-assistant/playback/config",
        json={"llm_model": "custom-model:latest"},
    )
    assert res.status_code == 200
    assert res.json()["llm_model"] == "custom-model:latest"


def test_native_ticket_custom_home_preserves_home_storage_identity():
    """Verify that a native principal for a custom HERMES_HOME resolves directly to that home directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_home = Path(tmpdir) / "custom_deployment_home"
        custom_home.mkdir(parents=True, exist_ok=True)

        from fastapi import Request
        from starlette.datastructures import Headers

        # Mock request with state.native_http_principal pointing to custom_home
        mock_scope = {
            "type": "http",
            "method": "GET",
            "path": "/status",
            "headers": [],
            "query_string": b"",
        }
        req = Request(mock_scope)
        req.state.native_http_principal = {"profile_id": str(custom_home)}

        from hermes_voice.server.api import _req_assistant, _resolve_authorized_context
        prof_name, auth_home = _resolve_authorized_context(req)
        assert auth_home == custom_home.resolve()

        ast = _req_assistant(req)
        # Ensure the assistant uses the custom home as its storage identity
        assert (custom_home / "voice_assistant").exists()
        assert ast.library_path == custom_home / "voice_assistant" / "voice_library.json"


def test_missing_dependencies_status_endpoint_returns_json():
    """Verify dashboard/plugin_api.py fallback handler returns structured guidance without NameError."""
    from fastapi import APIRouter
    _import_err_msg = "No module named 'pymupdf'"
    router = APIRouter()

    @router.get("/status")
    async def _missing_deps():
        return {
            "error": "missing_dependencies",
            "detail": f"Dipendenze Python mancanti ({_import_err_msg}). Eseguire: hermes plugins install voice-document-assistant",
        }

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    test_app = FastAPI()
    test_app.include_router(router)
    tc = TestClient(test_app)
    res = tc.get("/status")
    assert res.status_code == 200
    assert res.json()["error"] == "missing_dependencies"
    assert "pymupdf" in res.json()["detail"]


def test_state_keys_assistants_consistently_across_name_and_home_dir():
    """Verify that accessing by profile name and by authorized home path returns the identical singleton instance."""
    from hermes_cli.profiles import get_profile_dir
    from hermes_voice.server.state import get_assistant, reset_assistants

    profile_name = "test_unified_identity"
    home_dir = get_profile_dir(profile_name)

    reset_assistants(profile_name)
    try:
        ast_by_name = get_assistant(profile=profile_name)
        ast_by_home = get_assistant(home_dir=home_dir)
        assert ast_by_name is ast_by_home
        assert ast_by_name.library_path == home_dir / "voice_assistant" / "voice_library.json"
    finally:
        reset_assistants(profile_name)


def test_scoped_home_with_profiles_segment_preserves_full_override_path():
    """Verify that a scoped home containing a 'profiles' path segment preserves the override path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        override_root = Path(tmpdir) / "other_root" / "profiles" / "tenant_alice"
        override_root.mkdir(parents=True, exist_ok=True)

        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from hermes_voice.profile import resolve_voice_profile_dir

        token = set_hermes_home_override(str(override_root))
        try:
            target_dir = resolve_voice_profile_dir()
            assert target_dir == override_root.resolve() / "voice_assistant"
            assert str(override_root.resolve()) in str(target_dir)
        finally:
            reset_hermes_home_override(token)

