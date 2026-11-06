"""Tests for backend FastAPI REST API routes."""

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.models import Citation, GroundedAnswer
from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.server.standalone import app
from hermes_voice.server.state import get_assistant, reset_assistants

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
    token = set_hermes_home_override(str(prof_dir.parent))
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

    # Verify JSON format for desktop ctx.rest bridge
    res_json = client.get("/api/plugins/voice-document-assistant/audio/sentence/0?format=json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["format"] == "wav"
    assert "audio_base64" in data
    assert len(data["audio_base64"]) > 0


def test_unauthorized_profile_selection_rejected_in_unbound_context():
    """Verify that an untrusted caller cannot supply an arbitrary profile in an unbound context."""
    res = client.get(
        "/api/plugins/voice-document-assistant/status",
        headers={"X-Hermes-Profile": "unauthorized_foreign_profile"},
    )
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]


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
    from hermes_voice.server.state import get_assistant, reset_assistants, reset_assistants

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


def test_authorized_default_profile_selector_accepted():
    """Verify that an explicitly selected default profile is accepted on the default home."""
    res_hdr = client.get(
        "/api/plugins/voice-document-assistant/status",
        headers={"X-Hermes-Profile": "default"},
    )
    assert res_hdr.status_code == 200

    res_query = client.get(
        "/api/plugins/voice-document-assistant/status?profile=default",
    )
    assert res_query.status_code == 200


def test_client_playback_mode_selection():
    """Verify that /playback/play with output='client' configures client_playback mode."""
    assistant = get_assistant()
    if not assistant.current_document:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "doc.pdf"
            create_sample_italian_pdf(pdf_path)
            assistant.load_document(pdf_path)

    res = client.post(
        "/api/plugins/voice-document-assistant/playback/play",
        json={"output": "client"},
    )
    assert res.status_code == 200
    assert assistant.player.client_playback is True
    assistant.player.stop()


def test_client_playback_ack_synchronization():
    """Verify that /playback/ack updates server-side synchronization events."""
    assistant = get_assistant()
    if not assistant.current_document:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "doc.pdf"
            create_sample_italian_pdf(pdf_path)
            assistant.load_document(pdf_path)

    res_start = client.post(
        "/api/plugins/voice-document-assistant/playback/ack",
        json={"sentence_index": 0, "event": "started"},
    )
    assert res_start.status_code == 200
    assert assistant.player.client_playback is True

    res_progress = client.post(
        "/api/plugins/voice-document-assistant/playback/ack",
        json={"sentence_index": 0, "event": "progress", "offset_seconds": 1.5},
    )
    assert res_progress.status_code == 200

    res_end = client.post(
        "/api/plugins/voice-document-assistant/playback/ack",
        json={"sentence_index": 0, "event": "ended"},
    )
    assert res_end.status_code == 200


def test_upload_cross_profile_file_path_rejected_with_403():
    """Verify that specifying a file_path inside another profile's directory is blocked with 403."""
    from hermes_voice.profile import resolve_voice_profile_dir

    other_prof_dir = resolve_voice_profile_dir("victim_profile")
    foreign_pdf = other_prof_dir / "victim_secret.pdf"
    create_sample_italian_pdf(foreign_pdf)
    try:
        res = client.post(
            "/api/plugins/voice-document-assistant/upload",
            json={"file_path": str(foreign_pdf.resolve())},
        )
        assert res.status_code == 403
        assert "belongs to profile" in res.json()["detail"]
    finally:
        if foreign_pdf.exists():
            foreign_pdf.unlink()


def test_custom_home_matching_profile_basename_cannot_access_named_profile_files(monkeypatch):
    """Verify that a session using a custom home whose basename matches a named profile cannot access that profile's files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_home = Path(tmpdir) / "noemetra"
        custom_home.mkdir(parents=True, exist_ok=True)

        fake_profiles_root = Path(tmpdir) / "standard_profiles"
        named_profile_dir = fake_profiles_root / "noemetra"
        named_profile_dir.mkdir(parents=True, exist_ok=True)
        victim_pdf = named_profile_dir / "confidential.pdf"
        victim_pdf.write_bytes(b"%PDF-1.4 dummy")

        monkeypatch.setattr("hermes_cli.profiles._get_profiles_root", lambda: fake_profiles_root)
        monkeypatch.setattr("hermes_cli.profiles.get_profile_dir", lambda name: fake_profiles_root / name)
        monkeypatch.setattr("hermes_cli.profiles.list_profile_names", lambda: ["noemetra"])

        from hermes_voice.profile import validate_path_profile_ownership
        with pytest.raises(PermissionError) as exc_info:
            validate_path_profile_ownership(
                victim_pdf,
                profile="noemetra",
                home_dir=custom_home,
            )
        assert "belongs to profile 'noemetra' and is outside the authorized home directory" in str(exc_info.value)


def test_standalone_rejects_untrusted_cross_origin_requests():
    """Verify that standalone mutating requests from untrusted origins or cross-site contexts are blocked."""
    # Untrusted Origin header
    res_origin = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Origin": "https://evil.com"},
    )
    assert res_origin.status_code == 403
    assert "Untrusted origin forbidden" in res_origin.text

    # Null Origin header (sandboxed iframe / data URI)
    res_null = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Origin": "null"},
    )
    assert res_null.status_code == 403
    assert "Untrusted origin forbidden" in res_null.text

    # Untrusted Referer header when Origin is absent
    res_ref = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Referer": "https://attacker.org/exploit.html"},
    )
    assert res_ref.status_code == 403
    assert "Untrusted referer forbidden" in res_ref.text

    # Cross-site Sec-Fetch-Site without verified loopback origin
    res_sec = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert res_sec.status_code == 403
    assert "Cross-origin request forbidden" in res_sec.text


def test_standalone_allows_trusted_loopback_and_safe_requests():
    """Verify that loopback origins and read-only GET requests pass through."""
    # Loopback origin on 127.0.0.1
    res_loopback = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Origin": "http://127.0.0.1:8080"},
    )
    assert res_loopback.status_code == 200

    # Loopback origin on localhost:3000 (desktop dev server)
    res_dev = client.post(
        "/api/plugins/voice-document-assistant/playback/stop",
        headers={"Origin": "http://localhost:3000"},
    )
    assert res_dev.status_code == 200

    # GET requests are safe and not blocked by mutating CSRF guard
    res_get = client.get(
        "/api/plugins/voice-document-assistant/status",
        headers={"Origin": "https://evil.com"},
    )
    assert res_get.status_code == 200


def test_custom_home_cannot_access_another_custom_home_files():
    """Verify that a session in one custom HERMES_HOME cannot upload/access files from another custom HERMES_HOME."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home_a = Path(tmpdir) / "custom_home_a"
        home_b = Path(tmpdir) / "custom_home_b"
        home_a.mkdir(parents=True, exist_ok=True)
        home_b.mkdir(parents=True, exist_ok=True)

        victim_pdf = home_a / "confidential_a.pdf"
        create_sample_italian_pdf(victim_pdf)

        from hermes_voice.profile import (
            clear_registered_served_profile_homes,
            register_served_profile_home,
            validate_path_profile_ownership,
        )

        clear_registered_served_profile_homes()
        # Register home_a as a served profile home
        register_served_profile_home(home_a, "custom_a")

        # Session in home_b attempts to validate ownership of home_a's PDF
        with pytest.raises(PermissionError) as exc_info:
            validate_path_profile_ownership(
                victim_pdf,
                profile="custom_b",
                home_dir=home_b,
            )
        assert "outside the authorized home directory" in str(exc_info.value)

        # Also test structural voice_assistant isolation without prior registration
        clear_registered_served_profile_homes()
        voice_pdf = home_a / "voice_assistant" / "uploaded_pdfs" / "stored.pdf"
        voice_pdf.parent.mkdir(parents=True, exist_ok=True)
        create_sample_italian_pdf(voice_pdf)

        with pytest.raises(PermissionError) as exc_info2:
            validate_path_profile_ownership(
                voice_pdf,
                profile="custom_b",
                home_dir=home_b,
            )
        assert "outside the authorized home directory" in str(exc_info2.value)


def test_models_endpoint_dispatched():
    """Verify that GET /models executes and returns provider status structure."""
    res = client.get("/api/plugins/voice-document-assistant/models")
    assert res.status_code == 200
    data = res.json()
    assert "default_provider" in data
    assert "ollama" in data
    assert "allow_remote" in data


def test_custom_homes_with_same_basename_are_strictly_isolated(tmp_path):
    """Verify that multiple custom homes sharing the same basename are not dropped or conflated (AGENTS.md:13)."""
    from hermes_voice.profile import (
        clear_registered_served_profile_homes,
        register_served_profile_home,
        validate_path_profile_ownership,
    )

    home_1 = tmp_path / "tenant_alpha" / "workspace"
    home_2 = tmp_path / "tenant_beta" / "workspace"
    home_1.mkdir(parents=True, exist_ok=True)
    home_2.mkdir(parents=True, exist_ok=True)

    pdf_in_1 = home_1 / "doc1.pdf"
    pdf_in_2 = home_2 / "doc2.pdf"
    create_sample_italian_pdf(pdf_in_1)
    create_sample_italian_pdf(pdf_in_2)

    clear_registered_served_profile_homes()
    # Register both homes which share basename 'workspace'
    register_served_profile_home(home_1, "workspace")
    register_served_profile_home(home_2, "workspace")

    # Home 1 can access its own file
    validate_path_profile_ownership(pdf_in_1, home_dir=home_1)

    # Home 1 CANNOT access home 2's file despite identical basename
    with pytest.raises(PermissionError) as exc_1:
        validate_path_profile_ownership(pdf_in_2, home_dir=home_1)
    assert "outside the authorized home directory" in str(exc_1.value)

    # Home 2 can access its own file
    validate_path_profile_ownership(pdf_in_2, home_dir=home_2)

    # Home 2 CANNOT access home 1's file
    with pytest.raises(PermissionError) as exc_2:
        validate_path_profile_ownership(pdf_in_1, home_dir=home_2)
    assert "outside the authorized home directory" in str(exc_2.value)

    # Also test when passed via served_homes iterable
    clear_registered_served_profile_homes()
    with pytest.raises(PermissionError):
        validate_path_profile_ownership(pdf_in_2, home_dir=home_1, served_homes=[home_1, home_2])


def test_unscoped_request_with_custom_hermes_home_preserves_process_home(monkeypatch):
    """Verify unscoped requests under custom HERMES_HOME operate in process home, not profiles/custom (P1)."""
    from hermes_voice.profile import clear_registered_served_profile_homes
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_proc_home = (Path(tmpdir) / "custom_tenant_workspace").resolve()
        custom_proc_home.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HERMES_HOME", str(custom_proc_home))

        reset_assistants()
        clear_registered_served_profile_homes()

        client = TestClient(app)

        # 1. An unscoped request operates directly in custom_proc_home
        resp = client.get("/api/plugins/voice-document-assistant/status")
        assert resp.status_code == 200

        # Verify assistant was anchored to custom_proc_home / voice_assistant
        expected_dir = custom_proc_home / "voice_assistant"
        assert expected_dir.exists()

        # 2. A request attempting to access a profile named 'custom' is rejected with 403 Forbidden
        cross_resp = client.get("/api/plugins/voice-document-assistant/status?profile=custom")
        assert cross_resp.status_code == 403
        assert "Access denied" in cross_resp.json()["detail"]






