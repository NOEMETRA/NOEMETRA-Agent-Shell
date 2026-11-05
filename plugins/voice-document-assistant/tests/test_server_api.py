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
