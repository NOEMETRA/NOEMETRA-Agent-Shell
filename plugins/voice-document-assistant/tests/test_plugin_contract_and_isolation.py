"""Tests for Hermes Tool Registry contract compliance, profile isolation, and privacy guardrails."""

import json
import tempfile
from pathlib import Path
import pytest

from hermes_plugin.voice_plugin import (
    TOOLS,
    voice_ask_document,
    voice_get_status,
    voice_load_document,
    voice_pause_document,
    voice_play_document,
    voice_resume_document,
    voice_seek_document,
    voice_stop_document,
)
from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.model_router import ModelRouter
from hermes_voice.profile import resolve_voice_profile_dir
from hermes_voice.server.state import get_assistant, reset_assistants


def test_tool_schemas_have_no_outer_wrapper():
    """Verify each tool schema has top-level parameters and description, with no outer function wrapper."""
    for tool_def in TOOLS:
        schema = tool_def["schema"]
        assert "type" not in schema or schema.get("type") != "function", (
            f"Tool {tool_def['name']} schema must not be pre-wrapped in 'type: function'"
        )
        assert "function" not in schema, (
            f"Tool {tool_def['name']} schema must not contain nested 'function' key"
        )
        assert "parameters" in schema, f"Tool {tool_def['name']} missing 'parameters'"
        assert isinstance(schema["parameters"], dict), f"Tool {tool_def['name']} parameters must be a dict"
        assert "description" in schema, f"Tool {tool_def['name']} missing 'description'"


def test_tool_handlers_accept_registry_argument_dict():
    """Verify tool handlers accept the single argument dictionary passed by the Hermes Tool Registry dispatch."""
    reset_assistants()
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "sample.pdf"
        create_sample_italian_pdf(pdf_path)

        # 1. voice_load_document with dict
        res_load = json.loads(voice_load_document({"pdf_path": str(pdf_path)}))
        assert res_load["status"] == "success"
        assert res_load["total_pages"] == 3

        # 2. zero-argument tools receiving empty dict
        res_play = json.loads(voice_play_document({}))
        assert "status" in res_play

        res_pause = json.loads(voice_pause_document({}))
        assert "status" in res_pause

        res_resume = json.loads(voice_resume_document({}))
        assert "status" in res_resume

        res_seek = json.loads(voice_seek_document({"page": 2}))
        assert res_seek["current_page"] == 2

        res_status = json.loads(voice_get_status({}))
        assert "state" in res_status

        res_stop = json.loads(voice_stop_document({}))
        assert "status" in res_stop


def test_profile_isolation_preserves_independent_state():
    """Verify multiple profiles in the same process maintain strict isolation of state and directories."""
    reset_assistants()
    try:
        dir_prof_a = resolve_voice_profile_dir("profile_alpha")
        dir_prof_b = resolve_voice_profile_dir("profile_beta")

        assert dir_prof_a != dir_prof_b
        assert "profile_alpha" in str(dir_prof_a)
        assert "profile_beta" in str(dir_prof_b)

        ast_a = get_assistant("profile_alpha")
        ast_b = get_assistant("profile_beta")

        assert ast_a is not ast_b
        assert ast_a.library_path != ast_b.library_path
        assert ast_a.player.bookmark_path != ast_b.player.bookmark_path
    finally:
        reset_assistants()


def test_uncited_answer_preserves_empty_citations_and_fails_verification():
    """Verify that an uncited answer does NOT fabricate citations and is rejected by the verifier."""
    from hermes_voice.agents.analyst import AnalystAgent
    from hermes_voice.agents.verifier import VerifierAgent
    from hermes_voice.extractor import DocumentExtractor

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        analyst = AnalystAgent()
        verifier = VerifierAgent(doc)

        # Direct extraction test on an uncited response
        uncited_text = "Questa è una risposta inventata che non contiene alcun riferimento a pagine del documento."
        citations = analyst._extract_citations(uncited_text, excerpts=[])
        assert citations == [], "Uncited answer must have empty citations"

        from hermes_voice.models import GroundedAnswer
        answer = GroundedAnswer(
            question="Qualcosa?",
            answer=uncited_text,
            citations=citations,
        )
        res = verifier.verify(answer)
        assert res.is_valid is False
        assert "Nessuna citazione formale fornita" in res.unsupported_claims[0]
