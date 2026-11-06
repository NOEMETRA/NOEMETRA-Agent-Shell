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
        get_assistant().player.virtual_playback = True

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


def test_profile_isolation_preserves_independent_state(tmp_path, monkeypatch):
    """Verify multiple profiles in the same process maintain strict isolation of state and directories."""
    default_home = tmp_path / ".hermes"
    (default_home / "profiles" / "profile_alpha").mkdir(parents=True, exist_ok=True)
    (default_home / "profiles" / "profile_beta").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(default_home))

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


def test_profile_validation_rejects_directory_traversal(tmp_path, monkeypatch):
    """Verify profile validation rejects path traversal, slashes, and illegal symbols with ValueError."""
    default_home = tmp_path / ".hermes"
    default_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(default_home))

    for bad in ["..", "../etc", "foo/bar", "foo\\bar", ".hidden", "bad spaces", "a" * 65]:
        with pytest.raises(ValueError, match="Invalid profile name"):
            resolve_voice_profile_dir(bad)

    # Valid names should resolve cleanly when their profile homes exist
    for good in ["default", "agent_1", "profile-a", "user123"]:
        if good != "default":
            (default_home / "profiles" / good).mkdir(parents=True, exist_ok=True)
        resolved = resolve_voice_profile_dir(good)
        assert resolved.exists() or resolved.parent.exists()


def test_player_tts_synthesis_error_sets_paused_state():
    """Verify that an unexpected exception during TTS synthesis sets state to PAUSED without crashing."""
    from hermes_voice.extractor import DocumentExtractor
    from hermes_voice.models import PlayerState
    from hermes_voice.player import DocumentPlayer

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        bm_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=False)
        player._has_audio_output_device = lambda: True
        player.load_document(doc)

        class BrokenTTS:
            def synthesize(self, text):
                raise RuntimeError("Simulated TTS synthesis failure")

        player.tts = BrokenTTS()
        player.play()
        if player._worker_thread:
            player._worker_thread.join(timeout=3.0)

        assert player.state == PlayerState.PAUSED
        assert player.current_sentence_index == 0


def test_player_audio_stream_failure_preserves_sentence_index():
    """Verify that an audio output device error pauses playback without skipping the sentence."""
    from hermes_voice.extractor import DocumentExtractor
    from hermes_voice.models import PlayerState
    from hermes_voice.player import DocumentPlayer
    import numpy as np

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        bm_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=False)
        player._has_audio_output_device = lambda: True
        player.load_document(doc)

        class DummyTTS:
            def synthesize(self, text):
                # Return 0.5s of silent audio
                return np.zeros(12000, dtype=np.float32), 24000

        player.tts = DummyTTS()

        import unittest.mock as mock
        with mock.patch("sounddevice.OutputStream", side_effect=RuntimeError("Audio hardware busy")):
            player.play()
            if player._worker_thread:
                player._worker_thread.join(timeout=3.0)

            assert player.state == PlayerState.PAUSED
            # Verify sentence index was NOT advanced
            assert player.current_sentence_index == 0


def test_voice_load_document_rejects_cross_profile_path(tmp_path, monkeypatch):
    """Verify voice_load_document tool blocks loading a PDF belonging to another profile (P1)."""
    default_home = tmp_path / ".hermes"
    (default_home / "profiles" / "victim_profile").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(default_home))

    reset_assistants()
    victim_dir = resolve_voice_profile_dir("victim_profile")
    victim_pdf = victim_dir / "secret.pdf"
    create_sample_italian_pdf(victim_pdf)
    try:
        # Caller is default profile assistant
        res = json.loads(voice_load_document({"pdf_path": str(victim_pdf.resolve())}))
        assert "error" in res
        assert "Access denied" in res["error"]
        assert "victim_profile" in res["error"]
    finally:
        reset_assistants()
        if victim_pdf.exists():
            victim_pdf.unlink()


def test_named_profile_can_load_own_file(tmp_path, monkeypatch):
    """Verify that a named profile can load a PDF located in its own profile directory without default-home collision (P2)."""
    from hermes_voice.profile import validate_path_profile_ownership, resolve_voice_profile_dir

    default_home = tmp_path / ".hermes"
    named_prof = "custom_named_profile"
    (default_home / "profiles" / named_prof).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(default_home))

    prof_dir = resolve_voice_profile_dir(named_prof)
    my_pdf = prof_dir / "my_report.pdf"
    create_sample_italian_pdf(my_pdf)
    try:
        # Must not raise PermissionError
        validate_path_profile_ownership(my_pdf, profile=named_prof)
    finally:
        if my_pdf.exists():
            my_pdf.unlink()


def test_client_playback_does_not_advance_on_audio_fetch():
    """Verify that fetching audio for a sentence does NOT mark the playback clock as started (P2)."""
    from hermes_voice.extractor import DocumentExtractor
    from hermes_voice.player import DocumentPlayer
    from hermes_voice.tts_engine import PocketTTSEngine

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        bm_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(tts_engine=PocketTTSEngine(lazy_load=True), bookmark_path=bm_path, virtual_playback=True)
        player.load_document(doc)
        player.client_playback = True

        # Fetch sentence audio
        wav = player.get_sentence_audio_wav(0)
        assert len(wav) > 0
        # Started event must NOT be set simply by fetching audio
        assert not player._client_started_event.is_set()

        # Started event is only set when client explicitly sends started ack
        player.handle_client_ack(0, "started")
        assert player._client_started_event.is_set()


def test_implicit_storage_resolution_from_active_hermes_home(monkeypatch):
    """Verify that omitting profile resolves storage directly under active Hermes home, not profiles/custom (P1)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_home = Path(tmpdir) / "custom_home"
        custom_home.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HERMES_HOME", str(custom_home))

        # Calling resolve_voice_profile_dir() with no arguments or None/empty
        resolved = resolve_voice_profile_dir()
        assert resolved == (custom_home / "voice_assistant").resolve()
        assert "profiles" not in str(resolved)
        assert resolved.exists()


def test_refuses_to_recreate_deleted_or_missing_named_profile_home(tmp_path, monkeypatch):
    """Verify deleted or missing named profile homes are never recreated by in-flight requests or tool calls (P2)."""
    import shutil
    from hermes_constants import (
        mark_named_profile_deleted,
        reset_hermes_home_override,
        set_hermes_home_override,
    )

    default_home = tmp_path / ".hermes"
    default_home.mkdir(parents=True, exist_ok=True)
    (default_home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(default_home))

    # 1. Missing named profile must raise FileNotFoundError and not create directory
    missing_dir = default_home / "profiles" / "never_created"
    with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
        resolve_voice_profile_dir(profile="never_created")
    assert not missing_dir.exists()

    # 2. Live named profile resolves and creates voice_assistant subdirectory normally
    worker_dir = default_home / "profiles" / "worker"
    worker_dir.mkdir(parents=True, exist_ok=True)
    (worker_dir / ".env").write_text("# profile\n", encoding="utf-8")
    reset_assistants()
    try:
        voice_dir = resolve_voice_profile_dir(profile="worker")
        assert voice_dir == (worker_dir / "voice_assistant").resolve()
        assert voice_dir.is_dir()

        # Instantiate cached assistant before profile deletion
        ast = get_assistant(profile="worker")
        assert ast.library_path.parent == voice_dir

        # Simulate profile deletion while requests/tools are still in flight
        mark_named_profile_deleted(worker_dir)
        shutil.rmtree(worker_dir)
        assert not worker_dir.exists()

        # 2a. Explicit profile resolution refuses to recreate deleted home
        with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
            resolve_voice_profile_dir(profile="worker")
        assert not worker_dir.exists()

        # 2b. Explicit home_dir resolution (e.g. stale native ticket grant) refuses to recreate deleted home
        with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
            resolve_voice_profile_dir(home_dir=worker_dir)
        assert not worker_dir.exists()

        # 2c. Implicit-home resolution via context override (e.g. in-flight tool call) refuses to recreate deleted home
        token = set_hermes_home_override(worker_dir)
        try:
            with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
                resolve_voice_profile_dir()
            with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
                voice_get_status({})
        finally:
            reset_hermes_home_override(token)
        assert not worker_dir.exists()

        # 2d. Implicit-home resolution via HERMES_HOME env refuses to recreate deleted home
        monkeypatch.setenv("HERMES_HOME", str(worker_dir))
        with pytest.raises(FileNotFoundError, match="Named profile home does not exist"):
            resolve_voice_profile_dir()
        assert not worker_dir.exists()

        # 2e. Late background bookmark/library save on pre-existing objects must not recreate deleted home
        ast._save_library_catalog()
        ast.player._save_bookmark()
        assert not worker_dir.exists()
    finally:
        monkeypatch.setenv("HERMES_HOME", str(default_home))
        reset_assistants()


def test_desktop_plugin_configures_extended_timeouts_for_slow_endpoints():
    """Verify desktop plugin bundles stay in sync and grant sufficient timeoutMs for local LLM/TTS operations (P2)."""
    import re

    plugin_root = Path(__file__).resolve().parents[1]
    repo_root = plugin_root.parents[1]
    bundled_js = repo_root / "apps" / "desktop" / "src" / "plugins" / "voice-document-assistant" / "plugin.js"
    mirror_js = plugin_root / "desktop" / "plugin.js"

    mirror_src = mirror_js.read_text(encoding="utf-8")
    if bundled_js.exists():
        assert bundled_js.read_text(encoding="utf-8") == mirror_src

    ask_const = re.search(r"const\s+ASK_REQUEST_TIMEOUT_MS\s*=\s*(\d+)", mirror_src)
    assert ask_const is not None
    assert int(ask_const.group(1)) >= 240000  # Must exceed backend 180s Ollama generation budget

    # /ask, /audio/sentence, and /upload must pass explicit timeoutMs
    opts_body = r"(?:[^{}]|\{[^{}]*\})*"
    assert re.search(rf"ctx\.rest\('/ask',\s*\{{{opts_body}timeoutMs:\s*ASK_REQUEST_TIMEOUT_MS", mirror_src, re.DOTALL)
    assert re.search(rf"ctx\.rest\(`/audio/sentence/\$\{{currentSentIdx\}}\?format=json`,\s*\{{{opts_body}timeoutMs:\s*AUDIO_SYNTH_TIMEOUT_MS", mirror_src, re.DOTALL)
    assert re.search(rf"ctx\.rest\('/upload',\s*\{{{opts_body}timeoutMs:\s*DOCUMENT_LOAD_TIMEOUT_MS", mirror_src, re.DOTALL)





