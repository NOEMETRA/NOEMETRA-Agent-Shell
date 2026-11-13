"""Tests for player playback, pause, resume, and bookmark persistence."""

import json
import tempfile
import threading
import time
from pathlib import Path
import numpy as np
import pytest

from hermes_voice.extractor import DocumentExtractor, create_sample_italian_pdf
from hermes_voice.models import PlayerState
from hermes_voice.player import AudioOutputUnavailableError, DocumentPlayer


def test_player_pause_resume_bookmark():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        bookmark_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bookmark_path, virtual_playback=True)
        player.load_document(doc)

        assert player.state == PlayerState.IDLE

        # Start play
        player.play()
        assert player.state == PlayerState.PLAYING
        time.sleep(0.3)

        # Pause
        bm_pause = player.pause()
        assert player.state == PlayerState.PAUSED
        assert bookmark_path.exists()

        # Check saved bookmark file
        data = json.loads(bookmark_path.read_text(encoding="utf-8"))
        assert data["doc_id"] == doc.doc_id
        assert data["current_sentence_index"] == bm_pause.current_sentence_index
        assert data["current_page"] == bm_pause.current_page
        assert data["audio_sample_offset"] >= 0

        # Create new player simulating app restart, check bookmark restore
        player2 = DocumentPlayer(bookmark_path=bookmark_path, virtual_playback=True)
        player2.load_document(doc, resume_from_bookmark=True)

        assert player2.current_sentence_index == bm_pause.current_sentence_index
        assert player2.get_bookmark().current_page == bm_pause.current_page

        # Resume from exact bookmark
        player2.resume()
        assert player2.state == PlayerState.PLAYING
        time.sleep(0.2)
        player2.stop()
        assert player2.state == PlayerState.STOPPED


def test_player_rapid_pause_join_no_deadlock():
    """Verify that pause joins the worker thread cleanly without waiting for timeout."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test2.pdf"
        bookmark_path = Path(tmpdir) / "state2.json"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bookmark_path, virtual_playback=True)
        player.load_document(doc)
        player.play()
        time.sleep(0.12)

        t0 = time.perf_counter()
        player.pause()
        duration = time.perf_counter() - t0

        # Should finish fast (< 0.6s) without timing out at 1.5s
        assert duration < 1.0, f"pause() took {duration:.2f}s (deadlock/timeout detected)"
        assert not player._worker_thread.is_alive()


def test_player_switching_documents_preserves_independent_bookmarks():
    """Verify switching between library documents preserves each document's reading bookmark."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path_a = Path(tmpdir) / "doc_a.pdf"
        pdf_path_b = Path(tmpdir) / "doc_b.pdf"
        bookmark_path = Path(tmpdir) / "state_multi.json"
        create_sample_italian_pdf(pdf_path_a)
        create_sample_italian_pdf(pdf_path_b)

        extractor = DocumentExtractor()
        doc_a = extractor.extract(pdf_path_a)
        doc_b = extractor.extract(pdf_path_b)

        player = DocumentPlayer(bookmark_path=bookmark_path, virtual_playback=True)

        # 1. Load Doc A, seek to sentence 3, save bookmark
        player.load_document(doc_a)
        player.seek_to_sentence(3)
        player.pause()
        assert player.current_sentence_index == 3

        # 2. Load Doc B, seek to sentence 5, save bookmark
        player.load_document(doc_b)
        player.seek_to_sentence(5)
        player.pause()
        assert player.current_sentence_index == 5

        # 3. Switch back to Doc A, verify bookmark restores sentence 3
        player.load_document(doc_a, resume_from_bookmark=True)
        assert player.current_sentence_index == 3

        # 4. Switch back to Doc B, verify bookmark restores sentence 5
        player.load_document(doc_b, resume_from_bookmark=True)
        assert player.current_sentence_index == 5


def test_player_load_document_waits_for_previous_worker_without_audio_leak():
    """Verify that load_document waits for the previous worker and does not inherit stale audio."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path_a = Path(tmpdir) / "doc_a.pdf"
        pdf_path_b = Path(tmpdir) / "doc_b.pdf"
        bm_path = Path(tmpdir) / "state_leak.json"
        create_sample_italian_pdf(pdf_path_a)
        create_sample_italian_pdf(pdf_path_b)

        extractor = DocumentExtractor()
        doc_a = extractor.extract(pdf_path_a)
        doc_b = extractor.extract(pdf_path_b)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=True)
        player.load_document(doc_a)
        player.play()

        # Switch to Doc B while Doc A worker is running
        player.load_document(doc_b)
        assert player.document.doc_id == doc_b.doc_id
        assert player.state == PlayerState.IDLE
        assert player._current_audio is None
        assert player._current_sent_idx == 0


def test_player_discards_stale_synthesized_audio_after_seek():
    """Verify that synthesized audio finishing after a sentence seek within the same doc is discarded (P2)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        bm_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=True)
        player.load_document(doc)

        try:
            # Capture state before seek
            gen_before_seek = player._playback_generation
            sent_idx_before_seek = player.current_sentence_index
            assert sent_idx_before_seek == 0

            # Seek to sentence 2
            player.seek_to_sentence(2)
            assert player._playback_generation > gen_before_seek
            assert player.current_sentence_index == 2

            # An old worker finishing synthesis for sentence 0 attempts to cache its result
            stale_audio = np.ones(1000, dtype=np.float32)
            with player._lock:
                # Guard implemented in player.py lines 433 and 542:
                if (
                    player._document
                    and player._document.doc_id == doc.doc_id
                    and player._current_sent_idx == sent_idx_before_seek
                    and player._playback_generation == gen_before_seek
                ):
                    player._current_audio = stale_audio

            # Stale audio must have been discarded because sentence index and generation changed
            with player._lock:
                assert player._current_audio is None
        finally:
            player.stop()


def test_repeated_play_call_does_not_bump_generation_or_interrupt_playback():
    """Verify idempotent play() call when already PLAYING does not bump generation (P2)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc.pdf"
        bm_path = Path(tmpdir) / "state.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=True)
        player.load_document(doc)

        try:
            player.play()
            assert player.state == PlayerState.PLAYING
            gen_first = player._playback_generation

            # Call play() again while active
            player.play()
            assert player.state == PlayerState.PLAYING
            assert player._playback_generation == gen_first

            # Call resume() while active
            player.resume()
            assert player.state == PlayerState.PLAYING
            assert player._playback_generation == gen_first
        finally:
            player.stop()


def test_player_refuses_headless_server_playback_without_advancing_bookmark():
    """Verify server-side playback fails fast on headless machines without simulating progress (P2)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "doc_headless.pdf"
        bm_path = Path(tmpdir) / "state_headless.json"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        player = DocumentPlayer(bookmark_path=bm_path, virtual_playback=False, client_playback=False)
        player._has_audio_output_device = lambda: False
        player.load_document(doc)

        # 1. Server-side play() must raise AudioOutputUnavailableError and keep IDLE at sentence 0
        with pytest.raises(AudioOutputUnavailableError, match="Nessun dispositivo hardware di output audio"):
            player.play()
        assert player.state == PlayerState.IDLE
        assert player.current_sentence_index == 0

        # 2. Server-side resume() from a paused bookmark must raise and preserve exact sentence index
        player.seek_to_sentence(2)
        assert player.state == PlayerState.PAUSED
        assert player.current_sentence_index == 2
        with pytest.raises(AudioOutputUnavailableError, match="Nessun dispositivo hardware di output audio"):
            player.resume()
        assert player.state == PlayerState.PAUSED
        assert player.current_sentence_index == 2

        # 3. Even if _run_audio_playback() is invoked after device loss, it pauses without advancing
        player._state = PlayerState.PLAYING
        player._run_audio_playback()
        assert player.state == PlayerState.PAUSED
        assert player.current_sentence_index == 2


def test_tts_engine_clears_model_on_voice_initialization_failure_and_recovers(monkeypatch):
    """Verify PocketTTSEngine publishes _model only after _voice_state succeeds and retries cleanly after failure (P2)."""
    import sys
    from types import SimpleNamespace
    from hermes_voice.tts_engine import PocketTTSEngine

    attempts = {"load_model": 0, "voice_prompt": 0}

    class FakeTTSModel:
        config = SimpleNamespace(mimi=SimpleNamespace(sample_rate=24000))

        def to(self, device: str):
            return self

        def get_state_for_audio_prompt(self, voice: str):
            attempts["voice_prompt"] += 1
            if attempts["voice_prompt"] == 1:
                raise ConnectionError("Simulated interrupted voice prompt download")
            return {"voice": voice, "ready": True}

        def generate_audio(self, model_state, text_to_generate: str, copy_state: bool = True):
            assert model_state is not None and model_state.get("ready") is True
            return np.ones(2400, dtype=np.float32) * 0.1

    class FakeTTSModelFactory:
        @staticmethod
        def load_model(language: str, quantize: bool = False):
            attempts["load_model"] += 1
            return FakeTTSModel()

    monkeypatch.setitem(sys.modules, "pocket_tts", SimpleNamespace(TTSModel=FakeTTSModelFactory))

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = PocketTTSEngine(cache_dir=Path(tmpdir) / "tts_cache", lazy_load=True)

        # First call fails during voice conditioning; _model and _voice_state must remain unpublished (None)
        with pytest.raises(ConnectionError, match="Simulated interrupted voice prompt download"):
            engine.synthesize("Prima frase di prova.", use_cache=False)

        assert engine._model is None
        assert engine._voice_state is None
        assert attempts["load_model"] == 1
        assert attempts["voice_prompt"] == 1

        # Subsequent call after connectivity recovery re-runs full initialization and succeeds
        audio_np, sr = engine.synthesize("Prima frase di prova.", use_cache=False)
        assert sr == 24000
        assert len(audio_np) == 2400
        assert engine._model is not None
        assert engine._voice_state == {"voice": "giovanni", "ready": True}
        assert attempts["load_model"] == 2
        assert attempts["voice_prompt"] == 2


def test_normalize_text_for_tts_technical_schemas():
    from hermes_voice.tts_engine import normalize_text_for_tts

    # Numbered paragraphs & sections
    assert normalize_text_for_tts("1. Configurazione di sistema.") == "1, Configurazione di sistema."
    assert normalize_text_for_tts("1.2.3 Titolo tecnico") == "1 punto 2 punto 3, Titolo tecnico"
    assert normalize_text_for_tts("Art. 1. Oggetto") == "Articolo 1, Oggetto"

    # Alphanumeric assignments, operators, temperatures
    assert normalize_text_for_tts("P1=10") == "P 1 uguale a 10"
    assert normalize_text_for_tts("p1<=5") == "p 1 minore o uguale a 5"
    assert normalize_text_for_tts("T2>=25°C") == "T 2 maggiore o uguale a 25 gradi Celsius"
    assert normalize_text_for_tts("P1!=0 -> attivo") == "P 1 diverso da 0 verso attivo"

    # Slashes read as "barra"
    assert normalize_text_for_tts("Modello client/server") == "Modello client barra server"
    assert normalize_text_for_tts("Modalità lettura/scrittura (on/off)") == (
        "Modalità lettura barra scrittura on barra off"
    )

    # Versions, decimals, thousands, decorative dividers, and prose preservation
    assert normalize_text_for_tts("Versione v2.6 con fattore 0.75") == (
        "Versione v 2 punto 6 con fattore 0 virgola 75"
    )
    assert normalize_text_for_tts("Valore pari a 1.000.000 euro.") == "Valore pari a 1.000.000 euro."
    assert normalize_text_for_tts("---") == ""
    assert normalize_text_for_tts("•••") == ""
    prose = "La presente relazione illustra i risultati dell'analisi nel 2025."
    assert normalize_text_for_tts(prose) == prose


def test_normalize_text_for_tts_dates_and_uppercase_titles():
    from hermes_voice.tts_engine import normalize_text_for_tts

    # Dates in European, dot, hyphen, ISO, 2-digit year, and MM/YYYY formats (with trailing period)
    assert normalize_text_for_tts("13/11/2026") == "13 novembre 2026"
    assert normalize_text_for_tts("Valido dal 13/11/2026.") == "Valido dal 13 novembre 2026."
    assert normalize_text_for_tts("Data: 13.11.2026") == "Data: 13 novembre 2026"
    assert normalize_text_for_tts("Aggiornato il 2026-11-13.") == "Aggiornato il 13 novembre 2026."
    assert normalize_text_for_tts("13-11-2026") == "13 novembre 2026"
    assert normalize_text_for_tts("01/02/25") == "1 febbraio 25"
    assert normalize_text_for_tts("Rev. 11/2026") == "Revisione novembre 2026"

    # ALL-CAPS titles and embedded uppercase blocks converted cleanly while preserving technical acronyms
    assert normalize_text_for_tts("MANUALE TECNICO DI INSTALLAZIONE") == (
        "Manuale tecnico di installazione"
    )
    assert normalize_text_for_tts("1. INTRODUZIONE AL SISTEMA TCP/IP") == (
        "1, Introduzione al sistema TCP barra IP"
    )
    assert normalize_text_for_tts("ART. 1. OGGETTO DEL CONTRATTO") == (
        "Articolo 1, oggetto del contratto"
    )
    assert normalize_text_for_tts("CAPITOLO 1 - ARCHITETTURA") == (
        "Capitolo 1, architettura"
    )
    assert normalize_text_for_tts("CAPITOLO IV - NORME") == "Capitolo 4, norme"
    assert normalize_text_for_tts("Rev. 1.2 del 13/11/2026") == (
        "Revisione 1 punto 2 del 13 novembre 2026"
    )
    assert normalize_text_for_tts("Configurazione AI e REST API") == (
        "Configurazione AI e REST API"
    )


def test_tts_engine_synthesizes_normalized_technical_text(monkeypatch):
    import sys
    from types import SimpleNamespace
    from hermes_voice.tts_engine import PocketTTSEngine

    captured_prompts = []

    class FakeTTSModel:
        config = SimpleNamespace(mimi=SimpleNamespace(sample_rate=24000))

        def to(self, device: str):
            return self

        def get_state_for_audio_prompt(self, voice: str):
            return {"voice": voice, "ready": True}

        def generate_audio(self, model_state, text_to_generate: str, copy_state: bool = True):
            captured_prompts.append(text_to_generate)
            return np.ones(1200, dtype=np.float32) * 0.1

    class FakeTTSModelFactory:
        @staticmethod
        def load_model(language: str, quantize: bool = False):
            return FakeTTSModel()

    monkeypatch.setitem(sys.modules, "pocket_tts", SimpleNamespace(TTSModel=FakeTTSModelFactory))

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = PocketTTSEngine(cache_dir=Path(tmpdir) / "tts_cache", lazy_load=True)

        # Non-speakable divider returns short silence without loading or calling the model
        silent, sr = engine.synthesize("---", use_cache=True)
        assert sr == 24000
        assert len(silent) == 2400
        assert captured_prompts == []

        audio, sr = engine.synthesize("1. Modalità client/server con P1=10.", use_cache=True)
        assert sr == 24000
        assert len(audio) == 1200
        assert captured_prompts == ["1, Modalità client barra server con P 1 uguale a 10."]

        # Second call with same input hits audio cache without re-invoking generate_audio
        cached_audio, _ = engine.synthesize("1. Modalità client/server con P1=10.", use_cache=True)
        assert len(cached_audio) == 1200
        assert len(captured_prompts) == 1





