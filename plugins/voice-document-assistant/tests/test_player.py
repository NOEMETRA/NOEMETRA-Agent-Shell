"""Tests for player playback, pause, resume, and bookmark persistence."""

import json
import tempfile
import time
from pathlib import Path
import pytest

from hermes_voice.extractor import DocumentExtractor, create_sample_italian_pdf
from hermes_voice.models import PlayerState
from hermes_voice.player import DocumentPlayer


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
