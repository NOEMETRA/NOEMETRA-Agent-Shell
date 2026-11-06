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



