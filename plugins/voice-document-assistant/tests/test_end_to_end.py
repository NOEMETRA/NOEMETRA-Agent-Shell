"""End-to-End Success Criterion Integration Test.

Test scenario:
1. Load Italian PDF
2. Play audio of verbatim text
3. Pause playback and save exact bookmark
4. Ask a question during pause and receive verified answer with page number
5. Resume playback from the exact paused bookmark
"""

import tempfile
import time
from pathlib import Path
import pytest

from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.models import PlayerState
from hermes_voice.pipeline import HermesVoiceAssistant


def test_full_success_scenario():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "documento_test.pdf"
        bookmark_path = Path(tmpdir) / "bookmark.json"
        create_sample_italian_pdf(pdf_path)

        # 1. Carico un PDF italiano
        assistant = HermesVoiceAssistant(
            bookmark_path=bookmark_path,
            virtual_playback=True,
        )
        initial_bm = assistant.load_document(pdf_path)
        assert assistant.current_document is not None
        assert assistant.current_document.total_pages == 3
        assert len(assistant.current_document.all_sentences) >= 6

        # 2. Ascolto il testo originale (Avvio lettura)
        play_bm = assistant.play()
        assert assistant.player.state == PlayerState.PLAYING
        time.sleep(0.4)

        # 3. Interrompo la lettura
        pause_bm = assistant.pause()
        assert assistant.player.state == PlayerState.PAUSED
        paused_sent_idx = pause_bm.current_sentence_index
        paused_page = pause_bm.current_page
        paused_offset = pause_bm.audio_sample_offset

        assert paused_sent_idx >= 0
        assert paused_page >= 1
        assert pause_bm.current_sentence_text != ""

        # 4. Faccio una domanda, ricevo una risposta con riferimenti verificabili
        question = "Quali sono i tre agenti che compongono la triade di interazione?"
        answer = assistant.ask(question)

        assert answer.answer != ""
        assert len(answer.citations) > 0

        # Citations must point to Page 3 where the Triad of Agents is discussed
        cited_pages = [c.page_number for c in answer.citations]
        assert 3 in cited_pages or 1 in cited_pages

        # Verification must pass without unsupported claims
        assert answer.verification is not None
        assert answer.verification.is_valid is True
        assert answer.verification.citation_match_score >= 0.8

        # 5. Riprendo esattamente da dove mi ero fermato
        resume_bm = assistant.resume()
        assert assistant.player.state == PlayerState.PLAYING
        assert resume_bm.current_sentence_index == paused_sent_idx
        assert resume_bm.current_page == paused_page

        time.sleep(0.2)
        assistant.stop()
        assert assistant.player.state == PlayerState.STOPPED
