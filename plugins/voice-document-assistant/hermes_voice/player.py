"""Audio player with pause, resume, exact position tracking and bookmark persistence.

Strict constraint: Reads verbatim document sentences synthesized by Pocket TTS.
Zero LLM rewriting of document text.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional
import numpy as np

from hermes_voice.models import ExtractedDocument, PlayerState, ReadingBookmark, SentenceSpan
from hermes_voice.tts_engine import PocketTTSEngine

logger = logging.getLogger(__name__)


class DocumentPlayer:
    """Manages audio synthesis and playback with exact pause/resume semantics."""

    def __init__(
        self,
        tts_engine: Optional[PocketTTSEngine] = None,
        bookmark_path: Optional[str | Path] = None,
        virtual_playback: bool = False,
        on_sentence_change: Optional[Callable[[SentenceSpan], None]] = None,
    ):
        self.tts = tts_engine or PocketTTSEngine(lazy_load=True)
        self.bookmark_path = Path(bookmark_path or Path.home() / ".hermes" / "reading_state.json")
        self.bookmark_path.parent.mkdir(parents=True, exist_ok=True)
        self.virtual_playback = virtual_playback
        self.on_sentence_change = on_sentence_change

        self._document: Optional[ExtractedDocument] = None
        self._state = PlayerState.IDLE
        self._current_sent_idx = 0
        self._sample_offset = 0
        self._speed: float = 1.0

        self._current_audio: Optional[np.ndarray] = None
        self._current_sr: int = 24000

        self._lock = threading.RLock()
        self._stream = None
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

    @property
    def state(self) -> PlayerState:
        with self._lock:
            return self._state

    @property
    def current_sentence_index(self) -> int:
        with self._lock:
            return self._current_sent_idx

    @property
    def document(self) -> Optional[ExtractedDocument]:
        return self._document

    @property
    def speed(self) -> float:
        with self._lock:
            return self._speed

    def set_speed(self, speed: float) -> None:
        """Set playback speed factor (e.g. 1.0, 1.25, 1.5)."""
        with self._lock:
            self._speed = max(0.5, min(2.5, float(speed)))

    def load_document(self, document: ExtractedDocument, resume_from_bookmark: bool = True) -> ReadingBookmark:
        """Load an extracted document and optionally restore previous bookmark."""
        with self._lock:
            self.stop()
            self._document = document
            self._current_sent_idx = 0
            self._sample_offset = 0
            self._current_audio = None
            self._state = PlayerState.IDLE

            if resume_from_bookmark and self.bookmark_path.exists():
                try:
                    data = json.loads(self.bookmark_path.read_text(encoding="utf-8"))
                    saved_bookmark = ReadingBookmark(**data)
                    if saved_bookmark.doc_id == document.doc_id:
                        self._current_sent_idx = min(
                            saved_bookmark.current_sentence_index,
                            max(0, len(document.all_sentences) - 1),
                        )
                        self._sample_offset = saved_bookmark.audio_sample_offset
                        self._state = PlayerState.PAUSED
                        logger.info(
                            f"Bookmark ripristinato: frase {self._current_sent_idx + 1}/"
                            f"{len(document.all_sentences)} (Pagina {saved_bookmark.current_page})"
                        )
                except Exception as e:
                    logger.warning(f"Errore lettura bookmark da {self.bookmark_path}: {e}")

            return self.get_bookmark()

    def play(self) -> ReadingBookmark:
        """Start or resume playback from current position."""
        with self._lock:
            if not self._document or not self._document.all_sentences:
                raise ValueError("Nessun documento caricato per la riproduzione.")

            if self._state == PlayerState.PLAYING:
                return self.get_bookmark()

            # Ensure previous worker thread is finished
            if self._worker_thread and self._worker_thread.is_alive():
                self._stop_event.set()
                self._pause_event.set()
                self._worker_thread.join(timeout=1.0)

            self._stop_event.clear()
            self._pause_event.clear()
            self._state = PlayerState.PLAYING

            if self.virtual_playback:
                self._worker_thread = threading.Thread(target=self._run_virtual_playback, daemon=True)
            else:
                self._worker_thread = threading.Thread(target=self._run_audio_playback, daemon=True)

            self._worker_thread.start()
            self._save_bookmark()
            return self.get_bookmark()

    def pause(self) -> ReadingBookmark:
        """Pause playback and save bookmark with exact millisecond/sentence offset."""
        worker_to_join = None
        with self._lock:
            if self._state != PlayerState.PLAYING:
                return self.get_bookmark()

            self._pause_event.set()
            self._state = PlayerState.PAUSED

            if self._stream is not None:
                try:
                    self._stream.stop()
                    self._stream.close()
                except Exception:
                    pass
                self._stream = None

            if self._worker_thread and self._worker_thread.is_alive():
                worker_to_join = self._worker_thread

        # Join worker thread cleanly outside the lock to prevent deadlock with worker's sample_offset lock
        if worker_to_join and worker_to_join != threading.current_thread():
            worker_to_join.join(timeout=1.5)

        with self._lock:
            bookmark = self._save_bookmark()
            logger.info(
                f"Riproduzione in pausa su frase {bookmark.current_sentence_index + 1} "
                f"(Pagina {bookmark.current_page}, offset {bookmark.audio_seconds_offset:.2f}s)"
            )
            return bookmark

    def resume(self) -> ReadingBookmark:
        """Resume playback from exactly where paused."""
        return self.play()

    def stop(self) -> ReadingBookmark:
        """Stop playback completely."""
        worker_to_join = None
        with self._lock:
            self._stop_event.set()
            self._pause_event.set()

            if self._stream is not None:
                try:
                    self._stream.stop()
                    self._stream.close()
                except Exception:
                    pass
                self._stream = None

            if self._worker_thread and self._worker_thread.is_alive():
                worker_to_join = self._worker_thread

            self._state = PlayerState.STOPPED

        # Join worker thread cleanly outside the lock
        if worker_to_join and worker_to_join != threading.current_thread():
            worker_to_join.join(timeout=1.5)

        with self._lock:
            return self._save_bookmark()

    def seek_to_sentence(self, sentence_index: int) -> ReadingBookmark:
        """Jump to specific sentence index."""
        with self._lock:
            if not self._document:
                raise ValueError("Nessun documento caricato.")
            was_playing = (self._state == PlayerState.PLAYING)
            self.stop()
            self._current_sent_idx = max(0, min(sentence_index, len(self._document.all_sentences) - 1))
            self._sample_offset = 0
            self._current_audio = None
            self._state = PlayerState.PAUSED
            self._save_bookmark()
            if was_playing:
                self.play()
            return self.get_bookmark()

    def seek_to_page(self, page_number: int) -> ReadingBookmark:
        """Jump to the first sentence of the given page."""
        with self._lock:
            if not self._document:
                raise ValueError("Nessun documento caricato.")
            target_idx = 0
            for sent in self._document.all_sentences:
                if sent.page_number == page_number:
                    target_idx = sent.sentence_index
                    break
            return self.seek_to_sentence(target_idx)

    def get_bookmark(self) -> ReadingBookmark:
        """Get current playback state snapshot."""
        with self._lock:
            doc_id = self._document.doc_id if self._document else ""
            file_path = self._document.file_path if self._document else ""
            curr_sent = None
            page = 1
            text = ""
            total = 0

            if self._document and self._document.all_sentences:
                total = len(self._document.all_sentences)
                if 0 <= self._current_sent_idx < total:
                    curr_sent = self._document.all_sentences[self._current_sent_idx]
                    page = curr_sent.page_number
                    text = curr_sent.text

            seconds = self._sample_offset / max(self._current_sr, 1)

            return ReadingBookmark(
                doc_id=doc_id,
                file_path=file_path,
                current_sentence_index=self._current_sent_idx,
                current_page=page,
                current_sentence_text=text,
                audio_sample_offset=self._sample_offset,
                audio_seconds_offset=round(seconds, 3),
                state=self._state,
                total_sentences=total,
            )

    def _save_bookmark(self) -> ReadingBookmark:
        """Persist current bookmark to JSON file if a document is loaded."""
        bookmark = self.get_bookmark()
        if not self._document:
            return bookmark
        try:
            self.bookmark_path.write_text(bookmark.model_dump_json(indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Impossibile salvare il bookmark su {self.bookmark_path}: {e}")
        return bookmark

    def _run_audio_playback(self) -> None:
        """Real audio playback loop using sounddevice."""
        try:
            import sounddevice as sd
        except ImportError:
            logger.warning("sounddevice non disponibile. Passaggio alla riproduzione virtuale.")
            self._run_virtual_playback()
            return

        while not self._stop_event.is_set() and not self._pause_event.is_set():
            with self._lock:
                if not self._document or self._current_sent_idx >= len(self._document.all_sentences):
                    self._state = PlayerState.FINISHED
                    self._save_bookmark()
                    break

                sentence = self._document.all_sentences[self._current_sent_idx]
                effective_speed = self._speed

            if self.on_sentence_change:
                try:
                    self.on_sentence_change(sentence)
                except Exception:
                    pass

            # Synthesize sentence if not already cached in memory
            if self._current_audio is None:
                audio_data, sr = self.tts.synthesize(sentence.text)
                with self._lock:
                    self._current_audio = audio_data
                    self._current_sr = sr

            # Prepare audio slice starting from sample_offset
            audio_to_play = self._current_audio[self._sample_offset:]
            if len(audio_to_play) == 0:
                with self._lock:
                    self._current_sent_idx += 1
                    self._sample_offset = 0
                    self._current_audio = None
                continue

            # Play using sounddevice stream with chunk progress tracking
            playback_sr = int(self._current_sr * effective_speed)
            chunk_size = int(self._current_sr * 0.1)  # 100ms chunks for responsive pause
            chunk_idx = 0

            try:
                with sd.OutputStream(samplerate=playback_sr, channels=1, dtype="float32") as stream:
                    self._stream = stream
                    while chunk_idx < len(audio_to_play):
                        if self._stop_event.is_set() or self._pause_event.is_set():
                            break

                        end_chunk = min(chunk_idx + chunk_size, len(audio_to_play))
                        slice_chunk = audio_to_play[chunk_idx:end_chunk]
                        stream.write(slice_chunk)

                        with self._lock:
                            self._sample_offset += len(slice_chunk)

                        chunk_idx = end_chunk

                    self._stream = None

            except Exception as e:
                logger.error(f"Errore hardware audio in riproduzione: {e}")
                time.sleep(0.1)

            if self._pause_event.is_set() or self._stop_event.is_set():
                break

            # Sentence finished naturally
            with self._lock:
                self._current_sent_idx += 1
                self._sample_offset = 0
                self._current_audio = None
                self._save_bookmark()

    def _run_virtual_playback(self) -> None:
        """Simulated playback loop for headless execution, automated tests and CI."""
        while not self._stop_event.is_set() and not self._pause_event.is_set():
            with self._lock:
                if not self._document or self._current_sent_idx >= len(self._document.all_sentences):
                    self._state = PlayerState.FINISHED
                    self._save_bookmark()
                    break

                sentence = self._document.all_sentences[self._current_sent_idx]
                effective_speed = self._speed

            if self.on_sentence_change:
                try:
                    self.on_sentence_change(sentence)
                except Exception:
                    pass

            words = sentence.text.split()
            estimated_duration = max(0.4, (len(words) * 0.25) / effective_speed)
            step_duration = 0.05
            elapsed = self._sample_offset / self._current_sr if self._current_sr else 0.0

            while elapsed < estimated_duration:
                if self._stop_event.is_set() or self._pause_event.is_set():
                    break
                time.sleep(step_duration)
                elapsed += step_duration
                with self._lock:
                    self._sample_offset = int(elapsed * self._current_sr)

            if self._pause_event.is_set() or self._stop_event.is_set():
                break

            # Sentence finished
            with self._lock:
                self._current_sent_idx += 1
                self._sample_offset = 0
                self._current_audio = None
                self._save_bookmark()
