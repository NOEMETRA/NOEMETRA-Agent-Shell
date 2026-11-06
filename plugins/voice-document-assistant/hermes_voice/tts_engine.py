"""Deterministic Pocket TTS synthesis engine with Italian models and voice Giovanni.

Strict constraint: Verbatim reading of extracted document sentences.
No text transformation or LLM rewriting is applied.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
import numpy as np
import soundfile as sf

from hermes_voice.profile import ensure_voice_dir, resolve_voice_profile_dir

logger = logging.getLogger(__name__)


class PocketTTSEngine:
    """Wrapper around Kyutai Labs Pocket TTS for Italian speech synthesis."""

    def __init__(
        self,
        language: str = "italian",
        voice: str = "giovanni",
        cache_dir: Optional[Union[str, Path]] = None,
        quantize: bool = False,
        lazy_load: bool = True,
    ):
        self.language = language
        self.voice = voice
        self.quantize = quantize
        self._lazy_load = lazy_load
        self.cache_dir = Path(cache_dir or resolve_voice_profile_dir() / "audio_cache")
        ensure_voice_dir(self.cache_dir)
        self._lock = threading.Lock()

        self._model = None
        self._voice_state = None
        self._sample_rate: int = 24000

        if not lazy_load:
            with self._lock:
                self._ensure_loaded()

    def set_model(self, language: str) -> None:
        """Switch model between 'italian' and 'italian_24l' thread-safely."""
        with self._lock:
            was_loaded = self._model is not None and self._voice_state is not None
            if language == self.language and was_loaded:
                return
            logger.info(f"Cambiamento modello Pocket TTS: '{self.language}' -> '{language}'")
            self.language = language
            self._model = None
            self._voice_state = None
            if was_loaded or not self._lazy_load:
                self._ensure_loaded()

    def set_voice(self, voice: str) -> None:
        """Switch voice (e.g. 'giovanni') thread-safely."""
        with self._lock:
            if voice == self.voice and self._voice_state is not None:
                return
            if self._model is not None:
                logger.info(f"Aggiornamento voce a '{voice}'...")
                new_voice_state = self._model.get_state_for_audio_prompt(voice)
                self.voice = voice
                self._voice_state = new_voice_state
            else:
                self.voice = voice

    def _ensure_loaded(self) -> None:
        """Load model and compute conditioning state for chosen voice atomically."""
        if self._model is not None and self._voice_state is not None:
            return

        from pocket_tts import TTSModel

        try:
            logger.info(f"Caricamento Pocket TTS: lingua='{self.language}', quantize={self.quantize}...")
            t0 = time.perf_counter()
            loaded_model = TTSModel.load_model(
                language=self.language,
                quantize=self.quantize,
            )
            loaded_model.to("cpu")
            load_time = time.perf_counter() - t0
            logger.info(f"Modello Pocket TTS caricato in {load_time:.2f}s")

            # Extract sample rate from config
            sample_rate = self._sample_rate
            if hasattr(loaded_model, "config") and hasattr(loaded_model.config, "mimi"):
                sample_rate = loaded_model.config.mimi.sample_rate

            # Cache voice conditioning state before publishing _model
            logger.info(f"Preparazione condizionamento vocale per '{self.voice}'...")
            loaded_voice_state = loaded_model.get_state_for_audio_prompt(self.voice)

            self._model = loaded_model
            self._voice_state = loaded_voice_state
            self._sample_rate = sample_rate
        except Exception:
            self._model = None
            self._voice_state = None
            raise

    @property
    def sample_rate(self) -> int:
        if self._model is not None and hasattr(self._model, "config"):
            return self._model.config.mimi.sample_rate
        return self._sample_rate

    def synthesize(self, text: str, use_cache: bool = True) -> Tuple[np.ndarray, int]:
        """Synthesize verbatim Italian text to audio array (float32, 1D)."""
        clean_text = text.strip()
        if not clean_text:
            return np.zeros(int(self.sample_rate * 0.1), dtype=np.float32), self.sample_rate

        # Cache key
        cache_key = hashlib.sha256(
            f"{self.language}_{self.voice}_{self.quantize}_{clean_text}".encode("utf-8")
        ).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.wav"

        if use_cache and cache_file.exists():
            data, sr = sf.read(str(cache_file), dtype="float32")
            if data.ndim > 1:
                data = data[:, 0]
            return data, sr

        # Audio generation serialized under model lock
        with self._lock:
            self._ensure_loaded()

            import torch

            audio_tensor = self._model.generate_audio(
                model_state=self._voice_state,
                text_to_generate=clean_text,
                copy_state=True,
            )

        # Convert to numpy float32 1D array
        if isinstance(audio_tensor, torch.Tensor):
            audio_np = audio_tensor.detach().cpu().numpy()
        else:
            audio_np = np.asarray(audio_tensor)

        audio_np = audio_np.squeeze().astype(np.float32)

        # Save to disk cache
        if use_cache:
            try:
                ensure_voice_dir(self.cache_dir)
                sf.write(str(cache_file), audio_np, self.sample_rate)
            except Exception as e:
                logger.warning(f"Impossibile scrivere la cache audio su {cache_file}: {e}")

        return audio_np, self.sample_rate

    def benchmark(
        self,
        test_text: str = "Questo è un test prestazionale della sintesi vocale italiana.",
        runs: int = 1,
    ) -> Dict[str, Union[float, str, int]]:
        """Run reproducible benchmark measuring latency, RTF and memory."""
        with self._lock:
            self._ensure_loaded()
        import psutil

        process = psutil.Process()
        mem_before_mb = process.memory_info().rss / (1024 * 1024)

        t_start = time.perf_counter()
        audio_arr, sr = self.synthesize(test_text, use_cache=False)
        total_time = time.perf_counter() - t_start

        mem_after_mb = process.memory_info().rss / (1024 * 1024)
        audio_duration_sec = len(audio_arr) / sr

        # Real-time factor (RTF): compute_time / audio_duration
        # Speedup: audio_duration / compute_time (e.g. 2.6x real time)
        rtf = total_time / max(audio_duration_sec, 0.001)
        speedup = audio_duration_sec / max(total_time, 0.001)

        return {
            "model_language": self.language,
            "voice": self.voice,
            "quantized": self.quantize,
            "sample_rate": sr,
            "audio_duration_sec": round(audio_duration_sec, 3),
            "generation_time_sec": round(total_time, 3),
            "rtf": round(rtf, 3),
            "speedup_factor": round(speedup, 2),
            "ram_before_mb": round(mem_before_mb, 1),
            "ram_after_mb": round(mem_after_mb, 1),
            "ram_delta_mb": round(mem_after_mb - mem_before_mb, 1),
            "is_realtime_capable": speedup >= 1.0,
        }
