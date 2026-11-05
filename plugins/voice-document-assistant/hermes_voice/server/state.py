"""Persistent singleton manager for HermesVoiceAssistant."""

from __future__ import annotations

import logging
import threading
from typing import Optional

from hermes_voice.pipeline import HermesVoiceAssistant

logger = logging.getLogger(__name__)

_assistant: Optional[HermesVoiceAssistant] = None
_lock = threading.Lock()


def get_assistant() -> HermesVoiceAssistant:
    """Return persistent singleton assistant instance across all requests and sessions."""
    global _assistant
    with _lock:
        if _assistant is None:
            logger.info("Inizializzazione del singleton persistente HermesVoiceAssistant...")
            _assistant = HermesVoiceAssistant()
        return _assistant
