"""Hermes Agent native plugin module.

Registers tools for document audio playback, pause, resume,
exact bookmarking, and grounded question answering adhering strictly
to the official Hermes Tool Registry contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_voice.server.state import get_assistant


def voice_load_document(pdf_path: str) -> str:
    """Carica un documento PDF, ne estrae il testo in modo deterministico e prepara la lettura vocale."""
    assistant = get_assistant()
    bookmark = assistant.load_document(pdf_path)
    return json.dumps({
        "status": "success",
        "doc_id": bookmark.doc_id,
        "title": assistant.current_document.title if assistant.current_document else "",
        "total_pages": assistant.current_document.total_pages if assistant.current_document else 0,
        "total_sentences": bookmark.total_sentences,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
    }, indent=2)


def voice_play_document() -> str:
    """Avvia o riprende la riproduzione vocale deterministica del documento caricato con Pocket TTS."""
    assistant = get_assistant()
    bookmark = assistant.play()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_pause_document() -> str:
    """Mette in pausa la lettura vocale e memorizza il punto esatto (frase e millisecondo)."""
    assistant = get_assistant()
    bookmark = assistant.pause()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "audio_seconds_offset": bookmark.audio_seconds_offset,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_resume_document() -> str:
    """Riprende la lettura vocale esattamente dal punto in cui era stata sospesa."""
    assistant = get_assistant()
    bookmark = assistant.resume()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_stop_document() -> str:
    """Interrompe completamente la riproduzione vocale."""
    assistant = get_assistant()
    bookmark = assistant.stop()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
    }, indent=2)


def voice_seek_document(page: Optional[int] = None, sentence_index: Optional[int] = None) -> str:
    """Salta a una pagina o frase specifica del documento."""
    assistant = get_assistant()
    if sentence_index is not None:
        bookmark = assistant.seek_sentence(sentence_index)
    elif page is not None:
        bookmark = assistant.seek_page(page)
    else:
        return json.dumps({"error": "Specificare 'page' o 'sentence_index'."})

    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_ask_document(question: str) -> str:
    """Interroga il documento: il Bibliotecario estrae le evidenze, l'Analista risponde con numeri di pagina e il Verificatore convalida la citazione."""
    assistant = get_assistant()
    answer = assistant.ask(question)
    return json.dumps({
        "question": answer.question,
        "answer": answer.answer,
        "citations": [c.model_dump() for c in answer.citations],
        "verification": answer.verification.model_dump() if answer.verification else None,
        "model_used": answer.model_used,
        "latency_seconds": answer.latency_seconds,
    }, indent=2)


def voice_get_status() -> str:
    """Restituisce lo stato attuale del lettore vocale e il bookmark registrato."""
    assistant = get_assistant()
    status = assistant.get_full_status()
    return json.dumps(status.model_dump(), indent=2)


# Official tool definitions with schema and signatures
TOOLS = [
    {
        "name": "voice_load_document",
        "description": "Carica un documento PDF nella memoria locale, estrae il testo in modo deterministico e lo predispone per la lettura vocale.",
        "handler": voice_load_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_load_document",
                "description": "Carica un PDF locale ed estrae le frasi originali.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pdf_path": {"type": "string", "description": "Percorso assoluto o relativo del file PDF"}
                    },
                    "required": ["pdf_path"],
                },
            },
        },
    },
    {
        "name": "voice_play_document",
        "description": "Avvia la lettura ad alta voce del documento caricato usando Pocket TTS con la voce italiana selezionata.",
        "handler": voice_play_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_play_document",
                "description": "Avvia la riproduzione vocale deterministica con Pocket TTS.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    },
    {
        "name": "voice_pause_document",
        "description": "Mette in pausa la lettura audio del documento e memorizza il punto esatto di lettura.",
        "handler": voice_pause_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_pause_document",
                "description": "Mette in pausa la riproduzione vocale e registra il bookmark esatto.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    },
    {
        "name": "voice_resume_document",
        "description": "Riprende la lettura vocale del documento dal punto esatto in cui era stata interrotta.",
        "handler": voice_resume_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_resume_document",
                "description": "Riprende la riproduzione dal punto esatto memorizzato.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    },
    {
        "name": "voice_stop_document",
        "description": "Interrompe completamente la riproduzione vocale in corso.",
        "handler": voice_stop_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_stop_document",
                "description": "Interrompe la riproduzione audio.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    },
    {
        "name": "voice_seek_document",
        "description": "Sposta il punto di lettura alla pagina o alla frase indicata.",
        "handler": voice_seek_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_seek_document",
                "description": "Sposta il cursore di lettura a una specifica pagina o frase.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "page": {"type": "integer", "description": "Numero di pagina a cui saltare (1-based)"},
                        "sentence_index": {"type": "integer", "description": "Indice frase a cui saltare (0-based)"},
                    },
                },
            },
        },
    },
    {
        "name": "voice_ask_document",
        "description": "Interroga il documento corrente: Bibliotecario estrae evidenze, Analista risponde con numeri di pagina, Verificatore valida la fedeltà delle citazioni.",
        "handler": voice_ask_document,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_ask_document",
                "description": "Interroga il documento con la Triade di Agenti e ricevi una risposta verificata con citazioni esplicite.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "question": {"type": "string", "description": "Domanda sul contenuto del documento"}
                    },
                    "required": ["question"],
                },
            },
        },
    },
    {
        "name": "voice_get_status",
        "description": "Ottiene lo stato live del lettore (in riproduzione, in pausa, stopped), frase corrente, tempo e stato degli agenti.",
        "handler": voice_get_status,
        "schema": {
            "type": "function",
            "function": {
                "name": "voice_get_status",
                "description": "Restituisce lo stato live della riproduzione vocale e degli agenti.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    },
]


def register(ctx) -> None:
    """Entrypoint called by Hermes Agent PluginManager."""
    toolset = "voice-document-assistant"

    if hasattr(ctx, "register_tool"):
        for tool_def in TOOLS:
            try:
                # Official Hermes signature:
                # register_tool(name, toolset, schema, handler, description=..., emoji=...)
                ctx.register_tool(
                    name=tool_def["name"],
                    toolset=toolset,
                    schema=tool_def["schema"],
                    handler=tool_def["handler"],
                    description=tool_def["description"],
                    emoji="🔊",
                )
            except TypeError:
                # Fallback for alternative signature shapes
                try:
                    ctx.register_tool(
                        tool_def["name"],
                        tool_def["handler"],
                        tool_def["description"],
                    )
                except Exception:
                    pass
