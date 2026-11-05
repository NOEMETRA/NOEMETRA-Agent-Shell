"""Hermes Agent native plugin module.

Registers tools for document audio playback, pause, resume,
exact bookmarking, and grounded question answering adhering strictly
to the official Hermes Tool Registry contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional

def _get_assistant():
    """Lazily load the assistant instance, handling missing optional dependencies gracefully."""
    try:
        from hermes_voice.server.state import get_assistant
        return get_assistant()
    except (ImportError, ModuleNotFoundError) as err:
        raise RuntimeError(
            f"Dipendenze Python mancanti per voice-document-assistant ({err}). "
            "Installare con: hermes plugins install voice-document-assistant"
        ) from err


def _extract_arg(args: Any, kwargs: dict, key: str, default: Any = None) -> Any:
    """Extract named argument from either dictionary args or keyword arguments."""
    if isinstance(args, dict):
        if key in args:
            return args[key]
    elif args is not None and not isinstance(args, dict):
        return args
    return kwargs.get(key, default)


def voice_load_document(args: Any = None, **kwargs) -> str:
    """Carica un documento PDF, ne estrae il testo in modo deterministico e prepara la lettura vocale."""
    pdf_path = str(_extract_arg(args, kwargs, "pdf_path", "") or "")
    if not pdf_path:
        return json.dumps({"error": "Parametro 'pdf_path' mancante o non valido."})

    assistant = _get_assistant()
    try:
        from hermes_voice.profile import validate_path_profile_ownership
        validate_path_profile_ownership(pdf_path, profile=assistant.profile, home_dir=assistant.home_dir)
    except PermissionError as err:
        return json.dumps({"error": f"Access denied: {err}"})
    except Exception as err:
        return json.dumps({"error": f"Errore validazione percorso: {err}"})

    try:
        bookmark = assistant.load_document(pdf_path)
    except PermissionError as err:
        return json.dumps({"error": f"Access denied: {err}"})
    except Exception as err:
        return json.dumps({"error": f"Errore caricamento documento: {err}"})

    return json.dumps({
        "status": "success",
        "doc_id": bookmark.doc_id,
        "title": assistant.current_document.title if assistant.current_document else "",
        "total_pages": assistant.current_document.total_pages if assistant.current_document else 0,
        "total_sentences": bookmark.total_sentences,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
    }, indent=2)


def voice_play_document(args: Any = None, **kwargs) -> str:
    """Avvia o riprende la riproduzione vocale deterministica del documento caricato con Pocket TTS."""
    assistant = _get_assistant()
    bookmark = assistant.play()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_pause_document(args: Any = None, **kwargs) -> str:
    """Mette in pausa la lettura vocale e memorizza il punto esatto (frase e millisecondo)."""
    assistant = _get_assistant()
    bookmark = assistant.pause()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "audio_seconds_offset": bookmark.audio_seconds_offset,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_resume_document(args: Any = None, **kwargs) -> str:
    """Riprende la lettura vocale esattamente dal punto in cui era stata sospesa."""
    assistant = _get_assistant()
    bookmark = assistant.resume()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_stop_document(args: Any = None, **kwargs) -> str:
    """Interrompe completamente la riproduzione vocale."""
    assistant = _get_assistant()
    bookmark = assistant.stop()
    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
    }, indent=2)


def voice_seek_document(args: Any = None, **kwargs) -> str:
    """Salta a una pagina o frase specifica del documento."""
    args_dict = args if isinstance(args, dict) else kwargs
    page = args_dict.get("page") if isinstance(args_dict, dict) else kwargs.get("page")
    sentence_index = args_dict.get("sentence_index") if isinstance(args_dict, dict) else kwargs.get("sentence_index")

    assistant = _get_assistant()
    if sentence_index is not None:
        bookmark = assistant.seek_sentence(int(sentence_index))
    elif page is not None:
        bookmark = assistant.seek_page(int(page))
    else:
        return json.dumps({"error": "Specificare 'page' o 'sentence_index'."})

    return json.dumps({
        "status": bookmark.state.value,
        "current_page": bookmark.current_page,
        "current_sentence_index": bookmark.current_sentence_index,
        "sentence_text": bookmark.current_sentence_text,
    }, indent=2)


def voice_ask_document(args: Any = None, **kwargs) -> str:
    """Interroga il documento: il Bibliotecario estrae le evidenze, l'Analista risponde con numeri di pagina e il Verificatore convalida la citazione."""
    question = str(_extract_arg(args, kwargs, "question", "") or "")
    if not question:
        return json.dumps({"error": "Parametro 'question' mancante o non valido."})

    assistant = _get_assistant()
    answer = assistant.ask(question)
    return json.dumps({
        "question": answer.question,
        "answer": answer.answer,
        "citations": [c.model_dump() for c in answer.citations],
        "verification": answer.verification.model_dump() if answer.verification else None,
        "model_used": answer.model_used,
        "latency_seconds": answer.latency_seconds,
    }, indent=2)


def voice_get_status(args: Any = None, **kwargs) -> str:
    """Restituisce lo stato attuale del lettore vocale e il bookmark registrato."""
    assistant = _get_assistant()
    status = assistant.get_full_status()
    return json.dumps(status.model_dump(), indent=2)


# Official tool definitions with unwrapped function schemas adhering to Hermes Tool Registry contract
TOOLS = [
    {
        "name": "voice_load_document",
        "description": "Carica un documento PDF nella memoria locale, estrae il testo in modo deterministico e lo predispone per la lettura vocale.",
        "handler": voice_load_document,
        "schema": {
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
    {
        "name": "voice_play_document",
        "description": "Avvia la lettura ad alta voce del documento caricato usando Pocket TTS con la voce italiana selezionata.",
        "handler": voice_play_document,
        "schema": {
            "name": "voice_play_document",
            "description": "Avvia la riproduzione vocale deterministica con Pocket TTS.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "voice_pause_document",
        "description": "Mette in pausa la lettura audio del documento e memorizza il punto esatto di lettura.",
        "handler": voice_pause_document,
        "schema": {
            "name": "voice_pause_document",
            "description": "Mette in pausa la riproduzione vocale e registra il bookmark esatto.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "voice_resume_document",
        "description": "Riprende la lettura vocale del documento dal punto esatto in cui era stata interrotta.",
        "handler": voice_resume_document,
        "schema": {
            "name": "voice_resume_document",
            "description": "Riprende la riproduzione dal punto esatto memorizzato.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "voice_stop_document",
        "description": "Interrompe completamente la riproduzione vocale in corso.",
        "handler": voice_stop_document,
        "schema": {
            "name": "voice_stop_document",
            "description": "Interrompe la riproduzione audio.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "voice_seek_document",
        "description": "Sposta il punto di lettura alla pagina o alla frase indicata.",
        "handler": voice_seek_document,
        "schema": {
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
    {
        "name": "voice_ask_document",
        "description": "Interroga il documento corrente: Bibliotecario estrae evidenze, Analista risponde con numeri di pagina, Verificatore valida la fedeltà delle citazioni.",
        "handler": voice_ask_document,
        "schema": {
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
    {
        "name": "voice_get_status",
        "description": "Ottiene lo stato live del lettore (in riproduzione, in pausa, stopped), frase corrente, tempo e stato degli agenti.",
        "handler": voice_get_status,
        "schema": {
            "name": "voice_get_status",
            "description": "Restituisce lo stato live della riproduzione vocale e degli agenti.",
            "parameters": {"type": "object", "properties": {}},
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
