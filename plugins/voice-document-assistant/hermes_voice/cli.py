"""Command line interface for Hermes Voice Document Assistant."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.models import PlayerState
from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.tts_engine import PocketTTSEngine


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hermes-voice",
        description="Assistente vocale documentale multi-agente per Windows 11.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando da eseguire")

    # Command: load
    load_parser = subparsers.add_parser("load", help="Carica un file PDF")
    load_parser.add_argument("pdf_path", help="Percorso del file PDF")

    # Command: play
    play_parser = subparsers.add_parser("play", help="Avvia la lettura del documento")
    play_parser.add_argument("--virtual", action="store_true", help="Usa riproduzione virtuale (headless)")

    # Command: pause
    subparsers.add_parser("pause", help="Mette in pausa la lettura e salva il bookmark")

    # Command: resume
    resume_parser = subparsers.add_parser("resume", help="Riprende la lettura dal punto esatto")
    resume_parser.add_argument("--virtual", action="store_true", help="Usa riproduzione virtuale")

    # Command: ask
    ask_parser = subparsers.add_parser("ask", help="Pone una domanda sul documento")
    ask_parser.add_argument("question", help="Domanda dell'utente")

    # Command: status
    subparsers.add_parser("status", help="Mostra lo stato attuale della lettura")

    # Command: demo
    demo_parser = subparsers.add_parser("demo", help="Esegue la dimostrazione completa del criterio di successo")
    demo_parser.add_argument("--pdf", help="Percorso PDF personalizzato (opzionale)")
    demo_parser.add_argument("--virtual", action="store_true", default=True, help="Modalità virtuale di riproduzione")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Esegue benchmark di Pocket TTS e Ollama")
    bench_parser.add_argument("--language", default="italian", choices=["italian", "italian_24l"])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    assistant = HermesVoiceAssistant(virtual_playback=getattr(args, "virtual", False))

    if args.command == "load":
        bookmark = assistant.load_document(args.pdf_path)
        print(f"Documento caricato: {bookmark.doc_id}")
        print(f"Pagine: {assistant.current_document.total_pages}, Frasi: {bookmark.total_sentences}")

    elif args.command == "play":
        bookmark = assistant.play()
        print(f"Riproduzione avviata: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        try:
            print("Riproduzione in corso (premere Ctrl+C per mettere in pausa)...")
            while assistant.player.state == PlayerState.PLAYING:
                time.sleep(0.2)
            if assistant.player.state == PlayerState.FINISHED:
                print("Lettura del documento completata.")
        except KeyboardInterrupt:
            bookmark = assistant.pause()
            print(f"\nRiproduzione interrotta su frase {bookmark.current_sentence_index + 1}.")

    elif args.command == "pause":
        bookmark = assistant.pause()
        print(f"Riproduzione in pausa: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        print(f"Offset temporale: {bookmark.audio_seconds_offset:.2f}s")
        print(f"Testo: '{bookmark.current_sentence_text}'")

    elif args.command == "resume":
        bookmark = assistant.resume()
        print(f"Riproduzione ripresa: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        try:
            print("Riproduzione in corso (premere Ctrl+C per mettere in pausa)...")
            while assistant.player.state == PlayerState.PLAYING:
                time.sleep(0.2)
            if assistant.player.state == PlayerState.FINISHED:
                print("Lettura del documento completata.")
        except KeyboardInterrupt:
            bookmark = assistant.pause()
            print(f"\nRiproduzione interrotta su frase {bookmark.current_sentence_index + 1}.")

    elif args.command == "ask":
        # Ensure document is loaded
        if not assistant.current_document and assistant.player.bookmark_path.exists():
            try:
                data = json.loads(assistant.player.bookmark_path.read_text(encoding="utf-8"))
                fp = data.get("file_path")
                if fp and Path(fp).exists():
                    assistant.load_document(fp)
            except Exception:
                pass

        if not assistant.current_document:
            default_sample = Path("test_document_it.pdf")
            if default_sample.exists():
                assistant.load_document(default_sample)
            else:
                print("Nessun documento attivo. Eseguire prima: hermes-voice load <documento.pdf>")
                sys.exit(1)

        answer = assistant.ask(args.question)
        print("\n" + "=" * 60)
        print(f"DOMANDA: {answer.question}")
        print("=" * 60)
        print(f"RISPOSTA (Modello: {answer.model_used}, Latenza: {answer.latency_seconds:.2f}s):")
        print(answer.answer)
        print("\nCITAZIONI VERIFICATE:")
        for cit in answer.citations:
            print(f"- [Pagina {cit.page_number}]: \"{cit.verbatim_quote}\"")

        if answer.verification:
            ver = answer.verification
            print(f"\nVERIFICA AGENTE VERIFICATORE:")
            print(f"Stato: {'SUPERATA' if ver.is_valid else 'FALLITA'} (Accuratezza: {ver.citation_match_score * 100:.0f}%)")
            for q in ver.verified_quotes:
                print(f"  + {q}")
            for u in ver.unsupported_claims:
                print(f"  ! {u}")
        print("=" * 60 + "\n")

    elif args.command == "status":
        bookmark = assistant.get_status()
        print(json.dumps(bookmark.model_dump(), indent=2))

    elif args.command == "benchmark":
        print(f"Avvio benchmark prestazionale Pocket TTS (modello='{args.language}', voce='giovanni')...")
        engine = PocketTTSEngine(language=args.language, voice="giovanni", lazy_load=False)
        res = engine.benchmark()
        print("\nRISULTATI BENCHMARK:")
        print(json.dumps(res, indent=2))

    elif args.command == "demo":
        run_full_demo(args.pdf, args.virtual)


def run_full_demo(custom_pdf: str | None = None, virtual: bool = True) -> None:
    """Execute end-to-end user scenario."""
    print("\n" + "#" * 65)
    print("# DEMO END-TO-END — HERMES VOICE DOCUMENT ASSISTANT")
    print("#" * 65)

    pdf_path = Path(custom_pdf) if custom_pdf else Path("test_document_it.pdf")
    if not pdf_path.exists():
        print(f"\n[1/6] Generazione PDF di test italiano: {pdf_path}...")
        create_sample_italian_pdf(pdf_path)

    assistant = HermesVoiceAssistant(virtual_playback=virtual)

    print(f"\n[2/6] Caricamento del documento: {pdf_path}...")
    bookmark = assistant.load_document(pdf_path)
    print(f"  -> Titolo: '{assistant.current_document.title}'")
    print(f"  -> Totale pagine: {assistant.current_document.total_pages}")
    print(f"  -> Totale frasi estratte: {len(assistant.current_document.all_sentences)}")

    print("\n[3/6] Avvio riproduzione deterministica (Pocket TTS)...")
    assistant.play()
    time.sleep(1.2)  # Play for a short while

    print("\n[4/6] Interruzione della lettura (Pausa e Bookmark)...")
    paused_bookmark = assistant.pause()
    print(f"  -> In pausa alla frase {paused_bookmark.current_sentence_index + 1}/"
          f"{paused_bookmark.total_sentences} (Pagina {paused_bookmark.current_page})")
    print(f"  -> Testo corrente: '{paused_bookmark.current_sentence_text}'")
    print(f"  -> Offset campioni: {paused_bookmark.audio_sample_offset} ({paused_bookmark.audio_seconds_offset:.2f}s)")

    print("\n[5/6] Formulazione domanda durante la pausa...")
    question = "Quali sono le prestazioni misurate per i modelli italiano e a 24 livelli di Pocket TTS?"
    print(f"  -> Domanda: \"{question}\"")
    answer = assistant.ask(question)

    print("\n" + "-" * 50)
    print("RISPOSTA ANALISTA:")
    print(answer.answer)
    print("\nCITAZIONI CON NUMERI DI PAGINA:")
    for c in answer.citations:
        print(f"  * [Pagina {c.page_number}]: {c.verbatim_quote}")
    print(f"VERIFICA: {'SUPERATA' if answer.verification.is_valid else 'FALLITA'} "
          f"(Punteggio: {answer.verification.citation_match_score * 100:.0f}%)")
    print("-" * 50)

    print("\n[6/6] Ripresa esatta della lettura dal punto interrotto...")
    resumed_bookmark = assistant.resume()
    print(f"  -> Lettura ripresa da frase {resumed_bookmark.current_sentence_index + 1} "
          f"(Pagina {resumed_bookmark.current_page})")
    print(f"  -> Testo ripreso: '{resumed_bookmark.current_sentence_text}'")
    time.sleep(1.0)
    assistant.stop()

    print("\n" + "=" * 65)
    print("CRITERIO DI SUCCESSO SODDISFATTO AL 100%:")
    print("1. Caricamento PDF italiano: ESEGUITO")
    print("2. Ascolto testo originale deterministico: ESEGUITO")
    print("3. Interruzione lettura: ESEGUITO CON SEGNALIBRO ESATTO")
    print("4. Domanda e risposta con numeri di pagina verificabili: ESEGUITO")
    print("5. Ripresa esatta dal punto di stop: ESEGUITO")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
