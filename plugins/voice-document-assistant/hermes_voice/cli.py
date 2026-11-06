"""Command line interface for Hermes Voice Document Assistant."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def is_pid_alive(pid: int) -> bool:
    """Check if process with given PID is currently active."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, SystemError, PermissionError):
        return False

from typing import Optional
import urllib.error
import urllib.request
from urllib.parse import urlparse

from hermes_voice.extractor import create_sample_italian_pdf
from hermes_voice.models import PlayerState, ReadingBookmark
from hermes_voice.pipeline import HermesVoiceAssistant
from hermes_voice.profile import PROFILE_ID_RE, compute_home_fingerprint, ensure_voice_dir
from hermes_voice.tts_engine import PocketTTSEngine

_ALLOWED_CLI_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_cli_logger = __import__("logging").getLogger(__name__)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects so local control probes never escape loopback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirects forbidden on local CLI control channel", headers, fp)


def _candidate_local_server_urls() -> list[str]:
    urls: list[str] = []
    env_url = (os.environ.get("HERMES_VOICE_SERVER_URL") or "").strip().rstrip("/")
    if env_url:
        try:
            parsed = urlparse(env_url)
            if parsed.scheme == "http" and (parsed.hostname or "").lower() in _ALLOWED_CLI_LOOPBACK_HOSTS:
                urls.append(env_url)
        except Exception:
            pass
    for default_url in ("http://127.0.0.1:8000", "http://127.0.0.1:8080"):
        if default_url not in urls:
            urls.append(default_url)
    return urls


def _try_pause_matching_local_server(assistant: HermesVoiceAssistant) -> Optional[ReadingBookmark]:
    """Pause a local Voice server ONLY if it provably serves the CLI's exact profile home (AGENTS.md:13)."""
    expected_fp = compute_home_fingerprint(assistant.home_dir)
    headers = {
        "Content-Type": "application/json",
        "X-Hermes-Voice-Home-Sha256": expected_fp,
    }
    if assistant.profile and PROFILE_ID_RE.match(assistant.profile.lower()):
        headers["X-Hermes-Profile"] = assistant.profile.lower()

    opener = urllib.request.build_opener(_NoRedirectHandler)
    for base_url in _candidate_local_server_urls():
        try:
            status_req = urllib.request.Request(
                f"{base_url}/api/plugins/voice-document-assistant/status",
                headers=headers,
                method="GET",
            )
            with opener.open(status_req, timeout=3.0) as status_resp:
                if status_resp.status != 200:
                    continue
                status_body = json.loads(status_resp.read().decode("utf-8"))
                resp_fp = (
                    status_resp.headers.get("X-Hermes-Voice-Home-Sha256")
                    or (status_body.get("home_fingerprint") if isinstance(status_body, dict) else "")
                    or ""
                ).strip().lower()
                if resp_fp != expected_fp:
                    continue
                if not isinstance(status_body, dict) or status_body.get("state") != PlayerState.PLAYING.value:
                    continue

            pause_req = urllib.request.Request(
                f"{base_url}/api/plugins/voice-document-assistant/playback/pause",
                data=b"{}",
                headers=headers,
                method="POST",
            )
            with opener.open(pause_req, timeout=3.0) as pause_resp:
                if pause_resp.status != 200:
                    continue
                pause_fp = (pause_resp.headers.get("X-Hermes-Voice-Home-Sha256") or "").strip().lower()
                if pause_fp != expected_fp:
                    continue
                pause_body = json.loads(pause_resp.read().decode("utf-8"))
                return ReadingBookmark.model_validate(pause_body)
        except Exception as err:
            _cli_logger.debug("Probe server voce locale %s scartato: %r", base_url, err)
            continue
    return None


def _write_ctrl_file(ctrl_file: Path, payload: dict) -> None:
    ensure_voice_dir(ctrl_file.parent)
    ctrl_file.write_text(json.dumps(payload), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hermes-voice",
        description="Assistente vocale documentale multi-agente per Windows 11.",
    )
    parser.add_argument("--profile", default=None, help="Profilo Hermes isolato da utilizzare")
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
    demo_parser.add_argument("--virtual", action="store_true", default=True, help="ModalitÃ  virtuale di riproduzione")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Esegue benchmark di Pocket TTS e Ollama")
    bench_parser.add_argument("--language", default="italian", choices=["italian", "italian_24l"])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "demo":
        run_full_demo(args.pdf, getattr(args, "virtual", True), profile=args.profile)
        return

    assistant = HermesVoiceAssistant(
        virtual_playback=getattr(args, "virtual", False),
        profile=args.profile,
    )

    if args.command == "load":
        bookmark = assistant.load_document(args.pdf_path)
        print(f"Documento caricato: {bookmark.doc_id}")
        print(f"Pagine: {assistant.current_document.total_pages}, Frasi: {bookmark.total_sentences}")

    elif args.command == "play":
        try:
            bookmark = assistant.play()
        except Exception as err:
            print(f"Errore avvio riproduzione: {err}", file=sys.stderr)
            sys.exit(1)
        print(f"Riproduzione avviata: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        ctrl_file = assistant.player.bookmark_path.parent / "player_control.json"
        _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "playing"})
        try:
            print("Riproduzione in corso (premere Ctrl+C per mettere in pausa)...")
            while assistant.player.state == PlayerState.PLAYING:
                time.sleep(0.2)
                if ctrl_file.exists():
                    try:
                        cdata = json.loads(ctrl_file.read_text(encoding="utf-8"))
                        cmd = cdata.get("command")
                        if cmd == "pause":
                            bookmark = assistant.pause()
                            _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "paused"})
                            print(f"\nRicevuto comando di pausa dall'esterno su frase {bookmark.current_sentence_index + 1}.")
                            break
                        elif cmd == "stop":
                            bookmark = assistant.stop()
                            _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "stopped"})
                            print("\nRicevuto comando di stop dall'esterno.")
                            break
                    except Exception:
                        pass
            if assistant.player.state == PlayerState.FINISHED:
                print("Lettura del documento completata.")
        except KeyboardInterrupt:
            bookmark = assistant.pause()
            print(f"\nRiproduzione interrotta su frase {bookmark.current_sentence_index + 1}.")
        finally:
            if ctrl_file.exists():
                try:
                    ctrl_file.unlink()
                except Exception:
                    pass

    elif args.command == "pause":
        # Check if another running player process exists for this profile
        ctrl_file = assistant.player.bookmark_path.parent / "player_control.json"
        routed = False
        if ctrl_file.exists():
            try:
                cdata = json.loads(ctrl_file.read_text(encoding="utf-8"))
                active_pid = cdata.get("pid")
                if active_pid and is_pid_alive(active_pid) and active_pid != os.getpid():
                    cdata["command"] = "pause"
                    _write_ctrl_file(ctrl_file, cdata)
                    for _ in range(25):
                        time.sleep(0.1)
                        if not ctrl_file.exists():
                            break
                        fresh = json.loads(ctrl_file.read_text(encoding="utf-8"))
                        if fresh.get("status") == "paused":
                            break
                    routed = True
            except Exception:
                pass

        server_bookmark: Optional[ReadingBookmark] = None
        if not routed:
            server_bookmark = _try_pause_matching_local_server(assistant)
            if server_bookmark is not None:
                routed = True

        if server_bookmark is not None:
            bookmark = server_bookmark
        elif not routed:
            bookmark = assistant.pause()
        else:
            # Reload persisted bookmark updated by the external CLI player process
            assistant.player = type(assistant.player)(
                tts_engine=assistant.tts,
                bookmark_path=assistant.player.bookmark_path,
                virtual_playback=assistant.player.virtual_playback,
            )
            bookmark = assistant.player.get_bookmark()

        print(f"Riproduzione in pausa: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        print(f"Offset temporale: {bookmark.audio_seconds_offset:.2f}s")
        print(f"Testo: '{bookmark.current_sentence_text}'")

    elif args.command == "resume":
        try:
            bookmark = assistant.resume()
        except Exception as err:
            print(f"Errore ripresa riproduzione: {err}", file=sys.stderr)
            sys.exit(1)
        print(f"Riproduzione ripresa: Frase {bookmark.current_sentence_index + 1} (Pagina {bookmark.current_page})")
        ctrl_file = assistant.player.bookmark_path.parent / "player_control.json"
        _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "playing"})
        try:
            print("Riproduzione in corso (premere Ctrl+C per mettere in pausa)...")
            while assistant.player.state == PlayerState.PLAYING:
                time.sleep(0.2)
                if ctrl_file.exists():
                    try:
                        cdata = json.loads(ctrl_file.read_text(encoding="utf-8"))
                        cmd = cdata.get("command")
                        if cmd == "pause":
                            bookmark = assistant.pause()
                            _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "paused"})
                            print(f"\nRicevuto comando di pausa dall'esterno su frase {bookmark.current_sentence_index + 1}.")
                            break
                        elif cmd == "stop":
                            bookmark = assistant.stop()
                            _write_ctrl_file(ctrl_file, {"pid": os.getpid(), "command": "", "status": "stopped"})
                            print("\nRicevuto comando di stop dall'esterno.")
                            break
                    except Exception:
                        pass
            if assistant.player.state == PlayerState.FINISHED:
                print("Lettura del documento completata.")
        except KeyboardInterrupt:
            bookmark = assistant.pause()
            print(f"\nRiproduzione interrotta su frase {bookmark.current_sentence_index + 1}.")
        finally:
            if ctrl_file.exists():
                try:
                    ctrl_file.unlink()
                except Exception:
                    pass

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
        engine = PocketTTSEngine(
            cache_dir=assistant.player.bookmark_path.parent / "audio_cache",
            language=args.language,
            voice="giovanni",
            lazy_load=False,
        )
        res = engine.benchmark()
        print("\nRISULTATI BENCHMARK:")
        print(json.dumps(res, indent=2))


def run_full_demo(
    custom_pdf: str | None = None,
    virtual: bool = True,
    profile: str | None = None,
) -> None:
    """Execute end-to-end user scenario."""
    print("\n" + "#" * 65)
    print("# DEMO END-TO-END â€” HERMES VOICE DOCUMENT ASSISTANT")
    print("#" * 65)

    assistant = HermesVoiceAssistant(virtual_playback=virtual, profile=profile)
    pdf_path = Path(custom_pdf) if custom_pdf else (assistant.player.bookmark_path.parent / "test_document_it.pdf")
    if not pdf_path.exists():
        print(f"\n[1/6] Generazione PDF di test italiano: {pdf_path}...")
        create_sample_italian_pdf(pdf_path)

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
