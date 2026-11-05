---
name: voice-doc-assistant
description: Voice document assistant with native Desktop GUI, Pocket TTS, verbatim reading, and verified multi-agent QA.
version: 0.2.0
author: Hermes Voice Research Team
license: MIT
platforms:
  - windows
  - linux
  - macos
metadata:
  hermes:
    category: productivity
    tags:
      - voice
      - tts
      - pdf
      - rag
      - audio
      - gui
      - desktop-plugin
---

# Voice Document Assistant Skill

Assistente vocale documentale multi-agente per Windows 11 basato su Hermes Desktop Plugin SDK, Pocket TTS, PyMuPDF e Ollama locale.
Adotta un approccio **GUI First**: l'utente gestisce l'intero ciclo vitale (caricamento, lettura, pausa, Q&A e ripresa) dall'interfaccia grafica nativa senza necessità di aprire la CLI.

## When to Use

- Ascolto continuativo di documenti PDF in italiano con voce naturale Kyutai Labs Pocket TTS (`italian` o `italian_24l`).
- Visualizzazione sincronizzata del documento con evidenziazione in tempo reale della frase in lettura.
- Interruzione della lettura per porre domande analitiche tramite la Triade di Agenti (Bibliotecario, Analista, Verificatore).
- Esigenza di risposte basate su citazioni e numeri di pagina verificabili senza allucinazioni, con badge cliccabili che aprono la pagina corrispondente.
- Ripresa della riproduzione vocale dall'esatto punto temporale e testuale di interruzione.
- Totale riservatezza dei dati: documenti mantenuti in locale per impostazione predefinita.

## Architecture & Components

1. **Native Desktop Plugin (`desktop/plugin.js`)**:
   - Registrato in `ROUTES_AREA` (`/voice-document`), `SIDEBAR_NAV_AREA` (icona `book`) e `STATUSBAR_AREAS.right`.
   - Interfaccia completa: visualizzatore PDF con highlight in lettura, controlli audio (Play, Pausa, Riprendi, Stop, Velocità), selezione modello TTS, stato reale degli agenti, chat con citazioni interattive e toggle consenso privacy.
2. **Persistent Backend Router (`dashboard/plugin_api.py` & `hermes_voice/server/`)**:
   - Montato nativamente dal gateway Hermes su `/api/plugins/voice-document-assistant/`.
   - Mantiene lo stato persistente della biblioteca, del lettore audio e dei bookmark anche tra riavvii.
3. **Triade Multi-Agente con Verifica Rigorosa**:
   - **Bibliotecario**: indicizzazione e retrieval deterministico dei passaggi con numero di pagina.
   - **Analista**: formulazione della risposta basata esclusivamente sulle evidenze, con citazioni `[Pagina X]`.
   - **Verificatore**: controllo stringente di corrispondenza letterale rispetto al testo sorgente. Rigetta allucinazioni, numeri di pagina inesistenti o risposte d'errore.
4. **Sintesi Vocale Pocket TTS**:
   - `italian`: modello distillato ottimizzato per CPU (2.6x real-time speedup).
   - `italian_24l`: modello non distillato ad alta fedeltà a 24 strati (0.54x real-time).
   - Voce `giovanni`.

## Tools Registrati

| Strumento | Descrizione |
|---|---|
| `voice_load_document` | Ingestione ed estrazione PDF nella biblioteca locale |
| `voice_play_document` | Avvio o ripresa della lettura vocale deterministica |
| `voice_pause_document` | Pausa e salvataggio del bookmark esatto |
| `voice_resume_document` | Ripresa dal punto esatto di sospensione |
| `voice_stop_document` | Interruzione completa della lettura |
| `voice_seek_document` | Spostamento a pagina o frase specifica |
| `voice_ask_document` | Domanda con riscontri verificabili tramite Triade |
| `voice_get_status` | Stato live del player, bookmark e stato agenti |

## Diagnostic & Negative Verification

- **Prova negativa**: In caso di modello non disponibile o citazione non riscontrata sul documento, il Verificatore dichiara esplicitamente `is_valid: false` e l'interfaccia segnala l'anomalia senza dichiarare falso successo.
- **Privacy Guard**: L'invio di dati verso provider remoti (Codex esterno o OpenAI/Anthropic) è bloccato a livello di router a meno di esplicita abilitazione (`allow_remote=True`).
