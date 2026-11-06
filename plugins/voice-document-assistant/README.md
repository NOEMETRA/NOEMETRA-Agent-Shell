# Hermes Voice Document Assistant — GUI First

> Assistente vocale documentale multi-agente deterministico nativo per Windows 11, basato su **Hermes Agent** (Nous Research), **Hermes Desktop Plugin SDK**, **Pocket TTS** (Kyutai Labs) e **Ollama**.

---

## 🎯 Decisione di Prodotto: GUI First

L'applicazione è progettata per operare **interamente tramite interfaccia grafica**:
- **Nessun comando da terminale o PowerShell** è richiesto all'utente per caricare documenti PDF, ascoltare la lettura vocale, mettere in pausa, interrogare la triade di agenti o riprendere l'ascolto.
- La CLI e gli script restano disponibili esclusivamente per sviluppo, benchmark diagnostici e test automatizzati.

---

## 🏛️ Architettura del Pacchetto Unificato

Il sistema implementa l'architettura ufficiale **Unified Package** di Hermes Agent:

```
Hermes-assistant-audio/
├── desktop/
│   └── plugin.js                  # Interfaccia grafica nativa Hermes Desktop SDK (@hermes/plugin-sdk)
├── dashboard/
│   ├── manifest.json              # Manifest discovery per backend e dashboard
│   └── plugin_api.py              # Mount API REST su /api/plugins/voice-document-assistant/
├── hermes_plugin/
│   └── voice_plugin.py            # Registrazione tool conforme al contratto ufficiale Hermes
├── hermes_voice/                  # Motore applicativo persistente
│   ├── models.py                  # Modelli Pydantic (SentenceSpan, Bookmark, LibraryEntry, GroundedAnswer)
│   ├── extractor.py               # Estrazione deterministica PyMuPDF con gestione esplicita OCR
│   ├── tts_engine.py              # Pocket TTS (italian 2.6x RT / italian_24l 24-strati, voce Giovanni)
│   ├── player.py                  # Player audio multithread, gestione ciclo di vita e bookmark millisecondo
│   ├── model_router.py            # Local-first ModelRouter (Ollama locale, Codex, API) con privacy guard
│   ├── pipeline.py                # Orchestratore unificato e memoria biblioteca persistente
│   ├── server/                    # Backend REST FastAPI & Server Standalone
│   │   ├── api.py                 # Router API REST per tutte le operazioni GUI
│   │   ├── state.py               # Singleton persistente (nessuna perdita di stato tra chiamate)
│   │   ├── standalone.py          # Server HTTP/Web autonomo (port 8080)
│   │   └── static/index.html      # GUI Web responsive accessibile anche via browser
│   └── agents/                    # Triade di Agenti
│       ├── librarian.py           # Bibliotecario (ingestione, indicizzazione ed estrazione evidenze)
│       ├── analyst.py             # Analista (sintesi basata su evidenze con citazioni [Pagina X])
│       └── verifier.py            # Verificatore (convalida stringente citazioni letterali e pagine)
├── skills/
│   └── voice-doc-assistant/
│       └── SKILL.md               # Specifiche della skill documentale Hermes
├── tests/                         # Suite completa di test automatizzati (19 test)
│   ├── test_agents.py             # Test Bibliotecario, Verificatore e test negativi (allucinazioni/errori)
│   ├── test_end_to_end.py         # Test integrale end-to-end con Ollama locale (gemma4:12b)
│   ├── test_extractor.py          # Test estrazione PDF e abbreviazioni italiane
│   ├── test_player.py             # Test riproduzione, pausa, ripresa e bookmark
│   ├── test_router.py             # Test privacy guard su Ollama, Codex e remote API
│   └── test_server_api.py         # Test endpoint REST FastAPI (/status, /upload, /playback, /ask)
├── plugin.yaml                    # Manifest del pacchetto unificato Hermes
└── README.md                      # Questa documentazione
```

---

## 🖥️ Funzionalità dell'Interfaccia Grafica (GUI)

L'interfaccia (disponibile sia in **Hermes Desktop** tramite `desktop/plugin.js` sia via Web su `http://127.0.0.1:8080/`) offre tutte le funzionalità obbligatorie:

1. **Biblioteca PDF Persistente**:
   - Menu a tendina con i documenti già indicizzati.
   - Caricamento di nuovi file PDF tramite file picker o base64 drag-and-drop.
   - Memoria della biblioteca salvata su `~/.hermes/voice_library.json`, ripristinata automaticamente al riavvio.
2. **Visualizzatore del Documento ed Evidenziazione Sincronizzata**:
   - Visualizzazione del testo originale della pagina corrente.
   - Controlli pagina precedente/successiva con indicatore `Pagina X di Y`.
   - **Evidenziazione dinamica della frase in lettura**: la frase attualmente pronunciata da Pocket TTS viene evidenziata in tempo reale con uno sfondo dorato attivo (`.active-sentence`).
   - Cliccando su qualsiasi frase nel documento, la riproduzione salta direttamente a quella frase.
3. **Controlli Audio Completi**:
   - Pulsanti dedicati: **Ascolta**, **Pausa**, **Riprendi**, **Stop**.
   - Barra di avanzamento temporale: frase corrente / frasi totali e offset in secondi.
   - Cursore velocità: `0.75x`, `1.0x` (normale), `1.25x`, `1.5x`.
4. **Selezione Modello Pocket TTS**:
   - `italian`: modello distillato ottimizzato per CPU (velocità **2.60x** tempo reale).
   - `italian_24l`: modello non distillato a 24 strati ad altissima fedeltà timbrica (**0.54x** tempo reale).
5. **Stato Reale della Triade Multi-Agente**:
   - Card in tempo reale per **Bibliotecario**, **Analista** e **Verificatore** che riflettono le reali fasi di calcolo (senza indicatori simulati).
6. **Interazione Q&A con Citazioni Cliccabili**:
   - Box di chat per porre domande sul documento.
   - Pulsante microfono per attivare l'input vocale tramite Web Speech API.
   - Risposte dell'Analista arricchite da badge interattivi `[Pagina X]`.
   - **Cliccando sul badge di citazione**, il visualizzatore e il lettore saltano immediatamente alla pagina citata.
   - Badge di verifica: Verde (✅ *Citazioni convalidate con successo*) oppure Rosso (⚠️ *Allucinazione o citazione non riscontrata*).
7. **Controllo Privacy e Vincolo Riservatezza**:
   - Toggle esplicito: *"Consenti provider remoti"*.
   - Se disattivato (impostazione predefinita), il sistema rifiuta qualsiasi chiamata a endpoint remoti (Codex esterno o OpenAI/Anthropic), proteggendo i dati aziendali.

---

## 🧪 Validazione e Prove Negative

La suite automatizzata conta **19 test**, tutti eseguiti e superati con successo:

```powershell
pytest tests/ -v
# 19 passed in 53.66s
```

### Prove Negative Eseguite e Verificate:
1. **Citazione a pagina inesistente**: il Verificatore rigetta la risposta con `is_valid: False` e notifica l'assenza della pagina.
2. **Citazione inventata su pagina reale**: il Verificatore verifica la mancata presenza del testo citato nella pagina sorgente e rifiuta la risposta (`is_valid: False`).
3. **Errore o allucinazione del modello**: in caso di timeout o messaggio di errore, il Verificatore non convalida la risposta.
4. **Violazione Privacy Provider Remoti**: chiamate verso server non localhost (127.0.0.1) sollevano `PermissionError` a meno che `allow_remote=True` non sia esplicitamente autorizzato.

---

## 🚀 Come Utilizzare l'Applicazione (Zero CLI)

Le dipendenze Python opzionali del pacchetto vocale sono gestite dall'extra `voice-document-assistant` di Hermes:
```powershell
hermes pm install --extra voice-document-assistant
# In caso di ripristino o dipendenze danneggiate: hermes pm repair
```

### Opzione A: Tramite Hermes Desktop
1. Avviare Hermes Desktop:
   ```powershell
   hermes desktop --skip-build
   ```
2. Cliccare sull'icona **Hermes Voice** nella barra laterale sinistra (o via palette ⌘K / Ctrl+K digitando `Open Hermes Voice`).
3. Dalla GUI:
   - Cliccare su **Carica PDF** e selezionare un documento italiano.
   - Cliccare su **Ascolta** per ascoltare Pocket TTS con evidenziazione in tempo reale.
   - Cliccare su **Pausa** per sospendere.
   - Digitare una domanda (es. *"Quali sono i tre agenti?"*) e cliccare su **Chiedi**.
   - Cliccare sul badge `[Pagina 3]` nella risposta per saltare a pagina 3.
   - Cliccare su **Riprendi** per proseguire la lettura esattamente dal punto salvato.

### Opzione B: Tramite GUI Web Dedicata
Il server di backend persistente è attivo su `http://127.0.0.1:8080`:
1. Aprire il browser su [http://127.0.0.1:8080/](http://127.0.0.1:8080/).
2. Eseguire tutte le operazioni (caricamento, lettura, pausa, domande, cambio pagina) interamente dalla pagina web.
