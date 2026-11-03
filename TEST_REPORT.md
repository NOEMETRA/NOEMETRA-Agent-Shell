# TEST_REPORT — Resoconto di Verifica e Baseline Operativa

## 1. Ambiente di Esecuzione e Hardware

- **Hardware Target**: Lenovo ThinkPad E14 Gen 8 (Intel Core Ultra 7 355 / Ultra 7, 16 GB RAM).
- **Sistema Operativo**: Windows 11 Pro 64-bit.
- **Python**: CPython 3.14.9 gestito con `uv 0.13.5`.
- **Node.js**: v26.8.1 (npm v11.19.0).
- **Inference Runtime Locale**: Ollama 0.40.13 con modello locale `gemma4:12b` (8.0 GB).
- **Directory Progetto**: `C:\Users\Admin\.gemini\antigravity\scratch\noemetra-agent-shell`.
- **Commit di Riferimento**: `c314285f077e91937c995d419b9fa40af9eb4981` (upstream-baseline-20261103).

---

## 2. Esiti delle Suite di Test Automatizzate

I test sono stati eseguiti con `uv run --group dev pytest`.

### 2.1 Suite Provider e Registry (`tests/providers/`)
- **`test_provider_profiles.py`**: **10 PASSED / 0 FAILED** (0.87s)
  - Verifica profili OpenRouter, Nous, Qwen, Alibaba, normalizzazione session_id, sticky headers e rimozione preferenze provider per Nous.
- **`test_transport_parity.py`**: **9 PASSED / 0 FAILED** (0.81s)
  - Verifica parità di trasporto per NVIDIA, Kimi, OpenRouter, Nous, Qwen e **Custom Ollama** (`num_ctx`, disattivazione `think`).
- **`test_profile_wiring.py`**: **6 PASSED / 0 FAILED** (0.80s)
  - Verifica wiring opzioni, max_tokens, temperature omission e developer roles.
- **`test_plugin_discovery.py`**: **3 PASSED / 0 FAILED**
  - Verifica rilevamento plugin bundled e override plugin utente.

### 2.2 Suite Guardrails e Robustezza Agentica (`tests/agent/`)
- **`test_agent_guardrails.py`**: **26 PASSED / 0 FAILED** (2.65s)
  - Disinfezione messaggi orfani, deduplicazione chiamate strumenti, unicità ID chiamate, limitazione chiamate delegate per turno.

### 2.3 Suite Subagenti e Delega (`tests/tools/test_delegate.py`)
- **`test_delegate.py`**: **71 PASSED / 0 FAILED** (25.94s)
  - Creazione agenti figli con database sessione dedicato.
  - Ereditarietà credenziali e parametri di esecuzione.
  - Limitazione ricorsione e profondità (`max_spawn_depth`).
  - Rollup automatico dei costi di computazione e token dal subagente al genitore.
  - Isolamento delle tracce e dei file di sessione.
  - Deallogazione risorse e chiusura pulita dei processi orfani.

---

## 3. Prove Eseguite sul Runtime Reale (Live E2E)

### Prova 1: Isolamento del Profilo NOEMETRA
- **Comando**: `uv run hermes profile create noemetra`
- **Risultato**: Profilo creato in `C:\Users\Admin\AppData\Local\hermes\profiles\noemetra`.
- **Verifica**: Creazione di `config.yaml`, `state.db` separato, directory `attachments` e `skills` dedicate. Nessuna contaminazione con il profilo di default.

### Prova 2: Configurazione e Inferenza Locale con Ollama (100% Offline)
- **Configurazione**:
  ```powershell
  uv run hermes -p noemetra config set model.provider ollama
  uv run hermes -p noemetra config set model.default gemma4:12b
  uv run hermes -p noemetra config set model.base_url http://127.0.0.1:11434/v1
  ```
- **Stato Verificato**:
  - `Model: gemma4:12b`
  - `Provider: custom (ollama)`
- **Esecuzione Query**:
  - `uv run hermes -p noemetra chat -q "Rispondi in una sola frase breve in italiano: chi sei?"`
  - **Output Generato**: `Sono un modello linguistico addestrato da Google.` (inferito da `gemma4:12b` via Ollama locale).
  - **Esito**: Connessione riuscita a Ollama, generazione della risposta e registrazione della sessione senza alcuna chiamata verso Nous Research.

### Prova 3: Persistenza e Ripristino della Sessione
- **Verifica Database**: Sessione `local-e9c678b9a3f9518f8f3b6d505ef546508bb98ed3d3275fa58a26ab4ab878cb15` registrata in `state.db`.
- **Comando**: `uv run hermes -p noemetra sessions list`
- **Output**:
  ```
  Title                        Workspace          Last Active   ID
  Rispondi in una sola frase   noemetra-agent-s   1m ago        local-e9c678b9a3f9518f8f3b6d505ef546508bb98ed3d3275fa58a26ab4ab878cb15
  ```
- **Esito**: Persistenza convalidata su disco, pronta per il comando `--resume`.

### Prova 4: Compilazione ed Avvio Reale della GUI Desktop (Electron)
- **Componenti Compilati**:
  - WebApp bundle React (`npm run build:webapp`): 16.210 moduli trasformati con Vite in 70s in `apps/desktop/dist-webapp/` (3.2 MB bundle principale, rendering Markdown KaTeX e Shiki).
  - Main process bundle Electron (`node scripts/bundle-electron-main.mjs --dev`): `dist/electron-main.mjs` (3.0 MB) e `dist/electron-preload.js` (45.5 KB).
- **Identità Grafica e Integrazione**:
  - `product-identity.cjs`: aggiornato con nome applicativo `NOEMETRA Agent Shell` e appId `org.noemetra.noemetra-agent-shell`.
  - `apps/desktop/electron/main.ts`: titolazione finestre browser legata dinamicamente a `PRODUCT_IDENTITY.displayName` e AppUserModelID configurato per Windows toast notification.
  - `apps/desktop/index.html`: `<title>NOEMETRA Agent Shell</title>`.
- **Esecuzione Effettiva**:
  - Avvio verificato con `npx electron .` in `apps/desktop/`: istanza GUI attiva, finestra visualizzata correttamente su Windows 11 senza errori di caricamento asar o assets mancanti.

### Prova 5: Riorganizzazione Provider e Setup Wizard Offline-First
- **Setup Wizard (`hermes setup`)**:
  - Aggiunta modalità `_run_first_time_local_setup` come prima opzione (`[0]` - raccomandata): rileva automaticamente server Ollama attivo su `127.0.0.1:11434`, interroga `/api/tags`, elenca i modelli disponibili ed imposta `model.provider=ollama` con zero chiamate esterne.
  - Nous Portal spostato in fondo alle opzioni come servizio cloud opzionale per chi ne ha esplicita necessità.
- **Catalogo Canonico (`models_catalog_static.py`)**:
  - Riorganizzato l'ordine dei provider canonici: aggregatori e provider aperti/standard (`openrouter`, `openai-codex`, `anthropic`, `openai-api`, `lmstudio`, `fireworks`, `gemini`) prioritari rispetto al portale proprietario Nous.
- **Regression Suite Eseguita**:
  - 75 test eseguiti tra provider profiles, transport parity, profile wiring, provider parity e guardrails: **75 PASSED / 0 FAILED** (18.43s).

### Prova 6: Esecuzione dell'Applicazione "Hermes Voice" come Plugin Puro Disaccoppiato
- **Architettura di Disaccoppiamento**: Il core di NOEMETRA Agent Shell rimane 100% universale, agnostico e privo di codice audio, TTS o PDF. L'applicazione `voice-document-assistant` è installata ed eseguita come plugin nativo all'interno del profilo `noemetra`.
- **Suite di Test del Prototipo Audio**: 21 test su 21 superati al 100% in 102.36s:
  - `test_agents.py`: 6/6 passed (Bibliotecario, Analista, Verificatore).
  - `test_extractor.py`: 2/2 passed (Estrazione deterministica PyMuPDF).
  - `test_player.py`: 2/2 passed (Stato riproduzione e offset audio).
  - `test_router.py`: 4/4 passed (Routing verso Ollama locale).
  - `test_server_api.py`: 6/6 passed (Endpoint FastAPI e stato REST).
  - `test_end_to_end.py`: 1/1 passed (Interrogazione completa con LLM locale).
- **Verifica Funzionale degli Strumenti sul Runtime NOEMETRA**:
  - Rilevamento e registrazione: 8 strumenti registrati con successo (`tools: 8`, `error: None`).
  - Esecuzione `voice_get_status()`: stato lettore e agenti operativi in modalità locale.
  - Esecuzione `voice_load_document()` su PDF italiano di test: 3 pagine estratte, 18 frasi identificate.
  - Esecuzione `voice_ask_document("Quali sono i tre agenti?")`: elaborazione multi-agente completata con Ollama `gemma4:12b`, risposta esatta generata con citazione verbatim a pagina 3 e riscontro certificato dal Verificatore (`citation_match_score: 1.0`, `is_valid: true`).

---

## 4. Riepilogo Indicatori di Qualità

| Requisito di Verifica | Esito | Dettaglio |
|---|---|---|
| Esecuzione CLI su Windows 11 | **CONFERMATO** | `hermes --version`, `hermes status` con banner personalizzato NOEMETRA |
| Inferenza Locale senza dipendenza Nous | **CONFERMATO** | Testata e completata con Ollama `gemma4:12b` (100% offline) |
| Orchestrazione Subagenti Reali | **CONFERMATO** | 71 test passati (`test_delegate.py`) |
| Persistenza Stato e Sessioni | **CONFERMATO** | SQLite WAL, sessioni tracciate e verificabili dopo riavvio |
| Installazione e Ricarica Plugin Utente | **CONFERMATO** | Plugin esterno `noemetra-echo-plugin` caricato dinamicamente a runtime |
| Avvio Effettivo GUI Desktop | **CONFERMATO** | Electron v44 + WebApp bundle funzionante con brand NOEMETRA |
| Integrazione Hermes Voice come Plugin Puro | **CONFERMATO** | 8 tool caricati ed eseguiti, citazioni verificate, core 100% agnostico |
| Isolamento Progetti | **CONFERMATO** | Supportato nativamente tramite profili dedicati (`--profile`) |

---

## 7. Risoluzione Rilievi Codex Review (Post-Baseline)

A seguito dell'esecuzione di `codex exec review` (modello `gpt-6.1-terra`), sono stati analizzati e risolti i seguenti rilievi:

1. **Riconoscimento Installazioni Locali nel Setup Wizard (`hermes_cli/setup.py`)**:
   - *Problema*: La condizione `is_existing` considerava solo chiavi remote o token attivi, trattando installazioni locali (Ollama/LM Studio) come nuove installazioni al riavvio del wizard.
   - *Risoluzione*: Aggiornato `is_existing` per riconoscere configurazioni con provider/modello espliciti (`model.provider != "auto"` e `model.default` impostato).
2. **Rimozione Voci Duplicate in `CANONICAL_PROVIDERS` (`hermes_cli/models_catalog_static.py`)**:
   - *Problema*: 5 provider (`lmstudio`, `anthropic`, `openai-codex`, `openai-api`, `gemini`) risultavano duplicati nella tupla statica.
   - *Risoluzione*: Rimosse le occorrenze duplicate mantenendo l'elenco coerente a 52 provider canonici unici.
3. **Flusso di Importazione Modelli nel Setup Locale (`hermes_cli/setup_quick.py`)**:
   - *Problema*: `_keep_imported_model` proponeva il passaggio a "Nous Portal" anche durante la configurazione locale offline.
   - *Risoluzione*: Introdotto `_keep_imported_model_local` che propone coerentemente la scelta tra il modello importato e la configurazione Ollama locale offline.
4. **Isolamento Fixture Test di Provider (`tests/providers/test_profile_home_layers.py`)**:
   - *Problema*: Un leak nello stato di discovery nella fixture `homes` causava la perdita del registro nei test eseguiti in sequenza.
   - *Risoluzione*: Garantita la pre-discovery del registro prima dello snapshot della fixture `homes`, portando la suite `tests/providers/` al 100% di successo (93/93 passati).
5. **Migrazione Automatica Stato Desktop Legacy Con Lock, Scoping e Ignoramento File Singleton (`apps/desktop/electron/main.ts`)**:
   - *Problema*: La modifica di `productName` in `package.json` indirizza Electron verso la nuova directory `userData` (`NOEMETRA Agent Shell`). Una migrazione ingenua prima dell'acquisizione del lock o in istanze isolate (`HERMES_DESKTOP_USER_DATA_DIR` o varianti) poteva causare race condition tra processi concorrenti o inquinare directory isolate. Inoltre, su Linux l'acquisizione del single-instance lock genera file `Singleton*` che facevano apparire la nuova cartella come non vuota, bloccando la migrazione.
   - *Risoluzione*: Implementata `maybeMigrateLegacyDesktopState` eseguita *esclusivamente* dopo l'acquisizione confermata del single-instance lock, vincolata esplicitamente alla variante predefinita (`appNamePascal === 'NoemetraAgentShell'`) ed escludendo lockfile e directory di crash (`Singleton*`, `Crashpad`) nella verifica dello stato preesistente. Aggiornati i test in `product-identity.test.ts` (10/10 passati).
6. **Normalizzazione Endpoint con Trailing Slash (`hermes_cli/setup_quick.py`)**:
   - *Problema*: L'inserimento di un URL con slash finale (es. `http://127.0.0.1:11434/v1/`) causava la generazione errata di `.../v1/v1`.
   - *Risoluzione*: Normalizzazione preventiva con `.strip().rstrip("/")`, garantendo endpoint sempre ben formati in qualsiasi combinazione di input.
7. **Disaccoppiamento Feed Aggiornamenti Desktop (`apps/desktop/electron-builder.config.cjs`, `update-notes.ts`, `update-status.tsx`)**:
   - *Problema*: In assenza di variabile d'ambiente `GITHUB_REPOSITORY`, i pacchetti desktop compilati facevano fallback sull'update feed di `NousResearch/hermes-agent`, rischiando di proporre build upstream anziché NOEMETRA.
   - *Risoluzione*: Impostato il fallback predefinito su `NOEMETRA/NOEMETRA-Agent-Shell` e allineati gli URL delle note di rilascio.
8. **Distinzione Server Ollama Vuoto vs Non Raggiungibile (`hermes_cli/setup_quick.py`)**:
   - *Problema*: Se Ollama era attivo ma senza alcun modello scaricato (`/api/tags` restituisce `[]`), il wizard lo trattava come offline/non rilevato e proponeva un modello predefinito senza avvisare della necessità del download.
   - *Risoluzione*: Distinto esplicitamente il caso di server raggiungibile ma privo di modelli (`models is not None and len(models) == 0`), fornendo chiare istruzioni CLI (`ollama pull <modello>`) prima dell'inizio della sessione.
9. **Inizializzazione Mappatura Modello in Setup Locale (`hermes_cli/setup_quick.py`)**:
   - *Problema*: In configurazioni pulite `model` può essere presente come stringa vuota (`""`). `setdefault("model", {})` non rimpiazzava la stringa, generando `TypeError: 'str' object does not support item assignment`.
   - *Risoluzione*: Sostituito con check esplicito `if not isinstance(config.get("model"), dict): config["model"] = {}`, permettendo il salvataggio immediato e senza errori di `provider`, `base_url` e `default`.
