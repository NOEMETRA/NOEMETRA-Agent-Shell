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
| Isolamento Progetti | **CONFERMATO** | Supportato nativamente tramite profili dedicati (`--profile`) |
