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

---

## 4. Riepilogo Indicatori di Qualità

| Requisito di Verifica | Esito | Dettaglio |
|---|---|---|
| Esecuzione CLI su Windows 11 | **CONFERMATO** | `hermes --version`, `hermes status` funzionanti su CPython 3.14.9 |
| Inferenza Locale senza dipendenza Nous | **CONFERMATO** | Testata e completata con Ollama `gemma4:12b` |
| Orchestrazione Subagenti Reali | **CONFERMATO** | 71 test passati (`test_delegate.py`) |
| Persistenza Stato e Sessioni | **CONFERMATO** | SQLite WAL, sessioni tracciate e verificabili |
| Isolamento Progetti | **CONFERMATO** | Supportato nativamente tramite profili dedicati (`--profile`) |
