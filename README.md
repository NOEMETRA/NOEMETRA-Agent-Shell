# NOEMETRA Agent Shell

> **Universal Application Shell per Sistemi AI Agentici, Modulari, Multi-Modello e Multi-Agente.**

NOEMETRA Agent Shell è una piattaforma agentica open source derivata da [Hermes Agent](https://github.com/NousResearch/hermes-agent) di Nous Research. 
Il progetto fornisce un nucleo architetturale universale e disaccoppiato da servizi cloud proprietari, consentendo l'esecuzione nativa su hardware locale (Windows 11 / Linux / macOS) con motori come **Ollama**, modelli remoti compatibili OpenAI/Codex, orchestrazione avanzata di subagenti e interfaccia utente grafica Desktop.

---

## 1. Caratteristiche Principali

- **Runtime & Reasoning Loop Completo**: Ciclo conversazionale e di pensiero con gestione automatica del contesto e compattazione intelligente della traiettoria (`num_ctx`).
- **Inference Agnostica & Locale-First**: Supporto pronto all'uso per modelli locali quantizzati via **Ollama** (es. `gemma4:12b`, `qwen`, `llama`), endpoint OpenAI-compatible e provider cloud opzionali.
- **Indipendenza Totale da Nous Research**: Funzionamento 100% autonomo senza account Nous, senza dipendenza dal portale Nous e senza modelli imposti.
- **Orchestrazione Gerarchica di Subagenti**: Sistema `delegate_task` per la creazione di subagenti paralleli/annidati con memoria isolata e tracciamento dei consumi.
- **GUI-First (Hermes Desktop)**: Interfaccia grafica nativa in Electron (React + Vite) per la gestione visiva di agenti, modelli, sessioni e diagnostica.
- **Isolamento dei Progetti**: Gestione multi-progetto ermetica basata su profili indipendenti (`--profile <nome>`), senza condivisione non voluta di cronologia o credenziali.
- **Strumenti, Skill ed Estensioni**: Supporto per toolset CLI, protocollo MCP (Model Context Protocol), skill dinamiche e plugin.

---

## 2. Requisiti di Sistema

- **OS**: Windows 11 (oppure Linux / macOS)
- **Python**: `>= 3.11, < 3.15` (consigliato Python 3.14 con `uv`)
- **Node.js**: `>= 26` (per la GUI Desktop)
- **Motore di Inferenza Locale**: [Ollama](https://ollama.com/) attivo su `http://127.0.0.1:11434` con un modello scaricato (es. `ollama run gemma4:12b`)

---

## 3. Installazione e Avvio Rapido

### 3.1 Preparazione dell'Ambiente Python
Il repository utilizza `uv` per la gestione riproducibile delle dipendenze esatte:

```powershell
# Clona o posizionati nel repository
cd noemetra-agent-shell

# Crea il virtual environment e sincronizza i pacchetti
uv sync --group dev
```

### 3.2 Configurazione di un Profilo Locale (Ollama)
Crea un profilo dedicato per isolare i tuoi progetti:

```powershell
# Crea il profilo 'noemetra'
uv run hermes profile create noemetra

# Configura il modello locale Ollama
uv run hermes -p noemetra config set model.provider ollama
uv run hermes -p noemetra config set model.default gemma4:12b
uv run hermes -p noemetra config set model.base_url http://127.0.0.1:11434/v1

# Verifica lo stato
uv run hermes -p noemetra status
```

### 3.3 Esecuzione da Linea di Comando (CLI)
```powershell
# Esegui una singola query
uv run hermes -p noemetra chat -q "Ciao! Quali strumenti hai a disposizione?"

# Avvia la chat interattiva
uv run hermes -p noemetra chat
```

### 3.4 Avvio dell'Interfaccia Desktop (GUI)
```powershell
cd apps/desktop

# Installa le dipendenze npm
npm install

# Compila il webapp bundle
npm run build:webapp

# Compila il main process in modalità dev
node scripts/bundle-electron-main.mjs --dev

# Avvia l'applicazione desktop
npx electron .
```

---

## 4. Documentazione Architetturale

I dettagli implementativi e le analisi tecniche sono documentati nei seguenti file:

- [`ARCHITECTURE.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/ARCHITECTURE.md): Architettura del runtime, livelli di astrazione e isolamento multi-agente.
- [`DEPENDENCY_MAP.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/DEPENDENCY_MAP.md): Mappatura esatta delle dipendenze, componenti esterni e servizi isolati.
- [`REMOVAL_PLAN.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/REMOVAL_PLAN.md): Matrice KEEP / DISABLE / REMOVE / REPLACE con motivazioni e analisi rischi.
- [`UPSTREAM_STRATEGY.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/UPSTREAM_STRATEGY.md): Strategia di tracciamento fork, rebase e rispetto della Minimum Diff Rule.
- [`TEST_REPORT.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/TEST_REPORT.md): Resoconto dettagliato dei test eseguiti (unit test, subagenti, inferenza reale su hardware locale).
- [`AGENTS.md`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/AGENTS.md): Regole operative per gli agenti AI e i contributori.

---

## 5. Licenza e Attribuzione

Questo software è distribuito con licenza **MIT License**.
Derivato dal codice di **Hermes Agent** — Copyright © 2025 Nous Research.
I contributi, l'involucro universale e le personalizzazioni sono copyright © 2026 NOEMETRA.
Vedi il file [`LICENSE`](file:///C:/Users/Admin/.gemini/antigravity/scratch/noemetra-agent-shell/LICENSE) per il testo integrale.
