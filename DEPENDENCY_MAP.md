# DEPENDENCY_MAP — NOEMETRA Agent Shell

## 1. Origine e Riferimento Upstream

- **Repository Upstream**: `https://github.com/NousResearch/hermes-agent`
- **Revisione Congelata**: `c314285f077e91937c995d419b9fa40af9eb4981` (Tue Nov 3 00:28:04 2026 -0800)
- **Tag Baseline Locale**: `upstream-baseline-20261103`
- **Organizzazione di Destinazione**: `https://github.com/NOEMETRA`
- **Licenza Upstream**: MIT License (Copyright © 2025 Nous Research). Tutti gli obblighi di licenza e attribuzione sono mantenuti inalterati.

---

## 2. Mappa delle Dipendenze Esterne e Nous Research

È stata condotta una mappatura sistematica di tutte le occorrenze, chiamate di rete e dipendenze legate all'infrastruttura commerciale Nous Research.

| Componente | Posizione Sorgente | Funzione | Stato nel Runtime NOEMETRA |
|---|---|---|---|
| **Plugin Provider Nous** | `plugins/model-providers/nous/` | Profilo di inferenza per Nous Portal API (`https://inference-api.nousresearch.com/v1`) | **ISOLATO / DISABILITATO PER DEFAULT**. Il runtime usa provider neutri o locali. |
| **Autenticazione Nous Portal** | `hermes_cli/auth_nous.py`, `auth.py` | Flusso Device Code OAuth (`portal.nousresearch.com`) e refresh token | **OPZIONALE / ISOLATO**. Nessuna chiamata automatica eseguita in assenza di comando esplicito. |
| **Anonymous Trial** | `hermes_cli/anon_auth.py`, `anon_sign_in.py` | Registrazione temporanea token trial sul portale Nous | **DISABILITATO**. Non invocato; NOEMETRA non richiede trial esterni. |
| **Reasoning Caps Warmer** | `hermes_cli/models_reasoning_caps.py` | Endpoint per preriscaldare capacità di reasoning Nous | **BYPASSATO**. Usato solo se il provider attivo è Nous. |
| **Chronos Scheduler** | `plugins/cron-chronos/`, `tools/chronos.py` | Cron NAS-mediated dipendente da Nous Portal | **NON ABILITATO**. Scheduler locale interno (`croniter`) pienamente autonomo. |
| **Desktop Product Identity** | `apps/desktop/product-identity.cjs` | Branding, Store publisher ID (`Nous Research Inc.`) e feed aggiornamento | **CONFIGURAZIONE SOSTITUIBILE**. Pronta per branding NOEMETRA e feed autonomi. |
| **Desktop Update Feed** | `apps/desktop/update-feed.cjs` | Controllo aggiornamenti canali Electron da server Nous | **DISABILITATO / INDIPENDENTE**. |

---

## 3. Dipendenze Software di Sistema

### 3.1 Ambiente Python (Core & Runtime)
- **Versione Python**: CPython 3.14.9 (x86_64 su Windows 11).
- **Package & Environment Manager**: `uv` (versione 0.13.5) con pin esatti (`==X.Y.Z`) definiti in `pyproject.toml` per massima riproducibilità e protezione della supply chain.
- **Librerie Chiave Verificate**:
  - `openai==2.54.0`: client per API compatibili OpenAI e Codex.
  - `pydantic==2.14.1`: convalida schemi e dati di sessione.
  - `fastapi`, `uvicorn`, `starlette`: backend API server e WebSocket per Desktop GUI.
  - `prompt_toolkit==3.0.53`: CLI interattiva.
  - `ruamel.yaml==0.18.16`: parsing e serializzazione configurazione senza perdita di commenti.
  - `truststore==0.10.5`: integrazione nativa con il certificato store del sistema operativo (Windows Certificate Store).

### 3.2 Ambiente Node / Electron (Desktop GUI)
- **Runtime Node**: Node.js v26.8.1 (npm v11.19.0).
- **Framework Frontend**: React 19, Vite, Tailwind CSS.
- **Shell Desktop**: Electron 38+.

### 3.3 Motori di Inferenza Verificati
- **Ollama**:
  - Versione installata: `0.40.13`.
  - Modello locale testato e funzionante: `gemma4:12b` (ID: `6114515d63c1`, dimensione 8.0 GB).
  - Protocollo: API nativa Ollama `/api/show` + endpoint OpenAI-compatible `/v1/chat/completions`.
- **OpenAI-Compatible Remoti**:
  - Supportati via configurazione standard (`base_url`, `api_key`).
