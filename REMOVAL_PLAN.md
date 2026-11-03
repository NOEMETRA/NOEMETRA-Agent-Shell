# REMOVAL_PLAN — Matrice Decisionale di Conservazione e Disaccoppiamento

In conformità con il Mandato (§2 "Non riscrivere ciò che funziona. Non cancellare componenti prima di averne verificato le dipendenze" e §9 "Produrre una matrice KEEP / DISABLE / REMOVE / REPLACE con motivazioni e rischi"), la seguente matrice documenta lo stato di ciascun componente architetturale di Hermes Agent.

---

## Matrice KEEP / DISABLE / REMOVE / REPLACE

| Componente | Azione | Motivazione Tecnica | Rischio e Dipendenze Verificate |
|---|---|---|---|
| **Agent Reasoning Loop** (`agent/`) | **KEEP** | Cuore del runtime agentico: turn management, prompt formatting, context compression, deadline tracking. Robusto e testato. | Zero rischi. Nessun vincolo a fornitori esterni. |
| **Hermes Desktop Shell & SDK** (`apps/desktop/`) | **KEEP & REPLACE** | Interfaccia Electron ricca (React, Vite) con visualizzazione sessioni, diagnostica, impostazioni modelli e gestione profili. L'identità di prodotto in `product-identity.cjs` viene riconfigurata per NOEMETRA. | Basso. Dipende dal server WebSocket/HTTP locale (`web_server.py`). Non richiede server remoti. |
| **Delegate Tool & Subagenti** (`tools/delegate_tool*.py`) | **KEEP** | Architettura completa di subagenti paralleli/gerarchici con isolamento database, rollup costi e limitazione profondità. Verificata con 71 test passati. | Zero rischi. Completamente indipendente da Nous. |
| **Provider Registry & Profiles** (`providers/base.py`, `providers/__init__.py`) | **KEEP** | Sistema ad architettura aperta basato su plugin. Supporta oltre 35 provider locali e remoti. | Nessuno. Disaccoppia nativamente il modello dal runtime. |
| **Local Inference Ollama** (`agent/agent_init_ollama.py`, `models_local.py`) | **KEEP** | Integrazione nativa impeccabile con probe context window (`/api/show`) e adattamento compressore di contesto. Verificato con `gemma4:12b`. | Nessuno. Esegue 100% offline su Windows 11. |
| **Configurazione & Profili** (`hermes_cli/config.py`, `--profile`) | **KEEP** | Gestione rigorosa dei profili isolati (`HERMES_HOME`), garantendo separazione ermetica di dati, sessioni e credenziali tra progetti. | Nessuno. Essenziale per il multi-progetto NOEMETRA. |
| **Plugin Provider Nous** (`plugins/model-providers/nous/`) | **DISABLE / ISOLATE** | Rappresenta il connettore verso l'infrastruttura commerciale Nous Portal. Non viene cancellato per non rompere il tree di discovery dei plugin, ma viene escluso dai default. | Basso se isolato. L'eliminazione fisica immediata richiederebbe modifiche a test legacy; l'isolamento è a zero impatto. |
| **Default Model/Provider Nous** (`config_defaults.py`, `models.py`) | **REPLACE** | I default di fabbrica non devono puntare ai modelli o al portale Nous. Sostituiti con selezione utente o fallback locale (Ollama). | Zero rischi. I profili NOEMETRA adottano `ollama` o provider esplicito. |
| **Anonymous Trial & Sign-In** (`hermes_cli/anon_*.py`) | **DISABLE** | Meccanismo per ottenere token temporanei dal portale Nous al primo avvio. Inutile e indesiderato per NOEMETRA. | Nessuno. Disabilitato senza impatto sul runtime offline o su chiavi personali. |
| **Chronos Cloud Cron** (`plugins/cron-chronos/`, `tools/chronos.py`) | **DISABLE** | Cron delegato al server Nous Portal. NOEMETRA supporta lo scheduler locale nativo basato su `croniter`. | Nessuno. Il cron locale continua a funzionare regolarmente. |
| **Feed di Aggiornamento Nous** (`apps/desktop/update-feed.cjs`) | **DISABLE / REPLACE** | Il meccanismo di auto-update Electron puntava ai repository Nous Research. Verrà configurato sui release asset NOEMETRA. | Nessun impatto sulle build locali. |
| **Telemetria / Chiamate Esterne** | **DISABLE** | Qualsiasi emissione verso `telemetry.nousresearch.com` o simili viene azzerata. | Garanzia di riservatezza e conformità per installazioni aziendali e offline. |

---

## Criteri Operativi per Eventuali Rimozioni Future

1. **Nessuna cancellazione a caldo**: i moduli dismessi vengono prima disattivati e isolati tramite configurazione o guard clause.
2. **Verifica della test suite**: prima di rimuovere file di codice sorgente, viene eseguita la test suite completa per accertare che non esistano import nascosti o dipendenze incrociate.
3. **Preservazione dell'albero Upstream**: le modifiche al codice upstream devono rimanere minimali e circoscritte, facilitando il rebase periodico con le release upstream.
