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
10. **Migrazione Stato Desktop per Tutte le Varianti Supportate (`apps/desktop/electron/main.ts`)**:
    - *Problema*: La funzione di migrazione verificava solo la variante standard (`appNamePascal === 'NoemetraAgentShell'`), escludendo le installazioni `bundled` e `light`. Inoltre, nelle release stabili di upstream, `package.json` manteneva `productName: "Hermes"` per tutte le varianti stabili (standard, bundled, light), per cui Electron salvava la directory utente in `Hermes`.
    - *Risoluzione*: Implementata `legacyDirectoryForVariant()` che risolve la directory sorgente effettiva: verifica prima l'eventuale directory specifica (`HermesLight`, `HermesAgent`) e fa fallback sulla cartella canonica upstream `Hermes`. In questo modo gli utenti che aggiornano da qualsiasi variante stabile preservano integralmente connessioni, profilo attivo e stato della finestra, mantenendo l'isolamento per build isolate (`USER_DATA_OVERRIDE` o `HERMES_DATA_DIR_SUFFIX`).
11. **Preservazione del Placeholder di Versione `0.0.0` in `pyproject.toml` per Compatibilità e Audit di Sicurezza**:
    - *Problema*: Una modifica di `version` in `pyproject.toml` a `0.1.0` alterava il contratto di discovery dell'ambiente virtuale (`_discover_venv`) e i contratti attesi dagli audit di compatibilità/sicurezza descritti in `tests/compat/README.md`.
    - *Risoluzione*: Ripristinato `version = "0.0.0"`. Il versioning applicativo viene governato dai tag di rilascio, da `apps/desktop/package.json` e dai canali di update di NOEMETRA, senza rompere i contratti di security audit sui sorgenti editabili.
12. **Adozione di `prompt_choice` per la Selezione Modelli nel Setup Locale (`hermes_cli/setup_quick.py`)**:
    - *Problema*: L'uso di raw `input()` nel setup rapido per la selezione dei modelli Ollama bypassava il seam ufficiale del wizard con navigazione da tastiera / frecce e supporto per replay / navigazione all'indietro (`prompt_choice`).
    - *Risoluzione*: Sostituito l'input grezzo con `prompt_choice`, consentendo la navigazione interattiva tra i modelli rilevati, l'inserimento manuale di un nome alternativo o la configurazione di un endpoint alternativo.
13. **Flessibilità Endpoint Locale con Selezione Alternativa anche con Ollama Attivo (`hermes_cli/setup_quick.py`)**:
    - *Problema*: Se Ollama rispondeva sulla porta 11434, l'utente non aveva un'opzione diretta per scegliere un server alternativo locale (es. LM Studio su porta 1234, vLLM su 8000).
    - *Risoluzione*: Aggiunta in modo trasparente l'opzione "Configure another local server (LM Studio, vLLM, custom endpoint)..." in tutti i branch di setup locale, configurando automaticamente il provider appropriato (`ollama` o `custom`) e normalizzando l'endpoint base.
14. **Pinning Esplicito del Percorso `userData` per le Release Stabili Desktop (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Nelle build stabili dove `applyDesktopIdentity()` restituiva `null`, l'assenza di un `app.setPath('userData', ...)` esplicito prima di `app.setName()` causava la ri-derivazione implicita di Electron della cartella utente verso il nome applicativo legacy (`Hermes`), rendendo inaccessibile lo stato migrato nella nuova cartella `NOEMETRA Agent Shell`.
    - *Risoluzione*: Aggiunto pinning preventivo con `app.setPath('userData', stableUserData)` prima della migrazione e prima dell'acquisizione del lock, garantendo che lock, migrazione ed esecuzione runtime puntino costantemente alla medesima directory `userData`. Aggiornato inoltre il fallback di `APP_NAME` su `PRODUCT_IDENTITY.displayName`.
15. **Isolamento delle Build Light Non-Stabili dalla Migrazione di Stato (`apps/desktop/electron/main.ts`)**:
    - *Problema*: La condizione `PRODUCT_IDENTITY.light` corrispondeva anche alle build canary o di commit di Light, rischiando di importare lo stato stabile di Hermes in ambienti di test/canary isolati.
    - *Risoluzione*: Rafforzato il controllo con il nome esatto della variante stabile `PRODUCT_IDENTITY.appNamePascal === 'NoemetraLight'`, escludendo in modo rigoroso le build canary e di commit dalla migrazione.
16. **Reset Completo dei Parametri di Trasporto nel Setup Locale (`hermes_cli/setup_quick.py`)**:
    - *Problema*: Quando l'utente importava una configurazione remota (es. OpenAI/Codex con `api_mode: "responses"`) e decideva di configurare un modello locale, l'aggiornamento parziale di `model` manteneva intatto `api_mode` o le intestazioni di autenticazione, causando chiamate con protocolli non supportati verso server Ollama o LM Studio.
    - *Risoluzione*: Invocata `clear_model_endpoint_credentials(model_cfg, clear_api_key=True, clear_api_mode=True)` e rimosse le chiavi di trasporto residue (`wire_format`, `headers`, `extra_body`, `auth_header`), garantendo che il provider locale operi su un endpoint OpenAI-compatible pulito (`/v1/chat/completions`).
17. **Rollback e Recupero della Migrazione Desktop su Fallimento della Destinazione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il merge da staging a destinazione falliva a metà, i file parzialmente scritti venivano considerati "stato significativo" da un riavvio successivo, bloccando definitivamente il retry della migrazione senza marcatore di completamento.
    - *Risoluzione*: Aggiunta marcatura di lavorazione `.migration-in-progress` e rollback immediato dei file tracciati in caso di eccezione durante il merge (in conformità alla policy per fallimenti di scritture autoritative di `apps/desktop/AGENTS.md`). All'avvio, l'eventuale presenza di un marker in-progress non completato pulisce i residui parziali e riesegue la migrazione in modo trasparente e sicuro.
18. **Supporto alla Migrazione per le Installazioni Canary di Hermes (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Gli utenti di build Canary (`appNamePascal` con suffisso `Canary`) non venivano intercettati dai controlli delle varianti stabili, iniziando con desktop vuoto.
    - *Risoluzione*: Mappate le directory legacy canary corrispondenti (`NoemetraAgentShellCanary` -> `HermesCanary`, `NoemetraAgentShellBundledCanary` -> `HermesBundledCanary` fallback `HermesCanary`, `NoemetraLightCanary` -> `HermesLightCanary` fallback `HermesCanary`), preservando il rigido isolamento di canale tra stabili e canary.
19. **Coordinamento della Migrazione con l'Applicazione Legacy e Consistenza Snapshot Storage (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se l'applicazione Hermes legacy era ancora aperta durante il primo avvio di NOEMETRA, la copia dei file di Chromium `Local Storage` e dei database LevelDB avveniva su file aperti in scrittura, rischiando stati inconsistenti o perdita delle impostazioni del renderer.
    - *Risoluzione*: Implementata `isLegacyAppRunning()` che verifica i lock attivi su `SingletonLock` e sul file `LOCK` di LevelDB (`Local Storage/leveldb/LOCK`). Se l'applicazione legacy è attiva, la migrazione viene posticipata in sicurezza al riavvio successivo a processo chiuso, garantendo la copia esclusiva di snapshot stabili, chiusi e consistenti.
20. **Ispezione Affidabile del Lock Singleton su Linux Senza Risoluzione del Simlink (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Su Linux, il file `SingletonLock` di Chromium è un symlink che punta a `<hostname>-<pid>` (un target non presente nel filesystem). `fs.existsSync` tentava di risolverlo fallendo con `ENOENT` e riportando falsamente il lock come inattivo. Inoltre, l'apertura del file `LOCK` di LevelDB non testa i lock consultivi Unix.
    - *Risoluzione*: Integrata `readlinkSync` che legge direttamente il target del simlink senza seguirlo, estrae il PID del proprietario e ne verifica l'effettiva liveness con `readLinuxProcState` e `isStaleSingletonLockOwner`, rilevando con certezza assoluta lo stato di esecuzione dell'applicazione legacy su Linux e macOS.
21. **Preservazione del Percorso di Retry per Migrazioni Posticipate (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se l'applicazione legacy era aperta al primo avvio di NOEMETRA, la migrazione veniva posticipata, ma l'avvio della shell generava file di configurazione predefiniti in `currentDir`. Al secondo avvio, tali file predefiniti venivano scambiati per "stato utente significativo", bloccando per sempre il recupero dello stato legacy.
    - *Risoluzione*: Introdotto il marcatore `.legacy-migration-pending`: se la migrazione è stata posticipata a causa del processo legacy attivo, un avvio successivo rileva il marcatore di attesa, bypassa i file predefiniti temporanei, completa il merge e rimuove il marcatore pendente garantendo che le impostazioni legacy vengano sempre recuperate.
22. **Ripristino Atomico dello Stato Pre-Esistente in Caso di Rollback della Migrazione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: In caso di migrazione posticipata, l'utente poteva avviare e utilizzare NOEMETRA creando stato locale prima della successiva migrazione. Se la copia da staging falliva, la procedura di rollback rimuoveva incondizionatamente le cartelle corrispondenti presenti in destinazione (incluso `Local Storage`), distruggendo lo stato pre-esistente dell'utente anziché ripristinarlo.
    - *Risoluzione*: Implementato snapshot transazionale preventivo in `.migration-backup`. In caso di eccezione durante il merge, `rollbackMigrationDestination()` ripristina integralmente ogni voce e directory pre-esistente dal backup, rispettando il vincolo di `apps/desktop/AGENTS.md` (L72-L78) che impone il rollback trasparente e sicuro delle scritture autoritative senza perdita di dati.
23. **Migrazione Atomica delle Directory Database LevelDB e Preservazione Modifiche Intermedie (`apps/desktop/electron/main.ts`)**:
    - *Problema*: La copia con `fs.cpSync(..., { force: false })` su una directory `Local Storage/leveldb` pre-esistente (creata dall'avvio temporaneo di NOEMETRA) non sovrascriveva i file collidenti (`CURRENT`, `MANIFEST`), lasciando attivo il database vuoto di default e generando una directory ibrida corrotta con file `.ldb` misti, vanificando la migrazione di connessioni e profili.
    - *Risoluzione*: Identificate le directory di storage atomiche (`DATABASE_DIR_NAMES`: `Local Storage`, `Session Storage`, `IndexedDB` e directory contenenti sottocartelle `leveldb`). Tali cartelle vengono trasferite come unità coerenti indivisibili: l'eventuale directory locale pre-esistente viene prima archiviata in sicurezza come backup (es. `Local Storage.postponed-backup`) per garantire che nessuna modifica utente intermedia venga scartata, e la cartella viene quindi sostituita integralmente dallo snapshot legacy integro e coerente.
24. **Preservazione Non-Distruttiva dei Database Attivi e Riconciliazione Connessioni (`apps/desktop/electron/main.ts`)**:
    - *Problema*: La sovrascrittura incondizionata dei database attivi (`Local Storage`, `IndexedDB`) con lo snapshot legacy causava la perdita di impostazioni e sessioni create dall'utente durante l'utilizzo di NOEMETRA a migrazione posticipata.
    - *Risoluzione*: Se la destinazione possiede già un database attivo, questo viene preservato intatto come sorgente attiva; lo snapshot legacy viene memorizzato a lato (`.legacy`) per consultazione e importazione, mentre i registri `connections.json` vengono riconciliati unendo in modo non distruttivo le connessioni legacy senza alterare il gateway primario configurato in NOEMETRA.
25. **Abort Tutelativo della Migrazione su Fallimento dello Snapshot di Backup (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se la copia di un elemento nel backup preventivo falliva, la procedura proseguiva con snapshot parziale; in caso di errore successivo, il rollback avrebbe rimosso elementi mai salvati nel backup.
    - *Risoluzione*: Implementato controllo rigoroso con ritorno booleano in `backupPreMigrationDestination()`. Se anche un solo elemento non può essere copiato nel backup, la migrazione viene immediatamente abortita prima di modificare `currentDir`, ottemperando alla policy di `apps/desktop/AGENTS.md` (L73-L78).
26. **Ripristino Pulito da Crash con Rimozione Preventiva dei File Parziali Staged (`apps/desktop/electron/main.ts`)**:
    - *Problema*: In caso di crash durante la migrazione prima della scrittura del marker di completamento, la routine di recupero ripristinava il backup senza ripulire i nuovi file parzialmente scritti da staging.
    - *Risoluzione*: In fase di recovery all'avvio, vengono prima rimossi tutti gli elementi staged parziali e successivamente ripristinati gli elementi originari da `.migration-backup`, garantendo che un successivo avvio riparta da uno stato 100% pulito e riproducibile.
27. **Conferma Separata dello Snapshot di Backup Prima di Marcare la Migrazione in Corso (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Scrivere `.migration-in-progress` prima del completamento del backup comportava che un crash durante la fase di copia del backup lasciasse un marcatore di progresso attivo con snapshot incompleto; al riavvio, il rollback eliminava i file di destinazione ripristinando un backup corrotto/incompleto.
    - *Risoluzione*: Introdotto il marker interno `.backup-complete`. Il marcatore `.migration-in-progress` viene ora scritto rigorosamente soltanto DOPO la verifica del completamento integrale del backup. In caso di crash antecedente, la destinazione non è stata modificata e il backup incompleto viene ripulito senza toccare i file utente.
28. **Risoluzione Esatta delle Directory Upstream Packaged con Spazi per le Varianti Desktop (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Nelle installazioni stabili e canary di Hermes Light e Hermes Bundled, i nomi ufficiali dei pacchetti upstream erano `Hermes Light` e `Hermes Agent` (con spazi). Il controllo cercava solo nomi PascalCase senza spazi, mancando lo stato preesistente e fallendo la migrazione.
    - *Risoluzione*: Aggiornata `legacyDirectoryForVariant()` per sondare in ordine di precedenza sia le denominazioni upstream con spazi (`Hermes Light`, `Hermes Agent`, `Hermes Light Canary`, `Hermes Agent Canary`) sia le varianti compatte, individuando con precisione la cartella `userData` legacy corretta.
29. **Ripristino Intelligente dello Stato Browser e Rilevamento Boilerplate Vuoto (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Durante un avvio a migrazione posticipata, Chromium generava cartelle `Local Storage` e `IndexedDB` vuote di default. Al successivo avvio a Hermes chiuso, la semplice presenza della cartella causava l'archiviazione di legacy in `.legacy` (mai aperto da Electron), impedendo all'utente di recuperare impostazioni del renderer, temi e bozze.
    - *Risoluzione*: Implementata `isDatabaseEmptyOrDefault()` che ispeziona la struttura di LevelDB: se la directory contiene solo metadati minimi di boot senza file tabella `.ldb`, la cartella viene considerata boilerplate temporaneo e sostituita atomisticamente dallo snapshot legacy, ripristinando integralmente le preferenze del renderer; se invece contiene dati utente reali creati nella sessione intermedia, questi vengono preservati in sicurezza prima del ripristino.
30. **Politica 'Merge, Don't Clobber' e Preservazione Attiva del Browser State Posticipato (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Quando l'utente ha prodotto stato attivo nella sessione intermedia, sovrascrivere o archiviare in cartelle cieche faceva sparire le modifiche recenti dell'utente.
    - *Risoluzione*: In ossequio al principio di `apps/desktop/AGENTS.md` (L59-L63), se il database di destinazione contiene dati utente attivi, questo non viene mai sovrascritto; la controparte legacy viene preservata come snapshot consultabile e recuperabile a lato (`.legacy`) corredata da un manifesto autoritativo di recupero `legacy-migration-available.json`.
31. **Trattenuta del Backup e del Marcatore di Recovery su Fallimento del Rollback (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il rollback falliva (es. disco pieno o permessi), il blocco catch ripuliva comunque backup e marcatore in-progress, cancellando permanentemente lo stato utente.
    - *Risoluzione*: `rollbackMigrationDestination` restituisce ora lo stato dell'operazione. Solo se il ripristino dello snapshot di backup è andato a buon fine al 100% vengono ripuliti il backup e il marcatore di progresso; altrimenti entrambi vengono trattenuti intatti per consentire al successivo avvio di completare il ripristino.
32. **Rilevamento Attivo dei Processi Hermes su Windows con Tasklist e Lock Probes (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Su Windows Chromium utilizza named mutex di processo anziché il symlink Unix di `SingletonLock`, e l'apertura del file `LOCK` di LevelDB non testa il byte-range lock `LockFileEx`, consentendo erroneamente a NOEMETRA di copiare database attivi durante la scrittura.
    - *Risoluzione*: Aggiunta scansione attiva dei processi in esecuzione su Windows tramite `tasklist.exe` con filtro CSV (intercettando `Hermes.exe`, `Hermes Agent.exe` e `Hermes Light.exe`) combinata con i probe esclusivi su `SingletonLock` e `LOCK`, garantendo che l'applicazione legacy venga rilevata anche su Windows prima di qualunque operazione di migrazione.
33. **Preservazione Rigorosa dei Database Senza Euristica di Dimensione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: L'analisi basata su log size e ricerca di file `.ldb` poteva scambiare database IndexedDB nidificati per directory vuote o considerare puliti LevelDB con piccoli log, rischiando di clobberare database utente attivi.
    - *Risoluzione*: Sostituita con `isDatabaseVerifiablyEmpty()`, che considera un database sostituibile soltanto se privo di file (`files.length === 0`). Qualunque database presente con contenuti viene rigorosamente lasciato intatto nella sessione attiva, archiviando la controparte legacy in `.legacy` con manifesto di recupero.
34. **Trattenuta dello Snapshot di Backup su Fallimento del Recupero Post-Interruzione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: In caso di crash antecedente con ripristino interrotto o fallito per problemi di I/O o lock all'avvio, gli errori venivano catturati e lo snapshot di backup e il marcatore in-progress venivano comunque eliminati, distruggendo la possibilità di recupero.
    - *Risoluzione*: Il ripristino di ciascun elemento viene verificato e tracciato: `backupDir` e `inProgressPath` vengono rimossi solo se il 100% degli elementi è stato ripristinato con successo; in caso di errore, sia il backup che il marcatore rimangono intatti per i successivi tentativi.
35. **Preservazione della Cartella di Staging su Fallimento del Rollback Immediato (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Il blocco `finally` ripuliva incondizionatamente la cartella di staging anche in caso di fallimento del rollback, privando il recovery ladder all'avvio successivo dell'elenco dei file parzialmente applicati da ripulire.
    - *Risoluzione*: Introdotto il flag `rollbackFailed`: la cartella `.migration-stage` viene trattenuta integra se il rollback non si è concluso con successo, permettendo all'avvio successivo di identificare ed eliminare le voci parziali prima di ripristinare il backup.
36. **Arresto Immediato della Migrazione su Fallimento del Ripristino Post-Interruzione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il ripristino di una precedente migrazione interrotta falliva, il codice continuava l'esecuzione avviando una nuova migrazione e sovrascrivendo il backup esistente con uno snapshot parzialmente corrotto.
    - *Risoluzione*: In caso di recovery fallito all'avvio, la funzione esegue un `return` immediato senza toccare il backup né tentare una nuova migrazione, preservando intatto lo snapshot per i tentativi successivi.
37. **Ripristino Autoritativo dei Database Browser e Canale IPC di Recupero (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Nei casi di migrazione posticipata, Chromium creava cartelle database con file di default (`CURRENT`, `MANIFEST`); considerare queste cartelle non vuote relegava lo snapshot legacy in `.legacy`, che nessun componente applicativo leggeva, impedendo all'utente di vedere temi, impostazioni e bozze storiche.
    - *Risoluzione*: Il database legacy viene trasferito come unità attiva principale nella destinazione (`Local Storage`, `IndexedDB`), mentre lo stato eventualmente creato nella sessione posticipata viene preservato in `${entry}.intervening`. Sono stati introdotti gli handler IPC `hermes:migration:get-recovery-info` e `hermes:migration:restore-intervening-database` che leggono il manifesto e offrono un percorso di recupero effettivo e invocabile.
38. **Preservazione dell'Eleggibilità alla Migrazione su Fallimenti Transitori (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il primo tentativo di migrazione falliva a causa di errori di I/O o permessi, l'avvio della shell creava file di default; al successivo riavvio `hasMeaningfulState` risultava vero e la migrazione non veniva più riprovata.
    - *Risoluzione*: Il marcatore `.legacy-migration-pending` viene scritto prima dell'inizio delle operazioni di staging, backup e copia, e viene rimosso solo dopo la conferma del completamento integrale, garantendo che qualunque errore transitorio mantenga attiva l'eleggibilità alla migrazione per il riavvio successivo.
39. **Precedenza dell'Intento Utente Attivo e Preservazione Non-Distruttiva dei Database (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Quando la migrazione veniva posticipata per processo legacy attivo, l'utente poteva utilizzare NOEMETRA configurando impostazioni e sessioni. Al successivo avvio a processo legacy chiuso, la migrazione considerava sacrificabile tutto lo stato intermedio sostituendo i database attivi con quelli legacy, causando la sparizione delle modifiche recenti dell'utente.
    - *Risoluzione*: Applicato rigorosamente il principio cardine di `apps/desktop/AGENTS.md` (L59-L64, L75-L78: *merge, don't clobber; newer intent takes precedence*). `hasDatabaseContent()` analizza la presenza di record e tabelle `.ldb` reali nei database attivi: se l'utente ha configurato dati in NOEMETRA, il database attivo (`Local Storage`, `Session Storage`, `IndexedDB`) rimane intatto e non viene toccato; la versione legacy viene preservata come affordance in `.legacy` corredata dal manifesto `legacy-migration-recovery.json`. Se invece la destinazione contiene solo boilerplate vuoto di boot, il database legacy viene ripristinato direttamente come database attivo.
40. **Controllo Rigoroso di Rimozione dei File Staged nel Recupero Post-Interruzione (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Durante il recovery da migrazione interrotta, la rimozione degli elementi staged precedentemente copiati nella destinazione avveniva in un blocco `try/catch` che ignorava gli errori; se un file o cartella parziale non poteva essere rimosso, la procedura proseguiva comunque, fondeva il backup nei file parziali rimasti e cancellava il backup.
    - *Risoluzione*: Introdotto il tracciamento `allStagedRemoved`: se anche una sola rimozione fallisce, l'operazione di recovery fallisce immediatamente, abortendo la procedura e trattenendo integro lo snapshot di backup, la cartella di staging e il marcatore `.migration-in-progress` in conformità alla policy per fallimenti di scritture autoritative.
41. **Canali IPC Unificati di Recupero per Database Legacy e Intermedi (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Mancavano percorsi di recupero bidirezionali invocabili per ripristinare sia snapshot legacy archiviati a lato sia snapshot intermedi salvati durante migrazioni posticipate.
    - *Risoluzione*: Aggiornati e unificati gli handler IPC `hermes:migration:get-recovery-info`, `hermes:migration:restore-legacy-database` e `hermes:migration:restore-intervening-database`, consentendo l'ispezione dei manifesti `legacy-migration-recovery.json` e `legacy-migration-available.json` e offrendo alle interfacce utente e ai tool diagnostici la capacità di ripristinare lo stato desiderato in qualunque scenario di migrazione complessa.
42. **Rilevamento Verificabile dello Stato Database Senza Soglie di Dimensione Arbitrarie (`apps/desktop/electron/main.ts`)**:
    - *Problema*: `hasDatabaseContent()` imponeva una soglia di 1024 byte per i file `.log` di LevelDB; se l'utente creava una quantità modesta di stato durante una migrazione posticipata, il write-ahead log numerato conteneva record validi in meno di 1 KB senza generare file `.ldb`, venendo scambiato per cartella vuota e cancellato.
    - *Risoluzione*: Rimosso ogni cutoff arbitrario di dimensione: qualunque file log numerato (`/^\d+\.log$/i`) con `size > 0` o tabella `.ldb` con `size > 0` o file non standard oltre i metadati di default (`CURRENT`, `LOCK`, `LOG`, `LOG.old`, `MANIFEST-*`) attesta la presenza verificabile di stato utente reale, preservando scrupolosamente le scritture recenti.
43. **Percorso di Recupero Raggiungibile In-App per i Database Legacy Preservati (`apps/desktop/src/store/legacy-migration-recovery.ts`, `apps/desktop/electron/preload.ts`, `apps/desktop/electron/main.ts`)**:
    - *Problema*: Quando i database legacy venivano archiviati a lato (`.legacy`) a causa della presenza di stato utente recente più prioritario, gli handler IPC non erano esposti nel preload né invocati dal renderer, lasciando l'utente privo di un meccanismo grafico per scoprire o ripristinare le preferenze e sessioni storiche.
    - *Risoluzione*: Esposto il bridge `window.hermesDesktop.migration` nel preload e registrato il listener reattivo in `apps/desktop/src/store/legacy-migration-recovery.ts` collegato al toast stack di notifica. All'avvio, se è presente uno snapshot legacy preservato, la shell mostra una notifica interattiva ("Legacy Settings & History Available") che consente all'utente con un solo click di ripristinare lo stato legacy ("Restore Legacy Data") o confermare lo stato corrente ("Keep Current"), ottemperando alla recovery guidance di `apps/desktop/AGENTS.md` (L73-L78).
44. **Rollback Transazionale e Retry su Fallimento della Riconciliazione Connessioni (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se la lettura, il parsing JSON o la scrittura di `connections.json` falliva durante la riconciliazione delle connessioni legacy, l'errore veniva silenziato nel `catch` e la migrazione veniva comunque registrata come completata, omettendo permanentemente le connessioni legacy senza possibilità di retry.
    - *Risoluzione*: Il fallimento genera preventivamente una copia di riserva `connections.legacy.json` ed effettua la propagazione esplicita dell'eccezione (`throw err`). Il chiamante esegue il rollback della transazione tramite `rollbackMigrationDestination`, preservando intatti staging, backup e marcatore pendente per consentire il retry al successivo avvio in piena conformità alle regole sulle scritture autoritative.
45. **Sostituzione Atomica dei Database Pre-Inizializzazione Chromium e Protezione Live Session (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Il ripristino immediato dei database storici tramite IPC rimuoveva e riscriveva la cartella LevelDB mentre Chromium era in esecuzione con file lock aperti, rischiando errori di I/O (`EBUSY`), corruzione di memoria e sovrascritture concorrenti durante il reload.
    - *Risoluzione*: Implementato il pattern di staged replacement con coordinate restart: il click su "Restore Legacy Data" scrive una richiesta transazionale in `.legacy-restore-pending.json` e riavvia l'applicazione con `relaunchApp()`. La funzione `applyPendingLegacyDatabaseRestore()` viene eseguita prima di `app.whenReady()` e prima di qualunque inizializzazione di Chromium: archivia preventivamente il database corrente in `.intervening`, copia lo snapshot legacy pulito, e in caso di errore esegue il rollback automatico da `.intervening`, eliminando qualsiasi conflitto a runtime.
46. **Manifesto Multi-Database e Preservazione Aggregata per Recovery Affordance (`apps/desktop/electron/main.ts`, `apps/desktop/src/global.d.ts`)**:
    - *Problema*: Quando più cartelle database contenevano stato (es. `Local Storage` e `Session Storage`), la scrittura del manifesto in ciascuna iterazione sovrascriveva il file `legacy-migration-recovery.json`, rendendo recuperabile soltanto l'ultimo database processato.
    - *Risoluzione*: Il manifesto raccoglie ora un array completo `databases` con tutti i database preservati (`Local Storage`, `Session Storage`, `IndexedDB`), consentendo all'affordance in-app e agli handler IPC di ripristinare contestualmente l'intero ecosistema di storage storico o singoli database selezionati.
47. **Offerta Universale della Migrazione e del Merge Anche in Presenza di Stato Esistente (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Il controllo `if (!hasMeaningfulState)` escludeva incondizionatamente la migrazione per le installazioni dove la cartella utente era già stata creata o utilizzata prima della migrazione, impedendo il recupero delle connessioni e la preservazione dello storico di Hermes.
    - *Risoluzione*: Rimosso il bypass restrittivo di `hasMeaningfulState`. Essendo l'algoritmo di migrazione intrinsecamente non distruttivo (preserva lo stato utente attivo, unisce le connessioni e archivia i database legacy come recovery affordance), la procedura viene sempre offerta ed eseguita finché il marcatore `.migration-complete` non certifica la conclusione positiva del processo.
48. **Preservazione dello Snapshot Intermedio Tramite Backup Temporaneo Isolato (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Quando veniva invocato il ripristino del database intermedio (`restoreInterveningDatabase`), `legacyPath` coincideva con `interveningPath`; la routine di swap eliminava `interveningPath` prima di copiare, distruggendo permanentemente lo snapshot intermedio e registrando un ripristino vuoto.
    - *Risoluzione*: Introdotta la cartella di backup temporaneo isolata `.swap-backup-${Date.now()}`: l'aggiornamento di `interveningPath` viene eseguito solo quando la sorgente non è lo snapshot intermedio stesso, garantendo che il ripristino di `.intervening` non distrugga mai la sorgente e consentendo un rollback integro in caso di fallimento.
49. **Preservazione delle Connessioni Legacy Distinte con ID Collidenti (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Due installazioni con etichette identiche (es. `local` o `my-server`) generavano ID identici; la riconciliazione scartava la connessione legacy collidente anche se puntava a un endpoint, host o tipologia di backend completamente differente.
    - *Risoluzione*: Implementata `areConnectionsEquivalent()` per confrontare URL, host, porta, username e profilo. Se due connessioni collidono nell'ID ma presentano configurazioni distinte, alla connessione legacy viene assegnato un nuovo ID univoco (`<id>-legacy`) ed etichetta distinta, conservando integralmente tutte le connessioni senza perdite.
50. **Propagazione del Fallimento Scrittura del Manifesto di Recovery (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se la scrittura del manifesto `legacy-migration-recovery.json` falliva (es. disco pieno o permessi), il blocco `catch` silente consentiva la scrittura del marcatore di completamento e l'eliminazione del backup, lasciando i database in `.legacy` senza affordance grafica e senza retry.
    - *Risoluzione*: L'eccezione viene ora propagata esplicitamente (`throw manifestErr`), attivando il rollback della destinazione tramite `rollbackMigrationDestination`, trattenendo lo snapshot di backup e staging, e garantendo che la migrazione venga ritentata al riavvio successivo.
51. **Confronto Completo dei Campi di Instradamento delle Connessioni (`apps/desktop/electron/main.ts`)**:
    - *Problema*: `areConnectionsEquivalent` utilizzava `type`, `username` e `profile` anziché i campi effettivi di `RegistryConnection` (`kind`, `user`, `remoteProfile`, `keyPath`, `remoteHermesPath`, `org`, `name`), rischiando di scartare connessioni SSH o Cloud distinte che differivano per utente o profilo remoto.
    - *Risoluzione*: Aggiornato il confronto su tutti i campi reali di instradamento del registro (`kind`, `url`, `host`, `port`, `user`/`username`, `remoteProfile`/`profile`, `keyPath`, `remoteHermesPath`, `org`, `name`). Qualunque discrepanza preserva la connessione legacy assegnando un ID univoco incrementale.
52. **Ripristino Bidirezionale dello Stato Intermedio Preservato Post-Restart (`apps/desktop/electron/main.ts`, `apps/desktop/src/store/legacy-migration-recovery.ts`)**:
    - *Problema*: Una volta ripristinati i dati legacy, la rimozione del manifesto impediva all'utente di invertire l'operazione per recuperare le impostazioni o cronologia NOEMETRA create prima dello swap, lasciando i database `.intervening` privi di un'affordance grafica.
    - *Risoluzione*: Al termine della sostituzione prima dell'avvio di Chromium, `applyPendingLegacyDatabaseRestore()` genera un manifesto attivo `status: 'intervening-preserved-legacy-active'` che elenca le directory `.intervening`. All'avvio, la shell mostra la notifica interattiva "Legacy Data Restored" con l'azione "Restore Previous Setup" (che invoca `restoreInterveningDatabase('all')`) e "Keep Legacy" per confermare definitivamente la configurazione storica.
53. **Persistenza della Notifica di Recovery su Fallimento della Richiesta (`apps/desktop/src/store/legacy-migration-recovery.ts`)**:
    - *Problema*: Se la chiamata di staging falliva (es. directory protetta da scrittura), l'errore veniva ignorato e il callback `onDismiss` rimuoveva il manifesto, precludendo ulteriori tentativi di recupero.
    - *Risoluzione*: Rimossa la rimozione preventiva in `onDismiss` e verificato il responso dell'operazione: in caso di fallimento (`res?.ok === false`), viene emessa una notifica di errore descrittiva e il manifesto di recovery viene conservato intatto consentendo all'utente di ritentare.
54. **Transazione Persistita di Swap con Tracciamento Intento 'in_progress' e Ripristino Senza Perdite (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se la copia di uno snapshot falliva dopo la rimozione del database attivo o se il processo veniva interrotto prima della registrazione dello swap completato, la procedura di rollback considerava il database non toccato ed eliminava il backup, causando la perdita irreparabile delle impostazioni o cronologia attiva.
    - *Risoluzione*: Lo stato `db.state = 'in_progress'` viene ora registrato su `.legacy-restore-tx.json` prima della rimozione della directory attiva. In caso di fallimento o crash, sia il rollback immediato che la routine di recupero al riavvio ripristinano dal backup qualunque database toccato (`in_progress` o `swapped`), e il file di backup viene eliminato solo dopo l'effettivo successo del ripristino.
55. **Preservazione dei Backup di Recovery e Transazione su Fallimento di Rollback (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il ripristino di un database dal backup falliva durante il recupero post-crash (es. per permessi o lock transitori), il ciclo rimuoveva comunque il backup e il blocco `finally` cancellava `.legacy-restore-tx.json`, eliminando l'unica copia integra dello stato utente e precludendo tentativi successivi.
    - *Risoluzione*: Il backup e il marcatore di transazione `.legacy-restore-tx.json` vengono ora preservati integralmente a meno che ogni singolo ripristino non si concluda con successo, garantendo la riesecuzione automatica al boot successivo come richiesto da AGENTS.md:73-78.
56. **Tolleranza per i Database Legacy Vuoti nella Migrazione Iniziale (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se un'installazione precedente presentava un database del browser vuoto (es. Session Storage o IndexedDB contenente solo i file di configurazione iniziali di LevelDB senza dati utente), la verifica `hasDatabaseContent()` generava un'eccezione annullando l'intera migrazione e impedendo l'importazione di impostazioni e connessioni valide.
    - *Risoluzione*: La creazione del sidecar `.legacy` viene ora condizionata a `hasDatabaseContent(stagedPath)`: se il database legacy è vuoto, lo stato attivo di destinazione viene preservato intatto senza creare sidecar inutili o generare errori, e la verifica della copia staged controlla la corretta creazione dei file senza imporre la presenza di record utente in database legittimamente vuoti.
57. **Transazione 'committed' e Pubblicazione Manifesto Prima della Pulizia dei Backup (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il processo si interrompeva durante la pulizia dei backup, la transazione rimaneva in stato `swapping` con alcuni backup già eliminati; al riavvio, il recupero tentava il rollback parziale lasciando uno stato database incoerente e non pubblicando l'affordance grafica di recovery.
    - *Risoluzione*: La transazione viene ora marcata `phase: 'committed'` prima di pubblicare il manifesto `legacy-migration-recovery.json`. La pulizia dei backup e la rimozione dei marcatori pendenti avvengono solo a manifesto pubblicato. In caso di interruzione durante o dopo `committed`, il recupero iniziale finalizza la pubblicazione del manifesto e la pulizia senza eseguire rollback.
58. **Blocco dell'Avvio Applicativo in Caso di Rollback Interrotto Incompleto (`apps/desktop/electron/main.ts`)**:
    - *Problema*: Se il rollback di una transazione interrotta falliva al riavvio (es. per file lock o permessi), il metodo terminava con un semplice log consentendo a Chromium di avviarsi e modificare i database parzialmente ripristinati; al successivo riavvio, il retry avrebbe sovrascritto tali nuove modifiche.
    - *Risoluzione*: In caso di rollback fallito (`!allRollbacksSucceeded`), l'applicazione emette una finestra diagnostica modale e termina immediatamente il processo con `app.exit(1)`, impedendo categoricamente a Chromium di aprire o alterare database in stato incoerente fino alla risoluzione del problema.
