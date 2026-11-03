# AGENTS.md — Regole Operative per gli Agenti di Sviluppo NOEMETRA

Questo documento definisce le regole operative vincolanti per qualsiasi agente AI o sviluppatore che opera sul codice sorgente di **NOEMETRA Agent Shell**.

---

## 1. Principi Fondamentali

1. **Non Riscrivere ciò che Funziona**: non rifattorizzare o sostituire codice funzionante per ragioni puramente stilistiche.
2. **Nessuna Cancellazione Cieca**: non eliminare moduli o file senza aver prima cercato le occorrenze in tutto il repository e verificato l'impatto con la test suite (`pytest`, `vitest`, `tsc`).
3. **Verifica Prima delle Asserzioni**: non dichiarare verificato, funzionante o compatibile ciò che non è stato realmente compilato o eseguito. Ogni asserzione deve basarsi su log ed evidenze concrete.
4. **Indipendenza da Servizi Chiusi**: nessun commit, modulo o configurazione predefinita deve rendere obbligatorio l'uso di account commerciali Nous Research, portali proprietari o modelli a pagamento imposti.
5. **Isolamento della Memoria e dei Progetti**: i profili (`--profile`) e i subagenti (`delegate_task`) devono mantenere la rigorosa separazione delle memorie e dei file di sessione.

---

## 2. Regole di Contributo e Codice

### 2.1 Architettura e Dipendenze
- **Minimum Diff Rule**: le modifiche rispetto all'upstream devono essere circoscritte e pulite, per facilitare il rebase periodico.
- **Supply Chain e Pinning**: le dipendenze Python dirette in `pyproject.toml` sono rigorosamente esatte (`==X.Y.Z`). Nessun range arbitrario che permetta l'infiltrazione di pacchetti non verificati.
- **Standard di Inferenza**:
  - Supporto primario per **runtime locali** (Ollama, endpoint compatibili OpenAI locali).
  - Supporto per **runtime remoti** tramite API key o OAuth ufficiali dei rispettivi provider. Non manipolare manualmente token OAuth di altri runtime.

### 2.2 Subagenti e Strumenti
- **Sottoinsiemi di Strumenti**: quando un subagente viene lanciato, deve ereditare soltanto gli strumenti necessari allo svolgimento del task assegnato (`DELEGATE_BLOCKED_TOOLS`).
- **Profondità Controllata**: la profondità di spawn deve rispettare i clamp di configurazione per prevenire loop infiniti o consumi anomali di risorse.
- **Prompt Caching Invariant**: non mutare il prefisso del prompt conversazionale durante la sessione a meno che non intervenga il compressore di contesto.

### 2.3 Licenze e Attribuzione
- Il repository è concesso sotto licenza **MIT License (Copyright © 2025 Nous Research)**.
- Ogni file derivato deve rispettare l'intestazione e i diritti originali, integrando le nuove attribuzioni per l'organizzazione NOEMETRA.

---

## 3. Workflow di Test e Verifica

Prima di considerare concluso un task o aprire un branch/PR:
1. **Verifica Unit Test**: eseguire i test pertinenti via `uv run --group dev pytest tests/<area>/`.
2. **Verifica Desktop**: se sono stati toccati file GUI/Electron, verificare la compilazione con:
   - `npm run build:webapp`
   - `npx tsc --build tsconfig.electron.json`
3. **Verifica Offline**: testare con Ollama locale per garantire che non vengano introdotte regressioni di connettività verso host esterni non desiderati.
