# UPSTREAM_STRATEGY — Strategia di Forking e Allineamento Upstream

## 1. Obiettivo Strategico

Mantenere **NOEMETRA Agent Shell** pienamente allineato all'evoluzione di Hermes Agent di Nous Research (bugfix, nuove capacità agentiche, standard di tool calling, aggiornamenti Electron e sicurezza), preservando allo stesso tempo l'indipendenza strutturale, la rimozione dei vincoli proprietari e l'identità NOEMETRA.

---

## 2. Topologia dei Repository Git

```
[Upstream: NousResearch/hermes-agent]
              │
              │  git fetch upstream
              ▼
   [Local Tracking: upstream/main]
              │
              │  git rebase / cherry-pick (selettivo)
              ▼
   [Branch di Lavoro: noemetra/main]
              │
              │  git push origin
              ▼
[Origin: NOEMETRA/noemetra-agent-shell]
```

### Configurazione dei Remotes
- **`upstream`**: `https://github.com/NousResearch/hermes-agent.git` (repository sorgente ufficiale)
- **`origin`**: `https://github.com/NOEMETRA/noemetra-agent-shell.git` (repository di destinazione NOEMETRA)

### Tagging e Versioning
- **Commit Baseline Congelato**: `c314285f077e91937c995d419b9fa40af9eb4981` (Tue Nov 3 00:28:04 2026 -0800)
- **Tag Baseline Locale**: `upstream-baseline-20261103`
- **Convenzione Tag NOEMETRA**: `v0.1.0-noemetra`, `v0.2.0-noemetra`, con tracciamento esatto dell'upstream commit di riferimento.

---

## 3. Politica di Modifica del Codice (Minimum Diff Rule)

Per garantire la massima manutenibilità nel lungo termine:

1. **Minimo Delta sui File Core**: non riscrivere o rifattorizzare file di runtime upstream se non strettamente necessario per l'indipendenza o la sicurezza.
2. **Estensioni tramite Plugin e Configurazione**:
   - Nuovi provider e backend di inferenza vengono aggiunti in `plugins/model-providers/<nome>/` o in runtime extensions dedicate.
   - Le impostazioni predefinite vengono governate tramite profili (`--profile noemetra`) e file di configurazione (`config.yaml`), evitando modifiche distruttive ai default sorgente.
3. **Isolamento dell'Identità Desktop**:
   - La configurazione grafica e il branding risiedono in `apps/desktop/product-identity.cjs`, consentendo di variare nome, ID applicativo e icone senza toccare la logica interna dell'interfaccia.
4. **Licenza e Diritti**:
   - Mantenimento integrale del file `LICENSE` originale MIT Copyright © 2025 Nous Research.
   - Aggiunta di note di copyright per i contributi derivati di NOEMETRA.

---

## 4. Procedura Operativa di Sincronizzazione Upstream

Quando upstream rilascia aggiornamenti rilevanti o correzioni di sicurezza:

1. Creazione di un branch temporaneo di sincronizzazione:
   ```powershell
   git checkout -b sync/upstream-<data> noemetra/main
   git fetch upstream
   ```
2. Analisi delle differenze:
   ```powershell
   git log --oneline noemetra/main..upstream/main
   ```
3. Applicazione tramite rebase o cherry-pick mirato:
   ```powershell
   git rebase upstream/main
   ```
4. Esecuzione dei test di regressione locali e verifica del funzionamento con Ollama e profili isolati.
5. Merge in `noemetra/main` e tagging della nuova release.
