# NOEMETRA Cyber Purple Suite

Suite Purple Team multi-agente avversaria nativa per **NOEMETRA Agent Shell**:

1. **CyberObserver & PrivacyScrubber (`observer.py`)**: ingestione deterministica zero-LLM di log (JSONL, Syslog, Auth/HTTP) e codice/IaC in record immutabili `EV-xxxx`, con mascheramento reversibile di IP privati, credenziali, JWT ed email prima di eventuali chiamate AI cloud.
2. **Red Operator (`red_agent.py`)**: costruzione kill-chain multi-hop MITRE ATT&CK, proof di raggiungibilità, probe safe-audit controllati ed eventi sintetici (attacco + varianti di evasione).
3. **Blue Investigator & Critic (`blue_agent.py`)**: caccia alle evidenze contraddittorie (`EV-xxxx`), formulazione dell'ipotesi concorrente, sintesi di regole **Sigma**, **YARA** e **patch di remediation**.
4. **Purple Verifier & Replay (`verifier.py`)**: controllo deterministico anti-allucinazione sulle citazioni, **Purple Replay** in memoria (regole Blue contro eventi Red e traffico baseline benigno), verdetto calibrato (`CONFIRMED_ATTACK`, `EXPLOITABLE_CHAIN`, `FALSE_POSITIVE_BENIGN`, `INSUFFICIENT_EVIDENCE`) e **Test Discriminante**.
5. **Arena Multi-Modello**: assegnazione indipendente dei modelli LLM per **Red Operator** e **Blue Critic** (Ollama, Unsloth/GGUF, Unsloth Studio, LM Studio, ChatGPT Codex OAuth, OpenRouter Free, Ollama Cloud, OpenCode Free).
