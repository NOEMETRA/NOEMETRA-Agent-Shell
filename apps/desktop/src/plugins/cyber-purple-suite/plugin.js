/**
 * NOEMETRA Cyber Purple Suite — Native Desktop Plugin (@hermes/plugin-sdk)
 *
 * Multi-agent adversarial cybersecurity pipeline:
 * - CyberObserver verbatim ingestion & PrivacyScrubber (RFC1918 IP, JWT, secrets, email masking)
 * - Red Operator: MITRE ATT&CK kill-chain, reachability proofs, safe-audit probes & evasion events
 * - Blue Investigator & Critic: contradiction hunting, competing hypothesis, Sigma/YARA & patches
 * - Purple Verifier & Replay: citation verification, live Sigma/YARA vs Red evasion replay & benchmark
 * - Configurable Multi-Model Arena: independent LLM assignment for Red Operator vs Blue Critic
 */

import {
  Codicon,
  host,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA
} from '@hermes/plugin-sdk'
import { useEffect, useMemo, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PLUGIN_ID = 'cyber-purple-suite'

const CSS = `
.cp-shell {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
  background: radial-gradient(circle at 10% 0%, rgba(244, 63, 94, 0.08), transparent 36%),
              radial-gradient(circle at 90% 10%, rgba(56, 189, 248, 0.08), transparent 40%),
              var(--background, #070b12);
  color: var(--foreground, #f1f5f9);
  font-family: "Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
  overflow: hidden;
}
.cp-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  padding: 12px 18px;
  background: color-mix(in srgb, var(--card, #0d1422) 86%, transparent);
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
}
.cp-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.cp-logo {
  width: 32px;
  height: 32px;
  border-radius: 9px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, rgba(244, 63, 94, 0.2), rgba(168, 85, 247, 0.25));
  border: 1px solid rgba(168, 85, 247, 0.45);
  color: #e879f9;
}
.cp-arena-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 8px 18px;
  background: rgba(10, 16, 28, 0.8);
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  font-size: 12px;
}
.cp-role-box {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-radius: 8px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(15, 23, 42, 0.72);
}
.cp-role-box.red { border-color: rgba(244, 63, 94, 0.35); }
.cp-role-box.blue { border-color: rgba(56, 189, 248, 0.35); }
.cp-select, .cp-input, .cp-textarea {
  background: color-mix(in srgb, var(--background, #090e18) 92%, transparent);
  color: var(--foreground, #f1f5f9);
  border: 1px solid rgba(148, 163, 184, 0.24);
  border-radius: 7px;
  padding: 5px 8px;
  font-size: 12px;
}
.cp-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 8px;
  padding: 6px 12px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid rgba(148, 163, 184, 0.25);
  background: rgba(15, 23, 42, 0.85);
  color: var(--foreground, #f1f5f9);
  cursor: pointer;
}
.cp-btn:disabled { opacity: 0.55; cursor: not-allowed; }
.cp-btn-primary {
  background: linear-gradient(135deg, #be123c, #7e22ce);
  border-color: rgba(168, 85, 247, 0.55);
  color: #fff;
}
.cp-main {
  display: grid;
  grid-template-columns: 350px 1fr;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.cp-col {
  display: flex;
  flex-direction: column;
  padding: 14px;
  overflow-y: auto;
  min-height: 0;
  gap: 12px;
}
.cp-col-left {
  border-right: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  background: rgba(9, 14, 24, 0.6);
}
.cp-card {
  background: color-mix(in srgb, var(--card, #0d1422) 90%, transparent);
  border: 1px solid rgba(148, 163, 184, 0.16);
  border-radius: 11px;
  padding: 12px 14px;
}
.cp-card-red { border-left: 3px solid #f43f5e; }
.cp-card-blue { border-left: 3px solid #38bdf8; }
.cp-card-purple { border-left: 3px solid #a855f7; }
.cp-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 10.5px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid transparent;
}
.cp-b-red { background: rgba(244, 63, 94, 0.16); color: #fda4af; border-color: rgba(244, 63, 94, 0.35); }
.cp-b-blue { background: rgba(56, 189, 248, 0.16); color: #7dd3fc; border-color: rgba(56, 189, 248, 0.35); }
.cp-b-purple { background: rgba(168, 85, 247, 0.18); color: #d8b4fe; border-color: rgba(168, 85, 247, 0.4); }
.cp-b-green { background: rgba(16, 185, 129, 0.16); color: #6ee7b7; border-color: rgba(16, 185, 129, 0.35); }
.cp-b-amber { background: rgba(245, 158, 11, 0.16); color: #fcd34d; border-color: rgba(245, 158, 11, 0.35); }
.cp-cite-btn {
  cursor: pointer;
  background: rgba(168, 85, 247, 0.18);
  color: #e9d5ff;
  border: 1px solid rgba(168, 85, 247, 0.45);
  border-radius: 999px;
  padding: 1px 7px;
  font-size: 10.5px;
  font-weight: 700;
  margin-right: 4px;
}
.cp-ev {
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid rgba(148, 163, 184, 0.12);
  background: rgba(15, 23, 42, 0.65);
  font-family: ui-monospace, Consolas, monospace;
  font-size: 11.5px;
  margin-bottom: 6px;
}
.cp-ev-active {
  border-color: #a855f7;
  background: rgba(168, 85, 247, 0.18);
  box-shadow: 0 0 0 1px rgba(168, 85, 247, 0.45);
}
.cp-tabs {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.cp-tab {
  padding: 6px 12px;
  border-radius: 8px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(15, 23, 42, 0.65);
  color: var(--muted-foreground, #94a3b8);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}
.cp-tab.active {
  color: #fff;
  border-color: rgba(168, 85, 247, 0.6);
  background: rgba(168, 85, 247, 0.22);
}
.cp-pre {
  background: #050911;
  border: 1px solid rgba(148, 163, 184, 0.16);
  border-radius: 8px;
  padding: 9px 11px;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 11.5px;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 6px 0 0;
}
.cp-stage-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
}
.cp-claim-card {
  padding: 10px 12px;
  border-radius: 9px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(15, 23, 42, 0.62);
  font-size: 12px;
  margin-bottom: 8px;
}
.cp-claim-card.supported { border-left: 3px solid #f43f5e; }
.cp-claim-card.open { border-left: 3px solid #f59e0b; }
.cp-claim-card.refuted { border-left: 3px solid #10b981; }
.cp-note-box {
  font-size: 11.5px;
  padding: 6px 9px;
  border-radius: 7px;
  background: rgba(245, 158, 11, 0.11);
  border: 1px solid rgba(245, 158, 11, 0.32);
  color: #fde68a;
  margin-top: 6px;
}
@media (max-width: 960px) {
  .cp-main { grid-template-columns: 1fr; }
  .cp-col-left { border-right: none; border-bottom: 1px solid rgba(148, 163, 184, 0.14); max-height: 280px; }
}
`

function verdictBadgeClass(verdict) {
  if (verdict === 'CONFIRMED_ATTACK' || verdict === 'EXPLOITABLE_CHAIN') return 'cp-badge cp-b-red'
  if (verdict === 'FALSE_POSITIVE_BENIGN') return 'cp-badge cp-b-green'
  return 'cp-badge cp-b-amber'
}

function claimStatusInfo(status) {
  if (status === 'supported') return { cls: 'cp-badge cp-b-red', label: 'SUPPORTATA' }
  if (status === 'refuted') return { cls: 'cp-badge cp-b-green', label: 'CONFUTATA' }
  return { cls: 'cp-badge cp-b-amber', label: 'IPOTESI APERTA' }
}

function claimPriorityInfo(priority) {
  if (priority === 'critical') return { cls: 'cp-badge cp-b-red', label: 'PRIORITA CRITICA' }
  if (priority === 'high') return { cls: 'cp-badge cp-b-amber', label: 'PRIORITA ALTA' }
  if (priority === 'low') return { cls: 'cp-badge cp-b-purple', label: 'PRIORITA BASSA' }
  return { cls: 'cp-badge cp-b-blue', label: 'PRIORITA MEDIA' }
}

function stageBadgeClass(stage, status) {
  if (stage === 'diagnosis') {
    if (status === 'CONFIRMED_THREAT') return 'cp-badge cp-b-red'
    if (status === 'REFUTED_FALSE_POSITIVE') return 'cp-badge cp-b-green'
    if (status === 'NO_THREAT_EVIDENCE') return 'cp-badge cp-b-blue'
    return 'cp-badge cp-b-amber'
  }
  if (stage === 'simulation') {
    if (status === 'COVERAGE_COMPLETE') return 'cp-badge cp-b-green'
    if (status === 'FALSE_POSITIVE_RISK') return 'cp-badge cp-b-red'
    if (status === 'COVERAGE_PARTIAL') return 'cp-badge cp-b-amber'
    return 'cp-badge cp-b-purple'
  }
  if (status === 'VERIFIED_FIXED') return 'cp-badge cp-b-green'
  if (status === 'STILL_VULNERABLE') return 'cp-badge cp-b-red'
  if (status === 'PARTIALLY_MITIGATED' || status === 'EVIDENCE_UPDATED') return 'cp-badge cp-b-amber'
  return 'cp-badge cp-b-purple'
}

function defaultVerifyModeForCase(rep) {
  const mode = rep?.verdict?.diagnosis?.analysis_mode
  const kind = rep?.ingestion?.source_kind
  if (mode === 'artifact_review' || kind === 'code' || kind === 'config') return 'verify_patch'
  return 'append_evidence'
}

function buildProviderGroups(modelsInfo, allowRemote) {
  const localItems = []
  const seen = new Set()
  const pushItem = (target, value, label) => {
    if (!value || seen.has(value)) return
    seen.add(value)
    target.push({ value, label })
  }

  const ollamaModels = Array.isArray(modelsInfo?.ollama?.models) ? modelsInfo.ollama.models : []
  pushItem(localItems, 'ollama', `Ollama Locale (${ollamaModels.length})`)

  const ggufModels = Array.isArray(modelsInfo?.local_gguf?.models) ? modelsInfo.local_gguf.models : []
  pushItem(localItems, 'gguf', `Unsloth / GGUF (${ggufModels.length})`)

  const localRuntimes = modelsInfo?.local_runtimes || {}
  for (const [rid, info] of Object.entries(localRuntimes)) {
    const rCount = Array.isArray(info?.models) ? info.models.length : 0
    if (rid === 'unsloth_studio' || info?.status === 'online') {
      pushItem(localItems, rid, `${info?.label || rid} (${rCount})`)
    }
  }

  const groups = [{ label: 'Runtime Locali', items: localItems }]

  if (allowRemote) {
    const cloudItems = []
    const codex = modelsInfo?.codex_oauth
    if (codex?.configured && Array.isArray(codex.models) && codex.models.length > 0) {
      pushItem(cloudItems, 'openai-codex', `ChatGPT Codex (${codex.models.length})`)
    }
    const cloud = modelsInfo?.cloud_providers || {}
    if (cloud.openrouter?.configured && Array.isArray(cloud.openrouter.free_models) && cloud.openrouter.free_models.length > 0) {
      pushItem(cloudItems, 'openrouter', `OpenRouter Free (${cloud.openrouter.free_models.length})`)
    }
    if (cloud.ollama_cloud?.configured && Array.isArray(cloud.ollama_cloud.models) && cloud.ollama_cloud.models.length > 0) {
      pushItem(cloudItems, 'ollama-cloud', `Ollama Cloud (${cloud.ollama_cloud.models.length})`)
    }
    if (cloud.opencode_free?.configured && Array.isArray(cloud.opencode_free.models) && cloud.opencode_free.models.length > 0) {
      pushItem(cloudItems, 'opencode-free', `OpenCode Free (${cloud.opencode_free.models.length})`)
    }
    if (cloud.openai?.configured) pushItem(cloudItems, 'openai', 'OpenAI API')
    if (cloud.anthropic?.configured) pushItem(cloudItems, 'anthropic', 'Anthropic API')
    if (cloudItems.length > 0) groups.push({ label: 'Cloud (Scrubbed IP/Secret)', items: cloudItems })
  }

  return groups
}

function getModelsForRoleProvider(modelsInfo, prov, activeModel) {
  const list = []
  const seen = new Set()
  const add = (value, label) => {
    if (!value || seen.has(value)) return
    seen.add(value)
    list.push({ value, label: label || value })
  }

  if (prov === 'ollama') {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (modelsInfo?.ollama?.models || [])) add(m, m)
    if (list.length === 0) add('gemma4:12b', 'gemma4:12b')
    return list
  }
  if (prov === 'gguf') {
    for (const g of (modelsInfo?.local_gguf?.models || [])) {
      if (g?.path) add(g.path, `${g.source === 'unsloth' ? 'Unsloth' : (g.source || 'GGUF')} · ${g.name}`)
    }
    if (activeModel) add(activeModel, activeModel)
    return list
  }
  const rt = modelsInfo?.local_runtimes?.[prov]
  if (rt) {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (rt.models || [])) add(m, m)
    return list
  }
  if (prov === 'openai-codex') {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (modelsInfo?.codex_oauth?.models || [])) add(m, m)
    return list
  }
  const cloud = modelsInfo?.cloud_providers || {}
  if (prov === 'openrouter') {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (cloud.openrouter?.free_models || [])) add(m, m)
    return list
  }
  if (prov === 'ollama-cloud') {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (cloud.ollama_cloud?.models || [])) add(m, m)
    return list
  }
  if (prov === 'opencode-free') {
    if (activeModel) add(activeModel, activeModel)
    for (const m of (cloud.opencode_free?.models || [])) add(m, m)
    return list
  }
  if (activeModel) add(activeModel, activeModel)
  return list
}

function CyberPurplePage({ ctx }) {
  const [status, setStatus] = useState(null)
  const [modelsInfo, setModelsInfo] = useState(null)
  const [scenarios, setScenarios] = useState([])
  const [selectedScenarioId, setSelectedScenarioId] = useState('')
  const [activeCase, setActiveCase] = useState(null)
  const [benchmarkReport, setBenchmarkReport] = useState(null)
  const [ackMissions, setAckMissions] = useState([])
  const [selectedAckMissionId, setSelectedAckMissionId] = useState('ack-m1-exploit-patch-bypass')
  const [ackDefenseMode, setAckDefenseMode] = useState('structural')
  const [ackReport, setAckReport] = useState(null)
  const [activeTab, setActiveTab] = useState('clash') // 'clash' | 'replay' | 'benchmark' | 'ack'
  const [highlightedEvId, setHighlightedEvId] = useState('')
  const [customTitle, setCustomTitle] = useState('Custom Security Log / Code')
  const [customContent, setCustomContent] = useState('')
  const [customKind, setCustomKind] = useState('auto')
  const [replayKeywordsInput, setReplayKeywordsInput] = useState('')
  const [replayExcludesInput, setReplayExcludesInput] = useState('')
  const [verifyMode, setVerifyMode] = useState('append_evidence')
  const [verifyContent, setVerifyContent] = useState('')
  const [busy, setBusy] = useState(false)
  const [loadError, setLoadError] = useState('')

  const evRefs = useRef({})

  const refreshAll = async (refreshCatalog = false) => {
    const [st, sc, md] = await Promise.all([
      ctx.rest('/status'),
      ctx.rest('/scenarios'),
      ctx.rest(`/models${refreshCatalog ? '?refresh=true' : ''}`)
    ])
    setStatus(st)
    const scList = Array.isArray(sc?.scenarios) ? sc.scenarios : []
    setScenarios(scList)
    if (!selectedScenarioId && scList.length > 0) setSelectedScenarioId(scList[0].scenario_id)
    setModelsInfo(md)
    if (st?.active_case) {
      setActiveCase(st.active_case)
      syncReplayInputsFromCase(st.active_case)
      setVerifyMode(defaultVerifyModeForCase(st.active_case))
    }
    if (st?.last_benchmark) setBenchmarkReport(st.last_benchmark)
    const missionsList = Array.isArray(st?.ack_missions) ? st.ack_missions : []
    setAckMissions(missionsList)
    if (missionsList.length > 0 && !missionsList.some((m) => m.mission_id === selectedAckMissionId)) {
      setSelectedAckMissionId(missionsList[0].mission_id)
    }
    if (st?.last_ack_report) setAckReport(st.last_ack_report)
  }

  const syncReplayInputsFromCase = (rep) => {
    const sigma = rep?.blue_report?.sigma_rule
    if (!sigma) return
    setReplayKeywordsInput((sigma.detection_keywords || []).join(', '))
    const flatExcl = Object.values(sigma.exclude_fields || {}).flat()
    setReplayExcludesInput(flatExcl.join(', '))
  }

  useEffect(() => {
    let active = true
    ;(async () => {
      try {
        await refreshAll(false)
      } catch (err) {
        if (active) setLoadError(err instanceof Error ? err.message : String(err))
      }
    })()
    return () => { active = false }
  }, [])

  const allowRemote = Boolean(status?.allow_remote ?? modelsInfo?.allow_remote)
  const redProvider = status?.red_provider || modelsInfo?.red_provider || 'ollama'
  const redModel = status?.red_model || modelsInfo?.red_model || 'gemma4:12b'
  const blueProvider = status?.blue_provider || modelsInfo?.blue_provider || 'ollama'
  const blueModel = status?.blue_model || modelsInfo?.blue_model || 'gemma4:12b'

  const providerGroups = useMemo(() => buildProviderGroups(modelsInfo, allowRemote), [modelsInfo, allowRemote])
  const redModelOptions = useMemo(() => getModelsForRoleProvider(modelsInfo, redProvider, redModel), [modelsInfo, redProvider, redModel])
  const blueModelOptions = useMemo(() => getModelsForRoleProvider(modelsInfo, blueProvider, blueModel), [modelsInfo, blueProvider, blueModel])

  const updateArenaConfig = async (patch) => {
    setBusy(true)
    try {
      const updated = await ctx.rest('/config', { method: 'POST', body: patch })
      setStatus(updated)
      const md = await ctx.rest(`/models${patch.allow_remote ? '?refresh=true' : ''}`)
      setModelsInfo(md)
    } catch (err) {
      host.notifyError(err, 'Errore configurazione Arena Multi-Modello')
    } finally {
      setBusy(false)
    }
  }

  const handleAnalyzeScenario = async () => {
    if (!selectedScenarioId || busy) return
    setBusy(true)
    try {
      const report = await ctx.rest('/analyze/scenario', {
        method: 'POST',
        body: { scenario_id: selectedScenarioId }
      })
      setActiveCase(report)
      syncReplayInputsFromCase(report)
      setVerifyMode(defaultVerifyModeForCase(report))
      setActiveTab('clash')
      setHighlightedEvId('')
      host.notify({ kind: 'info', message: `Verdetto Purple Team: ${report?.verdict?.verdict}` })
    } catch (err) {
      host.notifyError(err, 'Errore analisi scenario cyber')
    } finally {
      setBusy(false)
    }
  }

  const handleAnalyzeCustom = async () => {
    if (!customContent.trim() || busy) return
    setBusy(true)
    try {
      const report = await ctx.rest('/analyze/custom', {
        method: 'POST',
        body: { title: customTitle || 'Custom Security Artifact', content: customContent, source_kind: customKind }
      })
      setActiveCase(report)
      syncReplayInputsFromCase(report)
      setVerifyMode(defaultVerifyModeForCase(report))
      setActiveTab('clash')
      setHighlightedEvId('')
    } catch (err) {
      host.notifyError(err, 'Errore analisi artefatto custom')
    } finally {
      setBusy(false)
    }
  }

  const handleVerifyCaseUpdate = async () => {
    if (!activeCase?.case_id || !verifyContent.trim() || busy) return
    setBusy(true)
    try {
      const report = await ctx.rest('/verify', {
        method: 'POST',
        body: {
          case_id: activeCase.case_id,
          mode: verifyMode,
          content: verifyContent
        }
      })
      setActiveCase(report)
      syncReplayInputsFromCase(report)
      setVerifyContent('')
      setHighlightedEvId('')
      host.notify({
        kind: 'info',
        message: `Caso aggiornato (${report?.verdict?.remediation_verification?.status || report?.verdict?.verdict})`
      })
    } catch (err) {
      host.notifyError(err, 'Errore verifica / aggiornamento caso')
    } finally {
      setBusy(false)
    }
  }

  const handleRerunReplay = async () => {
    if (!activeCase?.case_id || busy) return
    setBusy(true)
    try {
      const keywords = replayKeywordsInput.split(',').map((s) => s.trim()).filter(Boolean)
      const excludes = replayExcludesInput.split(',').map((s) => s.trim()).filter(Boolean)
      const nextReplay = await ctx.rest('/replay', {
        method: 'POST',
        body: { case_id: activeCase.case_id, detection_keywords: keywords, exclude_values: excludes }
      })
      setActiveCase((prev) => prev ? { ...prev, verdict: { ...prev.verdict, replay: nextReplay } } : prev)
    } catch (err) {
      host.notifyError(err, 'Errore riesecuzione Purple Replay')
    } finally {
      setBusy(false)
    }
  }

  const handleRunBenchmark = async () => {
    if (busy) return
    setBusy(true)
    try {
      const bench = await ctx.rest('/benchmark', { method: 'POST', body: {} })
      setBenchmarkReport(bench)
      setActiveTab('benchmark')
    } catch (err) {
      host.notifyError(err, 'Errore benchmark Purple Suite')
    } finally {
      setBusy(false)
    }
  }

  const handleRunAckMission = async () => {
    if (!selectedAckMissionId || busy) return
    setBusy(true)
    try {
      const rep = await ctx.rest('/ack/run', {
        method: 'POST',
        body: {
          mission_id: selectedAckMissionId,
          mutation_rounds: 3,
          defense_mode: ackDefenseMode
        }
      })
      setAckReport(rep)
      setActiveTab('ack')
      host.notify({
        kind: rep?.certified ? 'info' : 'warning',
        message: `ACK ${rep?.mission_id}: ${rep?.certification_verdict}`
      })
    } catch (err) {
      host.notifyError(err, 'Errore esecuzione missione ACK')
    } finally {
      setBusy(false)
    }
  }

  const jumpToEvidence = (eid) => {
    setHighlightedEvId(eid)
    const node = evRefs.current[eid]
    if (node && typeof node.scrollIntoView === 'function') {
      node.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }

  const renderCitePills = (ids) => (ids || []).map((eid) => jsx('button', {
    type: 'button',
    className: 'cp-cite-btn',
    onClick: () => jumpToEvidence(eid),
    children: eid
  }, eid))

  const verdict = activeCase?.verdict
  const diagnosis = verdict?.diagnosis
  const simulation = verdict?.simulation
  const remediation = verdict?.remediation_verification
  const red = activeCase?.red_report
  const blue = activeCase?.blue_report
  const claims = Array.isArray(red?.claims) ? red.claims : []
  const evidences = activeCase?.ingestion?.evidences || []

  return jsxs('div', {
    className: 'cp-shell',
    children: [
      jsx('style', { children: CSS }),
      jsxs('div', {
        className: 'cp-header',
        children: [
          jsxs('div', {
            className: 'cp-title-row',
            children: [
              jsx('div', { className: 'cp-logo', children: jsx(Codicon, { name: 'shield', size: '1rem' }) }),
              jsxs('div', {
                children: [
                  jsx('div', { style: { fontWeight: 700, fontSize: '14px' }, children: 'NOEMETRA Cyber Purple Suite' }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--muted-foreground, #94a3b8)' },
                    children: 'Red Operator (Kill-Chain & Probes) vs Blue Critic (Contraddizioni, Sigma, YARA) + Purple Replay'
                  })
                ]
              }),
              jsx('span', {
                className: allowRemote ? 'cp-badge cp-b-amber' : 'cp-badge cp-b-green',
                children: allowRemote ? 'Cloud Autorizzato (Scrubber IP/Secret)' : 'Solo Locale (Air-Gapped)'
              })
            ]
          }),
          jsxs('div', {
            style: { display: 'flex', gap: '8px', alignItems: 'center' },
            children: [
              jsxs('button', {
                type: 'button',
                className: 'cp-btn cp-btn-primary',
                disabled: busy,
                onClick: handleRunBenchmark,
                children: [jsx(Codicon, { name: 'beaker', size: '0.9rem' }), 'Benchmark Single vs Purple']
              })
            ]
          })
        ]
      }),
      jsxs('div', {
        className: 'cp-arena-bar',
        children: [
          jsxs('label', {
            style: { display: 'inline-flex', alignItems: 'center', gap: '5px', cursor: 'pointer' },
            children: [
              jsx('input', {
                type: 'checkbox',
                checked: allowRemote,
                onChange: (e) => updateArenaConfig({ allow_remote: e.target.checked })
              }),
              'Abilita Modelli Cloud (con Scrubber)'
            ]
          }),
          jsxs('label', {
            style: { display: 'inline-flex', alignItems: 'center', gap: '5px', cursor: 'pointer' },
            children: [
              jsx('input', {
                type: 'checkbox',
                checked: Boolean(status?.use_llm),
                onChange: (e) => updateArenaConfig({ use_llm: e.target.checked })
              }),
              'Arricchimento LLM'
            ]
          }),
          jsxs('div', {
            className: 'cp-role-box red',
            children: [
              jsx('span', { className: 'cp-badge cp-b-red', children: 'RED' }),
              jsxs('select', {
                className: 'cp-select',
                'aria-label': 'Provider Red',
                value: redProvider,
                onChange: (e) => {
                  const nextProv = e.target.value
                  const firstMod = getModelsForRoleProvider(modelsInfo, nextProv, '')[0]?.value
                  updateArenaConfig({ red_provider: nextProv, ...(firstMod ? { red_model: firstMod } : {}) })
                },
                children: providerGroups.map((grp) => jsxs('optgroup', {
                  label: grp.label,
                  children: grp.items.map((it) => jsx('option', { value: it.value, children: it.label }, it.value))
                }, grp.label))
              }),
              jsxs('select', {
                className: 'cp-select',
                'aria-label': 'Modello Red',
                value: redModel,
                onChange: (e) => updateArenaConfig({ red_provider: redProvider, red_model: e.target.value }),
                children: redModelOptions.map((m) => jsx('option', { value: m.value, children: m.label }, m.value))
              })
            ]
          }),
          jsxs('div', {
            className: 'cp-role-box blue',
            children: [
              jsx('span', { className: 'cp-badge cp-b-blue', children: 'BLUE' }),
              jsxs('select', {
                className: 'cp-select',
                'aria-label': 'Provider Blue',
                value: blueProvider,
                onChange: (e) => {
                  const nextProv = e.target.value
                  const firstMod = getModelsForRoleProvider(modelsInfo, nextProv, '')[0]?.value
                  updateArenaConfig({ blue_provider: nextProv, ...(firstMod ? { blue_model: firstMod } : {}) })
                },
                children: providerGroups.map((grp) => jsxs('optgroup', {
                  label: grp.label,
                  children: grp.items.map((it) => jsx('option', { value: it.value, children: it.label }, it.value))
                }, grp.label))
              }),
              jsxs('select', {
                className: 'cp-select',
                'aria-label': 'Modello Blue',
                value: blueModel,
                onChange: (e) => updateArenaConfig({ blue_provider: blueProvider, blue_model: e.target.value }),
                children: blueModelOptions.map((m) => jsx('option', { value: m.value, children: m.label }, m.value))
              })
            ]
          })
        ]
      }),
      loadError ? jsx('div', { className: 'cp-card cp-card-red', style: { margin: '12px' }, children: loadError }) : null,
      jsxs('div', {
        className: 'cp-main',
        children: [
          jsxs('div', {
            className: 'cp-col cp-col-left',
            children: [
              jsxs('div', {
                className: 'cp-card',
                children: [
                  jsx('div', { style: { fontWeight: 700, fontSize: '12px', marginBottom: '6px' }, children: 'Scenari Dialettici Cyber' }),
                  jsxs('div', {
                    style: { display: 'flex', gap: '6px' },
                    children: [
                      jsxs('select', {
                        className: 'cp-select',
                        'aria-label': 'Scenario Cyber',
                        style: { flex: 1 },
                        value: selectedScenarioId,
                        onChange: (e) => setSelectedScenarioId(e.target.value),
                        children: scenarios.map((s) => jsx('option', {
                          value: s.scenario_id,
                          children: `${s.title}`
                        }, s.scenario_id))
                      }),
                      jsx('button', {
                        type: 'button',
                        className: 'cp-btn cp-btn-primary',
                        disabled: busy || !selectedScenarioId,
                        onClick: handleAnalyzeScenario,
                        children: 'Analizza'
                      })
                    ]
                  })
                ]
              }),
              jsxs('div', {
                className: 'cp-card',
                children: [
                  jsx('div', { style: { fontWeight: 700, fontSize: '12px', marginBottom: '6px' }, children: 'Ingestione Artefatto Custom (Read-Only)' }),
                  jsx('input', {
                    className: 'cp-input',
                    style: { width: '100%', marginBottom: '6px' },
                    value: customTitle,
                    onChange: (e) => setCustomTitle(e.target.value),
                    placeholder: 'Titolo caso'
                  }),
                  jsxs('select', {
                    className: 'cp-select',
                    style: { width: '100%', marginBottom: '6px' },
                    value: customKind,
                    onChange: (e) => setCustomKind(e.target.value),
                    children: [
                      jsx('option', { value: 'auto', children: 'Tipo: Auto-detect' }),
                      jsx('option', { value: 'log', children: 'Tipo: Log (JSONL / Syslog / Auth)' }),
                      jsx('option', { value: 'code', children: 'Tipo: Codice Sorgente' }),
                      jsx('option', { value: 'config', children: 'Tipo: IaC / Config (YAML / K8s)' }),
                      jsx('option', { value: 'http', children: 'Tipo: Traccia HTTP / WAF' })
                    ]
                  }),
                  jsx('textarea', {
                    className: 'cp-textarea',
                    rows: 4,
                    style: { width: '100%', marginBottom: '6px' },
                    placeholder: 'Incolla log di sicurezza, codice sorgente o manifest IaC...',
                    value: customContent,
                    onChange: (e) => setCustomContent(e.target.value)
                  }),
                  jsx('button', {
                    type: 'button',
                    className: 'cp-btn',
                    style: { width: '100%', justifyContent: 'center' },
                    disabled: busy || !customContent.trim(),
                    onClick: handleAnalyzeCustom,
                    children: 'Avvia Audit Purple su Artefatto'
                  })
                ]
              }),
              jsxs('div', {
                style: { flex: 1 },
                children: [
                  jsx('div', {
                    style: { fontWeight: 700, fontSize: '12px', marginBottom: '8px' },
                    children: `Evidenze Verbatim (${evidences.length})`
                  }),
                  evidences.length === 0
                    ? jsx('div', { style: { fontSize: '12px', color: 'var(--muted-foreground, #94a3b8)' }, children: 'Nessuna evidenza caricata.' })
                    : evidences.map((ev) => jsxs('div', {
                      ref: (el) => { evRefs.current[ev.evidence_id] = el },
                      className: `cp-ev${highlightedEvId === ev.evidence_id ? ' cp-ev-active' : ''}`,
                      children: [
                        jsxs('div', {
                          style: { display: 'flex', gap: '5px', alignItems: 'center', marginBottom: '4px' },
                          children: [
                            jsx('span', { className: 'cp-badge cp-b-purple', children: ev.evidence_id }),
                            jsx('span', { className: 'cp-badge cp-b-blue', children: ev.source_type }),
                            ev.is_benign_baseline ? jsx('span', { className: 'cp-badge cp-b-green', children: 'BASELINE' }) : null
                          ]
                        }),
                        jsx('div', { children: ev.raw_content })
                      ]
                    }, ev.evidence_id))
                ]
              })
            ]
          }),
          jsxs('div', {
            className: 'cp-col',
            children: [
              jsxs('div', {
                className: 'cp-tabs',
                children: [
                  jsx('button', {
                    type: 'button',
                    className: `cp-tab${activeTab === 'clash' ? ' active' : ''}`,
                    onClick: () => setActiveTab('clash'),
                    children: 'Scontro Red vs Blue & Verdetto'
                  }),
                  jsx('button', {
                    type: 'button',
                    className: `cp-tab${activeTab === 'replay' ? ' active' : ''}`,
                    onClick: () => setActiveTab('replay'),
                    children: 'Purple Replay & Sigma/YARA Lab'
                  }),
                  jsx('button', {
                    type: 'button',
                    className: `cp-tab${activeTab === 'benchmark' ? ' active' : ''}`,
                    onClick: () => setActiveTab('benchmark'),
                    children: 'Benchmark Comparativo'
                  }),
                  jsx('button', {
                    type: 'button',
                    className: `cp-tab${activeTab === 'ack' ? ' active' : ''}`,
                    onClick: () => setActiveTab('ack'),
                    children: 'ACK Detonation Arena (4 Missioni)'
                  })
                ]
              }),
              activeTab === 'ack'
                ? jsxs('div', {
                  style: { display: 'flex', flexDirection: 'column', gap: '12px' },
                  children: [
                    jsxs('div', {
                      className: 'cp-card cp-card-purple',
                      children: [
                        jsx('div', { style: { fontWeight: 700, fontSize: '13.5px', marginBottom: '6px' }, children: 'NOEMETRA Adversarial Cyber Kernel (ACK) — CoW Detonation Chamber & Out-of-Band Oracle' }),
                        jsx('div', { style: { fontSize: '12px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '10px' }, children: 'Separazione Control/Detonation Plane, osservabilità out-of-band, Fog of War asimmetrico e cambio forzato di classe offensiva su 4 missioni cyber pure.' }),
                        jsxs('div', {
                          style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' },
                          children: [
                            jsxs('select', {
                              className: 'cp-select',
                              'aria-label': 'Missione ACK',
                              style: { flex: 1, minWidth: '240px' },
                              value: selectedAckMissionId,
                              onChange: (e) => setSelectedAckMissionId(e.target.value),
                              children: (ackMissions.length > 0 ? ackMissions : [
                                { mission_id: 'ack-m1-exploit-patch-bypass', title: '1. Exploit-to-Patch & Bypass Loop' },
                                { mission_id: 'ack-m2-detection-evasion-arena', title: '2. Detection vs. Evasion Arena' },
                                { mission_id: 'ack-m3-attack-path-hardening', title: '3. Attack-Path Audit & Live Hardening' },
                                { mission_id: 'ack-m4-fuzz-to-fix-pipeline', title: '4. Fuzz-to-Fix Pipeline' }
                              ]).map((m) => jsx('option', { value: m.mission_id, children: m.title }, m.mission_id))
                            }),
                            jsxs('select', {
                              className: 'cp-select',
                              'aria-label': 'Modalita Difesa ACK',
                              value: ackDefenseMode,
                              onChange: (e) => setAckDefenseMode(e.target.value),
                              children: [
                                jsx('option', { value: 'structural', children: 'Difesa: Structural + Containment (Reale)' }),
                                jsx('option', { value: 'naive_string_replace', children: 'Anti-Cheat Test: Naive String Replace' }),
                                jsx('option', { value: 'naive_block_all', children: 'Anti-Cheat Test: Naive Block-All' }),
                                jsx('option', { value: 'overbroad_alert_all', children: 'Anti-Cheat Test: Overbroad Alert-All' })
                              ]
                            }),
                            jsx('button', {
                              type: 'button',
                              className: 'cp-btn cp-btn-primary',
                              disabled: busy,
                              onClick: handleRunAckMission,
                              children: 'Avvia Missione ACK in Detonation Chamber'
                            })
                          ]
                        })
                      ]
                    }),
                    ackReport
                      ? jsxs('div', {
                        style: { display: 'flex', flexDirection: 'column', gap: '12px' },
                        children: [
                          jsxs('div', {
                            className: 'cp-card',
                            children: [
                              jsxs('div', {
                                style: { display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '6px' },
                                children: [
                                  jsx('span', { className: ackReport.certified ? 'cp-badge cp-b-green' : 'cp-badge cp-b-red', children: ackReport.certified ? 'CERTIFIED' : 'REJECTED' }),
                                  jsx('span', { className: 'cp-badge cp-b-purple', children: ackReport.certification_verdict }),
                                  jsx('span', { className: 'cp-badge cp-b-blue', children: `Sandbox: ${ackReport.sandbox_id}` }),
                                  ackReport.isolation_backend ? jsx('span', { className: 'cp-badge cp-b-purple', children: ackReport.isolation_backend }) : null,
                                  ackReport.audit_scope ? jsx('span', { className: ackReport.audit_scope === 'cloned_target_manifest' ? 'cp-badge cp-b-green' : 'cp-badge cp-b-amber', children: ackReport.audit_scope }) : null,
                                  ackReport.fog_of_war?.enforced ? jsx('span', { className: 'cp-badge cp-b-green', children: 'Fog of War Enforced' }) : null,
                                  ackReport.shadow_clone_only ? jsx('span', { className: 'cp-badge cp-b-amber', children: 'Shadow Clone CoW' }) : null
                                ]
                              }),
                              jsx('div', { style: { fontWeight: 700, fontSize: '13.5px', marginBottom: '4px' }, children: ackReport.title }),
                              jsx('div', { style: { fontSize: '12px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '6px' }, children: `Invariante: ${ackReport.target_invariant} | Blue: ${ackReport.blue_patch_or_rules_summary}` }),
                              jsxs('div', {
                                style: { display: 'flex', gap: '8px', flexWrap: 'wrap' },
                                children: [
                                  jsx('span', { className: 'cp-badge cp-b-green', children: `TPR: ${Math.round((ackReport.tpr_fpr_matrix?.true_positive_rate || 0) * 100)}%` }),
                                  jsx('span', { className: (ackReport.tpr_fpr_matrix?.false_positive_rate || 0) <= 0.05 ? 'cp-badge cp-b-green' : 'cp-badge cp-b-red', children: `FPR: ${Math.round((ackReport.tpr_fpr_matrix?.false_positive_rate || 0) * 100)}%` }),
                                  jsx('span', { className: 'cp-badge cp-b-blue', children: `Evasion Resistance: ${Math.round((ackReport.tpr_fpr_matrix?.evasion_resistance_rate || 0) * 100)}%` }),
                                  jsx('span', { className: 'cp-badge cp-b-purple', children: `Functional Survival: ${Math.round((ackReport.tpr_fpr_matrix?.functional_survival_rate || 0) * 100)}%` }),
                                  jsx('span', { className: 'cp-badge cp-b-amber', children: `Post-Patch Breaches: ${ackReport.tpr_fpr_matrix?.post_patch_breaches ?? 0}` })
                                ]
                              })
                            ]
                          }),
                          jsxs('div', {
                            className: 'cp-card',
                            children: [
                              jsx('div', { style: { fontWeight: 700, fontSize: '12.5px', marginBottom: '6px' }, children: `Macchina a 7 Stati ACK (${(ackReport.state_transitions || []).length} transizioni)` }),
                              (ackReport.state_transitions || []).map((st, idx) => jsxs('div', {
                                className: 'cp-ev',
                                children: [
                                  jsx('span', { className: st.passed ? 'cp-badge cp-b-green' : 'cp-badge cp-b-red', children: st.state }),
                                  ' ',
                                  jsx('span', { className: 'cp-badge cp-b-purple', children: st.actor }),
                                  ' ',
                                  jsx('span', { children: st.summary })
                                ]
                              }, `${st.state}-${idx}`))
                            ]
                          }),
                          jsxs('div', {
                            className: 'cp-card cp-card-red',
                            children: [
                              jsx('div', { style: { fontWeight: 700, fontSize: '12.5px', marginBottom: '6px' }, children: `Round di Mutazione Red & Oracolo Out-of-Band (${(ackReport.mutation_rounds || []).length} classi distinte)` }),
                              (ackReport.mutation_rounds || []).length === 0
                                ? jsx('div', { style: { fontSize: '12px', color: 'var(--muted-foreground, #94a3b8)' }, children: 'Mutazioni non eseguite: difesa respinta dall’oracolo funzionale/FPR prima del ciclo di bypass.' })
                                : (ackReport.mutation_rounds || []).map((mr) => jsxs('div', {
                                  className: `cp-claim-card ${mr.bypass_succeeded ? 'supported' : 'refuted'}`,
                                  children: [
                                    jsxs('div', {
                                      style: { display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '4px' },
                                      children: [
                                        jsx('strong', { children: `Round ${mr.round_index}` }),
                                        jsx('span', { className: 'cp-badge cp-b-red', children: mr.attack_class }),
                                        jsx('span', { className: mr.bypass_succeeded ? 'cp-badge cp-b-red' : 'cp-badge cp-b-green', children: mr.oracle_evidence?.oracle_verdict }),
                                        jsx('span', { className: 'cp-badge cp-b-blue', children: `canary_accessed=${String(mr.oracle_evidence?.fs_diff?.canary_accessed)}` }),
                                        jsx('span', { className: 'cp-badge cp-b-purple', children: `lowerdir_untouched=${String(mr.oracle_evidence?.fs_diff?.lowerdir_untouched)}` })
                                      ]
                                    }),
                                    jsx('div', { style: { fontSize: '11.5px', color: 'var(--muted-foreground, #cbd5e1)' }, children: `Contract ${mr.contract?.action_id} [${mr.contract?.primitive}] -> ${mr.contract?.artifact_path} | Classi fallite in memoria: ${(mr.previous_failed_classes || []).join(', ') || 'Nessuna'}` })
                                  ]
                                }, mr.round_index))
                            ]
                          })
                        ]
                      })
                      : jsx('div', { className: 'cp-card', children: 'Seleziona una delle 4 missioni ACK e clicca "Avvia Missione ACK in Detonation Chamber" per eseguire test CoW reali e certificazione out-of-band.' })
                  ]
                })
                : activeTab === 'benchmark' && benchmarkReport
                ? jsxs('div', {
                  className: 'cp-card cp-card-purple',
                  children: [
                    jsx('h3', { style: { marginTop: 0 }, children: `Benchmark Comparativo Single-Agent vs Multi-Agent Purple (${benchmarkReport.total_scenarios} Scenari)` }),
                    jsxs('div', {
                      style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' },
                      children: [
                        jsx('span', { className: 'cp-badge cp-b-red', children: `Single-Agent Accuracy: ${Math.round(benchmarkReport.single_agent_accuracy * 100)}% (FPR: ${Math.round(benchmarkReport.single_agent_fpr * 100)}%)` }),
                        jsx('span', { className: 'cp-badge cp-b-green', children: `Purple Multi-Agent Accuracy: ${Math.round(benchmarkReport.purple_multi_agent_accuracy * 100)}% (FPR: ${Math.round(benchmarkReport.purple_fpr * 100)}%)` }),
                        jsx('span', { className: 'cp-badge cp-b-purple', children: `Astensione Ambigui: ${Math.round(benchmarkReport.abstention_accuracy * 100)}%` }),
                        jsx('span', { className: 'cp-badge cp-b-blue', children: `Avg Detection Coverage: ${Math.round(benchmarkReport.avg_detection_coverage * 100)}%` })
                      ]
                    }),
                    benchmarkReport.results.map((r) => jsxs('div', {
                      className: 'cp-ev',
                      children: [
                        jsx('strong', { children: r.title }),
                        jsx('div', {
                          children: `Atteso: ${r.expected_verdict} | Single-Agent: ${r.single_agent_verdict} | Multi-Agent Purple: ${r.purple_multi_agent_verdict} | Contraddizioni: ${r.contradictions_found}`
                        })
                      ]
                    }, r.scenario_id))
                  ]
                })
                : !activeCase
                  ? jsx('div', {
                    className: 'cp-card',
                    children: 'Seleziona uno scenario dalla colonna di sinistra o incolla log/codice/YAML per avviare Red Operator, Blue Critic e Purple Replay.'
                  })
                  : activeTab === 'replay'
                    ? jsxs('div', {
                      className: 'cp-card cp-card-purple',
                      children: [
                        jsx('h3', { style: { marginTop: 0 }, children: 'Purple Replay — Sigma & YARA Tuning Interattivo' }),
                        jsxs('div', {
                          style: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' },
                          children: [
                            jsx('span', { className: 'cp-badge cp-b-blue', children: `Detection Coverage: ${Math.round((verdict?.replay?.detection_coverage || 0) * 100)}% (${verdict?.replay?.attack_events_detected}/${verdict?.replay?.attack_events_total})` }),
                            jsx('span', { className: 'cp-badge cp-b-purple', children: `Evasion Caught: ${Math.round((verdict?.replay?.evasion_caught_rate || 0) * 100)}%` }),
                            jsx('span', { className: 'cp-badge cp-b-green', children: `Baseline FPR: ${Math.round((verdict?.replay?.false_positive_rate || 0) * 100)}% (${verdict?.replay?.false_positives_count}/${verdict?.replay?.benign_events_tested})` })
                          ]
                        }),
                        jsx('label', { style: { fontSize: '11.5px', fontWeight: 600 }, children: 'Sigma Detection Keywords (separate da virgola):' }),
                        jsx('input', {
                          className: 'cp-input',
                          'aria-label': 'Sigma detection keywords',
                          style: { width: '100%', margin: '4px 0 8px' },
                          value: replayKeywordsInput,
                          onChange: (e) => setReplayKeywordsInput(e.target.value)
                        }),
                        jsx('label', { style: { fontSize: '11.5px', fontWeight: 600 }, children: 'Exclusion Filters (anti-falsi positivi):' }),
                        jsx('input', {
                          className: 'cp-input',
                          'aria-label': 'Sigma exclusions',
                          style: { width: '100%', margin: '4px 0 10px' },
                          value: replayExcludesInput,
                          onChange: (e) => setReplayExcludesInput(e.target.value)
                        }),
                        jsx('button', {
                          type: 'button',
                          className: 'cp-btn cp-btn-primary',
                          disabled: busy,
                          onClick: handleRerunReplay,
                          children: 'Riesegui Purple Replay'
                        }),
                        jsx('div', {
                          style: { marginTop: '12px' },
                          children: (verdict?.replay?.event_results || []).map((er) => jsxs('div', {
                            className: 'cp-ev',
                            children: [
                              jsx('span', { className: er.variant === 'benign_baseline' ? 'cp-badge cp-b-green' : 'cp-badge cp-b-red', children: er.event_id }),
                              jsx('span', { className: 'cp-badge cp-b-blue', children: er.variant }),
                              jsx('span', { children: `Sigma=${er.matched_sigma ? 'MATCH' : 'MISS'} | YARA=${er.matched_yara ? 'MATCH' : 'MISS'}` })
                            ]
                          }, `${er.event_id}-${er.variant}`))
                        })
                      ]
                    })
                    : jsxs('div', {
                      style: { display: 'flex', flexDirection: 'column', gap: '12px' },
                      children: [
                        jsxs('div', {
                          className: 'cp-card cp-card-purple',
                          children: [
                            jsxs('div', {
                              style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '6px' },
                              children: [
                                jsx('span', { className: verdictBadgeClass(verdict.verdict), children: verdict.verdict }),
                                jsx('span', { className: 'cp-badge cp-b-purple', children: `Confidence: ${Math.round(verdict.confidence_score * 100)}%` }),
                                jsx('span', { className: 'cp-badge cp-b-blue', children: `Replay Coverage: ${Math.round((verdict.replay?.detection_coverage || 0) * 100)}%` }),
                                jsx('span', { className: 'cp-badge cp-b-green', children: `Support A=${verdict.hypothesis_a_support} vs B=${verdict.hypothesis_b_support}` }),
                                activeCase.privacy_scrubbed ? jsx('span', { className: 'cp-badge cp-b-amber', children: 'Privacy Scrubbed' }) : null,
                                verdict.incoherent_contradictions_rejected?.length > 0 ? jsx('span', { className: 'cp-badge cp-b-amber', children: `Contraddizioni incoerenti scartate: ${verdict.incoherent_contradictions_rejected.length}` }) : null
                              ]
                            }),
                            jsx('div', { style: { fontWeight: 700, fontSize: '14px', marginBottom: '4px' }, children: verdict.winning_hypothesis }),
                            jsx('div', { style: { fontSize: '12.5px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '8px' }, children: verdict.rationale }),
                            jsxs('div', {
                              style: { fontSize: '12px', padding: '8px 10px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.12)', border: '1px solid rgba(168, 85, 247, 0.35)' },
                              children: [
                                jsx('strong', { children: 'Test Discriminante: ' }),
                                jsx('code', { children: verdict.discriminating_test })
                              ]
                            })
                          ]
                        }),
                        jsxs('div', {
                          className: 'cp-stage-grid',
                          children: [
                            jsxs('div', {
                              className: 'cp-card',
                              children: [
                                jsxs('div', {
                                  style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px', marginBottom: '6px', flexWrap: 'wrap' },
                                  children: [
                                    jsx('strong', { style: { fontSize: '12.5px' }, children: '1. Diagnosi' }),
                                    jsx('span', { className: stageBadgeClass('diagnosis', diagnosis?.status), children: diagnosis?.status || 'N/A' })
                                  ]
                                }),
                                diagnosis?.analysis_mode_label ? jsx('div', {
                                  style: { marginBottom: '4px' },
                                  children: jsx('span', { className: 'cp-badge cp-b-blue', children: diagnosis.analysis_mode_label })
                                }) : null,
                                jsx('div', {
                                  style: { fontSize: '11.5px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '4px' },
                                  children: `Affermazioni: Supportate ${diagnosis?.supported_claims_count ?? 0} · Aperte ${diagnosis?.open_claims_count ?? 0} · Confutate ${diagnosis?.refuted_claims_count ?? 0}`
                                }),
                                diagnosis?.high_priority_open_claim_ids?.length > 0 ? jsx('div', {
                                  style: { fontSize: '11.5px', color: '#fcd34d', marginBottom: '4px' },
                                  children: `Dubbi prioritari aperti: ${diagnosis.high_priority_open_claim_ids.join(', ')}`
                                }) : null,
                                jsx('div', { style: { fontSize: '11.5px', color: 'var(--muted-foreground, #94a3b8)' }, children: diagnosis?.epistemic_scope || diagnosis?.summary || '' })
                              ]
                            }),
                            jsxs('div', {
                              className: 'cp-card',
                              children: [
                                jsxs('div', {
                                  style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px', marginBottom: '6px', flexWrap: 'wrap' },
                                  children: [
                                    jsx('strong', { style: { fontSize: '12.5px' }, children: '2. Simulazione Rilevazione' }),
                                    jsx('span', { className: stageBadgeClass('simulation', simulation?.status), children: simulation?.status || 'NOT_APPLICABLE' })
                                  ]
                                }),
                                jsx('div', {
                                  style: { fontSize: '11.5px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '4px' },
                                  children: `Coverage: ${Math.round((simulation?.detection_coverage ?? verdict?.replay?.detection_coverage ?? 0) * 100)}% | Evasion: ${Math.round((simulation?.evasion_caught_rate ?? verdict?.replay?.evasion_caught_rate ?? 0) * 100)}% | FPR Baseline: ${Math.round((simulation?.false_positive_rate ?? verdict?.replay?.false_positive_rate ?? 0) * 100)}%`
                                }),
                                jsx('div', { style: { fontSize: '11.5px', color: 'var(--muted-foreground, #94a3b8)' }, children: simulation?.summary || '' })
                              ]
                            }),
                            jsxs('div', {
                              className: 'cp-card',
                              children: [
                                jsxs('div', {
                                  style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px', marginBottom: '6px', flexWrap: 'wrap' },
                                  children: [
                                    jsx('strong', { style: { fontSize: '12.5px' }, children: '3. Verifica della Correzione' }),
                                    jsx('span', { className: stageBadgeClass('remediation', remediation?.status), children: remediation?.status || 'UNVERIFIED' })
                                  ]
                                }),
                                remediation?.verification_level && remediation.verification_level !== 'not_run' ? jsx('div', {
                                  style: { marginBottom: '4px' },
                                  children: jsx('span', {
                                    className: 'cp-badge cp-b-purple',
                                    children: remediation.verification_level === 'static_artifact_comparison' ? 'Controllo Statico Artefatto' : 'Rivalutazione Evidenze Incrementali'
                                  })
                                }) : null,
                                remediation?.before_verdict && remediation?.after_verdict ? jsx('div', {
                                  style: { fontSize: '11.5px', color: 'var(--muted-foreground, #cbd5e1)', marginBottom: '4px' },
                                  children: `Verdetto: ${remediation.before_verdict} -> ${remediation.after_verdict}`
                                }) : null,
                                jsx('div', { style: { fontSize: '11.5px', color: 'var(--muted-foreground, #94a3b8)' }, children: remediation?.summary || '' }),
                                remediation?.operational_caveat ? jsx('div', { className: 'cp-note-box', children: remediation.operational_caveat }) : null
                              ]
                            })
                          ]
                        }),
                        jsxs('div', {
                          className: 'cp-card cp-card-purple',
                          children: [
                            jsx('div', { style: { fontWeight: 700, fontSize: '13px', marginBottom: '8px' }, children: `Affermazioni Investigative — Osservato vs Ipotizzato (${claims.length})` }),
                            claims.length === 0
                              ? jsx('div', { style: { fontSize: '12px', color: 'var(--muted-foreground, #94a3b8)' }, children: 'Nessuna affermazione di minaccia aperta o supportata generata per questo artefatto.' })
                              : claims.map((clm) => {
                                const stInfo = claimStatusInfo(clm.status)
                                const prInfo = claimPriorityInfo(clm.priority)
                                const missingList = Array.isArray(clm.missing_conditions) ? clm.missing_conditions : []
                                return jsxs('div', {
                                  className: `cp-claim-card ${clm.status || 'open'}`,
                                  children: [
                                    jsxs('div', {
                                      style: { display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '6px' },
                                      children: [
                                        jsx('strong', { children: clm.claim_id }),
                                        jsx('span', { className: stInfo.cls, children: stInfo.label }),
                                        jsx('span', { className: prInfo.cls, children: prInfo.label }),
                                        clm.technique_id ? jsx('span', { className: 'cp-badge cp-b-blue', children: `${clm.tactic || 'MITRE'} (${clm.technique_id})` }) : null,
                                        jsxs('span', { children: renderCitePills(clm.evidence_ids) })
                                      ]
                                    }),
                                    jsxs('div', { style: { marginBottom: '3px' }, children: [jsx('strong', { children: 'Osservato: ' }), jsx('span', { children: clm.observed_fact })] }),
                                    jsxs('div', { style: { marginBottom: '3px', color: 'var(--muted-foreground, #cbd5e1)' }, children: [jsx('strong', { children: 'Ipotesi: ' }), jsx('span', { children: clm.proposed_interpretation })] }),
                                    jsxs('div', {
                                      style: { marginBottom: '3px', color: missingList.length ? '#fcd34d' : '#6ee7b7' },
                                      children: [
                                        jsx('strong', { children: 'Condizioni mancanti: ' }),
                                        jsx('span', { children: missingList.length ? missingList.join(' | ') : 'Nessuna (precondizioni soddisfatte nei record citati)' })
                                      ]
                                    }),
                                    jsxs('div', {
                                      style: { color: '#d8b4fe' },
                                      children: [jsx('strong', { children: 'Prossima prova: ' }), jsx('span', { children: clm.confirming_or_refuting_proof })]
                                    }),
                                    clm.priority_rationale ? jsx('div', { style: { fontSize: '11px', color: 'var(--muted-foreground, #94a3b8)', marginTop: '3px' }, children: `Triage: ${clm.priority_rationale}` }) : null
                                  ]
                                }, clm.claim_id)
                              })
                          ]
                        }),
                        jsxs('div', {
                          className: 'cp-card',
                          children: [
                            jsx('div', { style: { fontWeight: 700, fontSize: '12.5px', marginBottom: '6px' }, children: 'Continua Indagine / Verifica Versione Corretta' }),
                            jsxs('div', {
                              style: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '8px' },
                              children: [
                                jsxs('select', {
                                  className: 'cp-select',
                                  'aria-label': 'Modalita aggiornamento caso',
                                  value: verifyMode,
                                  onChange: (e) => setVerifyMode(e.target.value),
                                  children: [
                                    jsx('option', { value: 'append_evidence', children: 'Aggiungi Nuove Evidenze / Log (append_evidence)' }),
                                    jsx('option', { value: 'verify_patch', children: 'Verifica Artefatto / Codice Corretto (verify_patch)' })
                                  ]
                                }),
                                jsx('button', {
                                  type: 'button',
                                  className: 'cp-btn cp-btn-primary',
                                  disabled: busy || !verifyContent.trim(),
                                  onClick: handleVerifyCaseUpdate,
                                  children: verifyMode === 'verify_patch' ? 'Verifica Artefatto Corretto' : 'Rivaluta con Nuove Evidenze'
                                })
                              ]
                            }),
                            jsx('textarea', {
                              className: 'cp-textarea',
                              rows: 3,
                              style: { width: '100%' },
                              value: verifyContent,
                              onChange: (e) => setVerifyContent(e.target.value),
                              placeholder: verifyMode === 'verify_patch'
                                ? 'Incolla il codice/configurazione aggiornato per verificare quali superfici risultano mitigate...'
                                : 'Incolla ulteriori righe di log, eventi processo, VPN/Kerberos o metriche DNS TXT per chiudere le ipotesi aperte...'
                            })
                          ]
                        }),
                        jsxs('div', {
                          style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px' },
                          children: [
                            jsxs('div', {
                              className: 'cp-card cp-card-red',
                              children: [
                                jsx('div', { style: { fontWeight: 700, color: '#fda4af', marginBottom: '6px' }, children: `Red Operator (${red.model_used})` }),
                                jsx('div', { style: { fontSize: '12.5px', marginBottom: '8px' }, children: red.primary_hypothesis }),
                                red.kill_chain.map((step, i) => jsxs('div', {
                                  style: { marginBottom: '8px', fontSize: '12px' },
                                  children: [
                                    jsx('span', { className: 'cp-badge cp-b-red', children: step.technique_id }),
                                    ' ',
                                    jsx('strong', { children: `${step.tactic}: ${step.technique_name}` }),
                                    jsx('div', { style: { color: 'var(--muted-foreground, #cbd5e1)', margin: '2px 0' }, children: step.reachability_proof }),
                                    jsxs('div', { children: renderCitePills(step.evidence_ids) })
                                  ]
                                }, `${step.technique_id}-${i}`)),
                                jsx('div', { style: { fontWeight: 600, fontSize: '12px', marginTop: '8px' }, children: 'Red Team Safe-Audit Probes:' }),
                                red.probes.map((p) => jsx('pre', {
                                  className: 'cp-pre',
                                  children: `${p.probe_id} [${p.safety_level}] ${p.title}\nPayload: ${p.payload_or_command}\nExpected IOC: ${p.expected_ioc}`
                                }, p.probe_id))
                              ]
                            }),
                            jsxs('div', {
                              className: 'cp-card cp-card-blue',
                              children: [
                                jsx('div', { style: { fontWeight: 700, color: '#7dd3fc', marginBottom: '6px' }, children: `Blue Investigator & Critic (${blue.model_used})` }),
                                jsx('div', { style: { fontSize: '12.5px', marginBottom: '8px' }, children: blue.competing_hypothesis }),
                                blue.contradictions.map((c, idx) => jsxs('div', {
                                  style: { marginBottom: '8px', fontSize: '12px' },
                                  children: [
                                    jsx('span', { className: 'cp-badge cp-b-blue', children: c.impact_on_hypothesis }),
                                    ' ',
                                    c.target_claim_id ? jsx('span', { className: 'cp-badge cp-b-purple', children: c.target_claim_id }) : null,
                                    c.entity_coherent === false ? jsx('span', { className: 'cp-badge cp-b-amber', children: 'Rifiutata (Entita incoerenti)' }) : null,
                                    ' ',
                                    jsx('span', { children: c.explanation }),
                                    jsxs('div', { style: { marginTop: '3px' }, children: renderCitePills(c.contradicting_evidence_ids) })
                                  ]
                                }, idx)),
                                jsx('div', { style: { fontWeight: 600, fontSize: '12px', marginTop: '8px' }, children: 'Sigma Rule (YAML):' }),
                                jsx('pre', { className: 'cp-pre', children: blue.sigma_rule.yaml_text }),
                                jsx('div', { style: { fontWeight: 600, fontSize: '12px', marginTop: '8px' }, children: 'Remediation Patch:' }),
                                jsx('pre', { className: 'cp-pre', children: blue.remediation_patch })
                              ]
                            })
                          ]
                        })
                      ]
                    })
            ]
          })
        ]
      })
    ]
  })
}

export { CyberPurplePage }

export default {
  id: PLUGIN_ID,
  name: 'NOEMETRA Cyber',
  description: 'Suite Purple Team multi-agente avversaria: kill-chain Red Team, investigazione contraddizioni Blue, Sigma/YARA Replay e Arena multi-modello.',
  defaultEnabled: true,
  register(ctx) {
    ctx.register({
      id: 'page',
      area: ROUTES_AREA,
      data: { path: '/cyber-purple' },
      render: () => jsx(CyberPurplePage, { ctx })
    })

    ctx.register({
      id: 'nav',
      area: SIDEBAR_NAV_AREA,
      order: 48,
      data: {
        path: '/cyber-purple',
        label: 'NOEMETRA Cyber',
        codicon: 'shield'
      }
    })

    ctx.register({
      id: 'open-palette',
      area: PALETTE_AREA,
      data: {
        id: 'cyber-purple.open',
        label: 'Open NOEMETRA Cyber Purple Suite',
        keywords: ['cyber', 'security', 'red team', 'blue team', 'purple', 'sigma', 'yara', 'audit'],
        run: () => host.navigate('/cyber-purple')
      }
    })
  }
}
