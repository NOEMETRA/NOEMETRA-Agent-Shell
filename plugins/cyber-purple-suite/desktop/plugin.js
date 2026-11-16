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
  const [activeTab, setActiveTab] = useState('clash') // 'clash' | 'replay' | 'benchmark'
  const [highlightedEvId, setHighlightedEvId] = useState('')
  const [customTitle, setCustomTitle] = useState('Custom Security Log / Code')
  const [customContent, setCustomContent] = useState('')
  const [customKind, setCustomKind] = useState('auto')
  const [replayKeywordsInput, setReplayKeywordsInput] = useState('')
  const [replayExcludesInput, setReplayExcludesInput] = useState('')
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
    }
    if (st?.last_benchmark) setBenchmarkReport(st.last_benchmark)
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
      setActiveTab('clash')
      setHighlightedEvId('')
    } catch (err) {
      host.notifyError(err, 'Errore analisi artefatto custom')
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
  const red = activeCase?.red_report
  const blue = activeCase?.blue_report
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
                  })
                ]
              }),
              activeTab === 'benchmark' && benchmarkReport
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
                                activeCase.privacy_scrubbed ? jsx('span', { className: 'cp-badge cp-b-amber', children: 'Privacy Scrubbed' }) : null
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
