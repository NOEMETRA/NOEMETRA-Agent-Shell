import { fireEvent, render, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { discoverBundledPlugins } from '@/contrib/plugins'
import { $pluginDecisions, setPluginEnabled } from '@/contrib/plugins-store'
import { registry } from '@/contrib/registry'

vi.mock('@/contrib/runtime-loader', () => ({ watchRuntimePlugins: vi.fn() }))

describe('cyber-purple-suite desktop plugin', () => {
  afterEach(async () => {
    await setPluginEnabled('cyber-purple-suite', false)
    Reflect.deleteProperty(window, 'hermesDesktop')
    vi.restoreAllMocks()
  })

  it('supports Red vs Blue model arena switching, scenario analysis, clickable EV citations, and Purple Replay tuning', async () => {
    $pluginDecisions.set({ 'cyber-purple-suite': false, 'voice-document-assistant': false })
    discoverBundledPlugins()

    const mockReport = {
      case_id: 'case-1234',
      title: 'SQLi + SSRF Metadata Pivot + Privileged Container Chain',
      created_at: '2026-11-16T23:00:00Z',
      scenario_id: 'scen-03-sqli-ssrf-code-chain',
      privacy_scrubbed: false,
      scrub_stats: { private_ips: 0, secrets: 0, emails: 0 },
      ingestion: {
        case_id: 'case-1234',
        title: 'SQLi + SSRF',
        source_kind: 'code',
        sha256: 'abc123',
        total_records: 2,
        evidences: [
          {
            evidence_id: 'EV-0001',
            source_type: 'code',
            line_or_seq: 1,
            raw_content: 'query = f"SELECT * FROM reports WHERE tenant_id = {tenant_id}"',
            entities: { sinks: ['sql_concat'] },
            is_benign_baseline: false
          },
          {
            evidence_id: 'EV-0002',
            source_type: 'log',
            line_or_seq: 2,
            raw_content: '[BASELINE] GET /api/v1/health status=200 healthcheck=200 ok',
            entities: {},
            is_benign_baseline: true
          }
        ]
      },
      red_report: {
        primary_hypothesis: 'Exploitable Multi-Hop SQLi -> SSRF IMDS Chain',
        confidence: 0.92,
        kill_chain: [
          {
            tactic: 'Initial Access',
            technique_id: 'T1190',
            technique_name: 'SQLi -> SSRF Pivot',
            description: 'Unsanitized query string',
            evidence_ids: ['EV-0001'],
            reachability_proof: 'Externally reachable /api/v1/export feeds requests.get'
          }
        ],
        blind_spots: ['Regex misses octal IP aliases'],
        probes: [
          {
            probe_id: 'RED-PRB-01',
            title: 'Non-destructive SQLi + Loopback Check',
            target_surface: '/api/v1/export',
            method_or_vector: 'HTTP GET',
            payload_or_command: 'GET /api/v1/export?webhook_url=http://169.254.169.254/',
            expected_ioc: 'Metadata key returned',
            safety_level: 'safe-audit'
          }
        ],
        simulated_events: [],
        cited_evidence_ids: ['EV-0001'],
        model_used: 'deterministic'
      },
      blue_report: {
        competing_hypothesis: 'Alternative WAF check refuted',
        confidence: 0.22,
        contradictions: [
          {
            claim_challenged: 'Whether allowlist exists',
            contradicting_evidence_ids: ['EV-0001'],
            explanation: 'Zero allowlist present in export handler',
            impact_on_hypothesis: 'contextualizes'
          }
        ],
        sigma_rule: {
          title: 'SQLi + SSRF',
          id: 'sig-1',
          status: 'experimental',
          description: 'SSRF IMDS detection',
          logsource: { category: 'webserver', product: 'app_api' },
          detection_keywords: ['169.254.169.254', '0251.0376.0251.0376'],
          detection_fields: {},
          exclude_fields: { health: ['healthcheck=200 ok'] },
          level: 'critical',
          yaml_text: 'title: SQLi + SSRF\nlevel: critical'
        },
        yara_rule: {
          rule_name: 'Exploit_SQLi_SSRF',
          description: 'Matches metadata SSRF',
          strings: ['169.254.169.254'],
          condition: 'any of them',
          raw_rule: 'rule Exploit_SQLi_SSRF {}'
        },
        remediation_patch: '+ db.execute("SELECT ...", (tenant_id,))',
        hardening_steps: ['Parameterize SQL'],
        cited_evidence_ids: ['EV-0001'],
        model_used: 'deterministic'
      },
      verdict: {
        verdict: 'EXPLOITABLE_CHAIN',
        winning_hypothesis: 'Exploitable Multi-Hop SQLi -> SSRF IMDS Chain',
        confidence_score: 0.92,
        hypothesis_a_support: 0.92,
        hypothesis_b_support: 0.22,
        verified_citations: ['EV-0001'],
        hallucinated_citations_removed: [],
        discriminating_test: 'Run controlled probe on /api/v1/export and re-test after patch.',
        rationale: 'Multi-hop chain verified across code and trace.',
        replay: {
          attack_events_total: 2,
          attack_events_detected: 2,
          evasion_events_total: 1,
          evasion_events_detected: 1,
          benign_events_tested: 1,
          false_positives_count: 0,
          detection_coverage: 1.0,
          evasion_caught_rate: 1.0,
          false_positive_rate: 0.0,
          event_results: [
            { event_id: 'SIM-RED-01', variant: 'baseline_attack', matched_sigma: true, matched_yara: true, matched_keywords: ['169.254.169.254'] },
            { event_id: 'EV-0002', variant: 'benign_baseline', matched_sigma: false, matched_yara: false, matched_keywords: [] }
          ],
          defense_gaps: []
        }
      }
    }

    let arenaState = {
      status: 'ready',
      allow_remote: false,
      use_llm: false,
      red_provider: 'ollama',
      red_model: 'gemma4:12b',
      blue_provider: 'ollama',
      blue_model: 'gemma4:12b',
      active_case: null as typeof mockReport | null,
      last_benchmark: null
    }

    const calls: Array<{ path: string; method: string; body?: unknown }> = []
    const api = vi.fn(async (req: { path: string; method?: string; body?: unknown }) => {
      const method = req.method || 'GET'
      calls.push({ path: req.path, method, body: req.body })

      if (req.path === '/api/plugins/cyber-purple-suite/status') return { ...arenaState }
      if (req.path === '/api/plugins/cyber-purple-suite/scenarios') {
        return {
          scenarios: [
            {
              scenario_id: 'scen-03-sqli-ssrf-code-chain',
              title: 'SQLi + SSRF Metadata Pivot + Privileged Container Chain',
              category: 'Offensive Audit',
              description: 'Multi-hop chain',
              expected_verdict: 'EXPLOITABLE_CHAIN',
              is_ambiguous: false,
              source_kind: 'code'
            }
          ]
        }
      }
      if (req.path.startsWith('/api/plugins/cyber-purple-suite/models')) {
        return {
          allow_remote: arenaState.allow_remote,
          red_provider: arenaState.red_provider,
          red_model: arenaState.red_model,
          blue_provider: arenaState.blue_provider,
          blue_model: arenaState.blue_model,
          ollama: { status: 'online', models: ['gemma4:12b'] },
          local_runtimes: {},
          local_gguf: { models: [] },
          codex_oauth: { configured: true, models: ['gpt-6.1-sol'] },
          cloud_providers: {
            opencode_free: { configured: true, models: ['opencode/mimo-v2.6-flash-free'] }
          }
        }
      }
      if (req.path === '/api/plugins/cyber-purple-suite/config' && method === 'POST') {
        const b = req.body as Record<string, unknown>
        if (typeof b.allow_remote === 'boolean') arenaState.allow_remote = b.allow_remote
        if (typeof b.red_provider === 'string') arenaState.red_provider = b.red_provider
        if (typeof b.red_model === 'string') arenaState.red_model = b.red_model
        if (typeof b.blue_provider === 'string') arenaState.blue_provider = b.blue_provider
        if (typeof b.blue_model === 'string') arenaState.blue_model = b.blue_model
        return { ...arenaState }
      }
      if (req.path === '/api/plugins/cyber-purple-suite/analyze/scenario' && method === 'POST') {
        arenaState.active_case = mockReport
        return mockReport
      }
      if (req.path === '/api/plugins/cyber-purple-suite/replay' && method === 'POST') {
        return { ...mockReport.verdict.replay, detection_coverage: 1.0 }
      }
      return {}
    })

    Object.defineProperty(window, 'hermesDesktop', {
      configurable: true,
      value: { api }
    })

    await setPluginEnabled('cyber-purple-suite', true)
    const routeContrib = registry.getArea('routes').find(item => item.source === 'plugin:cyber-purple-suite')
    expect(routeContrib?.data).toMatchObject({ path: '/cyber-purple' })

    const view = render(routeContrib!.render!())
    await waitFor(() => expect(view.container.querySelector('select[aria-label="Scenario Cyber"]')?.textContent).toContain('SQLi + SSRF'))

    // Run scenario analysis
    const analyzeBtn = Array.from(view.container.querySelectorAll('button')).find(b => b.textContent === 'Analizza') as HTMLButtonElement
    fireEvent.click(analyzeBtn)

    await waitFor(() => {
      expect(view.container.textContent).toContain('EXPLOITABLE_CHAIN')
      expect(view.container.textContent).toContain('T1190')
      expect(view.container.textContent).toContain('RED-PRB-01')
      expect(view.container.textContent).toContain('Test Discriminante:')
    })

    // Clicking [EV-0001] highlights the matching verbatim evidence card
    const evBtn = Array.from(view.container.querySelectorAll('button.cp-cite-btn')).find(b => b.textContent === 'EV-0001') as HTMLButtonElement
    fireEvent.click(evBtn)
    await waitFor(() => {
      expect(view.container.querySelector('.cp-ev-active')?.textContent).toContain('EV-0001')
    })

    // Enable remote models & assign Codex to Red vs OpenCode Free to Blue
    const cloudToggle = view.container.querySelector('.cp-arena-bar input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(cloudToggle)
    const redProv = view.container.querySelector('select[aria-label="Provider Red"]') as HTMLSelectElement
    const blueProv = view.container.querySelector('select[aria-label="Provider Blue"]') as HTMLSelectElement
    await waitFor(() => {
      expect(Array.from(redProv.options).map(o => o.value)).toContain('openai-codex')
      expect(Array.from(blueProv.options).map(o => o.value)).toContain('opencode-free')
    })

    fireEvent.change(redProv, { target: { value: 'openai-codex' } })
    fireEvent.change(blueProv, { target: { value: 'opencode-free' } })
    await waitFor(() => {
      expect(calls.some(c =>
        c.path === '/api/plugins/cyber-purple-suite/config' &&
        (c.body as { red_provider?: string })?.red_provider === 'openai-codex'
      )).toBe(true)
      expect(calls.some(c =>
        c.path === '/api/plugins/cyber-purple-suite/config' &&
        (c.body as { blue_provider?: string })?.blue_provider === 'opencode-free'
      )).toBe(true)
    })

    // Open Replay tab and re-run interactive replay
    const replayTab = Array.from(view.container.querySelectorAll('button.cp-tab')).find(b => b.textContent?.includes('Purple Replay')) as HTMLButtonElement
    fireEvent.click(replayTab)
    await waitFor(() => expect(view.container.textContent).toContain('Detection Coverage: 100%'))

    const rerunBtn = Array.from(view.container.querySelectorAll('button')).find(b => b.textContent?.includes('Riesegui Purple Replay')) as HTMLButtonElement
    fireEvent.click(rerunBtn)
    await waitFor(() => {
      expect(calls.some(c => c.path === '/api/plugins/cyber-purple-suite/replay')).toBe(true)
    })

    view.unmount()
  })
})
