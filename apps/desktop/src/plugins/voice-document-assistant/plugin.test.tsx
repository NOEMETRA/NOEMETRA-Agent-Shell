import { render, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { discoverBundledPlugins } from '@/contrib/plugins'
import { $pluginDecisions, setPluginEnabled } from '@/contrib/plugins-store'
import { registry } from '@/contrib/registry'

vi.mock('@/contrib/runtime-loader', () => ({ watchRuntimePlugins: vi.fn() }))

class FakeAudio extends EventTarget {
  static instances: FakeAudio[] = []
  currentTime = 0
  duration = 4
  ended = false
  paused = true
  playbackRate = 1
  readyState = 4
  src: string
  pauseSpy = vi.fn(() => {
    this.paused = true
  })
  playSpy = vi.fn(async () => {
    this.paused = false
    this.dispatchEvent(new Event('play'))
  })

  constructor(src = '') {
    super()
    this.src = src
    FakeAudio.instances.push(this)
  }

  load(): void {}

  pause(): void {
    this.pauseSpy()
  }

  play(): Promise<void> {
    return this.playSpy()
  }

  removeAttribute(name: string): void {
    if (name === 'src') {
      this.src = ''
    }
  }
}

describe('voice-document-assistant desktop plugin lifecycle', () => {
  afterEach(async () => {
    await setPluginEnabled('voice-document-assistant', false)
    FakeAudio.instances = []
    Reflect.deleteProperty(window, 'hermesDesktop')
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('keeps client audio alive when the voice pane closes and pauses backend on plugin disable', async () => {
    $pluginDecisions.set({
      accent: false,
      kanban: false,
      'hermes-bots': false,
      radio: false,
      'voice-document-assistant': false
    })

    const calls: Array<{ body?: unknown; method?: string; path: string }> = []
    let backendState: 'paused' | 'playing' = 'playing'

    const api = vi.fn(async (req: { body?: unknown; method?: string; path: string }) => {
      calls.push({ path: req.path, method: req.method, body: req.body })

      if (req.path === '/api/plugins/voice-document-assistant/status') {
        return {
          state: backendState,
          doc_id: 'doc-alpha',
          doc_title: 'Alpha',
          current_page: 2,
          total_pages: 5,
          current_sentence_index: 3,
          total_sentences: 12,
          current_sentence_text: 'Frase di prova in riproduzione.',
          audio_seconds_offset: 0,
          tts_model: 'italian',
          speed: 1.0,
          client_playback: true,
          allow_remote: false,
          agents: { librarian: 'ready', analyst: 'ready', verifier: 'ready', detail: '' }
        }
      }

      if (req.path === '/api/plugins/voice-document-assistant/document/doc-alpha') {
        return {
          doc_id: 'doc-alpha',
          title: 'Alpha',
          total_pages: 5,
          pages: [{ page_number: 2, sentences: [{ sentence_index: 3, text: 'Frase di prova in riproduzione.' }] }]
        }
      }

      if (req.path === '/api/plugins/voice-document-assistant/library') {
        return { documents: [{ doc_id: 'doc-alpha', title: 'Alpha', total_pages: 5 }] }
      }

      if (req.path === '/api/plugins/voice-document-assistant/audio/sentence/3?format=json') {
        return { audio_base64: 'UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=' }
      }

      if (req.path === '/api/plugins/voice-document-assistant/playback/pause' && req.method === 'POST') {
        backendState = 'paused'
        return { state: 'paused' }
      }

      return { ok: true }
    })

    Object.defineProperty(window, 'hermesDesktop', {
      configurable: true,
      value: { api }
    })
    vi.stubGlobal('Audio', FakeAudio)

    discoverBundledPlugins()
    await setPluginEnabled('voice-document-assistant', true)

    const routeContrib = registry.getArea('routes').find(item => item.source === 'plugin:voice-document-assistant')
    const chipContrib = registry.getArea('statusBar.right').find(item => item.source === 'plugin:voice-document-assistant')

    expect(routeContrib?.render).toBeDefined()
    expect(chipContrib?.render).toBeDefined()

    const chipView = render(<>{chipContrib!.render!()}</>)
    const pageView = render(<>{routeContrib!.render!()}</>)

    await waitFor(() => {
      expect(FakeAudio.instances.length).toBe(1)
      expect(FakeAudio.instances[0].paused).toBe(false)
      expect(chipView.container.textContent).toContain('P.2 (4/12)')
    })

    const activeAudio = FakeAudio.instances[0]

    // Closing the voice-document pane must NOT pause client audio or leave status chip stale
    pageView.unmount()
    expect(activeAudio.pauseSpy).not.toHaveBeenCalled()
    expect(activeAudio.paused).toBe(false)
    expect(calls.some(c => c.path.endsWith('/playback/pause'))).toBe(false)
    expect(chipView.container.textContent).toContain('P.2 (4/12)')

    // Sentence completion while the pane is closed still acknowledges the backend
    activeAudio.dispatchEvent(new Event('ended'))
    await waitFor(() => {
      expect(
        calls.some(
          c =>
            c.path === '/api/plugins/voice-document-assistant/playback/ack' &&
            (c.body as { event?: string })?.event === 'ended'
        )
      ).toBe(true)
    })

    // Disabling/unloading the plugin stops audio AND explicitly pauses the backend
    chipView.unmount()
    await setPluginEnabled('voice-document-assistant', false)

    expect(activeAudio.pauseSpy).toHaveBeenCalled()
    expect(
      calls.some(c => c.path === '/api/plugins/voice-document-assistant/playback/pause' && c.method === 'POST')
    ).toBe(true)
  })

  it('renders Markdown synthesis with clickable page citations and structured verbatim document paragraphs', async () => {
    // @ts-expect-error runtime bundled plugin.js intentionally ships without .d.ts
    const { MarkdownView, DocumentPageSentences } = await import('./plugin.js')
    const jumpedPages: number[] = []
    const seekedSentences: number[] = []

    const mdSample = [
      '### Sintesi Tecnica',
      '',
      'Il protocollo usa **REST API** con formato `GeoJSON` [Pagina 2].',
      '',
      '- Prima regola *importante*',
      '- Seconda regola [link](https://example.com)',
      '',
      '> "Citazione letterale" [Pagina 3]'
    ].join('\n')

    const mdView = render(
      <MarkdownView text={mdSample} onJumpPage={(p: number) => jumpedPages.push(p)} />
    )

    expect(mdView.container.querySelector('h3.hv-md-h3')?.textContent).toBe('Sintesi Tecnica')
    expect(mdView.container.querySelector('strong')?.textContent).toBe('REST API')
    expect(mdView.container.querySelector('code.hv-md-code')?.textContent).toBe('GeoJSON')
    expect(mdView.container.querySelectorAll('ul.hv-md-ul li')).toHaveLength(2)
    expect(mdView.container.querySelector('blockquote.hv-md-quote')).not.toBeNull()

    const pageBtns = mdView.container.querySelectorAll('button.hv-md-page-ref')
    expect(pageBtns).toHaveLength(2)
    ;(pageBtns[0] as HTMLButtonElement).click()
    ;(pageBtns[1] as HTMLButtonElement).click()
    expect(jumpedPages).toEqual([2, 3])
    mdView.unmount()

    const docView = render(
      <DocumentPageSentences
        sentences={[
          { sentence_index: 0, paragraph_index: 0, text: '9 novembre 2026 • Documento | Pagina 1' },
          { sentence_index: 1, paragraph_index: 1, text: 'MANUALE TECNICO' },
          { sentence_index: 2, paragraph_index: 2, text: 'Q01 [P0] Formato dati' },
          { sentence_index: 3, paragraph_index: 2, text: '• Supporto nativo PDF e JSON.' },
          { sentence_index: 4, paragraph_index: 3, text: 'Testo normale leggibile.' }
        ]}
        activeSentenceIndex={4}
        isPlaying={true}
        onSeekSentence={(idx: number) => seekedSentences.push(idx)}
      />
    )

    expect(docView.container.querySelectorAll('.hv-doc-para')).toHaveLength(4)
    expect(docView.container.querySelector('.hv-doc-meta-line')?.textContent).toBe('9 novembre 2026 • Documento | Pagina 1')
    expect(docView.container.querySelector('.hv-doc-heading')?.textContent).toBe('MANUALE TECNICO')
    expect(docView.container.querySelector('.hv-doc-question-title')?.textContent).toBe('Q01 [P0] Formato dati')
    expect(docView.container.querySelector('.hv-doc-list-item')?.textContent).toBe('• Supporto nativo PDF e JSON.')
    const activeEl = docView.container.querySelector('.hv-sentence-active')
    expect(activeEl?.textContent?.trim()).toBe('Testo normale leggibile.')
    ;(docView.container.querySelector('.hv-doc-question-title') as HTMLElement).click()
    expect(seekedSentences).toEqual([2])
    docView.unmount()
  })

  it('supports TOC navigation, document search, citation quote highlights, prefetch N+1, header skip toggle, and AI reply TTS', async () => {
    // @ts-expect-error runtime bundled plugin.js intentionally ships without .d.ts
    const pluginMod = await import('./plugin.js')
    const {
      extractDocumentToc,
      findMatchingSentenceIndices,
      searchDocumentSentences
    } = pluginMod
    const { fireEvent } = await import('@testing-library/react')

    const sampleDoc = {
      doc_id: 'doc-rich',
      title: 'Questionario Tecnico',
      total_pages: 2,
      pages: [
        {
          page_number: 1,
          sentences: [
            { sentence_index: 0, paragraph_index: 0, text: 'HORIZON / TOPNETWORK - CONFRONTO', is_header_footer: true },
            { sentence_index: 1, paragraph_index: 1, text: '1. SCOPO DEL SISTEMA', is_header_footer: false },
            { sentence_index: 2, paragraph_index: 2, text: 'Supporta il protocollo REST API con token OAuth2.', is_header_footer: false },
            { sentence_index: 3, paragraph_index: 3, text: 'Footer | Pagina 1', is_header_footer: true }
          ]
        },
        {
          page_number: 2,
          sentences: [
            { sentence_index: 4, paragraph_index: 0, text: 'HORIZON / TOPNETWORK - CONFRONTO', is_header_footer: true },
            { sentence_index: 5, paragraph_index: 1, text: 'Q01 [P0] Formato dati EPSG', is_header_footer: false },
            { sentence_index: 6, paragraph_index: 2, text: 'Il formato primario è GeoJSON con proiezione EPSG:4326.', is_header_footer: false }
          ]
        }
      ]
    }

    expect(extractDocumentToc(sampleDoc)).toEqual([
      { sentence_index: 1, page_number: 1, kind: 'heading', label: '1. SCOPO DEL SISTEMA' },
      { sentence_index: 5, page_number: 2, kind: 'question', label: 'Q01 [P0] Formato dati EPSG' }
    ])
    expect(findMatchingSentenceIndices(sampleDoc.pages[1].sentences, 'Usa "GeoJSON con proiezione EPSG:4326" [Pagina 2]')).toEqual([6])
    expect(searchDocumentSentences(sampleDoc, 'GeoJSON')).toEqual([
      { sentence_index: 6, page_number: 2, text: 'Il formato primario è GeoJSON con proiezione EPSG:4326.' }
    ])

    $pluginDecisions.set({
      accent: false,
      kanban: false,
      'hermes-bots': false,
      radio: false,
      'voice-document-assistant': false
    })

    const calls: Array<{ body?: unknown; method?: string; path: string }> = []
    const api = vi.fn(async (req: { body?: unknown; method?: string; path: string }) => {
      calls.push({ path: req.path, method: req.method, body: req.body })

      if (req.path === '/api/plugins/voice-document-assistant/status') {
        return {
          state: 'playing',
          doc_id: 'doc-rich',
          doc_title: 'Questionario Tecnico',
          current_page: 1,
          total_pages: 2,
          current_sentence_index: 1,
          total_sentences: 7,
          current_sentence_text: '1. SCOPO DEL SISTEMA',
          audio_seconds_offset: 0,
          tts_model: 'italian',
          speed: 1.0,
          skip_headers_footers: true,
          client_playback: true,
          allow_remote: false,
          agents: { librarian: 'ready', analyst: 'ready', verifier: 'ready', detail: '' }
        }
      }
      if (req.path === '/api/plugins/voice-document-assistant/document/doc-rich') {
        return sampleDoc
      }
      if (req.path === '/api/plugins/voice-document-assistant/library') {
        return { documents: [{ doc_id: 'doc-rich', title: 'Questionario Tecnico', total_pages: 2 }] }
      }
      if (req.path.startsWith('/api/plugins/voice-document-assistant/audio/sentence/')) {
        return { audio_base64: 'UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=' }
      }
      if (req.path === '/api/plugins/voice-document-assistant/audio/text?format=json') {
        return { format: 'wav', audio_base64: 'UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=' }
      }
      if (req.path === '/api/plugins/voice-document-assistant/ask') {
        return {
          doc_id: 'doc-rich',
          answer: 'Il sistema adotta `GeoJSON` [Pagina 2].',
          citations: [{ page_number: 2, verbatim_quote: 'GeoJSON con proiezione EPSG:4326' }],
          verification: { is_valid: true, notes: 'OK' }
        }
      }
      return { ok: true }
    })

    Object.defineProperty(window, 'hermesDesktop', {
      configurable: true,
      value: { api }
    })
    vi.stubGlobal('Audio', FakeAudio)

    discoverBundledPlugins()
    await setPluginEnabled('voice-document-assistant', true)

    const routeContrib = registry.getArea('routes').find(item => item.source === 'plugin:voice-document-assistant')
    const view = render(<>{routeContrib!.render!()}</>)

    // Prefetch N+1: playing sentence 1 prefetches sentence 2 automatically
    await waitFor(() => {
      expect(calls.some(c => c.path === '/api/plugins/voice-document-assistant/audio/sentence/1?format=json')).toBe(true)
      expect(calls.some(c => c.path === '/api/plugins/voice-document-assistant/audio/sentence/2?format=json')).toBe(true)
      expect(view.container.textContent).toContain('Indice (2)')
    })

    // Toggle header/footer skipping checkbox -> sends /playback/config
    const skipCheckbox = view.container.querySelector('.hv-player-options input[type="checkbox"]') as HTMLInputElement
    expect(skipCheckbox.checked).toBe(true)
    fireEvent.click(skipCheckbox)
    await waitFor(() => {
      expect(calls.some(c =>
        c.path === '/api/plugins/voice-document-assistant/playback/config' &&
        (c.body as { skip_headers_footers?: boolean })?.skip_headers_footers === false
      )).toBe(true)
    })

    // Open TOC and click Q01
    const tocBtn = Array.from(view.container.querySelectorAll('button')).find(b => b.textContent?.includes('Indice (2)'))!
    fireEvent.click(tocBtn)
    const tocItems = view.container.querySelectorAll('.hv-toc-item')
    expect(tocItems).toHaveLength(2)
    fireEvent.click(tocItems[1])
    await waitFor(() => {
      expect(calls.some(c =>
        c.path === '/api/plugins/voice-document-assistant/playback/seek' &&
        (c.body as { sentence_index?: number })?.sentence_index === 5
      )).toBe(true)
    })

    // Ask question, click Fonti citation -> highlights matched sentence, click Ascolta -> calls /audio/text
    const askInput = view.container.querySelector('.hv-chat-input-bar input') as HTMLInputElement
    fireEvent.change(askInput, { target: { value: 'Quale formato dati?' } })
    fireEvent.keyDown(askInput, { key: 'Enter' })
    await waitFor(() => {
      expect(view.container.querySelector('.hv-msg-assistant')).not.toBeNull()
    })

    const fontiBtn = view.container.querySelector('.hv-citation-badge') as HTMLButtonElement
    fireEvent.click(fontiBtn)
    await waitFor(() => {
      const cited = view.container.querySelector('.hv-sentence-cited')
      expect(cited?.textContent).toContain('GeoJSON')
    })

    const speakBtn = view.container.querySelector('.hv-msg-speak-btn') as HTMLButtonElement
    fireEvent.click(speakBtn)
    await waitFor(() => {
      expect(calls.some(c => c.path === '/api/plugins/voice-document-assistant/audio/text?format=json' && c.method === 'POST')).toBe(true)
    })

    // Ctrl+F Search inside document highlights substring with <mark>
    fireEvent.keyDown(window, { key: 'f', ctrlKey: true })
    const searchInput = view.container.querySelector('.hv-search-bar input') as HTMLInputElement
    expect(searchInput).not.toBeNull()
    fireEvent.change(searchInput, { target: { value: 'GeoJSON' } })
    await waitFor(() => {
      expect(view.container.querySelector('.hv-search-count')?.textContent).toBe('1 / 1')
      expect(view.container.querySelector('mark.hv-search-mark')?.textContent).toBe('GeoJSON')
    })

    view.unmount()
  })
})
