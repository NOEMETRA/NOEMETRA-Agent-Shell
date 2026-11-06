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
})
