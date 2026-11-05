/**
 * Hermes Voice — Native Desktop Plugin (@hermes/plugin-sdk)
 *
 * Full-featured GUI for deterministic multi-agent voice document assistant:
 * - PDF Library with upload / drag-and-drop
 * - Verbatim document viewer with live sentence highlighting synchronized with Pocket TTS
 * - Full playback controls: Play, Pause, Resume, Stop, Seek, Speed
 * - Model selection: Pocket TTS 'italian' vs 'italian_24l'
 * - Real-time Agent Triad status (Bibliotecario, Analista, Verificatore)
 * - Grounded Q&A with clickable page citations that jump the document viewer
 * - Local-first privacy controls with explicit toggle for remote providers
 */

import {
  Codicon,
  host,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS
} from '@hermes/plugin-sdk'
import { useEffect, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PLUGIN_ID = 'voice-document-assistant'

// Custom styling adhering to Hermes theme CSS variables
const CSS = `
.hv-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
  background: var(--ui-bg-app, #121316);
  color: var(--ui-text-primary, #e4e4e7);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  overflow: hidden;
}

.hv-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  background: var(--ui-bg-surface, #18191d);
  border-bottom: 1px solid var(--ui-stroke-secondary, #27272a);
  gap: 12px;
  flex-wrap: wrap;
}

.hv-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}

.hv-title {
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text-primary, #ffffff);
}

.hv-badge {
  font-size: 11px;
  font-weight: 500;
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--ui-badge-bg, rgba(255,255,255,0.08));
  color: var(--ui-text-secondary, #a1a1aa);
}

.hv-badge-active {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.hv-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.hv-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid var(--ui-stroke-secondary, #3f3f46);
  background: var(--ui-btn-bg, #27272a);
  color: var(--ui-text-primary, #ffffff);
  transition: all 0.15s ease;
}

.hv-btn:hover {
  background: var(--ui-btn-hover, #3f3f46);
  border-color: var(--ui-stroke-primary, #52525b);
}

.hv-btn-primary {
  background: var(--ui-accent, #3b82f6);
  border-color: var(--ui-accent, #3b82f6);
  color: #ffffff;
}

.hv-btn-primary:hover {
  background: var(--ui-accent-hover, #2563eb);
}

.hv-btn-danger {
  background: rgba(239, 68, 68, 0.15);
  border-color: rgba(239, 68, 68, 0.4);
  color: #ef4444;
}

.hv-select {
  padding: 5px 8px;
  border-radius: 6px;
  background: var(--ui-btn-bg, #27272a);
  border: 1px solid var(--ui-stroke-secondary, #3f3f46);
  color: var(--ui-text-primary, #ffffff);
  font-size: 12px;
  cursor: pointer;
}

.hv-main-grid {
  display: grid;
  grid-template-columns: 1.15fr 1fr;
  flex: 1;
  overflow: hidden;
}

@media (max-width: 900px) {
  .hv-main-grid {
    grid-template-columns: 1fr;
    grid-template-rows: 1fr 1fr;
  }
}

.hv-doc-column {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--ui-stroke-secondary, #27272a);
  background: var(--ui-bg-app, #121316);
  overflow: hidden;
}

.hv-doc-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 14px;
  border-bottom: 1px solid var(--ui-stroke-secondary, #27272a);
  background: var(--ui-bg-surface, #18191d);
}

.hv-page-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.hv-doc-content {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
  line-height: 1.7;
  font-size: 14px;
}

.hv-sentence {
  display: inline;
  padding: 2px 3px;
  border-radius: 3px;
  cursor: pointer;
  transition: background 0.15s ease;
}

.hv-sentence:hover {
  background: rgba(255, 255, 255, 0.08);
}

.hv-sentence-active {
  background: rgba(245, 158, 11, 0.25) !important;
  color: #fbbf24 !important;
  box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.5);
  font-weight: 500;
}

.hv-panel-column {
  display: flex;
  flex-direction: column;
  background: var(--ui-bg-surface, #18191d);
  overflow: hidden;
}

.hv-player-box {
  padding: 14px 18px;
  border-bottom: 1px solid var(--ui-stroke-secondary, #27272a);
  background: var(--ui-bg-card, #1c1d22);
}

.hv-player-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.hv-timeline {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 11px;
  color: var(--ui-text-tertiary, #71717a);
}

.hv-progress-bar {
  flex: 1;
  height: 5px;
  background: var(--ui-stroke-secondary, #3f3f46);
  border-radius: 3px;
  overflow: hidden;
  position: relative;
}

.hv-progress-fill {
  height: 100%;
  background: var(--ui-accent, #3b82f6);
  transition: width 0.2s ease;
}

.hv-agents-box {
  padding: 12px 18px;
  border-bottom: 1px solid var(--ui-stroke-secondary, #27272a);
  background: var(--ui-bg-surface, #18191d);
}

.hv-agents-title {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--ui-text-tertiary, #71717a);
  margin-bottom: 8px;
  font-weight: 600;
}

.hv-agents-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.hv-agent-card {
  padding: 8px;
  border-radius: 6px;
  background: var(--ui-bg-app, #121316);
  border: 1px solid var(--ui-stroke-secondary, #27272a);
  font-size: 11px;
}

.hv-agent-name {
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 5px;
  margin-bottom: 3px;
}

.hv-agent-status {
  font-size: 10px;
  color: var(--ui-text-secondary, #a1a1aa);
}

.hv-chat-section {
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow: hidden;
}

.hv-chat-history {
  flex: 1;
  padding: 14px 18px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.hv-chat-msg {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.hv-msg-user {
  align-self: flex-end;
  background: var(--ui-accent, #3b82f6);
  color: #ffffff;
  padding: 8px 12px;
  border-radius: 8px 8px 2px 8px;
  max-width: 85%;
  font-size: 13px;
}

.hv-msg-assistant {
  align-self: flex-start;
  background: var(--ui-bg-card, #222329);
  border: 1px solid var(--ui-stroke-secondary, #2f3037);
  padding: 10px 14px;
  border-radius: 8px 8px 8px 2px;
  max-width: 90%;
  font-size: 13px;
  line-height: 1.5;
}

.hv-citations-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.hv-citation-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 7px;
  border-radius: 4px;
  background: rgba(59, 130, 246, 0.15);
  border: 1px solid rgba(59, 130, 246, 0.35);
  color: #60a5fa;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}

.hv-citation-badge:hover {
  background: rgba(59, 130, 246, 0.3);
  border-color: #60a5fa;
}

.hv-verification-box {
  margin-top: 8px;
  padding: 6px 10px;
  border-radius: 4px;
  font-size: 11px;
}

.hv-verification-valid {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #4ade80;
}

.hv-verification-invalid {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #f87171;
}

.hv-chat-input-bar {
  padding: 10px 18px;
  border-top: 1px solid var(--ui-stroke-secondary, #27272a);
  background: var(--ui-bg-surface, #18191d);
  display: flex;
  gap: 8px;
  align-items: center;
}

.hv-input {
  flex: 1;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px solid var(--ui-stroke-secondary, #3f3f46);
  background: var(--ui-bg-app, #121316);
  color: var(--ui-text-primary, #ffffff);
  font-size: 13px;
  outline: none;
}

.hv-input:focus {
  border-color: var(--ui-accent, #3b82f6);
}

.hv-privacy-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 18px;
  background: var(--ui-bg-app, #121316);
  border-top: 1px solid var(--ui-stroke-secondary, #27272a);
  font-size: 11px;
  color: var(--ui-text-tertiary, #71717a);
}

.hv-toggle-label {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
}
`

function VoiceDocumentPage({ ctx }) {
  const [status, setStatus] = useState(null)
  const [library, setLibrary] = useState([])
  const [docData, setDocData] = useState(null)
  const [viewPage, setViewPage] = useState(1)
  const [chatMessages, setChatMessages] = useState([])
  const [questionInput, setQuestionInput] = useState('')
  const [isAsking, setIsAsking] = useState(false)
  const [isRecording, setIsRecording] = useState(false)
  const fileInputRef = useRef(null)
  const clientAudioRef = useRef(null)
  const lastPlayedTargetRef = useRef('')
  const fetchingTargetRef = useRef('')

  // Poll backend status and synchronize client-side audio playback
  useEffect(() => {
    let disposed = false
    let timer = null
    let pollGen = 0

    const poll = async () => {
      try {
        const currentGen = ++pollGen
        const s = await ctx.rest('/status')
        if (disposed || currentGen !== pollGen) return
        setStatus(s)
        if (s && s.current_page) {
          const isPlaying = s.state === 'playing'
          if (!docData || isPlaying) {
            setViewPage(s.current_page)
          }

          // Composite key tracking both document ID and sentence index to prevent cross-document audio leakage
          const targetDocId = s.doc_id || (docData ? docData.doc_id : '')
          const playTargetKey = `${targetDocId}:${s.current_sentence_index}`

          // Client-side local audio streaming for desktop playback via profile-aware ctx.rest gateway bridge
          if (isPlaying) {
            if (playTargetKey !== lastPlayedTargetRef.current && fetchingTargetRef.current !== playTargetKey) {
              fetchingTargetRef.current = playTargetKey
              if (clientAudioRef.current) {
                clientAudioRef.current.pause()
                clientAudioRef.current = null
              }
              try {
                const currentSentIdx = s.current_sentence_index
                const audioData = await ctx.rest(`/audio/sentence/${currentSentIdx}?format=json`)

                // Discard audio fetched for an obsolete playback state or unmounted view (AGENTS.md:59-62)
                if (disposed || currentGen !== pollGen) {
                  fetchingTargetRef.current = ''
                  return
                }

                if (audioData && audioData.audio_base64) {
                  const audio = new Audio(`data:audio/wav;base64,${audioData.audio_base64}`)
                  if (s.speed) {
                    audio.playbackRate = s.speed
                  }
                  const startOffset = s.audio_seconds_offset || 0
                  if (startOffset > 0.05) {
                    const setOffset = () => {
                      try {
                        if (startOffset < audio.duration) {
                          audio.currentTime = startOffset
                        }
                      } catch (_) {}
                    }
                    if (audio.readyState >= 1) {
                      setOffset()
                    } else {
                      audio.addEventListener('loadedmetadata', setOffset, { once: true })
                    }
                  }
                  audio.addEventListener('play', () => {
                    ctx.rest('/playback/ack', {
                      method: 'POST',
                      body: { sentence_index: currentSentIdx, event: 'started' }
                    }).catch(() => {})
                  }, { once: true })
                  let lastProgressAck = 0
                  audio.addEventListener('timeupdate', () => {
                    const now = Date.now()
                    if (now - lastProgressAck > 300) {
                      lastProgressAck = now
                      ctx.rest('/playback/ack', {
                        method: 'POST',
                        body: {
                          sentence_index: currentSentIdx,
                          event: 'progress',
                          offset_seconds: audio.currentTime
                        }
                      }).catch(() => {})
                    }
                  })
                  audio.addEventListener('ended', () => {
                    ctx.rest('/playback/ack', {
                      method: 'POST',
                      body: { sentence_index: currentSentIdx, event: 'ended' }
                    }).catch(() => {})
                  }, { once: true })

                  // Re-verify freshness before initiating audio playback
                  if (disposed || currentGen !== pollGen) {
                    fetchingTargetRef.current = ''
                    return
                  }
                  clientAudioRef.current = audio
                  lastPlayedTargetRef.current = playTargetKey
                  fetchingTargetRef.current = ''
                  audio.play().catch(() => {})
                } else {
                  fetchingTargetRef.current = ''
                }
              } catch (e) {
                // Audio fetch failed or was aborted: clear fetching target to allow retry on next poll
                fetchingTargetRef.current = ''
                if (lastPlayedTargetRef.current === playTargetKey) {
                  lastPlayedTargetRef.current = ''
                }
              }
            } else if (clientAudioRef.current) {
              // Synchronize speed if changed
              if (s.speed && clientAudioRef.current.playbackRate !== s.speed) {
                clientAudioRef.current.playbackRate = s.speed
              }
              if (clientAudioRef.current.paused) {
                // Resume playback of existing audio within the same sentence at current bookmark offset
                if (s.audio_seconds_offset !== undefined && Math.abs(clientAudioRef.current.currentTime - s.audio_seconds_offset) > 0.3) {
                  try {
                    clientAudioRef.current.currentTime = s.audio_seconds_offset
                  } catch (_) {}
                }
                clientAudioRef.current.play().catch(() => {})
              }
            }
          } else {
            if (clientAudioRef.current && !clientAudioRef.current.paused) {
              clientAudioRef.current.pause()
            }
            if (s.state === 'stopped' || s.state === 'finished') {
              lastPlayedTargetRef.current = ''
              fetchingTargetRef.current = ''
              if (clientAudioRef.current) {
                clientAudioRef.current = null
              }
            }
          }
        }
      } catch (err) {
        // backend loading
      } finally {
        if (!disposed) {
          timer = setTimeout(poll, 600)
        }
      }
    }
    poll()
    return () => {
      disposed = true
      ++pollGen
      fetchingTargetRef.current = ''
      lastPlayedTargetRef.current = ''
      if (timer) clearTimeout(timer)
      if (clientAudioRef.current) {
        clientAudioRef.current.pause()
        clientAudioRef.current = null
      }
    }
  }, [ctx, docData])

  // Load library
  const refreshLibrary = async () => {
    try {
      const res = await ctx.rest('/library')
      if (res && res.documents) {
        setLibrary(res.documents)
      }
    } catch (err) {
      console.error('Error fetching library:', err)
    }
  }

  useEffect(() => {
    refreshLibrary()
  }, [])

  // When doc_id changes in status, load document text details
  useEffect(() => {
    if (status && status.doc_id) {
      if (!docData || docData.doc_id !== status.doc_id) {
        ctx.rest(`/document/${status.doc_id}`).then(d => {
          setDocData(d)
          if (status.current_page) setViewPage(status.current_page)
        }).catch(() => {})
      }
    }
  }, [status?.doc_id, ctx, docData])

  // Playback handlers
  const handlePlay = async () => {
    try {
      await ctx.rest('/playback/play', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { output: 'client' },
      })
    } catch (err) {
      host.notifyError(err, 'Errore avvio riproduzione audio')
    }
  }

  const handlePause = async () => {
    if (clientAudioRef.current) clientAudioRef.current.pause()
    try {
      await ctx.rest('/playback/pause', { method: 'POST' })
    } catch (err) {
      host.notifyError(err, 'Errore pausa audio')
    }
  }

  const handleResume = async () => {
    try {
      await ctx.rest('/playback/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { output: 'client' },
      })
    } catch (err) {
      host.notifyError(err, 'Errore ripresa audio')
    }
  }

  const handleStop = async () => {
    if (clientAudioRef.current) {
      clientAudioRef.current.pause()
      clientAudioRef.current = null
    }
    lastPlayedTargetRef.current = ''
    fetchingTargetRef.current = ''
    try {
      await ctx.rest('/playback/stop', { method: 'POST' })
    } catch (err) {
      host.notifyError(err, 'Errore stop audio')
    }
  }

  const handleSeekSentence = async (sentenceIdx) => {
    if (clientAudioRef.current) {
      clientAudioRef.current.pause()
      clientAudioRef.current = null
    }
    lastPlayedTargetRef.current = ''
    fetchingTargetRef.current = ''
    try {
      await ctx.rest('/playback/seek', {
        method: 'POST',
        body: { sentence_index: sentenceIdx }
      })
    } catch (err) {
      console.error(err)
    }
  }

  const handleSeekPage = async (page) => {
    if (clientAudioRef.current) {
      clientAudioRef.current.pause()
      clientAudioRef.current = null
    }
    lastPlayedTargetRef.current = ''
    fetchingTargetRef.current = ''
    setViewPage(page)
    try {
      await ctx.rest('/playback/seek', {
        method: 'POST',
        body: { page_number: page }
      })
    } catch (err) {
      console.error(err)
    }
  }

  const handleSeekCitation = async (docId, page) => {
    try {
      if (docId && docData && docData.doc_id !== docId) {
        if (clientAudioRef.current) {
          clientAudioRef.current.pause()
          clientAudioRef.current = null
        }
        lastPlayedTargetRef.current = ''
        fetchingTargetRef.current = ''
        await ctx.rest('/select_document', {
          method: 'POST',
          body: { doc_id: docId }
        })
        const switched = await ctx.rest(`/document/${docId}`)
        setDocData(switched)
      }
      handleSeekPage(page)
    } catch (err) {
      host.notifyError(err, 'Errore navigazione citazione')
    }
  }

  const handleModelChange = async (e) => {
    const tts_model = e.target.value
    try {
      await ctx.rest('/playback/config', {
        method: 'POST',
        body: { tts_model }
      })
      host.notify({ kind: 'info', message: `Modello Pocket TTS impostato su: ${tts_model}` })
    } catch (err) {
      host.notifyError(err, 'Errore cambio modello')
    }
  }

  const handleSpeedChange = async (e) => {
    const speed = parseFloat(e.target.value)
    if (clientAudioRef.current && !isNaN(speed) && speed > 0) {
      clientAudioRef.current.playbackRate = speed
    }
    try {
      await ctx.rest('/playback/config', {
        method: 'POST',
        body: { speed }
      })
    } catch (err) {
      console.error(err)
    }
  }

  const handlePrivacyToggle = async (e) => {
    const allow_remote = e.target.checked
    try {
      await ctx.rest('/config/privacy', {
        method: 'POST',
        body: { allow_remote }
      })
      host.notify({
        kind: allow_remote ? 'warning' : 'info',
        message: allow_remote
          ? 'Autorizzazione provider remoti ATTIVATA'
          : 'Privacy locale ripristinata (Provider remoti disattivati)'
      })
    } catch (err) {
      host.notifyError(err, 'Errore impostazione privacy')
    }
  }

  const handleFileUpload = async (e) => {
    const files = e.target.files
    if (!files || files.length === 0) return
    const file = files[0]

    const reader = new FileReader()
    reader.onload = async () => {
      try {
        const base64Data = reader.result.split(',')[1]
        host.notify({ kind: 'info', message: `Caricamento di "${file.name}"...` })
        const res = await ctx.rest('/upload', {
          method: 'POST',
          body: {
            filename: file.name,
            content_base64: base64Data
          }
        })
        if (res && res.document) {
          if (clientAudioRef.current) {
            clientAudioRef.current.pause()
            clientAudioRef.current = null
          }
          lastPlayedTargetRef.current = ''
          fetchingTargetRef.current = ''
          setDocData(res.document)
          setViewPage(1)
          refreshLibrary()
          host.notify({ kind: 'info', message: `Documento caricato: ${res.document.title}` })
        }
      } catch (err) {
        host.notifyError(err, 'Errore caricamento PDF')
      }
    }
    reader.readAsDataURL(file)
  }

  const handleSelectDoc = async (e) => {
    const docId = e.target.value
    if (!docId) return
    if (clientAudioRef.current) {
      clientAudioRef.current.pause()
      clientAudioRef.current = null
    }
    lastPlayedTargetRef.current = ''
    fetchingTargetRef.current = ''
    try {
      const res = await ctx.rest('/select_document', {
        method: 'POST',
        body: { doc_id: docId }
      })
      if (res && res.document) {
        setDocData(res.document)
        setViewPage(1)
        host.notify({ kind: 'info', message: `Documento attivato: ${res.document.title}` })
      }
    } catch (err) {
      host.notifyError(err, 'Errore selezione documento')
    }
  }

  // Ask question
  const handleAsk = async () => {
    const q = questionInput.trim()
    if (!q || isAsking) return
    setIsAsking(true)
    setQuestionInput('')

    const userMsg = { role: 'user', text: q, time: new Date().toLocaleTimeString() }
    setChatMessages(prev => [...prev, userMsg])

    const targetDocId = docData ? docData.doc_id : null
    try {
      const answer = await ctx.rest('/ask', {
        method: 'POST',
        body: { question: q }
      })
      const assistantMsg = {
        role: 'assistant',
        text: answer.answer,
        doc_id: targetDocId,
        citations: answer.citations || [],
        verification: answer.verification,
        model_used: answer.model_used,
        time: new Date().toLocaleTimeString()
      }
      setChatMessages(prev => [...prev, assistantMsg])
    } catch (err) {
      const errorMsg = {
        role: 'assistant',
        text: `Errore durante l'interrogazione: ${err.message || err}`,
        verification: {
          is_valid: false,
          citation_match_score: 0.0,
          notes: 'Errore runtime del modello o connessione interrotta.'
        },
        time: new Date().toLocaleTimeString()
      }
      setChatMessages(prev => [...prev, errorMsg])
    } finally {
      setIsAsking(false)
    }
  }

  // Toggle mic input (Speech recognition if available)
  const toggleRecording = () => {
    if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
      host.notify({ kind: 'warning', message: 'Riconoscimento vocale browser non disponibile su questa versione Electron.' })
      return
    }
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
    if (!isRecording) {
      try {
        const recognition = new SpeechRecognition()
        recognition.lang = 'it-IT'
        recognition.interimResults = false
        recognition.onstart = () => setIsRecording(true)
        recognition.onresult = (evt) => {
          const transcript = evt.results[0][0].transcript
          setQuestionInput(transcript)
          setIsRecording(false)
        }
        recognition.onerror = () => setIsRecording(false)
        recognition.onend = () => setIsRecording(false)
        recognition.start()
      } catch (e) {
        setIsRecording(false)
      }
    } else {
      setIsRecording(false)
    }
  }

  // Get current page object from docData
  const currentPageObj = docData?.pages?.find(p => p.page_number === viewPage)
  const totalPages = docData?.total_pages || 1
  const isPlaying = status?.state === 'playing'
  const isPaused = status?.state === 'paused'

  return jsxs('div', {
    className: 'hv-container',
    children: [
      // Injected CSS
      jsx('style', { children: CSS }),

      // Top Header
      jsxs('header', {
        className: 'hv-header',
        children: [
          jsxs('div', {
            className: 'hv-title-group',
            children: [
              jsx(Codicon, { name: 'book', size: '1.2rem' }),
              jsx('span', { className: 'hv-title', children: 'NOEMETRA Voice Assistant' }),
              jsx('span', {
                className: `hv-badge ${isPlaying ? 'hv-badge-active' : ''}`,
                children: status?.state ? status.state.toUpperCase() : 'DISCONNESSO'
              })
            ]
          }),
          jsxs('div', {
            className: 'hv-header-actions',
            children: [
              // Library selector
              jsxs('select', {
                className: 'hv-select',
                value: status?.doc_id || '',
                onChange: handleSelectDoc,
                children: [
                  jsx('option', { value: '', children: 'Seleziona documento...' }),
                  library.map(doc => jsx('option', {
                    key: doc.doc_id,
                    value: doc.doc_id,
                    children: `${doc.title} (${doc.total_pages} pag.)`
                  }))
                ]
              }),
              // Upload button
              jsx('input', {
                type: 'file',
                accept: '.pdf',
                ref: fileInputRef,
                style: { display: 'none' },
                onChange: handleFileUpload
              }),
              jsxs('button', {
                className: 'hv-btn',
                onClick: () => fileInputRef.current?.click(),
                children: [
                  jsx(Codicon, { name: 'cloud-upload' }),
                  'Carica PDF'
                ]
              }),
              // Pocket TTS Model Switcher
              jsxs('select', {
                className: 'hv-select',
                value: status?.tts_model || 'italian',
                onChange: handleModelChange,
                children: [
                  jsx('option', { value: 'italian', children: 'Pocket TTS: italian (Fast 2.6x)' }),
                  jsx('option', { value: 'italian_24l', children: 'Pocket TTS: italian_24l (Hi-Fi 24L)' })
                ]
              }),
              // Speed selector
              jsxs('select', {
                className: 'hv-select',
                value: status?.speed || 1.0,
                onChange: handleSpeedChange,
                children: [
                  jsx('option', { value: 0.75, children: '0.75x' }),
                  jsx('option', { value: 1.0, children: '1.0x (Normale)' }),
                  jsx('option', { value: 1.25, children: '1.25x' }),
                  jsx('option', { value: 1.5, children: '1.5x' })
                ]
              })
            ]
          })
        ]
      }),

      // Main Grid
      jsxs('div', {
        className: 'hv-main-grid',
        children: [
          // Left Column: Document Viewer with Live Highlighting
          jsxs('div', {
            className: 'hv-doc-column',
            children: [
              jsxs('div', {
                className: 'hv-doc-toolbar',
                children: [
                  jsx('span', {
                    style: { fontWeight: 500, fontSize: '13px' },
                    children: docData?.title || 'Nessun documento attivo'
                  }),
                  jsxs('div', {
                    className: 'hv-page-controls',
                    children: [
                      jsx('button', {
                        className: 'hv-btn',
                        disabled: viewPage <= 1,
                        onClick: () => handleSeekPage(viewPage - 1),
                        children: jsx(Codicon, { name: 'chevron-left' })
                      }),
                      jsx('span', { children: `Pagina ${viewPage} di ${totalPages}` }),
                      jsx('button', {
                        className: 'hv-btn',
                        disabled: viewPage >= totalPages,
                        onClick: () => handleSeekPage(viewPage + 1),
                        children: jsx(Codicon, { name: 'chevron-right' })
                      })
                    ]
                  })
                ]
              }),
              jsx('div', {
                className: 'hv-doc-content',
                children: currentPageObj?.sentences && currentPageObj.sentences.length > 0
                  ? currentPageObj.sentences.map(sent => {
                      const isCurrentSpeaking = (status?.current_sentence_index === sent.sentence_index) && isPlaying
                      return jsx('span', {
                        key: sent.sentence_index,
                        className: `hv-sentence ${isCurrentSpeaking ? 'hv-sentence-active' : ''}`,
                        onClick: () => handleSeekSentence(sent.sentence_index),
                        title: `Frase #${sent.sentence_index + 1} (Clicca per leggere)`,
                        children: sent.text + ' '
                      })
                    })
                  : jsx('div', {
                      style: { color: 'var(--ui-text-tertiary)', textAlign: 'center', marginTop: '40px' },
                      children: docData ? 'Questa pagina non contiene testo estratto.' : 'Carica un file PDF italiano o selezionalo dalla biblioteca per visualizzarlo.'
                    })
              })
            ]
          }),

          // Right Column: Controls, Agents, Chat
          jsxs('div', {
            className: 'hv-panel-column',
            children: [
              // Playback Box
              jsxs('div', {
                className: 'hv-player-box',
                children: [
                  jsxs('div', {
                    className: 'hv-player-controls',
                    children: [
                      !isPlaying
                        ? jsxs('button', {
                            className: 'hv-btn hv-btn-primary',
                            onClick: isPaused ? handleResume : handlePlay,
                            disabled: !docData,
                            children: [
                              jsx(Codicon, { name: 'play' }),
                              isPaused ? 'Riprendi' : 'Ascolta'
                            ]
                          })
                        : jsxs('button', {
                            className: 'hv-btn',
                            onClick: handlePause,
                            children: [
                              jsx(Codicon, { name: 'debug-pause' }),
                              'Pausa'
                            ]
                          }),
                      jsxs('button', {
                        className: 'hv-btn hv-btn-danger',
                        onClick: handleStop,
                        disabled: !status || status.state === 'stopped' || status.state === 'idle',
                        children: [
                          jsx(Codicon, { name: 'debug-stop' }),
                          'Stop'
                        ]
                      }),
                      jsx('span', {
                        style: { marginLeft: 'auto', fontSize: '11px', color: 'var(--ui-text-secondary)' },
                        children: status?.current_sentence_text
                          ? `In lettura: "${status.current_sentence_text.slice(0, 40)}..."`
                          : ''
                      })
                    ]
                  }),
                  // Timeline Bar
                  jsxs('div', {
                    className: 'hv-timeline',
                    children: [
                      jsx('span', {
                        children: status?.total_sentences
                          ? `Frase ${status.current_sentence_index + 1} / ${status.total_sentences}`
                          : '0 / 0'
                      }),
                      jsx('div', {
                        className: 'hv-progress-bar',
                        children: jsx('div', {
                          className: 'hv-progress-fill',
                          style: {
                            width: status?.total_sentences
                              ? `${((status.current_sentence_index + 1) / status.total_sentences) * 100}%`
                              : '0%'
                          }
                        })
                      }),
                      jsx('span', { children: `${(status?.audio_seconds_offset || 0).toFixed(1)}s` })
                    ]
                  })
                ]
              }),

              // Agent Triad Status Box
              jsxs('div', {
                className: 'hv-agents-box',
                children: [
                  jsx('div', { className: 'hv-agents-title', children: 'Stato Reale Triade Multi-Agente' }),
                  jsxs('div', {
                    className: 'hv-agents-cards',
                    children: [
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: ['📚 Bibliotecario']
                          }),
                          jsx('div', {
                            className: 'hv-agent-status',
                            children: status?.agents?.librarian === 'searching' ? '🔍 Ricerca...' : '✅ Indicizzato'
                          })
                        ]
                      }),
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: ['🧠 Analista']
                          }),
                          jsx('div', {
                            className: 'hv-agent-status',
                            children: isAsking || status?.agents?.analyst === 'generating'
                              ? '⏳ Generazione LLM...'
                              : '✅ Pronto (Ollama)'
                          })
                        ]
                      }),
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: ['🔍 Verificatore']
                          }),
                          jsx('div', {
                            className: 'hv-agent-status',
                            children: status?.agents?.verifier === 'valid'
                              ? '✅ Citazioni Convalidate'
                              : status?.agents?.verifier === 'invalid'
                              ? '⚠️ Rilevate Discrepanze'
                              : '✅ Pronto'
                          })
                        ]
                      })
                    ]
                  })
                ]
              }),

              // Agent Q&A Chat Section
              jsxs('div', {
                className: 'hv-chat-section',
                children: [
                  jsx('div', {
                    className: 'hv-chat-history',
                    children: chatMessages.length === 0
                      ? jsx('div', {
                          style: { color: 'var(--ui-text-tertiary)', textAlign: 'center', marginTop: '40px', fontSize: '13px' },
                          children: 'Poni una domanda sul documento. L\'Analista risponderà basandosi sulle evidenze estratte e il Verificatore convaliderà ogni numero di pagina.'
                        })
                      : chatMessages.map((msg, i) => {
                          if (msg.role === 'user') {
                            return jsxs('div', {
                              key: i,
                              className: 'hv-chat-msg',
                              children: [
                                jsx('div', { className: 'hv-msg-user', children: msg.text })
                              ]
                            })
                          } else {
                            const isValid = msg.verification?.is_valid
                            return jsxs('div', {
                              key: i,
                              className: 'hv-chat-msg',
                              children: [
                                jsxs('div', {
                                  className: 'hv-msg-assistant',
                                  children: [
                                    jsx('div', { children: msg.text }),
                                    // Clickable Citations
                                    msg.citations && msg.citations.length > 0 && jsxs('div', {
                                      className: 'hv-citations-row',
                                      children: [
                                        jsx('span', {
                                          style: { fontSize: '11px', color: 'var(--ui-text-secondary)', alignSelf: 'center' },
                                          children: 'Citazioni verificabili:'
                                        }),
                                        msg.citations.map((cit, cIdx) => jsx('button', {
                                          key: cIdx,
                                          className: 'hv-citation-badge',
                                          onClick: () => handleSeekCitation(msg.doc_id, cit.page_number),
                                          title: `Clicca per aprire Pagina ${cit.page_number}\n"${cit.verbatim_quote}"`,
                                          children: `[Pagina ${cit.page_number}]`
                                        }))
                                      ]
                                    }),
                                    // Verification Badge
                                    msg.verification && jsx('div', {
                                      className: `hv-verification-box ${isValid ? 'hv-verification-valid' : 'hv-verification-invalid'}`,
                                      children: isValid
                                        ? `✅ Verificatore: ${msg.verification.notes || 'Citazioni convalidate con precisione del 100%'}`
                                        : `⚠️ Verificatore: ${msg.verification.notes || 'Citazioni non conformi al testo sorgente.'}`
                                    })
                                  ]
                                })
                              ]
                            })
                          }
                        })
                  }),

                  // Question Input Bar
                  jsxs('div', {
                    className: 'hv-chat-input-bar',
                    children: [
                      jsx('input', {
                        className: 'hv-input',
                        placeholder: 'Formula una domanda sul documento...',
                        value: questionInput,
                        onChange: (e) => setQuestionInput(e.target.value),
                        onKeyDown: (e) => { if (e.key === 'Enter') handleAsk() }
                      }),
                      jsx('button', {
                        className: `hv-btn ${isRecording ? 'hv-btn-danger' : ''}`,
                        onClick: toggleRecording,
                        title: 'Input microfonico vocale',
                        children: jsx(Codicon, { name: isRecording ? 'mic-filled' : 'mic' })
                      }),
                      jsxs('button', {
                        className: 'hv-btn hv-btn-primary',
                        onClick: handleAsk,
                        disabled: isAsking || !questionInput.trim() || !docData,
                        children: [
                          jsx(Codicon, { name: isAsking ? 'loading' : 'send' }),
                          isAsking ? 'Analisi...' : 'Chiedi'
                        ]
                      })
                    ]
                  })
                ]
              }),

              // Privacy Consent Footer
              jsxs('footer', {
                className: 'hv-privacy-bar',
                children: [
                  jsxs('span', {
                    children: [
                      '🔒 Routing: ',
                      jsx('strong', { children: 'Ollama Locale (gemma4:12b)' }),
                      ' · Nessun dato trasmesso a terzi'
                    ]
                  }),
                  jsxs('label', {
                    className: 'hv-toggle-label',
                    children: [
                      jsx('input', {
                        type: 'checkbox',
                        checked: status?.allow_remote || false,
                        onChange: handlePrivacyToggle
                      }),
                      'Consenti provider remoti'
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

// Mini status-bar widget
function VoiceStatusChip({ ctx }) {
  const [status, setStatus] = useState(null)

  useEffect(() => {
    let timer = null
    const check = async () => {
      try {
        const s = await ctx.rest('/status')
        setStatus(s)
      } catch (e) {}
      timer = setTimeout(check, 1000)
    }
    check()
    return () => clearTimeout(timer)
  }, [ctx])

  if (!status || status.state === 'idle') return null

  const isPlaying = status.state === 'playing'

  return jsxs('div', {
    style: { display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '0 6px', fontSize: '11px' },
    children: [
      jsx(Codicon, { name: isPlaying ? 'unmute' : 'mute', size: '0.8rem' }),
      jsx('button', {
        type: 'button',
        style: { background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 },
        onClick: () => host.navigate('/voice-document'),
        children: `P.${status.current_page} (${status.current_sentence_index + 1}/${status.total_sentences})`
      })
    ]
  })
}

export default {
  id: PLUGIN_ID,
  name: 'NOEMETRA Voice',
  description: 'Assistente vocale documentale multi-agente deterministico con Pocket TTS e verifica citazioni.',
  defaultEnabled: true,
  register(ctx) {
    // Register full route in Hermes Desktop
    ctx.register({
      id: 'page',
      area: ROUTES_AREA,
      data: { path: '/voice-document' },
      render: () => jsx(VoiceDocumentPage, { ctx })
    })

    // Register sidebar nav icon
    ctx.register({
      id: 'nav',
      area: SIDEBAR_NAV_AREA,
      order: 45,
      data: {
        path: '/voice-document',
        label: 'NOEMETRA Voice',
        codicon: 'book'
      }
    })

    // Register status-bar mini chip
    ctx.register({
      id: 'status-chip',
      area: STATUSBAR_AREAS.right,
      order: 95,
      render: () => jsx(VoiceStatusChip, { ctx })
    })

    // Register palette command
    ctx.register({
      id: 'open-palette',
      area: PALETTE_AREA,
      data: {
        id: 'voice-document.open',
        label: 'Open NOEMETRA Voice Assistant',
        keywords: ['voice', 'document', 'audio', 'tts', 'pocket-tts', 'pdf', 'reader'],
        run: () => host.navigate('/voice-document')
      }
    })
  }
}
