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
  atom,
  Codicon,
  host,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  useValue
} from '@hermes/plugin-sdk'
import { useEffect, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PLUGIN_ID = 'voice-document-assistant'
const ASK_REQUEST_TIMEOUT_MS = 240000
const AUDIO_SYNTH_TIMEOUT_MS = 120000
const DOCUMENT_LOAD_TIMEOUT_MS = 120000

// Modern NOEMETRA Glass & Obsidian Styling synced with Hermes theme variables
const CSS = `
.hv-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
  background: radial-gradient(circle at 12% 0%, color-mix(in srgb, var(--primary, #22d3ee) 7%, transparent), transparent 42%),
              radial-gradient(circle at 88% 15%, rgba(79, 70, 229, 0.08), transparent 45%),
              var(--background, #080c14);
  color: var(--foreground, #f1f5f9);
  font-family: "Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
  overflow: hidden;
}

.hv-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  background: color-mix(in srgb, var(--card, #0d1320) 82%, transparent);
  backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
  gap: 12px;
  flex-wrap: wrap;
}

.hv-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}

.hv-logo-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(34, 211, 238, 0.18), rgba(79, 70, 229, 0.22));
  border: 1px solid rgba(34, 211, 238, 0.35);
  color: var(--primary, #22d3ee);
  box-shadow: 0 0 18px rgba(34, 211, 238, 0.14);
}

.hv-title {
  font-size: 14.5px;
  font-weight: 650;
  letter-spacing: -0.02em;
  color: var(--foreground, #f8fafc);
}

.hv-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  padding: 3px 9px;
  border-radius: 9999px;
  background: color-mix(in srgb, var(--muted, #131b2c) 85%, transparent);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.18));
  color: var(--muted-foreground, #94a3b8);
}

.hv-badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 9999px;
  background: var(--muted-foreground, #64748b);
}

.hv-badge-active {
  background: rgba(34, 211, 238, 0.12);
  color: #22d3ee;
  border-color: rgba(34, 211, 238, 0.35);
}

.hv-badge-active .hv-badge-dot {
  background: #22d3ee;
  box-shadow: 0 0 8px #22d3ee;
  animation: hv-pulse 1.6s ease-in-out infinite;
}

@keyframes hv-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.55; transform: scale(0.85); }
}

.hv-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.hv-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 6px 13px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.2));
  background: color-mix(in srgb, var(--card, #0d1320) 90%, var(--foreground, #fff) 4%);
  color: var(--foreground, #f1f5f9);
  transition: all 0.18s cubic-bezier(0.2, 0.8, 0.2, 1);
}

.hv-btn:hover:not(:disabled) {
  background: color-mix(in srgb, var(--card, #0d1320) 80%, var(--primary, #22d3ee) 10%);
  border-color: color-mix(in srgb, var(--primary, #22d3ee) 45%, transparent);
  transform: translateY(-0.5px);
}

.hv-btn:disabled {
  opacity: 0.42;
  cursor: not-allowed;
}

.hv-btn-icon {
  padding: 6px 8px;
  border-radius: 9px;
}

.hv-btn-primary {
  background: linear-gradient(135deg, #06b6d4, #4f46e5);
  border-color: rgba(34, 211, 238, 0.4);
  color: #ffffff;
  font-weight: 600;
  box-shadow: 0 4px 14px rgba(6, 182, 212, 0.22);
}

.hv-btn-primary:hover:not(:disabled) {
  background: linear-gradient(135deg, #22d3ee, #6366f1);
  border-color: rgba(34, 211, 238, 0.7);
  box-shadow: 0 6px 20px rgba(34, 211, 238, 0.3);
}

.hv-play-hero {
  width: 40px;
  height: 40px;
  padding: 0;
  border-radius: 9999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  border: 1px solid rgba(34, 211, 238, 0.45);
  background: linear-gradient(135deg, #06b6d4, #4f46e5);
  color: #ffffff;
  box-shadow: 0 4px 16px rgba(6, 182, 212, 0.28);
  transition: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
  flex-shrink: 0;
}

.hv-play-hero:hover:not(:disabled) {
  transform: scale(1.05);
  box-shadow: 0 6px 22px rgba(34, 211, 238, 0.4);
}

.hv-play-hero:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  box-shadow: none;
}

.hv-btn-danger {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.28);
  color: #f87171;
}

.hv-btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.18);
  border-color: rgba(239, 68, 68, 0.5);
}

.hv-select {
  padding: 6px 10px;
  border-radius: 10px;
  background: color-mix(in srgb, var(--card, #0d1320) 92%, var(--foreground, #fff) 3%);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.2));
  color: var(--foreground, #f1f5f9);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  outline: none;
  transition: border-color 0.15s ease;
}

.hv-select:hover, .hv-select:focus {
  border-color: color-mix(in srgb, var(--primary, #22d3ee) 55%, transparent);
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
  border-right: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
  background: transparent;
  overflow: hidden;
}

.hv-doc-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  background: color-mix(in srgb, var(--card, #0d1320) 60%, transparent);
  gap: 10px;
}

.hv-doc-title-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 12.5px;
  color: var(--foreground, #f1f5f9);
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hv-page-controls {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  color: var(--muted-foreground, #94a3b8);
  flex-shrink: 0;
}

.hv-doc-content {
  flex: 1;
  padding: 28px 32px;
  overflow-y: auto;
  line-height: 1.85;
  font-size: 14.5px;
  color: color-mix(in srgb, var(--foreground, #f1f5f9) 90%, transparent);
}

.hv-empty-doc {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  height: 100%;
  min-height: 220px;
  gap: 12px;
  color: var(--muted-foreground, #94a3b8);
}

.hv-empty-icon {
  width: 48px;
  height: 48px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: color-mix(in srgb, var(--primary, #22d3ee) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--primary, #22d3ee) 25%, transparent);
  color: var(--primary, #22d3ee);
  font-size: 20px;
}

.hv-sentence {
  display: inline;
  padding: 2px 4px;
  border-radius: 5px;
  cursor: pointer;
  transition: background 0.16s ease, color 0.16s ease;
}

.hv-sentence:hover {
  background: color-mix(in srgb, var(--foreground, #fff) 7%, transparent);
}

.hv-sentence-active {
  background: linear-gradient(90deg, rgba(34, 211, 238, 0.18), rgba(79, 70, 229, 0.16)) !important;
  color: var(--foreground, #ffffff) !important;
  box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.42);
  font-weight: 500;
}

.hv-panel-column {
  display: flex;
  flex-direction: column;
  background: color-mix(in srgb, var(--card, #0d1320) 55%, transparent);
  overflow: hidden;
}

.hv-player-box {
  margin: 14px 16px 0 16px;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.18));
  background: color-mix(in srgb, var(--card, #0d1320) 88%, var(--primary, #22d3ee) 3%);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.16);
}

.hv-player-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}

.hv-eq {
  display: inline-flex;
  align-items: flex-end;
  gap: 2.5px;
  height: 14px;
  padding: 0 4px;
}

.hv-eq span {
  width: 2.5px;
  border-radius: 9999px;
  background: #22d3ee;
  animation: hv-eq-bar 0.9s ease-in-out infinite;
}

.hv-eq span:nth-child(2) { animation-delay: 0.2s; }
.hv-eq span:nth-child(3) { animation-delay: 0.4s; }

@keyframes hv-eq-bar {
  0%, 100% { height: 4px; opacity: 0.55; }
  50% { height: 14px; opacity: 1; }
}

.hv-timeline {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  color: var(--muted-foreground, #94a3b8);
}

.hv-progress-bar {
  flex: 1;
  height: 6px;
  background: color-mix(in srgb, var(--foreground, #fff) 10%, transparent);
  border-radius: 9999px;
  overflow: hidden;
  position: relative;
}

.hv-progress-fill {
  height: 100%;
  border-radius: 9999px;
  background: linear-gradient(90deg, #06b6d4, #6366f1);
  transition: width 0.25s ease;
}

.hv-agents-box {
  padding: 12px 16px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
}

.hv-agents-title {
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted-foreground, #94a3b8);
  margin-bottom: 8px;
  font-weight: 600;
}

.hv-agents-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.hv-agent-card {
  padding: 9px 11px;
  border-radius: 12px;
  background: color-mix(in srgb, var(--card, #0d1320) 90%, var(--foreground, #fff) 2%);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
  font-size: 11px;
  transition: border-color 0.2s ease;
}

.hv-agent-name {
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
  color: var(--foreground, #f1f5f9);
}

.hv-agent-icon {
  color: var(--primary, #22d3ee);
  display: inline-flex;
  align-items: center;
}

.hv-agent-status {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10.5px;
  color: var(--muted-foreground, #94a3b8);
}

.hv-status-dot {
  width: 6px;
  height: 6px;
  border-radius: 9999px;
  flex-shrink: 0;
}

.hv-dot-ok { background: #10b981; }
.hv-dot-busy { background: #22d3ee; box-shadow: 0 0 8px #22d3ee; animation: hv-pulse 1.2s infinite; }
.hv-dot-warn { background: #f59e0b; }

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
  background: linear-gradient(135deg, #0891b2, #4338ca);
  color: #ffffff;
  padding: 9px 14px;
  border-radius: 14px 14px 4px 14px;
  max-width: 85%;
  font-size: 13px;
  line-height: 1.5;
  box-shadow: 0 4px 14px rgba(8, 145, 178, 0.22);
}

.hv-msg-assistant {
  align-self: flex-start;
  background: color-mix(in srgb, var(--card, #0d1320) 92%, var(--foreground, #fff) 3%);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.18));
  padding: 12px 15px;
  border-radius: 14px 14px 14px 4px;
  max-width: 92%;
  font-size: 13px;
  line-height: 1.58;
}

.hv-citations-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}

.hv-citation-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 9px;
  border-radius: 9999px;
  background: rgba(34, 211, 238, 0.1);
  border: 1px solid rgba(34, 211, 238, 0.32);
  color: #22d3ee;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}

.hv-citation-badge:hover {
  background: rgba(34, 211, 238, 0.22);
  border-color: #22d3ee;
}

.hv-verification-box {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 10px;
  padding: 7px 10px;
  border-radius: 9px;
  font-size: 11px;
  font-weight: 500;
}

.hv-verification-valid {
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.28);
  color: #34d399;
}

.hv-verification-invalid {
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  color: #fbbf24;
}

.hv-chat-input-bar {
  padding: 10px 16px;
  border-top: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  background: color-mix(in srgb, var(--card, #0d1320) 75%, transparent);
  display: flex;
  gap: 8px;
  align-items: center;
}

.hv-input {
  flex: 1;
  padding: 9px 14px;
  border-radius: 12px;
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.22));
  background: var(--background, #080c14);
  color: var(--foreground, #f1f5f9);
  font-size: 13px;
  outline: none;
  transition: border-color 0.16s ease, box-shadow 0.16s ease;
}

.hv-input:focus {
  border-color: var(--primary, #22d3ee);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--primary, #22d3ee) 20%, transparent);
}

.hv-privacy-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 18px;
  background: color-mix(in srgb, var(--background, #080c14) 92%, transparent);
  border-top: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  font-size: 11px;
  color: var(--muted-foreground, #94a3b8);
}

.hv-privacy-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.hv-toggle-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  user-select: none;
}
`

function createVoicePlaybackController(ctx) {
  const status = atom(null)
  const docData = atom(null)
  const viewPage = atom(1)
  const chatMessages = atom([])
  const isAsking = atom(false)
  const library = atom([])

  let disposed = false
  let cancelTimer = null
  let clientAudio = null
  let lastPlayedTarget = ''
  let fetchingTarget = ''
  let loadingDocId = ''
  let pollGen = 0

  const scheduleTimeout = (fn, ms) => {
    if (typeof ctx.setTimeout === 'function') {
      return ctx.setTimeout(fn, ms)
    }
    const id = setTimeout(fn, ms)
    return () => clearTimeout(id)
  }

  const currentScopeKey = () => {
    const conn = host?.state?.connectionId?.get?.() || 'local'
    const prof = host?.state?.profile?.get?.() || 'default'
    return `${conn}::${prof}`
  }

  let activeScope = currentScopeKey()
  const scope = atom(activeScope)

  const releaseClientAudio = () => {
    if (clientAudio) {
      try {
        clientAudio.pause()
        clientAudio.removeAttribute('src')
        if (typeof clientAudio.load === 'function') {
          clientAudio.load()
        }
      } catch (_) {}
      clientAudio = null
    }
  }

  const resetPlaybackTargets = () => {
    pollGen++
    releaseClientAudio()
    lastPlayedTarget = ''
    fetchingTarget = ''
  }

  const scheduleNextPoll = (delayMs = 600) => {
    if (disposed) return
    if (cancelTimer) {
      cancelTimer()
      cancelTimer = null
    }
    cancelTimer = scheduleTimeout(() => {
      cancelTimer = null
      void poll()
    }, delayMs)
  }

  const poll = async () => {
    if (disposed) return
    const scopeAtPoll = currentScopeKey()
    const currentGen = ++pollGen
    try {
      const s = await ctx.rest('/status')
      if (disposed || currentGen !== pollGen || currentScopeKey() !== scopeAtPoll) return
      status.set(s)

      if (s && s.doc_id) {
        const curDoc = docData.get()
        if ((!curDoc || curDoc.doc_id !== s.doc_id) && loadingDocId !== s.doc_id) {
          const expectedDocId = s.doc_id
          loadingDocId = expectedDocId
          ctx.rest(`/document/${expectedDocId}`, {
            timeoutMs: DOCUMENT_LOAD_TIMEOUT_MS
          }).then(d => {
            if (disposed || currentScopeKey() !== scopeAtPoll) return
            if (d && d.doc_id === expectedDocId && status.get()?.doc_id === expectedDocId) {
              docData.set(d)
              if (s.current_page) viewPage.set(s.current_page)
            }
          }).catch(() => {}).finally(() => {
            if (loadingDocId === expectedDocId) loadingDocId = ''
          })
        }
      }

      if (s && s.current_page) {
        const isPlaying = s.state === 'playing'
        const curDoc = docData.get()
        if (!curDoc || isPlaying) {
          viewPage.set(s.current_page)
        }

        // Composite key tracking both document ID and sentence index to prevent cross-document audio leakage
        const targetDocId = s.doc_id || (curDoc ? curDoc.doc_id : '')
        const playTargetKey = `${targetDocId}:${s.current_sentence_index}`

        // Client-side local audio streaming kept alive across route/pane visibility changes (apps/desktop/AGENTS.md:130-131)
        if (isPlaying && s.client_playback !== false) {
          if (playTargetKey !== lastPlayedTarget && fetchingTarget !== playTargetKey) {
            fetchingTarget = playTargetKey
            releaseClientAudio()
            try {
              const currentSentIdx = s.current_sentence_index
              const audioData = await ctx.rest(`/audio/sentence/${currentSentIdx}?format=json`, {
                timeoutMs: AUDIO_SYNTH_TIMEOUT_MS
              })

              if (disposed || currentGen !== pollGen || currentScopeKey() !== scopeAtPoll) {
                fetchingTarget = ''
                return
              }

              // Re-validate playback state and active document ID after audio synthesis
              const fresh = await ctx.rest('/status')
              const freshDocId = fresh && fresh.doc_id ? fresh.doc_id : ''
              if (
                disposed ||
                currentGen !== pollGen ||
                currentScopeKey() !== scopeAtPoll ||
                !fresh ||
                fresh.state !== 'playing' ||
                fresh.client_playback === false ||
                `${freshDocId}:${fresh.current_sentence_index}` !== playTargetKey
              ) {
                fetchingTarget = ''
                return
              }

              if (audioData && audioData.audio_base64) {
                const audio = new Audio(`data:audio/wav;base64,${audioData.audio_base64}`)
                const effectiveSpeed = fresh.speed || s.speed
                if (effectiveSpeed) {
                  audio.playbackRate = effectiveSpeed
                }
                const startOffset = fresh.audio_seconds_offset !== undefined ? fresh.audio_seconds_offset : (s.audio_seconds_offset || 0)
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
                  if (disposed || currentScopeKey() !== scopeAtPoll || lastPlayedTarget !== playTargetKey) return
                  ctx.rest('/playback/ack', {
                    method: 'POST',
                    body: { doc_id: freshDocId || targetDocId, sentence_index: currentSentIdx, event: 'started' }
                  }).catch(() => {})
                }, { once: true })
                let lastProgressAck = 0
                audio.addEventListener('timeupdate', () => {
                  if (disposed || currentScopeKey() !== scopeAtPoll || lastPlayedTarget !== playTargetKey) return
                  const now = Date.now()
                  if (now - lastProgressAck > 300) {
                    lastProgressAck = now
                    ctx.rest('/playback/ack', {
                      method: 'POST',
                      body: {
                        doc_id: freshDocId || targetDocId,
                        sentence_index: currentSentIdx,
                        event: 'progress',
                        offset_seconds: audio.currentTime
                      }
                    }).catch(() => {})
                  }
                })
                audio.addEventListener('ended', () => {
                  const sendEndedAck = (retryCount = 0) => {
                    if (disposed || currentScopeKey() !== scopeAtPoll || lastPlayedTarget !== playTargetKey) return
                    ctx.rest('/playback/ack', {
                      method: 'POST',
                      body: { doc_id: freshDocId || targetDocId, sentence_index: currentSentIdx, event: 'ended' }
                    }).catch(() => {
                      if (retryCount < 2 && !disposed && currentScopeKey() === scopeAtPoll && lastPlayedTarget === playTargetKey) {
                        scheduleTimeout(() => sendEndedAck(retryCount + 1), 1000)
                      }
                    })
                  }
                  sendEndedAck()
                }, { once: true })

                if (disposed || currentGen !== pollGen || currentScopeKey() !== scopeAtPoll) {
                  fetchingTarget = ''
                  return
                }
                clientAudio = audio
                lastPlayedTarget = playTargetKey
                fetchingTarget = ''
                audio.play().catch(() => {
                  if (lastPlayedTarget === playTargetKey) {
                    lastPlayedTarget = ''
                    if (clientAudio === audio) {
                      releaseClientAudio()
                    }
                  }
                })
              } else {
                fetchingTarget = ''
              }
            } catch (e) {
              fetchingTarget = ''
              if (lastPlayedTarget === playTargetKey) {
                lastPlayedTarget = ''
              }
            }
          } else if (clientAudio) {
            if (s.speed && clientAudio.playbackRate !== s.speed) {
              clientAudio.playbackRate = s.speed
            }
            if (clientAudio.paused && !clientAudio.ended) {
              if (s.audio_seconds_offset !== undefined && Math.abs(clientAudio.currentTime - s.audio_seconds_offset) > 0.3) {
                try {
                  clientAudio.currentTime = s.audio_seconds_offset
                } catch (_) {}
              }
              clientAudio.play().catch(() => {})
            }
          }
        } else {
          if (clientAudio && !clientAudio.paused) {
            clientAudio.pause()
          }
          if (s.state === 'stopped' || s.state === 'finished') {
            lastPlayedTarget = ''
            fetchingTarget = ''
            releaseClientAudio()
          }
        }
      }
    } catch (err) {
      // backend loading or unavailable
    } finally {
      if (!disposed) {
        scheduleNextPoll(600)
      }
    }
  }

  const handleScopeChange = () => {
    const nextScope = currentScopeKey()
    if (nextScope === activeScope) return
    activeScope = nextScope
    scope.set(nextScope)
    resetPlaybackTargets()
    loadingDocId = ''
    status.set(null)
    docData.set(null)
    library.set([])
    viewPage.set(1)
    chatMessages.set([])
    isAsking.set(false)
    scheduleNextPoll(0)
  }

  const unsubConn = host?.state?.connectionId?.listen?.(handleScopeChange)
  const unsubProf = host?.state?.profile?.listen?.(handleScopeChange)

  // Start background synchronization without autoplay
  scheduleNextPoll(0)

  return {
    scope,
    status,
    docData,
    viewPage,
    chatMessages,
    isAsking,
    library,
    setLibrary: (docs) => library.set(docs),
    currentScopeKey,
    setDocData: (d) => docData.set(d),
    setViewPage: (p) => viewPage.set(p),
    setChatMessages: (updater) => {
      const next = typeof updater === 'function' ? updater(chatMessages.get()) : updater
      chatMessages.set(next)
    },
    setIsAsking: (v) => isAsking.set(v),
    invalidatePlayback: resetPlaybackTargets,
    play: async () => {
      pollGen++
      await ctx.rest('/playback/play', {
        method: 'POST',
        body: { output: 'client' }
      })
      scheduleNextPoll(0)
    },
    pause: async () => {
      pollGen++
      fetchingTarget = ''
      if (clientAudio) clientAudio.pause()
      const cur = status.get()
      if (cur && cur.state === 'playing') {
        status.set({ ...cur, state: 'paused' })
      }
      await ctx.rest('/playback/pause', { method: 'POST' })
      scheduleNextPoll(0)
    },
    resume: async () => {
      pollGen++
      await ctx.rest('/playback/resume', {
        method: 'POST',
        body: { output: 'client' }
      })
      scheduleNextPoll(0)
    },
    stop: async () => {
      resetPlaybackTargets()
      await ctx.rest('/playback/stop', { method: 'POST' })
      scheduleNextPoll(0)
    },
    seekSentence: async (sentenceIdx) => {
      resetPlaybackTargets()
      await ctx.rest('/playback/seek', {
        method: 'POST',
        body: { sentence_index: sentenceIdx }
      })
      scheduleNextPoll(0)
    },
    seekPage: async (page) => {
      resetPlaybackTargets()
      viewPage.set(page)
      await ctx.rest('/playback/seek', {
        method: 'POST',
        body: { page_number: page }
      })
      scheduleNextPoll(0)
    },
    setSpeed: async (speed) => {
      if (clientAudio && !isNaN(speed) && speed > 0) {
        clientAudio.playbackRate = speed
      }
      await ctx.rest('/playback/config', {
        method: 'POST',
        body: { speed }
      })
    },
    dispose: () => {
      if (disposed) return
      const curStatus = status.get()
      const wasClientPlaying = Boolean(
        (clientAudio && !clientAudio.paused && !clientAudio.ended) ||
        (curStatus?.state === 'playing' && curStatus?.client_playback !== false)
      )
      disposed = true
      pollGen++
      fetchingTarget = ''
      lastPlayedTarget = ''
      loadingDocId = ''
      if (cancelTimer) {
        cancelTimer()
        cancelTimer = null
      }
      unsubConn?.()
      unsubProf?.()
      releaseClientAudio()
      status.set(null)
      if (wasClientPlaying) {
        ctx.rest('/playback/pause', { method: 'POST' }).catch(() => {})
      }
    }
  }
}

function VoiceDocumentPage({ ctx, controller }) {
  const status = useValue(controller.status)
  const docData = useValue(controller.docData)
  const viewPage = useValue(controller.viewPage)
  const chatMessages = useValue(controller.chatMessages)
  const isAsking = useValue(controller.isAsking)
  const library = useValue(controller.library)
  const [questionInput, setQuestionInput] = useState('')
  const [isRecording, setIsRecording] = useState(false)
  const fileInputRef = useRef(null)

  const activeScope = useValue(controller.scope)

  // Load library for active profile/connection
  const refreshLibrary = async () => {
    const scopeAtStart = controller.currentScopeKey()
    try {
      const res = await ctx.rest('/library')
      if (controller.currentScopeKey() !== scopeAtStart) return
      if (res && res.documents) {
        controller.setLibrary(res.documents)
      } else {
        controller.setLibrary([])
      }
    } catch (err) {
      if (controller.currentScopeKey() === scopeAtStart) {
        controller.setLibrary([])
      }
      console.error('Error fetching library:', err)
    }
  }

  useEffect(() => {
    controller.setLibrary([])
    refreshLibrary()
  }, [activeScope])

  // Playback handlers delegated to plugin-scoped controller
  const handlePlay = async () => {
    try {
      await controller.play()
    } catch (err) {
      host.notifyError(err, 'Errore avvio riproduzione audio')
    }
  }

  const handlePause = async () => {
    try {
      await controller.pause()
    } catch (err) {
      host.notifyError(err, 'Errore pausa audio')
    }
  }

  const handleResume = async () => {
    try {
      await controller.resume()
    } catch (err) {
      host.notifyError(err, 'Errore ripresa audio')
    }
  }

  const handleStop = async () => {
    try {
      await controller.stop()
    } catch (err) {
      host.notifyError(err, 'Errore stop audio')
    }
  }

  const handleSeekSentence = async (sentenceIdx) => {
    try {
      await controller.seekSentence(sentenceIdx)
    } catch (err) {
      console.error(err)
    }
  }

  const handleSeekPage = async (page) => {
    try {
      await controller.seekPage(page)
    } catch (err) {
      console.error(err)
    }
  }

  const handleSeekCitation = async (docId, page) => {
    try {
      const needsSwitch = Boolean(
        docId && (!docData || docData.doc_id !== docId || (status?.doc_id && status.doc_id !== docId))
      )
      if (needsSwitch) {
        controller.invalidatePlayback()
        await ctx.rest('/select_document', {
          method: 'POST',
          body: { doc_id: docId },
          timeoutMs: DOCUMENT_LOAD_TIMEOUT_MS
        })
        const switched = await ctx.rest(`/document/${docId}`, {
          timeoutMs: DOCUMENT_LOAD_TIMEOUT_MS
        })
        controller.setDocData(switched)
      }
      await handleSeekPage(page)
    } catch (err) {
      host.notifyError(err, 'Errore navigazione citazione')
    }
  }

  const handleModelChange = async (e) => {
    const tts_model = e.target.value
    try {
      await ctx.rest('/playback/config', {
        method: 'POST',
        body: { tts_model },
        timeoutMs: AUDIO_SYNTH_TIMEOUT_MS
      })
      host.notify({ kind: 'info', message: `Modello Pocket TTS impostato su: ${tts_model}` })
    } catch (err) {
      host.notifyError(err, 'Errore cambio modello')
    }
  }

  const handleSpeedChange = async (e) => {
    const speed = parseFloat(e.target.value)
    try {
      await controller.setSpeed(speed)
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
    const scopeAtUpload = controller.currentScopeKey()

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
          },
          timeoutMs: DOCUMENT_LOAD_TIMEOUT_MS
        })
        if (controller.currentScopeKey() !== scopeAtUpload) return
        if (res && res.document) {
          controller.invalidatePlayback()
          controller.setDocData(res.document)
          controller.setViewPage(1)
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
    const scopeAtSelect = controller.currentScopeKey()
    controller.invalidatePlayback()
    try {
      const res = await ctx.rest('/select_document', {
        method: 'POST',
        body: { doc_id: docId },
        timeoutMs: DOCUMENT_LOAD_TIMEOUT_MS
      })
      if (controller.currentScopeKey() !== scopeAtSelect) return
      if (res && res.document) {
        controller.setDocData(res.document)
        controller.setViewPage(1)
        host.notify({ kind: 'info', message: `Documento attivato: ${res.document.title}` })
      }
    } catch (err) {
      host.notifyError(err, 'Errore selezione documento')
    }
  }

  // Ask question bound to the displayed document ID
  const handleAsk = async () => {
    const q = questionInput.trim()
    const targetDocId = docData ? docData.doc_id : (status?.doc_id || null)
    if (!q || isAsking || !targetDocId) return
    const scopeAtAsk = controller.currentScopeKey()
    controller.setIsAsking(true)
    setQuestionInput('')

    const userMsg = { role: 'user', text: q, doc_id: targetDocId, time: new Date().toLocaleTimeString() }
    controller.setChatMessages(prev => [...prev, userMsg])

    try {
      const answer = await ctx.rest('/ask', {
        method: 'POST',
        body: { question: q, doc_id: targetDocId },
        timeoutMs: ASK_REQUEST_TIMEOUT_MS
      })
      if (controller.currentScopeKey() !== scopeAtAsk) return
      const resolvedDocId = answer.doc_id || targetDocId
      const latestDoc = controller.docData.get()
      const assistantMsg = {
        role: 'assistant',
        text: answer.answer,
        doc_id: resolvedDocId,
        doc_title: answer.doc_title || (latestDoc?.doc_id === resolvedDocId ? latestDoc?.title : undefined),
        citations: answer.citations || [],
        verification: answer.verification,
        model_used: answer.model_used,
        time: new Date().toLocaleTimeString()
      }
      controller.setChatMessages(prev => [...prev, assistantMsg])
    } catch (err) {
      if (controller.currentScopeKey() !== scopeAtAsk) return
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
      controller.setChatMessages(prev => [...prev, errorMsg])
    } finally {
      if (controller.currentScopeKey() === scopeAtAsk) {
        controller.setIsAsking(false)
      }
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
              jsx('span', {
                className: 'hv-logo-pill',
                children: jsx(Codicon, { name: 'audio-lines', size: '1.1rem' })
              }),
              jsx('span', { className: 'hv-title', children: 'NOEMETRA Voice' }),
              jsxs('span', {
                className: `hv-badge ${isPlaying ? 'hv-badge-active' : ''}`,
                children: [
                  jsx('span', { className: 'hv-badge-dot' }),
                  status?.state ? status.state.toUpperCase() : 'DISCONNESSO'
                ]
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
                    value: doc.doc_id,
                    children: `${doc.title} (${doc.total_pages} pag.)`
                  }, doc.doc_id))
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
                  jsx(Codicon, { name: 'cloud-upload', size: '0.95rem' }),
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

      // Missing dependencies recovery banner
      status?.error === 'missing_dependencies' && jsxs('div', {
        className: 'hv-missing-deps-banner',
        style: {
          background: 'rgba(234, 88, 12, 0.12)',
          border: '1px solid #ea580c',
          borderRadius: '12px',
          padding: '12px 16px',
          margin: '12px 20px 0 20px',
          color: '#f97316',
          fontSize: '0.88rem',
          lineHeight: '1.4'
        },
        children: [
          jsx('strong', { children: 'Dipendenze Python mancanti per il Voice Assistant: ' }),
          jsx('div', {
            style: { margin: '6px 0', color: '#e2e8f0' },
            children: status.detail || 'Le dipendenze del voice assistant (pocket-tts, pymupdf, sounddevice, soundfile) non sono presenti nel runtime Python.'
          }),
          jsx('div', {
            style: {
              background: '#0f172a',
              padding: '6px 10px',
              borderRadius: '6px',
              fontFamily: 'monospace',
              color: '#38bdf8',
              margin: '6px 0',
              userSelect: 'all'
            },
            children: status.repair_command || 'hermes pm install --extra voice-document-assistant'
          }),
          jsx('div', {
            style: { fontSize: '0.8rem', color: '#94a3b8' },
            children: 'Dopo l\'installazione tramite il gestore pacchetti, riavviare l\'applicazione Hermes o il gateway.'
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
                  jsxs('span', {
                    className: 'hv-doc-title-pill',
                    children: [
                      jsx(Codicon, { name: 'book', size: '0.95rem' }),
                      docData?.title || 'Nessun documento attivo'
                    ]
                  }),
                  jsxs('div', {
                    className: 'hv-page-controls',
                    children: [
                      jsx('button', {
                        className: 'hv-btn hv-btn-icon',
                        disabled: viewPage <= 1,
                        onClick: () => handleSeekPage(viewPage - 1),
                        children: jsx(Codicon, { name: 'chevron-left', size: '0.9rem' })
                      }),
                      jsx('span', { children: `Pagina ${viewPage} / ${totalPages}` }),
                      jsx('button', {
                        className: 'hv-btn hv-btn-icon',
                        disabled: viewPage >= totalPages,
                        onClick: () => handleSeekPage(viewPage + 1),
                        children: jsx(Codicon, { name: 'chevron-right', size: '0.9rem' })
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
                        className: `hv-sentence ${isCurrentSpeaking ? 'hv-sentence-active' : ''}`,
                        onClick: () => handleSeekSentence(sent.sentence_index),
                        title: `Frase #${sent.sentence_index + 1} (Clicca per leggere)`,
                        children: sent.text + ' '
                      }, sent.sentence_index)
                    })
                  : jsxs('div', {
                      className: 'hv-empty-doc',
                      children: [
                        jsx('div', {
                          className: 'hv-empty-icon',
                          children: jsx(Codicon, { name: docData ? 'warning' : 'cloud-upload', size: '1.35rem' })
                        }),
                        jsx('div', {
                          style: { maxWidth: '340px', fontSize: '13px', lineHeight: 1.55 },
                          children: docData
                            ? 'Questa pagina non contiene testo estratto.'
                            : 'Carica un file PDF italiano o selezionalo dalla biblioteca per avviare la lettura neurale e la verifica documentale.'
                        })
                      ]
                    })
              })
            ]
          }),

          // Right Column: Controls, Agents, Chat
          jsxs('div', {
            className: 'hv-panel-column',
            children: [
              // Modern Player Card
              jsxs('div', {
                className: 'hv-player-box',
                children: [
                  jsxs('div', {
                    className: 'hv-player-controls',
                    children: [
                      !isPlaying
                        ? jsx('button', {
                            className: 'hv-play-hero',
                            onClick: isPaused ? handleResume : handlePlay,
                            disabled: !docData,
                            title: isPaused ? 'Riprendi ascolto' : 'Ascolta documento',
                            children: jsx(Codicon, { name: 'play', size: '1.05rem', style: { marginLeft: '2px' } })
                          })
                        : jsx('button', {
                            className: 'hv-play-hero',
                            onClick: handlePause,
                            title: 'Metti in pausa',
                            children: jsx(Codicon, { name: 'debug-pause', size: '1.05rem' })
                          }),
                      jsxs('button', {
                        className: 'hv-btn hv-btn-danger',
                        onClick: handleStop,
                        disabled: !status || status.state === 'stopped' || status.state === 'idle',
                        children: [
                          jsx(Codicon, { name: 'debug-stop', size: '0.85rem' }),
                          'Stop'
                        ]
                      }),
                      isPlaying && jsxs('div', {
                        className: 'hv-eq',
                        'aria-hidden': 'true',
                        children: [jsx('span', {}), jsx('span', {}), jsx('span', {})]
                      }),
                      jsx('span', {
                        style: {
                          marginLeft: 'auto',
                          fontSize: '11.5px',
                          color: 'var(--muted-foreground, #94a3b8)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '220px'
                        },
                        children: status?.current_sentence_text
                          ? `"${status.current_sentence_text.slice(0, 48)}..."`
                          : (isPaused ? 'In pausa' : 'Pronto alla lettura')
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
                  jsx('div', { className: 'hv-agents-title', children: 'Triade Multi-Agente' }),
                  jsxs('div', {
                    className: 'hv-agents-cards',
                    children: [
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: [
                              jsx('span', { className: 'hv-agent-icon', children: jsx(Codicon, { name: 'library', size: '0.9rem' }) }),
                              'Bibliotecario'
                            ]
                          }),
                          jsxs('div', {
                            className: 'hv-agent-status',
                            children: [
                              jsx('span', { className: `hv-status-dot ${status?.agents?.librarian === 'searching' ? 'hv-dot-busy' : 'hv-dot-ok'}` }),
                              status?.agents?.librarian === 'searching' ? 'Ricerca...' : 'Indicizzato'
                            ]
                          })
                        ]
                      }),
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: [
                              jsx('span', { className: 'hv-agent-icon', children: jsx(Codicon, { name: 'chip', size: '0.9rem' }) }),
                              'Analista'
                            ]
                          }),
                          jsxs('div', {
                            className: 'hv-agent-status',
                            children: [
                              jsx('span', { className: `hv-status-dot ${isAsking || status?.agents?.analyst === 'generating' ? 'hv-dot-busy' : 'hv-dot-ok'}` }),
                              isAsking || status?.agents?.analyst === 'generating' ? 'Generazione...' : 'Ollama Pronto'
                            ]
                          })
                        ]
                      }),
                      jsxs('div', {
                        className: 'hv-agent-card',
                        children: [
                          jsxs('div', {
                            className: 'hv-agent-name',
                            children: [
                              jsx('span', { className: 'hv-agent-icon', children: jsx(Codicon, { name: 'shield-check', size: '0.9rem' }) }),
                              'Verificatore'
                            ]
                          }),
                          jsxs('div', {
                            className: 'hv-agent-status',
                            children: [
                              jsx('span', {
                                className: `hv-status-dot ${
                                  status?.agents?.verifier === 'invalid' ? 'hv-dot-warn' : 'hv-dot-ok'
                                }`
                              }),
                              status?.agents?.verifier === 'valid'
                                ? 'Convalidato'
                                : status?.agents?.verifier === 'invalid'
                                ? 'Discrepanze'
                                : 'Pronto'
                            ]
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
                      ? jsxs('div', {
                          className: 'hv-empty-doc',
                          style: { minHeight: '140px' },
                          children: [
                            jsx('div', {
                              className: 'hv-empty-icon',
                              style: { width: '38px', height: '38px', borderRadius: '11px' },
                              children: jsx(Codicon, { name: 'sparkle', size: '1.1rem' })
                            }),
                            jsx('div', {
                              style: { maxWidth: '320px', fontSize: '12.5px', lineHeight: 1.55 },
                              children: 'Poni una domanda sul documento. L\'Analista risponderà basandosi sulle evidenze estratte e il Verificatore convaliderà ogni numero di pagina.'
                            })
                          ]
                        })
                      : chatMessages.map((msg, i) => {
                          if (msg.role === 'user') {
                            return jsxs('div', {
                              className: 'hv-chat-msg',
                              children: [
                                jsx('div', { className: 'hv-msg-user', children: msg.text })
                              ]
                            }, i)
                          } else {
                            const isValid = msg.verification?.is_valid
                            return jsxs('div', {
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
                                          style: { fontSize: '11px', color: 'var(--muted-foreground, #94a3b8)', alignSelf: 'center' },
                                          children: 'Fonti:'
                                        }),
                                        msg.citations.map((cit, cIdx) => jsxs('button', {
                                          className: 'hv-citation-badge',
                                          onClick: () => handleSeekCitation(msg.doc_id, cit.page_number),
                                          title: `Clicca per aprire Pagina ${cit.page_number}\n"${cit.verbatim_quote}"`,
                                          children: [
                                            jsx(Codicon, { name: 'link-external', size: '0.7rem' }),
                                            `Pag. ${cit.page_number}`
                                          ]
                                        }, cIdx))
                                      ]
                                    }),
                                    // Verification Badge
                                    msg.verification && jsxs('div', {
                                      className: `hv-verification-box ${isValid ? 'hv-verification-valid' : 'hv-verification-invalid'}`,
                                      children: [
                                        jsx(Codicon, { name: isValid ? 'verified-filled' : 'warning', size: '0.9rem' }),
                                        isValid
                                          ? `Verificatore: ${msg.verification.notes || 'Citazioni convalidate con precisione del 100%'}`
                                          : `Verificatore: ${msg.verification.notes || 'Citazioni non conformi al testo sorgente.'}`
                                      ]
                                    })
                                  ]
                                })
                              ]
                            }, i)
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
                        className: `hv-btn hv-btn-icon ${isRecording ? 'hv-btn-danger' : ''}`,
                        onClick: toggleRecording,
                        title: 'Input microfonico vocale',
                        children: jsx(Codicon, { name: isRecording ? 'mic-filled' : 'mic', size: '0.95rem' })
                      }),
                      jsxs('button', {
                        className: 'hv-btn hv-btn-primary',
                        onClick: handleAsk,
                        disabled: isAsking || !questionInput.trim() || !docData,
                        children: [
                          jsx(Codicon, { name: isAsking ? 'loading' : 'send', size: '0.9rem' }),
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
                    className: 'hv-privacy-status',
                    children: [
                      jsx(Codicon, { name: 'shield-check', size: '0.9rem', style: { color: '#10b981' } }),
                      'Routing: ',
                      jsx('strong', { style: { color: 'var(--foreground, #f1f5f9)' }, children: 'Ollama Locale (gemma4:12b)' }),
                      ' · Privacy locale attiva'
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

// Mini status-bar widget sharing the plugin-scoped playback controller
function VoiceStatusChip({ controller }) {
  const status = useValue(controller.status)

  if (!status || status.state === 'idle') return null

  const isPlaying = status.state === 'playing'
  const isPaused = status.state === 'paused'

  return jsxs('div', {
    style: { display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '0 6px', fontSize: '11px' },
    children: [
      (isPlaying || isPaused)
        ? jsx('button', {
            type: 'button',
            title: isPlaying ? 'Pausa lettura vocale' : 'Riprendi lettura vocale',
            'aria-label': isPlaying ? 'Pausa lettura vocale' : 'Riprendi lettura vocale',
            style: { background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, display: 'inline-flex', alignItems: 'center' },
            onClick: () => {
              void (isPlaying ? controller.pause() : controller.resume()).catch(() => {})
            },
            children: jsx(Codicon, { name: isPlaying ? 'debug-pause' : 'play', size: '0.8rem' })
          })
        : jsx(Codicon, { name: 'mute', size: '0.8rem' }),
      jsx('button', {
        type: 'button',
        style: { background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 },
        onClick: () => host.navigate('/voice-document'),
        children: `P.${status.current_page} (${status.current_sentence_index + 1}/${status.total_sentences})`
      })
    ]
  })
}

export { createVoicePlaybackController }

export default {
  id: PLUGIN_ID,
  name: 'NOEMETRA Voice',
  description: 'Assistente vocale documentale multi-agente deterministico con Pocket TTS e verifica citazioni.',
  defaultEnabled: true,
  register(ctx) {
    const controller = createVoicePlaybackController(ctx)
    ctx.onDispose(() => controller.dispose())

    // Register full route in Hermes Desktop
    ctx.register({
      id: 'page',
      area: ROUTES_AREA,
      data: { path: '/voice-document' },
      render: () => jsx(VoiceDocumentPage, { ctx, controller })
    })

    // Register sidebar nav icon
    ctx.register({
      id: 'nav',
      area: SIDEBAR_NAV_AREA,
      order: 45,
      data: {
        path: '/voice-document',
        label: 'NOEMETRA Voice',
        codicon: 'audio-lines'
      }
    })

    // Register status-bar mini chip
    ctx.register({
      id: 'status-chip',
      area: STATUSBAR_AREAS.right,
      order: 95,
      render: () => jsx(VoiceStatusChip, { controller })
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
