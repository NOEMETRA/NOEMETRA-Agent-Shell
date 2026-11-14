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
import { useEffect, useMemo, useRef, useState } from 'react'
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

/* Readable Verbatim Document Structure */
.hv-doc-para {
  margin: 0 0 14px 0;
  line-height: 1.78;
}

.hv-doc-para:last-child {
  margin-bottom: 0;
}

.hv-doc-meta-line {
  font-size: 11.5px;
  letter-spacing: 0.03em;
  color: var(--muted-foreground, #94a3b8);
  padding: 4px 10px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--foreground, #fff) 4%, transparent);
  border-left: 2px solid color-mix(in srgb, var(--primary, #22d3ee) 45%, transparent);
  display: inline-block;
  margin-bottom: 10px;
}

.hv-doc-heading {
  display: block;
  font-size: 15.5px;
  font-weight: 700;
  letter-spacing: -0.015em;
  color: var(--foreground, #f8fafc);
  margin: 10px 0 4px 0;
  padding: 4px 8px;
  border-radius: 7px;
  background: color-mix(in srgb, var(--primary, #22d3ee) 7%, transparent);
}

.hv-doc-question-title {
  display: block;
  font-size: 14px;
  font-weight: 650;
  color: color-mix(in srgb, var(--primary, #22d3ee) 70%, var(--foreground, #f8fafc));
  margin: 8px 0 3px 0;
  padding: 3px 8px;
  border-left: 2.5px solid var(--primary, #22d3ee);
  border-radius: 0 6px 6px 0;
  background: color-mix(in srgb, var(--primary, #22d3ee) 6%, transparent);
}

.hv-doc-list-item {
  display: block;
  padding: 3px 8px 3px 16px;
  margin: 2px 0;
  border-radius: 6px;
}

/* Markdown Styling for AI Analyst Synthesis */
.hv-md-root {
  display: flex;
  flex-direction: column;
  gap: 8px;
  color: inherit;
  word-break: break-word;
}

.hv-md-h1, .hv-md-h2, .hv-md-h3, .hv-md-h4 {
  margin: 4px 0 2px 0;
  font-weight: 700;
  letter-spacing: -0.015em;
  color: var(--foreground, #f8fafc);
  line-height: 1.35;
}

.hv-md-h1 { font-size: 15px; }
.hv-md-h2 { font-size: 14px; }
.hv-md-h3, .hv-md-h4 { font-size: 13.2px; color: color-mix(in srgb, var(--primary, #22d3ee) 60%, var(--foreground, #f8fafc)); }

.hv-md-p {
  margin: 0;
  line-height: 1.6;
}

.hv-md-ul, .hv-md-ol {
  margin: 2px 0;
  padding-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.hv-md-li {
  line-height: 1.55;
}

.hv-md-quote {
  margin: 2px 0;
  padding: 6px 11px;
  border-left: 2.5px solid var(--primary, #22d3ee);
  background: color-mix(in srgb, var(--primary, #22d3ee) 7%, transparent);
  border-radius: 0 8px 8px 0;
  color: color-mix(in srgb, var(--foreground, #f1f5f9) 86%, transparent);
  font-style: italic;
}

.hv-md-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  padding: 1.5px 5px;
  border-radius: 5px;
  background: color-mix(in srgb, var(--foreground, #fff) 10%, transparent);
  color: color-mix(in srgb, var(--primary, #22d3ee) 80%, #f8fafc);
}

.hv-md-pre {
  margin: 4px 0;
  padding: 10px 12px;
  border-radius: 10px;
  background: rgba(2, 6, 23, 0.72);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.18));
  overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
}

.hv-md-table-wrap {
  overflow-x: auto;
  margin: 4px 0;
  border-radius: 9px;
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.2));
}

.hv-md-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.hv-md-table th, .hv-md-table td {
  padding: 6px 9px;
  text-align: left;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
}

.hv-md-table th {
  font-weight: 650;
  background: color-mix(in srgb, var(--foreground, #fff) 5%, transparent);
}

.hv-md-hr {
  border: none;
  border-top: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.2));
  margin: 4px 0;
}

.hv-md-page-ref {
  display: inline-flex;
  align-items: center;
  padding: 0 6px;
  margin: 0 2px;
  border-radius: 9999px;
  background: rgba(34, 211, 238, 0.14);
  border: 1px solid rgba(34, 211, 238, 0.35);
  color: #22d3ee;
  font-size: 11px;
  font-weight: 650;
  cursor: pointer;
  line-height: 1.6;
  vertical-align: baseline;
}

.hv-md-page-ref:hover {
  background: rgba(34, 211, 238, 0.24);
}

.hv-sentence-cited {
  background: rgba(245, 158, 11, 0.24);
  border-radius: 5px;
  padding: 2px 5px;
  box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.55);
}

.hv-sentence-search-active {
  background: rgba(34, 211, 238, 0.16);
  border-radius: 5px;
  padding: 2px 5px;
  box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.55);
}

.hv-search-mark {
  background: rgba(250, 204, 21, 0.35);
  color: inherit;
  border-radius: 3px;
  padding: 0 2px;
}

.hv-doc-toolbar-actions {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.hv-toc-popover {
  max-height: 220px;
  overflow-y: auto;
  padding: 8px 12px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
  background: color-mix(in srgb, var(--background, #080c14) 94%, transparent);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.hv-toc-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  width: 100%;
  text-align: left;
  padding: 6px 10px;
  border-radius: 8px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--foreground, #e2e8f0);
  font-size: 12px;
  cursor: pointer;
}

.hv-toc-item:hover {
  background: color-mix(in srgb, var(--primary, #22d3ee) 10%, transparent);
  border-color: color-mix(in srgb, var(--primary, #22d3ee) 30%, transparent);
}

.hv-toc-item-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hv-toc-kind {
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 9999px;
  background: rgba(34, 211, 238, 0.14);
  color: #22d3ee;
  flex-shrink: 0;
}

.hv-toc-page {
  font-size: 11px;
  color: var(--muted-foreground, #94a3b8);
  flex-shrink: 0;
}

.hv-search-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.16));
  background: color-mix(in srgb, var(--background, #080c14) 90%, transparent);
}

.hv-search-count {
  font-size: 11.5px;
  color: var(--muted-foreground, #94a3b8);
  white-space: nowrap;
  min-width: 54px;
  text-align: center;
}

.hv-player-options {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-top: 8px;
  font-size: 11.5px;
  color: var(--muted-foreground, #94a3b8);
}

.hv-msg-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: 6px;
}

.hv-msg-model-tag {
  font-size: 10.5px;
  color: var(--muted-foreground, #94a3b8);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.hv-chat-model-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  background: color-mix(in srgb, var(--background, #080c14) 86%, transparent);
  flex-wrap: wrap;
}

.hv-chat-model-label {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11.5px;
  font-weight: 650;
  color: var(--muted-foreground, #94a3b8);
  white-space: nowrap;
}

.hv-llm-select {
  flex: 1;
  min-width: 170px;
  padding: 5px 10px;
  font-size: 12px;
}

.hv-ollama-pill {
  font-size: 10.5px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 9999px;
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.22));
  color: var(--muted-foreground, #94a3b8);
  white-space: nowrap;
}

.hv-ollama-pill-online {
  border-color: rgba(16, 185, 129, 0.4);
  color: #34d399;
  background: rgba(16, 185, 129, 0.1);
}

.hv-local-dirs-panel {
  padding: 10px 14px;
  border-bottom: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.14));
  background: color-mix(in srgb, var(--background, #080c14) 92%, transparent);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.hv-local-dir-row {
  display: flex;
  align-items: center;
  gap: 6px;
}

.hv-local-dirs-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.hv-local-dir-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 6px;
  background: color-mix(in srgb, var(--background, #0f172a) 80%, transparent);
  border: 1px solid var(--ui-stroke-tertiary, rgba(148, 163, 184, 0.22));
  color: var(--foreground, #e2e8f0);
}

.hv-model-hint {
  font-size: 11px;
  color: var(--muted-foreground, #94a3b8);
}

.hv-msg-speak-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 9999px;
  border: 1px solid color-mix(in srgb, var(--primary, #22d3ee) 32%, transparent);
  background: color-mix(in srgb, var(--primary, #22d3ee) 10%, transparent);
  color: color-mix(in srgb, var(--primary, #22d3ee) 80%, #f8fafc);
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}

.hv-msg-speak-btn:hover:not(:disabled) {
  background: color-mix(in srgb, var(--primary, #22d3ee) 20%, transparent);
}

.hv-msg-speak-btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
`

function createVoicePlaybackController(ctx) {
  const status = atom(null)
  const docData = atom(null)
  const viewPage = atom(1)
  const chatMessages = atom([])
  const isAsking = atom(false)
  const library = atom([])
  const modelsInfo = atom(null)

  let disposed = false
  let cancelTimer = null
  let clientAudio = null
  let lastPlayedTarget = ''
  let fetchingTarget = ''
  let loadingDocId = ''
  let cachedTtsModel = ''
  let lastFollowedPageKey = ''
  const audioPrefetchCache = new Map()
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
    lastFollowedPageKey = ''
    audioPrefetchCache.clear()
  }

  const findNextPlayableSentenceIdx = (doc, fromSentIdx, skipHeaders = true) => {
    if (!doc || !Array.isArray(doc.pages)) return null
    const all = []
    for (const p of doc.pages) {
      if (Array.isArray(p.sentences)) {
        for (const s of p.sentences) all.push(s)
      }
    }
    if (all.length === 0) return null
    const pos = all.findIndex(s => s.sentence_index === fromSentIdx)
    if (pos < 0) return null
    for (let i = pos + 1; i < all.length; i++) {
      const cand = all[i]
      const isMeta = Boolean(cand.is_header_footer) || classifyDocumentSentence(cand.text) === 'meta'
      if (skipHeaders && isMeta) continue
      return cand.sentence_index
    }
    return null
  }

  const fetchSentenceAudioData = (targetDocId, currentSentIdx, ttsModel) => {
    const cacheKey = `${targetDocId}:${currentSentIdx}:${ttsModel || 'italian'}`
    if (audioPrefetchCache.has(cacheKey)) {
      return audioPrefetchCache.get(cacheKey)
    }
    if (audioPrefetchCache.size >= 8) {
      const oldestKey = audioPrefetchCache.keys().next().value
      if (oldestKey !== undefined) audioPrefetchCache.delete(oldestKey)
    }
    const reqPromise = ctx.rest(`/audio/sentence/${currentSentIdx}?format=json`, {
      timeoutMs: AUDIO_SYNTH_TIMEOUT_MS
    }).then(data => {
      if (!data || !data.audio_base64) {
        audioPrefetchCache.delete(cacheKey)
      }
      return data
    }).catch(err => {
      audioPrefetchCache.delete(cacheKey)
      throw err
    })
    audioPrefetchCache.set(cacheKey, reqPromise)
    return reqPromise
  }

  let llmWriteSeq = 0
  let llmWriteQueue = Promise.resolve()
  let lastConfirmedLlm = null
  let pendingBaselineLlm = null

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
      if (s?.llm_model) {
        lastConfirmedLlm = {
          llm_model: s.llm_model,
          llm_provider: s.llm_provider || 'ollama'
        }
      }
      if (s?.tts_model && cachedTtsModel && s.tts_model !== cachedTtsModel) {
        audioPrefetchCache.clear()
      }
      if (s?.tts_model) cachedTtsModel = s.tts_model
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
        const targetDocId = s.doc_id || (curDoc ? curDoc.doc_id : '')
        const pageKey = `${targetDocId}:${s.current_page}`
        if (!curDoc || (isPlaying && pageKey !== lastFollowedPageKey)) {
          lastFollowedPageKey = pageKey
          viewPage.set(s.current_page)
        }

        // Composite key tracking both document ID and sentence index to prevent cross-document audio leakage
        const playTargetKey = `${targetDocId}:${s.current_sentence_index}`

        // Client-side local audio streaming kept alive across route/pane visibility changes (apps/desktop/AGENTS.md:130-131)
        if (isPlaying && s.client_playback !== false) {
          if (playTargetKey !== lastPlayedTarget && fetchingTarget !== playTargetKey) {
            fetchingTarget = playTargetKey
            releaseClientAudio()
            try {
              const currentSentIdx = s.current_sentence_index
              const ttsModelAtFetch = s.tts_model || cachedTtsModel || 'italian'
              const audioData = await fetchSentenceAudioData(targetDocId, currentSentIdx, ttsModelAtFetch)

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
                const nextPrefetchIdx = findNextPlayableSentenceIdx(
                  docData.get() || curDoc,
                  currentSentIdx,
                  (fresh.skip_headers_footers ?? s.skip_headers_footers) !== false
                )
                if (nextPrefetchIdx !== null) {
                  void fetchSentenceAudioData(
                    freshDocId || targetDocId,
                    nextPrefetchIdx,
                    fresh.tts_model || ttsModelAtFetch
                  ).catch(() => {})
                }
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
    modelsInfo.set(null)
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
    modelsInfo,
    setLibrary: (docs) => library.set(docs),
    setModelsInfo: (info) => modelsInfo.set(info),
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
    setSkipHeadersFooters: async (enabled) => {
      audioPrefetchCache.clear()
      const cur = status.get()
      if (cur) {
        status.set({ ...cur, skip_headers_footers: Boolean(enabled) })
      }
      await ctx.rest('/playback/config', {
        method: 'POST',
        body: { skip_headers_footers: Boolean(enabled) }
      })
      scheduleNextPoll(0)
    },
    setLlmModel: (llmModel, llmProvider = 'ollama', llmBaseUrl = null) => {
      const cleanModel = String(llmModel || '').trim()
      const cleanProvider = String(llmProvider || 'ollama').trim() || 'ollama'
      const cleanBaseUrl = llmBaseUrl ? String(llmBaseUrl).trim() : ''
      if (!cleanModel) return Promise.resolve()
      const writeSeq = ++llmWriteSeq
      pollGen += 1
      const cur = status.get()
      if (!pendingBaselineLlm) {
        if (lastConfirmedLlm) {
          pendingBaselineLlm = { ...lastConfirmedLlm }
        } else if (cur) {
          pendingBaselineLlm = {
            llm_model: cur.llm_model,
            llm_provider: cur.llm_provider || 'ollama'
          }
        }
      }
      if (cur) {
        status.set({ ...cur, llm_model: cleanModel, llm_provider: cleanProvider })
      }
      const task = llmWriteQueue.then(async () => {
        try {
          await ctx.rest('/playback/config', {
            method: 'POST',
            body: {
              llm_model: cleanModel,
              llm_provider: cleanProvider,
              ...(cleanBaseUrl ? { llm_base_url: cleanBaseUrl } : {})
            }
          })
          lastConfirmedLlm = { llm_model: cleanModel, llm_provider: cleanProvider }
          if (writeSeq === llmWriteSeq) {
            pendingBaselineLlm = null
          }
        } catch (err) {
          if (writeSeq === llmWriteSeq) {
            const rollback = lastConfirmedLlm || pendingBaselineLlm
            pendingBaselineLlm = null
            const latest = status.get()
            if (latest && rollback?.llm_model) {
              status.set({
                ...latest,
                llm_model: rollback.llm_model,
                llm_provider: rollback.llm_provider || latest.llm_provider
              })
            }
          }
          throw err
        } finally {
          if (writeSeq === llmWriteSeq) {
            scheduleNextPoll(0)
          }
        }
      })
      llmWriteQueue = task.catch(() => {})
      return task
    },
    invalidatePrefetch: () => {
      audioPrefetchCache.clear()
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

const INLINE_MD_TOKEN_RE = /(\[Pagina\s+(\d+)\]|`[^`\n]+`|\*\*[^*\n]+?\*\*|__[^_\n]+?__|(?<!\*)\*[^*\n]+?\*(?!\*)|(?<!_)_[^_\n]+?_(?!_)|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\))/gi

function renderMarkdownInline(text, onJumpPage, keyPrefix = 'in') {
  if (!text) return text
  const parts = []
  let cursor = 0
  let match
  const re = new RegExp(INLINE_MD_TOKEN_RE.source, 'gi')
  let idx = 0

  while ((match = re.exec(text)) !== null) {
    if (match.index > cursor) {
      parts.push(text.slice(cursor, match.index))
    }
    const token = match[0]
    const pageNum = match[2] ? parseInt(match[2], 10) : null
    const k = `${keyPrefix}-${idx++}`

    if (pageNum && !Number.isNaN(pageNum)) {
      if (typeof onJumpPage === 'function') {
        parts.push(jsx('button', {
          type: 'button',
          className: 'hv-md-page-ref',
          onClick: () => onJumpPage(pageNum, text),
          title: `Vai a Pagina ${pageNum}`,
          children: `Pag. ${pageNum}`
        }, k))
      } else {
        parts.push(jsx('span', { className: 'hv-md-page-ref', children: `Pag. ${pageNum}` }, k))
      }
    } else if (token.startsWith('`') && token.endsWith('`')) {
      parts.push(jsx('code', { className: 'hv-md-code', children: token.slice(1, -1) }, k))
    } else if ((token.startsWith('**') && token.endsWith('**')) || (token.startsWith('__') && token.endsWith('__'))) {
      parts.push(jsx('strong', { children: renderMarkdownInline(token.slice(2, -2), onJumpPage, `${k}-b`) }, k))
    } else if ((token.startsWith('*') && token.endsWith('*')) || (token.startsWith('_') && token.endsWith('_'))) {
      parts.push(jsx('em', { children: renderMarkdownInline(token.slice(1, -1), onJumpPage, `${k}-i`) }, k))
    } else if (token.startsWith('[')) {
      const linkMatch = token.match(/^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/i)
      if (linkMatch) {
        parts.push(jsx('a', {
          href: linkMatch[2],
          target: '_blank',
          rel: 'noopener noreferrer',
          style: { color: '#22d3ee', textDecoration: 'underline' },
          children: linkMatch[1]
        }, k))
      } else {
        parts.push(token)
      }
    } else {
      parts.push(token)
    }
    cursor = re.lastIndex
  }
  if (cursor < text.length) {
    parts.push(text.slice(cursor))
  }
  return parts
}

function parseTableCells(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim())
}

function isTableSeparatorLine(line) {
  return /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?$/.test(line.trim())
}

function MarkdownView({ text, onJumpPage }) {
  if (!text) return null
  const lines = String(text).replace(/\r\n/g, '\n').split('\n')
  const blocks = []
  let i = 0
  let bIdx = 0

  while (i < lines.length) {
    const line = lines[i]
    const trimmed = line.trim()

    if (!trimmed) {
      i++
      continue
    }

    // Fenced code block
    if (trimmed.startsWith('```')) {
      const codeLines = []
      i++
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      if (i < lines.length) i++
      blocks.push(jsx('pre', {
        className: 'hv-md-pre',
        children: jsx('code', { children: codeLines.join('\n') })
      }, `b-${bIdx++}`))
      continue
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      blocks.push(jsx('hr', { className: 'hv-md-hr' }, `b-${bIdx++}`))
      i++
      continue
    }

    // Headings #..####
    const headingMatch = trimmed.match(/^(#{1,4})\s+(.+)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const tag = `h${level}`
      blocks.push(jsx(tag, {
        className: `hv-md-h${level}`,
        children: renderMarkdownInline(headingMatch[2], onJumpPage, `h-${bIdx}`)
      }, `b-${bIdx++}`))
      i++
      continue
    }

    // Markdown table
    if (trimmed.includes('|') && i + 1 < lines.length && isTableSeparatorLine(lines[i + 1])) {
      const headers = parseTableCells(line)
      i += 2
      const rows = []
      while (i < lines.length && lines[i].trim().includes('|') && lines[i].trim()) {
        rows.push(parseTableCells(lines[i]))
        i++
      }
      blocks.push(jsx('div', {
        className: 'hv-md-table-wrap',
        children: jsxs('table', {
          className: 'hv-md-table',
          children: [
            jsx('thead', {
              children: jsx('tr', {
                children: headers.map((h, ci) => jsx('th', {
                  children: renderMarkdownInline(h, onJumpPage, `th-${bIdx}-${ci}`)
                }, ci))
              })
            }),
            jsx('tbody', {
              children: rows.map((row, ri) => jsx('tr', {
                children: row.map((cell, ci) => jsx('td', {
                  children: renderMarkdownInline(cell, onJumpPage, `td-${bIdx}-${ri}-${ci}`)
                }, ci))
              }, ri))
            })
          ]
        })
      }, `b-${bIdx++}`))
      continue
    }

    // Blockquote
    if (trimmed.startsWith('>')) {
      const quoteLines = []
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''))
        i++
      }
      blocks.push(jsx('blockquote', {
        className: 'hv-md-quote',
        children: renderMarkdownInline(quoteLines.join(' '), onJumpPage, `q-${bIdx}`)
      }, `b-${bIdx++}`))
      continue
    }

    // Unordered list (- , * , • )
    if (/^(?:[-*]|\u2022)\s+/.test(trimmed)) {
      const items = []
      while (i < lines.length && /^(?:[-*]|\u2022)\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^(?:[-*]|\u2022)\s+/, ''))
        i++
      }
      blocks.push(jsx('ul', {
        className: 'hv-md-ul',
        children: items.map((item, liIdx) => jsx('li', {
          className: 'hv-md-li',
          children: renderMarkdownInline(item, onJumpPage, `ul-${bIdx}-${liIdx}`)
        }, liIdx))
      }, `b-${bIdx++}`))
      continue
    }

    // Ordered list (1. , 2. )
    if (/^\d+\.\s+/.test(trimmed)) {
      const items = []
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ''))
        i++
      }
      blocks.push(jsx('ol', {
        className: 'hv-md-ol',
        children: items.map((item, liIdx) => jsx('li', {
          className: 'hv-md-li',
          children: renderMarkdownInline(item, onJumpPage, `ol-${bIdx}-${liIdx}`)
        }, liIdx))
      }, `b-${bIdx++}`))
      continue
    }

    // Paragraph (join contiguous plain lines)
    const paraLines = []
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^(#{1,4}\s+|```|>\s?|(?:[-*]|\u2022)\s+|\d+\.\s+|(-{3,}|\*{3,}|_{3,})$)/.test(lines[i].trim()) &&
      !(lines[i].includes('|') && i + 1 < lines.length && isTableSeparatorLine(lines[i + 1]))
    ) {
      paraLines.push(lines[i].trim())
      i++
    }
    blocks.push(jsx('p', {
      className: 'hv-md-p',
      children: renderMarkdownInline(paraLines.join(' '), onJumpPage, `p-${bIdx}`)
    }, `b-${bIdx++}`))
  }

  return jsx('div', { className: 'hv-md-root', children: blocks })
}

function classifyDocumentSentence(text) {
  const t = (text || '').trim()
  if (!t) return 'body'
  if (/^(?:[•▪◦‣∙]|-\s)/.test(t)) return 'list'
  if (t.includes('|') || (t.includes('•') && t.length <= 120)) return 'meta'
  if (/^Q\d{1,3}\s+\[P\d+\]/i.test(t)) return 'question'
  const letters = t.replace(/[^A-Za-zÀ-Úà-ú]/g, '')
  const hasLower = /[a-zà-ú]/.test(letters)
  if (letters.length >= 3 && !hasLower && t.length <= 110) return 'heading'
  if (/^\d+(?:\.\d+)*\.\s+[A-ZÀ-Ú]/.test(t) && t.length <= 85 && !/[.!?]$/.test(t)) return 'heading'
  return 'body'
}

const _MATCH_STOP_WORDS = new Set([
  'che', 'chi', 'cui', 'del', 'della', 'delle', 'degli', 'dei', 'nel', 'nella',
  'nelle', 'nei', 'negli', 'sul', 'sulla', 'sulle', 'con', 'per', 'tra', 'fra',
  'una', 'uno', 'gli', 'come', 'sono', 'essere', 'alla', 'alle', 'agli', 'dalla',
  'dalle', 'dagli', 'pagina', 'pag'
])

function normalizeMatchText(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/\[pag(?:ina)?\.?\s*\d+\]/gi, ' ')
    .replace(/[.,;:'"“”«»!?()[\]{}\-—–*_#`•]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function findMatchingSentenceIndices(sentences, quoteHint) {
  if (!Array.isArray(sentences) || sentences.length === 0 || !quoteHint) return []
  const cleanedHint = normalizeMatchText(quoteHint)
  if (cleanedHint.length < 3) return []

  // Prefer quoted spans inside quoteHint if present
  const quoted = []
  const qRe = /["“«]([^"”»]{4,})["”»]/g
  let m
  while ((m = qRe.exec(String(quoteHint))) !== null) {
    const nq = normalizeMatchText(m[1])
    if (nq.length >= 4) quoted.push(nq)
  }
  const targets = quoted.length > 0 ? quoted : [cleanedHint]

  const exactHits = []
  for (const sent of sentences) {
    const sn = normalizeMatchText(sent.text)
    if (!sn) continue
    const hit = targets.some(t => sn.includes(t) || (sn.length >= 16 && t.includes(sn)))
    if (hit) exactHits.push(sent.sentence_index)
  }
  if (exactHits.length > 0) return exactHits

  const hintTokens = cleanedHint
    .split(' ')
    .filter(w => w.length > 2 && !_MATCH_STOP_WORDS.has(w))
  if (hintTokens.length === 0) return []

  let bestScore = 0
  const scored = []
  for (const sent of sentences) {
    const sn = normalizeMatchText(sent.text)
    if (!sn) continue
    const sentTokens = new Set(sn.split(' ').filter(w => w.length > 2 && !_MATCH_STOP_WORDS.has(w)))
    if (sentTokens.size === 0) continue
    let overlap = 0
    for (const tok of sentTokens) {
      if (hintTokens.includes(tok)) overlap++
    }
    if (overlap >= 2) {
      const coverage = overlap / Math.min(sentTokens.size, hintTokens.length)
      const score = overlap + coverage
      scored.push({ idx: sent.sentence_index, overlap, coverage, score })
      if (score > bestScore) bestScore = score
    }
  }
  if (scored.length === 0) return []
  return scored
    .filter(item => item.coverage >= 0.45 && item.score >= bestScore * 0.75)
    .map(item => item.idx)
}

function extractDocumentToc(doc) {
  if (!doc || !Array.isArray(doc.pages)) return []
  const entries = []
  let lastLabel = ''
  for (const page of doc.pages) {
    if (!Array.isArray(page.sentences)) continue
    for (const sent of page.sentences) {
      if (sent.is_header_footer) continue
      const role = classifyDocumentSentence(sent.text)
      if (role !== 'heading' && role !== 'question') continue
      const label = (sent.text || '').trim()
      if (!label || label === lastLabel) continue
      lastLabel = label
      entries.push({
        sentence_index: sent.sentence_index,
        page_number: page.page_number,
        kind: role,
        label
      })
    }
  }
  return entries
}

function searchDocumentSentences(doc, query) {
  const q = String(query || '').trim().toLowerCase()
  if (!doc || !Array.isArray(doc.pages) || q.length < 2) return []
  const matches = []
  for (const page of doc.pages) {
    if (!Array.isArray(page.sentences)) continue
    for (const sent of page.sentences) {
      const txt = sent.text || ''
      if (txt.toLowerCase().includes(q)) {
        matches.push({
          sentence_index: sent.sentence_index,
          page_number: page.page_number,
          text: txt
        })
      }
    }
  }
  return matches
}

function renderTextWithSearchHighlight(text, query) {
  const q = String(query || '').trim()
  if (!text || q.length < 2) return text
  const lowerText = text.toLowerCase()
  const lowerQ = q.toLowerCase()
  if (!lowerText.includes(lowerQ)) return text

  const nodes = []
  let cursor = 0
  let pos = lowerText.indexOf(lowerQ, cursor)
  let partIdx = 0
  while (pos !== -1) {
    if (pos > cursor) {
      nodes.push(text.slice(cursor, pos))
    }
    nodes.push(jsx('mark', {
      className: 'hv-search-mark',
      children: text.slice(pos, pos + q.length)
    }, `mk-${partIdx++}`))
    cursor = pos + q.length
    pos = lowerText.indexOf(lowerQ, cursor)
  }
  if (cursor < text.length) {
    nodes.push(text.slice(cursor))
  }
  return nodes
}

function DocumentPageSentences({
  sentences,
  activeSentenceIndex,
  isPlaying,
  highlightedSentenceIndices = [],
  searchQuery = '',
  activeSearchSentenceIndex = null,
  onSeekSentence
}) {
  const activeRef = useRef(null)
  const citedRef = useRef(null)
  const searchRef = useRef(null)
  const citedKey = Array.isArray(highlightedSentenceIndices) ? highlightedSentenceIndices.join(',') : ''

  useEffect(() => {
    if (isPlaying && activeRef.current && typeof activeRef.current.scrollIntoView === 'function') {
      activeRef.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [activeSentenceIndex, isPlaying])

  useEffect(() => {
    if (citedKey && citedRef.current && typeof citedRef.current.scrollIntoView === 'function') {
      citedRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' })
    }
  }, [citedKey])

  useEffect(() => {
    if (activeSearchSentenceIndex !== null && searchRef.current && typeof searchRef.current.scrollIntoView === 'function') {
      searchRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' })
    }
  }, [activeSearchSentenceIndex])

  const citedSet = new Set(Array.isArray(highlightedSentenceIndices) ? highlightedSentenceIndices : [])
  const firstCitedIdx = Array.isArray(highlightedSentenceIndices) && highlightedSentenceIndices.length > 0
    ? highlightedSentenceIndices[0]
    : null

  // Group contiguous sentences by paragraph_index while preserving verbatim sentence order
  const paragraphs = []
  let currentPara = null
  for (const sent of sentences) {
    const pKey = sent.paragraph_index ?? 0
    if (!currentPara || currentPara.key !== pKey) {
      currentPara = { key: pKey, items: [] }
      paragraphs.push(currentPara)
    }
    currentPara.items.push(sent)
  }

  return paragraphs.map((para, pIdx) => jsx('div', {
    className: 'hv-doc-para',
    children: para.items.map(sent => {
      const isCurrentSpeaking = (activeSentenceIndex === sent.sentence_index) && isPlaying
      const isCited = citedSet.has(sent.sentence_index)
      const isFirstCited = firstCitedIdx === sent.sentence_index
      const isActiveSearch = activeSearchSentenceIndex === sent.sentence_index
      const role = sent.is_header_footer ? 'meta' : classifyDocumentSentence(sent.text)
      const roleClass = role === 'heading'
        ? 'hv-doc-heading'
        : role === 'question'
        ? 'hv-doc-question-title'
        : role === 'list'
        ? 'hv-doc-list-item'
        : role === 'meta'
        ? 'hv-doc-meta-line'
        : ''

      const attachRef = (el) => {
        if (isCurrentSpeaking) activeRef.current = el
        if (isFirstCited) citedRef.current = el
        if (isActiveSearch) searchRef.current = el
      }

      const renderedText = renderTextWithSearchHighlight(sent.text, searchQuery)

      return jsx('span', {
        ref: (isCurrentSpeaking || isFirstCited || isActiveSearch) ? attachRef : undefined,
        className: [
          'hv-sentence',
          roleClass,
          isCurrentSpeaking ? 'hv-sentence-active' : '',
          isCited ? 'hv-sentence-cited' : '',
          isActiveSearch ? 'hv-sentence-search-active' : ''
        ].filter(Boolean).join(' '),
        onClick: () => onSeekSentence(sent.sentence_index),
        title: `Frase #${sent.sentence_index + 1} (Clicca per leggere)`,
        children: role === 'body'
          ? (Array.isArray(renderedText) ? [...renderedText, ' '] : renderedText + ' ')
          : renderedText
      }, sent.sentence_index)
    })
  }, `para-${para.key}-${pIdx}`))
}

function VoiceDocumentPage({ ctx, controller }) {
  const status = useValue(controller.status)
  const docData = useValue(controller.docData)
  const viewPage = useValue(controller.viewPage)
  const chatMessages = useValue(controller.chatMessages)
  const isAsking = useValue(controller.isAsking)
  const library = useValue(controller.library)
  const modelsInfo = useValue(controller.modelsInfo)
  const [questionInput, setQuestionInput] = useState('')
  const [isRecording, setIsRecording] = useState(false)
  const [tocOpen, setTocOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchCursor, setSearchCursor] = useState(0)
  const [citationHighlight, setCitationHighlight] = useState(null)
  const [speakingMsgIdx, setSpeakingMsgIdx] = useState(null)
  const [isLoadingMsgSpeech, setIsLoadingMsgSpeech] = useState(false)
  const [localDirsOpen, setLocalDirsOpen] = useState(false)
  const [newLocalDirInput, setNewLocalDirInput] = useState('')
  const [customRuntimeId, setCustomRuntimeId] = useState('ollama')
  const [customRuntimeUrl, setCustomRuntimeUrl] = useState('http://127.0.0.1:11434')
  const [customRuntimeModel, setCustomRuntimeModel] = useState('')
  const fileInputRef = useRef(null)
  const searchInputRef = useRef(null)
  const msgAudioRef = useRef(null)

  const activeScope = useValue(controller.scope)

  const tocEntries = useMemo(() => extractDocumentToc(docData), [docData])
  const searchMatches = useMemo(
    () => searchDocumentSentences(docData, searchQuery),
    [docData, searchQuery]
  )
  const activeSearchMatch =
    searchMatches.length > 0 ? searchMatches[Math.min(searchCursor, searchMatches.length - 1)] : null

  const stopMsgSpeech = () => {
    if (msgAudioRef.current) {
      try {
        msgAudioRef.current.pause()
        msgAudioRef.current.removeAttribute('src')
        if (typeof msgAudioRef.current.load === 'function') {
          msgAudioRef.current.load()
        }
      } catch (_) {}
      msgAudioRef.current = null
    }
    setSpeakingMsgIdx(null)
    setIsLoadingMsgSpeech(false)
  }

  useEffect(() => {
    return () => stopMsgSpeech()
  }, [])

  useEffect(() => {
    setTocOpen(false)
    setCitationHighlight(null)
    setSearchCursor(0)
  }, [docData?.doc_id, activeScope])

  useEffect(() => {
    setSearchCursor(0)
    if (searchOpen && searchMatches.length > 0) {
      controller.setViewPage(searchMatches[0].page_number)
    }
  }, [searchQuery, searchOpen, docData?.doc_id])

  useEffect(() => {
    const onKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'f' && docData) {
        e.preventDefault()
        setSearchOpen(true)
        setTimeout(() => searchInputRef.current?.focus(), 0)
      } else if (e.key === 'Escape' && searchOpen) {
        setSearchOpen(false)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [docData, searchOpen])

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

  const refreshModels = async (forceRefresh = false) => {
    const scopeAtStart = controller.currentScopeKey()
    try {
      const qs = forceRefresh ? '?refresh=true' : ''
      const res = await ctx.rest(`/models${qs}`)
      if (controller.currentScopeKey() !== scopeAtStart) return
      if (res && typeof res === 'object') {
        controller.setModelsInfo(res)
      }
    } catch (_) {}
  }

  const handleAddLocalDir = async () => {
    const clean = newLocalDirInput.trim()
    if (!clean) return
    try {
      const res = await ctx.rest('/models/local-dirs', {
        method: 'POST',
        body: { action: 'add', path: clean }
      })
      if (res && typeof res === 'object') {
        controller.setModelsInfo(res)
      }
      setNewLocalDirInput('')
      host.notify({ kind: 'info', message: `Cartella modelli aggiunta: ${clean}` })
    } catch (err) {
      host.notifyError(err, 'Errore aggiunta cartella modelli')
    }
  }

  const handleRemoveLocalDir = async (dirPath) => {
    try {
      const res = await ctx.rest('/models/local-dirs', {
        method: 'POST',
        body: { action: 'remove', path: dirPath }
      })
      if (res && typeof res === 'object') {
        controller.setModelsInfo(res)
      }
    } catch (err) {
      host.notifyError(err, 'Errore rimozione cartella modelli')
    }
  }

  useEffect(() => {
    controller.setLibrary([])
    controller.setModelsInfo(null)
    refreshLibrary()
    refreshModels()
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

  const handleSeekCitation = async (docId, page, quoteHint = '', sentenceIndexHint = null) => {
    try {
      let targetDoc = docData
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
        targetDoc = switched
      }
      await handleSeekPage(page)

      const targetPageObj = targetDoc?.pages?.find(p => p.page_number === page)
      const pageSents = targetPageObj?.sentences || []
      let matchedIndices = []
      if (sentenceIndexHint !== null && sentenceIndexHint !== undefined && pageSents.some(s => s.sentence_index === sentenceIndexHint)) {
        matchedIndices = [sentenceIndexHint]
      } else if (quoteHint) {
        matchedIndices = findMatchingSentenceIndices(pageSents, quoteHint)
      }
      setCitationHighlight(
        matchedIndices.length > 0
          ? { docId: docId || targetDoc?.doc_id, page, sentenceIndices: matchedIndices }
          : null
      )
    } catch (err) {
      host.notifyError(err, 'Errore navigazione citazione')
    }
  }

  const handleSkipHeadersToggle = async (e) => {
    const enabled = Boolean(e.target.checked)
    try {
      await controller.setSkipHeadersFooters(enabled)
    } catch (err) {
      host.notifyError(err, 'Errore impostazione salto intestazioni')
    }
  }

  const handleSelectTocEntry = async (entry) => {
    setTocOpen(false)
    if (!entry) return
    controller.setViewPage(entry.page_number)
    setCitationHighlight({
      docId: docData?.doc_id,
      page: entry.page_number,
      sentenceIndices: [entry.sentence_index]
    })
    await handleSeekSentence(entry.sentence_index)
  }

  const jumpToSearchMatch = (nextIdx) => {
    if (searchMatches.length === 0) return
    const wrapped = ((nextIdx % searchMatches.length) + searchMatches.length) % searchMatches.length
    setSearchCursor(wrapped)
    const match = searchMatches[wrapped]
    if (match) {
      controller.setViewPage(match.page_number)
    }
  }

  const handleSpeakMessage = async (msgIdx, text) => {
    if (speakingMsgIdx === msgIdx) {
      stopMsgSpeech()
      return
    }
    stopMsgSpeech()
    if (status?.state === 'playing') {
      try {
        await controller.pause()
      } catch (_) {}
    }
    setIsLoadingMsgSpeech(true)
    setSpeakingMsgIdx(msgIdx)
    try {
      const audioRes = await ctx.rest('/audio/text?format=json', {
        method: 'POST',
        body: { text, strip_markdown: true },
        timeoutMs: AUDIO_SYNTH_TIMEOUT_MS
      })
      if (!audioRes || !audioRes.audio_base64) {
        stopMsgSpeech()
        return
      }
      const audio = new Audio(`data:audio/wav;base64,${audioRes.audio_base64}`)
      if (status?.speed) {
        audio.playbackRate = status.speed
      }
      audio.addEventListener('ended', () => {
        if (msgAudioRef.current === audio) {
          stopMsgSpeech()
        }
      }, { once: true })
      msgAudioRef.current = audio
      setIsLoadingMsgSpeech(false)
      await audio.play()
    } catch (err) {
      stopMsgSpeech()
      host.notifyError(err, 'Errore lettura risposta AI')
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
      await refreshModels()
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

  const LOCAL_RUNTIME_DEFAULTS = {
    ollama: 'http://127.0.0.1:11434',
    lmstudio: 'http://127.0.0.1:1234/v1',
    unsloth_studio: 'http://127.0.0.1:8888/v1',
    llamacpp: 'http://127.0.0.1:8080/v1',
    jan: 'http://127.0.0.1:1337/v1',
    koboldcpp: 'http://127.0.0.1:5001/v1',
    vllm: 'http://127.0.0.1:8000/v1',
    custom: 'http://127.0.0.1:8000/v1'
  }

  const openLocalConfigDrawer = () => {
    const rtCandidate = LOCAL_RUNTIME_DEFAULTS[activeLlmProvider] ? activeLlmProvider : 'ollama'
    setCustomRuntimeId(rtCandidate)
    const detectedUrl = rtCandidate === 'ollama'
      ? (modelsInfo?.ollama?.url || LOCAL_RUNTIME_DEFAULTS.ollama)
      : (modelsInfo?.local_runtimes?.[rtCandidate]?.url || LOCAL_RUNTIME_DEFAULTS[rtCandidate] || '')
    setCustomRuntimeUrl(detectedUrl)
    if (LOCAL_RUNTIME_DEFAULTS[activeLlmProvider] && activeLlmModel) {
      setCustomRuntimeModel(activeLlmModel)
    }
    setLocalDirsOpen(true)
  }

  const handleCustomRuntimeSelect = (e) => {
    const rid = e.target.value
    setCustomRuntimeId(rid)
    const detectedUrl = rid === 'ollama'
      ? (modelsInfo?.ollama?.url || LOCAL_RUNTIME_DEFAULTS.ollama)
      : (modelsInfo?.local_runtimes?.[rid]?.url || LOCAL_RUNTIME_DEFAULTS[rid] || '')
    setCustomRuntimeUrl(detectedUrl)
    const detectedModels = rid === 'ollama'
      ? ollamaModels
      : (Array.isArray(modelsInfo?.local_runtimes?.[rid]?.models) ? modelsInfo.local_runtimes[rid].models : [])
    if (detectedModels.length > 0) {
      setCustomRuntimeModel(detectedModels[0])
    }
  }

  const handleApplyCustomLocalRuntime = async () => {
    const cleanModel = String(customRuntimeModel || '').trim()
    if (!cleanModel) {
      host.notify({ kind: 'warning', message: 'Inserisci l\'ID o tag del modello locale da utilizzare.' })
      return
    }
    const cleanUrl = String(customRuntimeUrl || '').trim() || null
    try {
      await controller.setLlmModel(cleanModel, customRuntimeId, cleanUrl)
      await refreshModels(false)
      host.notify({ kind: 'info', message: `Modello Analista impostato su: ${cleanModel} (${customRuntimeId})` })
    } catch (err) {
      host.notifyError(err, 'Errore configurazione runtime locale')
    }
  }

  const handleLlmModelChange = async (e) => {
    const rawVal = e.target.value
    if (!rawVal) return
    if (rawVal === '__configure_local__') {
      openLocalConfigDrawer()
      return
    }
    const sepIdx = rawVal.indexOf('::')
    const provider = sepIdx !== -1 ? rawVal.slice(0, sepIdx) : 'ollama'
    const model = sepIdx !== -1 ? rawVal.slice(sepIdx + 2) : rawVal
    const runtimeUrl = provider === 'ollama'
      ? (modelsInfo?.ollama?.url || null)
      : (modelsInfo?.local_runtimes?.[provider]?.url || null)
    try {
      await controller.setLlmModel(model, provider, runtimeUrl)
      host.notify({ kind: 'info', message: `Modello Analista impostato su: ${model} (${provider})` })
    } catch (err) {
      host.notifyError(err, 'Errore cambio modello Analista')
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

  const activeLlmProvider = status?.llm_provider || modelsInfo?.default_provider || 'ollama'
  const activeLlmModel = status?.llm_model || modelsInfo?.ollama?.model || 'gemma4:12b'
  const ollamaModels = Array.isArray(modelsInfo?.ollama?.models) ? modelsInfo.ollama.models : []
  const ollamaOnline = modelsInfo?.ollama?.status === 'online'
  const localRuntimes = modelsInfo?.local_runtimes && typeof modelsInfo.local_runtimes === 'object' ? modelsInfo.local_runtimes : {}
  const ggufModels = Array.isArray(modelsInfo?.local_gguf?.models) ? modelsInfo.local_gguf.models : []
  const llamaServerAvailable = Boolean(modelsInfo?.local_gguf?.llama_server_available)
  const customLocalDirs = Array.isArray(modelsInfo?.local_gguf?.custom_dirs) ? modelsInfo.local_gguf.custom_dirs : []
  const codexOauthInfo = modelsInfo?.codex_oauth || null
  const cloudProviders = modelsInfo?.cloud_providers || null
  const activeLlmValue = `${activeLlmProvider}::${activeLlmModel}`

  const onlineLocalRuntimeEntries = Object.entries(localRuntimes).filter(
    ([, info]) => info && info.status === 'online'
  )
  const localModelTotalCount =
    ollamaModels.length +
    ggufModels.length +
    onlineLocalRuntimeEntries.reduce(
      (acc, [, info]) => acc + (Array.isArray(info.models) ? info.models.length : 0),
      0
    )

  const PROVIDER_DISPLAY_NAMES = {
    ollama: 'Ollama Locale',
    'openai-codex': 'ChatGPT Codex (Quote)',
    openrouter: 'OpenRouter',
    'ollama-cloud': 'Ollama Cloud',
    gguf: 'GGUF / Unsloth Locale',
    lmstudio: 'LM Studio',
    unsloth_studio: 'Unsloth Studio',
    llamacpp: 'llama.cpp Locale',
    jan: 'Jan Locale',
    koboldcpp: 'KoboldCpp Locale',
    vllm: 'vLLM Locale',
    custom: 'Runtime Locale Custom',
    openai_compatible: 'Locale OpenAI-Compat'
  }

  const llmGroups = useMemo(() => {
    const groups = []
    const seen = new Set()
    const pushInto = (groupItems, provider, model, label, opts = {}) => {
      const value = opts.explicitValue || `${provider}::${model}`
      if (seen.has(value)) return
      seen.add(value)
      groupItems.push({ value, provider, model, label, disabled: Boolean(opts.disabled) })
    }

    const activeGroup = []
    const activeDisplayModel = activeLlmProvider === 'gguf'
      ? (String(activeLlmModel).split(/[\\/]/).pop() || activeLlmModel)
      : activeLlmModel
    const activeProviderName = PROVIDER_DISPLAY_NAMES[activeLlmProvider] || activeLlmProvider
    pushInto(
      activeGroup,
      activeLlmProvider,
      activeLlmModel,
      `${activeProviderName} · ${activeDisplayModel}`
    )
    for (const m of ollamaModels) {
      if (m && typeof m === 'string') {
        pushInto(activeGroup, 'ollama', m, `Ollama · ${m}`)
      }
    }
    for (const [rid, info] of onlineLocalRuntimeEntries) {
      const rLabel = info.label || PROVIDER_DISPLAY_NAMES[rid] || rid
      const rModels = Array.isArray(info.models) ? info.models : []
      if (rModels.length > 0) {
        for (const m of rModels) {
          if (m && typeof m === 'string') {
            pushInto(activeGroup, rid, m, `${rLabel} · ${m}`)
          }
        }
      } else {
        pushInto(
          activeGroup,
          rid,
          '',
          `${rLabel} (online · nessun modello caricato)`,
          { explicitValue: `__empty_runtime__::${rid}`, disabled: true }
        )
      }
    }
    pushInto(
      activeGroup,
      'custom',
      '',
      '⚙ Inserisci runtime / modello locale manuale...',
      { explicitValue: '__configure_local__' }
    )
    groups.push({ label: 'Runtime Locali Attivi', items: activeGroup })

    if (ggufModels.length > 0) {
      const ggufGroup = []
      for (const g of ggufModels) {
        if (g && g.path) {
          const srcTag = g.source === 'unsloth' ? 'Unsloth' : (g.source || 'GGUF')
          const quantTag = g.quant ? ` · ${g.quant}` : ''
          const sizeTag = g.size_label ? ` (${g.size_label})` : ''
          pushInto(ggufGroup, 'gguf', g.path, `${srcTag} · ${g.name}${quantTag}${sizeTag}`)
        }
      }
      if (ggufGroup.length > 0) {
        groups.push({ label: 'GGUF / Unsloth su Disco', items: ggufGroup })
      }
    }

    if (status?.allow_remote) {
      if (codexOauthInfo?.configured && Array.isArray(codexOauthInfo.models) && codexOauthInfo.models.length > 0) {
        const codexGroup = []
        for (const m of codexOauthInfo.models) {
          if (m && typeof m === 'string') {
            pushInto(codexGroup, 'openai-codex', m, `ChatGPT Codex · ${m}`)
          }
        }
        if (codexGroup.length > 0) {
          groups.push({ label: 'ChatGPT Codex (Quote ChatGPT)', items: codexGroup })
        }
      }

      const orInfo = cloudProviders?.openrouter
      if (orInfo && (orInfo.configured || (!cloudProviders && modelsInfo?.remote_api?.configured))) {
        const freeGroup = []
        for (const m of (Array.isArray(orInfo.free_models) ? orInfo.free_models : [])) {
          if (m && typeof m === 'string') {
            pushInto(freeGroup, 'openrouter', m, `OpenRouter Free · ${m}`)
          }
        }
        if (freeGroup.length > 0) {
          groups.push({ label: 'Cloud Gratuiti (OpenRouter :free)', items: freeGroup })
        }
      }

      const ocInfo = cloudProviders?.ollama_cloud
      if (ocInfo?.configured && Array.isArray(ocInfo.models) && ocInfo.models.length > 0) {
        const ocGroup = []
        for (const m of ocInfo.models) {
          if (m && typeof m === 'string') {
            pushInto(ocGroup, 'ollama-cloud', m, `Ollama Cloud · ${m}`)
          }
        }
        if (ocGroup.length > 0) {
          groups.push({ label: 'Ollama Cloud', items: ocGroup })
        }
      }

      const paidGroup = []
      if (cloudProviders) {
        if (cloudProviders.openai?.configured) {
          for (const m of (cloudProviders.openai.models || ['gpt-4o-mini'])) {
            pushInto(paidGroup, 'openai', m, `OpenAI API · ${m}`)
          }
        }
        if (cloudProviders.anthropic?.configured) {
          for (const m of (cloudProviders.anthropic.models || ['claude-3-5-sonnet-20241022'])) {
            pushInto(paidGroup, 'anthropic', m, `Anthropic API · ${m}`)
          }
        }
      } else if (modelsInfo?.remote_api?.configured) {
        pushInto(paidGroup, 'openai', 'gpt-4o-mini', 'OpenAI · gpt-4o-mini (remoto)')
        pushInto(paidGroup, 'anthropic', 'claude-3-5-sonnet-20241022', 'Anthropic · claude-3-5-sonnet (remoto)')
      }
      if (paidGroup.length > 0) {
        groups.push({ label: 'Cloud API (OpenAI / Anthropic)', items: paidGroup })
      }
    }

    return groups
  }, [
    activeLlmProvider,
    activeLlmModel,
    ollamaModels.join('|'),
    JSON.stringify(onlineLocalRuntimeEntries),
    JSON.stringify(ggufModels),
    status?.allow_remote,
    JSON.stringify(codexOauthInfo),
    JSON.stringify(cloudProviders),
    modelsInfo?.remote_api?.configured
  ])

  const providerLabel = PROVIDER_DISPLAY_NAMES[activeLlmProvider] || activeLlmProvider
  const activeModelDisplay = activeLlmProvider === 'gguf'
    ? (String(activeLlmModel).split(/[\\/]/).pop() || activeLlmModel)
    : activeLlmModel

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
                    className: 'hv-doc-toolbar-actions',
                    children: [
                      jsxs('button', {
                        type: 'button',
                        className: 'hv-btn',
                        disabled: tocEntries.length === 0,
                        onClick: () => setTocOpen(prev => !prev),
                        title: 'Indice sezioni e domande',
                        children: [
                          jsx(Codicon, { name: 'list-tree', size: '0.85rem' }),
                          `Indice (${tocEntries.length})`
                        ]
                      }),
                      jsx('button', {
                        type: 'button',
                        className: 'hv-btn hv-btn-icon',
                        disabled: !docData,
                        onClick: () => {
                          setSearchOpen(prev => {
                            const next = !prev
                            if (next) setTimeout(() => searchInputRef.current?.focus(), 0)
                            return next
                          })
                        },
                        title: 'Cerca nel documento (Ctrl+F)',
                        'aria-label': 'Cerca nel documento',
                        children: jsx(Codicon, { name: 'search', size: '0.85rem' })
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
                  })
                ]
              }),
              tocOpen && tocEntries.length > 0 && jsx('div', {
                className: 'hv-toc-popover',
                children: tocEntries.map((entry, idx) => jsxs('button', {
                  type: 'button',
                  className: 'hv-toc-item',
                  onClick: () => handleSelectTocEntry(entry),
                  title: entry.label,
                  children: [
                    jsxs('span', {
                      className: 'hv-toc-item-label',
                      children: [
                        jsx('span', {
                          className: 'hv-toc-kind',
                          children: entry.kind === 'question' ? 'Q' : '§'
                        }),
                        entry.label
                      ]
                    }),
                    jsx('span', {
                      className: 'hv-toc-page',
                      children: `Pag. ${entry.page_number}`
                    })
                  ]
                }, `toc-${entry.sentence_index}-${idx}`))
              }),
              searchOpen && jsxs('div', {
                className: 'hv-search-bar',
                children: [
                  jsx(Codicon, { name: 'search', size: '0.85rem' }),
                  jsx('input', {
                    ref: searchInputRef,
                    className: 'hv-input',
                    style: { padding: '5px 10px', fontSize: '12.5px' },
                    placeholder: 'Cerca nel documento (min. 2 caratteri)...',
                    value: searchQuery,
                    onChange: (e) => setSearchQuery(e.target.value),
                    onKeyDown: (e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        jumpToSearchMatch(e.shiftKey ? searchCursor - 1 : searchCursor + 1)
                      } else if (e.key === 'Escape') {
                        setSearchOpen(false)
                      }
                    }
                  }),
                  jsx('span', {
                    className: 'hv-search-count',
                    children: searchMatches.length > 0
                      ? `${Math.min(searchCursor, searchMatches.length - 1) + 1} / ${searchMatches.length}`
                      : (searchQuery.trim().length >= 2 ? '0 / 0' : '')
                  }),
                  jsx('button', {
                    type: 'button',
                    className: 'hv-btn hv-btn-icon',
                    disabled: searchMatches.length === 0,
                    onClick: () => jumpToSearchMatch(searchCursor - 1),
                    title: 'Occorrenza precedente',
                    children: jsx(Codicon, { name: 'chevron-up', size: '0.85rem' })
                  }),
                  jsx('button', {
                    type: 'button',
                    className: 'hv-btn hv-btn-icon',
                    disabled: searchMatches.length === 0,
                    onClick: () => jumpToSearchMatch(searchCursor + 1),
                    title: 'Occorrenza successiva',
                    children: jsx(Codicon, { name: 'chevron-down', size: '0.85rem' })
                  }),
                  jsx('button', {
                    type: 'button',
                    className: 'hv-btn hv-btn-icon',
                    onClick: () => {
                      setSearchOpen(false)
                      setSearchQuery('')
                    },
                    title: 'Chiudi ricerca',
                    children: jsx(Codicon, { name: 'close', size: '0.85rem' })
                  })
                ]
              }),
              jsx('div', {
                className: 'hv-doc-content',
                children: currentPageObj?.sentences && currentPageObj.sentences.length > 0
                  ? jsx(DocumentPageSentences, {
                      sentences: currentPageObj.sentences,
                      activeSentenceIndex: status?.current_sentence_index,
                      isPlaying,
                      highlightedSentenceIndices: (
                        citationHighlight &&
                        citationHighlight.page === viewPage &&
                        (!citationHighlight.docId || citationHighlight.docId === docData?.doc_id)
                      ) ? citationHighlight.sentenceIndices : [],
                      searchQuery: searchOpen ? searchQuery : '',
                      activeSearchSentenceIndex: (searchOpen && activeSearchMatch && activeSearchMatch.page_number === viewPage)
                        ? activeSearchMatch.sentence_index
                        : null,
                      onSeekSentence: handleSeekSentence
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
                  }),
                  jsxs('div', {
                    className: 'hv-player-options',
                    children: [
                      jsxs('label', {
                        className: 'hv-toggle-label',
                        title: 'Salta automaticamente intestazioni e piè di pagina ripetuti durante la lettura vocale',
                        children: [
                          jsx('input', {
                            type: 'checkbox',
                            checked: status?.skip_headers_footers ?? true,
                            onChange: handleSkipHeadersToggle
                          }),
                          'Salta intestazioni e piè di pagina'
                        ]
                      }),
                      jsx('span', { children: 'Prefetch frase N+1 attivo' })
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
                              isAsking || status?.agents?.analyst === 'generating' ? 'Generazione...' : activeModelDisplay
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
                  jsxs('div', {
                    className: 'hv-chat-model-bar',
                    children: [
                      jsxs('span', {
                        className: 'hv-chat-model-label',
                        children: [
                          jsx(Codicon, { name: 'chip', size: '0.85rem' }),
                          'Modello Analista'
                        ]
                      }),
                      jsx('select', {
                        className: 'hv-select hv-llm-select',
                        'aria-label': 'Modello Analista',
                        value: activeLlmValue,
                        onChange: handleLlmModelChange,
                        disabled: isAsking,
                        children: llmGroups.map(grp => jsxs('optgroup', {
                          label: grp.label,
                          children: grp.items.map(opt => jsx('option', {
                            value: opt.value,
                            disabled: Boolean(opt.disabled),
                            children: opt.label
                          }, opt.value))
                        }, grp.label))
                      }),
                      jsx('button', {
                        type: 'button',
                        className: 'hv-btn hv-btn-icon',
                        onClick: () => refreshModels(true),
                        title: 'Aggiorna modelli locali e cloud',
                        'aria-label': 'Aggiorna modelli',
                        children: jsx(Codicon, { name: 'refresh', size: '0.8rem' })
                      }),
                      jsx('button', {
                        type: 'button',
                        className: `hv-btn hv-btn-icon ${localDirsOpen ? 'hv-btn-primary' : ''}`,
                        onClick: () => (localDirsOpen ? setLocalDirsOpen(false) : openLocalConfigDrawer()),
                        title: 'Configura runtime locale / modello o cartelle GGUF & Unsloth',
                        'aria-label': 'Cartelle modelli locali',
                        children: jsx(Codicon, { name: 'folder', size: '0.8rem' })
                      }),
                      jsx('span', {
                        className: `hv-ollama-pill ${ollamaOnline || localModelTotalCount > 0 ? 'hv-ollama-pill-online' : ''}`,
                        title: modelsInfo?.ollama?.url || 'http://127.0.0.1:11434',
                        children: [
                          ollamaOnline ? `Ollama (${ollamaModels.length})` : 'Ollama offline',
                          onlineLocalRuntimeEntries.length > 0 ? ` · Runtime (${onlineLocalRuntimeEntries.length})` : '',
                          ggufModels.length > 0 ? ` · GGUF (${ggufModels.length})` : '',
                          codexOauthInfo?.configured ? ' · Codex' : ''
                        ].join('')
                      })
                    ]
                  }),
                  localDirsOpen
                    ? jsxs('div', {
                        className: 'hv-local-dirs-panel',
                        children: [
                          jsx('div', {
                            className: 'hv-model-hint',
                            children: 'Configura un runtime locale o specifica manualmente URL/porta e ID del modello locale (es. Unsloth Studio, Ollama, LM Studio, llama.cpp):'
                          }),
                          jsxs('div', {
                            className: 'hv-local-dir-row hv-custom-runtime-row',
                            children: [
                              jsxs('select', {
                                className: 'hv-select',
                                'aria-label': 'Runtime locale',
                                value: customRuntimeId,
                                onChange: handleCustomRuntimeSelect,
                                children: [
                                  jsx('option', { value: 'ollama', children: 'Ollama' }),
                                  jsx('option', { value: 'unsloth_studio', children: 'Unsloth Studio' }),
                                  jsx('option', { value: 'lmstudio', children: 'LM Studio' }),
                                  jsx('option', { value: 'llamacpp', children: 'llama.cpp Server' }),
                                  jsx('option', { value: 'jan', children: 'Jan' }),
                                  jsx('option', { value: 'koboldcpp', children: 'KoboldCpp' }),
                                  jsx('option', { value: 'vllm', children: 'vLLM' }),
                                  jsx('option', { value: 'custom', children: 'Custom OpenAI-Compat' })
                                ]
                              }),
                              jsx('input', {
                                className: 'hv-input',
                                'aria-label': 'Endpoint runtime locale',
                                placeholder: 'URL locale (es. http://127.0.0.1:8888/v1)',
                                value: customRuntimeUrl,
                                onChange: (e) => setCustomRuntimeUrl(e.target.value)
                              }),
                              jsx('input', {
                                className: 'hv-input',
                                'aria-label': 'ID modello locale',
                                placeholder: 'ID/Tag modello (es. gemma4:12b, unsloth/Qwen3...)',
                                value: customRuntimeModel,
                                onChange: (e) => setCustomRuntimeModel(e.target.value),
                                onKeyDown: (e) => { if (e.key === 'Enter') handleApplyCustomLocalRuntime() }
                              }),
                              jsx('button', {
                                type: 'button',
                                className: 'hv-btn hv-btn-primary',
                                onClick: handleApplyCustomLocalRuntime,
                                disabled: !customRuntimeModel.trim(),
                                children: 'Applica'
                              })
                            ]
                          }),
                          jsx('div', {
                            className: 'hv-model-hint',
                            children: llamaServerAvailable
                              ? 'llama-server rilevato su questo PC: i file GGUF / Unsloth su disco sono avviabili direttamente.'
                              : 'llama-server non rilevato su disco: avvia Unsloth Studio / Ollama / LM Studio o installa llama-server per usare GGUF diretti.'
                          }),
                          jsx('div', {
                            className: 'hv-model-hint',
                            children: 'Cartelle personalizzate per rilevare GGUF / Unsloth su qualsiasi PC (vengono già scansionate cache HF, LM Studio, Jan e llama.cpp):'
                          }),
                          jsxs('div', {
                            className: 'hv-local-dir-row hv-folder-dir-row',
                            children: [
                              jsx('input', {
                                className: 'hv-input',
                                placeholder: 'Percorso cartella modelli (es. D:\\AI\\Unsloth o ~/models)...',
                                value: newLocalDirInput,
                                onChange: (e) => setNewLocalDirInput(e.target.value),
                                onKeyDown: (e) => { if (e.key === 'Enter') handleAddLocalDir() }
                              }),
                              jsx('button', {
                                type: 'button',
                                className: 'hv-btn hv-btn-primary',
                                onClick: handleAddLocalDir,
                                disabled: !newLocalDirInput.trim(),
                                children: 'Aggiungi'
                              })
                            ]
                          }),
                          customLocalDirs.length > 0
                            ? jsx('div', {
                                className: 'hv-local-dirs-list',
                                children: customLocalDirs.map((dirPath) => jsxs('span', {
                                  className: 'hv-local-dir-chip',
                                  children: [
                                    jsx('span', { children: dirPath }),
                                    jsx('button', {
                                      type: 'button',
                                      style: { background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 },
                                      onClick: () => handleRemoveLocalDir(dirPath),
                                      title: 'Rimuovi cartella',
                                      children: '×'
                                    })
                                  ]
                                }, dirPath))
                              })
                            : null
                        ]
                      })
                    : null,
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
                            const isMsgSpeaking = speakingMsgIdx === i
                            return jsxs('div', {
                              className: 'hv-chat-msg',
                              children: [
                                jsxs('div', {
                                  className: 'hv-msg-assistant',
                                  children: [
                                    jsx(MarkdownView, {
                                      text: msg.text,
                                      onJumpPage: msg.doc_id
                                        ? (pn, inlineHint) => {
                                            const citMatch = (msg.citations || []).find(c => c.page_number === pn)
                                            return handleSeekCitation(
                                              msg.doc_id,
                                              pn,
                                              inlineHint || citMatch?.verbatim_quote || '',
                                              inlineHint ? null : (citMatch?.sentence_index ?? null)
                                            )
                                          }
                                        : undefined
                                    }),
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
                                          onClick: () => handleSeekCitation(
                                            msg.doc_id,
                                            cit.page_number,
                                            cit.verbatim_quote || '',
                                            cit.sentence_index ?? null
                                          ),
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
                                    }),
                                    // Speak Analyst Summary Action
                                    jsxs('div', {
                                      className: 'hv-msg-actions',
                                      children: [
                                        jsx('span', {
                                          className: 'hv-msg-model-tag',
                                          children: msg.model_used || activeLlmModel
                                        }),
                                        jsxs('button', {
                                          type: 'button',
                                          className: 'hv-msg-speak-btn',
                                          disabled: isLoadingMsgSpeech && !isMsgSpeaking,
                                          onClick: () => handleSpeakMessage(i, msg.text),
                                          title: isMsgSpeaking ? 'Ferma lettura sintesi' : 'Ascolta risposta con Pocket TTS',
                                          children: [
                                            jsx(Codicon, {
                                              name: isMsgSpeaking
                                                ? (isLoadingMsgSpeech ? 'loading' : 'debug-stop')
                                                : 'unmute',
                                              size: '0.75rem'
                                            }),
                                            isMsgSpeaking
                                              ? (isLoadingMsgSpeech ? 'Sintesi...' : 'Ferma')
                                              : 'Ascolta'
                                          ]
                                        })
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
                      jsx(Codicon, { name: 'shield-check', size: '0.9rem', style: { color: status?.allow_remote ? '#f59e0b' : '#10b981' } }),
                      'Routing: ',
                      jsx('strong', { style: { color: 'var(--foreground, #f1f5f9)' }, children: `${providerLabel} (${activeModelDisplay})` }),
                      status?.allow_remote ? ' · Provider remoti autorizzati' : ' · Privacy locale attiva'
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

export {
  classifyDocumentSentence,
  createVoicePlaybackController,
  DocumentPageSentences,
  extractDocumentToc,
  findMatchingSentenceIndices,
  MarkdownView,
  searchDocumentSentences,
  VoiceDocumentPage
}

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
