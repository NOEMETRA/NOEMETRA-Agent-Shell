(function () {
  const sdk = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!sdk || !registry) {
    console.warn("[voice-document-assistant] Hermes Plugin SDK or Registry not found on window");
    return;
  }

  const { React, hooks, fetchJSON } = sdk;
  const { useState, useEffect, useCallback, useRef } = hooks;
  const h = React.createElement;

  function VoiceDocumentDashboard() {
    const [status, setStatus] = useState(null);
    const [library, setLibrary] = useState([]);
    const [question, setQuestion] = useState("");
    const [answer, setAnswer] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const clientAudioRef = useRef(null);
    const lastPlayedTargetRef = useRef("");
    const fetchingTargetRef = useRef("");
    const pollGenRef = useRef(0);

    const refreshStatus = useCallback(async () => {
      try {
        const currentGen = ++pollGenRef.current;
        const data = await fetchJSON("/api/plugins/voice-document-assistant/status");
        if (currentGen !== pollGenRef.current) return;
        setStatus(data);
        // Client-side desktop audio stream
        const isPlaying = data && (data.state === "playing" || data.player_state === "PLAYING") && data.client_playback !== false;
        if (isPlaying) {
          const targetDocId = data.doc_id || "";
          const playTargetKey = `${targetDocId}:${data.current_sentence_index}`;
          if (playTargetKey !== lastPlayedTargetRef.current && fetchingTargetRef.current !== playTargetKey) {
            fetchingTargetRef.current = playTargetKey;
            if (clientAudioRef.current) {
              clientAudioRef.current.pause();
              clientAudioRef.current = null;
            }
            const currentSentIdx = data.current_sentence_index;
            let audioData = null;
            try {
              audioData = await fetchJSON(`/api/plugins/voice-document-assistant/audio/sentence/${currentSentIdx}?format=json`);
            } catch (err) {
              fetchingTargetRef.current = "";
              if (lastPlayedTargetRef.current === playTargetKey) {
                lastPlayedTargetRef.current = "";
              }
              return;
            }
            if (currentGen !== pollGenRef.current || !audioData || !audioData.audio_base64) {
              fetchingTargetRef.current = "";
              return;
            }
            // Re-validate playback state after audio synthesis
            const fresh = await fetchJSON("/api/plugins/voice-document-assistant/status");
            const freshPlaying = fresh && (fresh.state === "playing" || fresh.player_state === "PLAYING") && fresh.client_playback !== false;
            if (
              currentGen !== pollGenRef.current ||
              !freshPlaying ||
              `${fresh.doc_id || ""}:${fresh.current_sentence_index}` !== playTargetKey
            ) {
              fetchingTargetRef.current = "";
              return;
            }
            const audio = new Audio(`data:audio/wav;base64,${audioData.audio_base64}`);
            audio.addEventListener("error", () => {
              fetchingTargetRef.current = "";
              if (lastPlayedTargetRef.current === playTargetKey) {
                lastPlayedTargetRef.current = "";
              }
            }, { once: true });
            if (currentGen !== pollGenRef.current) {
              fetchingTargetRef.current = "";
              return;
            }
            if (data.speed) audio.playbackRate = data.speed;
            const startOffset = data.audio_seconds_offset || 0;
            if (startOffset > 0.05) {
              const setOffset = () => {
                try {
                  if (startOffset < audio.duration) audio.currentTime = startOffset;
                } catch (_) {}
              };
              if (audio.readyState >= 1) setOffset();
              else audio.addEventListener("loadedmetadata", setOffset, { once: true });
            }
            audio.addEventListener("play", () => {
              if (lastPlayedTargetRef.current !== playTargetKey) return;
              fetchJSON("/api/plugins/voice-document-assistant/playback/ack", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ doc_id: fresh.doc_id || targetDocId, sentence_index: currentSentIdx, event: "started" })
              }).catch(() => {});
            }, { once: true });
            let lastProgressAck = 0;
            audio.addEventListener("timeupdate", () => {
              if (lastPlayedTargetRef.current !== playTargetKey) return;
              const now = Date.now();
              if (now - lastProgressAck > 300) {
                lastProgressAck = now;
                fetchJSON("/api/plugins/voice-document-assistant/playback/ack", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ doc_id: fresh.doc_id || targetDocId, sentence_index: currentSentIdx, event: "progress", offset_seconds: audio.currentTime })
                }).catch(() => {});
              }
            });
            audio.addEventListener("ended", () => {
              const sendEndedAck = (retryCount = 0) => {
                if (lastPlayedTargetRef.current !== playTargetKey) return;
                fetchJSON("/api/plugins/voice-document-assistant/playback/ack", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ doc_id: fresh.doc_id || targetDocId, sentence_index: currentSentIdx, event: "ended" })
                }).catch(() => {
                  if (retryCount < 2 && lastPlayedTargetRef.current === playTargetKey) {
                    setTimeout(() => sendEndedAck(retryCount + 1), 1000);
                  }
                });
              };
              sendEndedAck();
            }, { once: true });
            if (currentGen !== pollGenRef.current) {
              fetchingTargetRef.current = "";
              return;
            }
            clientAudioRef.current = audio;
            lastPlayedTargetRef.current = playTargetKey;
            fetchingTargetRef.current = "";
            audio.play().catch(() => {});
          } else if (clientAudioRef.current) {
            if (data.speed && clientAudioRef.current.playbackRate !== data.speed) {
              clientAudioRef.current.playbackRate = data.speed;
            }
            if (clientAudioRef.current.paused && !clientAudioRef.current.ended) {
              if (data.audio_seconds_offset !== undefined && Math.abs(clientAudioRef.current.currentTime - data.audio_seconds_offset) > 0.3) {
                try {
                  clientAudioRef.current.currentTime = data.audio_seconds_offset;
                } catch (_) {}
              }
              clientAudioRef.current.play().catch(() => {});
            }
          }
        } else {
          if (clientAudioRef.current && !clientAudioRef.current.paused) {
            clientAudioRef.current.pause();
          }
          if (data && (data.state === "stopped" || data.state === "finished" || data.player_state === "STOPPED" || data.player_state === "FINISHED")) {
            lastPlayedTargetRef.current = "";
            fetchingTargetRef.current = "";
            clientAudioRef.current = null;
          }
        }
      } catch (err) {
        // silent on background polling
      }
    }, [fetchJSON]);

    const refreshLibrary = useCallback(async () => {
      try {
        const res = await fetchJSON("/api/plugins/voice-document-assistant/library");
        setLibrary(res.documents || []);
      } catch (err) {
        console.warn("Failed to load library:", err);
      }
    }, [fetchJSON]);

    useEffect(() => {
      refreshStatus();
      refreshLibrary();
      const interval = setInterval(refreshStatus, 3000);
      return () => {
        clearInterval(interval);
        fetchingTargetRef.current = "";
        lastPlayedTargetRef.current = "";
        if (clientAudioRef.current) clientAudioRef.current.pause();
      };
    }, [refreshStatus, refreshLibrary]);

    const handleAction = async (endpoint, body = {}) => {
      pollGenRef.current++;
      const normalizedEndpoint = (endpoint === "play" || endpoint === "pause" || endpoint === "resume" || endpoint === "stop" || endpoint === "seek" || endpoint === "config")
        ? `playback/${endpoint}`
        : endpoint;
      if (normalizedEndpoint === "playback/pause" || normalizedEndpoint === "playback/stop" || normalizedEndpoint === "playback/seek" || normalizedEndpoint === "select_document") {
        lastPlayedTargetRef.current = "";
        fetchingTargetRef.current = "";
        if (clientAudioRef.current) clientAudioRef.current.pause();
      }
      const finalBody = (normalizedEndpoint === "playback/play" || normalizedEndpoint === "playback/resume")
        ? { output: "client", ...body }
        : body;
      try {
        await fetchJSON(`/api/plugins/voice-document-assistant/${normalizedEndpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(finalBody),
        });
        await refreshStatus();
      } catch (err) {
        setError(err.message || String(err));
      }
    };

    const handleAsk = async (e) => {
      if (e) e.preventDefault();
      const targetDocId = status?.doc_id || null;
      if (!question.trim() || !targetDocId) return;
      setLoading(true);
      setError(null);
      try {
        const res = await fetchJSON("/api/plugins/voice-document-assistant/ask", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question, doc_id: targetDocId }),
        });
        setAnswer(res);
      } catch (err) {
        setError(err.message || String(err));
      } finally {
        setLoading(false);
      }
    };

    return h(
      "div",
      { className: "hv-dash-root" },
      h(
        "div",
        { className: "hv-dash-header" },
        h(
          "div",
          { className: "hv-dash-title" },
          "NOEMETRA Voice Assistant",
          h("span", { className: "hv-dash-badge" }, (status?.state || status?.player_state || "READY").toUpperCase())
        ),
        h(
          "p",
          { style: { margin: "0.25rem 0 0", color: "var(--ui-text-secondary, #a1a1aa)", fontSize: "0.875rem" } },
          "Assistente documentale con sintesi deterministica Pocket TTS e verifica rigorosa delle citazioni."
        )
      ),
      error &&
        h(
          "div",
          {
            style: {
              padding: "0.75rem",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid #ef4444",
              borderRadius: "0.5rem",
              color: "#f87171",
              marginBottom: "1rem",
            },
          },
          error
        ),
      h(
        "div",
        { className: "hv-dash-grid" },
        h(
          "div",
          { className: "hv-dash-card" },
          h("h3", null, "Riproduzione Audio & Stato"),
          h(
            "div",
            { className: "hv-dash-status-row" },
            h("span", null, "Documento attivo:"),
            h("strong", null, status?.doc_title || status?.current_doc_title || "Nessun documento selezionato")
          ),
          h(
            "div",
            { className: "hv-dash-status-row" },
            h("span", null, "Pagina / Frase:"),
            h("span", null, `Pag. ${status?.current_page || 1} | Frase #${(status?.current_sentence_index || 0) + 1}`)
          ),
          h(
            "div",
            { className: "hv-dash-status-row" },
            h("span", null, "Modello TTS:"),
            h("span", null, status?.tts_model || "italian")
          ),
          h(
            "div",
            { className: "hv-dash-status-row" },
            h("span", null, "Velocità:"),
            h("span", null, `${status?.speed || 1.0}x`)
          ),
          (status?.current_sentence_text || status?.highlight_text) &&
            h(
              "div",
              { className: "hv-dash-quote" },
              `"${status?.current_sentence_text || status?.highlight_text}"`
            ),
          h(
            "div",
            { className: "hv-dash-controls" },
            h(
              "button",
              { className: "hv-dash-btn", onClick: () => handleAction("play") },
              "Riproduci"
            ),
            h(
              "button",
              { className: "hv-dash-btn", onClick: () => handleAction("pause") },
              "Pausa"
            ),
            h(
              "button",
              { className: "hv-dash-btn", onClick: () => handleAction("resume") },
              "Riprendi"
            ),
            h(
              "button",
              { className: "hv-dash-btn", onClick: () => handleAction("stop") },
              "Ferma"
            )
          )
        ),
        h(
          "div",
          { className: "hv-dash-card" },
          h("h3", null, "Libreria Documenti"),
          library.length === 0
            ? h(
                "p",
                { style: { color: "var(--ui-text-secondary, #71717a)", fontSize: "0.875rem" } },
                "Nessun documento in libreria. Carica un PDF via tool o API."
              )
            : h(
                "div",
                { style: { display: "flex", flexDirection: "column", gap: "0.5rem" } },
                library.map((doc) =>
                  h(
                    "div",
                    {
                      key: doc.doc_id || doc.id,
                      className: "hv-dash-status-row",
                      style: { alignItems: "center" },
                    },
                    h(
                      "div",
                      null,
                      h("div", { style: { fontWeight: 500 } }, doc.doc_title || doc.title || doc.filename || doc.doc_id),
                      h(
                        "div",
                        { style: { fontSize: "0.75rem", color: "var(--ui-text-secondary, #71717a)" } },
                        `${doc.total_pages || doc.page_count || 1} pag. | Ultima pag.: ${doc.last_page || 1}`
                      )
                    ),
                    h(
                      "button",
                      {
                        className: "hv-dash-btn",
                        style: { padding: "0.25rem 0.6rem", fontSize: "0.75rem" },
                        onClick: () => handleAction("select_document", { doc_id: doc.doc_id || doc.id }),
                      },
                      "Seleziona"
                    )
                  )
                )
              )
        )
      ),
      h(
        "div",
        { className: "hv-dash-card", style: { marginTop: "1.5rem" } },
        h("h3", null, "Domande & Verifica Citazioni (Triade Agenti)"),
        h(
          "form",
          { onSubmit: handleAsk, style: { display: "flex", gap: "0.5rem", marginTop: "0.5rem" } },
          h("input", {
            type: "text",
            value: question,
            onChange: (e) => setQuestion(e.target.value),
            placeholder: "Fai una domanda sul documento attivo...",
            style: {
              flex: 1,
              padding: "0.5rem 0.75rem",
              borderRadius: "0.375rem",
              border: "1px solid var(--ui-border, #3f3f46)",
              background: "var(--ui-bg-app, #121316)",
              color: "var(--ui-text-primary, #fafafa)",
              fontSize: "0.875rem",
            },
          }),
          h(
            "button",
            {
              type: "submit",
              className: "hv-dash-btn",
              disabled: loading || !question.trim(),
              style: { opacity: loading ? 0.7 : 1 },
            },
            loading ? "Analisi..." : "Chiedi"
          )
        ),
        answer &&
          h(
            "div",
            {
              style: {
                marginTop: "1rem",
                padding: "1rem",
                background: "var(--ui-bg-subtle, #1f1f23)",
                borderRadius: "0.5rem",
              },
            },
            h("div", { style: { fontWeight: 600, marginBottom: "0.5rem" } }, "Risposta Verificata:"),
            h("p", { style: { margin: "0 0 0.5rem", lineHeight: 1.5, fontSize: "0.9rem" } }, answer.answer),
            h(
              "div",
              { style: { display: "flex", gap: "0.5rem", alignItems: "center", fontSize: "0.75rem" } },
              h(
                "span",
                {
                  style: {
                    color: (answer.verification ? answer.verification.is_valid : answer.is_grounded) ? "#22c55e" : "#ef4444",
                    fontWeight: 600,
                  },
                },
                (answer.verification ? answer.verification.is_valid : answer.is_grounded)
                  ? "✓ Verificata dal Verificatore"
                  : "⚠ Non verificata"
              ),
              answer.citations &&
                answer.citations.length > 0 &&
                h(
                  "span",
                  { style: { color: "var(--ui-text-secondary, #a1a1aa)" } },
                  `Citazioni: pag. ${answer.citations.map((c) => c.page_number).join(", ")}`
                )
            )
          )
      )
    );
  }

  registry.register("voice-document-assistant", VoiceDocumentDashboard);
})();
