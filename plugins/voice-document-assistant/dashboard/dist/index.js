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
    const lastPlayedSentRef = useRef(-1);

    const refreshStatus = useCallback(async () => {
      try {
        const data = await fetchJSON("/api/plugins/voice-document-assistant/status");
        setStatus(data);
        // Client-side desktop audio stream
        if (data && data.player_state === "PLAYING") {
          if (data.current_sentence_index !== lastPlayedSentRef.current) {
            lastPlayedSentRef.current = data.current_sentence_index;
            if (clientAudioRef.current) clientAudioRef.current.pause();
            const audio = new Audio("/api/plugins/voice-document-assistant/audio/sentence/" + data.current_sentence_index);
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
            clientAudioRef.current = audio;
            audio.play().catch(() => {});
          } else if (clientAudioRef.current) {
            if (data.speed && clientAudioRef.current.playbackRate !== data.speed) {
              clientAudioRef.current.playbackRate = data.speed;
            }
            if (clientAudioRef.current.paused) {
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
          if (data && (data.player_state === "STOPPED" || data.player_state === "FINISHED")) {
            lastPlayedSentRef.current = -1;
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
        if (clientAudioRef.current) clientAudioRef.current.pause();
      };
    }, [refreshStatus, refreshLibrary]);

    const handleAction = async (endpoint, body = {}) => {
      const normalizedEndpoint = (endpoint === "play" || endpoint === "pause" || endpoint === "resume" || endpoint === "stop" || endpoint === "seek" || endpoint === "config")
        ? `playback/${endpoint}`
        : endpoint;
      if (normalizedEndpoint === "playback/pause" || normalizedEndpoint === "playback/stop") {
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
      if (!question.trim()) return;
      setLoading(true);
      setError(null);
      try {
        const res = await fetchJSON("/api/plugins/voice-document-assistant/ask", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question }),
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
          h("span", { className: "hv-dash-badge" }, status?.player_state || "READY")
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
            h("strong", null, status?.current_doc_title || "Nessun documento selezionato")
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
          status?.highlight_text &&
            h(
              "div",
              { className: "hv-dash-quote" },
              `"${status.highlight_text}"`
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
                      key: doc.id,
                      className: "hv-dash-status-row",
                      style: { alignItems: "center" },
                    },
                    h(
                      "div",
                      null,
                      h("div", { style: { fontWeight: 500 } }, doc.title || doc.filename),
                      h(
                        "div",
                        { style: { fontSize: "0.75rem", color: "var(--ui-text-secondary, #71717a)" } },
                        `${doc.page_count} pag. | Pag. corrente: ${doc.last_page}`
                      )
                    ),
                    h(
                      "button",
                      {
                        className: "hv-dash-btn",
                        style: { padding: "0.25rem 0.6rem", fontSize: "0.75rem" },
                        onClick: () => handleAction("select_document", { doc_id: doc.id }),
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
                { style: { color: answer.is_grounded ? "#22c55e" : "#ef4444", fontWeight: 600 } },
                answer.is_grounded ? "✓ Verificata dal Verificatore" : "⚠ Non verificata"
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
