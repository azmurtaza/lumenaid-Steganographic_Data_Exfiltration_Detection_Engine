import React, { useState, useEffect, useCallback, useRef } from "react";

const API = "http://localhost:8000";

// ---------------------------------------------------------------------------
// Colour helpers — maps entropy → CSS rgb() string
//
// Three-stop gradient anchored to the file-type baseline:
//   0.0              → dark green  hsl(142, 70%, 18%)
//   mean             → yellow      hsl(48,  96%, 53%)
//   mean + sigma+    → bright red  hsl(0,   90%, 50%)
//
// Values between anchors are linearly interpolated in HSL space.
// ---------------------------------------------------------------------------
function entropyToColor(entropy, mean, sigma) {
  const threshold = mean + sigma;

  const lerp = (a, b, t) => a + (b - a) * Math.max(0, Math.min(1, t));

  let h, s, l;

  if (entropy <= mean) {
    // dark-green → yellow
    const t = mean === 0 ? 0 : entropy / mean;
    h = lerp(142, 48, t);
    s = lerp(70, 96, t);
    l = lerp(18, 53, t);
  } else {
    // yellow → bright-red
    const t = threshold === mean ? 1 : (entropy - mean) / (threshold - mean);
    h = lerp(48, 0, t);
    s = lerp(96, 90, t);
    l = lerp(53, 50, t);
  }

  return `hsl(${h.toFixed(1)}, ${s.toFixed(1)}%, ${l.toFixed(1)}%)`;
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------
function SeverityBadge({ severity }) {
  const palette = {
    CRITICAL: { bg: "#ff1744", text: "#fff" },
    HIGH: { bg: "#ff5722", text: "#fff" },
    MEDIUM: { bg: "#ff9800", text: "#111" },
    LOW: { bg: "#ffc107", text: "#111" },
  };
  const style = palette[severity] || { bg: "#555", text: "#fff" };
  return (
    <span
      style={{
        background: style.bg,
        color: style.text,
        padding: "2px 10px",
        borderRadius: 99,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 0.8,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Upload zone
// ---------------------------------------------------------------------------
function UploadZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const inputRef = useRef();

  const doUpload = useCallback(async (file) => {
    setLoading(true);
    setMessage(null);
    const form = new FormData();
    form.append("file", file);

    try {
      const res = await fetch(`${API}/upload`, { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      setMessage({ type: data.status === "FLAGGED" ? "warn" : "ok", text: data.message });
      onUploaded();
    } catch (e) {
      setMessage({ type: "err", text: e.message });
    } finally {
      setLoading(false);
    }
  }, [onUploaded]);

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) doUpload(file);
  };

  const msgColors = { ok: "#00e676", warn: "#ff9800", err: "#ff1744" };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current.click()}
      style={{
        border: `2px dashed ${dragging ? "#7c4dff" : "#334"}`,
        borderRadius: 16,
        padding: "36px 24px",
        textAlign: "center",
        cursor: "pointer",
        background: dragging ? "rgba(124,77,255,0.07)" : "rgba(255,255,255,0.02)",
        transition: "all 0.2s",
        userSelect: "none",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: "none" }}
        onChange={(e) => e.target.files[0] && doUpload(e.target.files[0])}
      />
      {loading ? (
        <Spinner />
      ) : (
        <>
          <div style={{ fontSize: 40, marginBottom: 8 }}>📂</div>
          <p style={{ color: "#aab", margin: 0 }}>
            Drag &amp; drop a file here, or click to browse
          </p>
        </>
      )}
      {message && (
        <p style={{ marginTop: 14, color: msgColors[message.type], fontWeight: 600 }}>
          {message.text}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// File list table
// ---------------------------------------------------------------------------
function statusStyle(status) {
  const map = {
    FLAGGED: { color: "#ff5252", icon: "🔴" },
    CLEAN: { color: "#69f0ae", icon: "🟢" },
    PENDING: { color: "#90a4ae", icon: "⏳" },
    SCANNING: { color: "#82b1ff", icon: "🔍" },
    ERROR: { color: "#ff6d00", icon: "⚠️" },
  };
  return map[status?.toUpperCase()] || { color: "#ccc", icon: "❓" };
}

function FileTable({ files, selectedId, onSelect }) {
  if (!files.length)
    return (
      <p style={{ color: "#667", textAlign: "center", padding: 24 }}>
        No files scanned yet. Upload one above.
      </p>
    );

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #223" }}>
            {["ID", "Name", "Type", "Status", "Submitted"].map((h) => (
              <th
                key={h}
                style={{
                  padding: "10px 14px",
                  textAlign: "left",
                  color: "#667",
                  fontWeight: 600,
                  letterSpacing: 0.5,
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {files.map((f) => {
            const st = statusStyle(f.status);
            const isSelected = f.file_id === selectedId;
            return (
              <tr
                key={f.file_id}
                onClick={() => onSelect(f.file_id)}
                style={{
                  borderBottom: "1px solid #1a1e2b",
                  cursor: "pointer",
                  background: isSelected
                    ? "rgba(124,77,255,0.12)"
                    : "transparent",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = isSelected
                    ? "rgba(124,77,255,0.12)"
                    : "transparent";
                }}
              >
                <td style={{ padding: "10px 14px", color: "#667" }}>{f.file_id}</td>
                <td style={{ padding: "10px 14px", color: "#dde" }}>
                  {f.file_name || <em style={{ color: "#556" }}>unnamed</em>}
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <code style={{ color: "#9c8cff", fontSize: 12 }}>{f.file_type?.toUpperCase()}</code>
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <span style={{ color: st.color, fontWeight: 600 }}>
                    {st.icon} {f.status}
                  </span>
                </td>
                <td style={{ padding: "10px 14px", color: "#667" }}>
                  {new Date(f.submitted_at).toLocaleString()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Entropy heatmap
// ---------------------------------------------------------------------------
function EntropyHeatmap({ segments, baseline }) {
  const [tooltip, setTooltip] = useState(null);
  const mean = baseline?.mean_entropy ?? 4.0;
  const sigma = baseline?.threshold_sigma ?? 1.0;

  if (!segments.length)
    return <p style={{ color: "#556", textAlign: "center" }}>No segments found.</p>;

  return (
    <div>
      {/* Legend */}
      <div style={{ display: "flex", gap: 18, marginBottom: 14, flexWrap: "wrap" }}>
        {[
          { color: "hsl(142,70%,18%)", label: "Low (0.0)" },
          { color: "hsl(48,96%,53%)", label: `Baseline (${mean.toFixed(2)})` },
          { color: "hsl(0,90%,50%)", label: `Anomaly (>${(mean + sigma).toFixed(2)})` },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 14, height: 14, borderRadius: 3, background: color }} />
            <span style={{ fontSize: 12, color: "#889" }}>{label}</span>
          </div>
        ))}
      </div>

      {/* Grid */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 3,
          position: "relative",
        }}
      >
        {segments.map((seg) => {
          const color = entropyToColor(seg.entropy_score, mean, sigma);
          const isAnomaly = seg.entropy_score > mean + sigma;
          return (
            <div
              key={seg.segment_id}
              onMouseEnter={(e) =>
                setTooltip({
                  x: e.clientX,
                  y: e.clientY,
                  seg,
                  isAnomaly,
                })
              }
              onMouseMove={(e) =>
                setTooltip((t) => t && { ...t, x: e.clientX, y: e.clientY })
              }
              onMouseLeave={() => setTooltip(null)}
              style={{
                width: 22,
                height: 22,
                borderRadius: 4,
                background: color,
                boxShadow: isAnomaly ? `0 0 8px 2px ${color}` : "none",
                cursor: "default",
                transition: "transform 0.1s",
              }}
              onMouseOver={(e) => { e.currentTarget.style.transform = "scale(1.35)"; }}
              onFocus={() => { }}
              onBlur={() => { }}
            />
          );
        })}
      </div>

      {/* Floating tooltip */}
      {tooltip && (
        <div
          style={{
            position: "fixed",
            left: tooltip.x + 14,
            top: tooltip.y + 14,
            background: "#0d1117",
            border: "1px solid #334",
            borderRadius: 8,
            padding: "8px 12px",
            fontSize: 12,
            color: "#dde",
            pointerEvents: "none",
            zIndex: 9999,
            minWidth: 180,
            boxShadow: "0 4px 24px rgba(0,0,0,0.5)",
          }}
        >
          <div style={{ fontWeight: 700, marginBottom: 4 }}>
            Segment #{tooltip.seg.segment_index}
          </div>
          <div>Entropy: <strong style={{ color: tooltip.isAnomaly ? "#ff5252" : "#69f0ae" }}>
            {tooltip.seg.entropy_score.toFixed(4)}
          </strong></div>
          <div style={{ color: "#667", marginTop: 2 }}>
            Threshold: {(mean + sigma).toFixed(4)}
          </div>
          {tooltip.isAnomaly && (
            <div style={{ color: "#ff5252", fontWeight: 600, marginTop: 4 }}>
              ⚠ ANOMALY
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Threat panel — shown only when status === FLAGGED
// ---------------------------------------------------------------------------
function ThreatPanel({ alerts }) {
  if (!alerts.length)
    return (
      <p style={{ color: "#556", fontStyle: "italic" }}>No alert records found.</p>
    );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {alerts.map((a) => (
        <div
          key={a.alert_id}
          style={{
            background: "rgba(255,82,82,0.07)",
            border: "1px solid rgba(255,82,82,0.25)",
            borderRadius: 10,
            padding: "12px 16px",
            display: "flex",
            alignItems: "flex-start",
            gap: 12,
          }}
        >
          <span style={{ fontSize: 20, lineHeight: 1 }}>🚨</span>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <SeverityBadge severity={a.severity} />
              {a.entropy_score != null && (
                <span style={{ color: "#778", fontSize: 12 }}>
                  score: <strong style={{ color: "#ff5252" }}>{a.entropy_score.toFixed(4)}</strong>
                </span>
              )}
            </div>
            <p style={{ margin: 0, color: "#ccd", fontSize: 13 }}>
              {a.description || "No description provided."}
            </p>
            <p style={{ margin: "4px 0 0", color: "#556", fontSize: 11 }}>
              {new Date(a.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
function Spinner() {
  return (
    <div
      style={{
        width: 28,
        height: 28,
        border: "3px solid #334",
        borderTop: "3px solid #7c4dff",
        borderRadius: "50%",
        animation: "spin 0.7s linear infinite",
        margin: "0 auto",
      }}
    />
  );
}

function Card({ children, style = {} }) {
  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        border: "1px solid #1f2535",
        borderRadius: 16,
        padding: 24,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <h2
      style={{
        margin: "0 0 16px",
        fontSize: 15,
        fontWeight: 700,
        color: "#9c8cff",
        letterSpacing: 1,
        textTransform: "uppercase",
      }}
    >
      {children}
    </h2>
  );
}

// ---------------------------------------------------------------------------
// Main Dashboard component
// ---------------------------------------------------------------------------
export default function Dashboard() {
  const [files, setFiles] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loadingAna, setLoadingAna] = useState(false);

  const fetchFiles = useCallback(async () => {
    try {
      const res = await fetch(`${API}/files`);
      const data = await res.json();
      setFiles(data);
    } catch {
      /* silently retry on next upload */
    }
  }, []);

  const fetchAnalysis = useCallback(async (id) => {
    setLoadingAna(true);
    setAnalysis(null);
    try {
      const res = await fetch(`${API}/files/${id}/analysis`);
      const data = await res.json();
      setAnalysis(data);
    } catch {
      setAnalysis(null);
    } finally {
      setLoadingAna(false);
    }
  }, []);

  useEffect(() => { fetchFiles(); }, [fetchFiles]);

  const handleSelect = (id) => {
    setSelectedId(id);
    fetchAnalysis(id);
  };

  const handleUploaded = () => {
    fetchFiles();
  };

  const isFlagged = analysis?.status?.toUpperCase() === "FLAGGED";

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#080c14",
        color: "#dde",
        fontFamily: "'Inter', system-ui, sans-serif",
        padding: "32px 24px",
        boxSizing: "border-box",
      }}
    >
      {/* CSS for spinner + hover reset */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        * { box-sizing: border-box; }
        body { margin: 0; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        .fade-in { animation: fadeIn 0.3s ease; }
      `}</style>

      {/* ── Header ── */}
      <header style={{ maxWidth: 1200, margin: "0 auto 32px", display: "flex", alignItems: "center", gap: 16 }}>
        <div
          style={{
            width: 44,
            height: 44,
            borderRadius: 12,
            background: "linear-gradient(135deg, #7c4dff, #00e5ff)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 22,
            flexShrink: 0,
          }}
        >
          🔬
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, letterSpacing: -0.5 }}>
            LumenAid
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: "#667" }}>
            Steganographic Data Exfiltration Detection Engine
          </p>
        </div>
      </header>

      <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", flexDirection: "column", gap: 24 }}>

        {/* ── Upload ── */}
        <Card>
          <SectionTitle>Upload &amp; Scan</SectionTitle>
          <UploadZone onUploaded={handleUploaded} />
        </Card>

        {/* ── File list ── */}
        <Card>
          <SectionTitle>Scanned Files</SectionTitle>
          <FileTable files={files} selectedId={selectedId} onSelect={handleSelect} />
        </Card>

        {/* ── Analysis pane (shown after selecting a file) ── */}
        {(selectedId || loadingAna) && (
          <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: 24 }}>

            {loadingAna && (
              <Card style={{ textAlign: "center", padding: 48 }}>
                <Spinner />
                <p style={{ color: "#556", marginTop: 12 }}>Loading analysis…</p>
              </Card>
            )}

            {analysis && !loadingAna && (
              <>
                {/* ── File summary bar ── */}
                <Card
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 16,
                    flexWrap: "wrap",
                    background: isFlagged
                      ? "rgba(255,82,82,0.05)"
                      : "rgba(105,240,174,0.04)",
                    border: isFlagged
                      ? "1px solid rgba(255,82,82,0.2)"
                      : "1px solid rgba(105,240,174,0.15)",
                  }}
                >
                  <div style={{ fontSize: 36 }}>{isFlagged ? "🔴" : "🟢"}</div>
                  <div>
                    <p style={{ margin: 0, fontSize: 18, fontWeight: 700, color: isFlagged ? "#ff5252" : "#69f0ae" }}>
                      {isFlagged ? "THREAT DETECTED" : "FILE IS CLEAN"}
                    </p>
                    <p style={{ margin: 0, fontSize: 13, color: "#667" }}>
                      file_id {analysis.file_id} &nbsp;·&nbsp;
                      type <code style={{ color: "#9c8cff" }}>{analysis.file_type?.toUpperCase()}</code> &nbsp;·&nbsp;
                      {analysis.segments.length} segments
                    </p>
                  </div>
                  {analysis.baseline && (
                    <div style={{ marginLeft: "auto", textAlign: "right" }}>
                      <p style={{ margin: 0, fontSize: 12, color: "#556" }}>Baseline</p>
                      <p style={{ margin: 0, fontSize: 13, color: "#9c8cff", fontWeight: 600 }}>
                        μ = {analysis.baseline.mean_entropy.toFixed(4)} &nbsp;
                        σ = {analysis.baseline.threshold_sigma.toFixed(4)}
                      </p>
                    </div>
                  )}
                </Card>

                {/* ── Entropy heatmap ── */}
                <Card>
                  <SectionTitle>Entropy Heatmap</SectionTitle>
                  <EntropyHeatmap
                    segments={analysis.segments}
                    baseline={analysis.baseline}
                  />
                </Card>

                {/* ── Threat panel (only when FLAGGED) ── */}
                {isFlagged && (
                  <Card
                    style={{
                      border: "1px solid rgba(255,82,82,0.3)",
                      background: "rgba(255,82,82,0.03)",
                    }}
                  >
                    <SectionTitle>⚠ Threat Alerts</SectionTitle>
                    <ThreatPanel alerts={analysis.alerts} />
                  </Card>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
