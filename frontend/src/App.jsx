import { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import "./styles.css";

const api = async (path, opts) => {
  const r = await fetch(`/api${path}`, opts);
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json();
};

const SEV = { CRITICAL: "#ef4444", HIGH: "#f59e0b", MEDIUM: "#eab308", LOW: "#22c55e" };
const TYPE_COLOR = {
  GitHubUser: "#8b7cf6", GitHubTeam: "#8b7cf6", Repository: "#5b8def", Workflow: "#38bdf8", Secret: "#f472b6",
  OIDCProvider: "#2dd4bf", IAMUser: "#fb923c", IAMRole: "#fb923c", IAMPolicy: "#fbbf24", Resource: "#ef4444",
};
const COLUMN = { GitHubUser: 0, GitHubTeam: 0, Repository: 1, Workflow: 2, Secret: 2, OIDCProvider: 3, IAMUser: 3, IAMRole: 3, IAMPolicy: 4, Resource: 5 };

const nodeStyle = (type, strong = false) => ({
  background: "#181226", color: "#f3f0ff", border: `2px solid ${TYPE_COLOR[type] || "#888"}`,
  borderRadius: 10, padding: "8px 10px", fontSize: 12, width: 150, textAlign: "center",
  boxShadow: strong ? `0 0 14px ${TYPE_COLOR[type]}66` : "none",
});

function Stat({ label, value, color }) {
  return (
    <div className="stat">
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function FlowView({ flow }) {
  const { nodes, edges } = useMemo(() => {
    const last = flow.nodes.length - 1;
    return {
      nodes: flow.nodes.map((n, i) => ({
        id: n.id, position: { x: i * 230, y: 40 + (i % 2) * 60 }, data: { label: `${n.name}\n(${n.type})` },
        style: { ...nodeStyle(n.type, i === 0 || i === last), whiteSpace: "pre-line" }, draggable: false,
      })),
      edges: flow.edges.map((e, i) => ({
        id: `e${i}`, source: e.source, target: e.target, label: e.label, animated: true,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#8b7cf6" }, style: { stroke: "#8b7cf6" },
        labelStyle: { fill: "#c9c2f5", fontSize: 11 }, labelBgStyle: { fill: "#0f0b1a" },
      })),
    };
  }, [flow]);
  return (
    <div className="flow">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} nodesConnectable={false}>
        <Background color="#2a2145" /><Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function Explorer() {
  const [g, setG] = useState(null);
  useEffect(() => { api("/graph").then(setG).catch(() => {}); }, []);
  const { nodes, edges } = useMemo(() => {
    if (!g) return { nodes: [], edges: [] };
    const rowCount = {};
    return {
      nodes: g.nodes.map((n) => {
        const col = COLUMN[n.type] ?? 0;
        const row = (rowCount[col] = (rowCount[col] ?? -1) + 1);
        return { id: n.id, position: { x: col * 210, y: row * 70 }, data: { label: n.name }, style: { ...nodeStyle(n.type), width: 140 } };
      }),
      edges: g.edges.map((e, i) => ({ id: `g${i}`, source: e.source, target: e.target, label: e.rel,
        style: { stroke: "#4b3f7a" }, labelStyle: { fill: "#9a90c9", fontSize: 9 }, labelBgStyle: { fill: "#0f0b1a" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#4b3f7a" } })),
    };
  }, [g]);
  return (
    <div className="flow tall">
      <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} proOptions={{ hideAttribution: true }}>
        <Background color="#2a2145" /><Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("dashboard");
  const [summary, setSummary] = useState(null);
  const [paths, setPaths] = useState([]);
  const [toxic, setToxic] = useState(null);
  const [entries, setEntries] = useState([]);
  const [entry, setEntry] = useState("");
  const [sel, setSel] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (entryFilter = entry) => {
    try {
      const q = entryFilter ? `?entry=${encodeURIComponent(entryFilter)}` : "";
      const [s, p, t, e] = await Promise.all([api("/summary"), api(`/paths${q}`), api("/toxic"), api("/entry-points")]);
      setSummary(s); setPaths(p); setToxic(t); setEntries(e); setError("");
      setSel(p[0] ? await api(`/paths/${p[0].id}`) : null);
    } catch (err) { setError(err.message); }
  }, [entry]);

  useEffect(() => { load(); }, []); // eslint-disable-line

  const pick = async (id, llm = false) => setSel(await api(`/paths/${id}?llm=${llm}`));
  const scan = async (source) => {
    setBusy(true);
    try { await api("/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source, sync_neo4j: true }) }); await load(); }
    catch (err) { setError(err.message); }
    setBusy(false);
  };

  return (
    <div className="app">
      <header>
        <div>
          <h1>BreachPath CI/CD</h1>
          <p>Which cloud assets can a compromised GitHub account reach?</p>
        </div>
        <div className="actions">
          <button onClick={() => scan("mock")} disabled={busy}>Scan demo data</button>
          <button className="primary" onClick={() => scan("live")} disabled={busy}>{busy ? "Scanning..." : "Scan my GitHub and AWS"}</button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <nav>
        {[["dashboard", "Attack paths"], ["toxic", "Toxic permissions"], ["graph", "Graph explorer"]].map(([k, l]) => (
          <button key={k} className={tab === k ? "tab on" : "tab"} onClick={() => setTab(k)}>{l}</button>
        ))}
        {summary && <span className="meta">{summary.source} data{summary.llm_enabled ? " · LLM on" : ""}</span>}
      </nav>

      {summary && (
        <section className="stats">
          <Stat label="Critical paths" value={summary.severity.CRITICAL} color={SEV.CRITICAL} />
          <Stat label="High-risk paths" value={summary.severity.HIGH} color={SEV.HIGH} />
          <Stat label="Medium-risk paths" value={summary.severity.MEDIUM} color={SEV.MEDIUM} />
          <Stat label="Assets" value={summary.total_assets} />
          <Stat label="Identities" value={summary.total_identities} />
        </section>
      )}

      {tab === "dashboard" && (
        <div className="grid">
          <div className="panel">
            <div className="row">
              <h2>Top attack paths</h2>
              <select value={entry} onChange={(e) => { setEntry(e.target.value); load(e.target.value); }}>
                <option value="">All entry points</option>
                {entries.map((e) => <option key={e.id} value={e.name}>{e.name} ({e.confirmed_paths})</option>)}
              </select>
            </div>
            {paths.length === 0 && <p className="muted">No attack paths found for this selection.</p>}
            {paths.map((p) => (
              <div key={p.id} className={`path ${sel?.id === p.id ? "on" : ""}`} onClick={() => pick(p.id)}>
                <span className="score" style={{ color: SEV[p.severity] }}>{p.score}</span>
                <div>
                  <div className="chain">{p.nodes.map((n) => n.name).join("  →  ")}</div>
                  <div className="muted">{p.severity.toLowerCase()} · {p.hops} steps{p.toxic_rules.length ? ` · ${p.toxic_rules.join(", ")}` : ""}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="panel">
            {sel ? (
              <>
                <div className="row">
                  <h2>Path explanation</h2>
                  <span className="pill" style={{ borderColor: SEV[sel.severity], color: SEV[sel.severity] }}>{sel.score}/100 {sel.severity.toLowerCase()}</span>
                </div>
                <FlowView flow={sel.explanation.flow} />
                <p className="summary">{sel.explanation.summary}</p>
                <ol className="steps">{sel.explanation.steps.map((s) => <li key={s.n}>{s.text}</li>)}</ol>
                {sel.explanation.llm_text && <blockquote>{sel.explanation.llm_text}</blockquote>}
                {summary?.llm_enabled && !sel.explanation.llm_text && <button onClick={() => pick(sel.id, true)}>Explain in plain English</button>}
                <h3>Why this score</h3>
                <div className="breakdown">
                  {Object.entries(sel.breakdown).map(([k, v]) => (
                    <div key={k} className="bar"><span>{k}</span><div><i style={{ width: `${v.value * 100}%`, background: SEV[v.level] }} /></div><b>{v.level.toLowerCase()}</b></div>
                  ))}
                </div>
                {sel.explanation.fixes.length > 0 && (<><h3>How to fix it</h3><ul>{sel.explanation.fixes.map((f) => <li key={f}>{f}</li>)}</ul></>)}
              </>
            ) : <p className="muted">Select a path to see how the attack works.</p>}
          </div>
        </div>
      )}

      {tab === "toxic" && toxic && (
        <div className="panel">
          <h2>Toxic permission combinations</h2>
          <p className="muted">{toxic.quantification.toxic_combo_paths} of {toxic.quantification.total_paths} paths ({toxic.quantification.toxic_share_pct}%) exist only because several permissions combine. {toxic.quantification.single_misconfig_paths} come from a single misconfiguration.</p>
          {toxic.alerts.map((a) => (
            <div key={a.id} className="alert"><b>{a.count}</b><div><div>{a.name} <span className="muted">({a.id})</span></div><div className="muted">{a.description}</div></div></div>
          ))}
          <h3>Frequently co-occurring permissions</h3>
          <table><thead><tr><th>Combination</th><th>Support</th><th>Lift</th></tr></thead>
            <tbody>{toxic.frequent_combinations.map((c) => <tr key={c.combo.join()}><td>{c.combo.join(" + ")}</td><td>{c.support}</td><td>{c.lift}</td></tr>)}</tbody></table>
        </div>
      )}

      {tab === "graph" && <div className="panel"><h2>Security graph</h2><Explorer /></div>}
    </div>
  );
}
