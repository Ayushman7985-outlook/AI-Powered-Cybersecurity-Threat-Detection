import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, Database, RefreshCw, Shield, ShieldAlert, Wifi } from "lucide-react";
import "./index.css";

const API = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
type Health = { status: string; model_ready: boolean };
type ModelStatus = { ready: boolean; artifact_path: string; error: string | null };
type Metric = { dataset: string; testing_rows: number; accuracy: number; precision: number; recall: number; f1_score: number; confusion_matrix: number[][] };
type Sample = { source_type: "dataset"; dataset_label_for_comparison_only: number; features: Record<string, unknown> };
type Prediction = { event_id: string; predicted_label: number; prediction: "normal" | "attack"; confidence: number | null; attack_probability: number | null; source_type: "dataset" | "synthetic"; alert: { timestamp: string; severity: string } | null };
type Detection = { event_id: string; timestamp: string; predicted_label: number; prediction: string; confidence: number | null; severity: string | null; source_type: string };
type History = { items: Detection[]; total: number; limit: number };

async function get<T>(path: string): Promise<T> {
  let response: Response;
  try { response = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(10000), headers: { Accept: "application/json" } }); }
  catch (error) { throw new Error(`Cannot reach API at ${API}. ${error instanceof Error ? error.message : "Network error"}`); }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `API returned HTTP ${response.status}.`);
  return body as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  try { response = await fetch(`${API}${path}`, { method: "POST", signal: AbortSignal.timeout(15000), headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch (error) { throw new Error(`Cannot reach API at ${API}. ${error instanceof Error ? error.message : "Network error"}`); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : `API returned HTTP ${response.status}.`);
  return data as T;
}

function percent(value?: number | null) { return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "Not available"; }
function date(value: string) { const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString(); }

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [model, setModel] = useState<ModelStatus | null>(null);
  const [metrics, setMetrics] = useState<Metric | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [features, setFeatures] = useState("");
  const [sampleLabel, setSampleLabel] = useState<number | null>(null);
  const [source, setSource] = useState<"dataset" | "synthetic">("dataset");
  const [prediction, setPrediction] = useState<Prediction | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(false);

  const refresh = useCallback(async () => {
    setChecking(true);
    const [healthResult, modelResult, metricsResult, historyResult] = await Promise.allSettled([
      get<Health>("/health"), get<ModelStatus>("/model/status"), get<Metric>("/metrics"), get<History>("/detections?limit=8"),
    ]);
    setHealth(healthResult.status === "fulfilled" ? healthResult.value : null);
    setModel(modelResult.status === "fulfilled" ? modelResult.value : null);
    setMetrics(metricsResult.status === "fulfilled" ? metricsResult.value : null);
    setHistory(historyResult.status === "fulfilled" ? historyResult.value : null);
    const failed = [healthResult, modelResult, historyResult].find((result) => result.status === "rejected");
    setError(failed?.status === "rejected" ? failed.reason.message : "");
    setChecking(false);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const loadSample = async () => {
    setError(""); setPrediction(null); setLoading(true);
    try {
      const sample = await get<Sample>("/dataset/sample?split=test&index=0");
      setFeatures(JSON.stringify(sample.features, null, 2));
      setSampleLabel(sample.dataset_label_for_comparison_only);
      setSource("dataset");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load dataset sample."); }
    finally { setLoading(false); }
  };

  const classify = async (event: React.FormEvent) => {
    event.preventDefault(); setError(""); setPrediction(null);
    let values: unknown;
    try { values = JSON.parse(features); }
    catch { setError("Features must be valid JSON."); return; }
    if (typeof values !== "object" || values === null || Array.isArray(values)) { setError("Enter a JSON object containing all model features."); return; }
    setLoading(true);
    try {
      const result = await post<Prediction>("/predict", { features: values, source_type: source });
      setPrediction(result);
      const updated = await get<History>("/detections?limit=8");
      setHistory(updated);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Prediction failed."); }
    finally { setLoading(false); }
  };

  const chart = metrics ? [
    { name: "Normal", count: metrics.confusion_matrix[0][0] + metrics.confusion_matrix[1][0], color: "#47d6c4" },
    { name: "Attack", count: metrics.confusion_matrix[0][1] + metrics.confusion_matrix[1][1], color: "#ff667d" },
  ] : [];
  const chartMax = Math.max(1, ...chart.map((item) => item.count));

  return <div className="app"><aside className="sidebar"><a className="brand" href="#top"><span className="brand-icon"><Shield size={20} /></span><span><b>CYBER<span>OPS</span></b><small>THREAT DETECTION</small></span></a><div className="nav-label">COMMAND CENTER</div><a className="nav-item active" href="#overview"><Activity size={17} />Overview</a><a className="nav-item" href="#predict"><ShieldAlert size={17} />Test prediction</a><a className="nav-item" href="#history"><Database size={17} />Detection history</a><div className="sidebar-bottom"><i className="live-dot" />Offline flow analysis<small>No live packet capture</small></div></aside>
    <main id="top" className="main"><header className="topbar"><div><div className="crumb">SECURITY OPERATIONS <span>/</span> OVERVIEW</div><h1>Cybersecurity Command Center</h1></div><div className="top-actions"><span className={`status ${health?.status === "healthy" ? "ok" : "bad"}`}><i />API {health?.status === "healthy" ? "CONNECTED" : "OFFLINE"}</span><span className={`status ${model?.ready ? "ok" : "bad"}`}><i />MODEL {model?.ready ? "READY" : "NOT READY"}</span><button className="icon-button" onClick={() => void refresh()} disabled={checking} aria-label="Refresh status"><RefreshCw size={16} className={checking ? "spin" : ""} /></button></div></header>
      <section id="overview" className="content"><div className="intro"><div><div className="eyebrow">OFFLINE MODEL MONITORING</div><h2>Threat detection overview</h2><p>Saved UNSW-NB15 benchmark results and local prediction history.</p></div><span className="offline-tag"><Wifi size={14} /> Local analysis</span></div>
        {error && <div className="error-banner" role="alert"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => void refresh()}>Retry</button></div>}
        {model && !model.ready && <div className="warning-banner"><AlertTriangle size={17} /><span>Model not ready. Prediction requests are disabled until a trained artifact is available.</span></div>}
        <div className="metrics"><Metric label="Held-out test records" value={metrics?.testing_rows?.toLocaleString() ?? "Not available"} note="Official test split · not live events" icon="01" /><Metric label="Attack recall" value={percent(metrics?.recall)} note="Labeled attacks detected" icon="02" tone="red" /><Metric label="Attack precision" value={percent(metrics?.precision)} note="Attack predictions correct" icon="03" tone="amber" /><Metric label="Attack F1 score" value={percent(metrics?.f1_score)} note="Precision and recall balance" icon="04" tone="violet" /><Metric label="Recorded detections" value={history?.total.toLocaleString() ?? "Not available"} note="Persisted local history" icon="05" tone="green" /><Metric label="Model status" value={model ? (model.ready ? "Ready" : "Unavailable") : "Not available"} note={model?.artifact_path ?? "Check backend connection"} icon="06" tone="blue" /></div>
        <div className="section-heading"><div><h3>Test split predictions</h3><p>Actual predicted class counts from the saved confusion matrix</p></div><span className="dataset-chip">HELD-OUT DATASET</span></div>
        <section className="panel chart-panel"><div className="chart-area">{chart.length ? chart.map((item) => <div className="bar-row" key={item.name}><span>{item.name}</span><div className="bar-track"><i style={{ width: `${Math.max(3, item.count / chartMax * 100)}%`, background: item.color }} /></div><b>{item.count.toLocaleString()}</b></div>) : <p className="empty">Saved evaluation metrics are unavailable.</p>}</div><div className="chart-note">Test-set predictions only. This chart is not a live traffic stream.</div></section>
        <section id="predict" className="panel predict-panel"><div className="section-heading"><div><span className="eyebrow">MODEL INFERENCE</span><h3>Test a network-flow record</h3><p>Load a real held-out row, or enter the complete model feature object as JSON.</p></div><button className="button secondary" onClick={() => void loadSample()} disabled={loading || !model?.ready}>Load test dataset sample</button></div><form onSubmit={classify}><div className="form-row"><label>Record source<select value={source} onChange={(e) => setSource(e.target.value as "dataset" | "synthetic")}><option value="dataset">Dataset record</option><option value="synthetic">Synthetic demonstration</option></select></label><label className="label-hint">Feature schema is validated by the backend · all 42 model inputs are required</label></div><label className="feature-label">Model features<textarea value={features} onChange={(e) => { setFeatures(e.target.value); setSampleLabel(null); }} placeholder="Load a real dataset sample or paste a JSON object with all required feature names." spellCheck={false} required /></label><div className="form-footer"><button className="button primary" disabled={loading || !model?.ready || !features.trim()}>{loading ? "Classifying…" : "Run prediction"}</button>{sampleLabel !== null && <span className="comparison">Loaded test label for comparison: <b>{sampleLabel === 1 ? "Attack" : "Normal"}</b></span>}</div></form>
          {prediction && <div className={`prediction-result ${prediction.predicted_label ? "attack" : "normal"}`} role="status"><div><strong>{prediction.predicted_label ? "Attack predicted" : "Normal predicted"}</strong><span>Class {prediction.predicted_label} · {prediction.source_type} · score {percent(prediction.attack_probability ?? prediction.confidence)}{prediction.alert ? ` · ${prediction.alert.severity} demo alert` : " · no alert generated"}</span></div><details><summary>Response JSON</summary><pre>{JSON.stringify(prediction, null, 2)}</pre></details></div>}</section>
        <section id="history" className="panel history-panel"><div className="section-heading"><div><h3>Recent detection history</h3><p>{history ? `${history.total.toLocaleString()} records persisted in local SQLite` : "History endpoint unavailable"}</p></div><button className="button secondary" onClick={() => void refresh()} disabled={checking}><RefreshCw size={14} />Refresh</button></div>{history?.items.length ? <div className="table-wrap"><table><thead><tr><th>Timestamp</th><th>Source</th><th>Classification</th><th>Confidence</th><th>Severity</th></tr></thead><tbody>{history.items.slice(0, 8).map((event) => <tr key={event.event_id}><td>{date(event.timestamp)}</td><td><span className={`source ${event.source_type}`}>{event.source_type}</span></td><td><span className={`class-pill ${event.predicted_label ? "attack" : "normal"}`}>{event.prediction}</span></td><td>{percent(event.confidence)}</td><td>{event.severity ?? "—"}</td></tr>)}</tbody></table></div> : <p className="empty">{history ? "No detection records yet. Submit a prediction to add one." : "Detection history is not available."}</p>}</section>
        <footer className="footer">Random Forest · {metrics?.dataset ?? "UNSW-NB15"} · Benchmark results do not guarantee production security effectiveness.</footer>
      </section>
    </main></div>;
}

function Metric({ label, value, note, icon, tone = "cyan" }: { label: string; value: string; note: string; icon: string; tone?: string }) {
  return <article className={`metric ${tone}`}><div className="metric-head"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{note}</small></article>;
}