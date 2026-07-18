import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, Database, FileSearch, Gauge, Inbox, Play, RefreshCw, ShieldCheck, Wrench } from "lucide-react";
import "./styles.css";

type Tab = "approvals" | "invocations" | "replay" | "tools" | "budgets" | "audit";

const apiBase = import.meta.env.VITE_AEGIS_API_BASE ?? "http://localhost:8080";
const tenantID = "tenant_acme";
const loadingText = "Loading from Aegis";

function App() {
  const [tab, setTab] = useState<Tab>("approvals");
  const tabs = useMemo(
    () => [
      ["approvals", Inbox, "Approvals"],
      ["invocations", FileSearch, "Invocations"],
      ["replay", Play, "Policy Replay"],
      ["tools", Wrench, "Tools"],
      ["budgets", Gauge, "Budgets"],
      ["audit", ShieldCheck, "Audit"]
    ] as const,
    []
  );

  return (
    <main>
      <aside>
        <div className="brand"><Database size={20} /> Aegis</div>
        <nav>
          {tabs.map(([id, Icon, label]) => (
            <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>
              <Icon size={18} /> {label}
            </button>
          ))}
        </nav>
      </aside>
      <section>
        {tab === "approvals" && <Approvals />}
        {tab === "invocations" && <JsonPanel title="Invocation Detail" path={`/v1/invocations/inv_000001?tenant_id=${tenantID}`} emptyText="No seeded invocation with this ID is available yet." />}
        {tab === "replay" && <PolicyReplay />}
        {tab === "tools" && <JsonPanel title="Tool Registry" path={`/v1/tools?tenant_id=${tenantID}`} emptyText="No tools are registered for this tenant." />}
        {tab === "budgets" && <StaticPanel title="Budget Ledger" text="Budget reservations and releases are visible through invocation outcomes in this local build." />}
        {tab === "audit" && <Audit />}
      </section>
    </main>
  );
}

function Approvals() {
  return <JsonPanel title="Approval Inbox" path={`/v1/approvals?tenant_id=${tenantID}`} emptyText="No approval requests are waiting for review." />;
}

function PolicyReplay() {
  const [replayRuns, setReplayRuns] = useState(loadingText);
  const [bundles, setBundles] = useState(loadingText);

  async function load() {
    try {
      const [bundleResponse, simulationResponse] = await Promise.all([
        fetch(`${apiBase}/v1/policy/bundles?tenant_id=${tenantID}&limit=20`),
        fetch(`${apiBase}/v1/policy/simulations?tenant_id=${tenantID}&limit=20`)
      ]);
      setBundles(await responseText(bundleResponse, "No policy bundles are registered yet."));
      setReplayRuns(await responseText(simulationResponse, "No policy replay runs have been queued yet."));
    } catch (err) {
      const message = `Could not reach Aegis at ${apiBase}: ${String(err)}`;
      setBundles(message);
      setReplayRuns(message);
    }
  }

  async function registerBundle() {
    const now = Date.now();
    const hashSuffix = now.toString(16).padStart(16, "0").slice(-16);
    const response = await fetch(`${apiBase}/v1/policy/bundles?tenant_id=${tenantID}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: `candidate-${now}`,
        policy_hash: `sha256:${"b".repeat(48)}${hashSuffix}`,
        source: "candidate",
        description: "Local candidate policy bundle",
        metadata: { opa_package: "aegis.authz", registered_from: "admin" }
      })
    });
    setBundles(await responseText(response, "Candidate bundle registered."));
  }

  async function queueSimulation() {
    const response = await fetch(`${apiBase}/v1/policy/simulations?tenant_id=${tenantID}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        baseline_policy_version: "local-policy-v1",
        baseline_policy_hash: "sha256:020b3726a1d72f47bb05413ac4436ff0e131f16244863e83f03e9dd9c09f66c4",
        proposed_policy_version: "candidate-demo",
        proposed_policy_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        sample_scope: { tool_id: "payments.refund", sample_limit: 100 }
      })
    });
    setReplayRuns(await responseText(response, "Policy replay queued."));
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="panel">
      <div className="panel-header">
        <p className="eyebrow">Tenant {tenantID}</p>
        <h1>Policy Replay</h1>
        <p className="muted">Compare the active local bundle with a candidate bundle against recent Acme refund samples.</p>
      </div>
      <div className="toolbar">
        <button className="primary" onClick={queueSimulation}><Play size={16} /> Queue Replay</button>
        <button className="secondary" onClick={registerBundle}><ShieldCheck size={16} /> Register Candidate</button>
        <button className="secondary" onClick={load}><RefreshCw size={16} /> Refresh</button>
      </div>
      <div className="split">
        <ResultBlock title="Policy Bundles" text={bundles} />
        <ResultBlock title="Replay Runs" text={replayRuns} />
      </div>
    </div>
  );
}

function Audit() {
  const [result, setResult] = useState<string>("");
  async function verify() {
    const response = await fetch(`${apiBase}/v1/audit/verify?tenant_id=${tenantID}`, { method: "POST" });
    setResult(await responseText(response, "Audit chain verified."));
  }
  return (
    <div className="panel">
      <h1>Audit Verification</h1>
      <div className="toolbar">
        <button className="primary" onClick={verify}><Check size={16} /> Verify</button>
      </div>
      <pre>{result}</pre>
    </div>
  );
}

function JsonPanel({ title, path, emptyText }: { title: string; path: string; emptyText: string }) {
  const [text, setText] = useState(loadingText);
  useEffect(() => {
    fetch(`${apiBase}${path}`)
      .then((r) => responseText(r, emptyText))
      .then(setText)
      .catch((err) => setText(`Could not reach Aegis at ${apiBase}: ${String(err)}`));
  }, [emptyText, path]);
  return (
    <div className="panel">
      <h1>{title}</h1>
      <ResultBlock title="Response" text={text} />
    </div>
  );
}

function StaticPanel({ title, text }: { title: string; text: string }) {
  return (
    <div className="panel">
      <h1>{title}</h1>
      <p>{text}</p>
    </div>
  );
}

function ResultBlock({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <h2>{title}</h2>
      <pre>{text}</pre>
    </div>
  );
}

async function responseText(response: Response, emptyText: string) {
  const raw = await response.text();
  if (!raw.trim()) {
    return emptyText;
  }
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

createRoot(document.getElementById("root")!).render(<App />);
