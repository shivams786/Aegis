import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, Database, FileSearch, Gauge, Inbox, Play, RefreshCw, ShieldCheck, Wrench } from "lucide-react";
import "./styles.css";

type Tab = "approvals" | "invocations" | "simulator" | "tools" | "budgets" | "audit";

const apiBase = import.meta.env.VITE_AEGIS_API_BASE ?? "http://localhost:8080";

function App() {
  const [tab, setTab] = useState<Tab>("approvals");
  const tabs = useMemo(
    () => [
      ["approvals", Inbox, "Approvals"],
      ["invocations", FileSearch, "Invocations"],
      ["simulator", Play, "Simulator"],
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
        {tab === "invocations" && <JsonPanel title="Invocation Explorer" path="/v1/invocations/inv_000001?tenant_id=tenant_acme" />}
        {tab === "simulator" && <Simulator />}
        {tab === "tools" && <JsonPanel title="Tool Registry" path="/v1/tools?tenant_id=tenant_acme" />}
        {tab === "budgets" && <StaticPanel title="Budget Usage" text="Budget ledger APIs are active in the gateway engine and are exposed through invocation outcomes in this build." />}
        {tab === "audit" && <Audit />}
      </section>
    </main>
  );
}

function Approvals() {
  return <JsonPanel title="Approval Inbox" path="/v1/approvals?tenant_id=tenant_acme" />;
}

function Simulator() {
  const [simulations, setSimulations] = useState("Loading");
  const [bundles, setBundles] = useState("Loading");

  async function load() {
    try {
      const [bundleResponse, simulationResponse] = await Promise.all([
        fetch(`${apiBase}/v1/policy/bundles?tenant_id=tenant_acme&limit=20`),
        fetch(`${apiBase}/v1/policy/simulations?tenant_id=tenant_acme&limit=20`)
      ]);
      setBundles(await bundleResponse.text());
      setSimulations(await simulationResponse.text());
    } catch (err) {
      const message = String(err);
      setBundles(message);
      setSimulations(message);
    }
  }

  async function registerBundle() {
    const now = Date.now();
    const hashSuffix = now.toString(16).padStart(16, "0").slice(-16);
    const response = await fetch(`${apiBase}/v1/policy/bundles?tenant_id=tenant_acme`, {
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
    setBundles(await response.text());
  }

  async function queueSimulation() {
    const response = await fetch(`${apiBase}/v1/policy/simulations?tenant_id=tenant_acme`, {
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
    setSimulations(await response.text());
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="panel">
      <h1>Policy Simulator</h1>
      <div className="toolbar">
        <button className="primary" onClick={queueSimulation}><Play size={16} /> Queue</button>
        <button className="secondary" onClick={registerBundle}><ShieldCheck size={16} /> Register Bundle</button>
        <button className="secondary" onClick={load}><RefreshCw size={16} /> Refresh</button>
      </div>
      <div className="split">
        <pre>{bundles}</pre>
        <pre>{simulations}</pre>
      </div>
    </div>
  );
}

function Audit() {
  const [result, setResult] = useState<string>("");
  async function verify() {
    const response = await fetch(`${apiBase}/v1/audit/verify?tenant_id=tenant_acme`, { method: "POST" });
    setResult(await response.text());
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

function JsonPanel({ title, path }: { title: string; path: string }) {
  const [text, setText] = useState("Loading");
  useEffect(() => {
    fetch(`${apiBase}${path}`)
      .then((r) => r.text())
      .then(setText)
      .catch((err) => setText(String(err)));
  }, [path]);
  return (
    <div className="panel">
      <h1>{title}</h1>
      <pre>{text}</pre>
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

createRoot(document.getElementById("root")!).render(<App />);
