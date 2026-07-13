import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, Database, FileSearch, Gauge, Inbox, Play, ShieldCheck, Wrench } from "lucide-react";
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
  return (
    <StaticPanel
      title="Policy Simulator"
      text="Policy comparison flags approval-to-allow, deny-to-allow, credential-scope widening, and redaction removal in the backend policy package."
    />
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
      <button className="primary" onClick={verify}><Check size={16} /> Verify</button>
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
