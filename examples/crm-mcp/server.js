import http from "node:http";

const customers = {
  "tenant_acme:CUST-1042": { customer_id: "CUST-1042", tenant_id: "tenant_acme", name: "Ada Customer", email: "ada@acme.example", restricted_note: "vip escalation" },
  "tenant_globex:CUST-9001": { customer_id: "CUST-9001", tenant_id: "tenant_globex", name: "Globex Customer", email: "casey@globex.example", restricted_note: "restricted" }
};

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; if (body.length > 1024 * 1024) req.destroy(); });
    req.on("end", () => resolve(body ? JSON.parse(body) : {}));
    req.on("error", reject);
  });
}

function validateCredential(credential, scope) {
  if (!credential || credential.tenant_id !== scope.tenant_id || credential.tool_id !== scope.tool_id || credential.resource !== scope.resource) {
    throw new Error("credential scope rejected");
  }
}

function redact(customer) {
  return { customer_id: customer.customer_id, name: customer.name, email: customer.email };
}

function call(params) {
  const name = params.name;
  const args = params.arguments ?? {};
  if (name === "crm.get_customer") {
    validateCredential(params.credential, { tenant_id: params.tenant_id, tool_id: name, resource: `customer:${args.customer_id}` });
    const customer = customers[`${params.tenant_id}:${args.customer_id}`];
    if (!customer) throw new Error("not found");
    return redact(customer);
  }
  if (name === "crm.search_customers") {
    validateCredential(params.credential, { tenant_id: params.tenant_id, tool_id: name, resource: `tenant:${params.tenant_id}` });
    return Object.values(customers).filter((customer) => customer.tenant_id === params.tenant_id).map(redact);
  }
  if (name === "crm.export_customers") {
    validateCredential(params.credential, { tenant_id: params.tenant_id, tool_id: name, resource: `tenant:${params.tenant_id}` });
    return { count: Object.values(customers).filter((customer) => customer.tenant_id === params.tenant_id).length };
  }
  throw new Error("unknown tool");
}

http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/live") return json(res, 200, { status: "ok", service: "crm-mcp" });
  if (req.method !== "POST") return json(res, 405, { error: "method not allowed" });
  try {
    const message = await readBody(req);
    if (message.method === "tools/list") return json(res, 200, { jsonrpc: "2.0", id: message.id, result: { tools: ["crm.get_customer", "crm.search_customers", "crm.export_customers"] } });
    if (message.method === "tools/call") return json(res, 200, { jsonrpc: "2.0", id: message.id, result: call(message.params) });
    return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } });
  } catch (error) {
    return json(res, 200, { jsonrpc: "2.0", error: { code: -32000, message: error.message } });
  }
}).listen(process.env.PORT || 8092, "0.0.0.0");
