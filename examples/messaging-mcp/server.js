import http from "node:http";

const sent = [];
const allowedDomains = new Set(["example.com", "acme.example"]);
const windows = new Map();

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

function checkRate(key) {
  const now = Date.now();
  const cutoff = now - 60_000;
  const events = (windows.get(key) ?? []).filter((time) => time > cutoff);
  if (events.length >= 3) throw new Error("rate limit exceeded");
  events.push(now);
  windows.set(key, events);
}

function sendEmail(params) {
  const args = params.arguments ?? {};
  validateCredential(params.credential, { tenant_id: params.tenant_id, tool_id: "messaging.send_email", resource: `tenant:${params.tenant_id}` });
  checkRate(`${params.tenant_id}:${params.agent_id}`);
  for (const recipient of args.recipients ?? []) {
    const domain = String(recipient).split("@")[1];
    if (!allowedDomains.has(domain)) throw new Error("recipient domain rejected");
  }
  if ((args.recipients ?? []).length > 10) throw new Error("approval required for large recipient group");
  const result = { message_id: `msg_${sent.length + 1}`, status: "sent" };
  sent.push(result);
  return result;
}

http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/live") return json(res, 200, { status: "ok", service: "messaging-mcp" });
  if (req.method !== "POST") return json(res, 405, { error: "method not allowed" });
  try {
    const message = await readBody(req);
    if (message.method === "tools/list") return json(res, 200, { jsonrpc: "2.0", id: message.id, result: { tools: ["messaging.send_email"] } });
    if (message.method === "tools/call") return json(res, 200, { jsonrpc: "2.0", id: message.id, result: sendEmail(message.params) });
    return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } });
  } catch (error) {
    return json(res, 200, { jsonrpc: "2.0", error: { code: -32000, message: error.message } });
  }
}).listen(process.env.PORT || 8093, "0.0.0.0");
