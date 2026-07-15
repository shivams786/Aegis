import http from "node:http";

const refunds = new Map();
const byKey = new Map();

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) req.destroy();
    });
    req.on("end", () => resolve(body ? JSON.parse(body) : {}));
    req.on("error", reject);
  });
}

function validateCredential(credential, scope) {
  if (!credential || credential.tenant_id !== scope.tenant_id || credential.tool_id !== scope.tool_id) {
    throw new Error("credential scope rejected");
  }
  if (credential.resource !== scope.resource) {
    throw new Error("credential resource rejected");
  }
  if (scope.amount_minor && credential.amount_minor && scope.amount_minor > credential.amount_minor) {
    throw new Error("credential amount rejected");
  }
}

function refund(params) {
  const args = params.arguments ?? {};
  const scope = {
    tenant_id: params.tenant_id,
    tool_id: "payments.refund",
    resource: `customer:${args.customer_id}`,
    amount_minor: args.amount_minor
  };
  validateCredential(params.credential, scope);
  const idempotencyKey = `${params.tenant_id}:${params.idempotency_key}`;
  if (byKey.has(idempotencyKey)) {
    return refunds.get(byKey.get(idempotencyKey));
  }
  if (args.simulate === "unknown_outcome") {
    const result = createRefund(params, args, idempotencyKey);
    return { ...result, status: "unknown" };
  }
  if (args.simulate === "timeout") {
    throw new Error("timeout_simulated_unknown_outcome");
  }
  return createRefund(params, args, idempotencyKey);
}

function createRefund(params, args, idempotencyKey) {
  const refundId = `rfnd_${args.customer_id}_${refunds.size + 1}`;
  const result = {
    refund_id: refundId,
    status: "succeeded",
    customer_id: args.customer_id,
    amount_minor: args.amount_minor,
    currency: args.currency
  };
  refunds.set(refundId, result);
  byKey.set(idempotencyKey, refundId);
  return result;
}

function getRefund(params) {
  const args = params.arguments ?? {};
  validateCredential(params.credential, {
    tenant_id: params.tenant_id,
    tool_id: "payments.get_refund",
    resource: `refund:${args.refund_id}`
  });
  const refund = refunds.get(args.refund_id);
  if (!refund) throw new Error("refund not found");
  return refund;
}

function reconcile(params) {
  const refundId = byKey.get(`${params.tenant_id}:${params.idempotency_key}`);
  return refundId ? refunds.get(refundId) : null;
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/live") return json(res, 200, { status: "ok", service: "payments-mcp" });
  if (req.method !== "POST") return json(res, 405, { error: "method not allowed" });
  try {
    const message = await readBody(req);
    if (message.method === "tools/list") {
      return json(res, 200, { jsonrpc: "2.0", id: message.id, result: { tools: ["payments.refund", "payments.get_refund"] } });
    }
    if (message.method === "tools/call") {
      const name = message.params?.name;
      const result = name === "payments.refund" ? refund(message.params) :
        name === "payments.get_refund" ? getRefund(message.params) :
        name === "payments.reconcile" ? reconcile(message.params) :
        (() => { throw new Error("unknown tool"); })();
      return json(res, 200, { jsonrpc: "2.0", id: message.id, result });
    }
    return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } });
  } catch (error) {
    return json(res, 200, { jsonrpc: "2.0", error: { code: -32000, message: error.message } });
  }
});

server.listen(process.env.PORT || 8091, "0.0.0.0");
