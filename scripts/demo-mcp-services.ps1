$ErrorActionPreference = "Stop"

$payments = $env:PAYMENTS_MCP_URL
if (-not $payments) { $payments = "http://localhost:8091" }
$crm = $env:CRM_MCP_URL
if (-not $crm) { $crm = "http://localhost:8092" }
$messaging = $env:MESSAGING_MCP_URL
if (-not $messaging) { $messaging = "http://localhost:8093" }

Invoke-RestMethod -Method Get -Uri "$payments/live" | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Get -Uri "$crm/live" | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Get -Uri "$messaging/live" | ConvertTo-Json -Depth 10

$refund = @{
  jsonrpc = "2.0"
  id = "payments-1"
  method = "tools/call"
  params = @{
    name = "payments.refund"
    tenant_id = "tenant_acme"
    idempotency_key = "demo-node-refund"
    credential = @{ tenant_id = "tenant_acme"; tool_id = "payments.refund"; resource = "customer:CUST-1042"; amount_minor = 50000 }
    arguments = @{ customer_id = "CUST-1042"; amount_minor = 50000; currency = "INR"; reason = "duplicate_charge" }
  }
} | ConvertTo-Json -Depth 20

Invoke-RestMethod -Method Post -Uri $payments -ContentType "application/json" -Body $refund | ConvertTo-Json -Depth 20
