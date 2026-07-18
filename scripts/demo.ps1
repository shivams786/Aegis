$ErrorActionPreference = "Stop"

$base = $env:AEGIS_BASE_URL
if (-not $base) {
  $base = "http://localhost:8080"
}

Write-Host "Aegis local demo against $base"
Invoke-RestMethod -Method Get -Uri "$base/live" | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Get -Uri "$base/ready" | ConvertTo-Json -Depth 10

$lowRisk = @{
  tenant_id = "tenant_acme"
  protocol = "rest"
  idempotency_key = "demo-low-risk-refund"
  subject = @{ type = "human"; id = "user_123"; groups = @("support"); roles = @("refund_operator") }
  agent = @{ id = "agent_refund_assistant"; trust_level = 3; owner_id = "user_123"; client_id = "refund-agent-client" }
  delegation_id = "dlg_auto_refund"
  tool = @{ id = "payments.refund" }
  action = "refund"
  resource = @{ type = "customer"; id = "CUST-1042"; owner_tenant_id = "tenant_acme" }
  purpose = "customer_support"
  arguments = @{ customer_id = "CUST-1042"; amount_minor = 50000; currency = "INR"; reason = "duplicate_charge" }
} | ConvertTo-Json -Depth 20

Write-Host "Scenario 1: small refund within the auto-approval threshold"
Invoke-RestMethod -Method Post -Uri "$base/v1/invocations" -ContentType "application/json" -Body $lowRisk | ConvertTo-Json -Depth 20

$highRisk = @{
  tenant_id = "tenant_acme"
  protocol = "rest"
  idempotency_key = "demo-high-risk-refund"
  subject = @{ type = "human"; id = "user_123"; groups = @("support"); roles = @("refund_operator") }
  agent = @{ id = "agent_refund_assistant"; trust_level = 3; owner_id = "user_123"; client_id = "refund-agent-client" }
  delegation_id = "dlg_789"
  tool = @{ id = "payments.refund" }
  action = "refund"
  resource = @{ type = "customer"; id = "CUST-1042"; owner_tenant_id = "tenant_acme" }
  purpose = "customer_support"
  arguments = @{ customer_id = "CUST-1042"; amount_minor = 5000000; currency = "INR"; reason = "duplicate_charge" }
} | ConvertTo-Json -Depth 20

Write-Host "Scenario 2: high-value refund that waits for two finance approvals"
$pending = Invoke-RestMethod -Method Post -Uri "$base/v1/invocations" -ContentType "application/json" -Body $highRisk
$pending | ConvertTo-Json -Depth 20

$approval1 = @{ approver = @{ type = "approver"; id = "approver_finance_1"; groups = @("finance"); roles = @("approval_operator") }; reason = "finance review 1" } | ConvertTo-Json -Depth 10
$approval2 = @{ approver = @{ type = "approver"; id = "approver_finance_2"; groups = @("finance"); roles = @("approval_operator") }; reason = "finance review 2" } | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Post -Uri "$base/v1/approvals/$($pending.approval_request_id)/approve?tenant_id=tenant_acme" -ContentType "application/json" -Body $approval1 | ConvertTo-Json -Depth 20
Invoke-RestMethod -Method Post -Uri "$base/v1/approvals/$($pending.approval_request_id)/approve?tenant_id=tenant_acme" -ContentType "application/json" -Body $approval2 | ConvertTo-Json -Depth 20

Write-Host "Audit verification for tenant_acme"
Invoke-RestMethod -Method Post -Uri "$base/v1/audit/verify?tenant_id=tenant_acme" | ConvertTo-Json -Depth 10
