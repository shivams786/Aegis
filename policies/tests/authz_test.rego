package aegis.authz

test_default_deny_without_delegation {
  decision with input as {
    "delegation": {"valid": false},
    "invocation": {"tenant_id": "tenant_acme", "resource": {"owner_tenant_id": "tenant_acme"}},
    "tool": {"active": true, "id": "payments.refund"},
    "arguments": {"amount_minor": 50000},
    "risk": {"score": 20},
  } == {
    "allow": false,
    "decision": "DENY",
    "reason_codes": ["DEFAULT_DENY"],
  }
}

test_high_value_refund_requires_approval {
  result = decision with input as {
    "delegation": {"valid": true},
    "invocation": {"tenant_id": "tenant_acme", "resource": {"owner_tenant_id": "tenant_acme"}},
    "tool": {"active": true, "id": "payments.refund"},
    "arguments": {"amount_minor": 5000000},
    "risk": {"score": 78},
  }

  result.decision == "REQUIRE_APPROVAL"
  result.approval.required_approvals == 2
  result.approval.requester_may_approve == false
}

test_cross_tenant_resource_denied {
  result = decision with input as {
    "delegation": {"valid": true},
    "invocation": {"tenant_id": "tenant_acme", "resource": {"owner_tenant_id": "tenant_globex"}},
    "tool": {"active": true, "id": "payments.refund"},
    "arguments": {"amount_minor": 50000},
    "risk": {"score": 20},
  }

  result.decision == "DENY"
  result.reason_codes == ["DEFAULT_DENY"]
}
