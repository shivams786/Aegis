package aegis.authz

test_default_deny_without_delegation {
  decision with input as {
    "delegation": {"valid": false},
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
    "tool": {"active": true, "id": "payments.refund"},
    "arguments": {"amount_minor": 5000000},
    "risk": {"score": 78},
  }

  result.decision == "REQUIRE_APPROVAL"
  result.approval.required_approvals == 2
  result.approval.requester_may_approve == false
}
