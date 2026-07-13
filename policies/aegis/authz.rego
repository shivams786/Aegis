package aegis.authz

default decision = {
  "allow": false,
  "decision": "DENY",
  "reason_codes": ["DEFAULT_DENY"],
}

decision = result {
  input.delegation.valid == true
  input.tool.active == true
  input.tool.side_effect == "READ_ONLY"
  input.risk.score < 50
  result = {
    "allow": true,
    "decision": "ALLOW",
    "reason_codes": ["LOW_RISK_READ"],
  }
}

decision = result {
  input.delegation.valid == true
  input.tool.active == true
  input.tool.id == "payments.refund"
  input.arguments.amount_minor <= 1000000
  input.risk.score < 70
  result = {
    "allow": true,
    "decision": "ALLOW",
    "reason_codes": ["REFUND_WITHIN_LIMIT"],
  }
}

decision = result {
  input.delegation.valid == true
  input.tool.active == true
  input.tool.id == "payments.refund"
  input.arguments.amount_minor > 1000000
  result = {
    "allow": false,
    "decision": "REQUIRE_APPROVAL",
    "reason_codes": ["REFUND_AMOUNT_REQUIRES_APPROVAL"],
    "approval": {
      "required_approvals": 2,
      "required_group": "finance",
      "requester_may_approve": false,
      "expires_in_seconds": 3600,
    },
  }
}
