INSERT INTO tenants (id, slug, name)
VALUES
    ('tenant_acme', 'acme', 'Acme Support'),
    ('tenant_globex', 'globex', 'Globex Support')
ON CONFLICT (id) DO NOTHING;

INSERT INTO subjects (tenant_id, id, type, groups, roles)
VALUES
    ('tenant_acme', 'user_123', 'human', ARRAY['support'], ARRAY['refund_operator']),
    ('tenant_acme', 'approver_finance_1', 'approver', ARRAY['finance'], ARRAY['approval_operator']),
    ('tenant_acme', 'approver_finance_2', 'approver', ARRAY['finance'], ARRAY['approval_operator']),
    ('tenant_globex', 'user_999', 'human', ARRAY['support'], ARRAY['refund_operator'])
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO agents (tenant_id, id, owner_subject_id, client_id, trust_level)
VALUES
    ('tenant_acme', 'agent_refund_assistant', 'user_123', 'refund-agent-client', 3),
    ('tenant_acme', 'agent_low_trust', 'user_123', 'low-trust-agent-client', 1),
    ('tenant_globex', 'agent_globex_support', 'user_999', 'globex-agent-client', 3)
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO delegation_grants (
    tenant_id,
    id,
    grantor_subject_id,
    grantee_agent_id,
    allowed_tools,
    allowed_resources,
    argument_constraints,
    purpose,
    audience,
    max_delegation_depth,
    not_before,
    expires_at
)
VALUES (
    'tenant_acme',
    'dlg_789',
    'user_123',
    'agent_refund_assistant',
    ARRAY['payments.refund'],
    ARRAY['customer:CUST-1042'],
    '{"currency":["INR"],"max_amount_minor":1000000}'::jsonb,
    'customer_support',
    'aegis',
    1,
    now() - interval '1 hour',
    now() + interval '30 days'
)
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO tools (tenant_id, tool_id, display_name, mcp_server_id, mcp_tool_name)
VALUES
    ('tenant_acme', 'payments.refund', 'Refund payment', 'payments-mcp', 'refund'),
    ('tenant_acme', 'crm.get_customer', 'Get customer', 'crm-mcp', 'get_customer'),
    ('tenant_acme', 'messaging.send_email', 'Send email', 'messaging-mcp', 'send_email')
ON CONFLICT (tenant_id, tool_id) DO NOTHING;

INSERT INTO tool_versions (
    tenant_id,
    tool_id,
    schema_version,
    schema_hash,
    description,
    input_schema,
    output_schema,
    risk_classification,
    side_effect_classification,
    data_sensitivity,
    required_scopes,
    required_credential_template,
    timeout_ms,
    retry_policy,
    idempotency_supported,
    approval_defaults,
    allowed_network_destination,
    connector_version
)
VALUES (
    'tenant_acme',
    'payments.refund',
    1,
    'sha256:9d2231cc5f406f65b1f92959f938ef5edc39fcd3bb6fb9c60fbc77c7bc0ebf78',
    'Issue an idempotent refund for one customer payment.',
    '{"type":"object","additionalProperties":false,"required":["customer_id","amount_minor","currency","reason"],"properties":{"customer_id":{"type":"string"},"amount_minor":{"type":"integer","minimum":1},"currency":{"const":"INR"},"reason":{"type":"string","minLength":3,"maxLength":256}}}'::jsonb,
    '{"type":"object","required":["refund_id","status"],"properties":{"refund_id":{"type":"string"},"status":{"type":"string"}}}'::jsonb,
    'HIGH',
    'FINANCIAL',
    'CONFIDENTIAL',
    ARRAY['payments:refund'],
    'payments-refund-scoped',
    5000,
    '{"max_attempts":1}'::jsonb,
    true,
    '{"required_approvals":2,"required_group":"finance","amount_threshold_minor":1000000}'::jsonb,
    'http://payments-mcp:8091',
    'demo-v1'
)
ON CONFLICT (tenant_id, tool_id, schema_version) DO NOTHING;

INSERT INTO budgets (tenant_id, id, name, scope_type, scope_id, currency, limit_minor)
VALUES ('tenant_acme', 'budget_refunds_july', 'July refund budget', 'agent', 'agent_refund_assistant', 'INR', 10000000)
ON CONFLICT (tenant_id, id) DO NOTHING;
