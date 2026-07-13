CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
    id text PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE TABLE subjects (
    tenant_id text NOT NULL REFERENCES tenants(id),
    id text NOT NULL,
    type text NOT NULL CHECK (type IN ('human', 'agent', 'service_account', 'approver', 'administrator', 'mcp_client', 'downstream_tool_workload')),
    groups text[] NOT NULL DEFAULT '{}',
    roles text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE agents (
    tenant_id text NOT NULL REFERENCES tenants(id),
    id text NOT NULL,
    owner_subject_id text NOT NULL,
    client_id text NOT NULL,
    trust_level smallint NOT NULL CHECK (trust_level BETWEEN 0 AND 5),
    registered_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, client_id),
    FOREIGN KEY (tenant_id, owner_subject_id) REFERENCES subjects(tenant_id, id)
);

CREATE TABLE delegation_grants (
    tenant_id text NOT NULL REFERENCES tenants(id),
    id text NOT NULL,
    grantor_subject_id text NOT NULL,
    grantee_agent_id text NOT NULL,
    allowed_tools text[] NOT NULL CHECK (cardinality(allowed_tools) > 0),
    allowed_resources text[] NOT NULL CHECK (cardinality(allowed_resources) > 0),
    argument_constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
    purpose text NOT NULL,
    audience text NOT NULL,
    max_delegation_depth integer NOT NULL CHECK (max_delegation_depth >= 0),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, grantor_subject_id) REFERENCES subjects(tenant_id, id),
    FOREIGN KEY (tenant_id, grantee_agent_id) REFERENCES agents(tenant_id, id),
    CHECK (expires_at > not_before)
);

CREATE TABLE tools (
    tenant_id text NOT NULL REFERENCES tenants(id),
    tool_id text NOT NULL,
    display_name text NOT NULL,
    mcp_server_id text NOT NULL,
    mcp_tool_name text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, tool_id)
);

CREATE TABLE tool_versions (
    tenant_id text NOT NULL,
    tool_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    schema_hash text NOT NULL CHECK (schema_hash LIKE 'sha256:%'),
    description text NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    risk_classification text NOT NULL CHECK (risk_classification IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    side_effect_classification text NOT NULL CHECK (side_effect_classification IN ('READ_ONLY', 'REVERSIBLE_WRITE', 'IRREVERSIBLE_WRITE', 'FINANCIAL')),
    data_sensitivity text NOT NULL CHECK (data_sensitivity IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    required_scopes text[] NOT NULL DEFAULT '{}',
    required_credential_template text NOT NULL,
    timeout_ms integer NOT NULL CHECK (timeout_ms BETWEEN 1 AND 120000),
    retry_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    idempotency_supported boolean NOT NULL DEFAULT false,
    approval_defaults jsonb NOT NULL DEFAULT '{}'::jsonb,
    allowed_network_destination text NOT NULL,
    connector_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, tool_id, schema_version),
    FOREIGN KEY (tenant_id, tool_id) REFERENCES tools(tenant_id, tool_id)
);

CREATE TABLE invocations (
    tenant_id text NOT NULL REFERENCES tenants(id),
    invocation_id text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('rest', 'mcp')),
    protocol_request_id text,
    idempotency_key text,
    subject_id text NOT NULL,
    agent_id text NOT NULL,
    delegation_id text NOT NULL,
    tool_id text NOT NULL,
    tool_schema_version integer NOT NULL,
    tool_schema_hash text NOT NULL CHECK (tool_schema_hash LIKE 'sha256:%'),
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    purpose text NOT NULL,
    canonical_request_hash text NOT NULL CHECK (canonical_request_hash LIKE 'sha256:%'),
    redacted_arguments jsonb NOT NULL DEFAULT '{}'::jsonb,
    state text NOT NULL CHECK (state IN ('RECEIVED', 'DENIED', 'PENDING_APPROVAL', 'APPROVED', 'RESERVED', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'RECONCILIATION_REQUIRED')),
    decision text NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
    reason_codes text[] NOT NULL DEFAULT '{}',
    risk_score integer CHECK (risk_score BETWEEN 0 AND 100),
    risk_engine_version text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, invocation_id),
    FOREIGN KEY (tenant_id, subject_id) REFERENCES subjects(tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id),
    FOREIGN KEY (tenant_id, delegation_id) REFERENCES delegation_grants(tenant_id, id),
    FOREIGN KEY (tenant_id, tool_id, tool_schema_version) REFERENCES tool_versions(tenant_id, tool_id, schema_version)
);

CREATE UNIQUE INDEX invocations_idempotency_key_uniq
    ON invocations (tenant_id, tool_id, action, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE approval_requests (
    tenant_id text NOT NULL,
    id text NOT NULL,
    invocation_id text NOT NULL,
    required_approvals integer NOT NULL CHECK (required_approvals > 0),
    required_group text,
    requester_subject_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
    reason_required boolean NOT NULL DEFAULT true,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, invocation_id) REFERENCES invocations(tenant_id, invocation_id),
    FOREIGN KEY (tenant_id, requester_subject_id) REFERENCES subjects(tenant_id, id)
);

CREATE TABLE approval_decisions (
    tenant_id text NOT NULL,
    approval_request_id text NOT NULL,
    approver_subject_id text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
    reason text NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, approval_request_id, approver_subject_id),
    FOREIGN KEY (tenant_id, approval_request_id) REFERENCES approval_requests(tenant_id, id),
    FOREIGN KEY (tenant_id, approver_subject_id) REFERENCES subjects(tenant_id, id)
);

CREATE TABLE budgets (
    tenant_id text NOT NULL REFERENCES tenants(id),
    id text NOT NULL,
    name text NOT NULL,
    scope_type text NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'tool', 'delegation')),
    scope_id text NOT NULL,
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    limit_minor bigint NOT NULL CHECK (limit_minor >= 0),
    reserved_minor bigint NOT NULL DEFAULT 0 CHECK (reserved_minor >= 0),
    committed_minor bigint NOT NULL DEFAULT 0 CHECK (committed_minor >= 0),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK (reserved_minor + committed_minor <= limit_minor)
);

CREATE TABLE budget_ledger_entries (
    tenant_id text NOT NULL,
    id text NOT NULL DEFAULT gen_random_uuid()::text,
    budget_id text NOT NULL,
    invocation_id text,
    entry_type text NOT NULL CHECK (entry_type IN ('RESERVE', 'COMMIT', 'RELEASE', 'ADJUST')),
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, budget_id) REFERENCES budgets(tenant_id, id),
    FOREIGN KEY (tenant_id, invocation_id) REFERENCES invocations(tenant_id, invocation_id)
);

CREATE TABLE outbox_events (
    tenant_id text NOT NULL REFERENCES tenants(id),
    event_id text NOT NULL DEFAULT gen_random_uuid()::text,
    aggregate_id text NOT NULL,
    aggregate_version bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    trace_context jsonb NOT NULL DEFAULT '{}'::jsonb,
    schema_version integer NOT NULL DEFAULT 1,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    delivery_attempts integer NOT NULL DEFAULT 0,
    last_error text,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX outbox_events_pending_idx ON outbox_events (occurred_at) WHERE published_at IS NULL;

CREATE TABLE audit_events (
    tenant_id text NOT NULL REFERENCES tenants(id),
    sequence_no bigint NOT NULL,
    event_id text NOT NULL DEFAULT gen_random_uuid()::text,
    invocation_id text,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    safe_reason_code text,
    redacted_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    previous_hash text,
    event_hash text NOT NULL CHECK (event_hash LIKE 'sha256:%'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence_no),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, invocation_id) REFERENCES invocations(tenant_id, invocation_id)
);

CREATE TABLE audit_roots (
    tenant_id text NOT NULL REFERENCES tenants(id),
    root_id text NOT NULL DEFAULT gen_random_uuid()::text,
    from_sequence_no bigint NOT NULL,
    to_sequence_no bigint NOT NULL,
    root_hash text NOT NULL CHECK (root_hash LIKE 'sha256:%'),
    generated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, root_id),
    CHECK (to_sequence_no >= from_sequence_no)
);

ALTER TABLE subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE budget_ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_roots ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_subjects ON subjects
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agents ON agents
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_delegation_grants ON delegation_grants
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_tools ON tools
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_tool_versions ON tool_versions
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_invocations ON invocations
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_approval_requests ON approval_requests
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_approval_decisions ON approval_decisions
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_budgets ON budgets
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_budget_ledger_entries ON budget_ledger_entries
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_outbox_events ON outbox_events
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_audit_events ON audit_events
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_audit_roots ON audit_roots
    USING (tenant_id = current_setting('app.tenant_id', true));
