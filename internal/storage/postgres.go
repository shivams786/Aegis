package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/aegis/aegis/internal/audit"
	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/delegation"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/outbox"
	"github.com/aegis/aegis/internal/policy"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

type OutboxDrainOptions struct {
	BatchSize   int
	MaxAttempts int
}

type OutboxDrainResult struct {
	Published    int
	Failed       int
	DeadLettered int
}

type AuditRootResult struct {
	Generated int
}

type BudgetReservationSweepOptions struct {
	StaleAfter time.Duration
	BatchSize  int
}

type BudgetReservationSweepResult struct {
	Released int64
}

type ReconciliationLeaseOptions struct {
	LeaseOwner    string
	LeaseDuration time.Duration
	RetryAfter    time.Duration
	BatchSize     int
}

type ReconciliationLeaseResult struct {
	Leased int64
}

type PolicySimulationLeaseOptions struct {
	LeaseOwner    string
	LeaseDuration time.Duration
	RetryAfter    time.Duration
	BatchSize     int
}

type PolicySimulationLeaseResult struct {
	Leased int64
}

type PolicySimulationCompleteOptions struct {
	LeaseOwner string
	BatchSize  int
}

type PolicySimulationCompleteResult struct {
	Completed int64
	Failed    int64
}

type policySimulationReplaySample struct {
	Request invocation.Request
	Tool    tools.Definition
	Risk    risk.Result
}

type PolicyBundleCreate struct {
	TenantID             string         `json:"tenant_id"`
	ID                   string         `json:"id,omitempty"`
	Version              string         `json:"version"`
	PolicyHash           string         `json:"policy_hash"`
	Source               string         `json:"source"`
	Description          string         `json:"description,omitempty"`
	OPABundleURL         string         `json:"opa_bundle_url,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	CreatedBySubjectID   string         `json:"created_by_subject_id,omitempty"`
	TraceContext         map[string]any `json:"-"`
}

type PolicyBundle struct {
	TenantID             string         `json:"tenant_id"`
	ID                   string         `json:"id"`
	Version              string         `json:"version"`
	PolicyHash           string         `json:"policy_hash"`
	Source               string         `json:"source"`
	Status               string         `json:"status"`
	Active               bool           `json:"active"`
	Description          string         `json:"description"`
	OPABundleURL         string         `json:"opa_bundle_url,omitempty"`
	Metadata             map[string]any `json:"metadata"`
	CreatedBySubjectID   string         `json:"created_by_subject_id,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	ActivatedAt          *time.Time     `json:"activated_at,omitempty"`
	RetiredAt            *time.Time     `json:"retired_at,omitempty"`
}

type PolicySimulationRunCreate struct {
	TenantID                string         `json:"tenant_id"`
	ID                      string         `json:"id,omitempty"`
	RequestedBySubjectID    string         `json:"requested_by_subject_id,omitempty"`
	BaselinePolicyVersion   string         `json:"baseline_policy_version"`
	BaselinePolicyHash      string         `json:"baseline_policy_hash"`
	ProposedPolicyVersion   string         `json:"proposed_policy_version"`
	ProposedPolicyHash      string         `json:"proposed_policy_hash"`
	SampleScope             map[string]any `json:"sample_scope,omitempty"`
	TraceContext            map[string]any `json:"-"`
}

type PolicySimulationRun struct {
	TenantID                string         `json:"tenant_id"`
	ID                      string         `json:"id"`
	RequestedBySubjectID    string         `json:"requested_by_subject_id,omitempty"`
	BaselinePolicyVersion   string         `json:"baseline_policy_version"`
	BaselinePolicyHash      string         `json:"baseline_policy_hash"`
	ProposedPolicyVersion   string         `json:"proposed_policy_version"`
	ProposedPolicyHash      string         `json:"proposed_policy_hash"`
	SampleScope             map[string]any `json:"sample_scope"`
	State                   string         `json:"state"`
	TotalSamples            int            `json:"total_samples"`
	DangerousFindings       int            `json:"dangerous_findings"`
	Findings                []any          `json:"findings"`
	Attempts                int            `json:"attempts"`
	NotBefore               *time.Time     `json:"not_before,omitempty"`
	LeaseOwner              string         `json:"lease_owner,omitempty"`
	LeaseUntil              *time.Time     `json:"lease_until,omitempty"`
	LastError               string         `json:"last_error,omitempty"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
	CompletedAt             *time.Time     `json:"completed_at,omitempty"`
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) ResolveActingIdentity(ctx context.Context, identity authn.ActingIdentity) (authn.ActingIdentity, error) {
	if err := identity.Validate(); err != nil {
		return authn.ActingIdentity{}, err
	}
	if s == nil || s.pool == nil {
		return authn.ActingIdentity{}, errors.New("postgres pool is not configured")
	}
	var subject authn.Subject
	var subjectType string
	err := s.pool.QueryRow(ctx, `
		select type, id, groups, roles
		from subjects
		where tenant_id = $1
		  and id = $2
		  and disabled_at is null
	`, identity.TenantID, identity.Subject.ID).Scan(&subjectType, &subject.ID, &subject.Groups, &subject.Roles)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authn.ActingIdentity{}, errors.New("subject not found")
		}
		return authn.ActingIdentity{}, fmt.Errorf("resolve subject: %w", err)
	}
	subject.Type = authn.PrincipalType(subjectType)
	var agent authn.Agent
	err = s.pool.QueryRow(ctx, `
		select id, trust_level, owner_subject_id, client_id
		from agents
		where tenant_id = $1
		  and id = $2
		  and disabled_at is null
	`, identity.TenantID, identity.Agent.ID).Scan(&agent.ID, &agent.TrustLevel, &agent.OwnerID, &agent.ClientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authn.ActingIdentity{}, errors.New("agent not found")
		}
		return authn.ActingIdentity{}, fmt.Errorf("resolve agent: %w", err)
	}
	if agent.ClientID != identity.Agent.ClientID || agent.ClientID != identity.ClientID {
		return authn.ActingIdentity{}, errors.New("authenticated client is not bound to agent")
	}
	if agent.OwnerID != identity.Agent.OwnerID {
		return authn.ActingIdentity{}, errors.New("agent owner binding mismatch")
	}
	identity.Subject = subject
	identity.Agent = agent
	return identity, nil
}

type Tenant struct {
	ID        string
	Slug      string
	Name      string
	CreatedAt time.Time
}

func Open(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Store, error) {
	if cfg.DatabaseURL == "" {
		if cfg.RequireDatabase {
			return nil, errors.New("database URL is required")
		}
		return &Store{logger: logger}, nil
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	poolConfig.MaxConns = 10
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}

	store := &Store{pool: pool, logger: logger}
	if err := store.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres readiness check failed: %w", err)
	}

	return store, nil
}

func (s *Store) Pool() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.pool
}

func (s *Store) Close() {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres pool is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var one int
	if err := s.pool.QueryRow(ctx, "select 1").Scan(&one); err != nil {
		return fmt.Errorf("postgres ping query: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("postgres ping returned %d", one)
	}
	return nil
}

func (s *Store) WithTenantTx(ctx context.Context, tenantID string, fn func(context.Context, pgx.Tx) error) error {
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	if s == nil || s.pool == nil {
		return errors.New("postgres pool is not configured")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, "select set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}

func (s *Store) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	if tenantID == "" {
		return Tenant{}, errors.New("tenant_id is required")
	}
	if s == nil || s.pool == nil {
		return Tenant{}, errors.New("postgres pool is not configured")
	}
	var tenant Tenant
	err := s.pool.QueryRow(ctx, `
		select id, slug, name, created_at
		from tenants
		where id = $1
		  and deleted_at is null
	`, tenantID).Scan(&tenant.ID, &tenant.Slug, &tenant.Name, &tenant.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tenant{}, errors.New("tenant not found")
		}
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return tenant, nil
}

func (s *Store) LoadDelegationGrant(ctx context.Context, tenantID, delegationID string) (delegation.Grant, error) {
	if tenantID == "" || delegationID == "" {
		return delegation.Grant{}, errors.New("tenant_id and delegation_id are required")
	}
	if s == nil || s.pool == nil {
		return delegation.Grant{}, errors.New("postgres pool is not configured")
	}
	var grant delegation.Grant
	var constraintsJSON json.RawMessage
	var revokedAt pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		select tenant_id,
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
		       expires_at,
		       revoked_at
		from delegation_grants
		where tenant_id = $1
		  and id = $2
	`, tenantID, delegationID).Scan(
		&grant.TenantID,
		&grant.ID,
		&grant.GrantorSubjectID,
		&grant.GranteeAgentID,
		&grant.AllowedTools,
		&grant.AllowedResources,
		&constraintsJSON,
		&grant.Purpose,
		&grant.Audience,
		&grant.MaxDelegationDepth,
		&grant.NotBefore,
		&grant.ExpiresAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return delegation.Grant{}, errors.New("delegation grant not found")
		}
		return delegation.Grant{}, fmt.Errorf("load delegation grant: %w", err)
	}
	constraints, err := parseArgumentConstraints(constraintsJSON)
	if err != nil {
		return delegation.Grant{}, err
	}
	grant.ArgumentConstraints = constraints
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		grant.RevokedAt = &t
	}
	return grant, nil
}

type argumentConstraintsJSON struct {
	Currency        []string `json:"currency"`
	Currencies      []string `json:"currencies"`
	MaxAmountMinor  *int64   `json:"max_amount_minor"`
	RequiredFields  []string `json:"required_fields"`
	RejectUnknown   bool     `json:"reject_unknown"`
	AllowedArgNames []string `json:"allowed_arg_names"`
}

func parseArgumentConstraints(raw json.RawMessage) (delegation.ArgumentConstraints, error) {
	if len(raw) == 0 {
		return delegation.ArgumentConstraints{}, nil
	}
	var payload argumentConstraintsJSON
	if err := json.Unmarshal(raw, &payload); err != nil {
		return delegation.ArgumentConstraints{}, fmt.Errorf("parse delegation argument constraints: %w", err)
	}
	currencies := payload.Currencies
	if len(currencies) == 0 {
		currencies = payload.Currency
	}
	return delegation.ArgumentConstraints{
		Currencies:      currencies,
		MaxAmountMinor:  payload.MaxAmountMinor,
		RequiredFields:  payload.RequiredFields,
		RejectUnknown:   payload.RejectUnknown,
		AllowedArgNames: payload.AllowedArgNames,
	}, nil
}

func (s *Store) CreatePolicyBundle(ctx context.Context, req PolicyBundleCreate) (PolicyBundle, error) {
	if s == nil || s.pool == nil {
		return PolicyBundle{}, errors.New("postgres pool is not configured")
	}
	if req.TenantID == "" || req.Version == "" || req.PolicyHash == "" {
		return PolicyBundle{}, errors.New("policy bundle tenant, version, and hash are required")
	}
	if req.Source == "" {
		req.Source = "candidate"
	}
	if req.Metadata == nil {
		req.Metadata = map[string]any{}
	}
	if req.TraceContext == nil {
		req.TraceContext = map[string]any{}
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("pbun_%d", time.Now().UTC().UnixNano())
	}
	metadata, err := json.Marshal(req.Metadata)
	if err != nil {
		return PolicyBundle{}, fmt.Errorf("marshal policy bundle metadata: %w", err)
	}
	traceContext, err := json.Marshal(req.TraceContext)
	if err != nil {
		return PolicyBundle{}, fmt.Errorf("marshal policy bundle trace context: %w", err)
	}
	var bundle PolicyBundle
	err = s.WithTenantTx(ctx, req.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := scanPolicyBundle(tx.QueryRow(ctx, `
			insert into policy_bundles (
				tenant_id,
				id,
				version,
				policy_hash,
				source,
				description,
				opa_bundle_url,
				metadata,
				created_by_subject_id
			) values ($1, $2, $3, $4, $5, $6, nullif($7, ''), $8, nullif($9, ''))
			returning tenant_id,
			          id,
			          version,
			          policy_hash,
			          source,
			          status,
			          active,
			          description,
			          opa_bundle_url,
			          metadata,
			          created_by_subject_id,
			          created_at,
			          updated_at,
			          activated_at,
			          retired_at
		`, req.TenantID, req.ID, req.Version, req.PolicyHash, req.Source, req.Description, req.OPABundleURL, metadata, req.CreatedBySubjectID))
		if err != nil {
			return fmt.Errorf("create policy bundle: %w", err)
		}
		payload, err := json.Marshal(map[string]any{
			"bundle_id":             inserted.ID,
			"version":               inserted.Version,
			"policy_hash":           inserted.PolicyHash,
			"source":                inserted.Source,
			"status":                inserted.Status,
			"active":                inserted.Active,
			"created_by_subject_id": inserted.CreatedBySubjectID,
		})
		if err != nil {
			return fmt.Errorf("marshal policy bundle outbox payload: %w", err)
		}
		_, err = tx.Exec(ctx, `
			insert into outbox_events (
				tenant_id,
				event_id,
				aggregate_id,
				aggregate_version,
				event_type,
				payload,
				trace_context,
				schema_version,
				occurred_at
			) values ($1, $2, $3, $4, 'PolicyBundleRegistered', $5, $6, 1, $7)
			on conflict (tenant_id, event_id) do nothing
		`, inserted.TenantID, "evt_"+inserted.ID+"_PolicyBundleRegistered", inserted.ID, inserted.CreatedAt.UnixNano(), payload, traceContext, inserted.CreatedAt)
		if err != nil {
			return fmt.Errorf("enqueue policy bundle registration event: %w", err)
		}
		bundle = inserted
		return nil
	})
	if err != nil {
		return PolicyBundle{}, err
	}
	return bundle, nil
}

func (s *Store) ListPolicyBundles(ctx context.Context, tenantID string, limit int) ([]PolicyBundle, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("postgres pool is not configured")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	bundles := []PolicyBundle{}
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			select tenant_id,
			       id,
			       version,
			       policy_hash,
			       source,
			       status,
			       active,
			       description,
			       opa_bundle_url,
			       metadata,
			       created_by_subject_id,
			       created_at,
			       updated_at,
			       activated_at,
			       retired_at
			from policy_bundles
			where tenant_id = $1
			order by active desc, created_at desc, id desc
			limit $2
		`, tenantID, limit)
		if err != nil {
			return fmt.Errorf("list policy bundles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			bundle, err := scanPolicyBundle(rows)
			if err != nil {
				return err
			}
			bundles = append(bundles, bundle)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate policy bundles: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

func (s *Store) GetPolicyBundle(ctx context.Context, tenantID, bundleID string) (PolicyBundle, error) {
	if s == nil || s.pool == nil {
		return PolicyBundle{}, errors.New("postgres pool is not configured")
	}
	var bundle PolicyBundle
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		selected, err := scanPolicyBundle(tx.QueryRow(ctx, `
			select tenant_id,
			       id,
			       version,
			       policy_hash,
			       source,
			       status,
			       active,
			       description,
			       opa_bundle_url,
			       metadata,
			       created_by_subject_id,
			       created_at,
			       updated_at,
			       activated_at,
			       retired_at
			from policy_bundles
			where tenant_id = $1
			  and id = $2
		`, tenantID, bundleID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("policy bundle not found")
			}
			return err
		}
		bundle = selected
		return nil
	})
	if err != nil {
		return PolicyBundle{}, err
	}
	return bundle, nil
}

func (s *Store) ActivatePolicyBundle(ctx context.Context, tenantID, bundleID string, traceContext map[string]any) (PolicyBundle, error) {
	if s == nil || s.pool == nil {
		return PolicyBundle{}, errors.New("postgres pool is not configured")
	}
	if tenantID == "" || bundleID == "" {
		return PolicyBundle{}, errors.New("policy bundle tenant and id are required")
	}
	if traceContext == nil {
		traceContext = map[string]any{}
	}
	traceRaw, err := json.Marshal(traceContext)
	if err != nil {
		return PolicyBundle{}, fmt.Errorf("marshal policy bundle trace context: %w", err)
	}
	now := time.Now().UTC()
	var bundle PolicyBundle
	err = s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			update policy_bundles
			set active = false,
			    status = 'RETIRED',
			    retired_at = $3,
			    updated_at = $3
			where tenant_id = $1
			  and active = true
			  and id <> $2
		`, tenantID, bundleID, now); err != nil {
			return fmt.Errorf("retire active policy bundle: %w", err)
		}
		activated, err := scanPolicyBundle(tx.QueryRow(ctx, `
			update policy_bundles
			set active = true,
			    status = 'ACTIVE',
			    activated_at = coalesce(activated_at, $3),
			    retired_at = null,
			    updated_at = $3
			where tenant_id = $1
			  and id = $2
			  and status <> 'REJECTED'
			returning tenant_id,
			          id,
			          version,
			          policy_hash,
			          source,
			          status,
			          active,
			          description,
			          opa_bundle_url,
			          metadata,
			          created_by_subject_id,
			          created_at,
			          updated_at,
			          activated_at,
			          retired_at
		`, tenantID, bundleID, now))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("policy bundle not found or rejected")
			}
			return fmt.Errorf("activate policy bundle: %w", err)
		}
		payload, err := json.Marshal(map[string]any{
			"bundle_id":   activated.ID,
			"version":     activated.Version,
			"policy_hash": activated.PolicyHash,
			"source":      activated.Source,
			"status":      activated.Status,
			"active":      activated.Active,
		})
		if err != nil {
			return fmt.Errorf("marshal policy bundle activation payload: %w", err)
		}
		_, err = tx.Exec(ctx, `
			insert into outbox_events (
				tenant_id,
				event_id,
				aggregate_id,
				aggregate_version,
				event_type,
				payload,
				trace_context,
				schema_version,
				occurred_at
			) values ($1, $2, $3, $4, 'PolicyBundleActivated', $5, $6, 1, $7)
			on conflict (tenant_id, event_id) do nothing
		`, activated.TenantID, fmt.Sprintf("evt_%s_PolicyBundleActivated_%d", activated.ID, now.UnixNano()), activated.ID, activated.UpdatedAt.UnixNano(), payload, traceRaw, activated.UpdatedAt)
		if err != nil {
			return fmt.Errorf("enqueue policy bundle activation event: %w", err)
		}
		bundle = activated
		return nil
	})
	if err != nil {
		return PolicyBundle{}, err
	}
	return bundle, nil
}

func scanPolicyBundle(scanner rowScanner) (PolicyBundle, error) {
	var bundle PolicyBundle
	var opaBundleURL pgtype.Text
	var createdBy pgtype.Text
	var metadataRaw []byte
	var activatedAt pgtype.Timestamptz
	var retiredAt pgtype.Timestamptz
	if err := scanner.Scan(
		&bundle.TenantID,
		&bundle.ID,
		&bundle.Version,
		&bundle.PolicyHash,
		&bundle.Source,
		&bundle.Status,
		&bundle.Active,
		&bundle.Description,
		&opaBundleURL,
		&metadataRaw,
		&createdBy,
		&bundle.CreatedAt,
		&bundle.UpdatedAt,
		&activatedAt,
		&retiredAt,
	); err != nil {
		return PolicyBundle{}, fmt.Errorf("scan policy bundle: %w", err)
	}
	metadata, err := decodeJSONMap(metadataRaw)
	if err != nil {
		return PolicyBundle{}, fmt.Errorf("decode policy bundle metadata: %w", err)
	}
	bundle.Metadata = metadata
	if opaBundleURL.Valid {
		bundle.OPABundleURL = opaBundleURL.String
	}
	if createdBy.Valid {
		bundle.CreatedBySubjectID = createdBy.String
	}
	if activatedAt.Valid {
		t := activatedAt.Time.UTC()
		bundle.ActivatedAt = &t
	}
	if retiredAt.Valid {
		t := retiredAt.Time.UTC()
		bundle.RetiredAt = &t
	}
	return bundle, nil
}

func (s *Store) CreatePolicySimulationRun(ctx context.Context, req PolicySimulationRunCreate) (PolicySimulationRun, error) {
	if s == nil || s.pool == nil {
		return PolicySimulationRun{}, errors.New("postgres pool is not configured")
	}
	if req.TenantID == "" || req.BaselinePolicyVersion == "" || req.BaselinePolicyHash == "" || req.ProposedPolicyVersion == "" || req.ProposedPolicyHash == "" {
		return PolicySimulationRun{}, errors.New("policy simulation tenant and policy identifiers are required")
	}
	if req.SampleScope == nil {
		req.SampleScope = map[string]any{}
	}
	if req.TraceContext == nil {
		req.TraceContext = map[string]any{}
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("psim_%d", time.Now().UTC().UnixNano())
	}
	sampleScope, err := json.Marshal(req.SampleScope)
	if err != nil {
		return PolicySimulationRun{}, fmt.Errorf("marshal policy simulation sample scope: %w", err)
	}
	traceContext, err := json.Marshal(req.TraceContext)
	if err != nil {
		return PolicySimulationRun{}, fmt.Errorf("marshal policy simulation trace context: %w", err)
	}
	var run PolicySimulationRun
	err = s.WithTenantTx(ctx, req.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := scanPolicySimulationRun(tx.QueryRow(ctx, `
			insert into policy_simulation_runs (
				tenant_id,
				id,
				requested_by_subject_id,
				baseline_policy_version,
				baseline_policy_hash,
				proposed_policy_version,
				proposed_policy_hash,
				sample_scope
			) values ($1, $2, nullif($3, ''), $4, $5, $6, $7, $8)
			returning tenant_id,
			          id,
			          requested_by_subject_id,
			          baseline_policy_version,
			          baseline_policy_hash,
			          proposed_policy_version,
			          proposed_policy_hash,
			          sample_scope,
			          state,
			          total_samples,
			          dangerous_findings,
			          findings,
			          attempts,
			          not_before,
			          lease_owner,
			          lease_until,
			          last_error,
			          created_at,
			          updated_at,
			          completed_at
		`, req.TenantID, req.ID, req.RequestedBySubjectID, req.BaselinePolicyVersion, req.BaselinePolicyHash, req.ProposedPolicyVersion, req.ProposedPolicyHash, sampleScope))
		if err != nil {
			return fmt.Errorf("create policy simulation run: %w", err)
		}
		payload, err := json.Marshal(map[string]any{
			"simulation_id":             inserted.ID,
			"state":                     inserted.State,
			"baseline_policy_version":   inserted.BaselinePolicyVersion,
			"baseline_policy_hash":      inserted.BaselinePolicyHash,
			"proposed_policy_version":   inserted.ProposedPolicyVersion,
			"proposed_policy_hash":      inserted.ProposedPolicyHash,
			"requested_by_subject_id":   inserted.RequestedBySubjectID,
		})
		if err != nil {
			return fmt.Errorf("marshal policy simulation outbox payload: %w", err)
		}
		_, err = tx.Exec(ctx, `
			insert into outbox_events (
				tenant_id,
				event_id,
				aggregate_id,
				aggregate_version,
				event_type,
				payload,
				trace_context,
				schema_version,
				occurred_at
			) values ($1, $2, $3, $4, 'PolicySimulationRunCreated', $5, $6, 1, $7)
			on conflict (tenant_id, event_id) do nothing
		`, inserted.TenantID, "evt_"+inserted.ID+"_PolicySimulationRunCreated", inserted.ID, inserted.CreatedAt.UnixNano(), payload, traceContext, inserted.CreatedAt)
		if err != nil {
			return fmt.Errorf("enqueue policy simulation creation event: %w", err)
		}
		run = inserted
		return nil
	})
	if err != nil {
		return PolicySimulationRun{}, err
	}
	return run, nil
}

func (s *Store) ListPolicySimulationRuns(ctx context.Context, tenantID string, limit int) ([]PolicySimulationRun, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("postgres pool is not configured")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	runs := []PolicySimulationRun{}
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			select tenant_id,
			       id,
			       requested_by_subject_id,
			       baseline_policy_version,
			       baseline_policy_hash,
			       proposed_policy_version,
			       proposed_policy_hash,
			       sample_scope,
			       state,
			       total_samples,
			       dangerous_findings,
			       findings,
			       attempts,
			       not_before,
			       lease_owner,
			       lease_until,
			       last_error,
			       created_at,
			       updated_at,
			       completed_at
			from policy_simulation_runs
			where tenant_id = $1
			order by created_at desc, id desc
			limit $2
		`, tenantID, limit)
		if err != nil {
			return fmt.Errorf("list policy simulation runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			run, err := scanPolicySimulationRun(rows)
			if err != nil {
				return err
			}
			runs = append(runs, run)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate policy simulation runs: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runs, nil
}

func (s *Store) GetPolicySimulationRun(ctx context.Context, tenantID, runID string) (PolicySimulationRun, error) {
	if s == nil || s.pool == nil {
		return PolicySimulationRun{}, errors.New("postgres pool is not configured")
	}
	var run PolicySimulationRun
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		selected, err := scanPolicySimulationRun(tx.QueryRow(ctx, `
			select tenant_id,
			       id,
			       requested_by_subject_id,
			       baseline_policy_version,
			       baseline_policy_hash,
			       proposed_policy_version,
			       proposed_policy_hash,
			       sample_scope,
			       state,
			       total_samples,
			       dangerous_findings,
			       findings,
			       attempts,
			       not_before,
			       lease_owner,
			       lease_until,
			       last_error,
			       created_at,
			       updated_at,
			       completed_at
			from policy_simulation_runs
			where tenant_id = $1
			  and id = $2
		`, tenantID, runID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("policy simulation run not found")
			}
			return err
		}
		run = selected
		return nil
	})
	if err != nil {
		return PolicySimulationRun{}, err
	}
	return run, nil
}

func scanPolicySimulationRun(scanner rowScanner) (PolicySimulationRun, error) {
	var run PolicySimulationRun
	var requestedBy pgtype.Text
	var sampleScopeRaw []byte
	var findingsRaw []byte
	var notBefore pgtype.Timestamptz
	var leaseOwner pgtype.Text
	var leaseUntil pgtype.Timestamptz
	var lastError pgtype.Text
	var completedAt pgtype.Timestamptz
	if err := scanner.Scan(
		&run.TenantID,
		&run.ID,
		&requestedBy,
		&run.BaselinePolicyVersion,
		&run.BaselinePolicyHash,
		&run.ProposedPolicyVersion,
		&run.ProposedPolicyHash,
		&sampleScopeRaw,
		&run.State,
		&run.TotalSamples,
		&run.DangerousFindings,
		&findingsRaw,
		&run.Attempts,
		&notBefore,
		&leaseOwner,
		&leaseUntil,
		&lastError,
		&run.CreatedAt,
		&run.UpdatedAt,
		&completedAt,
	); err != nil {
		return PolicySimulationRun{}, fmt.Errorf("scan policy simulation run: %w", err)
	}
	sampleScope, err := decodeJSONMap(sampleScopeRaw)
	if err != nil {
		return PolicySimulationRun{}, fmt.Errorf("decode policy simulation sample scope: %w", err)
	}
	var findings []any
	if len(findingsRaw) > 0 {
		if err := json.Unmarshal(findingsRaw, &findings); err != nil {
			return PolicySimulationRun{}, fmt.Errorf("decode policy simulation findings: %w", err)
		}
	}
	if findings == nil {
		findings = []any{}
	}
	run.SampleScope = sampleScope
	run.Findings = findings
	if requestedBy.Valid {
		run.RequestedBySubjectID = requestedBy.String
	}
	if notBefore.Valid {
		t := notBefore.Time.UTC()
		run.NotBefore = &t
	}
	if leaseOwner.Valid {
		run.LeaseOwner = leaseOwner.String
	}
	if leaseUntil.Valid {
		t := leaseUntil.Time.UTC()
		run.LeaseUntil = &t
	}
	if lastError.Valid {
		run.LastError = lastError.String
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		run.CompletedAt = &t
	}
	return run, nil
}

func (s *Store) EnqueueOutboxEvent(ctx context.Context, event outbox.Event) (outbox.Event, error) {
	if event.TenantID == "" || event.AggregateID == "" || event.EventType == "" {
		return outbox.Event{}, errors.New("outbox event missing required fields")
	}
	if s == nil || s.pool == nil {
		return outbox.Event{}, errors.New("postgres pool is not configured")
	}
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("evt_%s_%s_%d", event.AggregateID, event.EventType, time.Now().UTC().UnixNano())
	}
	if event.AggregateVersion <= 0 {
		event.AggregateVersion = 1
	}
	if event.SchemaVersion <= 0 {
		event.SchemaVersion = 1
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	if event.TraceContext == nil {
		event.TraceContext = map[string]any{}
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return outbox.Event{}, fmt.Errorf("marshal outbox payload: %w", err)
	}
	traceContext, err := json.Marshal(event.TraceContext)
	if err != nil {
		return outbox.Event{}, fmt.Errorf("marshal outbox trace context: %w", err)
	}
	err = s.WithTenantTx(ctx, event.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			insert into outbox_events (
				tenant_id,
				event_id,
				aggregate_id,
				aggregate_version,
				event_type,
				payload,
				trace_context,
				schema_version,
				occurred_at
			) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			on conflict (tenant_id, event_id) do nothing
		`, event.TenantID, event.EventID, event.AggregateID, event.AggregateVersion, event.EventType, payload, traceContext, event.SchemaVersion, event.OccurredAt)
		if err != nil {
			return fmt.Errorf("enqueue outbox event: %w", err)
		}
		return nil
	})
	if err != nil {
		return outbox.Event{}, err
	}
	return event, nil
}

func (s *Store) ExpirePendingApprovals(ctx context.Context) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("postgres pool is not configured")
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, tenantID := range tenants {
		expired, err := s.expireTenantApprovals(ctx, tenantID)
		if err != nil {
			return total, err
		}
		total += expired
	}
	return total, nil
}

func (s *Store) expireTenantApprovals(ctx context.Context, tenantID string) (int64, error) {
	var expired int64
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			with expired as (
				update approval_requests
				set state = 'EXPIRED',
				    updated_at = now()
				where tenant_id = $1
				  and state = 'PENDING'
				  and expires_at <= now()
				returning tenant_id, id, invocation_id, updated_at
			),
			inserted_events as (
				insert into outbox_events (
					tenant_id,
					event_id,
					aggregate_id,
					aggregate_version,
					event_type,
					payload,
					trace_context,
					schema_version,
					occurred_at
				)
				select tenant_id,
				       'evt_' || invocation_id || '_ApprovalExpired_' || id,
				       invocation_id,
				       floor(extract(epoch from updated_at) * 1000000000)::bigint,
				       'ApprovalExpired',
				       jsonb_build_object(
				       	 'approval_request_id', id,
				       	 'invocation_id', invocation_id,
				       	 'state', 'EXPIRED',
				       	 'reason_codes', jsonb_build_array('APPROVAL_EXPIRED')
				       ),
				       '{}'::jsonb,
				       1,
				       updated_at
				from expired
				on conflict (tenant_id, event_id) do nothing
				returning 1
			)
			select count(*) from expired
		`, tenantID).Scan(&expired)
	})
	if err != nil {
		return 0, fmt.Errorf("expire pending approvals: %w", err)
	}
	return expired, nil
}

func (s *Store) ReleaseStaleBudgetReservations(ctx context.Context, opts BudgetReservationSweepOptions) (BudgetReservationSweepResult, error) {
	if s == nil || s.pool == nil {
		return BudgetReservationSweepResult{}, errors.New("postgres pool is not configured")
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 15 * time.Minute
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 50
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return BudgetReservationSweepResult{}, err
	}
	var result BudgetReservationSweepResult
	cutoff := time.Now().UTC().Add(-opts.StaleAfter)
	for _, tenantID := range tenants {
		released, err := s.releaseTenantStaleBudgetReservations(ctx, tenantID, cutoff, opts.BatchSize)
		if err != nil {
			return result, err
		}
		result.Released += released
	}
	return result, nil
}

func (s *Store) releaseTenantStaleBudgetReservations(ctx context.Context, tenantID string, cutoff time.Time, batchSize int) (int64, error) {
	var released int64
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			with stale_reserves as (
				select r.tenant_id,
				       r.id,
				       r.budget_id,
				       r.invocation_id,
				       r.amount_minor,
				       r.currency,
				       r.created_at
				from budget_ledger_entries r
				where r.tenant_id = $1
				  and r.entry_type = 'RESERVE'
				  and r.invocation_id is not null
				  and r.created_at <= $2
				  and not exists (
					select 1
					from budget_ledger_entries terminal
					where terminal.tenant_id = r.tenant_id
					  and terminal.budget_id = r.budget_id
					  and terminal.invocation_id = r.invocation_id
					  and (
						terminal.entry_type = 'COMMIT'
						or (
							terminal.entry_type = 'RELEASE'
							and terminal.id = 'bgl_release_' || r.id
						)
					  )
				  )
				order by r.created_at, r.id
				limit $3
				for update skip locked
			),
			released as (
				update budgets b
				set reserved_minor = reserved_minor - stale_reserves.amount_minor,
				    version = version + 1,
				    updated_at = now()
				from stale_reserves
				where b.tenant_id = stale_reserves.tenant_id
				  and b.id = stale_reserves.budget_id
				  and b.reserved_minor >= stale_reserves.amount_minor
				returning stale_reserves.tenant_id,
				          stale_reserves.id as reserve_entry_id,
				          stale_reserves.budget_id,
				          stale_reserves.invocation_id,
				          stale_reserves.amount_minor,
				          stale_reserves.currency,
				          b.version,
				          b.updated_at
			),
			release_entries as (
				insert into budget_ledger_entries (
					tenant_id,
					id,
					budget_id,
					invocation_id,
					entry_type,
					amount_minor,
					currency,
					created_at
				)
				select tenant_id,
				       'bgl_release_' || reserve_entry_id,
				       budget_id,
				       invocation_id,
				       'RELEASE',
				       amount_minor,
				       currency,
				       updated_at
				from released
				on conflict (tenant_id, id) do nothing
				returning tenant_id, id, budget_id, invocation_id, amount_minor, currency, created_at
			),
			inserted_events as (
				insert into outbox_events (
					tenant_id,
					event_id,
					aggregate_id,
					aggregate_version,
					event_type,
					payload,
					trace_context,
					schema_version,
					occurred_at
				)
				select release_entries.tenant_id,
				       'evt_' || release_entries.id || '_BudgetReservationReleased',
				       release_entries.budget_id,
				       floor(extract(epoch from release_entries.created_at) * 1000000000)::bigint,
				       'BudgetReservationReleased',
				       jsonb_build_object(
				       	 'budget_id', release_entries.budget_id,
				       	 'invocation_id', release_entries.invocation_id,
				       	 'amount_minor', release_entries.amount_minor,
				       	 'currency', release_entries.currency,
				       	 'state', 'RELEASED',
				       	 'reason_codes', jsonb_build_array('STALE_BUDGET_RESERVATION_RELEASED')
				       ),
				       '{}'::jsonb,
				       1,
				       release_entries.created_at
				from release_entries
				on conflict (tenant_id, event_id) do nothing
				returning 1
			)
			select count(*) from release_entries
		`, tenantID, cutoff, batchSize).Scan(&released)
	})
	if err != nil {
		return 0, fmt.Errorf("release stale budget reservations: %w", err)
	}
	return released, nil
}

func (s *Store) LeaseReconciliationInvocations(ctx context.Context, opts ReconciliationLeaseOptions) (ReconciliationLeaseResult, error) {
	if s == nil || s.pool == nil {
		return ReconciliationLeaseResult{}, errors.New("postgres pool is not configured")
	}
	if opts.LeaseOwner == "" {
		opts.LeaseOwner = "aegis-worker"
	}
	if opts.LeaseDuration <= 0 {
		opts.LeaseDuration = 2 * time.Minute
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = time.Minute
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 25
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return ReconciliationLeaseResult{}, err
	}
	var result ReconciliationLeaseResult
	now := time.Now().UTC()
	leaseUntil := now.Add(opts.LeaseDuration)
	notBefore := now.Add(opts.RetryAfter)
	for _, tenantID := range tenants {
		leased, err := s.leaseTenantReconciliationInvocations(ctx, tenantID, opts.LeaseOwner, now, leaseUntil, notBefore, opts.BatchSize)
		if err != nil {
			return result, err
		}
		result.Leased += leased
	}
	return result, nil
}

func (s *Store) leaseTenantReconciliationInvocations(ctx context.Context, tenantID, leaseOwner string, now, leaseUntil, notBefore time.Time, batchSize int) (int64, error) {
	var leased int64
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			with candidates as (
				select tenant_id,
				       invocation_id
				from invocations
				where tenant_id = $1
				  and state = 'RECONCILIATION_REQUIRED'
				  and (reconciliation_not_before is null or reconciliation_not_before <= $2)
				  and (reconciliation_lease_until is null or reconciliation_lease_until <= $2)
				order by updated_at, invocation_id
				limit $6
				for update skip locked
			),
			leased as (
				update invocations i
				set reconciliation_attempts = reconciliation_attempts + 1,
				    reconciliation_lease_owner = $3,
				    reconciliation_lease_until = $4,
				    reconciliation_not_before = $5,
				    updated_at = $2
				from candidates
				where i.tenant_id = candidates.tenant_id
				  and i.invocation_id = candidates.invocation_id
				returning i.tenant_id,
				          i.invocation_id,
				          i.state,
				          i.decision,
				          i.reason_codes,
				          i.reconciliation_attempts,
				          i.reconciliation_lease_owner,
				          i.reconciliation_lease_until,
				          i.updated_at
			),
			inserted_events as (
				insert into outbox_events (
					tenant_id,
					event_id,
					aggregate_id,
					aggregate_version,
					event_type,
					payload,
					trace_context,
					schema_version,
					occurred_at
				)
				select tenant_id,
				       'evt_' || invocation_id || '_ReconciliationLeaseClaimed_' || reconciliation_attempts,
				       invocation_id,
				       floor(extract(epoch from updated_at) * 1000000000)::bigint,
				       'ReconciliationLeaseClaimed',
				       jsonb_build_object(
				       	 'invocation_id', invocation_id,
				       	 'state', state,
				       	 'decision', decision,
				       	 'reason_codes', reason_codes,
				       	 'attempt', reconciliation_attempts,
				       	 'lease_owner', reconciliation_lease_owner,
				       	 'lease_until', reconciliation_lease_until
				       ),
				       '{}'::jsonb,
				       1,
				       updated_at
				from leased
				on conflict (tenant_id, event_id) do nothing
				returning 1
			)
			select count(*) from leased
		`, tenantID, now, leaseOwner, leaseUntil, notBefore, batchSize).Scan(&leased)
	})
	if err != nil {
		return 0, fmt.Errorf("lease reconciliation invocations: %w", err)
	}
	return leased, nil
}

func (s *Store) LeasePolicySimulationRuns(ctx context.Context, opts PolicySimulationLeaseOptions) (PolicySimulationLeaseResult, error) {
	if s == nil || s.pool == nil {
		return PolicySimulationLeaseResult{}, errors.New("postgres pool is not configured")
	}
	if opts.LeaseOwner == "" {
		opts.LeaseOwner = "aegis-worker"
	}
	if opts.LeaseDuration <= 0 {
		opts.LeaseDuration = 5 * time.Minute
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = 5 * time.Minute
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return PolicySimulationLeaseResult{}, err
	}
	var result PolicySimulationLeaseResult
	now := time.Now().UTC()
	leaseUntil := now.Add(opts.LeaseDuration)
	notBefore := now.Add(opts.RetryAfter)
	for _, tenantID := range tenants {
		leased, err := s.leaseTenantPolicySimulationRuns(ctx, tenantID, opts.LeaseOwner, now, leaseUntil, notBefore, opts.BatchSize)
		if err != nil {
			return result, err
		}
		result.Leased += leased
	}
	return result, nil
}

func (s *Store) leaseTenantPolicySimulationRuns(ctx context.Context, tenantID, leaseOwner string, now, leaseUntil, notBefore time.Time, batchSize int) (int64, error) {
	var leased int64
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			with candidates as (
				select tenant_id,
				       id
				from policy_simulation_runs
				where tenant_id = $1
				  and state in ('PENDING', 'RUNNING')
				  and (not_before is null or not_before <= $2)
				  and (lease_until is null or lease_until <= $2)
				order by updated_at, id
				limit $6
				for update skip locked
			),
			leased as (
				update policy_simulation_runs r
				set state = 'RUNNING',
				    attempts = attempts + 1,
				    lease_owner = $3,
				    lease_until = $4,
				    not_before = $5,
				    last_error = null,
				    updated_at = $2
				from candidates
				where r.tenant_id = candidates.tenant_id
				  and r.id = candidates.id
				returning r.tenant_id,
				          r.id,
				          r.state,
				          r.baseline_policy_version,
				          r.baseline_policy_hash,
				          r.proposed_policy_version,
				          r.proposed_policy_hash,
				          r.attempts,
				          r.lease_owner,
				          r.lease_until,
				          r.updated_at
			),
			inserted_events as (
				insert into outbox_events (
					tenant_id,
					event_id,
					aggregate_id,
					aggregate_version,
					event_type,
					payload,
					trace_context,
					schema_version,
					occurred_at
				)
				select tenant_id,
				       'evt_' || id || '_PolicySimulationLeaseClaimed_' || attempts,
				       id,
				       floor(extract(epoch from updated_at) * 1000000000)::bigint,
				       'PolicySimulationLeaseClaimed',
				       jsonb_build_object(
				       	 'simulation_id', id,
				       	 'state', state,
				       	 'baseline_policy_version', baseline_policy_version,
				       	 'baseline_policy_hash', baseline_policy_hash,
				       	 'proposed_policy_version', proposed_policy_version,
				       	 'proposed_policy_hash', proposed_policy_hash,
				       	 'attempt', attempts,
				       	 'lease_owner', lease_owner,
				       	 'lease_until', lease_until
				       ),
				       '{}'::jsonb,
				       1,
				       updated_at
				from leased
				on conflict (tenant_id, event_id) do nothing
				returning 1
			)
			select count(*) from leased
		`, tenantID, now, leaseOwner, leaseUntil, notBefore, batchSize).Scan(&leased)
	})
	if err != nil {
		return 0, fmt.Errorf("lease policy simulation runs: %w", err)
	}
	return leased, nil
}

func (s *Store) CompleteLeasedPolicySimulationRuns(ctx context.Context, opts PolicySimulationCompleteOptions) (PolicySimulationCompleteResult, error) {
	if s == nil || s.pool == nil {
		return PolicySimulationCompleteResult{}, errors.New("postgres pool is not configured")
	}
	if opts.LeaseOwner == "" {
		opts.LeaseOwner = "aegis-worker"
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return PolicySimulationCompleteResult{}, err
	}
	var total PolicySimulationCompleteResult
	for _, tenantID := range tenants {
		result, err := s.completeTenantPolicySimulationRuns(ctx, tenantID, opts.LeaseOwner, opts.BatchSize)
		if err != nil {
			return total, err
		}
		total.Completed += result.Completed
		total.Failed += result.Failed
	}
	return total, nil
}

func (s *Store) completeTenantPolicySimulationRuns(ctx context.Context, tenantID, leaseOwner string, batchSize int) (PolicySimulationCompleteResult, error) {
	var result PolicySimulationCompleteResult
	now := time.Now().UTC()
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			select tenant_id,
			       id,
			       requested_by_subject_id,
			       baseline_policy_version,
			       baseline_policy_hash,
			       proposed_policy_version,
			       proposed_policy_hash,
			       sample_scope,
			       state,
			       total_samples,
			       dangerous_findings,
			       findings,
			       attempts,
			       not_before,
			       lease_owner,
			       lease_until,
			       last_error,
			       created_at,
			       updated_at,
			       completed_at
			from policy_simulation_runs
			where tenant_id = $1
			  and state = 'RUNNING'
			  and lease_owner = $2
			  and (lease_until is null or lease_until > $3)
			order by updated_at, id
			limit $4
			for update skip locked
		`, tenantID, leaseOwner, now, batchSize)
		if err != nil {
			return fmt.Errorf("load leased policy simulation runs: %w", err)
		}
		defer rows.Close()
		runs := []PolicySimulationRun{}
		for rows.Next() {
			run, err := scanPolicySimulationRun(rows)
			if err != nil {
				return err
			}
			runs = append(runs, run)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate leased policy simulation runs: %w", err)
		}
		for _, run := range runs {
			baselineBundle, baselineExists, err := loadPolicySimulationBundle(ctx, tx, tenantID, run.BaselinePolicyHash)
			if err != nil {
				return err
			}
			proposedBundle, proposedExists, err := loadPolicySimulationBundle(ctx, tx, tenantID, run.ProposedPolicyHash)
			if err != nil {
				return err
			}
			if !baselineExists || !proposedExists {
				if err := failPolicySimulationRun(ctx, tx, run, now, baselineExists, proposedExists); err != nil {
					return err
				}
				result.Failed++
				continue
			}
			samples, err := loadPolicySimulationReplaySamples(ctx, tx, tenantID, run.SampleScope)
			if err != nil {
				return err
			}
			if err := completePolicySimulationRun(ctx, tx, run, baselineBundle, proposedBundle, samples, now); err != nil {
				return err
			}
			result.Completed++
		}
		return nil
	})
	if err != nil {
		return PolicySimulationCompleteResult{}, fmt.Errorf("complete policy simulation runs: %w", err)
	}
	return result, nil
}

func loadPolicySimulationBundle(ctx context.Context, tx pgx.Tx, tenantID, policyHash string) (PolicyBundle, bool, error) {
	bundle, err := scanPolicyBundle(tx.QueryRow(ctx, `
		select tenant_id,
		       id,
		       version,
		       policy_hash,
		       source,
		       status,
		       active,
		       description,
		       opa_bundle_url,
		       metadata,
		       created_by_subject_id,
		       created_at,
		       updated_at,
		       activated_at,
		       retired_at
		from policy_bundles
		where tenant_id = $1
		  and policy_hash = $2
	`, tenantID, policyHash))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicyBundle{}, false, nil
		}
		return PolicyBundle{}, false, fmt.Errorf("load policy simulation bundle: %w", err)
	}
	return bundle, true, nil
}

func loadPolicySimulationReplaySamples(ctx context.Context, tx pgx.Tx, tenantID string, scope map[string]any) ([]policySimulationReplaySample, error) {
	limit := policySimulationSampleLimit(scope)
	rows, err := tx.Query(ctx, `
		select i.tenant_id,
		       i.invocation_id,
		       i.protocol,
		       coalesce(i.protocol_request_id, ''),
		       coalesce(i.idempotency_key, ''),
		       i.subject_id,
		       s.type,
		       s.groups,
		       s.roles,
		       i.agent_id,
		       a.trust_level,
		       a.owner_subject_id,
		       a.client_id,
		       i.delegation_id,
		       i.tool_id,
		       i.tool_schema_version,
		       i.tool_schema_hash,
		       i.action,
		       i.resource_type,
		       i.resource_id,
		       i.purpose,
		       i.redacted_arguments,
		       i.created_at,
		       t.display_name,
		       t.mcp_server_id,
		       t.mcp_tool_name,
		       t.active,
		       tv.description,
		       tv.input_schema,
		       tv.output_schema,
		       tv.risk_classification,
		       tv.side_effect_classification,
		       tv.data_sensitivity,
		       tv.required_scopes,
		       tv.required_credential_template,
		       tv.timeout_ms,
		       tv.retry_policy,
		       tv.idempotency_supported,
		       tv.approval_defaults,
		       tv.allowed_network_destination,
		       tv.connector_version
		from invocations i
		join subjects s
		  on s.tenant_id = i.tenant_id
		 and s.id = i.subject_id
		join agents a
		  on a.tenant_id = i.tenant_id
		 and a.id = i.agent_id
		join tools t
		  on t.tenant_id = i.tenant_id
		 and t.tool_id = i.tool_id
		join tool_versions tv
		  on tv.tenant_id = i.tenant_id
		 and tv.tool_id = i.tool_id
		 and tv.schema_version = i.tool_schema_version
		where i.tenant_id = $1
		  and ($2 = '' or i.tool_id = $2)
		  and ($3 = '' or i.action = $3)
		  and ($4 = '' or i.resource_type = $4)
		  and ($5 = '' or i.resource_id = $5)
		order by i.created_at desc, i.invocation_id desc
		limit $6
	`, tenantID, policySimulationScopeString(scope, "tool_id"), policySimulationScopeString(scope, "action"), policySimulationScopeString(scope, "resource_type"), policySimulationScopeString(scope, "resource_id"), limit)
	if err != nil {
		return nil, fmt.Errorf("load policy simulation replay samples: %w", err)
	}
	defer rows.Close()

	samples := make([]policySimulationReplaySample, 0, limit)
	for rows.Next() {
		sample, err := scanPolicySimulationReplaySample(rows)
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy simulation replay samples: %w", err)
	}
	return samples, nil
}

func scanPolicySimulationReplaySample(rows pgx.Rows) (policySimulationReplaySample, error) {
	var sample policySimulationReplaySample
	var subjectType string
	var argumentsRaw []byte
	var requestedAt time.Time
	var inputSchemaRaw []byte
	var outputSchemaRaw []byte
	var retryPolicyRaw []byte
	var approvalDefaultsRaw []byte
	var timeoutMS int
	var protocol string
	var toolRisk string
	var sideEffect string
	var dataSensitivity string
	if err := rows.Scan(
		&sample.Request.TenantID,
		&sample.Request.InvocationID,
		&protocol,
		&sample.Request.ProtocolRequestID,
		&sample.Request.IdempotencyKey,
		&sample.Request.Subject.ID,
		&subjectType,
		&sample.Request.Subject.Groups,
		&sample.Request.Subject.Roles,
		&sample.Request.Agent.ID,
		&sample.Request.Agent.TrustLevel,
		&sample.Request.Agent.OwnerID,
		&sample.Request.Agent.ClientID,
		&sample.Request.DelegationID,
		&sample.Request.Tool.ID,
		&sample.Request.Tool.SchemaVersion,
		&sample.Request.Tool.SchemaHash,
		&sample.Request.Action,
		&sample.Request.Resource.Type,
		&sample.Request.Resource.ID,
		&sample.Request.Purpose,
		&argumentsRaw,
		&requestedAt,
		&sample.Tool.DisplayName,
		&sample.Tool.MCPServerID,
		&sample.Tool.MCPToolName,
		&sample.Tool.Active,
		&sample.Tool.Description,
		&inputSchemaRaw,
		&outputSchemaRaw,
		&toolRisk,
		&sideEffect,
		&dataSensitivity,
		&sample.Tool.RequiredScopes,
		&sample.Tool.RequiredCredentialTemplate,
		&timeoutMS,
		&retryPolicyRaw,
		&sample.Tool.IdempotencySupported,
		&approvalDefaultsRaw,
		&sample.Tool.AllowedNetworkDestination,
		&sample.Tool.ConnectorVersion,
	); err != nil {
		return policySimulationReplaySample{}, fmt.Errorf("scan policy simulation replay sample: %w", err)
	}
	arguments, err := decodeJSONMap(argumentsRaw)
	if err != nil {
		return policySimulationReplaySample{}, fmt.Errorf("decode policy simulation sample arguments: %w", err)
	}
	inputSchema, err := decodeJSONMap(inputSchemaRaw)
	if err != nil {
		return policySimulationReplaySample{}, fmt.Errorf("decode policy simulation input schema: %w", err)
	}
	outputSchema, err := decodeJSONMap(outputSchemaRaw)
	if err != nil {
		return policySimulationReplaySample{}, fmt.Errorf("decode policy simulation output schema: %w", err)
	}
	var retryPolicy tools.RetryPolicy
	if len(retryPolicyRaw) > 0 {
		if err := json.Unmarshal(retryPolicyRaw, &retryPolicy); err != nil {
			return policySimulationReplaySample{}, fmt.Errorf("decode policy simulation retry policy: %w", err)
		}
	}
	var approvalDefaults tools.ApprovalDefaults
	if len(approvalDefaultsRaw) > 0 {
		if err := json.Unmarshal(approvalDefaultsRaw, &approvalDefaults); err != nil {
			return policySimulationReplaySample{}, fmt.Errorf("decode policy simulation approval defaults: %w", err)
		}
	}
	sample.Request.Subject.Type = authn.PrincipalType(subjectType)
	sample.Request.Protocol = invocation.Protocol(protocol)
	sample.Request.Arguments = arguments
	sample.Request.Resource.OwnerTenantID = sample.Request.TenantID
	sample.Request.RequestContext.RequestedAt = requestedAt.UTC()
	sample.Tool.TenantID = sample.Request.TenantID
	sample.Tool.ID = sample.Request.Tool.ID
	sample.Tool.SchemaVersion = sample.Request.Tool.SchemaVersion
	sample.Tool.SchemaHash = sample.Request.Tool.SchemaHash
	sample.Tool.InputSchema = inputSchema
	sample.Tool.OutputSchema = outputSchema
	sample.Tool.Risk = tools.RiskClassification(toolRisk)
	sample.Tool.SideEffect = tools.SideEffectClassification(sideEffect)
	sample.Tool.DataSensitivity = tools.DataSensitivity(dataSensitivity)
	sample.Tool.Timeout = time.Duration(timeoutMS) * time.Millisecond
	sample.Tool.RetryPolicy = retryPolicy
	sample.Tool.ApprovalDefaults = approvalDefaults
	sample.Risk = risk.Calculate(sample.Request, sample.Tool, risk.Context{HourUTC: requestedAt.UTC().Hour()})
	return sample, nil
}

func completePolicySimulationRun(ctx context.Context, tx pgx.Tx, run PolicySimulationRun, baselineBundle, proposedBundle PolicyBundle, samples []policySimulationReplaySample, completedAt time.Time) error {
	const maxFindingDetails = 100
	findingsList := []map[string]any{}
	dangerousFindings := 0
	findingDetailsTruncated := false
	for _, sample := range samples {
		baseline := policy.EvaluateBundleSimulation(sample.Request, sample.Tool, sample.Risk, policy.BundleSimulationConfig{
			Version:  baselineBundle.Version,
			Hash:     baselineBundle.PolicyHash,
			Metadata: baselineBundle.Metadata,
		})
		proposed := policy.EvaluateBundleSimulation(sample.Request, sample.Tool, sample.Risk, policy.BundleSimulationConfig{
			Version:  proposedBundle.Version,
			Hash:     proposedBundle.PolicyHash,
			Metadata: proposedBundle.Metadata,
		})
		comparison := policy.CompareDecisions(baseline, proposed)
		if !comparison.Dangerous {
			continue
		}
		dangerousFindings += len(comparison.Findings)
		if len(findingsList) >= maxFindingDetails {
			findingDetailsTruncated = true
			continue
		}
		findingsList = append(findingsList, map[string]any{
			"type":                    "DANGEROUS_POLICY_CHANGE",
			"invocation_id":           sample.Request.InvocationID,
			"tool_id":                 sample.Request.Tool.ID,
			"action":                  sample.Request.Action,
			"resource_type":           sample.Request.Resource.Type,
			"resource_id":             sample.Request.Resource.ID,
			"risk_score":              sample.Risk.Score,
			"findings":                comparison.Findings,
			"baseline_policy_version": baselineBundle.Version,
			"baseline_policy_hash":    baselineBundle.PolicyHash,
			"baseline_decision":       comparison.BaselineAction,
			"baseline_decision_id":    comparison.BaselineID,
			"proposed_policy_version": proposedBundle.Version,
			"proposed_policy_hash":    proposedBundle.PolicyHash,
			"proposed_decision":       comparison.ProposedAction,
			"proposed_decision_id":    comparison.ProposedID,
		})
	}
	findingsList = append([]map[string]any{{
		"type":                       "SIMULATION_SUMMARY",
		"baseline_policy_version":    baselineBundle.Version,
		"baseline_policy_hash":       baselineBundle.PolicyHash,
		"proposed_policy_version":    proposedBundle.Version,
		"proposed_policy_hash":       proposedBundle.PolicyHash,
		"sample_count":               len(samples),
		"dangerous_findings":         dangerousFindings,
		"finding_details_truncated":  findingDetailsTruncated,
	}}, findingsList...)
	findings, err := json.Marshal(findingsList)
	if err != nil {
		return fmt.Errorf("marshal policy simulation completion findings: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		update policy_simulation_runs
		set state = 'SUCCEEDED',
		    total_samples = $3,
		    dangerous_findings = $4,
		    findings = $5,
		    lease_owner = null,
		    lease_until = null,
		    last_error = null,
		    updated_at = $6,
		    completed_at = $6
		where tenant_id = $1
		  and id = $2
		  and state = 'RUNNING'
	`, run.TenantID, run.ID, len(samples), dangerousFindings, findings, completedAt)
	if err != nil {
		return fmt.Errorf("complete policy simulation run: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("policy simulation run disappeared while completing")
	}
	return enqueuePolicySimulationTerminalEvent(ctx, tx, run, "PolicySimulationRunCompleted", "SUCCEEDED", len(samples), dangerousFindings, "", completedAt)
}

func failPolicySimulationRun(ctx context.Context, tx pgx.Tx, run PolicySimulationRun, failedAt time.Time, baselineExists, proposedExists bool) error {
	reason := "policy bundle hash not found"
	if !baselineExists && proposedExists {
		reason = "baseline policy bundle hash not found"
	}
	if baselineExists && !proposedExists {
		reason = "proposed policy bundle hash not found"
	}
	findings, err := json.Marshal([]map[string]any{
		{
			"type":                    "SIMULATION_VALIDATION_FAILED",
			"reason":                  reason,
			"baseline_policy_hash":    run.BaselinePolicyHash,
			"baseline_bundle_found":   baselineExists,
			"proposed_policy_hash":    run.ProposedPolicyHash,
			"proposed_bundle_found":   proposedExists,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal policy simulation failure findings: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		update policy_simulation_runs
		set state = 'FAILED',
		    total_samples = 0,
		    dangerous_findings = 0,
		    findings = $3,
		    lease_owner = null,
		    lease_until = null,
		    last_error = $4,
		    updated_at = $5,
		    completed_at = $5
		where tenant_id = $1
		  and id = $2
		  and state = 'RUNNING'
	`, run.TenantID, run.ID, findings, reason, failedAt)
	if err != nil {
		return fmt.Errorf("fail policy simulation run: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("policy simulation run disappeared while failing")
	}
	return enqueuePolicySimulationTerminalEvent(ctx, tx, run, "PolicySimulationRunFailed", "FAILED", 0, 0, reason, failedAt)
}

func enqueuePolicySimulationTerminalEvent(ctx context.Context, tx pgx.Tx, run PolicySimulationRun, eventType, state string, totalSamples, dangerousFindings int, lastError string, occurredAt time.Time) error {
	payload, err := json.Marshal(map[string]any{
		"simulation_id":             run.ID,
		"state":                     state,
		"baseline_policy_version":   run.BaselinePolicyVersion,
		"baseline_policy_hash":      run.BaselinePolicyHash,
		"proposed_policy_version":   run.ProposedPolicyVersion,
		"proposed_policy_hash":      run.ProposedPolicyHash,
		"total_samples":             totalSamples,
		"dangerous_findings":        dangerousFindings,
		"last_error":                lastError,
	})
	if err != nil {
		return fmt.Errorf("marshal policy simulation terminal payload: %w", err)
	}
	_, err = tx.Exec(ctx, `
		insert into outbox_events (
			tenant_id,
			event_id,
			aggregate_id,
			aggregate_version,
			event_type,
			payload,
			trace_context,
			schema_version,
			occurred_at
		) values ($1, $2, $3, $4, $5, $6, '{}'::jsonb, 1, $7)
		on conflict (tenant_id, event_id) do nothing
	`, run.TenantID, fmt.Sprintf("evt_%s_%s_%d", run.ID, eventType, occurredAt.UnixNano()), run.ID, occurredAt.UnixNano(), eventType, payload, occurredAt)
	if err != nil {
		return fmt.Errorf("enqueue policy simulation terminal event: %w", err)
	}
	return nil
}

func policySimulationSampleLimit(scope map[string]any) int {
	const defaultLimit = 100
	const maxLimit = 1000
	value, ok := scope["sample_limit"]
	if !ok {
		return defaultLimit
	}
	limit := 0
	switch typed := value.(type) {
	case int:
		limit = typed
	case int64:
		limit = int(typed)
	case float64:
		limit = int(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			limit = int(parsed)
		}
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func policySimulationScopeString(scope map[string]any, key string) string {
	value, ok := scope[key]
	if !ok || value == nil {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func (s *Store) PublishPendingOutbox(ctx context.Context, publisher outbox.Publisher, opts OutboxDrainOptions) (OutboxDrainResult, error) {
	if publisher == nil {
		return OutboxDrainResult{}, errors.New("outbox publisher is required")
	}
	if s == nil || s.pool == nil {
		return OutboxDrainResult{}, errors.New("postgres pool is not configured")
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 50
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 5
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return OutboxDrainResult{}, err
	}
	var total OutboxDrainResult
	for _, tenantID := range tenants {
		result, err := s.publishTenantOutbox(ctx, tenantID, publisher, opts)
		if err != nil {
			return total, err
		}
		total.Published += result.Published
		total.Failed += result.Failed
		total.DeadLettered += result.DeadLettered
	}
	return total, nil
}

func (s *Store) listTenantIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		select id
		from tenants
		where deleted_at is null
		order by id
	`)
	if err != nil {
		return nil, fmt.Errorf("list tenants for outbox drain: %w", err)
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan tenant for outbox drain: %w", err)
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants for outbox drain: %w", err)
	}
	return tenants, nil
}

func (s *Store) publishTenantOutbox(ctx context.Context, tenantID string, publisher outbox.Publisher, opts OutboxDrainOptions) (OutboxDrainResult, error) {
	var result OutboxDrainResult
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		events, err := loadPendingOutboxEvents(ctx, tx, tenantID, opts)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := publisher.Publish(event); err != nil {
				deadLettered, markErr := markOutboxFailed(ctx, tx, event, err, opts.MaxAttempts)
				if markErr != nil {
					return markErr
				}
				result.Failed++
				if deadLettered {
					result.DeadLettered++
				}
				continue
			}
			if err := markOutboxPublished(ctx, tx, event); err != nil {
				return err
			}
			result.Published++
		}
		return nil
	})
	return result, err
}

func loadPendingOutboxEvents(ctx context.Context, tx pgx.Tx, tenantID string, opts OutboxDrainOptions) ([]outbox.Event, error) {
	rows, err := tx.Query(ctx, `
		select tenant_id,
		       event_id,
		       aggregate_id,
		       aggregate_version,
		       event_type,
		       payload,
		       trace_context,
		       schema_version,
		       occurred_at,
		       published_at,
		       delivery_attempts,
		       last_error,
		       dead_lettered
		from outbox_events
		where tenant_id = $1
		  and published_at is null
		  and dead_lettered = false
		  and delivery_attempts < $2
		order by occurred_at
		limit $3
		for update skip locked
	`, tenantID, opts.MaxAttempts, opts.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("load pending outbox events: %w", err)
	}
	defer rows.Close()
	events := make([]outbox.Event, 0, opts.BatchSize)
	for rows.Next() {
		event, err := scanOutboxEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending outbox events: %w", err)
	}
	return events, nil
}

func scanOutboxEvent(rows pgx.Rows) (outbox.Event, error) {
	var event outbox.Event
	var payloadRaw []byte
	var traceRaw []byte
	var publishedAt pgtype.Timestamptz
	var lastError pgtype.Text
	if err := rows.Scan(
		&event.TenantID,
		&event.EventID,
		&event.AggregateID,
		&event.AggregateVersion,
		&event.EventType,
		&payloadRaw,
		&traceRaw,
		&event.SchemaVersion,
		&event.OccurredAt,
		&publishedAt,
		&event.DeliveryAttempts,
		&lastError,
		&event.DeadLettered,
	); err != nil {
		return outbox.Event{}, fmt.Errorf("scan outbox event: %w", err)
	}
	payload, err := decodeJSONMap(payloadRaw)
	if err != nil {
		return outbox.Event{}, fmt.Errorf("decode outbox payload: %w", err)
	}
	traceContext, err := decodeJSONMap(traceRaw)
	if err != nil {
		return outbox.Event{}, fmt.Errorf("decode outbox trace context: %w", err)
	}
	event.Payload = payload
	event.TraceContext = traceContext
	if publishedAt.Valid {
		t := publishedAt.Time.UTC()
		event.PublishedAt = &t
	}
	if lastError.Valid {
		event.LastError = lastError.String
	}
	return event, nil
}

func decodeJSONMap(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value == nil {
		value = map[string]any{}
	}
	return value, nil
}

func markOutboxPublished(ctx context.Context, tx pgx.Tx, event outbox.Event) error {
	tag, err := tx.Exec(ctx, `
		update outbox_events
		set published_at = now(),
		    delivery_attempts = delivery_attempts + 1,
		    last_error = null
		where tenant_id = $1
		  and event_id = $2
	`, event.TenantID, event.EventID)
	if err != nil {
		return fmt.Errorf("mark outbox event published: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("outbox event disappeared while marking published")
	}
	return nil
}

func markOutboxFailed(ctx context.Context, tx pgx.Tx, event outbox.Event, publishErr error, maxAttempts int) (bool, error) {
	nextAttempts := event.DeliveryAttempts + 1
	deadLettered := nextAttempts >= maxAttempts
	tag, err := tx.Exec(ctx, `
		update outbox_events
		set delivery_attempts = $3,
		    last_error = $4,
		    dead_lettered = $5
		where tenant_id = $1
		  and event_id = $2
	`, event.TenantID, event.EventID, nextAttempts, publishErr.Error(), deadLettered)
	if err != nil {
		return false, fmt.Errorf("mark outbox event failed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, errors.New("outbox event disappeared while marking failed")
	}
	return deadLettered, nil
}

func (s *Store) GenerateAuditRoots(ctx context.Context, signer string) (AuditRootResult, error) {
	if s == nil || s.pool == nil {
		return AuditRootResult{}, errors.New("postgres pool is not configured")
	}
	if signer == "" {
		signer = "aegis-dev-signer"
	}
	tenants, err := s.listTenantIDs(ctx)
	if err != nil {
		return AuditRootResult{}, err
	}
	var result AuditRootResult
	for _, tenantID := range tenants {
		generated, err := s.generateTenantAuditRoot(ctx, tenantID, signer)
		if err != nil {
			return result, err
		}
		if generated {
			result.Generated++
		}
	}
	return result, nil
}

func (s *Store) generateTenantAuditRoot(ctx context.Context, tenantID, signer string) (bool, error) {
	generated := false
	err := s.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		lastSequence, previousHash, err := currentAuditRootBoundary(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		events, err := loadAuditEventsAfter(ctx, tx, tenantID, lastSequence)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		if err := audit.VerifySegment(events, previousHash, lastSequence+1); err != nil {
			return err
		}
		root, err := audit.RootManifest(tenantID, events, signer, time.Now().UTC())
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			insert into audit_roots (
				tenant_id,
				root_id,
				from_sequence_no,
				to_sequence_no,
				root_hash,
				signer,
				signature,
				generated_at
			) values ($1, $2, $3, $4, $5, $6, $7, $8)
			on conflict (tenant_id, root_id) do nothing
		`, root.TenantID, root.RootID, root.FromSequenceNo, root.ToSequenceNo, root.RootHash, signer, root.Signature, root.GeneratedAt)
		if err != nil {
			return fmt.Errorf("insert audit root: %w", err)
		}
		generated = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("generate tenant audit root: %w", err)
	}
	return generated, nil
}

func currentAuditRootBoundary(ctx context.Context, tx pgx.Tx, tenantID string) (int64, string, error) {
	var lastSequence int64
	if err := tx.QueryRow(ctx, `
		select coalesce(max(to_sequence_no), 0)
		from audit_roots
		where tenant_id = $1
	`, tenantID).Scan(&lastSequence); err != nil {
		return 0, "", fmt.Errorf("load audit root boundary: %w", err)
	}
	if lastSequence == 0 {
		return 0, "", nil
	}
	var previousHash string
	if err := tx.QueryRow(ctx, `
		select event_hash
		from audit_events
		where tenant_id = $1
		  and sequence_no = $2
	`, tenantID, lastSequence).Scan(&previousHash); err != nil {
		return 0, "", fmt.Errorf("load audit previous hash: %w", err)
	}
	return lastSequence, previousHash, nil
}

func loadAuditEventsAfter(ctx context.Context, tx pgx.Tx, tenantID string, afterSequence int64) ([]audit.Event, error) {
	rows, err := tx.Query(ctx, `
		select tenant_id,
		       sequence_no,
		       event_id,
		       invocation_id,
		       event_type,
		       actor_type,
		       actor_id,
		       safe_reason_code,
		       redacted_payload,
		       previous_hash,
		       event_hash,
		       occurred_at
		from audit_events
		where tenant_id = $1
		  and sequence_no > $2
		order by sequence_no
		for update
	`, tenantID, afterSequence)
	if err != nil {
		return nil, fmt.Errorf("load audit events for root: %w", err)
	}
	defer rows.Close()
	events := []audit.Event{}
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events for root: %w", err)
	}
	return events, nil
}

func scanAuditEvent(rows pgx.Rows) (audit.Event, error) {
	var event audit.Event
	var invocationID pgtype.Text
	var safeReason pgtype.Text
	var previousHash pgtype.Text
	var payloadRaw []byte
	if err := rows.Scan(
		&event.TenantID,
		&event.SequenceNo,
		&event.EventID,
		&invocationID,
		&event.EventType,
		&event.ActorType,
		&event.ActorID,
		&safeReason,
		&payloadRaw,
		&previousHash,
		&event.EventHash,
		&event.OccurredAt,
	); err != nil {
		return audit.Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	payload, err := decodeJSONMap(payloadRaw)
	if err != nil {
		return audit.Event{}, fmt.Errorf("decode audit event payload: %w", err)
	}
	if invocationID.Valid {
		event.InvocationID = invocationID.String
	}
	if safeReason.Valid {
		event.SafeReasonCode = safeReason.String
	}
	if previousHash.Valid {
		event.PreviousHash = previousHash.String
	}
	event.RedactedPayload = payload
	return event, nil
}
