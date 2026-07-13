package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/delegation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func (s *Store) ResolveActingIdentity(ctx context.Context, identity authn.ActingIdentity) (authn.ActingIdentity, error) {
	if err := identity.Validate(); err != nil {
		return authn.ActingIdentity{}, err
	}
	if s == nil || s.pool == nil {
		return authn.ActingIdentity{}, errors.New("postgres pool is not configured")
	}
	var subject authn.Subject
	err := s.pool.QueryRow(ctx, `
		select type, id, groups, roles
		from subjects
		where tenant_id = $1
		  and id = $2
		  and disabled_at is null
	`, identity.TenantID, identity.Subject.ID).Scan(&subject.Type, &subject.ID, &subject.Groups, &subject.Roles)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authn.ActingIdentity{}, errors.New("subject not found")
		}
		return authn.ActingIdentity{}, fmt.Errorf("resolve subject: %w", err)
	}
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
