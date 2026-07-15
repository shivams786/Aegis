COMPOSE := docker compose -f deploy/docker-compose.yml --env-file .env
POSTGRES_USER ?= aegis
POSTGRES_DB ?= aegis
DATABASE_URL ?= postgres://aegis:aegis_dev_password@localhost:5432/aegis?sslmode=disable
AUDIT_EVENTS_FILE ?=
AUDIT_TENANT ?= tenant_acme

.PHONY: bootstrap up migrate seed test test-integration test-security test-race test-policy lint demo demo-mcp-services audit-verify audit-verify-file admin-build load-test down

bootstrap:
	@test -f .env || cp .env.example .env
	@echo "Created .env if it did not already exist."

up:
	$(COMPOSE) up -d --build

migrate:
	$(COMPOSE) exec -T postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -f /migrations/000001_initial.up.sql

seed:
	$(COMPOSE) exec -T postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -f /seed/seed.sql

test:
	go test ./...

test-integration:
	AEGIS_TEST_DATABASE_URL="$(DATABASE_URL)" go test -tags=integration ./tests/integration

test-security:
	go test ./internal/authn ./internal/delegation ./internal/api

test-race:
	go test -race ./...

test-policy:
	opa test policies

lint:
	golangci-lint run ./...

demo:
	powershell -ExecutionPolicy Bypass -File ./scripts/demo.ps1

demo-mcp-services:
	powershell -ExecutionPolicy Bypass -File ./scripts/demo-mcp-services.ps1

admin-build:
	npm install --prefix admin
	npm run build --prefix admin

load-test:
	k6 run tests/performance/gateway.k6.js

audit-verify:
	go run ./cmd/audit-verifier

audit-verify-file:
	go run ./cmd/audit-verifier -file "$(AUDIT_EVENTS_FILE)" -tenant "$(AUDIT_TENANT)"

down:
	$(COMPOSE) down
