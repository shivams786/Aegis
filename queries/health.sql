-- name: Ping :one
SELECT 1::int AS ok;

-- name: GetTenant :one
SELECT id, slug, name, created_at
FROM tenants
WHERE id = $1
  AND deleted_at IS NULL;
