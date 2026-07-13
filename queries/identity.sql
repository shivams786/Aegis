-- name: GetSubjectForIdentity :one
SELECT type, id, groups, roles
FROM subjects
WHERE tenant_id = $1
  AND id = $2
  AND disabled_at IS NULL;

-- name: GetAgentForIdentity :one
SELECT id, trust_level, owner_subject_id, client_id
FROM agents
WHERE tenant_id = $1
  AND id = $2
  AND disabled_at IS NULL;
