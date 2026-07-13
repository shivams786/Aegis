-- name: GetDelegationGrant :one
SELECT tenant_id,
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
FROM delegation_grants
WHERE tenant_id = $1
  AND id = $2;
