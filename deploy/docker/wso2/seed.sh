#!/usr/bin/env bash
# Provision WSO2 IS 7.2 for the Agent Integrator demo.
# Idempotent: checks for existing resources before creating.
#
# Usage: WSO2_BASE=https://localhost:9443 ./seed.sh
set -euo pipefail

WSO2_BASE="${WSO2_BASE:-https://wso2is:9443}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
APP_NAME="agent-integrator"
SCOPE_NAME="agent-integrator"
ORG="${WSO2_ORG:-acme}"

CURL="curl -sk -u ${ADMIN_USER}:${ADMIN_PASS} -H Content-Type:application/json"

wait_healthy() {
  echo "Waiting for WSO2 IS at ${WSO2_BASE}..."
  for i in $(seq 1 60); do
    if ${CURL} "${WSO2_BASE}/api/server/v1/server-info" >/dev/null 2>&1; then
      echo "WSO2 IS is ready."
      return 0
    fi
    sleep 5
    echo "  attempt ${i}/60..."
  done
  echo "ERROR: WSO2 IS did not become healthy in time." >&2
  exit 1
}

create_scope() {
  local existing
  existing=$(${CURL} "${WSO2_BASE}/api/server/v1/oidc/scopes" | grep -o "\"name\":\"${SCOPE_NAME}\"" || true)
  if [ -n "${existing}" ]; then
    echo "Scope '${SCOPE_NAME}' already exists, skipping."
    return
  fi

  echo "Creating OIDC scope '${SCOPE_NAME}'..."
  ${CURL} -X POST "${WSO2_BASE}/api/server/v1/oidc/scopes" \
    -d "{
      \"name\": \"${SCOPE_NAME}\",
      \"displayName\": \"Agent Integrator\",
      \"description\": \"Scope for Agent Integrator access\",
      \"claims\": [\"sub\", \"email\", \"roles\"]
    }"
  echo "Scope created."
}

create_application() {
  local existing
  existing=$(${CURL} "${WSO2_BASE}/api/server/v1/applications?filter=name+eq+${APP_NAME}" | grep -o "\"name\":\"${APP_NAME}\"" || true)
  if [ -n "${existing}" ]; then
    echo "Application '${APP_NAME}' already exists, skipping."
    return
  fi

  echo "Creating application '${APP_NAME}'..."
  local app_response
  app_response=$(${CURL} -X POST "${WSO2_BASE}/api/server/v1/applications" \
    -d "{
      \"name\": \"${APP_NAME}\",
      \"description\": \"Agent Integrator - execution-scoped authority for AI agents\",
      \"inboundProtocolConfiguration\": {
        \"oidc\": {
          \"grantTypes\": [\"client_credentials\", \"urn:ietf:params:oauth:grant-type:token-exchange\"],
          \"allowedOrigins\": [],
          \"accessToken\": {
            \"type\": \"JWT\",
            \"userAccessTokenExpiryInSeconds\": 3600,
            \"applicationAccessTokenExpiryInSeconds\": 3600
          },
          \"scopeValidators\": [],
          \"scopes\": [\"openid\", \"${SCOPE_NAME}\"]
        }
      },
      \"authenticationSequence\": {
        \"type\": \"DEFAULT\"
      }
    }")

  echo "Application created."
  echo "${app_response}" | grep -o '"clientId":"[^"]*"' || true
  echo "${app_response}" | grep -o '"clientSecret":"[^"]*"' || true

  local client_id client_secret
  client_id=$(echo "${app_response}" | grep -o '"clientId":"[^"]*"' | cut -d'"' -f4 || echo "")
  client_secret=$(echo "${app_response}" | grep -o '"clientSecret":"[^"]*"' | cut -d'"' -f4 || echo "")

  if [ -n "${client_id}" ] && [ -n "${client_secret}" ]; then
    ENV_FILE="${ENV_FILE:-../../../.env}"
    mkdir -p "$(dirname "${ENV_FILE}")"
    {
      echo "AGENT_CLIENT_ID=${client_id}"
      echo "AGENT_CLIENT_SECRET=${client_secret}"
      echo "WSO2_BASE=${WSO2_BASE}"
      echo "IDP_AUDIENCE=${APP_NAME}"
    } >> "${ENV_FILE}"
    echo "Credentials written to ${ENV_FILE}"
  fi
}

create_role() {
  local role_name="Procurement-Specialist"
  local existing
  existing=$(${CURL} "${WSO2_BASE}/scim2/v2/Roles?filter=displayName+eq+${role_name}" | grep -o "\"displayName\":\"${role_name}\"" || true)
  if [ -n "${existing}" ]; then
    echo "Role '${role_name}' already exists, skipping."
    return
  fi

  echo "Creating role '${role_name}'..."
  ${CURL} -X POST "${WSO2_BASE}/scim2/v2/Roles" \
    -d "{
      \"displayName\": \"${role_name}\",
      \"permissions\": [
        \"/permission/admin/manage/ai/agent/procurement\"
      ]
    }"
  echo "Role created."
}

wait_healthy
create_scope
create_application
create_role

echo "WSO2 provisioning complete."
