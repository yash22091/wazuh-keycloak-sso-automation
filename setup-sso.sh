#!/bin/bash
set -euo pipefail
# Function to display help message
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help                     Show this help message and exit"
    echo "  -k, --keycloak-url URL         Keycloak URL"
    echo "  -r, --realm REALM              Realm name"
    echo "  -c, --client CLIENT            Client name"
    echo "  -a, --admin-user USER          Admin username"
    echo "  -p, --admin-pass PASS          Admin password"
    echo "  -u, --new-user USER            New username"
    echo "  -w, --new-pass PASS            New user password"
    echo "  -e, --new-email EMAIL          New user email"
    echo "  -f, --new-firstname NAME       New user first name"
    echo "  -l, --new-lastname NAME        New user last name"
    echo "  -s, --siem_url URL             Siem URL Name"
    echo "  -d, --debug                    Enable debug mode"
    echo
    echo "Example:"
    echo "  $0 -k https://keycloak.example.com -r myrealm -c myclient -a admin -p adminpass -u newuser -w newpass -e user@example.com -f John -l Doe -s url"
}

# Initialize variables with default values
DEBUG=false
KEYCLOAK_URL=""
REALM_NAME=""
CLIENT_NAME=""
ADMIN_USER=""
ADMIN_PASSWORD=""
NEW_USER_USERNAME=""
NEW_USER_PASSWORD=""
NEW_USER_EMAIL=""
NEW_USER_FIRST_NAME=""
NEW_USER_LAST_NAME=""
SIEM_URL=""

# Parse command line arguments
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -h|--help)
    show_help
    exit 0
    ;;
    -k|--keycloak-url)
    KEYCLOAK_URL="$2"
    shift # past argument
    shift # past value
    ;;
    -r|--realm)
    REALM_NAME="$2"
    shift # past argument
    shift # past value
    ;;
    -c|--client)
    CLIENT_NAME="$2"
    shift # past argument
    shift # past value
    ;;
    -a|--admin-user)
    ADMIN_USER="$2"
    shift # past argument
    shift # past value
    ;;
    -p|--admin-pass)
    ADMIN_PASSWORD="$2"
    shift # past argument
    shift # past value
    ;;
    -u|--new-user)
    NEW_USER_USERNAME="$2"
    shift # past argument
    shift # past value
    ;;
    -w|--new-pass)
    NEW_USER_PASSWORD="$2"
    shift # past argument
    shift # past value
    ;;
    -e|--new-email)
    NEW_USER_EMAIL="$2"
    shift # past argument
    shift # past value
    ;;
    -f|--new-firstname)
    NEW_USER_FIRST_NAME="$2"
    shift # past argument
    shift # past value
    ;;
    -l|--new-lastname)
    NEW_USER_LAST_NAME="$2"
    shift # past argument
    shift # past value
    ;;
    -s|--siem_url)
    SIEM_URL="$2"
    shift # past argument
    shift # past value
    ;;
    -d|--debug)
    DEBUG=true
    shift # past argument
    ;;
    *)    # unknown option
    echo "Unknown option: $1"
    show_help
    exit 1
    ;;
esac
done

# Check if all required parameters are provided
if [ -z "$KEYCLOAK_URL" ] || [ -z "$REALM_NAME" ] || [ -z "$CLIENT_NAME" ] || [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PASSWORD" ] || [ -z "$NEW_USER_USERNAME" ] || [ -z "$NEW_USER_PASSWORD" ] || [ -z "$NEW_USER_EMAIL" ] || [ -z "$NEW_USER_FIRST_NAME" ] || [ -z "$NEW_USER_LAST_NAME" ] || [ -z "$SIEM_URL" ]; then
    echo "Error: Missing required parameters."
    show_help
    exit 1
fi

# Function to print debug messages
debug() {
  if [ "$DEBUG" = true ]; then
    echo "DEBUG: $1"
  fi
}

# Install required packages
apt install jq -y

# Define your services here
services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard" "filebeat")

# Function to check the status of a service
check_service() {
    local service=$1
    systemctl is-active --quiet "$service"
    return $?
}

# Function to wait for all services to be running
wait_for_services() {
    local all_services_running=false

    while [ "$all_services_running" != true ]; do
        all_services_running=true
        for service in "${services[@]}"; do
            if ! check_service "$service"; then
                echo "Waiting for $service to start..."
                all_services_running=false
                sleep 5 # wait for 5 seconds before checking again
            fi
        done
        if [ "$all_services_running" = true ]; then
            echo "All services are now running."
        fi
    done
}

# Wait for all services to be running
wait_for_services

# The location where you want to save the configuration file
config_file="/etc/wazuh-indexer/opensearch-security/config.yml.keycloak"

# Write the configuration content to the file
cat << 'EOF' > "$config_file"
_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    http:
      anonymous_auth_enabled: false
      xff:
        enabled: false
        internalProxies: '192\.168\.0\.10|192\.168\.0\.11' # regex pattern
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: internal
      openid_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 1
        http_authenticator:
          type: openid
          challenge: false
          config:
            openid_connect_url: http://172.17.14.105:8080/auth/realms/yash/.well-known/openid-configuration
            kibana_url: https://172.17.14.80
            roles_key: roles
            subject_key: preferred_username
            verify_hostnames: false
        authentication_backend:
          type: noop
EOF


# Variables

REDIRECT_URIS='["https://'$SIEM_URL/*'"]'
WAZUH_CONFIG_FILE="/etc/wazuh-indexer/opensearch-security/config.yml.keycloak"
ADMIN_USER="admin"
ADMIN_PASSWORD=$ADMIN_PASSWORD
KEYCLOAK_CLIENT_ID="admin-cli"
HOST_IP=$(hostname -I | awk '{print $1}')
SIEM_URL="https://$SIEM_URL"
#CLIENT_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
CLIENT_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1)

# Define your roles here
declare -a REALM_ROLES=("roles" "admin" "readonly-role")
declare -a CLIENT_ROLES=("roles" "admin" "readonly-role")

# Get admin access token
get_admin_token() {
debug "Retrieving admin access token..."
TOKEN=$(curl -k -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASSWORD" \
    -d 'grant_type=password' \
    -d "client_id=$KEYCLOAK_CLIENT_ID" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
  echo "Failed to retrieve admin token"
  exit 1
fi

debug "Admin token retrieved successfully. $TOKEN"
}

# Check if realm exists and create if it doesn't
check_and_create_realm() {
    debug "Checking if realm $REALM_NAME exists..."
    REALM_EXISTS=$(curl -k -s -o /dev/null -w "%{http_code}" -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
        -H "Authorization: Bearer $TOKEN")

    if [ "$REALM_EXISTS" -eq 404 ]; then
        debug "Realm $REALM_NAME does not exist. Creating..."
        REALM_CREATION_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{
              "realm": "'"$REALM_NAME"'",
              "enabled": true,
              "sslRequired": "none",
              "loginTheme": "'"$CUSTOM_THEME_NAME"'",
              "accountTheme": "'"$CUSTOM_THEME_NAME"'",
              "adminTheme": "'"$CUSTOM_THEME_NAME"'",
              "emailTheme": "'"$CUSTOM_THEME_NAME"'"
            }')

        REALM_CREATION_STATUS=$(echo "$REALM_CREATION_RESPONSE" | tail -n1)
        REALM_CREATION_BODY=$(echo "$REALM_CREATION_RESPONSE" | sed '$d')

        if [ "$REALM_CREATION_STATUS" -eq 201 ]; then
            debug "Realm $REALM_NAME created successfully."
        else
            echo "Failed to create realm: $REALM_NAME"
            echo "Status code: $REALM_CREATION_STATUS"
            echo "Response body: $REALM_CREATION_BODY"
            exit 1
        fi
    else
        debug "Realm $REALM_NAME already exists."
    fi
}

# Check if client exists and create if it doesn't
check_and_create_client() {
    debug "Checking if client $CLIENT_NAME exists..."
    CLIENT_ID=$(curl -k -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.clientId=="'"$CLIENT_NAME"'") | .id')

    if [ -z "$CLIENT_ID" ]; then
        debug "Client $CLIENT_NAME does not exist. Creating..."
        CLIENT_CREATION_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{
              "clientId": "'"$CLIENT_NAME"'",
              "standardFlowEnabled": true,
              "directAccessGrantsEnabled": true,
              "serviceAccountsEnabled": true,
              "authorizationServicesEnabled": true,
              "redirectUris": '"$REDIRECT_URIS"',
              "webOrigins": ["*"],
              "publicClient": false,
              "enabled": true,
              "clientAuthenticatorType": "client-secret",
              "secret": "'"$CLIENT_SECRET"'",
              "protocolMappers": [
                {
                  "name": "realm roles",
                  "protocol": "openid-connect",
                  "protocolMapper": "oidc-usermodel-realm-role-mapper",
                  "consentRequired": false,
                  "config": {
                    "userinfo.token.claim": "true",
                    "user.attribute": "User Realm Role",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "roles",
                    "jsonType.label": "String",
                    "multivalued": "true"
                  }
                }
              ]
            }')

        CLIENT_CREATION_STATUS=$(echo "$CLIENT_CREATION_RESPONSE" | tail -n1)
        CLIENT_CREATION_BODY=$(echo "$CLIENT_CREATION_RESPONSE" | sed '$d')

        if [ "$CLIENT_CREATION_STATUS" -eq 201 ]; then
            debug "Client $CLIENT_NAME created successfully."
            CLIENT_ID=$(echo "$CLIENT_CREATION_BODY" | jq -r '.id')
            debug "New client ID: $CLIENT_ID"
        else
            echo "Failed to create client: $CLIENT_NAME"
            echo "Status code: $CLIENT_CREATION_STATUS"
            echo "Response body: $CLIENT_CREATION_BODY"
            exit 1
        fi
    else
        debug "Client $CLIENT_NAME already exists with ID: $CLIENT_ID"
    fi
}

# Check if user exists
check_user_exists() {
    debug "Checking if user $NEW_USER_USERNAME exists..."
    USER_ID=$(curl -k -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=$NEW_USER_USERNAME" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

    if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
        debug "User $NEW_USER_USERNAME already exists with ID: $USER_ID"
        return 0
    else
        debug "User $NEW_USER_USERNAME does not exist."
        return 1
    fi
}

# Create or update user
create_or_update_user() {
    if check_user_exists; then
        debug "Updating user: $NEW_USER_USERNAME..."
        RESPONSE=$(curl -k -s -w "%{http_code}" -o /tmp/user_response.json -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{
                "username": "'"$NEW_USER_USERNAME"'",
                "enabled": true,
                "email": "'"$NEW_USER_EMAIL"'",
                "firstName": "'"$NEW_USER_FIRST_NAME"'",
                "lastName": "'"$NEW_USER_LAST_NAME"'",
                "credentials": [{
                    "type": "password",
                    "value": "'"$NEW_USER_PASSWORD"'",
                    "temporary": true
                }]
            }')
    else
        debug "Creating new user: $NEW_USER_USERNAME..."
        RESPONSE=$(curl -k -s -w "%{http_code}" -o /tmp/user_response.json -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{
                "username": "'"$NEW_USER_USERNAME"'",
                "enabled": true,
                "email": "'"$NEW_USER_EMAIL"'",
                "firstName": "'"$NEW_USER_FIRST_NAME"'",
                "lastName": "'"$NEW_USER_LAST_NAME"'",
                "credentials": [{
                    "type": "password",
                    "value": "'"$NEW_USER_PASSWORD"'",
                    "temporary": true
                }]
            }')
    fi

    if [ "$RESPONSE" -ne 201 ] && [ "$RESPONSE" -ne 204 ]; then
      echo "Failed to create/update user: $NEW_USER_USERNAME"
      cat /tmp/user_response.json
      exit 1
    fi

    debug "User $NEW_USER_USERNAME created/updated successfully."
}

# Create realm roles
create_realm_roles() {
    for role in "${REALM_ROLES[@]}"; do
        debug "Creating/updating realm role: $role..."
        curl -k -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "{\"name\": \"$role\"}"
    done
}

# Create client roles
create_client_roles() {
    for role in "${CLIENT_ROLES[@]}"; do
        debug "Creating/updating client role: $role..."
        curl -k -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_ID/roles" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "{\"name\": \"$role\"}"
    done
}

# Get user ID
get_user_id() {
    debug "Getting user ID for username: $NEW_USER_USERNAME"
    USER_ID=$(curl -k -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=$NEW_USER_USERNAME" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

    if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
        echo "Failed to get user ID for username: $NEW_USER_USERNAME"
        exit 1
    fi
    debug "User ID obtained successfully: $USER_ID"
}

# Assign roles to user
assign_roles_to_user() {
    debug "Assigning roles to user: $NEW_USER_USERNAME (ID: $USER_ID)"

    # Assign realm roles
    for role in "${REALM_ROLES[@]}"; do
        debug "Assigning realm role: $role"
        ROLE_ID=$(curl -k -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$role" \
            -H "Authorization: Bearer $TOKEN" | jq -r '.id')

        if [ -z "$ROLE_ID" ] || [ "$ROLE_ID" = "null" ]; then
            debug "Failed to get ID for realm role: $role"
            continue
        fi

        RESPONSE=$(curl -k -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '[{"id":"'"$ROLE_ID"'","name":"'"$role"'"}]')

        debug "Realm role assignment response: $RESPONSE"
    done

    # Assign client roles
    for role in "${CLIENT_ROLES[@]}"; do
        debug "Assigning client role: $role"
        ROLE_ID=$(curl -k -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_ID/roles/$role" \
            -H "Authorization: Bearer $TOKEN" | jq -r '.id')

        if [ -z "$ROLE_ID" ] || [ "$ROLE_ID" = "null" ]; then
            debug "Failed to get ID for client role: $role"
            continue
        fi

        RESPONSE=$(curl -k -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/clients/$CLIENT_ID" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '[{"id":"'"$ROLE_ID"'","name":"'"$role"'"}]')

        debug "Client role assignment response: $RESPONSE"
    done

    debug "Role assignment completed for user: $TARGET_USERNAME"
}



# Main execution
get_admin_token
check_and_create_realm
check_and_create_client
create_or_update_user
create_realm_roles
create_client_roles
get_user_id
assign_roles_to_user

# Final output
echo "Configuration completed successfully."
echo "Organization: $ORGANIZATION_NAME"
echo "Realm: $REALM_NAME"
echo "Client: $CLIENT_NAME"
echo "User created/updated: $NEW_USER_USERNAME"
echo "Wazuh configuration updated and services restarted."
echo "Please verify the integration by logging into the Wazuh dashboard."


# Update Wazuh configuration
update_wazuh_config() {
    debug "Updating Wazuh configuration..."
    sed -i "s|openid_connect_url:.*|openid_connect_url: $KEYCLOAK_URL/realms/$REALM_NAME/.well-known/openid-configuration|" "$WAZUH_CONFIG_FILE"
    sed -i "s|kibana_url:.*|kibana_url: $SIEM_URL|" "$WAZUH_CONFIG_FILE"

    chown wazuh-indexer:wazuh-indexer "$WAZUH_CONFIG_FILE"
}

# Update Wazuh Dashboard configuration
update_wazuh_dashboard_config() {
    debug "Updating Opensearch Dashboard configuration..."
    DASHBOARD_CONFIG_FILE="/etc/wazuh-dashboard/opensearch_dashboards.yml"

    # Backup the original file
    cp "$DASHBOARD_CONFIG_FILE" "${DASHBOARD_CONFIG_FILE}.bak"

    # Add or update OpenID configuration
    sed -i '/^opensearch_security/d' "$DASHBOARD_CONFIG_FILE"
    cat << EOF >> "$DASHBOARD_CONFIG_FILE"

opensearch_security.auth.type: "openid"
opensearch_security.openid.connect_url: "$KEYCLOAK_URL/realms/$REALM_NAME/.well-known/openid-configuration"
opensearch_security.openid.client_id: "$CLIENT_NAME"
opensearch_security.openid.client_secret: "$CLIENT_SECRET"
opensearch_security.openid.base_redirect_url: "$SIEM_URL"
opensearch_security.openid.logout_url: "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/logout"
EOF

    chown wazuh-dashboard:wazuh-dashboard    "$DASHBOARD_CONFIG_FILE"
}

# Run Wazuh security admin script
run_wazuh_security_admin() {
    debug "Running Opensearch security admin script..."
    export JAVA_HOME=/usr/share/opensearch/jdk/
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f "$WAZUH_CONFIG_FILE" -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv

    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/roles.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv

    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv
}

# Restart Invinsense services
restart_wazuh_services() {
    debug "Restarting  services..."
    systemctl restart wazuh-manager
    systemctl restart wazuh-indexer
    systemctl restart wazuh-dashboard
    systemctl restart filebeat
}

# Main execution (continued)
update_wazuh_config
update_wazuh_dashboard_config
run_wazuh_security_admin
restart_wazuh_services

# Final output
echo "Configuration completed successfully."
echo "Realm: "$ORGNAME$REALM_NAME""
echo "Client: $CLIENT_NAME"
echo "User created/updated: $NEW_USER_USERNAME"
echo "Wazuh configuration updated and services restarted."
echo "Please verify the integration by logging into the Wazuh dashboard."

# Optional: Add any additional checks or verifications here
# For example, you could add a function to test the Keycloak connection or verify Wazuh service status

# Example of a verification function
verify_wazuh_services() {
    debug "Verifying Wazuh services status..."
    services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard" "filebeat")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "$service is running."
        else
            echo "WARNING: $service is not running."
        fi
    done
}

verify_wazuh_services

echo "Script execution completed."

echo "Configuration completed successfully."
echo "Realm: $REALM_NAME"
echo "Client: $CLIENT_NAME"
echo "User created/updated: $NEW_USER_USERNAME"
