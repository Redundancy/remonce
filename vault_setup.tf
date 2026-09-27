# Terraform configuration to set up a Vault server.
# This file will enable userpass and OIDC authentication methods.

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 3.0.0"
    }
  }
}

# ------------------------------------------------------------------------------
# PROVIDER CONFIGURATION
# ------------------------------------------------------------------------------
# Configure the Vault provider. It is recommended to use environment variables
# (VAULT_ADDR and VAULT_TOKEN) instead of hardcoding values here.
variable "vault_addr" {
  description = "URL of the Vault server (e.g., http://127.0.0.1:8200)"
  type        = string
  default     = "http://127.0.0.1:8200"
}

variable "vault_token" {
  description = "Root or admin token to configure Vault"
  type        = string
  sensitive   = true
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

# ------------------------------------------------------------------------------
# USERNAME & PASSWORD AUTHENTICATION
# ------------------------------------------------------------------------------
# Enable the 'userpass' authentication backend.
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

# Variable for the user's password.
variable "app_user_password" {
  description = "Password for the application user."
  type        = string
  sensitive   = true
}

# Create a policy for the user.
resource "vault_policy" "app_user_policy" {
  name   = "app-user-policy"
  policy = <<-EOT
    # Grant read access to a sample path
    path "secret/data/app/*" {
      capabilities = ["read", "list"]
    }
  EOT
}

# Create a user with username/password credentials.
# Note: There is no dedicated resource for a userpass user,
# so we use the generic endpoint API.
resource "vault_generic_endpoint" "app_user" {
  path = "auth/userpass/users/webapp"

  data_json = jsonencode({
    password = var.app_user_password
    policies = [vault_policy.app_user_policy.name]
  })

  depends_on = [
    vault_auth_backend.userpass
  ]
}

# A second user, so requests that need two different people's approval can
# be tried locally. Same password as the first.
resource "vault_generic_endpoint" "app_user2" {
  path = "auth/userpass/users/webapp2"

  data_json = jsonencode({
    password = var.app_user_password
    policies = [vault_policy.app_user_policy.name]
  })

  depends_on = [
    vault_auth_backend.userpass
  ]
}

resource "vault_identity_entity" "webapp_user2" {
  name = "webapp-user2"
}

resource "vault_identity_entity_alias" "webapp_user2_alias" {
  name           = "webapp2"
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.webapp_user2.id
}

# Create an entity for the webapp user so we can assign it to the OIDC client
resource "vault_identity_entity" "webapp_user" {
  name = "webapp-user"
}

# Alias the userpass login to this entity
resource "vault_identity_entity_alias" "webapp_user_alias" {
  name            = "webapp"
  mount_accessor  = vault_auth_backend.userpass.accessor
  canonical_id    = vault_identity_entity.webapp_user.id
}

# Create a group for the webapp users
resource "vault_identity_group" "webapp_users" {
  name = "webapp-users"
  type = "internal"
  member_entity_ids = [
    vault_identity_entity.webapp_user.id,
    vault_identity_entity.webapp_user2.id,
  ]
}

# Create an OIDC Assignment - this is the "Bridge" between entities/groups and the Client
resource "vault_identity_oidc_assignment" "app_assignment" {
  name       = "app-assignment"
  group_ids  = [vault_identity_group.webapp_users.id]
  entity_ids = [vault_identity_entity.webapp_user.id] 
}

# ------------------------------------------------------------------------------
# VAULT AS OIDC PROVIDER
# ------------------------------------------------------------------------------
# This section configures Vault to act as an OIDC Identity Provider.

# Create a signing key for the OIDC tokens.
resource "vault_identity_oidc_key" "provider_key" {
  name      = "provider_key"
  algorithm = "RS256"
}

# Create a role that assigns the key to a client.
resource "vault_identity_oidc_role" "token_role" {
  name = "generated-token"
  key  = vault_identity_oidc_key.provider_key.name
  client_id = vault_identity_oidc_client.webapp_client.client_id
}

# Configure the OIDC provider itself.
# The issuer is set to localhost without HTTPS as requested.
resource "vault_identity_oidc_provider" "localhost_provider" {
  name = "vaultprovider"
  # The issuer URL must be accessible from the browser of the user authenticating.
  # For local testing, this is typically the Vault address.
  # issuer = "http://127.0.0.1:8200"
  allowed_client_ids = [
    vault_identity_oidc_client.webapp_client.client_id,
    vault_identity_oidc_client.viewer_client.client_id,
  ]
  scopes_supported = [
    vault_identity_oidc_scope.groups.name,
    vault_identity_oidc_scope.user_profile.name
  ]
}

resource "vault_identity_oidc_scope" "groups" {
  name        = "groups"
  description = "Vault Groups Scope"
  template    = base64encode(<<EOF
{
  "groups": {{identity.entity.groups.names}}
}
EOF
  )
}

resource "vault_identity_oidc_scope" "user_profile" {
  name        = "user_profile"
  description = "Vault User Profile Scope"
  template    = base64encode(<<EOF
{
  "username": {{identity.entity.name}}
}
EOF
  )
}

# Create an OIDC client application.
# This represents an application that will use Vault to authenticate users.
resource "vault_identity_oidc_client" "webapp_client" {
  name = "webapp-client"

  # URIs where the OIDC provider can redirect the user after authentication.
  redirect_uris = [
    "http://localhost:8080/oidc/callback",
    "http://127.0.0.1:8080/oidc/callback"
  ]

  # Assign the assignment resource
  assignments = [
    vault_identity_oidc_assignment.app_assignment.name
  ]

  # Type of client. 'public' clients cannot securely store a secret (e.g., SPAs).
  client_type = "public"

  # TTL for tokens. Signing freshness is measured from the token's `iat`,
  # so this lifetime no longer extends how long a signature stays valid.
  id_token_ttl     = 3600 # 1 hour
  access_token_ttl = 3600 # 1 hour


}

# The viewer client: logs users in for browsing files and execution logs.
# Its tokens are bearer credentials, accepted by agents only on read-only
# endpoints, so keep them short-lived. Must be a different client from the
# signing client above.
resource "vault_identity_oidc_client" "viewer_client" {
  name = "webapp-viewer"

  redirect_uris = [
    "http://localhost:8080/oidc/callback",
    "http://127.0.0.1:8080/oidc/callback"
  ]

  assignments = [
    vault_identity_oidc_assignment.app_assignment.name
  ]

  client_type = "public"

  id_token_ttl     = 900 # 15 minutes
  access_token_ttl = 900
}


# ------------------------------------------------------------------------------
# OUTPUTS
# ------------------------------------------------------------------------------
output "userpass_auth_path" {
  value       = vault_auth_backend.userpass.path
  description = "The path where the userpass auth method is enabled."
}

output "oidc_provider_issuer_url" {
  value       = vault_identity_oidc_provider.localhost_provider.issuer
  description = "The issuer URL for Vault's OIDC provider. Use this for the '.well-known/oidc-configuration' endpoint."
}

output "oidc_viewer_client_id" {
  value       = vault_identity_oidc_client.viewer_client.client_id
  description = "The Client ID for the viewer (browsing) OIDC client."
}

output "oidc_client_id" {
  value       = vault_identity_oidc_client.webapp_client.client_id
  description = "The Client ID for the OIDC signing client."
}
