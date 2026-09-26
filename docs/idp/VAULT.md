# HashiCorp Vault OIDC Configuration

This guide walks through configuring HashiCorp Vault as an OIDC Identity Provider for Remonce.

> [!TIP]
> A complete Terraform example is available in [`vault_setup.tf`](../../vault_setup.tf) at the project root.

## Overview

Vault can act as an OIDC provider, issuing JWTs that Remonce uses for authentication. The key challenge is correctly configuring **claim templates** so that user identity and group memberships are included in the ID Token.

```mermaid
graph LR
    A[User] --> B[Vault Login]
    B --> C[ID Token with Claims]
    C --> D[Remonce Agent]
    D --> E[OPA Policy Check]
```

## Prerequisites

- HashiCorp Vault server (1.9+) with enterprise auth (LDAP, OIDC, SAML, etc.)
- Terraform (recommended) or Vault CLI
- Admin access to Vault
- Existing identity entities (created automatically by your auth method)

> [!TIP]
> **Local Development**: For dev/test setup using userpass auth, see [DEVELOPMENT.md](../../DEVELOPMENT.md#vault-development-configuration).

---

## Step 1: Create Identity Groups

Groups enable role-based access control in OPA policies. Add your existing identity entities to groups:

```hcl
resource "vault_identity_group" "example_users" {
  name              = "example-users"
  type              = "internal"
  member_entity_ids = [vault_identity_entity.example_user.id]
}
```

---

## Step 2: Define OIDC Scopes (Claim Templates)

This is where most configuration issues occur. Vault uses **scope templates** to inject claims into the JWT.

### Groups Scope

```hcl
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
```

### User Profile Scope

```hcl
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
```

> [!CAUTION]
> **Template Syntax**: Note that `{{identity.entity.groups.names}}` uses **double braces** and is **not** quoted. Vault injects the value as a JSON array. Quoting it will produce a malformed string.

### Available Template Variables

| Variable | Type | Description |
|----------|------|-------------|
| `{{identity.entity.id}}` | string | Entity UUID |
| `{{identity.entity.name}}` | string | Entity name |
| `{{identity.entity.groups.names}}` | array | Group names |
| `{{identity.entity.metadata}}` | object | Custom metadata |
| `{{identity.entity.aliases}}` | array | Login aliases |

---

## Step 3: Create the OIDC Clients

Remonce needs **two** clients: a *signing* client, used for a fresh re-authenticating login on every approval, cosign and revocation, and a *viewer* client, used for the ordinary browsing login (files and execution logs). Agents accept each only where it belongs, so a signing token carried inside a delegated bundle can never be used to browse.

```hcl
resource "vault_identity_oidc_client" "remonce_client" {
  name = "remonce-client"

  redirect_uris = [
    # Loopback addresses for local CLI/desktop usage
    "http://localhost:8080/oidc/callback",
    "http://127.0.0.1:8080/oidc/callback",
    
    # Production web server (add your actual URL)
    "https://remonce.example.com/oidc/callback"
  ]

  # Public client for browser-based apps (no client secret)
  client_type = "public"

  # Token lifetimes. Signature validity is measured from the login (`iat`),
  # so this no longer widens how long a signature is usable.
  id_token_ttl     = 3600  # 1 hour
  access_token_ttl = 3600  # 1 hour
}

# The viewer client. Its tokens are bearer credentials for read-only
# endpoints, so keep them short-lived.
resource "vault_identity_oidc_client" "remonce_viewer" {
  name          = "remonce-viewer"
  redirect_uris = vault_identity_oidc_client.remonce_client.redirect_uris
  client_type   = "public"

  id_token_ttl     = 900   # 15 minutes
  access_token_ttl = 900
}
```

Assign both clients the same assignment (Step 4).

> [!IMPORTANT]
> **Redirect URI Requirements**:
> - **Loopback addresses** (`localhost`, `127.0.0.1`): Required for local CLI usage or running Remonce on your machine.
> - **Production URLs**: Required for each managed Remonce web server. OIDC will not allow authentication to servers not in this list.
> - **All redirect URIs must be explicitly listed**—OIDC does not support wildcards for security reasons.

> [!WARNING]
> **Do Not Reuse This Client**: This configuration creates a dedicated OIDC client for Remonce. Because Remonce exposes the JWT to execution targets (see delegation model), sharing this client ID with other applications would allow those targets to reuse the token against those applications. Keep this client exclusive to Remonce.

---

## Step 4: Create an OIDC Assignment

Assignments **bridge** entities/groups to the OIDC client. Only assigned entities can authenticate.

```hcl
resource "vault_identity_oidc_assignment" "remonce_assignment" {
  name       = "remonce-assignment"
  group_ids  = [vault_identity_group.example_users.id]
  entity_ids = [vault_identity_entity.example_user.id]
}
```

> [!TIP]
> **Multiple Assignments**: Create separate assignments if you have different user populations for different clients (e.g., `remonce-admins` vs `remonce-operators`). Each assignment can reference different groups/entities.

---

## Step 5: Configure the OIDC Provider

Finally, create the provider that serves the OIDC endpoints.

```hcl
resource "vault_identity_oidc_provider" "oidc_provider" {
  name = "vaultprovider"
  
  allowed_client_ids = [
    vault_identity_oidc_client.remonce_client.client_id,
    vault_identity_oidc_client.remonce_viewer.client_id,
  ]
  
  scopes_supported = [
    vault_identity_oidc_scope.groups.name,
    vault_identity_oidc_scope.user_profile.name
  ]
}
```

---

## Step 6: Create the Signing Key and Role

The **signing key** is the cryptographic key Vault uses to sign issued JWTs. The **role** binds this key to a specific client, defining how tokens are generated for that client.

```hcl
# The key Vault uses to sign JWTs (public key is exposed at .well-known/jwks)
resource "vault_identity_oidc_key" "remonce_key" {
  name               = "remonce_key"
  algorithm          = "ES256"
  rotation_period    = 604800  # 1 week
  allowed_client_ids = [
    vault_identity_oidc_client.remonce_client.client_id,
    vault_identity_oidc_client.remonce_viewer.client_id,
  ]
}

# Binds the signing key to the Remonce client
resource "vault_identity_oidc_role" "token_role" {
  name      = "generated-token"
  key       = vault_identity_oidc_key.remonce_key.name
  client_id = vault_identity_oidc_client.remonce_client.client_id
}

output "oidc_client_id" {
  description = "Signing client ID for Remonce"
  value       = vault_identity_oidc_client.remonce_client.client_id
}

output "oidc_viewer_client_id" {
  description = "Viewer client ID for Remonce"
  value       = vault_identity_oidc_client.remonce_viewer.client_id
}
```

> [!NOTE]
> **Configuration Choices**:
> - **ES256**: Produces smaller tokens than RS256. Use RS256 if you need broader compatibility with older systems.
> - **Client-specific key**: The `allowed_client_ids` restriction ensures this key can only be used by the Remonce client.
> - **Weekly rotation**: Keys rotate automatically; during rotation both old and new keys remain valid for graceful token expiration.

---

## Remonce Configuration

After Vault is configured, update your `config.toml`:

```toml
[oidc]
issuer_url       = "https://vault.example.com/v1/identity/oidc/provider/vaultprovider"
client_id        = "<oidc_client_id from terraform output>"
viewer_client_id = "<oidc_viewer_client_id from terraform output>"
redirect_uri     = "http://localhost:8080/oidc/callback"
```

Leave `signing_max_age` at its default of `1s`: Vault rejects `max_age=0` ("max_age must be greater than zero").

### Getting the Client IDs

```bash
terraform output oidc_client_id
terraform output oidc_viewer_client_id
```

---

## Verification

### 1. Check OIDC Discovery

```bash
curl https://vault.example.com/v1/identity/oidc/provider/vaultprovider/.well-known/openid-configuration
```

### 2. Verify Token Claims

After signing something through Remonce, the signing JWT in the bundle should contain:

```json
{
  "iss": "https://vault.example.com/v1/identity/oidc/provider/vaultprovider",
  "sub": "<entity-id>",
  "aud": "<signing-client-id>",
  "iat": 1790460388,
  "auth_time": 1790460388,
  "nonce": "<sha256-of-ephemeral-public-key>",
  "groups": ["example-users"],
  "username": "example-user"
}
```

`aud` must be the bare client ID (not a list with other audiences), and `auth_time` must be present and close to `iat`. Vault issues `auth_time` when `max_age` is requested, and with `max_age=1` it sends the user back through the login page even if they have a Vault session.

---

## Troubleshooting

### Claims are missing from JWT

| Symptom | Cause | Fix |
|---------|-------|-----|
| No `groups` claim | Entity not in a group | Add entity to group |
| No custom claims at all | No entity alias | Create alias linking login to entity |
| `groups` is a string | Template uses quotes | Remove quotes around `{{...}}` |

### "Client not found" or "Unauthorized"

- Verify the client ID matches exactly between Vault and `config.toml`
- Ensure the entity is included in an assignment linked to the client

### Redirect URI mismatch

- Vault is strict about URIs. `localhost` ≠ `127.0.0.1`
- Add both variants to `redirect_uris` during development

---

## Security Best Practices

1. **Dedicated Client IDs**: Never share the Remonce signing or viewer client ID with other applications, or with each other
2. **Short Viewer Token TTL**: Viewer tokens are bearer credentials for files and logs; keep their TTL short (5-15 minutes). The signing client's TTL no longer affects how long a signature is usable
3. **Claim Minimization**: Only request scopes needed for OPA policies
4. **HTTPS in Production**: Never use HTTP issuer URLs in production
5. **Restrict Assignments**: Only assign entities that should access Remonce
