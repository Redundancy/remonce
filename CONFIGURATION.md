# Configuration Guide

This document identifies the configuration options available for the Remonse agent, including authentication, authorization, and security settings.

## Configuration File (`config.toml`)

The agent is configured via a `config.toml` file located in the current working directory.
    
### General Settings

Basic network and storage configuration.

```toml
# Interface and port to bind the web server to.
# Default: "127.0.0.1:8080"
listen_address = "127.0.0.1:8080"

# Directory where execution logs will be stored.
# Default: "logs"
logs_dir = "logs"
```

### Identity (OIDC)

These settings connect the agent to your OIDC provider (Vault, Keycloak, etc.).

```toml
[oidc]
# Base URL of the OIDC provider's issuer.
# Must match the 'iss' claim in your JWTs.
issuer_url = "http://127.0.0.1:8200/v1/identity/oidc/provider/vaultprovider"

# The Client ID registered with the OIDC provider.
client_id = "your_client_id"

# Redirect URI for the OIDC callback.
# Ensure this matches exactly what is registered in your OIDC provider.
redirect_uri = "http://localhost:8080/oidc/callback"
```

### Authorization (OPA)

These settings determine how the agent checks permissions.

```toml
# URL of the Open Policy Agent service.
# If omitted, defaults to "http://localhost:8181".
opa_url = "http://127.0.0.1:8181"
```

### Security & TSA (RFC 3161)

To ensure non-repudiation of executed commands, the agent verifies RFC 3161 Timestamp Tokens.

```toml
[timestamp_authority]
# (Optional) URL of the Time Stamping Authority.
# Used if the agent needs to request timestamps itself (future feature).
url = "http://timestamp.digicert.com"

# (Optional) Path to a file containing trusted CA certificates for TSA verification.
# PEM format.
# If omitted, the agent uses the operating system's native trust store.
ca_path = "./tsa_chain.pem"
```

> [!IMPORTANT]
> **Intermediate Certificates for TSA**
>
> Many public TSAs (like DigiCert) sign tokens using an intermediate certificate that is NOT sent with the token. If verification fails with "Signing certificate not found inside token", you must ensure the intermediate certificate is trusted.
>
> **Resolution:**
> 1. Download the intermediate CA certificate (e.g., "DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1").
> 2. Save it to a file (e.g., `tsa_chain.pem`).
> 3. Set `ca_path = "./tsa_chain.pem"` under `[timestamp_authority]` in your `config.toml`.
> 4. Alternatively, install the certificate into your OS system trust store.

### Commands

Define the commands that can be executed by the agent.

```toml
[[commands]]
name = "ping-test"
description = "Pings localhost for connectivity check."
opa_rule = "data.remonse.authz.decision" # The OPA rule to query for authorization
executable = "ping"
args = ["-n", "4", "127.0.0.1"]
```

## Environment Variables

Configuration can also be overridden by environment variables (prefixed with `remonse_` is planned, but currently `config.toml` is the primary source).
