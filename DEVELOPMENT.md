# Local Development Guide

This guide describes how to set up `remonce` locally, iterate on features, and test changes.

## Prerequisites

Ensure you have the following installed and available in `bin/` or your PATH:

- **Rust**: [Install Rust](https://www.rust-lang.org/tools/install)
- **Terraform**: [Install Terraform](https://developer.hashicorp.com/terraform/downloads)
- **Vault**: [Install Vault](https://developer.hashicorp.com/vault/downloads)
- **OPA**: [Install Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#running-opa)

> **Important**: The `start_services.bat` script **requires** these tools to be present in the `bin/` directory of the project root. Please download the executables and place `vault.exe`, `opa.exe`, and `terraform.exe` inside `bin/`.

## Initial Setup

1.  **Clone/Open the Repository** in your terminal.
2.  **Start Background Services**:
    Run the provided helper script to spin up Vault (Dev Mode) and OPA:
    ```powershell
    ./start_services.bat
    ```
    *This script also initializes Terraform to configure Vault with the necessary OIDC clients and policies.*

    Keep this terminal window open.

## Vault Development Configuration

`start_services.bat` configures Vault for local development, which differs from production in two ways.

### 1. Userpass Authentication

Production Vault deployments typically use enterprise auth methods (LDAP, OIDC, SAML) where entities and aliases are created automatically. For local development, `vault_setup.tf` creates a simple userpass backend:

```hcl
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}
```

### 2. Manual Entity and Alias Creation

With userpass, entities and aliases must be created manually (enterprise auth methods create them on first login):

```hcl
resource "vault_identity_entity" "example_user" {
  name = "example-user"
}

resource "vault_identity_entity_alias" "example_user_alias" {
  name           = "example"                              # Username
  mount_accessor = vault_auth_backend.userpass.accessor   # Auth method
  canonical_id   = vault_identity_entity.example_user.id
}
```

> [!TIP]
> For production Vault OIDC configuration, see [docs/idp/VAULT.md](docs/idp/VAULT.md).

## Running the Application

In a **new terminal** window:

1.  **Run the Web Server (UI/Auth)**:
    In one terminal:
    ```powershell
    cargo run -- web
    ```
    This starts the OIDC-enabled web interface on `http://localhost:8080`.

2.  **Run the Execution Agent**:
    In a **second terminal**:
    ```powershell
    cargo run -- agent
    ```
    This starts the agent which listens for execution requests (WebSocket).

## Iteration Workflow

### Frontend Development (`ui/`)

The UI is plain HTML, CSS and JavaScript with no framework, build step or third-party assets. Everything is served from the `ui/` directory, under a strict Content Security Policy (no inline script or styles, no external origins).

-   **Pages**: `ui/layout.html` is the shell (sidebar, top bar); each page is a fragment (`ui/commands.html`, `review.html`, `execute.html`, `monitor.html`, `files.html`) rendered into it.
    -   *Note*: The Rust server loads these templates **at runtime** on each request, so you **do not** need to restart `cargo run` to see HTML changes. Just refresh your browser.
-   **Modify CSS**: Edit `ui/static/remonce.css`.
    -   You may need to hard-refresh (Ctrl+F5) to clear browser cache.
-   **Modify JS**: Edit `ui/static/app.js`. It builds the DOM without `innerHTML`, and must not add inline handlers (the CSP blocks them).
    -   Refresh browser to see changes.

### Backend Development (`src/`)

The backend is written in **Rust** using `Axum`.

-   **Modify Routes/Logic**: Edit files in `src/`.
-   **Apply Changes**: You **must restart** the application to apply backend changes:
    1.  `Ctrl+C` in the `cargo run` terminal.
    2.  `cargo run` again.

### Policy Development (`policy/`)

Authorization logic is handled by **OPA** using Rego.

-   **Modify Policy**: Edit `policy/authz.rego`, the shared helper `policy/lib.rego`, or the per-command requirement documents in `policy/requirements.json`.
-   **Apply Changes**: The `start_services.bat` script runs OPA with `--watch policy`. Changes to `.rego` and `.json` files are **automatically reloaded** by OPA. You do not need to restart anything; agents fetch requirements for each catalog request.
-   **Test**: `bin\opa.exe test policy policy_test -v`. The tests live outside `policy/` so the served policy doesn't include them.

## Authentication Flow (Local)

1.  Visit [http://localhost:8080](http://localhost:8080).
2.  You will be redirected to Vault for login.
    -   **Username**: `webapp` (a second user, `webapp2`, lets you try commands that need two approvals, such as `ping-pair`)
    -   **Password**: the `app_user_password` that `configure_local.ps1` passes to Terraform (both users share it).
3.  Upon success, you are redirected back to the `remonce` Commands page. This login uses the *viewer* client: it lets you browse and identifies you when you execute.
4.  Every signature (Approve, Revoke) sends you back to Vault to log in again: each gets its own login to the *signing* client and a one-time key. Both client IDs are written to `config.toml` by `configure_local.ps1`. To add a second approval, approve as `webapp`, then approve the result again logged in as `webapp2`.

## Troubleshooting

-   **"No session state found"**: Ensure you are accessing `http://localhost:8080` and NOT `127.0.0.1:8080` to match the configured Redirect URI.
-   **Vault/OPA not reachable**: Check if the `start_services.bat` terminal is still running.
-   **Verification Errors**: Ensure the TSA URL in `config.toml` is reachable (defaults to DigiCert).
