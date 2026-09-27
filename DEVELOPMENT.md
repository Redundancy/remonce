# Local Development Guide

This guide describes how to set up `remonce` locally, iterate on features, and test changes.

## Prerequisites

Ensure you have the following installed and available in `bin/` or your PATH:

- **Rust**: [Install Rust](https://www.rust-lang.org/tools/install)
- **Terraform**: [Install Terraform](https://developer.hashicorp.com/terraform/downloads)
- **Vault**: [Install Vault](https://developer.hashicorp.com/vault/downloads)
- **OPA** (optional): only to try the remote-OPA mode or run `opa test`. Policy is evaluated inside remonce by default.

> The start scripts use Vault and Terraform from the project's `bin/` folder if they're there, otherwise from your `PATH`. See [GETTING_STARTED.md](GETTING_STARTED.md#1-prerequisites) for ways to install them.

## Initial Setup

1.  **Clone/Open the Repository** in your terminal.
2.  **Start Background Services**:
    Run the helper script to spin up Vault (dev mode):
    ```sh
    ./start_services.sh      # Linux and macOS
    .\start_services.bat     # Windows
    ```
    *This script also initializes Terraform to configure Vault with the necessary OIDC clients and policies, and writes their IDs into `config.toml`.*

    Keep Vault running (the terminal on Linux and macOS, the window it opens on Windows).

## Vault Development Configuration

The start script configures Vault for local development, which differs from production in two ways.

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

The UI is plain HTML, CSS and JavaScript with no framework, build step or third-party assets. The files in `ui/` are compiled into the binary (`src/ui_assets.rs`), so a signer needs nothing beside it. They're served under a strict Content Security Policy (no inline script or styles, no external origins).

-   **Pages**: `ui/layout.html` is the shell (sidebar, top bar); each page is a fragment (`ui/commands.html`, `review.html`, `execute.html`, `monitor.html`, `files.html`) rendered into it.
-   **Modify CSS**: Edit `ui/static/remonce.css`.
-   **Modify JS**: Edit `ui/static/app.js`. It builds the DOM without `innerHTML`, and must not add inline handlers (the CSP blocks them).
-   **See changes**: because the UI is embedded, restart `cargo run -- web` (it rebuilds) and refresh. Static files are sent with an ETag and `Cache-Control: no-cache`, so a plain refresh picks them up. A new page needs an entry in `ui_assets::PAGES`, a new static file one in `ASSETS`.

### Backend Development (`src/`)

The backend is written in **Rust** using `Axum`.

-   **Modify Routes/Logic**: Edit files in `src/`.
-   **Apply Changes**: You **must restart** the application to apply backend changes:
    1.  `Ctrl+C` in the `cargo run` terminal.
    2.  `cargo run` again.

### Policy Development (`policy/`)

Authorization is Rego policy, evaluated inside the agent (embedded [Regorus](https://github.com/microsoft/regorus)) unless `opa_url` points at an OPA server.

-   **Modify Policy**: Edit `policy/authz.rego`, the shared helper `policy/lib.rego`, or the per-command requirement documents in `policy/requirements.json`.
-   **Apply Changes**: The agent notices changed `.rego`, `.json` and `.yaml` files on its next decision. You do not need to restart anything.
-   **Test**: `cargo test` runs `policy_test/` on the embedded engine. With OPA installed, `bin\opa.exe test policy policy_test -v` runs them on OPA; `opa run --server policy` plus `REMONCE_TEST_OPA_URL=http://127.0.0.1:8181 cargo test policy` checks that both engines agree. The tests live outside `policy/` so they aren't loaded as policy.

## Authentication Flow (Local)

1.  Visit [http://localhost:8080](http://localhost:8080).
2.  You will be redirected to Vault for login.
    -   **Username**: `webapp` (a second user, `webapp2`, lets you try commands that need two approvals, such as `ping-pair`)
    -   **Password**: the `app_user_password` that `configure_local.ps1` passes to Terraform (both users share it).
3.  Upon success, you are redirected back to the `remonce` Commands page. This login uses the *viewer* client: it lets you browse and identifies you when you execute.
4.  Every signature (Approve, Revoke) sends you back to Vault to log in again: each gets its own login to the *signing* client and a one-time key. Both client IDs are written to `config.toml` by `configure_local.ps1`. To add a second approval, approve as `webapp`, then approve the result again logged in as `webapp2`.

## Troubleshooting

-   **"No session state found"**: Ensure you are accessing `http://localhost:8080` and NOT `127.0.0.1:8080` to match the configured Redirect URI.
-   **Vault not reachable**: Check that Vault is still running (the `start_services` terminal or window).
-   **Verification Errors**: Ensure the TSA URL in `config.toml` is reachable (defaults to DigiCert).

## CI and releases

GitHub Actions builds and tests every push to `main` and every pull request on Linux and Windows (`.github/workflows/ci.yml`), including the Rego policy tests.

To publish a release (`.github/workflows/release.yml`):

1.  Set the new version in `Cargo.toml` (it stays below 1.0 for now: `0.x.y`), run `cargo build` so `Cargo.lock` follows, and commit.
2.  Tag that commit with the same version and push the tag:
    ```sh
    git tag v0.2.0
    git push origin v0.2.0
    ```

The workflow refuses a tag that doesn't match `Cargo.toml`, then builds a static Linux binary (`x86_64-unknown-linux-musl`) and a Windows one (`x86_64-pc-windows-msvc`), packages each with `scripts/package.sh`, and publishes them as a GitHub pre-release with SHA-256 checksums. The UI is inside the binary; each archive adds a sample `config.toml`, `policy/`, the local identity-provider scripts and the docs, so [GETTING_STARTED.md](GETTING_STARTED.md) works from it.

To build a package locally: `cargo build --release --locked --bin remonce --target <target>`, then `scripts/package.sh <version> <target>`; it lands in `dist/`.

