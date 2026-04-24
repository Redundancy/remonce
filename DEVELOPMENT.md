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

The UI is built with **HTML** and **Bootstrap 5.3**. Assets are served locally from the `ui/` directory.

-   **Modify HTML**: Edit `ui/*.html` files.
    -   *Note*: The Rust server loads these templates **at runtime** on each request, so you **do not** need to restart `cargo run` to see HTML changes. Just refresh your browser.
-   **Modify CSS**: Edit `ui/style.css`.
    -   You may need to hard-refresh (Ctrl+F5) to clear browser cache.
-   **Modify JS**: Edit `ui/signing.js`.
    -   Refresh browser to see changes.

### Backend Development (`src/`)

The backend is written in **Rust** using `Axum`.

-   **Modify Routes/Logic**: Edit files in `src/`.
-   **Apply Changes**: You **must restart** the application to apply backend changes:
    1.  `Ctrl+C` in the `cargo run` terminal.
    2.  `cargo run` again.

### Policy Development (`policy/`)

Authorization logic is handled by **OPA** using Rego.

-   **Modify Policy**: Edit `policy/authz.rego`.
-   **Apply Changes**: The `start_services.bat` script runs OPA with `--watch policy`. Changes to `.rego` files are **automatically reloaded** by OPA. You do not need to restart anything.

## Authentication Flow (Local)

1.  Visit [http://localhost:8080](http://localhost:8080).
2.  You will be redirected to Vault for login.
    -   **Username**: `webapp`
    -   **Password**: *See `vault_setup.tf` or Terraform output (commonly `password` or similar in dev setups)*.
3.  Upon success, you are redirected back to the `remonce` Commands page.

## Troubleshooting

-   **"No session state found"**: Ensure you are accessing `http://localhost:8080` and NOT `127.0.0.1:8080` to match the configured Redirect URI.
-   **Vault/OPA not reachable**: Check if the `start_services.bat` terminal is still running.
-   **Verification Errors**: Ensure the TSA URL in `config.toml` is reachable (defaults to DigiCert).
