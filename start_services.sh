#!/usr/bin/env bash
# Local development identity provider for Linux and macOS (start_services.bat
# on Windows): starts Vault in dev mode, configures it with Terraform
# (vault_setup.tf), and writes the OIDC client IDs into config.toml.
#
# Vault and Terraform are taken from bin/ if present, otherwise from PATH.
# Leave this running; Ctrl+C stops Vault (dev mode keeps nothing on disk).
set -euo pipefail
cd "$(dirname "$0")"

find_tool() {
    for candidate in "bin/$1" "bin/$1.exe"; do
        if [ -x "$candidate" ]; then echo "$candidate"; return; fi
    done
    if command -v "$1" >/dev/null 2>&1; then command -v "$1"; return; fi
    echo "error: $1 not found; install it or put it in bin/ (see GETTING_STARTED.md)" >&2
    exit 1
}
VAULT=$(find_tool vault)
TERRAFORM=$(find_tool terraform)

# The dev users' password (both webapp and webapp2). Same default as
# configure_local.ps1; override with APP_USER_PASSWORD.
APP_USER_PASSWORD="${APP_USER_PASSWORD:-password123}"

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root_token

echo "Starting Vault in dev mode (log: vault.log)..."
"$VAULT" server -dev -dev-root-token-id="$VAULT_TOKEN" > vault.log 2>&1 &
VAULT_PID=$!
trap 'kill $VAULT_PID 2>/dev/null || true' INT TERM

for _ in $(seq 1 30); do
    if "$VAULT" status >/dev/null 2>&1; then break; fi
    sleep 1
done
if ! "$VAULT" status >/dev/null 2>&1; then
    echo "error: Vault didn't start; see vault.log" >&2
    exit 1
fi
if ! kill -0 "$VAULT_PID" 2>/dev/null; then
    echo "Another Vault is already listening on $VAULT_ADDR; configuring that one."
    VAULT_PID=
fi

echo "Configuring Vault with Terraform..."
"$TERRAFORM" init -input=false >/dev/null
"$TERRAFORM" apply -auto-approve -input=false \
    -var="vault_token=$VAULT_TOKEN" -var="app_user_password=$APP_USER_PASSWORD"

signing_client_id=$("$TERRAFORM" output -raw oidc_signing_client_id)
viewer_client_id=$("$TERRAFORM" output -raw oidc_viewer_client_id)
issuer_url=$("$TERRAFORM" output -raw oidc_provider_issuer_url)

# Anchored, so the patterns can't match each other; the first also accepts
# the older `client_id` name. -i.bak works with both GNU and BSD sed.
sed -i.bak -E \
    -e "s|^(signing_)?client_id = \".*\"|signing_client_id = \"$signing_client_id\"|" \
    -e "s|^viewer_client_id = \".*\"|viewer_client_id = \"$viewer_client_id\"|" \
    -e "s|^issuer_url = \".*\"|issuer_url = \"$issuer_url\"|" \
    config.toml
rm -f config.toml.bak

echo
echo "Updated config.toml: signing client $signing_client_id, viewer client $viewer_client_id."
echo "Users webapp and webapp2 are ready."
if [ -n "$VAULT_PID" ]; then
    echo "Vault is running; leave this open, Ctrl+C to stop it."
    wait "$VAULT_PID"
fi
