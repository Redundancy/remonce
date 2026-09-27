@echo off
echo Starting Vault in dev mode...
start "Vault Server" "bin\vault.exe" server -dev -dev-root-token-id=root_token
echo Waiting for Vault to start (5 seconds)...
ping 127.0.0.1 -n 6 > nul

set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root_token

echo Initializing Terraform...
"bin\terraform.exe" init

echo Updating Config...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure_local.ps1"

echo Done!
pause
