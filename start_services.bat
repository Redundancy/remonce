@echo off
rem Local development identity provider for Windows (start_services.sh on
rem Linux and macOS): starts Vault in dev mode, configures it with Terraform
rem (vault_setup.tf), and writes the OIDC client IDs into config.toml.
rem Vault and Terraform are taken from bin\ if present, otherwise from PATH.
cd /d "%~dp0"

set VAULT=vault
if exist "bin\vault.exe" set VAULT=bin\vault.exe
where "%VAULT%" >nul 2>nul || if not exist "%VAULT%" (
    echo error: vault not found; install it or put vault.exe in bin\ ^(see GETTING_STARTED.md^)
    exit /b 1
)

echo Starting Vault in dev mode...
start "Vault Server" "%VAULT%" server -dev -dev-root-token-id=root_token
echo Waiting for Vault to start (5 seconds)...
ping 127.0.0.1 -n 6 > nul

set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=root_token

echo Configuring Vault with Terraform...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure_local.ps1"
if errorlevel 1 exit /b 1

echo Done! Vault runs in its own window; close it to stop Vault.
pause
