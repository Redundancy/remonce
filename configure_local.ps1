$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Terraform from bin\ if present, otherwise from PATH.
$terraform = if (Test-Path ".\bin\terraform.exe") { ".\bin\terraform.exe" } else { "terraform" }
if (-not (Get-Command $terraform -ErrorAction SilentlyContinue)) {
    throw "terraform not found; install it or put terraform.exe in bin\ (see GETTING_STARTED.md)"
}

# The dev users' password (both webapp and webapp2). Same default as
# start_services.sh; override with APP_USER_PASSWORD.
$appUserPassword = if ($env:APP_USER_PASSWORD) { $env:APP_USER_PASSWORD } else { "password123" }

Write-Host "Initializing Terraform..."
& $terraform init -input=false | Out-Null

Write-Host "Running Terraform Apply..."
& $terraform apply -auto-approve -input=false -var="vault_token=root_token" -var="app_user_password=$appUserPassword"
if ($LASTEXITCODE -ne 0) { throw "terraform apply failed" }

Write-Host "Retrieving Terraform Outputs..."
$clientId = & $terraform output -raw oidc_client_id
$viewerClientId = & $terraform output -raw oidc_viewer_client_id
$issuerUrl = & $terraform output -raw oidc_provider_issuer_url

Write-Host "Found signing Client ID: $clientId"
Write-Host "Found viewer Client ID: $viewerClientId"
Write-Host "Found Issuer URL: $issuerUrl"

$configPath = "config.toml"
$configContent = Get-Content $configPath

# Update Client IDs. Anchored so the signing pattern can't also match
# (and clobber) viewer_client_id.
$configContent = $configContent -replace '^client_id = ".*"', "client_id = ""$clientId"""
$configContent = $configContent -replace '^viewer_client_id = ".*"', "viewer_client_id = ""$viewerClientId"""

# Update Issuer URL
$configContent = $configContent -replace '^issuer_url = ".*"', "issuer_url = ""$issuerUrl"""

# UTF-8 without a byte-order mark, which TOML parsers may reject.
[System.IO.File]::WriteAllLines((Join-Path $PSScriptRoot $configPath), [string[]]$configContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Updated config.toml successfully. Users webapp and webapp2 are ready."
