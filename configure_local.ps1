$ErrorActionPreference = "Stop"

Write-Host "Running Terraform Apply..."
.\bin\terraform.exe apply -auto-approve -var="vault_token=root_token" -var="app_user_password=password123"

Write-Host "Retrieving Terraform Outputs..."
$clientId = .\bin\terraform.exe output -raw oidc_client_id
$viewerClientId = .\bin\terraform.exe output -raw oidc_viewer_client_id
$issuerUrl = .\bin\terraform.exe output -raw oidc_provider_issuer_url

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
$configContent = $configContent -replace 'issuer_url = ".*"', "issuer_url = ""$issuerUrl"""

Set-Content -Path $configPath -Value $configContent
Write-Host "Updated config.toml successfully."

Write-Host "You can now run 'cargo run' to start the application."
