$ErrorActionPreference = "Stop"

Write-Host "Running Terraform Apply..."
.\bin\terraform.exe apply -auto-approve -var="vault_token=root_token" -var="app_user_password=password123"

Write-Host "Retrieving Terraform Outputs..."
$clientId = .\bin\terraform.exe output -raw oidc_client_id
$issuerUrl = .\bin\terraform.exe output -raw oidc_provider_issuer_url

Write-Host "Found Client ID: $clientId"
Write-Host "Found Issuer URL: $issuerUrl"

$configPath = "config.toml"
$configContent = Get-Content $configPath

# Update Client ID
$configContent = $configContent -replace 'client_id = ".*"', "client_id = ""$clientId"""

# Update Issuer URL
$configContent = $configContent -replace 'issuer_url = ".*"', "issuer_url = ""$issuerUrl"""

Set-Content -Path $configPath -Value $configContent
Write-Host "Updated config.toml successfully."

Write-Host "You can now run 'cargo run' to start the application."
