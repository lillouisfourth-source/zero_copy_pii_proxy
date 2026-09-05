$ErrorActionPreference = 'Stop'

$PCR0_HASH = Read-Host "Enter the PCR0_HASH from the successful GitHub Actions determinism gate"
if ([string]::IsNullOrWhiteSpace($PCR0_HASH)) {
    throw "PCR0_HASH cannot be empty."
}

$env:TF_VAR_pcr0_hash = $PCR0_HASH
Write-Host "TF_VAR_pcr0_hash exported: $($env:TF_VAR_pcr0_hash)"

Push-Location "$PSScriptRoot/terraform/eks_enclaves"
try {
    Write-Host "[1/3] Running terraform init..."
    terraform init

    Write-Host "[2/3] Running terraform apply..."
    terraform apply -auto-approve
}
finally {
    Pop-Location
}

Write-Host "Terraform apply complete. KMS policy should now reflect the approved PCR0 hash."
