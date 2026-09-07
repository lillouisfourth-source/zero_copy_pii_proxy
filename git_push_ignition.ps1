$ErrorActionPreference = 'Stop'

Write-Host "[1/3] Staging repository changes..."
git add -A

Write-Host "[2/3] Creating commit..."
$commitMessage = "feat: finalize deterministic EIF pipeline and KMS state machine"
git commit -m $commitMessage

Write-Host "[3/3] Pushing to origin main..."
git push origin main

Write-Host "Git push complete. GitHub Actions determinism gate is now running."
