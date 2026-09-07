#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* ]]; then
  if command -v powershell.exe >/dev/null 2>&1; then
    ROOT_DIR_WIN="$(powershell.exe -NoProfile -Command "[System.IO.Path]::GetFullPath('$ROOT_DIR')" 2>/dev/null | tr -d '\r')"
    TERRAFORM_BIN="${TERRAFORM_BIN:-C:/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe/terraform.exe}"
    HELM_BIN="${HELM_BIN:-C:/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe/windows-amd64/helm.exe}"

    echo "==> Terraform validation"
    powershell.exe -NoProfile -Command "\$ErrorActionPreference='Stop'; Set-Location -Path '$ROOT_DIR_WIN'; & '$TERRAFORM_BIN' -chdir '$ROOT_DIR_WIN\\terraform\\eks_enclaves' init -backend=false -input=false; & '$TERRAFORM_BIN' -chdir '$ROOT_DIR_WIN\\terraform\\eks_enclaves' validate"

    echo "==> Helm rendering"
    powershell.exe -NoProfile -Command "\$ErrorActionPreference='Stop'; Set-Location -Path '$ROOT_DIR_WIN'; & '$HELM_BIN' template zero-copy-pii-proxy '$ROOT_DIR_WIN\\charts\\zero-copy-pii-proxy' -f '$ROOT_DIR_WIN\\deploy\\staging-values.yaml'"
    exit 0
  fi
fi

TERRAFORM_BIN="${TERRAFORM_BIN:-terraform}"
HELM_BIN="${HELM_BIN:-helm}"

if ! command -v "$TERRAFORM_BIN" >/dev/null 2>&1; then
  echo "Terraform executable not found in PATH." >&2
  exit 1
fi

if ! command -v "$HELM_BIN" >/dev/null 2>&1; then
  echo "Helm executable not found in PATH." >&2
  exit 1
fi

echo "==> Terraform validation"
"$TERRAFORM_BIN" -chdir="$ROOT_DIR/terraform/eks_enclaves" init -backend=false -input=false >/dev/null
"$TERRAFORM_BIN" -chdir="$ROOT_DIR/terraform/eks_enclaves" validate

echo "==> Helm rendering"
"$HELM_BIN" template zero-copy-pii-proxy "$ROOT_DIR/charts/zero-copy-pii-proxy" -f "$ROOT_DIR/deploy/staging-values.yaml"
