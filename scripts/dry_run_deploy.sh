#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find_tool() {
  local tool="$1"

  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return 0
  fi

  local candidates=(
    "/usr/local/bin/${tool}"
    "/usr/local/bin/${tool}.exe"
    "/usr/bin/${tool}"
    "/usr/bin/${tool}.exe"
    "/opt/homebrew/bin/${tool}"
    "/opt/homebrew/bin/${tool}.exe"
    "/snap/bin/${tool}"
    "/snap/bin/${tool}.exe"
    "/mnt/c/Program Files/HashiCorp/${tool}/${tool}.exe"
    "/mnt/c/Program Files/HashiCorp/${tool}.exe"
    "/mnt/c/Program Files/Helm/${tool}/${tool}.exe"
    "/mnt/c/Program Files/Helm/${tool}.exe"
    "/mnt/c/ProgramData/chocolatey/bin/${tool}.exe"
    "/c/Program Files/HashiCorp/${tool}/${tool}.exe"
    "/c/Program Files/HashiCorp/${tool}.exe"
    "/c/Program Files/Helm/${tool}/${tool}.exe"
    "/c/Program Files/Helm/${tool}.exe"
    "/c/ProgramData/chocolatey/bin/${tool}.exe"
    "/mnt/c/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe/${tool}.exe"
    "/mnt/c/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe/windows-amd64/${tool}.exe"
    "/c/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe/${tool}.exe"
    "/c/Users/ASUS/AppData/Local/Microsoft/WinGet/Packages/Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe/windows-amd64/${tool}.exe"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v powershell.exe >/dev/null 2>&1; then
    local ps_path
    ps_path="$(powershell.exe -NoProfile -Command \"(Get-Command $tool -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source | Select-Object -First 1) 2>\$null\" 2>/dev/null | tr -d '\r' | head -n 1)"
    if [[ -n "$ps_path" && -e "$ps_path" ]]; then
      printf '%s\n' "$ps_path"
      return 0
    fi
  fi

  return 1
}

TERRAFORM_BIN="${TERRAFORM_BIN:-$(find_tool terraform || true)}"
HELM_BIN="${HELM_BIN:-$(find_tool helm || true)}"

if [[ -z "$TERRAFORM_BIN" ]]; then
  echo "Terraform executable not found in PATH or common install locations." >&2
  exit 1
fi

if [[ -z "$HELM_BIN" ]]; then
  echo "Helm executable not found in PATH or common install locations." >&2
  exit 1
fi

echo "==> Using terraform: $TERRAFORM_BIN"
echo "==> Using helm: $HELM_BIN"

echo "==> Terraform validation"
"$TERRAFORM_BIN" -chdir="$ROOT_DIR/terraform/eks_enclaves" init -backend=false -input=false >/dev/null
"$TERRAFORM_BIN" -chdir="$ROOT_DIR/terraform/eks_enclaves" validate

echo "==> Helm rendering"
"$HELM_BIN" template zero-copy-pii-proxy "$ROOT_DIR/charts/zero-copy-pii-proxy" -f "$ROOT_DIR/deploy/staging-values.yaml"
