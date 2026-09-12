#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# 1. Trigger the Remote Deterministic Build
gh workflow run enclave-release.yml --ref main
gh run watch "$(gh run list --workflow=enclave-release.yml -L 1 --json databaseId -q '.[0].databaseId')"
gh run download -n pcr0-artifact
export PCR0="$(tr -d '\r\n' < verified_pcr0.txt)"

# 2. The Hardware Chasm (Terraform)
cd terraform/eks_enclaves
terraform init
terraform apply -auto-approve \
  -var="pcr0_hash=$PCR0" \
  -var="region=$AWS_REGION" \
  -var="account_id=$AWS_ACCOUNT_ID" \
  -var="enclave_role_arn=$ENCLAVE_ROLE_ARN"
aws eks update-kubeconfig --region "$AWS_REGION" --name "$(terraform output -raw cluster_name)"

# 3. Live EKS Deployment (Helm)
cd "$ROOT_DIR"
helm upgrade --install zero-copy-pii-proxy ./charts/zero-copy-pii-proxy \
  --set enclave.enabled=true \
  --set secrets.authTokens="$PROXY_AUTH_TOKEN" \
  --wait
export PROXY_IP="$(kubectl get svc zero-copy-pii-proxy -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"

# 4. Live Hardware PKI Verification
python ./scripts/verify_e2e.py --target "http://$PROXY_IP:3000" --expected-pcr0 "$PCR0"

# 5. Finalize and Commit
chmod +x ./scripts/ignition.sh
git add scripts/ignition.sh
git commit -m "chore(deploy): implement push-button live ignition script for zero-trust physical provisioning"
git push origin main
