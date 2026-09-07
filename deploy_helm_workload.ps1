$ErrorActionPreference = 'Stop'

Write-Host "[1/4] Updating kubeconfig for EKS cluster..."
aws eks update-kubeconfig --name $(Get-ChildItem -Path . -Filter "*.tfvars" -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.BaseName }) --region $(aws configure get region)

Write-Host "[2/4] Applying AWS Nitro device plugin..."
kubectl apply -f ./manifests/aws-nitro-enclaves-device-plugin.yaml

Write-Host "[3/4] Waiting for Nitro device plugin to be ready..."
kubectl -n kube-system rollout status daemonset/aws-nitro-enclaves-device-plugin --timeout=180s

Write-Host "[4/4] Installing or upgrading Helm release..."
helm upgrade --install zero-copy-pii-proxy ./charts/zero-copy-pii-proxy -f ./charts/zero-copy-pii-proxy/values.yaml

Write-Host "Helm deployment complete. Waiting on workload health checks is required in the target environment."
