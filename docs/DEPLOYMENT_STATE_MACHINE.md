# Deployment State Machine

This document defines the mandatory deployment gate for the Nitro Enclave KMS attestation flow.

## Required sequence

1. GitHub Actions runs the EIF build workflow.
   - `.github/workflows/eif-build.yml` builds the enclave image twice in isolated execution steps.
   - Each build runs `nitro-cli build-enclave` inside an `amazonlinux:2023` container.
   - The workflow verifies that the two PCR0 values are identical.
   - On success, the verified PCR0 value is written to `verified_pcr0.txt` and exposed as the workflow output `verified_pcr0`.

2. GitHub Actions passes the verified PCR0 to Terraform.
   - The workflow must set `TF_VAR_pcr0_hash` from the content of `verified_pcr0.txt`.
   - Terraform receives the exact approved `pcr0_hash` and renders the KMS key policy from `terraform/kms_policy.json.tpl`.

3. Terraform applies the updated KMS policy.
   - The key policy must include root administrative access.
   - The key policy must allow `kms:Decrypt` only for the trusted IRSA principal and only when `kms:RecipientAttestation:ImageSha384` matches the verified PCR0 hash.
   - Terraform must complete successfully before any workload deployment proceeds.

4. GitHub Actions triggers the Kubernetes deployment only after the KMS update succeeds.
   - Helm upgrade/install occurs only after the `TF_VAR_pcr0_hash` attestation gate has been applied to AWS KMS.
   - This ensures the workload is never scheduled with a stale or unknown PCR0 trust value.

## Critical contract

The pod deployment is blocked unless all of the following are true:

- `verified_pcr0.txt` exists and contains the verified PCR0 value.
- Terraform successfully applied the KMS policy with the exact `pcr0_hash`.
- The `proxy_irsa_role_name` is the only principal authorized to call `kms:Decrypt` under the attestation condition.
- The root principal retains administrative access to avoid accidental KMS lockout.

## State diagram

```text
EIF build workflow
  -> verify PCR0 run 1 == run 2
  -> write verified_pcr0.txt
  -> export verified_pcr0 as workflow output
  -> pass TF_VAR_pcr0_hash
  -> terraform apply kms_policy.json.tpl
  -> success
  -> helm upgrade deploy workload
```

## Enforcement rule

No Helm upgrade or pod scheduling may happen before Terraform has successfully updated AWS KMS with the verified PCR0 attestation policy.
