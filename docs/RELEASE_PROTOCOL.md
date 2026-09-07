# Release Protocol

## 1. Environment Bootstrap

Before any production promotion, establish the AWS control plane, EKS cluster, and enclave prerequisites that the service depends on. This includes the target VPC, node group, IAM role, KMS key, and the approved Nitro attestation policy. The environment must be provisioned and confirmed healthy before the software release is marked as deployable.

## 2. Release Tagging

After CI has passed and the code is verified as green, create the signed or annotated release tag for the deployment candidate. This tag represents the exact artifact set intended for promotion and ensures the environment can be reproduced from a known-good point in source history.

## 3. KMS Binding

Bind the enclave to the production KMS key policy using the approved PCR0 hash and the role that is allowed to request attested decrypts. This is the trust boundary that authorizes the enclave to access encrypted secrets at runtime. The KMS policy must be fixed to the expected attestation identity before traffic is admitted.

## 4. Live Attestation

Deploy the tagged release into the attested environment and verify the runtime attestation document, enclave identity, and key policy match the expected AWS state. Once the service reports healthy and the attestation checks pass, the deployment transitions from a staged environment to a live, trusted AWS deployment.

This four-step sequence keeps promotion deterministic: bootstrap the environment, tag the release, bind the trusted KMS key, and only then go live with attestation-driven validation.
