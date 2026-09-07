#!/bin/bash
set -euo pipefail

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_REGION=us-east-1

mkdir -p /var/lib/localstack/mock
KEY_ID=$(awslocal kms create-key \
    --description "local dev symmetric kms key" \
    --key-usage ENCRYPT_DECRYPT \
    --origin AWS_KMS \
    --query KeyMetadata.KeyId \
    --output text)

awslocal kms encrypt \
    --key-id "$KEY_ID" \
    --plaintext 'sk_live_mock_12345' \
    --query CiphertextBlob \
    --output text \
    > /var/lib/localstack/mock/ciphertext.b64
