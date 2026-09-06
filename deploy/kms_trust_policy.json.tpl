{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAttestedEnclaveDecrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:role/${enclave_role_name}"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "${pcr0_hash}"
        }
      }
    }
  ]
}