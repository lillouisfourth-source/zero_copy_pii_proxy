{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccountRootAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAttestedEnclaveDecrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${enclave_role_arn}"
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