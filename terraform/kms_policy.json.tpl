{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRootAdministrativeAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAttestedIRSADecrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:role/${proxy_irsa_role_name}"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:RecipientAttestation:ImageSha384": "${pcr0_hash}"
        }
      }
    }
  ]
}
