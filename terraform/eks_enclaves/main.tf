terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "region" {
  type        = string
  description = "AWS region for the EKS node group."
}

variable "name" {
  type        = string
  description = "Name prefix for the launch template."
  default     = "pii-proxy-enclave"
}

variable "ami_id" {
  type        = string
  description = "EKS-optimized Amazon Linux 2023 AMI ID."
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name passed to the bootstrap script."
}

variable "instance_profile_name" {
  type        = string
  description = "IAM instance profile attached to EKS worker nodes."
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups for the EKS worker nodes."
}

variable "subnet_id" {
  type        = string
  description = "Subnet used by the node group."
}

variable "pcr0_hash" {
  type        = string
  description = "Approved Nitro Enclave PCR0 hash passed by CI."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{96}$", var.pcr0_hash))
    error_message = "pcr0_hash must be exactly 96 hexadecimal characters."
  }
}

variable "kms_key_id" {
  type        = string
  description = "KMS key ID or ARN whose key policy authorizes the attested enclave."
}

variable "enclave_role_name" {
  type        = string
  description = "IAM role name allowed to request attested KMS decrypts."
}

data "aws_caller_identity" "current" {}

locals {
  kms_trust_policy = templatefile("${path.module}/../../deploy/kms_trust_policy.json.tpl", {
    account_id        = data.aws_caller_identity.current.account_id
    enclave_role_name = var.enclave_role_name
    pcr0_hash         = var.pcr0_hash
  })
}

resource "aws_kms_key_policy" "enclave_trust" {
  key_id = var.kms_key_id
  policy = local.kms_trust_policy
}

resource "aws_launch_template" "eks_enclave" {
  name_prefix            = "${var.name}-"
  image_id               = var.ami_id
  instance_type          = "m6i.xlarge"
  update_default_version = true

  enclave_options {
    enabled = true
  }

  iam_instance_profile {
    name = var.instance_profile_name
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups              = var.security_group_ids
    subnet_id                    = var.subnet_id
  }

  user_data = base64encode(<<-EOT
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="==NITRO_ENCLAVE_NODE=="

    --==NITRO_ENCLAVE_NODE==
    Content-Type: text/x-shellscript; charset="us-ascii"

    #!/bin/bash
    set -euo pipefail

    REGION="${var.region}"
    CLUSTER_NAME="${var.cluster_name}"

    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel aws-nitro-enclaves-allocator aws-nitro-enclaves-vsock-proxy

    install -d -m 0755 /etc/nitro_enclaves
    cat >/etc/nitro_enclaves/allocator.yaml <<'ALLOCATOR_CONFIG'
    ---
    memory_mib: 1024
    cpu_count: 2
    ALLOCATOR_CONFIG

    cat >/etc/nitro_enclaves/vsock-proxy.yaml <<VSOCK_PROXY_CONFIG
    ---
    vsock_port: 8000
    host: kms.$${REGION}.amazonaws.com
    port: 443
    VSOCK_PROXY_CONFIG

    systemctl enable --now nitro-enclaves-allocator
    systemctl enable --now nitro-enclaves-vsock-proxy

    /etc/eks/bootstrap.sh "$${CLUSTER_NAME}" \
      --kubelet-extra-args '--node-labels=nitro-enclaves=true --cpu-manager-policy=static --kube-reserved=cpu=1,memory=1Gi --system-reserved=cpu=1,memory=1Gi --kubelet-reserved=hugepages-2Mi=100Mi'

    --==NITRO_ENCLAVE_NODE==--
  EOT
  )
}