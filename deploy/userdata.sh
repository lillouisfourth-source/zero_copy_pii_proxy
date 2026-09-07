#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 /etc/nitro_enclaves
cat > /etc/nitro_enclaves/allocator.yaml <<'ALLOCATOR_CONFIG'
---
memory_mib: 1024
cpu_count: 2
ALLOCATOR_CONFIG

systemctl enable --now nitro-enclaves-allocator.service
install -m 0644 /opt/host-relay.service /etc/systemd/system/host-relay.service
systemctl daemon-reload
systemctl enable --now host-relay

: <<'KUBELET_CONFIGURATION'
Configure the EKS Kubelet args with --cpu-manager-policy=static.
Reserve host and system CPU capacity for the Nitro Enclave allocator.
KUBELET_CONFIGURATION