#!/usr/bin/env bash
set -euo pipefail

BUILD_OUTPUT="build_output.json"
PCR_OUTPUT="pcr_measurements.json"
BUILD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "local-$(date +%s)")
IMAGE_TAG="pii-proxy-enclave:${BUILD_HASH}"

docker build -f Dockerfile.enclave -t "${IMAGE_TAG}" .

nitro-cli build-enclave \
    --docker-uri "${IMAGE_TAG}" \
    --output-file enclave.eif \
    > "${BUILD_OUTPUT}"

jq -r '{PCR0: .Measurements.PCR0, PCR1: .Measurements.PCR1, PCR2: .Measurements.PCR2}' \
    "${BUILD_OUTPUT}" > "${PCR_OUTPUT}"

printf '%s\n' "========================================"
printf 'Nitro Enclave PCR0: %s\n' "$(jq -r '.PCR0' "${PCR_OUTPUT}")"
printf '%s\n' "========================================"
