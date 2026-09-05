#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MEASUREMENTS="${1:-${SCRIPT_DIR}/../pcr_measurements.json}"
TEMPLATE="${SCRIPT_DIR}/kms_policy_template.json"
OUTPUT="${SCRIPT_DIR}/kms_policy.json"

PCR0="$(jq -er '.PCR0' "${MEASUREMENTS}")"
sed "s/PCR0_HASH_PLACEHOLDER/${PCR0}/g" "${TEMPLATE}" > "${OUTPUT}"
printf 'Wrote %s using PCR0 %s\n' "${OUTPUT}" "${PCR0}"