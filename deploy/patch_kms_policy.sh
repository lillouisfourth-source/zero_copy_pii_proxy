#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MEASUREMENTS="${1:-${SCRIPT_DIR}/../pcr_measurements.json}"
TEMPLATE="${SCRIPT_DIR}/kms_trust_policy.json.tpl"
OUTPUT="${SCRIPT_DIR}/kms_trust_policy.json"

PCR0="$(jq -er '.PCR0 // .verified_pcr0' "${MEASUREMENTS}")"
sed "s/\${pcr0_hash}/${PCR0}/g" "${TEMPLATE}" > "${OUTPUT}"
printf 'Wrote %s using PCR0 %s\n' "${OUTPUT}" "${PCR0}"