#!/usr/bin/env bash
set -euo pipefail

ENCLAVE_ID=""

cleanup() {
    if [ -n "$ENCLAVE_ID" ]; then
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
    fi
    if [ -n "${CONSOLE_PID:-}" ]; then
        kill "$CONSOLE_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

nitro-cli run-enclave \
    --cpu-count 2 \
    --memory 1024 \
    --eif-path /enclave.eif \
    > /tmp/enclave_out.json

ENCLAVE_ID=$(jq -r '.EnclaveID' /tmp/enclave_out.json)

if [ -z "$ENCLAVE_ID" ] || [ "$ENCLAVE_ID" = "null" ]; then
    echo "Fatal: nitro-cli did not return an EnclaveID" >&2
    exit 1
fi

nitro-cli console --enclave-id "$ENCLAVE_ID" > /var/log/enclave.log 2>&1 &
CONSOLE_PID=$!

while nitro-cli describe-enclaves | grep -q "$ENCLAVE_ID"; do
    sleep 5
done

echo "Fatal: enclave $ENCLAVE_ID is no longer running" >&2
exit 1