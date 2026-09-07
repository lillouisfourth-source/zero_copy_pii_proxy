#!/usr/bin/env bash
set -euo pipefail

ENCLAVE_ID=""
RELAY_PID=""

require_nitro_device() {
    if [ ! -e /dev/nitro_enclaves ]; then
        echo "Fatal: /dev/nitro_enclaves is unavailable" >&2
        exit 1
    fi
}

wait_for_vsock_listener() {
    local port="$1"
    for _ in $(seq 1 30); do
        if ! kill -0 "$RELAY_PID" 2>/dev/null; then
            echo "Fatal: host relay exited while waiting for VSOCK port $port" >&2
            exit 1
        fi
        if ss -H -l -A vsock 2>/dev/null | awk -v port="$port" '$0 ~ (":" port "([[:space:]]|$)") { found = 1 } END { exit(found ? 0 : 1) }'; then
            return 0
        fi
        sleep 1
    done
    echo "Fatal: host relay did not expose VSOCK port $port" >&2
    exit 1
}

cleanup() {
    if [ -n "$ENCLAVE_ID" ]; then
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
    fi
    if [ -n "${CONSOLE_PID:-}" ]; then
        kill "$CONSOLE_PID" 2>/dev/null || true
    fi
    if [ -n "$RELAY_PID" ]; then
        kill "$RELAY_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

require_nitro_device
/usr/local/bin/host_relay &
RELAY_PID=$!
wait_for_vsock_listener 8000
wait_for_vsock_listener 8001

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