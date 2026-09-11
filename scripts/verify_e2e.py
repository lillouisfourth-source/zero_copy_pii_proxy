#!/usr/bin/env python3
"""Exercise the proxy and verify redaction, BLAKE3, and Ed25519 end to end."""

# Dependencies: python -m pip install blake3 cbor2 cryptography

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import urllib.request
from urllib.parse import urlencode
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_receipt import canonical_receipt_digest, decode_bytes, extract_attested_identity

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--attestation-url", required=True)
    parser.add_argument("--expected-pcr0", required=True)
    args = parser.parse_args()

    nonce = secrets.token_hex(32)
    attestation_url = f"{args.attestation_url}?{urlencode({'nonce': nonce})}"
    with urllib.request.urlopen(attestation_url, timeout=30) as attestation_response:
        attestation_document = decode_bytes(attestation_response.read().decode("ascii"))
    public_key = extract_attested_identity(attestation_document, args.expected_pcr0.lower(), None)

    body = json.dumps({
        "model": "ci-proof",
        "messages": [{"role": "user", "content": "safe password"}],
        "stream": True,
    }).encode()
    request = urllib.request.Request(
        args.url,
        data=body,
        headers={
            "Authorization": f"Bearer {args.api_key}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        transcript = bytearray()
        while True:
            chunk = response.read(257)
            if not chunk:
                break
            transcript.extend(chunk)

    raw = bytes(transcript)
    if b"password" in raw:
        raise AssertionError("PII was not redacted")
    marker = b"data: [DONE]"
    done_start = raw.find(marker)
    if done_start < 0:
        raise AssertionError("fragmented SSE response has no DONE marker")
    audit_marker = b"\nevent: proxy_audit\n"
    audit_start = raw.find(audit_marker)
    if audit_start < 0 or audit_start > done_start:
        raise AssertionError("proxy_audit event missing or ordered after DONE")

    audit_data_start = raw.find(b"data:", audit_start)
    audit_data_end = raw.find(b"\n\n", audit_data_start)
    if audit_data_start < 0 or audit_data_end < 0:
        raise AssertionError("malformed proxy_audit event")
    audit_payload = raw[audit_data_start + len(b"data:"):audit_data_end].strip()
    audit_text = audit_payload.decode("utf-8")
    audit = json.loads(audit_text)
    receipt = audit.get("receipt")
    if not isinstance(receipt, dict):
        raise AssertionError("receipt must be a JSON object")
    for field in ("request_id", "tenant_id", "upstream_url", "request_hash", "payload_hash", "policy_digest", "pcr0", "tuple_digest", "timestamp"):
        if field not in receipt:
            raise AssertionError(f"receipt missing required field: {field}")
    for field in ("request_id", "tenant_id", "upstream_url", "request_hash", "payload_hash", "policy_digest", "pcr0", "tuple_digest"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise AssertionError(f"receipt field must be a non-empty string: {field}")
    if not isinstance(receipt["timestamp"], int) or receipt["timestamp"] < 0:
        raise AssertionError("receipt timestamp must be a non-negative integer")
    if receipt["request_hash"] != blake3.blake3(body).hexdigest():
        raise AssertionError("request_hash does not match the request body")
    if not receipt["upstream_url"]:
        raise AssertionError("upstream_url must be non-empty")
    if len(receipt["request_hash"]) != 64 or len(receipt["payload_hash"]) != 64 or len(receipt["policy_digest"]) != 64 or len(receipt["tuple_digest"]) != 64:
        raise AssertionError("receipt hashes must be 32-byte hexadecimal BLAKE3 digests")
    if len(receipt["pcr0"]) != 96:
        raise AssertionError("receipt pcr0 must be a 48-byte hexadecimal digest")
    for field in ("request_hash", "payload_hash", "policy_digest", "pcr0", "tuple_digest"):
        try:
            bytes.fromhex(receipt[field])
        except ValueError as error:
            raise AssertionError(f"receipt field is not hexadecimal: {field}") from error

    signature = base64.b64decode(audit["signature"], validate=True)
    computed = blake3.blake3(raw[:audit_start]).hexdigest()
    declared_hash = receipt.get("payload_hash")
    if computed != declared_hash:
        raise AssertionError(f"BLAKE3 mismatch: computed {computed}, declared {declared_hash}")

    tuple_digest = canonical_receipt_digest(receipt)
    if receipt["tuple_digest"] != tuple_digest.hex():
        raise AssertionError("receipt tuple_digest does not match canonical tuple")
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, tuple_digest)
    print(
        "verified redaction, fragmented DONE, canonical receipt fields, "
        f"BLAKE3 {declared_hash}, and Ed25519 signature"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())