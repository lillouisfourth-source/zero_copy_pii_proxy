#!/usr/bin/env python3
"""Exercise the proxy and verify redaction, BLAKE3, and Ed25519 end to end."""

# Dependencies: python -m pip install blake3 cbor2 cryptography

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_receipt import decode_bytes, extract_attested_identity

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--attestation-url", required=True)
    parser.add_argument("--expected-pcr0", required=True)
    args = parser.parse_args()

    with urllib.request.urlopen(args.attestation_url, timeout=30) as attestation_response:
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
    for field in ("request_id", "tenant_id", "payload_hash", "policy_digest", "timestamp"):
        if field not in receipt:
            raise AssertionError(f"receipt missing required field: {field}")
    for field in ("request_id", "tenant_id", "payload_hash", "policy_digest"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise AssertionError(f"receipt field must be a non-empty string: {field}")
    if not isinstance(receipt["timestamp"], int) or receipt["timestamp"] < 0:
        raise AssertionError("receipt timestamp must be a non-negative integer")
    if len(receipt["payload_hash"]) != 64 or len(receipt["policy_digest"]) != 64:
        raise AssertionError("receipt hashes must be 32-byte hexadecimal BLAKE3 digests")
    for field in ("payload_hash", "policy_digest"):
        try:
            bytes.fromhex(receipt[field])
        except ValueError as error:
            raise AssertionError(f"receipt field is not hexadecimal: {field}") from error

    receipt_key = '"receipt"'
    receipt_key_start = audit_text.find(receipt_key)
    if receipt_key_start < 0:
        raise AssertionError("audit event has no receipt field")
    receipt_value_start = audit_text.find(":", receipt_key_start + len(receipt_key)) + 1
    while receipt_value_start < len(audit_text) and audit_text[receipt_value_start].isspace():
        receipt_value_start += 1
    receipt_value_end = json.JSONDecoder().raw_decode(audit_text, receipt_value_start)[1]
    receipt_json = audit_text[receipt_value_start:receipt_value_end].encode("utf-8")
    signature = base64.b64decode(audit["signature"], validate=True)
    computed = blake3.blake3(raw[:audit_start]).hexdigest()
    declared_hash = receipt.get("payload_hash")
    if computed != declared_hash:
        raise AssertionError(f"BLAKE3 mismatch: computed {computed}, declared {declared_hash}")

    Ed25519PublicKey.from_public_bytes(public_key).verify(
        signature, receipt_json
    )
    print(
        "verified redaction, fragmented DONE, canonical receipt fields, "
        f"BLAKE3 {declared_hash}, and Ed25519 signature"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())