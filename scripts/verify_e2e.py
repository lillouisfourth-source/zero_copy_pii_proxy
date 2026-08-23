#!/usr/bin/env python3
"""Exercise the proxy and verify redaction, BLAKE3, and Ed25519 end to end."""

# Dependencies: python -m pip install blake3 cryptography

from __future__ import annotations

import argparse
import base64
import json
import urllib.request

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def public_key_bytes(value: str) -> bytes:
    raw = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args()

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
    audit = json.loads(raw[audit_data_start + len(b"data:"):audit_data_end].strip())
    receipt = audit["receipt"]
    signature = base64.b64decode(audit["signature"], validate=True)
    computed = blake3.blake3(raw[:audit_start]).hexdigest()
    if computed != receipt:
        raise AssertionError(f"BLAKE3 mismatch: computed {computed}, declared {receipt}")

    Ed25519PublicKey.from_public_bytes(public_key_bytes(args.public_key)).verify(
        signature, receipt.encode()
    )
    print(f"verified redaction, fragmented DONE, BLAKE3 {receipt}, and Ed25519 signature")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())