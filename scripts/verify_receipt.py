#!/usr/bin/env python3
"""Verify a proxy_audit receipt from a raw SSE transcript.

Install dependencies with:
    python -m pip install blake3 cryptography
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DONE_MARKER = b"data: [DONE]"


def decode_public_key(value: str) -> bytes:
    value = value.strip()
    try:
        raw = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"invalid public key encoding: {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"public key must decode to 32 bytes, got {len(raw)}")
    return raw


def hash_transcript(path: Path) -> tuple[str, dict[str, object], bytes, str]:
    """Hash SSE bytes before DONE while extracting the injected audit event."""
    hasher = blake3.blake3()
    receipt = None
    receipt_json = None
    signature = None
    expecting_audit_data = False
    expecting_audit_blank = False
    pending_line = None

    with path.open("rb") as stream:
        for line in stream:
            if expecting_audit_data:
                if not line.startswith(b"data:"):
                    raise ValueError("proxy_audit event is missing its data line")
                try:
                    data = json.loads(line[len(b"data:"):].strip())
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid proxy_audit JSON: {exc}") from exc
                receipt = data.get("receipt")
                signature = data.get("signature")
                if not isinstance(receipt, dict) or not isinstance(signature, str):
                    raise ValueError("proxy_audit payload missing receipt or signature")
                for field in ("request_id", "tenant_id", "payload_hash", "policy_digest", "timestamp"):
                    if field not in receipt:
                        raise ValueError(f"receipt missing required field: {field}")
                for field in ("request_id", "tenant_id", "payload_hash", "policy_digest"):
                    if not isinstance(receipt[field], str) or not receipt[field]:
                        raise ValueError(f"receipt field must be a non-empty string: {field}")
                if not isinstance(receipt["timestamp"], int) or receipt["timestamp"] < 0:
                    raise ValueError("receipt timestamp must be a non-negative integer")
                for field in ("payload_hash", "policy_digest"):
                    value = receipt[field]
                    if len(value) != 64:
                        raise ValueError(f"receipt field must be a 32-byte hexadecimal digest: {field}")
                    try:
                        bytes.fromhex(value)
                    except ValueError as exc:
                        raise ValueError(f"receipt field is not hexadecimal: {field}") from exc
                receipt_key = b'"receipt"'
                receipt_key_start = line[len(b"data:"):].find(receipt_key)
                if receipt_key_start < 0:
                    raise ValueError("audit event has no receipt field")
                receipt_value_start = line.find(b":", len(b"data:") + receipt_key_start + len(receipt_key)) + 1
                while receipt_value_start < len(line) and line[receipt_value_start:receipt_value_start + 1].isspace():
                    receipt_value_start += 1
                receipt_value_end = json.JSONDecoder().raw_decode(
                    line.decode("utf-8"), receipt_value_start
                )[1]
                receipt_json = line[receipt_value_start:receipt_value_end].rstrip(b"\r\n")
                expecting_audit_data = False
                expecting_audit_blank = True
                continue

            if expecting_audit_blank:
                if line not in (b"\n", b"\r\n"):
                    raise ValueError("proxy_audit event is missing its terminating blank line")
                expecting_audit_blank = False
                continue

            is_audit_event = line.rstrip(b"\r\n") == b"event: proxy_audit"
            if pending_line is not None:
                if not is_audit_event:
                    hasher.update(pending_line)
                pending_line = None

            if is_audit_event:
                expecting_audit_data = True
                continue

            marker_start = line.find(DONE_MARKER)
            if marker_start >= 0:
                if pending_line is not None:
                    hasher.update(pending_line)
                    pending_line = None
                hasher.update(line[:marker_start])
                break

            pending_line = line

    if expecting_audit_data or expecting_audit_blank:
        raise ValueError("proxy_audit event is missing its data line")
    if receipt is None or receipt_json is None or signature is None:
        raise ValueError("no proxy_audit event found before [DONE]")
    return hasher.hexdigest(), receipt, receipt_json, signature


def verify_signature(receipt_json: bytes, signature_b64: str, public_key: bytes) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except base64.binascii.Error as exc:
        raise ValueError(f"signature is not valid base64: {exc}") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, receipt_json
        )
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature verification failed") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", type=Path, help="raw SSE transcript file")
    parser.add_argument("--public-key", required=True, help="32-byte Ed25519 public key in hex or base64")
    args = parser.parse_args()

    try:
        public_key = decode_public_key(args.public_key)
        computed, receipt, receipt_json, signature = hash_transcript(args.transcript)
        declared_hash = receipt["payload_hash"]
        if computed != declared_hash:
            raise ValueError(f"BLAKE3 mismatch: computed {computed}, transcript declares {declared_hash}")
        verify_signature(receipt_json, signature, public_key)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"verified receipt payload hash {receipt['payload_hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
