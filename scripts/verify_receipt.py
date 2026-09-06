#!/usr/bin/env python3
"""Verify a proxy_audit receipt from a raw SSE transcript.

Install dependencies with:
    python -m pip install blake3 cbor2 cryptography
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import blake3
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DONE_MARKER = b"data: [DONE]"


def decode_bytes(value: str) -> bytes:
    value = value.strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"invalid base64 attestation document: {exc}") from exc
    return raw


def verify_certificate_chain(certificate_der: bytes, cabundle_der: list[bytes], root_path: Path) -> None:
    certificates = [x509.load_der_x509_certificate(certificate_der)]
    certificates.extend(x509.load_der_x509_certificate(value) for value in cabundle_der)
    root = x509.load_der_x509_certificate(root_path.read_bytes())
    certificates.append(root)
    for child, issuer in zip(certificates, certificates[1:]):
        if child.issuer != issuer.subject:
            raise ValueError("attestation certificate issuer chain is inconsistent")
        public_key = issuer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise ValueError("unsupported attestation certificate public-key type")
    if root.subject != root.issuer:
        raise ValueError("AWS attestation root certificate is not self-signed")


def extract_attested_identity(document: bytes, expected_pcr0: str, root_path: Path | None) -> bytes:
    try:
        decoded = cbor2.loads(document)
    except (ValueError, cbor2.CBORDecodeError) as exc:
        raise ValueError(f"attestation document is not valid CBOR: {exc}") from exc

    if isinstance(decoded, dict) and decoded.get("format") == "local-mock-not-nitro":
        pcr0 = decoded.get("pcr0")
        public_key = decoded.get("user_data")
        if pcr0 != expected_pcr0:
            raise ValueError("mock attestation PCR0 does not match expected release hash")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("mock attestation user_data must contain a 32-byte public key")
        return public_key

    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ValueError("attestation document must be a COSE_Sign1 structure")
    payload = decoded[2]
    if not isinstance(payload, bytes):
        raise ValueError("COSE attestation payload is missing")
    try:
        claims = cbor2.loads(payload)
    except (ValueError, cbor2.CBORDecodeError) as exc:
        raise ValueError(f"attestation payload is not valid CBOR: {exc}") from exc
    if not isinstance(claims, dict):
        raise ValueError("attestation payload must be a CBOR map")

    pcrs = claims.get("pcrs", claims.get(4))
    pcr0 = pcrs.get(0) if isinstance(pcrs, dict) else None
    if isinstance(pcr0, bytes):
        pcr0 = pcr0.hex()
    if pcr0 != expected_pcr0:
        raise ValueError("attestation PCR0 does not match expected release hash")

    certificate = claims.get("certificate", claims.get(3))
    cabundle = claims.get("cabundle", claims.get(4))
    if not isinstance(certificate, bytes) or not isinstance(cabundle, list) or not cabundle:
        raise ValueError("attestation certificate chain is missing; AWS PKI validation required")
    if root_path is None:
        raise ValueError("--aws-root-cert is required for AWS Nitro certificate-chain validation")
    verify_certificate_chain(certificate, cabundle, root_path)
    public_key = claims.get("user_data", claims.get(5))
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("attestation user_data must contain the 32-byte Ed25519 public key")
    return public_key


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
    parser.add_argument("--attestation-doc", required=True, help="base64-encoded NSM attestation document")
    parser.add_argument("--expected-pcr0", required=True, help="expected 48-byte PCR0 digest in hexadecimal")
    parser.add_argument("--aws-root-cert", type=Path, help="AWS Nitro root certificate in DER format")
    args = parser.parse_args()

    try:
        public_key = extract_attested_identity(
            decode_bytes(args.attestation_doc), args.expected_pcr0.lower(), args.aws_root_cert
        )
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
