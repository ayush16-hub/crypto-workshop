"""Strict JSON package parsing and canonical serialization."""
from __future__ import annotations
import base64, binascii, json
from typing import Any

MAX_PACKAGE_BYTES = 25 * 1024 * 1024
TOP_FIELDS = {"metadata", "encrypted_session_key", "nonce", "ciphertext", "authentication_tag", "signature"}
META_FIELDS = {"protocol_version", "package_id", "created_at_utc", "original_filename", "encryption_algorithm", "key_wrapping_algorithm", "signature_algorithm"}

class PackageError(ValueError):
    """Package is malformed or violates the supported format."""

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def signed_bytes(package: dict[str, Any]) -> bytes:
    return canonical_json({k: v for k, v in package.items() if k != "signature"})

def aad_bytes(metadata: dict[str, Any]) -> bytes:
    return canonical_json(metadata)

def b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str): raise PackageError(f"Invalid {field} encoding")
    try: return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError): raise PackageError(f"Invalid {field} encoding") from None

def parse_package(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_PACKAGE_BYTES: raise PackageError("Package exceeds size limit")
    try: obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise PackageError("Malformed JSON package") from None
    if not isinstance(obj, dict) or set(obj) != TOP_FIELDS: raise PackageError("Missing or unexpected package fields")
    meta = obj["metadata"]
    if not isinstance(meta, dict) or set(meta) != META_FIELDS: raise PackageError("Missing or unexpected metadata fields")
    if any(not isinstance(v, str) for v in meta.values()): raise PackageError("Invalid metadata value type")
    if meta["protocol_version"] != "1.0": raise PackageError("Unsupported protocol version")
    algorithms = {"encryption_algorithm":"AES-256-GCM", "key_wrapping_algorithm":"RSA-OAEP-SHA256", "signature_algorithm":"RSA-PSS-SHA256"}
    if any(meta[k] != v for k,v in algorithms.items()): raise PackageError("Unsupported algorithm")
    for field in ("encrypted_session_key", "nonce", "ciphertext", "authentication_tag", "signature"):
        b64decode(obj[field], field)
    if len(b64decode(obj["nonce"], "nonce")) != 12: raise PackageError("Invalid nonce length")
    if len(b64decode(obj["authentication_tag"], "tag")) != 16: raise PackageError("Invalid authentication tag length")
    if not obj["ciphertext"] and len(b64decode(obj["ciphertext"], "ciphertext")) != 0: raise PackageError("Invalid ciphertext")
    return obj
