"""Sender-side package creation."""
from __future__ import annotations
import base64, os, uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto_utils import OAEP, PSS
from .package_manager import aad_bytes, signed_bytes, canonical_json

MAX_INPUT_BYTES = 20 * 1024 * 1024
def create_package(input_path: Path, output_path: Path, sender_private, recipient_public) -> None:
    data = input_path.read_bytes()
    if len(data) > MAX_INPUT_BYTES: raise ValueError("Input exceeds 20 MiB limit")
    key, nonce = os.urandom(32), os.urandom(12)
    meta = {"protocol_version":"1.0", "package_id":str(uuid.uuid4()), "created_at_utc":datetime.now(timezone.utc).isoformat(), "original_filename":input_path.name, "encryption_algorithm":"AES-256-GCM", "key_wrapping_algorithm":"RSA-OAEP-SHA256", "signature_algorithm":"RSA-PSS-SHA256"}
    combined = AESGCM(key).encrypt(nonce, data, aad_bytes(meta))
    package = {"metadata":meta, "encrypted_session_key":base64.b64encode(recipient_public.encrypt(key, OAEP)).decode("ascii"), "nonce":base64.b64encode(nonce).decode("ascii"), "ciphertext":base64.b64encode(combined[:-16]).decode("ascii"), "authentication_tag":base64.b64encode(combined[-16:]).decode("ascii")}
    package["signature"] = base64.b64encode(sender_private.sign(signed_bytes(package), PSS, __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256())).decode("ascii")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json(package))
