"""Receiver-side signature verification and authenticated decryption."""
from __future__ import annotations
import base64, os, re, tempfile
from pathlib import Path
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .crypto_utils import OAEP, PSS
from .package_manager import parse_package, signed_bytes, aad_bytes, b64decode

class ExchangeError(ValueError): pass

def verify_package(package_path: Path, sender_public) -> dict:
    package = parse_package(package_path.read_bytes())
    try: sender_public.verify(b64decode(package["signature"], "signature"), signed_bytes(package), PSS, hashes.SHA256())
    except InvalidSignature: raise ExchangeError("Sender signature verification failed") from None
    return package

def decrypt_package(package_path: Path, destination: Path, sender_public, recipient_private) -> Path:
    package = verify_package(package_path, sender_public)
    try: key = recipient_private.decrypt(b64decode(package["encrypted_session_key"], "session key"), OAEP)
    except Exception: raise ExchangeError("Could not unwrap session key; recipient key may be incorrect") from None
    if len(key) != 32: raise ExchangeError("Invalid session key length")
    try:
        plaintext = AESGCM(key).decrypt(b64decode(package["nonce"], "nonce"), b64decode(package["ciphertext"], "ciphertext") + b64decode(package["authentication_tag"], "tag"), aad_bytes(package["metadata"]))
    except InvalidTag: raise ExchangeError("AES-GCM authentication failed") from None
    name = package["metadata"]["original_filename"]
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name).strip("._") or "recovered_exam.txt"
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / safe
    if output.exists(): raise ExchangeError("Output file already exists; choose another destination")
    fd, tempname = tempfile.mkstemp(prefix=".decrypt-", suffix=".tmp", dir=destination)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(plaintext); stream.flush(); os.fsync(stream.fileno())
        os.link(tempname, output)
    except FileExistsError: raise ExchangeError("Output file already exists; choose another destination") from None
    finally:
        try: os.unlink(tempname)
        except FileNotFoundError: pass
    return output
