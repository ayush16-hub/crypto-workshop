"""RSA key generation, encrypted private-key storage and loading."""
from pathlib import Path
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 3072

def generate_keypair(private_path: Path, public_path: Path, password: bytes) -> None:
    if not password: raise ValueError("Private-key password cannot be empty")
    private_path.parent.mkdir(parents=True, exist_ok=True); public_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    try: os.chmod(private_path, 0o600)
    except OSError: pass

def load_private(path: Path, password: bytes):
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072: raise ValueError("Expected RSA private key of at least 3072 bits")
    return key

def load_public(path: Path):
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072: raise ValueError("Expected RSA public key of at least 3072 bits")
    return key
