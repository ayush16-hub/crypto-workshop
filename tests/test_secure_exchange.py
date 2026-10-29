import base64, json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from src.sender import create_package
from src.receiver import decrypt_package, verify_package, ExchangeError
from src.package_manager import signed_bytes, canonical_json, parse_package
from src.crypto_utils import PSS

@pytest.fixture
def setup(tmp_path):
    sender=rsa.generate_private_key(public_exponent=65537,key_size=3072); recipient=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    source=tmp_path/"exam.txt"; source.write_text("Fictional Workshop Assessment\nQuestion 1: Explain a made-up protocol.\n",encoding="utf8")
    return tmp_path,sender,recipient,source

def emit(tmp, sender, recipient, src, name="a.secpkg"):
    p=tmp/name; create_package(src,p,sender,recipient.public_key()); return p

def test_authorized_successful_transfer(setup):
    t,s,r,f=setup; p=emit(t,s,r,f); out=decrypt_package(p,t/"out",s.public_key(),r); assert out.read_bytes()==f.read_bytes()
def test_ciphertext_tampering_rejected(setup):
    t,s,r,f=setup; p=emit(t,s,r,f); x=json.loads(p.read_text()); b=bytearray(base64.b64decode(x["ciphertext"])); b[0]^=1; x["ciphertext"]=base64.b64encode(b).decode(); p.write_bytes(canonical_json(x))
    with pytest.raises(ExchangeError): decrypt_package(p,t/"out",s.public_key(),r)
    assert not list((t/"out").glob("*.txt")) if (t/"out").exists() else True
def test_resigned_ciphertext_fails_gcm(setup):
    t,s,r,f=setup; p=emit(t,s,r,f); x=json.loads(p.read_text()); b=bytearray(base64.b64decode(x["ciphertext"])); b[0]^=1; x["ciphertext"]=base64.b64encode(b).decode(); x["signature"]=base64.b64encode(s.sign(signed_bytes(x),PSS,hashes.SHA256())).decode(); p.write_bytes(canonical_json(x))
    with pytest.raises(ExchangeError,match="AES-GCM"): decrypt_package(p,t/"out",s.public_key(),r)
def test_metadata_and_signature_tampering(setup):
    t,s,r,f=setup; p=emit(t,s,r,f); x=json.loads(p.read_text()); x["metadata"]["package_id"]="tampered"; p.write_bytes(canonical_json(x))
    with pytest.raises(ExchangeError,match="signature"): decrypt_package(p,t/"out",s.public_key(),r)
    p=emit(t,s,r,f,"b.secpkg"); x=json.loads(p.read_text()); x["signature"]="A"+x["signature"][1:]; p.write_bytes(canonical_json(x))
    with pytest.raises(ExchangeError): decrypt_package(p,t/"out",s.public_key(),r)
def test_wrong_keys_rejected(setup):
    t,s,r,f=setup; p=emit(t,s,r,f); wrong=rsa.generate_private_key(public_exponent=65537,key_size=3072); wrong_sender=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    with pytest.raises(ExchangeError,match="signature"): verify_package(p,wrong_sender.public_key())
    with pytest.raises(ExchangeError,match="recipient key"): decrypt_package(p,t/"out",s.public_key(),wrong)
def test_fresh_randomness_and_both_decrypt(setup):
    t,s,r,f=setup; a=emit(t,s,r,f,"a.secpkg"); b=emit(t,s,r,f,"b.secpkg"); x=json.loads(a.read_text()); y=json.loads(b.read_text()); assert a.read_bytes()!=b.read_bytes(); assert x["nonce"]!=y["nonce"] and x["encrypted_session_key"]!=y["encrypted_session_key"]
    assert decrypt_package(a,t/"out-a",s.public_key(),r).read_bytes()==f.read_bytes(); assert decrypt_package(b,t/"out-b",s.public_key(),r).read_bytes()==f.read_bytes()
@pytest.mark.parametrize("mutate",[lambda x:x.pop("signature"),lambda x:x.update(nonce="%%%"),lambda x:x["metadata"].update(encryption_algorithm="bad"),lambda x:x.update(authentication_tag="AA==")])
def test_malformed_package(setup,mutate):
    t,s,r,f=setup; p=emit(t,s,r,f); x=json.loads(p.read_text()); mutate(x); p.write_bytes(canonical_json(x))
    with pytest.raises(ValueError): parse_package(p.read_bytes())
