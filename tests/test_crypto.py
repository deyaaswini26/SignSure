"""Unit tests for cryptographic core (SignSure/app/crypto.py)."""

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest

from app.crypto import (
    generate_rsa_keypair,
    RSAKeyPair,
    sha256_digest,
    sign_message,
    verify_signature,
    CryptoError,
    public_key_fingerprint,
)

def test_keypair_generation_and_serialization():
    kp = generate_rsa_keypair()
    assert isinstance(kp, RSAKeyPair)

    password = b"testpassword"
    priv_pem = kp.serialize_private(password)
    pub_pem = kp.serialize_public()

    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem

    loaded_priv = RSAKeyPair.load_private(priv_pem, password)
    loaded_pub = RSAKeyPair.load_public(pub_pem)
    assert loaded_priv.public_key().public_numbers() == kp.public_key.public_numbers()
    assert loaded_pub.public_numbers() == kp.public_key.public_numbers()

def test_sign_and_verify():
    kp = generate_rsa_keypair()
    message = b"sample message for signing"
    digest = sha256_digest(message)
    signature = sign_message(kp.private_key, digest)
    assert isinstance(signature, bytes)
    assert verify_signature(kp.public_key, digest, signature) is True
    bad_sig = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert verify_signature(kp.public_key, digest, bad_sig) is False

def test_fingerprint_consistency():
    kp = generate_rsa_keypair()
    pub_pem = kp.serialize_public()
    fp1 = public_key_fingerprint(pub_pem)
    fp2 = public_key_fingerprint(pub_pem)
    assert fp1 == fp2
    kp2 = generate_rsa_keypair()
    fp3 = public_key_fingerprint(kp2.serialize_public())
    assert fp3 != fp1

def test_error_on_empty_password():
    kp = generate_rsa_keypair()
    with pytest.raises(CryptoError):
        kp.serialize_private(b"")
