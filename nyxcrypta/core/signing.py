"""
Ed25519 detached signatures for NyxCrypta.

A signature proves that a file (or a byte string) was produced by the holder of
an Ed25519 private key and has not been modified since. It is independent from
encryption: RSA encryption with a public key does not authenticate the sender,
so sign the plaintext if the recipient must be able to verify who produced it.

What is signed
--------------
The file is hashed with SHA-512 in a streaming fashion (so size is not an issue)
and Ed25519 signs `CONTEXT || digest`. The context is a domain separator: a
NyxCrypta signature can never be mistaken for a signature made by another
protocol with the same key.

Signature file (JSON, UTF-8)
----------------------------
    {
      "version": 1,
      "algorithm": "Ed25519",
      "hash": "SHA-512",
      "key_fingerprint": "<hex SHA-256 of the public key, SubjectPublicKeyInfo DER>",
      "signature": "<base64>"
    }

`key_fingerprint` only helps to tell a "wrong key" from a "modified file" in
error messages; the cryptographic check never relies on it.
"""
import base64
import hashlib
import json
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SIGNATURE_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_HASH = "SHA-512"
CONTEXT = b"NyxCrypta-signature-v1\x00"
READ_CHUNK = 1024 * 1024


def hash_file(path: str) -> bytes:
    """SHA-512 digest of a file, read in chunks."""
    digest = hashlib.sha512()
    with open(path, 'rb') as f:
        while chunk := f.read(READ_CHUNK):
            digest.update(chunk)
    return digest.digest()


def hash_data(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def key_fingerprint(public_key) -> str:
    """Hex SHA-256 fingerprint of a public key (SubjectPublicKeyInfo DER)."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def require_ed25519_private(key) -> ed25519.Ed25519PrivateKey:
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(
            f"An Ed25519 signing key is required (got {type(key).__name__.replace('_', '')}). "
            "Generate one with 'signkeygen'."
        )
    return key


def require_ed25519_public(key) -> ed25519.Ed25519PublicKey:
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(
            f"An Ed25519 verification key is required (got {type(key).__name__.replace('_', '')})."
        )
    return key


def create_signature(private_key: ed25519.Ed25519PrivateKey, digest: bytes) -> bytes:
    """Signs a SHA-512 digest and returns the serialized signature (JSON bytes)."""
    private_key = require_ed25519_private(private_key)
    signature = private_key.sign(CONTEXT + digest)
    return json.dumps({
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "hash": SIGNATURE_HASH,
        "key_fingerprint": key_fingerprint(private_key.public_key()),
        "signature": base64.b64encode(signature).decode('ascii'),
    }, indent=2).encode('utf-8') + b"\n"


def parse_signature(data: bytes) -> dict:
    """Parses and validates the structure of a signature file."""
    try:
        obj = json.loads(data)
        if obj["version"] != SIGNATURE_VERSION:
            raise ValueError(f"Unsupported signature version: {obj['version']}")
        if obj["algorithm"] != SIGNATURE_ALGORITHM or obj["hash"] != SIGNATURE_HASH:
            raise ValueError("Unsupported signature algorithm")
        raw = base64.b64decode(obj["signature"], validate=True)
        if len(raw) != 64:
            raise ValueError("Invalid signature length")
        return {"signature": raw, "key_fingerprint": obj.get("key_fingerprint")}
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid signature file: {e}") from e


def check_signature(public_key: ed25519.Ed25519PublicKey, digest: bytes,
                    signature_data: bytes) -> bool:
    """Verifies a serialized signature against a digest. Returns False on any failure."""
    try:
        public_key = require_ed25519_public(public_key)
        parsed = parse_signature(signature_data)

        expected = key_fingerprint(public_key)
        claimed = parsed["key_fingerprint"]
        if claimed and claimed != expected:
            logging.error(
                "Signature was made with a different key "
                f"(signature key {claimed[:16]}…, provided key {expected[:16]}…)"
            )
            return False

        public_key.verify(parsed["signature"], CONTEXT + digest)
        return True
    except InvalidSignature:
        logging.error("Invalid signature: the content was modified or the signature is not genuine")
        return False
    except ValueError as e:
        logging.error(f"Signature verification failed: {str(e)}")
        return False
