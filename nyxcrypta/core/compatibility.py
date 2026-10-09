"""
Compatibility module for NyxCrypta.
Handles key serialization, loading and format conversion.

Private keys are protected with the NyxCrypta key container (Argon2id +
AES-256-GCM, see `security.py`). Standard password-protected PKCS8 keys written
by NyxCrypta 3.1.0 and earlier (or by OpenSSL) are still loaded transparently.
"""
from cryptography.hazmat.primitives import serialization
from typing import Optional
import base64
import json
import logging

from .security import (
    Argon2Params,
    armor,
    dearmor,
    is_armored,
    is_protected_blob,
    protect_private_key,
    unprotect_private_key,
)


class KeyFormat:
    PEM = "PEM"
    DER = "DER"
    SSH = "SSH"
    JSON = "JSON"


PRIVATE_JSON_FORMAT = "NYXK-Argon2id-AES256GCM"


def detect_format(data: bytes) -> str:
    """Guess the format of a serialized key from its content."""
    head = data.lstrip()[:16]
    if head.startswith(b"{"):
        return KeyFormat.JSON
    if head.startswith(b"-----BEGIN"):
        return KeyFormat.PEM
    if head.startswith(b"ssh-"):
        return KeyFormat.SSH
    return KeyFormat.DER


def detect_key_type(key_data: bytes, input_format: Optional[str] = None) -> str:
    """Returns 'public' or 'private' by inspecting the key content (not its path)."""
    input_format = input_format or detect_format(key_data)
    if input_format == KeyFormat.SSH:
        return "public"
    if input_format == KeyFormat.JSON:
        try:
            key_type = json.loads(key_data)["type"]
        except (KeyError, TypeError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid JSON key file: {e}") from e
        if key_type not in ("public", "private"):
            raise ValueError(f"Unknown key type in JSON file: {key_type}")
        return key_type
    if input_format == KeyFormat.PEM:
        if b"PRIVATE KEY" in key_data:
            return "private"
        if b"PUBLIC KEY" in key_data:
            return "public"
        raise ValueError("Unrecognized PEM content")
    if is_protected_blob(key_data):
        return "private"
    try:  # DER has no marker: a public key parses without a password
        serialization.load_der_public_key(key_data)
        return "public"
    except ValueError:
        return "private"


def _unwrap_json_key(key_data: bytes, expected_type: str) -> bytes:
    """Extracts the PEM payload embedded in a NyxCrypta JSON key."""
    try:
        obj = json.loads(key_data)
        if obj["type"] != expected_type:
            raise ValueError(f"Expected a {expected_type} key, got '{obj['type']}'")
        return base64.b64decode(obj["key"])
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid JSON key file: {e}") from e


def load_public_key(key_data: bytes, input_format: Optional[str] = None):
    """Loads a public key (RSA or Ed25519). The format is detected from the content if not given."""
    input_format = input_format or detect_format(key_data)
    if input_format == KeyFormat.JSON:
        key_data, input_format = _unwrap_json_key(key_data, "public"), KeyFormat.PEM
    if input_format == KeyFormat.PEM:
        return serialization.load_pem_public_key(key_data)
    if input_format == KeyFormat.DER:
        return serialization.load_der_public_key(key_data)
    if input_format == KeyFormat.SSH:
        return serialization.load_ssh_public_key(key_data)
    raise ValueError(f"Unsupported input format: {input_format}")


def _load_protected(blob: bytes, password: Optional[bytes]):
    pkcs8_der = unprotect_private_key(blob, password or b"")
    return serialization.load_der_private_key(pkcs8_der, password=None)


def load_private_key(key_data: bytes, password: Optional[bytes] = None,
                     input_format: Optional[str] = None):
    """Loads a private key (RSA or Ed25519). The format is detected from the content if not given.

    Handles NyxCrypta key containers (Argon2id) as well as standard PKCS8 keys,
    encrypted or not.
    """
    input_format = input_format or detect_format(key_data)
    if input_format == KeyFormat.JSON:
        key_data, input_format = _unwrap_json_key(key_data, "private"), KeyFormat.PEM
    if input_format == KeyFormat.PEM:
        if is_armored(key_data):
            return _load_protected(dearmor(key_data), password)
        return serialization.load_pem_private_key(key_data, password=password)
    if input_format == KeyFormat.DER:
        if is_protected_blob(key_data):
            return _load_protected(key_data, password)
        return serialization.load_der_private_key(key_data, password=password)
    raise ValueError(f"Unsupported input format: {input_format}")


def serialize_private_key(private_key, key_format: str, password: Optional[bytes],
                          params: Optional[Argon2Params] = None) -> bytes:
    """Serializes a private key.

    With a password the key is protected by the Argon2id key container (PEM
    armor, raw binary for DER, or embedded in JSON). Without a password, PEM and
    DER produce an unencrypted PKCS8 key; JSON always requires a password.
    """
    if key_format not in (KeyFormat.PEM, KeyFormat.DER, KeyFormat.JSON):
        raise ValueError(f"Unsupported output format: {key_format}")

    pkcs8_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    if not password:
        if key_format == KeyFormat.JSON:
            raise ValueError(
                "A password is required to export a private key as JSON "
                "(the key is always stored encrypted)"
            )
        if key_format == KeyFormat.DER:
            return pkcs8_der
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    blob = protect_private_key(pkcs8_der, password, params)
    if key_format == KeyFormat.DER:
        return blob
    armored = armor(blob)
    if key_format == KeyFormat.PEM:
        return armored
    return json.dumps({
        "type": "private",
        "format": PRIVATE_JSON_FORMAT,
        "encrypted": True,
        "key": base64.b64encode(armored).decode('utf-8')
    }).encode('utf-8')


def serialize_public_key(public_key, key_format: str) -> bytes:
    """Serializes a public key as PEM, DER, OpenSSH or JSON."""
    if key_format == KeyFormat.PEM:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    if key_format == KeyFormat.DER:
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    if key_format == KeyFormat.SSH:
        return public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
    if key_format == KeyFormat.JSON:
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return json.dumps({
            "type": "public",
            "format": "SubjectPublicKeyInfo",
            "key": base64.b64encode(key_bytes).decode('utf-8')
        }).encode('utf-8')
    raise ValueError(f"Unsupported output format: {key_format}")


class KeyConverter:
    """Handles conversion between different key formats."""

    @staticmethod
    def convert_private_key(
        key_data: bytes,
        input_format: str,
        output_format: str,
        password: Optional[bytes] = None,
        params: Optional[Argon2Params] = None
    ) -> bytes:
        """Converts a private key from one format to another.

        With a password, the output is always protected with the Argon2id key
        container, so converting a key to its own format re-encrypts a legacy
        PKCS8 key with Argon2id. The JSON output requires a password.
        """
        try:
            private_key = load_private_key(key_data, password, input_format)
            return serialize_private_key(private_key, output_format, password, params)
        except Exception as e:
            logging.error(f"Error during private key conversion: {str(e)}")
            raise

    @staticmethod
    def convert_public_key(
        key_data: bytes,
        input_format: str,
        output_format: str
    ) -> bytes:
        """Converts a public key from one format to another."""
        try:
            public_key = load_public_key(key_data, input_format)
            return serialize_public_key(public_key, output_format)
        except Exception as e:
            logging.error(f"Error during public key conversion: {str(e)}")
            raise
