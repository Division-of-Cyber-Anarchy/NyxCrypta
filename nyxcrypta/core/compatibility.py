"""
Compatibility module for NyxCrypta.
Handles key format conversion and data compatibility.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from typing import Union, Tuple, Optional
import base64
import json
import logging

class KeyFormat:
    PEM = "PEM"
    DER = "DER"
    SSH = "SSH"
    JSON = "JSON"

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
    """Loads a public key. The format is detected from the content if not given."""
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


def load_private_key(key_data: bytes, password: Optional[bytes] = None,
                     input_format: Optional[str] = None):
    """Loads a private key. The format is detected from the content if not given."""
    input_format = input_format or detect_format(key_data)
    if input_format == KeyFormat.JSON:
        key_data, input_format = _unwrap_json_key(key_data, "private"), KeyFormat.PEM
    if input_format == KeyFormat.PEM:
        return serialization.load_pem_private_key(key_data, password=password)
    if input_format == KeyFormat.DER:
        return serialization.load_der_private_key(key_data, password=password)
    raise ValueError(f"Unsupported input format: {input_format}")


class KeyConverter:
    """Handles conversion between different key formats."""

    @staticmethod
    def convert_private_key(
        key_data: bytes,
        input_format: str,
        output_format: str,
        password: Optional[bytes] = None
    ) -> bytes:
        """Converts a private key from one format to another.

        The JSON output always embeds an *encrypted* PKCS8 key, so a password
        is mandatory for that format.
        """
        try:
            private_key = load_private_key(key_data, password, input_format)
            encryption = (
                serialization.BestAvailableEncryption(password)
                if password else serialization.NoEncryption()
            )

            if output_format == KeyFormat.PEM:
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
            elif output_format == KeyFormat.DER:
                return private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
            elif output_format == KeyFormat.JSON:
                if not password:
                    raise ValueError(
                        "A password is required to export a private key as JSON "
                        "(the key is always stored encrypted)"
                    )
                key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                )
                return json.dumps({
                    "type": "private",
                    "format": "PKCS8",
                    "encrypted": True,
                    "key": base64.b64encode(key_bytes).decode('utf-8')
                }).encode('utf-8')
            else:
                raise ValueError(f"Unsupported output format: {output_format}")

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

            if output_format == KeyFormat.PEM:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            elif output_format == KeyFormat.DER:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            elif output_format == KeyFormat.SSH:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                )
            elif output_format == KeyFormat.JSON:
                key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return json.dumps({
                    "type": "public",
                    "format": "SubjectPublicKeyInfo",
                    "key": base64.b64encode(key_bytes).decode('utf-8')
                }).encode('utf-8')
            else:
                raise ValueError(f"Unsupported output format: {output_format}")

        except Exception as e:
            logging.error(f"Error during public key conversion: {str(e)}")
            raise

class VersionCompatibility:
    """Handles compatibility between different data format versions."""
    
    @staticmethod
    def convert_data_format(data: bytes, from_version: int, to_version: int) -> bytes:
        """Converts data from one format version to another."""
        if from_version == to_version:
            return data
            
        if from_version == 1 and to_version == 2:
            return VersionCompatibility._convert_v1_to_v2(data)
        else:
            raise ValueError(f"Unsupported conversion: v{from_version} to v{to_version}")
    
    @staticmethod
    def _convert_v1_to_v2(data: bytes) -> bytes:
        """Converts data from v1 to v2 format."""
        try:
            header = data[:16]
            payload = data[16:]
            
            new_header = bytes([2])
            key_size = len(header)
            new_header += key_size.to_bytes(4, byteorder='little')
            new_header += header
            new_header += bytes(12)
            
            return new_header + payload
            
        except Exception as e:
            logging.error(f"Error during v1 to v2 conversion: {str(e)}")
            raise