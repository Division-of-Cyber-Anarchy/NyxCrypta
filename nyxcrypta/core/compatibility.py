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

class KeyConverter:
    """Handles conversion between different key formats."""
    
    @staticmethod
    def convert_private_key(
        key_data: bytes,
        input_format: str,
        output_format: str,
        password: Optional[bytes] = None
    ) -> bytes:
        """Converts a private key from one format to another."""
        try:
            # Load key based on input format
            if input_format == KeyFormat.PEM:
                private_key = serialization.load_pem_private_key(key_data, password=password)
            elif input_format == KeyFormat.DER:
                private_key = serialization.load_der_private_key(key_data, password=password)
            else:
                raise ValueError(f"Unsupported input format: {input_format}")

            # Convert to output format
            if output_format == KeyFormat.PEM:
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
                )
            elif output_format == KeyFormat.DER:
                return private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
                )
            elif output_format == KeyFormat.JSON:
                key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                return json.dumps({
                    "type": "private",
                    "format": "PKCS8",
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
            # Load key based on input format
            if input_format == KeyFormat.PEM:
                public_key = serialization.load_pem_public_key(key_data)
            elif input_format == KeyFormat.DER:
                public_key = serialization.load_der_public_key(key_data)
            elif input_format == KeyFormat.SSH:
                public_key = serialization.load_ssh_public_key(key_data)
            else:
                raise ValueError(f"Unsupported input format: {input_format}")

            # Convert to output format
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