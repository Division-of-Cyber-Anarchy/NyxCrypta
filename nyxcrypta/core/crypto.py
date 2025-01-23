import os
import struct
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
from tqdm import tqdm
from .security import SecurityLevel
from .utils import file_exists
from .compatibility import KeyFormat

class NyxCrypta:
    def __init__(self, security_level=SecurityLevel.STANDARD):
        self.security_level = security_level
        self.ph = PasswordHasher(time_cost=2, memory_cost=2 ** 16, parallelism=1)
        self.version = 2
        self.chunk_size = 1024 * 1024  # 1MB chunks for progress bar

    def generate_rsa_keypair(self):
        key_sizes = {
            SecurityLevel.STANDARD: 2048,
            SecurityLevel.HIGH: 3072,
            SecurityLevel.PARANOID: 4096
        }
        key_size = key_sizes[self.security_level]

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    def get_hash_algorithm(self):
        return hashes.SHA256()

    def save_keys(self, output_dir, password, key_format=KeyFormat.PEM):
        try:
            os.makedirs(output_dir, exist_ok=True)
            print("Generating RSA key pair...")
            with tqdm(total=1) as pbar:
                private_key, public_key = self.generate_rsa_keypair()
                pbar.update(1)

            # Private key backup (encrypted)
            private_key_path = os.path.join(output_dir, f'private_key.{key_format.lower()}')
            print("Saving private key...")
            with tqdm(total=1) as pbar:
                if key_format == KeyFormat.PEM:
                    encoding = serialization.Encoding.PEM
                elif key_format == KeyFormat.DER:
                    encoding = serialization.Encoding.DER
                else:
                    raise ValueError(f"Unsupported key format for private key: {key_format}")

                with open(private_key_path, 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=encoding,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                    ))
                pbar.update(1)
            logging.info(f"Private key (encrypted) saved: {private_key_path}")

            # Public key backup
            public_key_path = os.path.join(output_dir, f'public_key.{key_format.lower()}')
            print("Saving public key...")
            with tqdm(total=1) as pbar:
                if key_format == KeyFormat.PEM:
                    encoding = serialization.Encoding.PEM
                    pub_format = serialization.PublicFormat.SubjectPublicKeyInfo
                elif key_format == KeyFormat.DER:
                    encoding = serialization.Encoding.DER
                    pub_format = serialization.PublicFormat.SubjectPublicKeyInfo
                elif key_format == KeyFormat.SSH:
                    encoding = serialization.Encoding.OpenSSH
                    pub_format = serialization.PublicFormat.OpenSSH
                else:
                    raise ValueError(f"Unsupported key format for public key: {key_format}")

                with open(public_key_path, 'wb') as f:
                    f.write(public_key.public_bytes(
                        encoding=encoding,
                        format=pub_format
                    ))
                pbar.update(1)
            logging.info(f"Public key saved: {public_key_path}")

            return True
        except Exception as e:
            logging.error(f"Error during key generation: {str(e)}")
            return False