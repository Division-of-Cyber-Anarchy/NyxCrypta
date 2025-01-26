import os
import struct
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
from tqdm import tqdm
from .security import SecurityLevel
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
            if key_format != KeyFormat.SSH:  # SSH format is only for public keys
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

    def encrypt_file(self, input_file, output_file, public_key_path):
        """Encrypt a file using RSA public key"""
        try:
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Generate a random AES key
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Write header
            with open(output_file, 'wb') as f:
                f.write(struct.pack('<B', self.version))  # Version
                f.write(struct.pack('<I', len(encrypted_key)))  # Key length
                f.write(encrypted_key)  # Encrypted AES key
                f.write(nonce)  # Nonce

                # Process file in chunks
                with open(input_file, 'rb') as inf:
                    while chunk := inf.read(self.chunk_size):
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                        f.write(encrypted_chunk)

            return True
        except Exception as e:
            logging.error(f"Error during file encryption: {str(e)}")
            return False

    def decrypt_file(self, input_file, output_file, private_key_path, password):
        """Decrypt a file using RSA private key"""
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode()
                )

            with open(input_file, 'rb') as f:
                # Read header
                version = struct.unpack('<B', f.read(1))[0]
                if version != self.version:
                    raise ValueError(f"Unsupported version: {version}")

                key_length = struct.unpack('<I', f.read(4))[0]
                encrypted_key = f.read(key_length)
                nonce = f.read(12)

                # Decrypt AES key
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                aesgcm = AESGCM(aes_key)

                # Process file in chunks
                with open(output_file, 'wb') as outf:
                    while chunk := f.read(self.chunk_size):
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        outf.write(decrypted_chunk)

            return True
        except Exception as e:
            logging.error(f"Error during file decryption: {str(e)}")
            return False

    def encrypt_data(self, data, public_key_path):
        """Encrypt raw data using RSA public key"""
        try:
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Generate a random AES key
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Encrypt data with AES
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Format: version(1) + key_length(4) + encrypted_key + nonce(12) + encrypted_data
            result = bytearray()
            result.extend(struct.pack('<B', self.version))
            result.extend(struct.pack('<I', len(encrypted_key)))
            result.extend(encrypted_key)
            result.extend(nonce)
            result.extend(encrypted_data)

            return result.hex()
        except Exception as e:
            logging.error(f"Error during data encryption: {str(e)}")
            return None

    def decrypt_data(self, encrypted_data, private_key_path, password):
        """Decrypt raw data using RSA private key"""
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode()
                )

            # Read header
            data = encrypted_data
            version = struct.unpack('<B', data[:1])[0]
            if version != self.version:
                raise ValueError(f"Unsupported version: {version}")

            pos = 1
            key_length = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            encrypted_key = data[pos:pos+key_length]
            pos += key_length
            nonce = data[pos:pos+12]
            pos += 12
            encrypted_content = data[pos:]

            # Decrypt AES key
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            aesgcm = AESGCM(aes_key)

            # Decrypt data
            return aesgcm.decrypt(nonce, encrypted_content, None)
        except Exception as e:
            logging.error(f"Error during data decryption: {str(e)}")
            return None