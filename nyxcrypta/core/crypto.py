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

    def save_keys(self, output_dir, password):
        try:
            os.makedirs(output_dir, exist_ok=True)
            print("Generating RSA key pair...")
            with tqdm(total=1) as pbar:
                private_key, public_key = self.generate_rsa_keypair()
                pbar.update(1)

            # Private key backup (encrypted)
            private_key_path = os.path.join(output_dir, 'private_key.pem')
            print("Saving private key...")
            with tqdm(total=1) as pbar:
                with open(private_key_path, 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                    ))
                pbar.update(1)
            logging.info(f"Private key (encrypted) saved: {private_key_path}")

            # Public key backup
            public_key_path = os.path.join(output_dir, 'public_key.pem')
            print("Saving public key...")
            with tqdm(total=1) as pbar:
                with open(public_key_path, 'wb') as f:
                    f.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                pbar.update(1)
            logging.info(f"Public key saved: {public_key_path}")

            return True
        except Exception as e:
            logging.error(f"Error during key generation: {str(e)}")
            return False

    def encrypt_file(self, input_file, output_file, public_key_file):
        try:
            file_exists(input_file)
            file_exists(public_key_file)

            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            # Get file size for progress bar
            file_size = os.path.getsize(input_file)
            chunks = (file_size + self.chunk_size - 1) // self.chunk_size

            # AES key and nonce generation
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            # AES key encryption with RSA
            print("Encrypting AES key...")
            with tqdm(total=1) as pbar:
                hash_algorithm = self.get_hash_algorithm()
                encrypted_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_algorithm),
                        algorithm=hash_algorithm,
                        label=None
                    )
                )
                pbar.update(1)

            # Data encryption with AES-GCM
            print("Encrypting file...")
            with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                # Write header
                out_file.write(struct.pack('<B', self.version))
                out_file.write(struct.pack('<I', len(encrypted_key)))
                out_file.write(encrypted_key)
                out_file.write(nonce)

                # Encrypt file in chunks with progress bar
                with tqdm(total=chunks, unit='MB') as pbar:
                    while True:
                        chunk = in_file.read(self.chunk_size)
                        if not chunk:
                            break
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                        out_file.write(encrypted_chunk)
                        pbar.update(1)

            logging.info(f"Encrypted file saved: {output_file}")
            return True
        except Exception as e:
            logging.error(f"Error during encryption: {str(e)}")
            return False

    def decrypt_file(self, input_file, output_file, private_key_file, password):
        try:
            file_exists(input_file)
            file_exists(private_key_file)

            # Private key loading with password
            print("Loading private key...")
            with tqdm(total=1) as pbar:
                with open(private_key_file, 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=password.encode()
                    )
                pbar.update(1)

            # Get file size for progress bar
            file_size = os.path.getsize(input_file)
            
            with open(input_file, 'rb') as f:
                version = struct.unpack('<B', f.read(1))[0]
                if version != self.version:
                    raise ValueError(f"Format version not supported: {version}")

                key_size = struct.unpack('<I', f.read(4))[0]
                encrypted_key = f.read(key_size)
                nonce = f.read(12)
                
                # Calculate remaining bytes for progress bar
                remaining_bytes = file_size - (1 + 4 + key_size + 12)
                chunks = (remaining_bytes + self.chunk_size - 1) // self.chunk_size

                # AES key decryption
                print("Decrypting AES key...")
                with tqdm(total=1) as pbar:
                    hash_algorithm = self.get_hash_algorithm()
                    aes_key = private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hash_algorithm),
                            algorithm=hash_algorithm,
                            label=None
                        )
                    )
                    pbar.update(1)

                # Data decryption in chunks
                aesgcm = AESGCM(aes_key)
                print("Decrypting file...")
                with open(output_file, 'wb') as out_file, tqdm(total=chunks, unit='MB') as pbar:
                    while True:
                        chunk = f.read(self.chunk_size)
                        if not chunk:
                            break
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        out_file.write(decrypted_chunk)
                        pbar.update(1)

            logging.info(f"Decrypted file saved: {output_file}")
            return True
        except Exception as e:
            logging.error(f"Error during decryption: {str(e)}")
            return False

    def encrypt_data(self, data, public_key_file):
        try:
            print("Loading public key...")
            with tqdm(total=1) as pbar:
                with open(public_key_file, 'rb') as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
                pbar.update(1)

            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("The loaded public key is not an RSAPublicKey object")

            print("Encrypting data...")
            with tqdm(total=3) as pbar:
                # AES key and nonce generation
                aes_key = AESGCM.generate_key(bit_length=256)
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                pbar.update(1)

                # AES key encryption with RSA
                hash_algorithm = self.get_hash_algorithm()
                encrypted_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_algorithm),
                        algorithm=hash_algorithm,
                        label=None
                    )
                )
                pbar.update(1)

                # Data encryption with AES-GCM
                encrypted_data = aesgcm.encrypt(nonce, data, None)
                pbar.update(1)

            # Return encrypted data in binary form
            result = struct.pack('<B', self.version) + struct.pack('<I', len(encrypted_key)) + encrypted_key + nonce + encrypted_data
            return result.hex()

        except Exception as e:
            logging.error(f"Error during data encryption: {str(e)}")
            return None

    def decrypt_data(self, encrypted_data, private_key_file, password):
        try:
            print("Loading private key...")
            with tqdm(total=1) as pbar:
                with open(private_key_file, 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=password.encode()
                    )
                pbar.update(1)

            print("Decrypting data...")
            with tqdm(total=3) as pbar:
                # Extracting information from the encrypted format
                version = struct.unpack('<B', encrypted_data[:1])[0]
                if version != self.version:
                    raise ValueError(f"Format version not supported: {version}")

                key_size = struct.unpack('<I', encrypted_data[1:5])[0]
                encrypted_key = encrypted_data[5:5 + key_size]
                nonce = encrypted_data[5 + key_size:17 + key_size]
                encrypted_data = encrypted_data[17 + key_size:]
                pbar.update(1)

                # AES key decryption
                hash_algorithm = self.get_hash_algorithm()
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_algorithm),
                        algorithm=hash_algorithm,
                        label=None
                    )
                )
                pbar.update(1)

                # Data decryption
                aesgcm = AESGCM(aes_key)
                data = aesgcm.decrypt(nonce, encrypted_data, None)
                pbar.update(1)

            return data

        except Exception as e:
            logging.error(f"Data decryption error: {str(e)}")
            return None