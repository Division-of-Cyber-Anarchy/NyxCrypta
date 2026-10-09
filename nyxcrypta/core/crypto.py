import os
import struct
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm
from . import signing
from .security import SecurityLevel, params_for_level
from .compatibility import (
    KeyFormat, load_public_key, load_private_key, serialize_private_key, serialize_public_key
)

# Container format versions
#   v2 (legacy): a single AES-GCM nonce reused for every chunk, no AAD.
#                Decryption is still supported so existing files stay readable.
#   v3 (current): unique nonce per chunk, header + chunk index + "final" flag
#                 authenticated through the GCM additional data (AAD).
VERSION_LEGACY = 2
VERSION = 3

TAG_SIZE = 16               # AES-GCM authentication tag
NONCE_SIZE = 12             # AES-GCM nonce
NONCE_PREFIX_SIZE = 8       # random per-file prefix; 4 bytes left for the chunk counter
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_WRAPPED_KEY_SIZE = 4096  # RSA-16384 would still fit


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )


class NyxCrypta:
    def __init__(self, security_level=SecurityLevel.STANDARD):
        self.security_level = security_level
        self.version = VERSION
        self.chunk_size = 1024 * 1024  # 1MB chunks

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

    # ------------------------------------------------------------------ keys

    def save_keys(self, output_dir, password, key_format=KeyFormat.PEM):
        """Generates and saves an RSA key pair (PEM, DER, SSH or JSON).

        The private key is always saved protected by the Argon2id key container
        (cost depends on the security level). SSH is a public-key-only format:
        the public key is written as OpenSSH and the private key as PEM.
        """
        try:
            print("Generating RSA key pair...")
            with tqdm(total=1) as pbar:
                private_key, public_key = self.generate_rsa_keypair()
                pbar.update(1)
            return self._save_keypair(output_dir, private_key, public_key, password,
                                      key_format, "private_key", "public_key")
        except Exception as e:
            logging.error(f"Error during key generation: {str(e)}")
            return False

    def save_signing_keys(self, output_dir, password, key_format=KeyFormat.PEM):
        """Generates and saves an Ed25519 signing key pair.

        Files: signing_private_key.<fmt> (protected with Argon2id) and
        signing_public_key.<fmt>. As for RSA keys, SSH writes an OpenSSH public
        key and a PEM private key. The security level only sets the Argon2id cost.
        """
        try:
            print("Generating Ed25519 signing key pair...")
            with tqdm(total=1) as pbar:
                private_key = ed25519.Ed25519PrivateKey.generate()
                pbar.update(1)
            return self._save_keypair(output_dir, private_key, private_key.public_key(), password,
                                      key_format, "signing_private_key", "signing_public_key")
        except Exception as e:
            logging.error(f"Error during signing key generation: {str(e)}")
            return False

    def _save_keypair(self, output_dir, private_key, public_key, password, key_format,
                      private_name, public_name):
        os.makedirs(output_dir, exist_ok=True)

        private_format = KeyFormat.PEM if key_format == KeyFormat.SSH else key_format
        private_data = serialize_private_key(
            private_key, private_format, password.encode(), params_for_level(self.security_level))
        public_data = serialize_public_key(public_key, key_format)

        private_key_path = os.path.join(output_dir, f'{private_name}.{private_format.lower()}')
        print("Saving private key...")
        with tqdm(total=1) as pbar:
            with open(private_key_path, 'wb') as f:
                f.write(private_data)
            pbar.update(1)
        logging.info(f"Private key (encrypted) saved: {private_key_path}")

        public_key_path = os.path.join(output_dir, f'{public_name}.{key_format.lower()}')
        print("Saving public key...")
        with tqdm(total=1) as pbar:
            with open(public_key_path, 'wb') as f:
                f.write(public_data)
            pbar.update(1)
        logging.info(f"Public key saved: {public_key_path}")
        return True

    @staticmethod
    def _load_public(path, key_format=None):
        """key_format=None -> detected from the file content."""
        with open(path, 'rb') as f:
            return load_public_key(f.read(), key_format)

    @staticmethod
    def _load_private(path, password, key_format=None):
        with open(path, 'rb') as f:
            return load_private_key(f.read(), password.encode(), key_format)

    @classmethod
    def _load_rsa_public(cls, path, key_format=None):
        key = cls._load_public(path, key_format)
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError(f"An RSA public key is required for encryption (got {type(key).__name__})")
        return key

    @classmethod
    def _load_rsa_private(cls, path, password, key_format=None):
        key = cls._load_private(path, password, key_format)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"An RSA private key is required for decryption (got {type(key).__name__})")
        return key

    # ------------------------------------------------------------ primitives

    @staticmethod
    def _chunk_nonce(prefix, index):
        return prefix + struct.pack('<I', index)

    @staticmethod
    def _chunk_aad(header, index, is_final):
        # Binds the chunk to the header, its position and the end-of-stream flag:
        # reordering, duplicating or truncating chunks makes authentication fail.
        return header + struct.pack('<IB', index, 1 if is_final else 0)

    # ------------------------------------------------------------- file mode

    def encrypt_file(self, input_file, output_file, public_key_path, key_format=None):
        """Encrypt a file using RSA public key (format v3, chunked AES-256-GCM)"""
        partial = output_file + ".part"
        try:
            public_key = self._load_rsa_public(public_key_path, key_format)

            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
            encrypted_key = public_key.encrypt(aes_key, _oaep())

            # Authenticated header: version | key_len | wrapped key | nonce prefix | chunk size
            header = (
                struct.pack('<BI', self.version, len(encrypted_key))
                + encrypted_key
                + nonce_prefix
                + struct.pack('<I', self.chunk_size)
            )

            with open(partial, 'wb') as f, open(input_file, 'rb') as inf:
                f.write(header)

                chunk = inf.read(self.chunk_size)
                index = 0
                while True:
                    # Look ahead so the last chunk can be flagged as final.
                    # An empty file produces one empty final chunk (tag only).
                    next_chunk = inf.read(self.chunk_size)
                    is_final = not next_chunk
                    if index >= 2 ** 32:
                        raise ValueError("File too large for the chunk counter")
                    f.write(aesgcm.encrypt(
                        self._chunk_nonce(nonce_prefix, index),
                        chunk,
                        self._chunk_aad(header, index, is_final)
                    ))
                    if is_final:
                        break
                    chunk = next_chunk
                    index += 1

            os.replace(partial, output_file)
            return True
        except Exception as e:
            logging.error(f"Error during file encryption: {str(e)}")
            return False
        finally:
            if os.path.exists(partial):
                os.remove(partial)

    def decrypt_file(self, input_file, output_file, private_key_path, password, key_format=None):
        """Decrypt a file using RSA private key (supports formats v3 and legacy v2)"""
        partial = output_file + ".part"
        try:
            private_key = self._load_rsa_private(private_key_path, password, key_format)

            with open(input_file, 'rb') as f, open(partial, 'wb') as outf:
                version_byte = f.read(1)
                if len(version_byte) != 1:
                    raise ValueError("Truncated file")
                version = version_byte[0]
                if version not in (VERSION, VERSION_LEGACY):
                    raise ValueError(f"Unsupported version: {version}")

                raw_len = f.read(4)
                if len(raw_len) != 4:
                    raise ValueError("Truncated header")
                key_length = struct.unpack('<I', raw_len)[0]
                if not 0 < key_length <= MAX_WRAPPED_KEY_SIZE:
                    raise ValueError("Invalid header")
                encrypted_key = f.read(key_length)
                if len(encrypted_key) != key_length:
                    raise ValueError("Truncated header")

                aesgcm = AESGCM(private_key.decrypt(encrypted_key, _oaep()))

                if version == VERSION_LEGACY:
                    self._decrypt_stream_legacy(f, outf, aesgcm, self.chunk_size)
                else:
                    self._decrypt_stream_v3(f, outf, aesgcm, version_byte + raw_len + encrypted_key)

            os.replace(partial, output_file)
            return True
        except Exception as e:
            logging.error(f"Error during file decryption: {str(e)}")
            return False
        finally:
            # Never leave unauthenticated / partial plaintext behind
            if os.path.exists(partial):
                os.remove(partial)

    def _decrypt_stream_v3(self, f, outf, aesgcm, header_start):
        nonce_prefix = f.read(NONCE_PREFIX_SIZE)
        raw_chunk_size = f.read(4)
        if len(nonce_prefix) != NONCE_PREFIX_SIZE or len(raw_chunk_size) != 4:
            raise ValueError("Truncated header")
        chunk_size = struct.unpack('<I', raw_chunk_size)[0]
        if not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError("Invalid chunk size")
        header = header_start + nonce_prefix + raw_chunk_size

        block_size = chunk_size + TAG_SIZE  # ciphertext = plaintext chunk + GCM tag
        current = f.read(block_size)
        if len(current) < TAG_SIZE:
            raise ValueError("Truncated file")
        index = 0
        while True:
            next_block = f.read(block_size)
            is_final = not next_block
            outf.write(aesgcm.decrypt(
                self._chunk_nonce(nonce_prefix, index),
                current,
                self._chunk_aad(header, index, is_final)
            ))
            if is_final:
                break
            current = next_block
            index += 1

    @staticmethod
    def _decrypt_stream_legacy(f, outf, aesgcm, chunk_size):
        """v2 files: one nonce reused for all chunks, no AAD, no truncation protection."""
        logging.warning(
            "Legacy v2 file: it was encrypted with a reused nonce and offers no "
            "truncation protection. Re-encrypt it with the current version."
        )
        nonce = f.read(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise ValueError("Truncated header")
        block_size = chunk_size + TAG_SIZE
        while block := f.read(block_size):
            outf.write(aesgcm.decrypt(nonce, block, None))

    # ------------------------------------------------------------- data mode

    def encrypt_data(self, data, public_key_path, key_format=None):
        """Encrypt raw data using RSA public key. Returns a hex string."""
        try:
            public_key = self._load_rsa_public(public_key_path, key_format)

            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(NONCE_SIZE)
            encrypted_key = public_key.encrypt(aes_key, _oaep())

            # Format: version(1) + key_length(4) + encrypted_key + nonce(12) + ciphertext+tag
            # The header (version, key length, wrapped key) is authenticated as AAD.
            header = struct.pack('<BI', self.version, len(encrypted_key)) + encrypted_key
            encrypted_data = aesgcm.encrypt(nonce, data, header)

            return (header + nonce + encrypted_data).hex()
        except Exception as e:
            logging.error(f"Error during data encryption: {str(e)}")
            return None

    def decrypt_data(self, encrypted_data, private_key_path, password, key_format=None):
        """Decrypt raw data using RSA private key (supports v3 and legacy v2)"""
        try:
            private_key = self._load_rsa_private(private_key_path, password, key_format)

            data = encrypted_data
            if len(data) < 5:
                raise ValueError("Truncated data")
            version = data[0]
            if version not in (VERSION, VERSION_LEGACY):
                raise ValueError(f"Unsupported version: {version}")

            key_length = struct.unpack('<I', data[1:5])[0]
            if not 0 < key_length <= MAX_WRAPPED_KEY_SIZE:
                raise ValueError("Invalid header")
            header_end = 5 + key_length
            encrypted_key = data[5:header_end]
            nonce = data[header_end:header_end + NONCE_SIZE]
            encrypted_content = data[header_end + NONCE_SIZE:]
            if len(encrypted_key) != key_length or len(nonce) != NONCE_SIZE:
                raise ValueError("Truncated data")

            aesgcm = AESGCM(private_key.decrypt(encrypted_key, _oaep()))

            if version == VERSION_LEGACY:
                return aesgcm.decrypt(nonce, encrypted_content, None)
            return aesgcm.decrypt(nonce, encrypted_content, data[:header_end])
        except Exception as e:
            logging.error(f"Error during data decryption: {str(e)}")
            return None

    # ------------------------------------------------------------ signatures

    @staticmethod
    def _write_atomic(path, data):
        partial = path + ".part"
        try:
            with open(partial, 'wb') as f:
                f.write(data)
            os.replace(partial, path)
        finally:
            if os.path.exists(partial):
                os.remove(partial)

    def sign_file(self, input_file, private_key_path, password, signature_file=None, key_format=None):
        """Signs a file with an Ed25519 private key (detached JSON signature).

        The signature is written to `signature_file` (default: `<input_file>.sig`).
        Returns True on success.
        """
        try:
            signature_file = signature_file or input_file + ".sig"
            private_key = signing.require_ed25519_private(
                self._load_private(private_key_path, password, key_format))
            self._write_atomic(
                signature_file, signing.create_signature(private_key, signing.hash_file(input_file)))
            return True
        except Exception as e:
            logging.error(f"Error during file signing: {str(e)}")
            return False

    def verify_file(self, input_file, signature_file, public_key_path, key_format=None):
        """Verifies the detached signature of a file. Returns True only if it is valid."""
        try:
            public_key = self._load_public(public_key_path, key_format)
            with open(signature_file, 'rb') as f:
                signature_data = f.read()
            return signing.check_signature(public_key, signing.hash_file(input_file), signature_data)
        except Exception as e:
            logging.error(f"Error during signature verification: {str(e)}")
            return False

    def sign_data(self, data, private_key_path, password, key_format=None):
        """Signs raw bytes. Returns the signature (JSON bytes) or None on failure."""
        try:
            private_key = signing.require_ed25519_private(
                self._load_private(private_key_path, password, key_format))
            return signing.create_signature(private_key, signing.hash_data(data))
        except Exception as e:
            logging.error(f"Error during data signing: {str(e)}")
            return None

    def verify_data(self, data, signature, public_key_path, key_format=None):
        """Verifies a signature produced by `sign_data`. Returns True only if it is valid."""
        try:
            public_key = self._load_public(public_key_path, key_format)
            return signing.check_signature(public_key, signing.hash_data(data), signature)
        except Exception as e:
            logging.error(f"Error during data signature verification: {str(e)}")
            return False
