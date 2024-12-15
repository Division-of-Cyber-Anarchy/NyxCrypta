#!/usr/bin/env python3

import argparse
import os
import sys
import struct
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from enum import Enum
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SecurityLevel(Enum):
    STANDARD = 1  # RSA 2048
    HIGH = 2  # RSA 3072
    PARANOID = 3  # RSA 4096


class NyxCrypta:
    def __init__(self, security_level=SecurityLevel.STANDARD):
        self.security_level = security_level
        self.ph = PasswordHasher(time_cost=2, memory_cost=2 ** 16, parallelism=1)
        self.version = 2

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
            private_key, public_key = self.generate_rsa_keypair()

            # Private key backup (encrypted)
            private_key_path = os.path.join(output_dir, 'private_key.pem')
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                ))
            logging.info(f"Private key (encrypted) saved : {private_key_path}")

            # Public key backup
            public_key_path = os.path.join(output_dir, 'public_key.pem')
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logging.info(f"Public key saved : {public_key_path}")

            return True
        except Exception as e:
            logging.error(f"Error during key generation : {str(e)}")
            return False

    def encrypt_file(self, input_file, output_file, public_key_file):
        try:
            self.file_exists(input_file)
            self.file_exists(public_key_file)

            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            with open(input_file, 'rb') as f:
                data = f.read()

            # AES key and nonce generation
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

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

            # Data encryption with AES-GCM
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # File format : version || len(encrypted_key) || encrypted_key || nonce || encrypted_data
            with open(output_file, 'wb') as f:
                f.write(struct.pack('<B', self.version))
                f.write(struct.pack('<I', len(encrypted_key)))
                f.write(encrypted_key)
                f.write(nonce)
                f.write(encrypted_data)

            logging.info(f"Encrypted file saved : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Error during encryption : {str(e)}")
            return False

    def decrypt_file(self, input_file, output_file, private_key_file, password):
        try:
            self.file_exists(input_file)
            self.file_exists(private_key_file)

            # Private key loading with password
            with open(private_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode()
                )

            with open(input_file, 'rb') as f:
                version = struct.unpack('<B', f.read(1))[0]
                if version != self.version:
                    raise ValueError(f"Format version not supported : {version}")

                key_size = struct.unpack('<I', f.read(4))[0]
                encrypted_key = f.read(key_size)
                nonce = f.read(12)
                encrypted_data = f.read()

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

            # Data decryption
            aesgcm = AESGCM(aes_key)
            data = aesgcm.decrypt(nonce, encrypted_data, None)

            with open(output_file, 'wb') as f:
                f.write(data)

            logging.info(f"Decrypted file saved : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Error during decryption : {str(e)}")
            return False

    def encrypt_data(self, data, public_key_file):
        try:
            # Load public key from PEM file
            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            # Check that the key loaded is an RSAPublicKey object
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("The loaded public key is not an RSAPublicKey object")

            # AES key and nonce generation
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

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

            # Data encryption with AES-GCM
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Return encrypted data in binary form
            result = struct.pack('<B', self.version) + struct.pack('<I', len(encrypted_key)) + encrypted_key + nonce + encrypted_data
            return result.hex()

        except Exception as e:
            logging.error(f"Error during data encryption : {str(e)}")
            return None

    def decrypt_data(self, encrypted_data, private_key_file, password):
        try:
            # Loading private key with password
            with open(private_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode()
                )

            # Extracting information from the encrypted format
            version = struct.unpack('<B', encrypted_data[:1])[0]
            if version != self.version:
                raise ValueError(f"Format version not supported : {version}")

            key_size = struct.unpack('<I', encrypted_data[1:5])[0]
            encrypted_key = encrypted_data[5:5 + key_size]
            nonce = encrypted_data[5 + key_size:17 + key_size]
            encrypted_data = encrypted_data[17 + key_size:]

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

            # Data decryption
            aesgcm = AESGCM(aes_key)
            data = aesgcm.decrypt(nonce, encrypted_data, None)

            return data

        except Exception as e:
            logging.error(f"Data decryption error : {str(e)}")
            return None

    @staticmethod
    def file_exists(file_path):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file '{file_path}' does not exist.")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Insufficient permission to read '{file_path}'.")
        logging.debug(f"Successful file verification : {file_path}")


def print_help():
    help_message = """
NyxCrypta v1.2.1 - Python cryptography tool

Usage:
  nyxcrypta <command> [options]

Commands:
  keygen   Generate a key pair
  encrypt  Encrypting a file
  decrypt  Decrypting a file
  encryptdata  Encrypting raw data
  decryptdata  Decrypting raw data

Global options:
  --securitylevel  Security level (1=Standard, 2=High, 3=Paranoid) [default: 1]

Examples:
  Key generation:
    nyxcrypta keygen -o ./keys -p "my_strong_password"

  File encryption:
    nyxcrypta encrypt -i file.txt -o file.nyx -k ./keys/public_key.pem

  File decryption:
    nyxcrypta decrypt -i file.nyx -o file.txt -k ./keys/private_key.pem -p "my_strong_password"
    
  Data encryption:
    nyxcrypta encryptdata -d "My RAW data" -k ./keys/public_key.pem
    
  Data decryption:
    nyxcrypta decryptdata -d "0203be021" -k ./keys/private_key.pem -p "my_strong_password"
    """
    print(help_message)


def main():
    parser = argparse.ArgumentParser(description="NyxCrypta v1.2.1 - Python cryptography tool")
    parser.add_argument('--securitylevel', type=int, choices=[1, 2, 3], default=1,
                        help="Security Level (1=Standard, 2=High, 3=Paranoid)")

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # keygen
    keygen_parser = subparsers.add_parser('keygen', help='Generate a key pair')
    keygen_parser.add_argument('-o', '--output', required=True, help='Output folder for keys')
    keygen_parser.add_argument('-p', '--password', required=True, help='Password for private key')

    # encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='File encryption')
    encrypt_parser.add_argument('-i', '--input', required=True, help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Encrypted output file')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Public key path')

    # decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='File decryption')
    decrypt_parser.add_argument('-i', '--input', required=True, help='File to decrypt')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Decrypted output file')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Private key path')
    decrypt_parser.add_argument('-p', '--password', required=True, help='Private key password')

    # encryptdata
    encryptdata_parser = subparsers.add_parser('encryptdata', help='RAW data encryption')
    encryptdata_parser.add_argument('-d', '--data', required=True, help='Data to encrypt')
    encryptdata_parser.add_argument('-k', '--key', required=True, help='Public key path')

    # decryptdata
    decryptdata_parser = subparsers.add_parser('decryptdata', help='RAW data decryption')
    decryptdata_parser.add_argument('-d', '--data', required=True, help='Data to decrypt')
    decryptdata_parser.add_argument('-k', '--key', required=True, help='Private key path')
    decryptdata_parser.add_argument('-p', '--password', required=True, help='Private key password')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)
    args = parser.parse_args()
    if not args.command:
        print("Error : No command supplied.")
        print_help()
        sys.exit(1)

    # NyxCrypta instance creation
    nyxcrypta = NyxCrypta(SecurityLevel(args.securitylevel))

    try:
        if args.command == 'keygen':
            nyxcrypta.save_keys(args.output, args.password)
        elif args.command == 'encrypt':
            nyxcrypta.encrypt_file(args.input, args.output, args.key)
        elif args.command == 'decrypt':
            nyxcrypta.decrypt_file(args.input, args.output, args.key, args.password)
        elif args.command == 'encryptdata':
            data = args.data.encode('utf-8')
            encrypted_data = nyxcrypta.encrypt_data(data, args.key)
            if encrypted_data:
                print("Encrypted data :", encrypted_data)
        elif args.command == 'decryptdata':
            encrypted_data = bytes.fromhex(args.data)
            decrypted_data = nyxcrypta.decrypt_data(encrypted_data, args.key, args.password)
            if decrypted_data:
                print("Decrypted data :", decrypted_data.decode('utf-8'))
    except Exception as e:
        logging.error(f"Error : {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()