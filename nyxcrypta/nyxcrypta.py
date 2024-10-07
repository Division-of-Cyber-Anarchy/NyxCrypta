#!/usr/bin/env python3

import argparse
import os
import sys
import struct
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from enum import Enum
import logging

# Configurer le logging pour afficher les messages
logging.basicConfig(level=logging.INFO)


class SecurityLevel(Enum):
    STANDARD = 1
    HIGH = 2
    PARANOID = 3


class NyxCrypta:
    def __init__(self, security_level=SecurityLevel.STANDARD):
        self.security_level = security_level
        self.ph = PasswordHasher(time_cost=2, memory_cost=2 ** 16, parallelism=1)

    def generate_rsa_keypair(self):
        key_size = 2048 if self.security_level == SecurityLevel.STANDARD else \
            3072 if self.security_level == SecurityLevel.HIGH else 4096

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    def save_keys(self, output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            private_key, public_key = self.generate_rsa_keypair()

            # Sauvegarde de la clé privée
            private_key_path = os.path.join(output_dir, 'private_key.pem')
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            logging.info(f"Clé privée sauvegardée : {private_key_path}")

            # Sauvegarde de la clé publique
            public_key_path = os.path.join(output_dir, 'public_key.pem')
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logging.info(f"Clé publique sauvegardée : {public_key_path}")

            return True
        except Exception as e:
            logging.error(f"Erreur lors de la génération des clés : {str(e)}")
            return False

    def encrypt_file(self, input_file, output_file, public_key_file):
        try:
            # Vérifie si le fichier existe
            self.file_exists(input_file)
            self.file_exists(public_key_file)

            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            with open(input_file, 'rb') as f:
                data = f.read()

            aes_key = os.urandom(32)
            iv = os.urandom(16)

            # Utiliser le bon algorithme de hachage selon le niveau de sécurité
            hash_algorithm = hashes.SHA256() if self.security_level in [SecurityLevel.STANDARD,
                                                                        SecurityLevel.HIGH] else hashes.SHA3_512()

            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_algorithm),
                    algorithm=hash_algorithm,
                    label=None
                )
            )

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padded_data = self._pad_data(data)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            with open(output_file, 'wb') as f:
                f.write(struct.pack('<I', len(encrypted_key)))
                f.write(encrypted_key)
                f.write(iv)
                f.write(encrypted_data)

            logging.info(f"Fichier chiffré sauvegardé : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors du chiffrement : {str(e)}")
            return False

    def decrypt_file(self, input_file, output_file, private_key_file):
        try:
            # Vérifie si le fichier existe
            self.file_exists(input_file)
            self.file_exists(private_key_file)

            with open(private_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

            with open(input_file, 'rb') as f:
                key_size = struct.unpack('<I', f.read(4))[0]
                encrypted_key = f.read(key_size)
                iv = f.read(16)
                encrypted_data = f.read()

            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            data = self._unpad_data(padded_data)

            with open(output_file, 'wb') as f:
                f.write(data)

            logging.info(f"Fichier déchiffré sauvegardé : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors du déchiffrement : {str(e)}")
            return False

    @staticmethod
    def _pad_data(data):
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def _unpad_data(padded_data):
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    @staticmethod
    def file_exists(file_path):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Le fichier '{file_path}' n'existe pas.")
        logging.info(f"Fichier trouvé : {file_path}")

    @staticmethod
    def check_permissions(file_path, mode='r'):
        if not os.access(file_path, os.R_OK if mode == 'r' else os.W_OK):
            raise PermissionError(
                f"Vous n'avez pas les permissions nécessaires pour accéder à '{file_path}' en mode {mode}.")
        logging.info(f"Permissions valides pour le fichier : {file_path}")


def print_help():
    """Affiche l'aide personnalisée"""
    help_message = """
    NyxCrypta - Outil de cryptographie Python

    Commandes disponibles :
    keygen        : Générer une paire de clés
    encrypt       : Chiffrer un fichier
    decrypt       : Déchiffrer un fichier

    Utilisation :
    nyxcrypta <commande> [options]

    Exemple :
    nyxcrypta keygen -o ./keys
    nyxcrypta encrypt -i fichier.txt -o fichier_chiffré.bin -k ./keys/public_key.pem
    nyxcrypta decrypt -i fichier_chiffré.bin -o fichier_déchiffré.txt -k ./keys/private_key.pem
    """
    print(help_message)

def main():
    parser = argparse.ArgumentParser(description="NyxCrypta - Outil de cryptographie Python")
    parser.add_argument('--securitylevel', type=int, choices=[1, 2, 3], default=1, help=argparse.SUPPRESS)  # Ne pas afficher dans l'aide

    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')

    keygen_parser = subparsers.add_parser('keygen', help='Générer une paire de clés')
    keygen_parser.add_argument('-o', '--output', required=True, help='Dossier de sortie pour les clés')

    encrypt_parser = subparsers.add_parser('encrypt', help='Chiffrer un fichier')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Fichier à chiffrer')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Fichier de sortie chiffré')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Chemin de la clé publique')

    decrypt_parser = subparsers.add_parser('decrypt', help='Déchiffrer un fichier')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Fichier à déchiffrer')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Fichier de sortie déchiffré')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Chemin de la clé privée')

    # Vérifie si l'argument -h ou --help a été passé
    if '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Vérifie si les arguments sont valides
    if not args.command:
        print("Erreur : Aucune commande fournie.")
        print_help()
        sys.exit(1)

    nx = NyxCrypta()

    try:
        if args.command == 'keygen':
            nx.save_keys(args.output)

        elif args.command == 'encrypt':
            nx.encrypt_file(args.input, args.output, args.key)

        elif args.command == 'decrypt':
            nx.decrypt_file(args.input, args.output, args.key)

    except Exception as e:
        print(f"Erreur : {str(e)}")
        print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
