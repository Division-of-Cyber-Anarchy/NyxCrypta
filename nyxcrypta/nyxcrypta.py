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

# Configuration du logging
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

            # Sauvegarde de la clé privée (chiffrée)
            private_key_path = os.path.join(output_dir, 'private_key.pem')
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                ))
            logging.info(f"Clé privée (chiffrée) sauvegardée : {private_key_path}")

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
            self.file_exists(input_file)
            self.file_exists(public_key_file)

            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            with open(input_file, 'rb') as f:
                data = f.read()

            # Génération de la clé AES et du nonce
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            # Chiffrement de la clé AES avec RSA
            hash_algorithm = self.get_hash_algorithm()
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_algorithm),
                    algorithm=hash_algorithm,
                    label=None
                )
            )

            # Chiffrement des données avec AES-GCM
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Format du fichier : version || len(encrypted_key) || encrypted_key || nonce || encrypted_data
            with open(output_file, 'wb') as f:
                f.write(struct.pack('<B', self.version))
                f.write(struct.pack('<I', len(encrypted_key)))
                f.write(encrypted_key)
                f.write(nonce)
                f.write(encrypted_data)

            logging.info(f"Fichier chiffré sauvegardé : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors du chiffrement : {str(e)}")
            return False

    def decrypt_file(self, input_file, output_file, private_key_file, password):
        try:
            self.file_exists(input_file)
            self.file_exists(private_key_file)

            # Chargement de la clé privée avec mot de passe
            with open(private_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode()
                )

            with open(input_file, 'rb') as f:
                version = struct.unpack('<B', f.read(1))[0]
                if version != self.version:
                    raise ValueError(f"Version de format non supportée : {version}")

                key_size = struct.unpack('<I', f.read(4))[0]
                encrypted_key = f.read(key_size)
                nonce = f.read(12)
                encrypted_data = f.read()

            # Déchiffrement de la clé AES
            hash_algorithm = self.get_hash_algorithm()
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_algorithm),
                    algorithm=hash_algorithm,
                    label=None
                )
            )

            # Déchiffrement des données
            aesgcm = AESGCM(aes_key)
            data = aesgcm.decrypt(nonce, encrypted_data, None)

            with open(output_file, 'wb') as f:
                f.write(data)

            logging.info(f"Fichier déchiffré sauvegardé : {output_file}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors du déchiffrement : {str(e)}")
            return False

    @staticmethod
    def file_exists(file_path):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Le fichier '{file_path}' n'existe pas.")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Permissions insuffisantes pour lire '{file_path}'.")
        logging.debug(f"Vérification du fichier réussie : {file_path}")


def print_help():
    help_message = """
NyxCrypta v1.1.1 - Outil de cryptographie Python

Usage:
  nyxcrypta <commande> [options]

Commandes:
  keygen   Générer une paire de clés
  encrypt  Chiffrer un fichier
  decrypt  Déchiffrer un fichier

Options globales:
  --securitylevel  Niveau de sécurité (1=Standard, 2=High, 3=Paranoid) [défaut: 1]

Exemples:
  Générer des clés:
    nyxcrypta keygen -o ./keys -p "mot_de_passe_fort"

  Chiffrer un fichier:
    nyxcrypta encrypt -i fichier.txt -o fichier.enc -k ./keys/public_key.pem

  Déchiffrer un fichier:
    nyxcrypta decrypt -i fichier.enc -o fichier.txt -k ./keys/private_key.pem -p "mot_de_passe_fort"
    """
    print(help_message)


def main():
    parser = argparse.ArgumentParser(description="NyxCrypta v1.1.1 - Outil de cryptographie Python")
    parser.add_argument('--securitylevel', type=int, choices=[1, 2, 3], default=1,
                        help="Niveau de sécurité (1=Standard, 2=High, 3=Paranoid)")

    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')

    # keygen
    keygen_parser = subparsers.add_parser('keygen', help='Générer une paire de clés')
    keygen_parser.add_argument('-o', '--output', required=True, help='Dossier de sortie pour les clés')
    keygen_parser.add_argument('-p', '--password', required=True, help='Mot de passe pour la clé privée')

    # encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='Chiffrer un fichier')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Fichier à chiffrer')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Fichier de sortie chiffré')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Chemin de la clé publique')

    # decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='Déchiffrer un fichier')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Fichier à déchiffrer')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Fichier de sortie déchiffré')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Chemin de la clé privée')
    decrypt_parser.add_argument('-p', '--password', required=True, help='Mot de passe de la clé privée')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.command:
        print("Erreur : Aucune commande fournie.")
        print_help()
        sys.exit(1)

    nx = NyxCrypta(SecurityLevel(args.securitylevel))

    try:
        if args.command == 'keygen':
            nx.save_keys(args.output, args.password)
        elif args.command == 'encrypt':
            nx.encrypt_file(args.input, args.output, args.key)
        elif args.command == 'decrypt':
            nx.decrypt_file(args.input, args.output, args.key, args.password)
    except Exception as e:
        logging.error(f"Erreur : {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()