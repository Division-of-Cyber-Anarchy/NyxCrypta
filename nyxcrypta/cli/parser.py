import argparse

def create_parser():
    parser = argparse.ArgumentParser(description="NyxCrypta v1.3.0 - Python cryptography tool")
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

    return parser
