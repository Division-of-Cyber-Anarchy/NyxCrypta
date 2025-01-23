import argparse

def create_parser():
    parser = argparse.ArgumentParser(description="NyxCrypta v1.3.3 - Python cryptography tool")
    parser.add_argument('--securitylevel', type=int, choices=[1, 2, 3], default=1,
                        help="Security Level (1=Standard, 2=High, 3=Paranoid)")

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # test command
    test_parser = subparsers.add_parser('test', help='Run all tests')

    # keygen
    keygen_parser = subparsers.add_parser('keygen', help='Generate a key pair')
    keygen_parser.add_argument('-o', '--output', required=True, help='Output folder for keys')
    keygen_parser.add_argument('-p', '--password', required=True, help='Password for private key')
    keygen_parser.add_argument('-f', '--format', choices=['PEM', 'DER', 'SSH', 'JSON'], default='PEM',
                              help='Key format (default: PEM)')

    # convert
    convert_parser = subparsers.add_parser('convert', help='Convert key format')
    convert_parser.add_argument('-i', '--input', required=True, help='Input key file')
    convert_parser.add_argument('-o', '--output', required=True, help='Output key file')
    convert_parser.add_argument('--from-format', required=True, choices=['PEM', 'DER', 'SSH', 'JSON'],
                               help='Input key format')
    convert_parser.add_argument('--to-format', required=True, choices=['PEM', 'DER', 'SSH', 'JSON'],
                               help='Output key format')
    convert_parser.add_argument('-p', '--password', help='Password for private key')
    convert_parser.add_argument('--public', action='store_true', help='Convert public key (default: private)')

    # encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='File encryption')
    encrypt_parser.add_argument('-i', '--input', required=True, help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Encrypted output file')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Public key path')
    encrypt_parser.add_argument('--key-format', choices=['PEM', 'DER', 'SSH'], default='PEM',
                               help='Key format (default: PEM)')

    # decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='File decryption')
    decrypt_parser.add_argument('-i', '--input', required=True, help='File to decrypt')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Decrypted output file')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Private key path')
    decrypt_parser.add_argument('-p', '--password', required=True, help='Private key password')
    decrypt_parser.add_argument('--key-format', choices=['PEM', 'DER'], default='PEM',
                               help='Key format (default: PEM)')

    # encryptdata
    encryptdata_parser = subparsers.add_parser('encryptdata', help='RAW data encryption')
    encryptdata_parser.add_argument('-d', '--data', required=True, help='Data to encrypt')
    encryptdata_parser.add_argument('-k', '--key', required=True, help='Public key path')
    encryptdata_parser.add_argument('--key-format', choices=['PEM', 'DER', 'SSH'], default='PEM',
                                   help='Key format (default: PEM)')

    # decryptdata
    decryptdata_parser = subparsers.add_parser('decryptdata', help='RAW data decryption')
    decryptdata_parser.add_argument('-d', '--data', required=True, help='Data to decrypt')
    decryptdata_parser.add_argument('-k', '--key', required=True, help='Private key path')
    decryptdata_parser.add_argument('-p', '--password', required=True, help='Private key password')
    decryptdata_parser.add_argument('--key-format', choices=['PEM', 'DER'], default='PEM',
                                   help='Key format (default: PEM)')

    return parser