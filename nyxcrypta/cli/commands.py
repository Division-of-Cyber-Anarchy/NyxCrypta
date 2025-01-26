import sys
import logging
from ..core.compatibility import KeyConverter, KeyFormat

def print_help():
    help_message = """
NyxCrypta v1.4.0 - Python cryptography tool

Usage:
  nyxcrypta <command> [options]

Commands:
  test          Run all tests
  keygen        Generate a key pair
  convert       Convert key format
  encrypt       Encrypting a file
  decrypt       Decrypting a file
  encryptdata   Encrypting raw data
  decryptdata   Decrypting raw data

Global options:
  --securitylevel  Security level (1=Standard, 2=High, 3=Paranoid) [default: 1]

Key formats:
  PEM           Standard PEM format
  DER           Binary DER format
  SSH           OpenSSH format (public keys only)
  JSON          JSON format with base64 encoded key

Examples:
  Run tests:
    nyxcrypta test

  Key generation in PEM format:
    nyxcrypta keygen -o ./keys -p "my_strong_password" -f PEM

  Convert key format:
    nyxcrypta convert -i key.pem -o key.der --from-format PEM --to-format DER

  File encryption with PEM key:
    nyxcrypta encrypt -i file.txt -o file.nyx -k ./keys/public_key.pem --key-format PEM

  File decryption with DER key:
    nyxcrypta decrypt -i file.nyx -o file.txt -k ./keys/private_key.der -p "password" --key-format DER
    
  Data encryption with SSH key:
    nyxcrypta encryptdata -d "My RAW data" -k ./keys/public_key.ssh --key-format SSH
    
  Data decryption with PEM key:
    nyxcrypta decryptdata -d "0203be021" -k ./keys/private_key.pem -p "password" --key-format PEM
    """
    print(help_message)

def handle_command(args, nyxcrypta):
    try:
        if args.command == 'keygen':
            # Convert format string to KeyFormat enum value
            key_format = getattr(KeyFormat, args.format.upper())
            nyxcrypta.save_keys(args.output, args.password, key_format)
        elif args.command == 'convert':
            with open(args.input, 'rb') as f:
                key_data = f.read()
            
            # Determine if it's a public key based on filename
            is_public = 'public' in args.input.lower() or args.public
            
            # Convert format strings to KeyFormat enum values
            from_format = getattr(KeyFormat, args.from_format.upper())
            to_format = getattr(KeyFormat, args.to_format.upper())
            
            if is_public:
                converted_key = KeyConverter.convert_public_key(
                    key_data,
                    from_format,
                    to_format
                )
            else:
                converted_key = KeyConverter.convert_private_key(
                    key_data,
                    from_format,
                    to_format,
                    args.password.encode() if args.password else None
                )
            
            with open(args.output, 'wb') as f:
                f.write(converted_key)
            print(f"Key successfully converted to {args.to_format} format")
            
        elif args.command == 'encrypt':
            nyxcrypta.encrypt_file(args.input, args.output, args.key, key_format=args.key_format)
        elif args.command == 'decrypt':
            nyxcrypta.decrypt_file(args.input, args.output, args.key, args.password, key_format=args.key_format)
        elif args.command == 'encryptdata':
            data = args.data.encode('utf-8')
            encrypted_data = nyxcrypta.encrypt_data(data, args.key, key_format=args.key_format)
            if encrypted_data:
                print("Encrypted data:", encrypted_data)
        elif args.command == 'decryptdata':
            encrypted_data = bytes.fromhex(args.data)
            decrypted_data = nyxcrypta.decrypt_data(encrypted_data, args.key, args.password, key_format=args.key_format)
            if decrypted_data:
                print("Decrypted data:", decrypted_data.decode('utf-8'))
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)