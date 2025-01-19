import sys
import logging

def print_help():
    help_message = """
NyxCrypta v1.3.0 - Python cryptography tool

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

def handle_command(args, nyxcrypta):
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
