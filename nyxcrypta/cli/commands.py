import sys
import logging
import questionary
from rich.console import Console
from .interactive import InteractiveCLI
from ..core.compatibility import KeyConverter, KeyFormat
from argparse import Namespace

console = Console()
cli = InteractiveCLI()

def print_help():
    cli.welcome()
    cli.show_info("Use the interactive menu with command: nyxcrypta")
    help_message = """
[bold]Available Commands:[/bold]

  test          Run all tests
  keygen        Generate key pair
  convert       Convert key format
  encrypt       Encrypt a file
  decrypt       Decrypt a file
  encryptdata   Encrypt raw data
  decryptdata   Decrypt raw data

[bold]Global Options:[/bold]

  --securitylevel  Security level (1=Standard, 2=High, 3=Paranoid) [default: 1]

[bold]Key Formats:[/bold]

  PEM           Standard PEM format
  DER           Binary DER format
  SSH           OpenSSH format (public keys only)
  JSON          JSON format with base64 encoded key

[bold]Examples:[/bold]

  Run tests:
    nyxcrypta test

  Generate PEM format keys:
    nyxcrypta keygen -o ./keys -p "password" -f PEM

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
    console.print(help_message)

def handle_command(args, nyxcrypta):
    try:
        if args.command == 'keygen':
            cli.show_info("Generating new key pair...")
            
            # Si nous sommes en mode interactif et que les arguments sont manquants
            if not hasattr(args, 'output') or not args.output:
                output_dir = cli.get_file_path("save to", "directory")
                password = cli.get_password()
                key_format = cli.get_key_format()
                # Mettre à jour les arguments
                args = Namespace(
                    output=output_dir,
                    password=password,
                    format=key_format,  # key_format est déjà une chaîne
                    command='keygen'
                )
            
            with cli.show_progress("Generating keys"):
                success = nyxcrypta.save_keys(args.output, args.password, args.format)
            
            if success:
                cli.show_success(f"Keys generated successfully in {args.output}")
                # Display key information
                cli.show_key_info(f"{args.output}/public_key.{args.format.lower()}", "Public Key")
                cli.show_info("Private key has been encrypted and saved")
            else:
                cli.show_error("Failed to generate keys")

        elif args.command == 'convert':
            cli.show_info("Converting key format...")
            
            # Interactive parameters if needed
            if not hasattr(args, 'input') or not args.input:
                input_path = cli.get_file_path("read", "source key")
                output_path = cli.get_file_path("write", "converted key")
                from_format = cli.get_key_format()
                to_format = cli.get_key_format()
                is_public = cli.confirm_action("convert a public key")
                password = None if is_public else cli.get_password(confirm=False)
                # Mettre à jour les arguments
                args = Namespace(
                    input=input_path,
                    output=output_path,
                    from_format=from_format,  # from_format est déjà une chaîne
                    to_format=to_format,      # to_format est déjà une chaîne
                    public=is_public,
                    password=password,
                    command='convert'
                )
            
            with open(args.input, 'rb') as f:
                key_data = f.read()
            
            is_public = 'public' in args.input.lower() or args.public
            password = None if is_public else (args.password or cli.get_password(confirm=False))
            
            with cli.show_progress("Converting"):
                if is_public:
                    converted_key = KeyConverter.convert_public_key(
                        key_data,
                        args.from_format,
                        args.to_format
                    )
                else:
                    converted_key = KeyConverter.convert_private_key(
                        key_data,
                        args.from_format,
                        args.to_format,
                        password.encode() if password else None
                    )
            
            with open(args.output, 'wb') as f:
                f.write(converted_key)
            
            cli.show_success(f"Key converted successfully to {args.to_format}")
            if not is_public:
                cli.show_info("Private key remains password protected")

        elif args.command == 'encrypt':
            cli.show_info("Encrypting file...")
            
            if not hasattr(args, 'input') or not args.input:
                input_file = cli.get_file_path("encrypt")
                output_file = cli.get_file_path("save", "encrypted file")
                key_path = cli.get_file_path("use", "public key")
                # Mettre à jour les arguments
                args = Namespace(
                    input=input_file,
                    output=output_file,
                    key=key_path,
                    command='encrypt'
                )
            
            with cli.show_progress("Encrypting"):
                success = nyxcrypta.encrypt_file(args.input, args.output, args.key)
            
            if success:
                cli.show_success(f"File encrypted successfully: {args.output}")
            else:
                cli.show_error("Encryption failed")

        elif args.command == 'decrypt':
            cli.show_info("Decrypting file...")
            
            if not hasattr(args, 'input') or not args.input:
                input_file = cli.get_file_path("decrypt")
                output_file = cli.get_file_path("save", "decrypted file")
                key_path = cli.get_file_path("use", "private key")
                password = cli.get_password(confirm=False)
                # Mettre à jour les arguments
                args = Namespace(
                    input=input_file,
                    output=output_file,
                    key=key_path,
                    password=password,
                    command='decrypt'
                )
            
            with cli.show_progress("Decrypting"):
                success = nyxcrypta.decrypt_file(args.input, args.output, args.key, args.password)
            
            if success:
                cli.show_success(f"File decrypted successfully: {args.output}")
            else:
                cli.show_error("Decryption failed")

        elif args.command == 'encryptdata':
            cli.show_info("Encrypting data...")
            
            if not hasattr(args, 'data') or not args.data:
                data = questionary.text("Data to encrypt:").ask()
                key_path = cli.get_file_path("use", "public key")
                # Mettre à jour les arguments
                args = Namespace(
                    data=data,
                    key=key_path,
                    command='encryptdata'
                )
            
            with cli.show_progress("Encrypting"):
                encrypted_data = nyxcrypta.encrypt_data(args.data.encode(), args.key)
            
            if encrypted_data:
                cli.show_success("Data encrypted successfully")
                console.print("\n[bold]Encrypted data:[/bold]")
                console.print(encrypted_data)
            else:
                cli.show_error("Data encryption failed")

        elif args.command == 'decryptdata':
            cli.show_info("Decrypting data...")
            
            if not hasattr(args, 'data') or not args.data:
                data = questionary.text("Data to decrypt (hex):").ask()
                key_path = cli.get_file_path("use", "private key")
                password = cli.get_password(confirm=False)
                # Mettre à jour les arguments
                args = Namespace(
                    data=data,
                    key=key_path,
                    password=password,
                    command='decryptdata'
                )
            
            with cli.show_progress("Decrypting"):
                decrypted_data = nyxcrypta.decrypt_data(
                    bytes.fromhex(args.data),
                    args.key,
                    args.password
                )
            
            if decrypted_data:
                cli.show_success("Data decrypted successfully")
                console.print("\n[bold]Decrypted data:[/bold]")
                console.print(decrypted_data.decode())
            else:
                cli.show_error("Data decryption failed")

    except Exception as e:
        cli.show_error(str(e))
        logging.error(str(e))
        sys.exit(1)