import sys
import logging
import questionary
from rich.console import Console
from .interactive import InteractiveCLI
from ..core.compatibility import KeyConverter, KeyFormat

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
    """
    console.print(help_message)

def handle_command(args, nyxcrypta):
    try:
        if args.command == 'keygen':
            cli.show_info("Generating new key pair...")
            
            # Get parameters interactively if not provided
            output_dir = args.output or cli.get_file_path("save to", "directory")
            password = args.password or cli.get_password()
            key_format = args.format or cli.get_key_format()
            
            with cli.show_progress("Generating keys"):
                success = nyxcrypta.save_keys(output_dir, password, key_format)
            
            if success:
                cli.show_success(f"Keys generated successfully in {output_dir}")
                # Display key information
                cli.show_key_info(f"{output_dir}/public_key.{key_format.lower()}", "Public Key")
                cli.show_info("Private key has been encrypted and saved")
            else:
                cli.show_error("Failed to generate keys")

        elif args.command == 'convert':
            cli.show_info("Converting key format...")
            
            # Interactive parameters
            input_path = args.input or cli.get_file_path("read", "source key")
            output_path = args.output or cli.get_file_path("write", "converted key")
            from_format = args.from_format or cli.get_key_format()
            to_format = args.to_format or cli.get_key_format()
            
            with open(input_path, 'rb') as f:
                key_data = f.read()
            
            is_public = 'public' in input_path.lower() or args.public
            password = None if is_public else (args.password or cli.get_password(confirm=False))
            
            with cli.show_progress("Converting"):
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
                        password.encode() if password else None
                    )
            
            with open(output_path, 'wb') as f:
                f.write(converted_key)
            
            cli.show_success(f"Key converted successfully to {to_format}")
            if not is_public:
                cli.show_info("Private key remains password protected")

        elif args.command == 'encrypt':
            cli.show_info("Encrypting file...")
            
            input_file = args.input or cli.get_file_path("encrypt")
            output_file = args.output or cli.get_file_path("save", "encrypted file")
            key_path = args.key or cli.get_file_path("use", "public key")
            
            with cli.show_progress("Encrypting"):
                success = nyxcrypta.encrypt_file(input_file, output_file, key_path)
            
            if success:
                cli.show_success(f"File encrypted successfully: {output_file}")
            else:
                cli.show_error("Encryption failed")

        elif args.command == 'decrypt':
            cli.show_info("Decrypting file...")
            
            input_file = args.input or cli.get_file_path("decrypt")
            output_file = args.output or cli.get_file_path("save", "decrypted file")
            key_path = args.key or cli.get_file_path("use", "private key")
            password = args.password or cli.get_password(confirm=False)
            
            with cli.show_progress("Decrypting"):
                success = nyxcrypta.decrypt_file(input_file, output_file, key_path, password)
            
            if success:
                cli.show_success(f"File decrypted successfully: {output_file}")
            else:
                cli.show_error("Decryption failed")

        elif args.command == 'encryptdata':
            cli.show_info("Encrypting data...")
            
            data = args.data or questionary.text("Data to encrypt:").ask()
            key_path = args.key or cli.get_file_path("use", "public key")
            
            with cli.show_progress("Encrypting"):
                encrypted_data = nyxcrypta.encrypt_data(data.encode(), key_path)
            
            if encrypted_data:
                cli.show_success("Data encrypted successfully")
                console.print("\n[bold]Encrypted data:[/bold]")
                console.print(encrypted_data)
            else:
                cli.show_error("Data encryption failed")

        elif args.command == 'decryptdata':
            cli.show_info("Decrypting data...")
            
            data = args.data or questionary.text("Data to decrypt (hex):").ask()
            key_path = args.key or cli.get_file_path("use", "private key")
            password = args.password or cli.get_password(confirm=False)
            
            with cli.show_progress("Decrypting"):
                decrypted_data = nyxcrypta.decrypt_data(
                    bytes.fromhex(data),
                    key_path,
                    password
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