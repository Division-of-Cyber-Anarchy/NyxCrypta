import sys
import logging
import questionary
from rich.console import Console
from .interactive import InteractiveCLI, UserCancelled
from ..core.compatibility import KeyConverter, KeyFormat, detect_key_type
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
  JSON          JSON format with base64 encoded key (private keys are always encrypted)

[bold]Key format option:[/bold]

  --key-format is optional: the format is auto-detected from the key file.
  Pass it to force a specific format.

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
    """Runs a command. Returns True on success, False otherwise.

    Never exits the process: the caller decides (the interactive session must
    survive an error, the classic CLI turns False into a non-zero exit code).
    """
    ok = True
    try:
        if args.command == 'keygen':
            cli.show_info("Generating new key pair...")

            # Interactive mode: ask for missing parameters
            if not hasattr(args, 'output') or not args.output:
                output_dir = cli.get_file_path("save to", "directory")
                password = cli.get_password()
                key_format = cli.get_key_format()
                args = Namespace(
                    output=output_dir,
                    password=password,
                    format=key_format,
                    command='keygen'
                )

            with cli.show_progress("Generating keys"):
                success = nyxcrypta.save_keys(args.output, args.password, args.format)

            if success:
                cli.show_success(f"Keys generated successfully in {args.output}")
                cli.show_key_info(f"{args.output}/public_key.{args.format.lower()}", "Public Key")
                if args.format == "SSH":
                    cli.show_info("Private key has been encrypted and saved as private_key.pem (SSH is a public-key-only format)")
                else:
                    cli.show_info("Private key has been encrypted and saved")
            else:
                cli.show_error("Failed to generate keys")
                ok = False

        elif args.command == 'convert':
            cli.show_info("Converting key format...")

            # Interactive mode: ask for missing parameters
            if not hasattr(args, 'input') or not args.input:
                input_path = cli.get_file_path("read", "source key")
                output_path = cli.get_file_path("write", "converted key")
                from_format = cli.get_key_format()
                to_format = cli.get_key_format()
                args = Namespace(
                    input=input_path,
                    output=output_path,
                    from_format=from_format,
                    to_format=to_format,
                    public=False,
                    password=None,
                    command='convert'
                )

            with open(args.input, 'rb') as f:
                key_data = f.read()

            # The key type comes from the key content, never from its path
            is_public = args.public or detect_key_type(key_data, args.from_format) == "public"
            password = None
            if not is_public:
                password = args.password or cli.get_password(confirm=False)

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
            if not is_public and password:
                cli.show_info("Private key remains password protected")

        elif args.command == 'encrypt':
            cli.show_info("Encrypting file...")

            if not hasattr(args, 'input') or not args.input:
                input_file = cli.get_file_path("encrypt")
                output_file = cli.get_file_path("save", "encrypted file")
                key_path = cli.get_file_path("use", "public key")
                args = Namespace(
                    input=input_file,
                    output=output_file,
                    key=key_path,
                    key_format=None,
                    command='encrypt'
                )

            with cli.show_progress("Encrypting"):
                success = nyxcrypta.encrypt_file(
                    args.input, args.output, args.key, getattr(args, 'key_format', None))

            if success:
                cli.show_success(f"File encrypted successfully: {args.output}")
            else:
                cli.show_error("Encryption failed")
                ok = False

        elif args.command == 'decrypt':
            cli.show_info("Decrypting file...")

            if not hasattr(args, 'input') or not args.input:
                input_file = cli.get_file_path("decrypt")
                output_file = cli.get_file_path("save", "decrypted file")
                key_path = cli.get_file_path("use", "private key")
                password = cli.get_password(confirm=False)
                args = Namespace(
                    input=input_file,
                    output=output_file,
                    key=key_path,
                    password=password,
                    key_format=None,
                    command='decrypt'
                )

            with cli.show_progress("Decrypting"):
                success = nyxcrypta.decrypt_file(
                    args.input, args.output, args.key, args.password, getattr(args, 'key_format', None))

            if success:
                cli.show_success(f"File decrypted successfully: {args.output}")
            else:
                cli.show_error("Decryption failed")
                ok = False

        elif args.command == 'encryptdata':
            cli.show_info("Encrypting data...")

            if not hasattr(args, 'data') or not args.data:
                data = cli.ask_text("Data to encrypt:")
                key_path = cli.get_file_path("use", "public key")
                args = Namespace(
                    data=data,
                    key=key_path,
                    key_format=None,
                    command='encryptdata'
                )

            with cli.show_progress("Encrypting"):
                encrypted_data = nyxcrypta.encrypt_data(
                    args.data.encode(), args.key, getattr(args, 'key_format', None))

            if encrypted_data:
                cli.show_success("Data encrypted successfully")
                console.print("\n[bold]Encrypted data:[/bold]")
                console.print(encrypted_data, markup=False, highlight=False)
            else:
                cli.show_error("Data encryption failed")
                ok = False

        elif args.command == 'decryptdata':
            cli.show_info("Decrypting data...")

            if not hasattr(args, 'data') or not args.data:
                data = cli.ask_text("Data to decrypt (hex):")
                key_path = cli.get_file_path("use", "private key")
                password = cli.get_password(confirm=False)
                args = Namespace(
                    data=data,
                    key=key_path,
                    password=password,
                    key_format=None,
                    command='decryptdata'
                )

            with cli.show_progress("Decrypting"):
                decrypted_data = nyxcrypta.decrypt_data(
                    bytes.fromhex(args.data),
                    args.key,
                    args.password,
                    getattr(args, 'key_format', None)
                )

            # `is not None`: an empty plaintext (b"") is a valid result
            if decrypted_data is not None:
                cli.show_success("Data decrypted successfully")
                console.print("\n[bold]Decrypted data:[/bold]")
                if not decrypted_data:
                    console.print("(empty)", markup=False)
                else:
                    try:
                        console.print(decrypted_data.decode('utf-8'), markup=False, highlight=False)
                    except UnicodeDecodeError:
                        cli.show_warning("Binary data (not valid UTF-8), displayed as hexadecimal")
                        console.print(decrypted_data.hex(), markup=False, highlight=False)
            else:
                cli.show_error("Data decryption failed")
                ok = False

    except UserCancelled:
        cli.show_warning("Operation cancelled")
        ok = False
    except Exception as e:
        cli.show_error(str(e))
        logging.error(str(e))
        ok = False

    return ok
