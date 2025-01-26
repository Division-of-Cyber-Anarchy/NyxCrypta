# NyxCrypta

![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

NyxCrypta is a Python cryptography library that combines asymmetric RSA encryption and symmetric AES encryption to secure your data efficiently and easily.

## Features

- 🔐 RSA key pair generation with multiple security levels
- 📄 Multiple key formats support (PEM, DER, SSH)
- 🔒 File encryption and decryption
- 💾 Raw data encryption and decryption
- 🛡️ Strong encryption using RSA + AES hybrid approach
- 🔄 Key format conversion utilities

## Security Levels

- Standard (2048-bit RSA)
- High (3072-bit RSA)
- Paranoid (4096-bit RSA)

## Installation

From PyPI (coming soon):
```bash
pip install nyxcrypta
```

From source:
```bash
git clone https://github.com/Division-of-Cyber-Anarchy/NyxCrypta.git
cd NyxCrypta
pip install -e .
```

## Usage

### Key Generation

Generate a key pair in PEM format:
```bash
nyxcrypta keygen -o ./keys -p "your_strong_password" -f PEM
```

Generate a key pair in DER format:
```bash
nyxcrypta keygen -o ./keys -p "your_strong_password" -f DER
```

Generate a public key in SSH format:
```bash
nyxcrypta keygen -o ./keys -p "your_strong_password" -f SSH
```

### Key Format Conversion

Convert from PEM to DER:
```bash
nyxcrypta convert -i ./keys/public_key.pem -o ./keys/key.der --from-format PEM --to-format DER
```

Convert from DER to SSH (public key only):
```bash
nyxcrypta convert -i ./keys/public_key.der -o ./keys/key.ssh --from-format DER --to-format SSH --public
```

### File Encryption/Decryption

Encrypt a file:
```bash
nyxcrypta encrypt -i file.txt -o file.nyx -k ./keys/public_key.pem
```

Decrypt a file:
```bash
nyxcrypta decrypt -i file.nyx -o file.txt -k ./keys/private_key.pem -p "your_password"
```

### Data Encryption/Decryption

Encrypt raw data:
```bash
nyxcrypta encryptdata -d "My secret data" -k ./keys/public_key.pem
```

Decrypt raw data:
```bash
nyxcrypta decryptdata -d "encrypted_hex_string" -k ./keys/private_key.pem -p "your_password"
```

## Security Features

- Hybrid encryption using RSA for key exchange and AES for data encryption
- Strong key derivation using Argon2
- Secure random number generation
- Support for multiple security levels
- Encrypted private key storage

## Testing

Run the test suite:
```bash
nyxcrypta test
```

## Key Format Support

### Public Keys
- PEM format (.pem)
- DER format (.der)
- OpenSSH format (.ssh)
- JSON format (.json)

### Private Keys
- PEM format (.pem)
- DER format (.der)
- JSON format (.json)

## Python example

```python
from nyxcrypta import NyxCrypta, SecurityLevel, KeyFormat

# Initialize NyxCrypta
nx = NyxCrypta()  # Uses STANDARD security level by default

# Generate key pair
nx.save_keys("./keys", "your_password", KeyFormat.PEM)

# Encrypt a file
nx.encrypt_file("secret.txt", "secret.nyx", "./keys/public_key.pem")

# Decrypt a file
nx.decrypt_file("secret.nyx", "decrypted.txt", "./keys/private_key.pem", "your_password")

# Encrypt and decrypt data
message = b"Hello, World!"
encrypted = nx.encrypt_data(message, "./keys/public_key.pem")
decrypted = nx.decrypt_data(bytes.fromhex(encrypted), "./keys/private_key.pem", "your_password")
print(decrypted.decode())  # Prints: Hello, World!

# Using higher security level
nx_secure = NyxCrypta(SecurityLevel.PARANOID)
nx_secure.save_keys("./secure_keys", "your_password", KeyFormat.PEM)

# Key format conversion
from nyxcrypta import KeyConverter

# Convert public key from PEM to SSH format
with open("./keys/public_key.pem", "rb") as f:
    pem_data = f.read()
ssh_key = KeyConverter.convert_public_key(pem_data, KeyFormat.PEM, KeyFormat.SSH)
with open("./keys/public_key.ssh", "wb") as f:
    f.write(ssh_key)

# Convert private key from PEM to DER format
with open("./keys/private_key.pem", "rb") as f:
    pem_data = f.read()
der_key = KeyConverter.convert_private_key(
    pem_data,
    KeyFormat.PEM,
    KeyFormat.DER,
    "your_password".encode()
)
with open("./keys/private_key.der", "wb") as f:
    f.write(der_key)
```

## Dependencies

- cryptography>=41.0.5
- argon2-cffi>=20.1.0
- cffi>=1.0.0
- tqdm>=4.67

## Security Considerations

- Always use strong passwords for private keys
- Keep private keys secure and never share them
- Use appropriate security levels based on your needs
- Regularly update encryption keys
- Verify file integrity after encryption/decryption

## Development Status

This project is currently in active development. While it's functional, please be aware that:
- The API may change without notice
- Some features might be experimental
- Additional testing and security audits are ongoing

## Contributing

1. Fork the [repository](https://github.com/Division-of-Cyber-Anarchy/NyxCrypta)
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Bug Reports and Feature Requests

Please use the [GitHub issue tracker](https://github.com/Division-of-Cyber-Anarchy/NyxCrypta/issues) to report bugs or suggest features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

Division of Cyber Anarchy (DCA)
- [Malic1tus]
- [Calypt0sis]
- [NyxCrypta]
- [ViraL0x]

Contact : malic1tus@proton.me nyxcrypta@proton.me calypt0sis@proton.me viral0x@proton.me

Github : https://github.com/Division-of-Cyber-Anarchy/

---

*Simplicity is the ultimate sophistication. - Leonardo da Vinci*

[Malic1tus]: <https://github.com/malic1tus>
[Calypt0sis]: <https://github.com/calypt0sis>
[NyxCrypta]: <https://github.com/nyxcrypta>
[Viral0x]: <https://github.com/viral0x>
