# NyxCrypta

![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

NyxCrypta is a Python cryptography library that combines asymmetric RSA encryption and symmetric AES encryption to secure your data efficiently and easily.

## Features

- 🔒 **Hybrid encryption**: Combines AES-256 and RSA (2048 to 4096 bits)
- 🎯 **Configurable security levels**: Standard, High, and Paranoid
- 🔑 **Key management**: Simple generation and use of RSA key pairs
- 📚 **Intuitive** command-line interface
- 🛡️ **Proactive security**: integrated file and permissions checks

## Installation

```bash
pip install NyxCrypta
```

## Quick guide

### 1. Key generation

```bash
nyxcrypta keygen -o ./keys -p "my_strong_password"
```
This command generates a pair of RSA keys and saves them in the specified folder.

### 2. File encryption

```bash
nyxcrypta encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

### 3. File decryption

```bash
nyxcrypta decrypt -i encrypted.nyx -o decrypted.txt -k ./keys/private_key.pem -p "my_strong_password"
```

### 4. Data encryption

```bash
nyxcrypta encryptdata -d "my data" -k ./keys/public_key.pem
```

### 5. Data decryption

```bash
nyxcrypta decryptdata -d "006bd6203029" -k ./keys/private_key.pem -p "my_stong_password"
```

## Security levels

NyxCrypta offers three levels of security:

1. **STANDARD** (default) : 
   - RSA 2048 bits
   - SHA-256 for OAEP padding

2. **HIGH** :
   - RSA 3072 bits
   - SHA-256 for OAEP padding

3. **PARANOID**:
   - RSA 4096 bits
   - SHA-256 for OAEP padding

The security level is selected via the `--securitylevel` option:
```bash
nyxcrypta --securitylevel 2 encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

## Technical implementation

- Use of AES-256 in CBC mode for symmetrical encryption
- AES key encryption with RSA-OAEP
- Secure generation of IV (Initialization Vector) for each operation
- Automatic data padding management

## Best security practices

1. **Key management** : 
   - Store private keys securely
   - Limit access to key files

2. **File selection**:
   - Always check input and output file paths
   - Make sure you have the necessary permissions

3. **Security level** :
   - The STANDARD level is sufficient for most uses.
   - Use higher levels for specific needs

## Python example

```python
from nyxcrypta import NyxCrypta, SecurityLevel

# initialization
nx = NyxCrypta(SecurityLevel.HIGH)
password = "my_strong_password"

# Keys generation
nx.save_keys("./keys", password)

# Encryption & Decryption
nx.encrypt_file("secret.txt", "encrypted.nyx", "./keys/public_key.pem")
nx.decrypt_file("encrypted.nyx", "decrypted.txt", "./keys/private_key.pem", password)
nx.encrypt_data("données secrètes".encode("utf-8"), "./keys/public_key.pem")
nx.decrypt_data(bytes.fromhex("023gna5donnéescryptées"), "./keys/private_key.pem", password)
```

## Dependencies

- cryptography>=3.3.2
- argon2-cffi>=20.1.0
- cffi>=1.0.0

## License

NyxCrypta is distributed under the MIT license. See the `LICENSE` file for more details.

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
