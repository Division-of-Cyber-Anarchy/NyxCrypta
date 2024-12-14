# NyxCrypta

![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)
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

### 1. key generation

```bash
nyxcrypta keygen -o ./keys -p "mot_de_passe_fort"
```
Cette commande génère une paire de clés RSA et les sauvegarde dans le dossier spécifié.

### 2. Chiffrement d'un fichier

```bash
nyxcrypta encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

### 3. Déchiffrement d'un fichier

```bash
nyxcrypta decrypt -i encrypted.nyx -o decrypted.txt -k ./keys/private_key.pem -p "mot_de_passe_fort"
```

### 4. Chiffrement de données

```bash
nyxcrypta encryptdata -d "mes données secrètes" -k ./keys/public_key.pem
```

### 5. Déchiffrement de données

```bash
nyxcrypta decryptdata -d "023gna5donnéescryptées" -k ./keys/private_key.pem -p "mot_de_passe_fort"
```

## Niveaux de sécurité

NyxCrypta offre trois niveaux de sécurité :

1. **STANDARD** (par défaut) : 
   - RSA 2048 bits
   - SHA-256 pour le padding OAEP

2. **HIGH** :
   - RSA 3072 bits
   - SHA-256 pour le padding OAEP

3. **PARANOID** :
   - RSA 4096 bits
   - SHA-256 pour le padding OAEP

La sélection du niveau de sécurité se fait via l'option `--securitylevel` :
```bash
nyxcrypta --securitylevel 2 encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

## Implémentation technique

- Utilisation d'AES-256 en mode CBC pour le chiffrement symétrique
- Chiffrement de la clé AES avec RSA-OAEP
- Génération sécurisée d'IV (Vecteur d'Initialisation) pour chaque opération
- Gestion automatique du padding des données

## Meilleures pratiques de sécurité

1. **Gestion des clés** : 
   - Stockez les clés privées de manière sécurisée
   - Limitez l'accès aux fichiers de clés

2. **Choix des fichiers** :
   - Vérifiez toujours les chemins des fichiers d'entrée et de sortie
   - Assurez-vous d'avoir les permissions nécessaires

3. **Niveau de sécurité** :
   - Le niveau STANDARD est suffisant pour la plupart des usages
   - Utilisez les niveaux supérieurs pour des besoins spécifiques

## Exemple Python

```python
from nyxcrypta import NyxCrypta, SecurityLevel

# Initialisation
nx = NyxCrypta(SecurityLevel.HIGH)
password = "mot_de_passe_fort"

# Génération des clés
nx.save_keys("./keys", password)

# Chiffrement et déchiffrement
nx.encrypt_file("secret.txt", "encrypted.nyx", "./keys/public_key.pem")
nx.decrypt_file("encrypted.nyx", "decrypted.txt", "./keys/private_key.pem", password)
nx.encrypt_data("données secrètes".encode("utf-8"), "./keys/public_key.pem")
nx.decrypt_data(bytes.fromhex("023gna5donnéescryptées"), "./keys/private_key.pem", password)
```

## Dépendances

- cryptography>=3.3.2
- argon2-cffi>=20.1.0
- cffi>=1.0.0

## Licence

NyxCrypta est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Auteurs

Division of Cyber Anarchy (DCA)
- Malic1tus
- Calypt0sis
- NyxCrypta
- ViraL0x

Contact : malic1tus@proton.me nyxcrypta@proton.me calypt0sis@proton.me viral0x@proton.me

Github : https://github.com/Division-of-Cyber-Anarchy/NyxCrypta

---

*"La simplicité est la sophistication suprême." - Léonard de Vinci*
