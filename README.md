# NyxCrypta

![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

NyxCrypta est une bibliothèque de cryptographie Python qui combine le chiffrement asymétrique RSA et le chiffrement symétrique AES pour sécuriser vos données de manière efficace et simple.

## Caractéristiques

- 🔒 **Chiffrement hybride** : Combine AES-256 et RSA (2048 à 4096 bits)
- 🎯 **Niveaux de sécurité configurables** : Standard, High, et Paranoid
- 🔑 **Gestion des clés** : Génération et utilisation simples des paires de clés RSA
- 📚 **Interface en ligne de commande intuitive**
- 🛡️ **Sécurité proactive** : Vérifications de fichiers et de permissions intégrées

## Installation

```bash
pip install NyxCrypta
```

## Guide rapide

### 1. Génération de clés

```bash
nyxcrypta keygen -o ./keys
```
Cette commande génère une paire de clés RSA et les sauvegarde dans le dossier spécifié.

### 2. Chiffrement d'un fichier

```bash
nyxcrypta encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

### 3. Déchiffrement d'un fichier

```bash
nyxcrypta decrypt -i encrypted.nyx -o decrypted.txt -k ./keys/private_key.pem
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
   - SHA3-512 pour le hachage

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

# Création d'une instance avec un niveau de sécurité personnalisé
nx = NyxCrypta(security_level=SecurityLevel.HIGH)

# Génération et sauvegarde des clés
nx.save_keys("./keys")

# Chiffrement d'un fichier
nx.encrypt_file("secret.txt", "encrypted.nyx", "./keys/public_key.pem")

# Déchiffrement d'un fichier
nx.decrypt_file("encrypted.nyx", "decrypted.txt", "./keys/private_key.pem")
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

Contact : malic1tus@proton.me

---

*"La simplicité est la sophistication suprême." - Léonard de Vinci*
