# NyxCrypta

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

NyxCrypta est une bibliothèque de cryptographie Python moderne et sophistiquée, conçue pour offrir une sécurité de niveau professionnel avec une interface simple et élégante.

## Caractéristiques

- 🔒 **Chiffrement hybride** : Combine AES-256 et RSA-4096 pour une sécurité optimale
- 🎯 **Authentification des données** : Utilisation de HMAC pour garantir l'intégrité
- 🔑 **Gestion avancée des clés** : Dérivation sécurisée des clés avec PBKDF2
- 🖼️ **Stéganographie intégrée** : Cachez vos données chiffrées dans des images
- 📚 **API intuitive** : Facile à utiliser, difficile à mal utiliser
- 🛡️ **Sécurité proactive** : Protection contre diverses attaques cryptographiques

## Installation

```bash
pip install nyxcrypta
```

## Guide rapide

### 1. Génération de clés

```bash
nyxcrypta keygen -o ./keys
```

### 2. Chiffrement d'un fichier

```bash
nyxcrypta encrypt -i secret.txt -o encrypted.nyx -k ./keys/public_key.pem
```

### 3. Déchiffrement d'un fichier

```bash
nyxcrypta decrypt -i encrypted.nyx -o decrypted.txt -k ./keys/private_key.pem
```

### 4. Utilisation de la stéganographie

```bash
# Cacher des données dans une image
nyxcrypta hide -d encrypted.nyx -i original.png -o hidden.png

# Extraire des données d'une image
nyxcrypta extract -i hidden.png -o extracted.nyx
```

## Utilisation via l'API Python

```python
from nyxcrypta import NyxCrypta

# Initialisation
nx = NyxCrypta()

# Génération de clés
private_key, public_key = nx.generate_rsa_keypair()

# Chiffrement
secret_data = b"Données confidentielles"
encrypted_package = nx.encrypt_data(secret_data, public_key)

# Déchiffrement
decrypted_data = nx.decrypt_data(encrypted_package, private_key)
```

## Configuration avancée

NyxCrypta offre de nombreuses options de configuration pour les utilisateurs avancés. Consultez notre documentation complète pour plus de détails sur :

- Personnalisation des paramètres de dérivation de clés
- Modes de chiffrement alternatifs
- Optimisation des performances
- Intégration avec d'autres systèmes de sécurité

## Paramètres secrets et modes avancés

NyxCrypta inclut des paramètres et modes supplémentaires non documentés pour les utilisateurs expérimentés. Ces fonctionnalités sont intentionnellement complexes et nécessitent une compréhension approfondie de la cryptographie pour être utilisées correctement.

*Note : L'utilisation incorrecte des paramètres avancés peut compromettre la sécurité de vos données.*

## Meilleures pratiques de sécurité

1. **Gestion des clés** : 
   - Stockez les clés privées de manière sécurisée
   - Utilisez des mots de passe forts pour protéger les clés
   - Effectuez des rotations régulières des clés

2. **Choix des paramètres** :
   - Utilisez les paramètres par défaut sauf si vous avez une raison spécifique de les modifier
   - Testez toujours la configuration complète avant le déploiement

3. **Audit et journalisation** :
   - Enregistrez toutes les opérations cryptographiques importantes
   - Effectuez des audits réguliers de l'utilisation des clés

## Exemples détaillés

### Chiffrement avec authentification renforcée

```python
from nyxcrypta import NyxCrypta, SecurityLevel

nx = NyxCrypta(security_level=SecurityLevel.PARANOID)
nx.set_iteration_count(200000)  # Double le nombre d'itérations PBKDF2 par défaut

private_key, public_key = nx.generate_rsa_keypair()
encrypted = nx.encrypt_data(secret_data, public_key)
```

### Utilisation de la stéganographie avec chiffrement

```python
# Chiffrement + stéganographie en une seule opération
nx.encrypt_and_hide(secret_data, public_key, "image.png", "output.png")

# Extraction et déchiffrement
decrypted = nx.extract_and_decrypt("output.png", private_key)
```

## FAQ

**Q: Quelle est la différence entre les niveaux de sécurité ?**
R: NyxCrypta offre différents niveaux de sécurité pour équilibrer performance et protection. Le niveau par défaut est suffisant pour la plupart des cas d'utilisation.

**Q: Puis-je utiliser NyxCrypta pour [cas d'utilisation spécifique] ?**
R: NyxCrypta est conçu pour être polyvalent. Contactez-nous pour discuter de cas d'utilisation spécifiques.

**Q: Comment NyxCrypta se compare-t-il aux autres solutions ?**
R: NyxCrypta utilise des algorithmes éprouvés tout en offrant des fonctionnalités uniques comme la stéganographie intégrée et des options avancées de configuration.

## Philosophie du projet

NyxCrypta a été développé avec les principes suivants :

1. **Sécurité par défaut** : Configurations sûres par défaut
2. **Flexibilité pour les experts** : Options avancées disponibles
3. **Discrétion et élégance** : Opérations cryptographiques sophistiquées

## Support et contribution

- 📚 [Documentation complète](https://nyxcrypta.readthedocs.io/)
- 🐛 [Signalement de bugs](https://github.com/nyxcrypta/issues)
- 💬 [Forum communautaire](https://community.nyxcrypta.com)

## Licence

NyxCrypta est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

*"La sécurité n'est pas un produit, mais un processus." - Bruce Schneier*
