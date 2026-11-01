# Bleax Vault

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=flat-square&logo=windows)
![Backend](https://img.shields.io/badge/Rust-2021-000000?style=flat-square&logo=rust)
![Frontend](https://img.shields.io/badge/Tauri-v2-24C8DB?style=flat-square&logo=tauri)

**Bleax Vault** est un gestionnaire de secrets hors-ligne (*Air-Gapped*) pour Windows, conçu pour protéger les données sensibles dans des environnements exposés en espace utilisateur (*Ring 3*). Il combine un moteur cryptographique en Rust avec une interface React *Zero-Knowledge*, déportant toutes les opérations critiques vers des sous-systèmes natifs Win32 isolés.

Ce dépôt contient la version consolidée d'un projet développé et itéré en local sur plusieurs mois (prototypage des appels Win32, gestion mémoire bas niveau et architecture IPC) avant sa structuration finale pour publication.

## Avertissement de Sécurité

**NOTE :** Bleax Vault applique des mesures de défense en profondeur en espace utilisateur (*User-Mode*). Il ne couvre pas les scénarios où le noyau du système d'exploitation (*Ring 0*) est préalablement compromis.

## Fonctionnalités

### Cryptographie & Stockage
* Chiffrement par enveloppe hors-ligne via `XChaCha20-Poly1305` (format binaire `.vault`)
* Dérivation de clé `Argon2id` haute mémoire (512 Mo) et `HKDF-SHA256`
* Authentification à double facteur avec clé matérielle externe (`.bin`) liée à la machine hôte via DPAPI
* Génération et restauration de secours hors-ligne par phrase mnémonique BIP39 (24 mots)
* Générateur de mots de passe CSPRNG intégré (`OsRng`)
* Écriture atomique sur disque et détection de conflits de synchronisation

### Sécurité Système & Isolation (Win32)
* Architecture front-end *Zero-Knowledge* (aucun secret en clair dans le DOM ou le moteur JS)
* Chiffrement des clés maîtresses en RAM (`CryptProtectMemory`) et déchiffrement *Just-In-Time*
* Verrouillage des pages en mémoire physique (`VirtualLock`) et nettoyage systématique (`Zeroize`)
* Saisie et lecture des secrets dans des fenêtres natives isolées hors du navigateur
* Protection contre la capture d'écran et l'enregistrement vidéo (`WDA_EXCLUDEFROMCAPTURE`)
* Presse-papier natif exclu de l'historique système avec purge automatique temporisée
* Verrouillage automatique sur inactivité (*Watchdog*) et lors de la mise en veille/hibernation de l'OS
* Intégration navigateur (LibreWolf/Firefox) via Named Pipes et chiffrement de bout en bout (`ECDH P-256` / `AES-256-GCM`)

## Compilation (Build)

Pour compiler le binaire de production depuis le code source :

##### Prérequis :
* Windows 10 / 11 (x64)
* [Rust](https://www.rust-lang.org/) (`stable-x86_64-pc-windows-msvc`)
* [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC & Windows SDK)
* [Node.js](https://nodejs.org/) (LTS)

##### Télécharger et compiler :
```powershell
git clone https://github.com/Bleax-D-Hack/Bleax-Vault.git
cd Bleax-Vault
npm install
npm run tauri build

```

L'exécutable autonome sera généré dans `src-tauri/target/release/bleax-vault.exe`.