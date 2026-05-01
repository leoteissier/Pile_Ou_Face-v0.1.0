# Pile ou Face

**Reverse engineering dans VS Code** — un outil d'analyse binaire intégré qui remplace IDA Pro et Ghidra.

Pile ou Face analyse des binaires ELF, PE et Mach-O (x86, x64, ARM64) directement dans VS Code via un hub interactif. Chargez un binaire, explorez ses fonctions, son désassemblage, son pseudo-C, et lancez des analyses de sécurité — le tout sans quitter votre éditeur.

---

## Ce que fait Pile ou Face

### Analyse du code

| Onglet | Description |
|--------|-------------|
| **Désassemblage** | Désassemblage Intel/AT&T avec coloration syntaxique et annotations |
| **CFG** | Graphe de flux de contrôle interactif (blocs de base + arcs) |
| **Call Graph** | Graphe d'appels — qui appelle qui dans le binaire |
| **Fonctions** | Découverte automatique de fonctions (y compris binaires strippés) |
| **Décompilateur** | Pseudo-C via retdec ou Ghidra, avec sélection de fonctions |
| **Hex View** | Dump hexadécimal avec coloration par section et patch de bytes |
| **Stack Frame** | Variables locales, paramètres et carte mémoire de la stack |
| **Binary Diff** | Comparaison de deux binaires — fonctions modifiées, ajoutées, supprimées |

### Données et métadonnées

| Onglet | Description |
|--------|-------------|
| **Strings** | Chaînes ASCII/UTF-8/UTF-16 extraites avec offset et section |
| **Symboles** | Table des symboles (fonctions, variables globales) |
| **Sections** | Sections du binaire (`.text`, `.data`, `.bss`…) avec taille et offset |
| **Infos** | Format, architecture, entry point, hashes MD5/SHA-256, packers |
| **Recherche** | Recherche par texte, hex ou regex dans les octets du binaire |

### Analyse malware

| Onglet | Description |
|--------|-------------|
| **Comportement** | Détection d'indicateurs malveillants (IPs, URLs, crypto, anti-VM) |
| **Taint** | Trace les flux de données dangereux (source → sink) |
| **Anti-analyse** | Détection de techniques anti-debug, VM detection, timing tricks |
| **Détection** | Scan YARA + CAPA (Mandiant) avec règles custom |

### Offensif

| Onglet | Description |
|--------|-------------|
| **ROP Gadgets** | Recherche de gadgets ROP (`pop rax ; ret`, `syscall ; ret`…) |
| **Vulnérabilités** | Détection de patterns CWE (gets, strcpy, system…) |
| **FLIRT** | Identification de fonctions de bibliothèques par signatures |
| **Déobfuscation** | Décodage automatique XOR/ROT sur les strings obfusquées |
| **Script** | Éditeur Python intégré avec API `pof` — remplace IDAPython |

---

## Installation

### Prérequis

- **Node.js** 18+
- **Python** 3.8+
- **git**

Support **Windows, macOS et Linux**. Détails : [docs/PLATFORMS.md](docs/PLATFORMS.md).

### Backend (Python)

```bash
make install
```

Installe les dépendances dans un venv (`lief`, `capstone`, `pyelftools`…).

### Extension (JavaScript)

```bash
cd extension
npm install
```

### Outils optionnels

| Outil | Pour quoi faire | Installation |
|-------|----------------|-------------|
| `retdec-decompiler` | Décompilation pseudo-C | [retdec releases](https://github.com/avast/retdec/releases) |
| `yara` | Scan YARA | `brew install yara` / `apt install yara` |
| `capa` | Analyse de capacités Mandiant | `pip install flare-capa` |

---

## Utilisation

1. Ouvrez VS Code avec l'extension Pile ou Face activée
2. **Ctrl+Shift+P** → `Pile ou Face: Hub`
3. Chargez un binaire (ELF, PE ou Mach-O)
4. Naviguez dans les onglets pour analyser

### Scripting

Le panneau **Script** (OFFENSIF → Script) permet d'écrire des scripts Python avec l'API `pof` :

```python
from pof import symbols, vulns, disasm

# Lister les fonctions
for s in symbols(binary)['data']:
    print(f"{s['addr']}  {s['name']}")

# Chercher des vulnérabilités
for v in vulns(binary)['data']['vulnerabilities']:
    print(f"{v['function']} — {v['cwe']}")
```

La variable `binary` est automatiquement injectée avec le chemin du binaire chargé.

---

## Structure du projet

```
Pile_Ou_Face/
├── extension/              # Extension VS Code (JavaScript)
│   ├── src/               # Logique extension + handlers
│   ├── webview/           # Hub (HTML, CSS, JS)
│   └── test/              # Tests Mocha
│
├── backends/              # Moteur d'analyse (Python)
│   ├── static/            # 30+ modules d'analyse statique
│   │   ├── pof/           # API Python unifiée (scripting)
│   │   └── tests/         # Tests pytest
│   ├── dynamic/           # Domaine dynamique
│   │   ├── core/          # Interfaces et types communs
│   │   ├── pipeline/      # Orchestration, modèle et enrichissements
│   │   ├── engine/        # Moteurs runtime concrets
│   │   └── tests/         # Tests du domaine dynamique
│   └── shared/            # Utilitaires partagés
│
├── examples/              # Exemples C pour tester
├── docs/                  # Documentation
│   ├── static/            # Doc des modules + roadmap
│   └── plans/             # Plans de features
├── scripts/               # Scripts de build/test
├── Makefile               # Build automation
└── requirements.txt       # Dépendances Python
```

---

## Commandes

```bash
make test              # Tous les tests (Python + JS)
make install           # Installer les dépendances Python
npm test -C extension  # Tests JS uniquement
npm run lint -C extension  # Linter
```

---

## Documentation

| Document | Contenu |
|----------|---------|
| [docs/static/README.md](docs/static/README.md) | Documentation complète des 30+ modules d'analyse |
| [docs/static/ROADMAP.md](docs/static/ROADMAP.md) | Roadmap et features à venir |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Vision, couches et responsabilités |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | Compatibilité Windows/macOS/Linux |

---

## Licence

MIT
