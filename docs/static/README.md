# Documentation — Analyse Statique (`backends/static/`)

## Documents rapides pour presentation

Si tu dois presenter la partie statique rapidement, commence par ces fichiers :

| Document | Usage |
|---|---|
| [PRESENTATION.md](PRESENTATION.md) | Vue d'ensemble claire de la partie statique, messages principaux et points forts |
| [DEMO.md](DEMO.md) | Parcours de demo pret a suivre, avec version 10 minutes et version 3 minutes |
| [SUPPORT_ORAL.md](SUPPORT_ORAL.md) | Notes de parole, pitch 30 secondes / 1 minute, plan oral et idees de slides |
| [FONCTIONNALITES.md](FONCTIONNALITES.md) | Liste complete des fonctionnalites par groupe `CODE`, `DATA`, `MALWARE`, `OFFENSIF` |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture statique : webview, extension VS Code, backend Python, cache et tests |
| [ROADMAP.md](ROADMAP.md) | Etat des features, reste a faire et ameliorations prevues |

---

Ce dossier décrit **tous les modules d'analyse statique** disponibles dans Pile ou Face.
Chaque module fonctionne en Python ou en CLI (`python -m backends.static.<module> --help`).

> **Pourquoi cette documentation ?**
> Pile ou Face est un outil de reverse engineering conçu pour remplacer IDA Pro et Ghidra.
> Ces modules constituent le moteur d'analyse — ils parsent, désassemblent, décompilent
> et inspectent des binaires ELF, PE et Mach-O sans quitter VS Code.

---

## Table des matières

1. [Informations binaire](#1-informations-binaire)
   - [headers.py](#headerspy) — type, arch, hashes, packers
   - [sections.py](#sectionspy) — sections ELF/PE/Mach-O
   - [symbols.py](#symbolspy) — fonctions et variables
   - [entropy.py](#entropypy) — entropie Shannon

2. [Analyse du code](#2-analyse-du-code)
   - [disasm.py](#disasmpy) — désassemblage
   - [cfg.py](#cfgpy) — graphe de flux de contrôle (CFG)
   - [call_graph.py](#call_graphpy) — graphe d'appels
   - [discover_functions.py](#discover_functionspy) — découverte de fonctions
   - [xrefs.py](#xrefspy) — cross-références
   - [stack_frame.py](#stack_framepy) — variables locales et stack frame

3. [Extraction de données](#3-extraction-de-données)
   - [strings.py](#stringspy) — chaînes lisibles
   - [search.py](#searchpy) — recherche binaire
   - [hex_view.py](#hex_viewpy) — dump hexadécimal

4. [Packers et obfuscation](#4-packers-et-obfuscation)
   - [packer_detect.py](#packer_detectpy) — détection de packers
   - [string_deobfuscate.py](#string_deobfuscatepy) — déobfuscation de strings

5. [Imports et signatures](#5-imports-et-signatures)
   - [imports_analysis.py](#imports_analysispy) — analyse des imports
   - [flirt.py](#flirtpy) — signatures FLIRT

6. [Décompilation](#6-décompilation)
   - [decompile.py](#decompilepy) — décompilateur (retdec / Ghidra)
   - [dwarf.py](#dwarfpy) — informations de debug DWARF

7. [Analyse malware](#7-analyse-malware)
   - [behavior.py](#behaviorpy) — analyse comportementale
   - [taint.py](#taintpy) — analyse de taint
   - [anti_analysis.py](#anti_analysispy) — techniques anti-analyse

8. [Offensif](#8-offensif)
   - [rop_gadgets.py](#rop_gadgetspy) — gadgets ROP
   - [vuln_patterns.py](#vuln_patternspy) — patterns de vulnérabilités
   - [bindiff.py](#bindiffpy) — comparaison de binaires (Binary Diff)

9. [Détection par règles](#9-détection-par-règles)
   - [yara_scan.py](#yara_scanpy) — scan YARA
   - [capa_scan.py](#capa_scanpy) — scan CAPA (Mandiant)
   - [rules_manager.py](#rules_managerpy) — gestion des règles

10. [Scripting](#10-scripting)
    - [pof/](#pof) — API Python unifiée
    - [repl.py](#replpy) — exécuteur de scripts intégré

11. [Utilitaires](#11-utilitaires)
    - [annotations.py](#annotationspy) — annotations persistantes
    - [offset_to_vaddr.py](#offset_to_vaddrpy) — conversion offset → adresse virtuelle
    - [asm_sim.py](#asm_simpy) — simulateur ASM
    - [binary_patch.py](#binary_patchpy) — patch de bytes
    - [export.py](#exportpy) — export CSV, JSON, DOT

---

## 1. Informations binaire

### `headers.py`

**Rôle** : Extrait les métadonnées essentielles d'un binaire (ELF, Mach-O, PE).

**Ce qu'il fait** :
- Détecte le format (ELF EXEC, DYN, PE AMD64, Mach-O ARM64…)
- Lit l'architecture (x86-64, ARM, AArch64…), le mode 32/64 bits
- Calcule l'adresse d'entry point
- Indique si le binaire est strippé (pas de symboles de fonctions)
- Calcule les hashes MD5 et SHA-256 du fichier
- Calcule l'imphash (PE uniquement) — compatible VirusTotal/IDA
- Lance automatiquement la détection de packers

**Output JSON** :
```json
{
  "path": "/tmp/sample.elf",
  "format": "ELF EXEC",
  "machine": "X86_64",
  "entry": "0x401000",
  "type": "EXEC",
  "bits": "64",
  "arch": "i386:x86-64",
  "stripped": "non",
  "interp": "/lib64/ld-linux-x86-64.so.2",
  "packers": "—",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha256": "e3b0c44298fc1c149afb...",
  "imphash": "a1b2c3..."
}
```

**CLI** :
```bash
python -m backends.static.headers --binary ./sample.exe --output info.json
```

**Dépendances** : `lief`

---

### `sections.py`

**Rôle** : Liste et localise toutes les sections du binaire.

**Ce qu'il fait** :
- Extrait nom, taille, offset fichier, adresse virtuelle de chaque section
- Fonctionne sur ELF (`.text`, `.data`, `.bss`, `.rodata`…), PE (`.text`, `.rdata`, `.rsrc`…), Mach-O (`__TEXT,__text`, `__DATA,__data`…)
- Expose `get_section_file_ranges()` utilisé par `strings.py` et `search.py` pour filtrer par section

**Output JSON** :
```json
[
  {"name": ".text",  "size": 4096, "offset": 4096,  "vaddr": "0x401000"},
  {"name": ".data",  "size": 512,  "offset": 8192,  "vaddr": "0x402000"},
  {"name": ".rodata","size": 256,  "offset": 8704,  "vaddr": "0x403000"}
]
```

**CLI** :
```bash
python -m backends.static.sections --binary ./sample.elf
```

**Dépendances** : `lief`

---

### `symbols.py`

**Rôle** : Extrait la table des symboles (fonctions, variables globales).

**Ce qu'il fait** :
- Lit la `symtab` ELF ou les exports/imports PE
- Retourne nom, adresse et type (`T`=code, `D`=data, `B`=bss, `U`=undefined)
- Option `defined_only=True` pour exclure les symboles externes
- Sert de base pour nommer les blocs dans le CFG et le call graph

**Output JSON** :
```json
[
  {"name": "main",       "addr": "0x401100", "type": "T"},
  {"name": "init_stuff", "addr": "0x401050", "type": "T"},
  {"name": "g_count",    "addr": "0x604010", "type": "D"}
]
```

**CLI** :
```bash
python -m backends.static.symbols --binary ./sample.elf
```

**Dépendances** : `lief`

---

### `entropy.py`

**Rôle** : Calcule l'entropie de Shannon du binaire et de chaque section.

**Ce qu'il fait** :
- Entropie globale sur tout le fichier (0.0 à 8.0 bits/byte)
- Entropie section par section via `lief`
- Détection de zones à haute entropie par sliding window (paramétrable)
- Une entropie > 7.2 indique généralement du code chiffré ou compressé (packed)

**Interpréter les valeurs** :
| Entropie | Signification |
|----------|---------------|
| < 5.0 | Code/données "normaux" |
| 5.0–7.0 | Zone compressée légèrement ou données mixtes |
| > 7.2 | Fortement suspect : code packagé, chiffré, shellcode |

**Output JSON** :
```json
{
  "global": 6.42,
  "sections": [
    {"name": ".text",   "entropy": 5.91, "size": 4096, "offset": 4096, "offset_hex": "0x1000"},
    {"name": ".upx0",   "entropy": 7.85, "size": 8192, "offset": 8192, "offset_hex": "0x2000"}
  ],
  "high_entropy_regions": [
    {"offset": 8192, "offset_hex": "0x2000", "entropy": 7.85}
  ],
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.entropy --binary ./packed.exe --threshold 7.0 --window 256
```

**Dépendances** : `lief` (pour sections), standard library seulement pour entropie globale

---

## 2. Analyse du code

### `disasm.py`

**Rôle** : Désassemble la section de code d'un binaire.

**Ce qu'il fait** :
- Utilise **Capstone** (désassembleur) + **LIEF** (parsing binaire)
- Auto-détecte l'architecture (x86-32/64, ARM, ARM64)
- Cherche automatiquement la section `.text` / `__text` / première section exécutable
- Génère un fichier `.asm` lisible (format objdump-like : `addr: bytes  mnemonic operands`)
- Génère un fichier JSON de mapping `addr → numéro de ligne`
- Support cache SQLite (`.pfdb`) pour éviter de recalculer

**Format de sortie `.asm`** :
```
  0x401000:  55                   push     rbp
  0x401001:  48 89 e5             mov      rbp, rsp
  0x401004:  48 83 ec 10          sub      rsp, 0x10
```

**Output JSON** :
```json
{
  "path": "output.asm",
  "binary": "/tmp/sample.elf",
  "lines": [
    {"addr": "0x401000", "text": "55                   push     rbp", "line": 1},
    {"addr": "0x401001", "text": "48 89 e5             mov      rbp, rsp", "line": 2}
  ]
}
```

**CLI** :
```bash
python -m backends.static.disasm \
  --binary ./sample.elf \
  --output ./sample.asm \
  --output-mapping ./mapping.json \
  --syntax intel \
  --section .text \
  --cache-db auto
```

**Dépendances** : `capstone`, `lief`

---

### `cfg.py`

**Rôle** : Construit le Graphe de Flux de Contrôle (CFG) d'une fonction.

**Ce qu'il fait** :
- Parse le désassemblage (sortie de `disasm.py`) pour identifier les blocs de base
- Détecte les instructions de branchement (jmp, je, jne, call, ret…) pour construire les arcs
- Retourne une liste de `BasicBlock` : séquence d'instructions sans branchement interne
- Chaque bloc connaît ses successeurs (blocs cibles des sauts)
- Sert de base à `xrefs.py` et au rendu SVG du hub

**Structure d'un BasicBlock** :
```python
BasicBlock(
    addr="0x401000",
    lines=[{"addr": "0x401000", "text": "push rbp", "line": 1}, ...],
    successors=["0x401010", "0x401020"],
    is_call=False
)
```

**Utilisation Python** :
```python
from backends.static.cfg import build_cfg
blocks = build_cfg(asm_lines, start_addr="0x401000")
```

**Dépendances** : `lief` (optionnel, pour résolution PLT), output de `disasm.py`

---

### `call_graph.py`

**Rôle** : Construit le graphe d'appels (qui appelle qui).

**Ce qu'il fait** :
- Analyse toutes les instructions `call` dans le désassemblage
- Résout les appels indirects PLT/GOT (ELF) et stubs dyld (Mach-O)
- Retourne un graphe `{caller_addr: [callee_addr, ...]}` avec noms de symboles
- Permet de voir les dépendances entre fonctions et d'identifier les fonctions centrales
- Rendu en SVG interactif dans le hub

**Output JSON** :
```json
{
  "nodes": [
    {"addr": "0x401100", "name": "main"},
    {"addr": "0x401050", "name": "init_stuff"},
    {"addr": "0x0",      "name": "printf@plt"}
  ],
  "edges": [
    {"from": "0x401100", "to": "0x401050"},
    {"from": "0x401100", "to": "printf@plt"}
  ]
}
```

**CLI** :
```bash
python -m backends.static.call_graph \
  --asm ./sample.asm \
  --binary ./sample.elf \
  --output callgraph.json
```

**Dépendances** : `lief`, output de `disasm.py`

---

### `discover_functions.py`

**Rôle** : Découvre des fonctions non listées dans la table des symboles.

**Ce qu'il fait** :
- Scanne le désassemblage pour des **prologues typiques** :
  - x86/x64 : `push rbp`, `sub rsp, 0x...`, `endbr64`
  - ARM64 : `stp x29, x30, [sp, ...]`, `sub sp, sp, ...`
- Utilise aussi des **seeds binaires** : entrypoint, `.pdata` PE, DWARF, signatures FLIRT
- Parcourt récursivement les fonctions seeds pour promouvoir les **cibles d'appels directs**, les **tail-calls** et les **thunks**
- Filtre les adresses déjà connues (symboles existants)
- Estime des métadonnées utiles : `kind`, `confidence`, `confidence_score`, `size`, `end_addr`, `target_addr` pour les thunks
- Utile sur les binaires strippés où la table des symboles est absente

**Output JSON** :
```json
[
  {
    "addr": "0x401050",
    "name": "sub_401050",
    "kind": "function",
    "confidence": "high",
    "confidence_score": 0.86,
    "reason": "push rbp",
    "end_addr": "0x40106a",
    "size": 26
  },
  {
    "addr": "0x401200",
    "name": "sub_401200",
    "kind": "thunk",
    "confidence": "high",
    "confidence_score": 0.91,
    "reason": "call_target_thunk",
    "target_addr": "0x402000",
    "end_addr": "0x401205",
    "size": 5
  }
]
```

**CLI** :
```bash
python -m backends.static.discover_functions \
  --mapping ./sample.disasm.mapping.json \
  --binary ./sample.elf
```

**Dépendances** : output de `disasm.py`

---

### `xrefs.py`

**Rôle** : Trouve toutes les références croisées vers une adresse (qui jump/call à cette adresse ?).

**Ce qu'il fait** :
- Parse le désassemblage et collecte tous les sauts (`jmp`, `je`, `jne`…) et appels (`call`)
- Pour une adresse cible donnée, retourne tous les sites qui la référencent
- Supporte aussi les références de données (`lea`, `mov` vers une adresse)
- Indispensable pour analyser comment une fonction est utilisée

**Output JSON** :
```json
[
  {"from_addr": "0x401120", "type": "call",  "text": "call 0x401050"},
  {"from_addr": "0x401200", "type": "jmp",   "text": "jmp  0x401050"},
  {"from_addr": "0x401310", "type": "data",  "text": "lea  rax, [0x401050]"}
]
```

**Utilisation Python** :
```python
from backends.static.xrefs import find_xrefs
refs = find_xrefs(asm_lines, target_addr="0x401050")
```

**Dépendances** : output de `disasm.py`

---

### `stack_frame.py`

**Rôle** : Analyse le stack frame d'une fonction — identifie les variables locales et les paramètres.

**À quoi ça sert ?**
Quand on regarde du désassemblage, on voit `[rbp-0x8]`, `[rbp-0x10]`… mais ça ne dit pas à quoi correspondent ces offsets. Ce module transforme ces adresses en noms lisibles (`var_8`, `arg_0`) et reconstruit la carte mémoire de la stack pour comprendre la structure d'une fonction.

**Ce qu'il fait** :
- Désassemble la fonction (max 512 instructions via Capstone)
- Détecte le prologue (`sub rsp, N`) pour calculer la taille du frame
- Collecte les accès stack : `[rbp-N]` → variables locales, `[rbp+N]` → arguments
- Nomme automatiquement : `var_8`, `var_10` (locales) et `arg_0`, `arg_8` (paramètres)
- Enrichit avec les infos DWARF si `pyelftools` est installé (noms réels du code source)

**Output JSON** :
```json
{
  "func_addr": "0x401000",
  "frame_size": 32,
  "vars": [
    {"name": "var_8",  "offset": -8,  "size": 8, "dwarf_name": "count"},
    {"name": "var_10", "offset": -16, "size": 8, "dwarf_name": null}
  ],
  "args": [
    {"name": "arg_0", "offset": 16, "size": 8, "dwarf_name": "argc"}
  ]
}
```

**CLI** :
```bash
python -m backends.static.stack_frame --binary ./sample.elf --addr 0x401000
```

**Dépendances** : `capstone`, `lief`, `pyelftools` (optionnel pour DWARF)

---

## 3. Extraction de données

### `strings.py`

**Rôle** : Extrait les chaînes de caractères lisibles d'un binaire.

**Ce qu'il fait** :
- Cherche les séquences de caractères ASCII/UTF-8/UTF-16 de longueur ≥ N (défaut : 4)
- Peut filtrer à une section spécifique (`--section .rodata`)
- Retourne offset fichier, adresse hex et valeur de la string
- Utile pour trouver des URLs, clés, messages d'erreur, commandes shell

**Output JSON** :
```json
[
  {"addr": "0x3010", "value": "https://evil.com/c2", "length": 19},
  {"addr": "0x3025", "value": "cmd.exe /c whoami",   "length": 17},
  {"addr": "0x3038", "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "length": 43}
]
```

**CLI** :
```bash
python -m backends.static.strings \
  --binary ./sample.exe \
  --min-len 6 \
  --encoding utf-16-le \
  --section .rdata
```

**Dépendances** : `lief` (pour filtrage par section, optionnel)

---

### `search.py`

**Rôle** : Recherche un pattern dans les octets du binaire.

**Ce qu'il fait** :
- 3 modes de recherche :
  - `text` : chaîne ASCII/UTF-8 (ex: `"password"`)
  - `hex` : octets hexadécimaux (ex: `"41424344"`)
  - `regex` : expression régulière Python (ex: `"\\x90{4,}"` pour trouver des NOPs)
- Peut limiter la recherche à une section
- Retourne offset, offset hex et contexte (16 octets autour)

**Output JSON** :
```json
[
  {
    "offset": 4096,
    "offset_hex": "0x1000",
    "value": "password",
    "context": "...6c 6f 67 69 6e 3a 70 61 73 73..."
  }
]
```

**CLI** :
```bash
# Recherche texte
python -m backends.static.search --binary ./sample.elf --pattern "secret" --mode text

# Recherche hex (magic bytes)
python -m backends.static.search --binary ./sample.elf --pattern "4d5a9000" --mode hex

# Regex (NOP sled)
python -m backends.static.search --binary ./sample.elf --pattern "\\x90{10,}" --mode regex
```

**Dépendances** : `lief` (pour filtrage par section, optionnel)

---

### `hex_view.py`

**Rôle** : Produit un dump hexadécimal du binaire avec les métadonnées de sections.

**À quoi ça sert ?**
Le hex view est la vue fondamentale du reverse engineering — il montre les octets bruts du fichier avec leur correspondance ASCII. C'est indispensable pour repérer des magic bytes, des structures de données, du shellcode, ou simplement voir ce qui se trouve à un offset précis.

**Ce qu'il fait** :
- Découpe le binaire en lignes de 16 octets (format `xxd` / ImHex)
- Affiche chaque ligne : offset hex, octets hex, représentation ASCII
- Enrichit avec les infos de sections (`lief`) : nom, type (`code`, `data`, `bss`)
- Supporte la pagination (offset + longueur) pour les gros binaires
- Coloration par type de section dans le hub (`.text` en bleu, `.data` en vert)

**Output JSON** :
```json
{
  "rows": [
    {"offset": 0, "hex": "7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00", "ascii": ".ELF............"},
    {"offset": 16, "hex": "03 00 3e 00 01 00 00 00 40 10 40 00 00 00 00 00", "ascii": "..>....@.@....."}
  ],
  "sections": [
    {"name": ".text", "offset": 4096, "size": 1024, "type": "code"}
  ],
  "total_size": 8192
}
```

**CLI** :
```bash
python -m backends.static.hex_view --binary ./sample.elf --offset 0x1000 --length 256
```

**Dépendances** : `lief` (optionnel, pour les métadonnées de sections)

---

## 4. Packers et obfuscation

### `packer_detect.py`

**Rôle** : Détecte si le binaire est packé (UPX, ASPack, Themida…).

**Ce qu'il fait** : 3 méthodes combinées :

1. **Signatures bytes** : recherche de séquences caractéristiques de 18 packers connus :
   - UPX (`UPX!`, `UPX0`, `UPX1`), ASPack, MPRESS, PECompact, FSG, Themida, Enigma, MEW, NsPack, PESpin, Obsidium

2. **Heuristique entropie** : section avec entropie ≥ 7.2 bits/byte et taille > 512 octets
   → indique du code chiffré ou compressé

3. **Anomalies PE** : `SizeOfRawData` >> `VirtualSize` (ratio > 1.5)
   → pattern typique de données compressées dans un PE

**Score** : 0–100 (40 pts par packer trouvé + 5 pts par indicateur brut)

**Output JSON** :
```json
{
  "packers": [
    {
      "name": "UPX",
      "confidence": "high",
      "offsets": [{"signature": "UPX!", "offset": "0x1234"}],
      "reason": "signature"
    }
  ],
  "score": 45,
  "raw": ["UPX détecté (3 occurrence(s) de signature)"],
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.packer_detect --binary ./packed.exe --json
```

**Dépendances** : `backends.static.entropy` (pour heuristique entropie)

---

### `string_deobfuscate.py`

**Rôle** : Tente de déobfusquer les strings encodées par XOR ou ROT.

**Ce qu'il fait** :
- Extrait des régions de bytes non-ASCII (longueur ≥ 6) comme candidats
- **Brute-force XOR** : teste toutes les clés XOR 0x01–0xFF, valide si ≥ 4 caractères imprimables
- **Brute-force ROT** : teste ROT-1 à ROT-25, valide par fréquences de lettres anglaises + mots communs
- Calcule un score de confiance basé sur les fréquences de lettres anglaises

**Méthodes** :
| Méthode | Description | Cas d'usage |
|---------|-------------|-------------|
| `xor_single` | Clé XOR d'1 byte (0x01–0xFF) | Obfuscation simple |
| `rot_N` | Décalage César (1–25) | Scripts, malware simple |

**Output JSON** :
```json
[
  {
    "addr": "0x3050",
    "raw_hex": "68 65 6c 6c 6f",
    "decoded": "hello",
    "method": "xor_single(key=0x00)",
    "confidence": 0.85
  }
]
```

**CLI** :
```bash
python -m backends.static.string_deobfuscate --binary ./obfuscated.bin
```

**Dépendances** : standard library uniquement

---

## 5. Imports et signatures

### `imports_analysis.py`

**Rôle** : Analyse les fonctions importées et détecte les patterns suspects.

**Ce qu'il fait** :
- Extrait tous les imports (DLL + fonction pour PE, symboles pour ELF/Mach-O)
- Regroupe par DLL
- Détecte les **fonctions dangereuses** dans 8 catégories :

| Catégorie | Exemples | Score |
|-----------|----------|-------|
| INJECTION | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | 25 pts |
| ANTI_DEBUG | `IsDebuggerPresent`, `NtQueryInformationProcess` | 20 pts |
| SHELLCODE | `VirtualProtect`, `mprotect`, `mmap` | 15 pts |
| PERSISTENCE | `RegSetValueEx`, `CreateService` | 15 pts |
| EXECUTION | `CreateProcess`, `WinExec`, `system`, `execve` | 10 pts |
| PRIVILEGE | `AdjustTokenPrivileges`, `OpenProcessToken` | 10 pts |
| NETWORK | `WSAStartup`, `socket`, `connect`, `URLDownloadToFile` | 5 pts |
| CRYPTO | `CryptEncrypt`, `BCryptDecrypt` | 5 pts |

**Output JSON** :
```json
{
  "imports": [
    {"dll": "kernel32.dll", "functions": ["CreateRemoteThread", "VirtualAllocEx"], "count": 2}
  ],
  "suspicious": [
    {"function": "CreateRemoteThread", "dll": "kernel32.dll", "category": "INJECTION",
     "description": "Crée un thread dans un autre processus"}
  ],
  "score": 45,
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.imports_analysis --binary ./malware.exe --threshold 30
```

**Dépendances** : `lief`

---

### `flirt.py`

**Rôle** : Identifie des fonctions de bibliothèques connues par correspondance de signatures (FLIRT-like).

**Ce qu'il fait** :
- Charge une base de signatures depuis `backends/static/data/flirt_sigs.json`
- Chaque signature : `{name, lib, pattern, offset}` où `pattern` est une séquence hex avec wildcards `??`
- Scanne les bytes du binaire pour trouver des correspondances
- Retourne nom, bibliothèque source, adresse et confiance

**Signatures incluses** : `malloc`, `free`, `strlen`, `memcpy`, `printf` (libc), `RC4_set_key` (OpenSSL)

**Format d'une signature** :
```json
{
  "name": "strlen",
  "lib": "libc",
  "pattern": "48 85 ff 74 ?? 48 89 f8",
  "offset": 0
}
```

**Output JSON** :
```json
[
  {"addr": "0x401234", "name": "strlen", "lib": "libc",   "confidence": "high"},
  {"addr": "0x401300", "name": "printf", "lib": "libc",   "confidence": "medium"}
]
```

**CLI** :
```bash
python -m backends.static.flirt --binary ./sample.elf
```

**Dépendances** : standard library uniquement

---

## 6. Décompilation

### `decompile.py`

**Rôle** : Décompile le binaire ou une fonction spécifique en pseudo-C via retdec.

**Ce qu'il fait** :
- Vérifie la disponibilité de `retdec-decompiler` (outil externe)
- Lance `retdec-decompiler` dans un répertoire temporaire
- Parse la sortie `.c` en séparant les fonctions par leurs commentaires d'adresse
- Mode `--addr` : décompile une seule fonction à l'adresse donnée
- Mode `--full` : décompile tout le binaire et retourne toutes les fonctions

**Prérequis** : [retdec](https://github.com/avast/retdec) doit être installé et dans le PATH

**Output JSON (fonction)** :
```json
{
  "addr": "0x401000",
  "code": "int32_t main(int argc, char ** argv) {\n    return 0;\n}",
  "error": null
}
```

**Output JSON (binaire complet)** :
```json
{
  "functions": [
    {"addr": "0x401000", "code": "int32_t main(...) { ... }"},
    {"addr": "0x401050", "code": "void init_stuff(...) { ... }"}
  ],
  "error": null
}
```

**CLI** :
```bash
# Décompiler une fonction spécifique
python -m backends.static.decompile --binary ./sample.elf --addr 0x401000

# Décompiler tout le binaire
python -m backends.static.decompile --binary ./sample.elf --full
```

**Dépendances** : `retdec-decompiler` (CLI externe)

---

### `dwarf.py`

**Rôle** : Extrait les informations de debug DWARF depuis un binaire ELF.

**À quoi ça sert ?**
Quand un binaire est compilé avec `-g` (mode debug), il contient des infos DWARF : les vrais noms de variables, les types (struct, union…), les adresses de chaque fonction. Ce module les extrait pour enrichir les autres analyses (désassemblage, décompilation, stack frame) avec les noms réels du code source.

**Ce qu'il fait** :
- Parse les sections `.debug_info` via `pyelftools`
- Extrait les fonctions : nom, adresse de début (`low_pc`), adresse de fin (`high_pc`), type de retour
- Extrait les types composites : structures, unions, types de base avec leurs membres
- Extrait les variables globales : nom, type, adresse

**Output JSON** :
```json
{
  "functions": [
    {"name": "main", "low_pc": "0x401000", "high_pc": "0x4010a0", "return_type": "int"}
  ],
  "types": [
    {"kind": "struct", "name": "player_t", "byte_size": 24,
     "members": [{"name": "name", "type": "char *", "offset": 0},
                 {"name": "score", "type": "int", "offset": 16}]}
  ],
  "variables": [
    {"name": "g_level", "type": "int", "addr": "0x604020"}
  ],
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.dwarf --binary ./sample_debug.elf
```

**Dépendances** : `pyelftools` (`pip install pyelftools`)

---

## 7. Analyse malware

### `behavior.py`

**Rôle** : Analyse comportementale statique — détecte les patterns malveillants dans les données du binaire.

**Ce qu'il fait** : Analyse les bytes bruts du binaire pour 5 catégories d'indicateurs :

| Catégorie | Méthode | Exemples d'indicateurs |
|-----------|---------|----------------------|
| `NETWORK` | Regex sur bytes | Adresses IP (regex RFC), URLs `http://...` |
| `CRYPTO` | Signature bytes | Préfixe AES S-box (`63 7c 77 7b f2 6b 6f c5`) |
| `EVASION` | Recherche strings | `vmware`, `virtualbox`, `vbox`, `qemu`, `sandbox`, `cuckoo`, `wireshark` |
| `PERSISTENCE` | Recherche patterns | Chemins registre Windows, chemins crontab Linux |
| `EXFILTRATION` | Combinaison | Présence simultanée NETWORK + CRYPTO |

**Score de sévérité** :
| Sévérité | Points |
|----------|--------|
| LOW | 5 |
| MEDIUM | 15 |
| HIGH | 25 |
| CRITICAL | 40 |

**Output JSON** :
```json
{
  "indicators": [
    {"category": "NETWORK",    "evidence": "http://192.168.1.1/payload", "severity": "HIGH",   "addr": "0x3020"},
    {"category": "EVASION",    "evidence": "vmware",                      "severity": "MEDIUM", "addr": "0x3100"},
    {"category": "PERSISTENCE","evidence": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "severity": "HIGH", "addr": "0x3150"}
  ],
  "score": 65,
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.behavior --binary ./malware.exe
```

**Dépendances** : standard library uniquement

---

### `taint.py`

**Rôle** : Analyse de taint simplifiée — trace les flux de données dangereuses (sources → sinks).

**Ce qu'il fait** :
- Extrait les imports du binaire via `lief`
- **Sources** (données potentiellement contrôlées par l'utilisateur) :
  `argv`, `envp`, `read`, `recv`, `recvfrom`, `fgets`, `scanf`, `fscanf`, `getenv`, `gets`
- **Sinks** (fonctions dangereuses) :
  `system`, `execve`, `execvp`, `execl`, `popen`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `printf`
- Génère tous les flux source → sink présents dans le binaire
- Attribue une confiance (`HIGH`/`MEDIUM`/`LOW`) selon la dangerosité de la paire

**Paires à haute confiance** :
| Source | Sink | Risque |
|--------|------|--------|
| `gets` | `strcpy` | Buffer overflow garanti |
| `scanf` | `system` | Injection de commande |
| `recv` | `system` | RCE réseau |
| `getenv` | `system` | Variable d'environnement malicieuse |

**Output JSON** :
```json
{
  "flows": [
    {"source_fn": "recv",   "sink_fn": "system", "confidence": "HIGH"},
    {"source_fn": "fgets",  "sink_fn": "sprintf","confidence": "MEDIUM"},
    {"source_fn": "scanf",  "sink_fn": "strcpy", "confidence": "MEDIUM"}
  ],
  "risk_score": 85,
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.taint --binary ./vuln_server.elf
```

**Dépendances** : `lief`

---

### `anti_analysis.py`

**Rôle** : Détecte les techniques anti-analyse (anti-debug, détection VM, timing).

**Ce qu'il fait** : 3 catégories de détection :

1. **VM strings** — recherche en bytes des strings VM connues :
   `vmware`, `virtualbox`, `vbox`, `qemu`, `sandbox`, `cuckoo`, `wireshark`

2. **Timing (RDTSC/CPUID)** — détecte les opcodes de timing :
   - `RDTSC` (`0F 31`) : lit le compteur TSC pour mesurer le temps (détecte émulateurs lents)
   - `CPUID` (`0F A2`) : interroge le CPU (peut révéler une VM)

3. **Imports anti-debug** — via `lief` :
   `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`

**Chaque détection inclut un bypass suggéré** (ex: "Patcher la comparaison de string", "NOP le RDTSC").

**Output JSON** :
```json
[
  {
    "technique":   "VM_DETECTION",
    "description": "VM string: VMware détecté",
    "bypass":      "Patch la comparaison de string",
    "confidence":  "HIGH",
    "addr":        "0x3042"
  },
  {
    "technique":   "TIMING_RDTSC",
    "description": "RDTSC utilisé pour timing check",
    "bypass":      "NOP les instructions RDTSC (0F 31)",
    "confidence":  "MEDIUM",
    "addr":        "0x1234"
  }
]
```

**CLI** :
```bash
python -m backends.static.anti_analysis --binary ./malware.exe
```

**Dépendances** : `lief` (pour détection anti-debug via imports)

---

## 8. Offensif

### `rop_gadgets.py`

**Rôle** : Recherche des gadgets ROP (Return-Oriented Programming) dans les sections exécutables.

**Ce qu'il fait** :
- Scanne les bytes exécutables pour les instructions `ret` (`0xC3`) et `ret N` (`0xC2`)
- Pour chaque `ret`, remonte jusqu'à 20 bytes en arrière (lookback)
- Désassemble via **Capstone** et reconstruit les gadgets (1 à `max_insns` instructions)
- Classe chaque gadget :

| Type | Description | Exemple |
|------|-------------|---------|
| `pop_ret` | Charge une valeur depuis la stack | `pop rax ; ret` |
| `syscall` | Appel système direct | `syscall ; ret` ou `int 0x80 ; ret` |
| `pivot` | Pivot de stack (xchg rsp) | `xchg rsp, rax ; ret` |
| `arithmetic` | Opération arithmétique | `add rax, rbx ; ret` |
| `load_store` | Accès mémoire | `mov [rax], rbx ; ret` |
| `generic` | Gadget générique | `nop ; ret` |

**Output JSON** :
```json
[
  {
    "addr":         "0x401234",
    "instructions": ["pop rax", "ret"],
    "type":         "pop_ret",
    "regs_modified": ["rax"]
  },
  {
    "addr":         "0x401300",
    "instructions": ["syscall", "ret"],
    "type":         "syscall",
    "regs_modified": []
  }
]
```

**CLI** :
```bash
python -m backends.static.rop_gadgets \
  --binary ./vuln.elf \
  --arch x86_64 \
  --max-insns 5
```

**Dépendances** : `capstone` (optionnel mais recommandé), `lief` (pour localiser les sections exec)

---

### `vuln_patterns.py`

**Rôle** : Détecte les patterns de vulnérabilités connues (CWE) via les imports.

**Ce qu'il fait** :
- Extrait les imports via `lief`
- Cherche les fonctions classiquement vulnérables avec leur CWE associé :

| Fonction | Type | Sévérité | CWE |
|----------|------|----------|-----|
| `gets` | STACK_OVERFLOW | HIGH | CWE-121 |
| `strcpy` | STACK_OVERFLOW | HIGH | CWE-121 |
| `strcat` | STACK_OVERFLOW | HIGH | CWE-121 |
| `sprintf` | STACK_OVERFLOW | HIGH | CWE-121 |
| `scanf` | STACK_OVERFLOW | MEDIUM | CWE-121 |
| `system` | COMMAND_INJECTION | CRITICAL | CWE-78 |
| `popen` | COMMAND_INJECTION | CRITICAL | CWE-78 |
| `execve` | COMMAND_INJECTION | CRITICAL | CWE-78 |

**Output JSON** :
```json
{
  "vulnerabilities": [
    {
      "type":        "STACK_OVERFLOW",
      "severity":    "HIGH",
      "description": "gets() sans limite de taille",
      "cwe":         "CWE-121",
      "addr":        null,
      "function":    "gets"
    }
  ],
  "count": 1,
  "error": null
}
```

**CLI** :
```bash
python -m backends.static.vuln_patterns --binary ./vuln_app.elf
```

**Dépendances** : `lief`

---

### `bindiff.py`

**Rôle** : Compare deux binaires au niveau des fonctions — équivalent open-source de BinDiff.

**À quoi ça sert ?**
Quand on analyse un patch de sécurité, une nouvelle version d'un malware ou une variante obfusquée, on veut savoir **ce qui a changé** entre deux binaires. Ce module identifie les fonctions ajoutées, supprimées et modifiées, avec un pourcentage de similarité pour chaque fonction.

**Ce qu'il fait** :

1. **Phase 1 — Matching par noms** : si les symboles sont disponibles, fait correspondre les fonctions par leur nom
2. **Phase 2 — Hash de basic blocks** : pour les binaires strippés, découpe chaque fonction en blocs de base, les hash, et calcule la similarité Jaccard
3. **Diff détaillé** : pour les fonctions modifiées, produit un diff ligne par ligne du désassemblage
4. **Statistiques globales** : nombre de fonctions identiques / modifiées / ajoutées / supprimées

**Architectures supportées** : x86, x86-64, ARM64 (AArch64)

**Output JSON** :
```json
{
  "ok": true,
  "functions": [
    {"name": "main",    "status": "modified", "similarity": 0.857},
    {"name": "win",     "status": "modified", "similarity": 0.667},
    {"name": "helper",  "status": "identical", "similarity": 1.0},
    {"name": "new_fn",  "status": "added",    "similarity": 0.0}
  ],
  "stats": {
    "identical": 1, "modified": 2, "added": 1, "removed": 0, "total_a": 3, "total_b": 4
  }
}
```

**CLI** :
```bash
python -m backends.static.bindiff \
  --binary-a ./v1.elf \
  --binary-b ./v2.elf \
  --threshold 0.6
```

**Cas d'usage** :
- Analyse de patches CVE : qu'est-ce qui a été corrigé entre deux versions ?
- Variantes malware : comparer deux samples d'une même famille
- Before/after obfuscation : mesurer l'impact d'un obfuscateur

**Dépendances** : `capstone`, `lief`

---

## 9. Détection par règles

### `yara_scan.py`

**Rôle** : Applique des règles YARA sur un binaire pour identifier des familles de malware.

**Ce qu'il fait** :
- Vérifie la disponibilité de la CLI `yara` (outil externe)
- Charge les règles depuis :
  1. Un chemin explicite (`rules_path`)
  2. Les règles custom du projet (`.pile-ou-face/rules/yara/`)
  3. Un fichier de config global
- Lance `yara` via subprocess avec timeout (défaut 60s)
- Parse la sortie pour extraire les règles qui ont matché

**Format des règles YARA** :
```yara
rule UPX_Packer {
    strings:
        $upx = "UPX!"
    condition:
        $upx
}
```

**Output** :
```json
[
  {"rule": "UPX_Packer", "tags": [], "meta": {}, "strings": [{"offset": 0x1234, "id": "$upx"}]}
]
```

**CLI** :
```bash
python -m backends.static.yara_scan \
  --binary ./sample.exe \
  --rules ./my_rules.yar
```

**Prérequis** : `yara` CLI installée (`brew install yara` / `apt install yara`)

**Dépendances** : `yara` CLI (externe)

---

### `capa_scan.py`

**Rôle** : Analyse les capacités d'un binaire avec Mandiant capa.

**Ce qu'il fait** :
- Vérifie la disponibilité de `capa` CLI
- Clone automatiquement `capa-rules` (Mandiant) si absent
- Lance `capa --json` et parse la sortie
- Identifie les **capacités** du binaire :
  chiffrement, sockets réseau, création de processus, persistance, exfiltration, UAC bypass…
- Retourne des résultats structurés avec ATT&CK mappings

**Cas d'usage typique** :
> "Ce binaire peut : créer des sockets TCP, écrire dans le registre Windows, créer des threads distants"

**Output JSON** :
```json
{
  "capabilities": [
    {
      "name":        "create remote thread",
      "namespace":   "host-interaction/process/inject",
      "attack":      [{"technique": "T1055", "tactic": "Defense Evasion"}],
      "matches":     2
    }
  ],
  "error": null
}
```

**Prérequis** : `capa` CLI installée (`pip install flare-capa`)

---

### `rules_manager.py`

**Rôle** : Gestionnaire centralisé des règles YARA et CAPA par projet.

**Ce qu'il fait** :
- Stocke les règles dans `.pile-ou-face/rules/` (dans le projet)
- Gère un fichier de config `rules-config.json` (activer/désactiver les règles)
- Supporte un config global (partagé entre projets)
- Opérations : `list`, `toggle`, `add`, `delete`

**Structure de répertoire** :
```
projet/
└── .pile-ou-face/
    ├── rules-config.json
    └── rules/
        ├── yara/
        │   ├── my_rule.yar
        │   └── ransomware_detect.yar
        └── capa/
            └── custom_capability.yml
```

**CLI** :
```bash
# Lister les règles
python -m backends.static.rules_manager list --cwd /projet

# Activer/désactiver une règle
python -m backends.static.rules_manager toggle \
  --rule-id my_rule --enabled false --cwd /projet

# Ajouter une règle
python -m backends.static.rules_manager add \
  --name detect_upx --type yara \
  --content 'rule UPX { strings: $u="UPX!" condition: $u }' \
  --cwd /projet

# Supprimer une règle
python -m backends.static.rules_manager delete --rule-id detect_upx --cwd /projet
```

---

## 10. Scripting

### `pof/`

**Rôle** : API Python unifiée pour accéder à tous les backends depuis un script.

**À quoi ça sert ?**
C'est le cœur du système de scripting. Au lieu d'appeler chaque backend manuellement en CLI, `pof` expose une API Python simple : `from pof import symbols, disasm, decompile`. C'est l'équivalent d'IDAPython — un module qui donne accès à toute la puissance de l'outil depuis un script.

**Fonctions disponibles** :

| Fonction | Backend | Description |
|----------|---------|-------------|
| `pof.symbols(binary)` | `symbols.py` | Liste des symboles (fonctions, variables) |
| `pof.disasm(binary, addr?)` | `disasm.py` | Désassemblage du binaire |
| `pof.decompile(binary, addr?)` | `decompile.py` | Décompilation en pseudo-C |
| `pof.xrefs(binary, addr)` | `xrefs.py` | Cross-références vers une adresse |
| `pof.strings(binary)` | `strings.py` | Chaînes de caractères extraites |
| `pof.sections(binary)` | `sections.py` | Sections du binaire |
| `pof.info(binary)` | `headers.py` | Métadonnées (format, arch, hashes) |
| `pof.cfg(binary, addr)` | `cfg.py` | Graphe de flux de contrôle |
| `pof.rop(binary)` | `rop_gadgets.py` | Gadgets ROP |
| `pof.behavior(binary)` | `behavior.py` | Analyse comportementale |
| `pof.taint(binary)` | `taint.py` | Analyse de taint |
| `pof.vulns(binary)` | `vuln_patterns.py` | Vulnérabilités CWE |
| `pof.flirt(binary)` | `flirt.py` | Signatures FLIRT |
| `pof.bindiff(a, b, threshold?)` | `bindiff.py` | Comparaison de binaires |
| `pof.deobfuscate(binary)` | `string_deobfuscate.py` | Désobfuscation XOR/ROT |

**Usage** :
```python
from pof import symbols, disasm, vulns

# Lister les fonctions
syms = symbols("/tmp/sample.elf")
for s in syms['data']:
    print(f"{s['addr']}  {s['name']}")

# Chercher des vulnérabilités
result = vulns("/tmp/sample.elf")
for v in result['data']['vulnerabilities']:
    print(f"⚠️  {v['function']} — {v['cwe']}")
```

Chaque fonction appelle son backend en subprocess et retourne `{'ok': True, 'data': ...}` ou `{'ok': False, 'error': '...'}`.

---

### `repl.py`

**Rôle** : Exécuteur de scripts Python intégré — le moteur derrière le panneau Script du hub.

**À quoi ça sert ?**
C'est le backend qui fait tourner les scripts écrits dans l'éditeur du hub. Il reçoit du code Python encodé en base64, l'exécute dans un environnement isolé avec la variable `binary` pré-injectée et le module `pof` disponible, puis renvoie stdout/stderr au format JSON.

**Ce qu'il fait** :
- Reçoit le code en base64 (évite les problèmes d'échappement shell)
- Injecte la variable `binary` (chemin du binaire chargé dans le hub)
- Rend le module `pof` importable
- Capture stdout et stderr séparément
- Mesure le temps d'exécution
- Timeout de 30s par défaut

**Interface CLI** :
```bash
python3 repl.py --code <base64_encoded_script> --binary /path/to/binary
```

**Output JSON** :
```json
{"ok": true, "stdout": "main\nwin\ncheck_password\n", "stderr": "", "duration_ms": 42}
```

En cas d'erreur :
```json
{"ok": false, "stdout": "", "stderr": "NameError: name 'foo' is not defined", "duration_ms": 5}
```

**Dépendances** : standard library uniquement (les dépendances de `pof` sont chargées au runtime)

---

## 11. Utilitaires

### `annotations.py`

**Rôle** : Stocke des annotations persistantes (commentaires, renommages) sur les adresses d'un binaire.

**Ce qu'il fait** :
- Stocke les annotations dans le cache SQLite `.pfdb` interne sous `.pile-ou-face/pfdb/`
- 2 types d'annotation : `comment` (texte libre) et `rename` (alias de fonction)
- Les annotations persistent entre sessions et sont liées au binaire par son chemin
- Façade haut niveau sur `DisasmCache`

**Interface Python** :
```python
from backends.static.annotations import AnnotationStore

with AnnotationStore("/path/to/binary.elf") as store:
    store.comment("0x401000", "entry point — initialise le stack frame")
    store.rename("0x401050", "decrypt_payload")

    for ann in store.list():
        print(f"{ann['addr']}: [{ann['kind']}] {ann['text']}")
```

**Interface Hub** :
- **Ctrl+Clic** sur une adresse dans le désassemblage → popup de saisie de note
- La note est sauvegardée et restaurée à chaque ouverture du hub

**Dépendances** : `backends.static.cache` (SQLite)

---

### `offset_to_vaddr.py`

**Rôle** : Convertit un offset fichier en adresse virtuelle (et vice-versa).

**Ce qu'il fait** :
- Parse les headers ELF, PE ou Mach-O sans dépendance externe (stdlib uniquement)
- Trouve la section contenant l'offset et calcule l'adresse virtuelle correspondante
- Utile pour naviguer entre la vue hex (offsets fichier) et la vue désassemblée (adresses virtuelles)

**Fonctions disponibles** :
- `offset_to_vaddr_elf(binary_path, file_offset)` → adresse virtuelle ou `None`
- `offset_to_vaddr_pe(binary_path, file_offset)` → adresse virtuelle ou `None`
- `offset_to_vaddr(binary_path, file_offset)` → essaie ELF puis PE automatiquement

**Exemple** :
```python
from backends.static.offset_to_vaddr import offset_to_vaddr

vaddr = offset_to_vaddr("/tmp/sample.elf", 0x1000)
# → 0x401000
```

**Dépendances** : standard library uniquement (`struct`, `pathlib`)

---

### `asm_sim.py`

**Rôle** : Simule l'exécution d'un sous-ensemble d'instructions x86-64 et produit une trace.

**Ce qu'il fait** :
- Lit un fichier `.asm` (Intel syntax, format de `disasm.py`)
- Simule un petit sous-ensemble d'instructions : `mov`, `push`, `pop`, `add`, `sub`, `xor`, `call`, `ret`
- Maintient un état : registres (rax–r15, rsp, rbp, rip, rflags) + stack (1024 mots)
- Exporte des snapshots JSON à chaque instruction simulée
- Utile pour comprendre l'effet d'un bloc de code sans l'exécuter

**Limites** :
- Pas de mémoire heap (uniquement registres + stack)
- Pas de syscalls simulés
- Pas de gestion des exceptions / interruptions

**Output JSON** :
```json
[
  {
    "step": 1,
    "addr": "0x401000",
    "instr": "push rbp",
    "regs": {"rax": 0, "rbp": 0, "rsp": 4096, ...},
    "stack_top": []
  }
]
```

**CLI** :
```bash
python -m backends.static.asm_sim --input ./sample.asm --output trace.json
```

**Dépendances** : standard library uniquement

---

### `binary_patch.py`

**Rôle** : Modifie des octets directement dans le binaire (patch in-place).

**À quoi ça sert ?**
En pwn et en reverse engineering, on a souvent besoin de modifier un binaire : remplacer une instruction par des NOPs (`90`), changer un saut conditionnel pour bypasser une vérification, injecter du shellcode. Ce module écrit des octets à un offset précis dans le fichier.

**Ce qu'il fait** :
- Écrit des octets hexadécimaux à l'offset spécifié
- Vérifie que l'offset et la longueur restent dans les bornes du fichier
- Modification in-place (pas de copie)

**Output JSON** :
```json
{"ok": true, "written": 2, "offset": 4096}
```

**CLI** :
```bash
# NOP 2 instructions à l'offset 0x1000
python -m backends.static.binary_patch --binary ./sample.elf --offset 0x1000 --bytes "90 90"

# Changer un JNE (75) en JMP (eb)
python -m backends.static.binary_patch --binary ./crackme.elf --offset 0x1234 --bytes "eb"
```

**Dépendances** : standard library uniquement

---

### `export.py`

**Rôle** : Exporte les résultats d'analyse dans des formats standards (CSV, JSON, DOT).

**À quoi ça sert ?**
Permet de sortir les données de Pile ou Face pour les utiliser ailleurs — dans un tableur, un notebook, Graphviz, ou un autre outil. Utile pour les rapports d'analyse, la documentation et le partage.

**Formats supportés** :

| Format | Fonction | Cas d'usage |
|--------|----------|-------------|
| CSV | `export_symbols_csv()` | Symboles → tableur / grep |
| CSV | `export_strings_csv()` | Strings → tableur / filtrage |
| JSON | `export_xrefs_json()` | Cross-refs → format IDA-compatible |
| DOT | `export_cfg_dot()` | CFG → rendu Graphviz (`dot -Tsvg`) |

**Usage Python** :
```python
from backends.static.export import export_symbols_csv, export_cfg_dot

export_symbols_csv(symbols, "symbols.csv")
export_cfg_dot(cfg, "cfg.dot")
```

**Dépendances** : standard library uniquement

---

## Architecture générale

```
backends/static/
├── Parsing binaire (lief)
│   ├── headers.py             # Métadonnées
│   ├── sections.py            # Sections
│   ├── symbols.py             # Symboles
│   └── entropy.py             # Entropie
│
├── Analyse du code
│   ├── disasm.py              # Désassemblage (capstone)
│   ├── cfg.py                 # CFG (blocs de base)
│   ├── call_graph.py          # Graphe d'appels
│   ├── discover_functions.py  # Découverte fonctions
│   ├── xrefs.py               # Cross-références
│   └── stack_frame.py         # Variables locales
│
├── Extraction
│   ├── strings.py             # Chaînes
│   ├── search.py              # Recherche binaire
│   └── hex_view.py            # Dump hexadécimal
│
├── Détection
│   ├── packer_detect.py       # Packers
│   ├── imports_analysis.py    # Imports suspects
│   ├── flirt.py               # Signatures FLIRT
│   ├── yara_scan.py           # YARA
│   ├── capa_scan.py           # CAPA (Mandiant)
│   └── rules_manager.py       # Gestion règles
│
├── Malware analysis
│   ├── behavior.py            # Comportemental
│   ├── taint.py               # Taint analysis
│   └── anti_analysis.py       # Anti-analyse
│
├── Offensif
│   ├── rop_gadgets.py         # Gadgets ROP
│   ├── vuln_patterns.py       # CWE patterns
│   └── bindiff.py             # Comparaison binaire
│
├── Décompilation
│   ├── decompile.py           # retdec / Ghidra wrapper
│   ├── dwarf.py               # Info debug DWARF
│   └── string_deobfuscate.py  # XOR/ROT
│
├── Scripting
│   ├── pof/                   # API Python unifiée
│   └── repl.py                # Exécuteur de scripts
│
└── Utilitaires
    ├── annotations.py         # Notes persistantes
    ├── offset_to_vaddr.py     # Offset ↔ VAddr
    ├── asm_sim.py             # Simulation ASM
    ├── binary_patch.py        # Patch de bytes
    └── export.py              # Export CSV/JSON/DOT
```

## Dépendances externes

| Outil/Lib | Rôle | Installation |
|-----------|------|-------------|
| `lief` | Parsing ELF/PE/Mach-O | `pip install lief` |
| `capstone` | Désassemblage (x86, x64, ARM64) | `pip install capstone` |
| `pyelftools` | Extraction DWARF | `pip install pyelftools` |
| `retdec-decompiler` | Décompilation | [retdec releases](https://github.com/avast/retdec/releases) |
| `yara` | Scan YARA | `brew install yara` / `apt install yara` |
| `capa` | Analyse capacités (Mandiant) | `pip install flare-capa` |
