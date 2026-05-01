# Roadmap — Pile ou Face

---

## Ce qui est fait ✅

### Multi-Architecture
- ✅ x86 / x64 — désassemblage, CFG, call graph, stack frame
- ✅ ARM32 / ARM64 (Mach-O + ELF) — désassemblage complet, prologues, branches conditionnelles
- ✅ MIPS (o32 / n64) — désassemblage + conventions d'appel
- ✅ RISC-V (32 / 64)
- ✅ PowerPC (32 / 64)
- ✅ WebAssembly
- ✅ SPARC, BPF, m68k, SH, TriCore
- ✅ Détection automatique de l'architecture depuis ELF / Mach-O / PE

### Décompilation
- ✅ Moteur de décompilation unifié piloté par `decompilers.json`
- ✅ Support Ghidra (Docker), RetDec (Docker), Angr (Docker), Rizin (local)
- ✅ Mode Auto avec scoring du pseudo-C (`_score_decompile_code`)
- ✅ Scoring basé sur : lignes, appels, structures de contrôle, type hints, casts, placeholders, gotos, résidus bas niveau, warnings
- ✅ `quality_bias` / `precision_bias` par décompilateur pour affiner le mode Auto
- ✅ `fallback_command` si la commande principale ne produit rien
- ✅ `detect_cmd` pour vérifier la disponibilité d'un plugin (ex : rz-ghidra)
- ✅ Filtrage du bruit stdout/stderr des outils (VERBOSE:, ERROR:, codes ANSI, rz_*)
- ✅ Images Docker fournies pour x86_64 et arm64

### Analyse Statique
- ✅ Désassemblage multi-archi avec capstone + lief
- ✅ CFG (Control Flow Graph) — ELF/Mach-O/PE, x86/ARM64
- ✅ Call graph — analyse des appels entre fonctions
- ✅ Symboles, sections, headers binaires
- ✅ Stack frame analysis (variables locales, arguments)
- ✅ Calling convention detection (x86, ARM, MIPS, RISC-V, PPC)
- ✅ Cross-références (xrefs)
- ✅ Strings extraction
- ✅ Hex view
- ✅ Imports / exports analysis
- ✅ PE resources
- ✅ Exception handlers
- ✅ YARA scan
- ✅ Capa capabilities scan
- ✅ ROP gadgets
- ✅ Vuln patterns detection
- ✅ Anti-analysis detection
- ✅ Behavior analysis
- ✅ Taint analysis
- ✅ FLIRT signatures
- ✅ Function similarity (MinHash)
- ✅ BinDiff (diff entre deux binaires)
- ✅ String deobfuscation
- ✅ Typed data / typed struct refs

### Annotations & Patches
- ✅ Annotations persistantes par adresse (labels, commentaires, types)
- ✅ Patch manager (apply / revert / redo)
- ✅ Typed structs avec références

### IA & MCP
- ✅ MCP (Model Context Protocol) — serveur intégré
- ✅ Bridge Ollama (LLM local)
- ✅ Python REPL intégré pour scripting sur le binaire

### Interface
- ✅ Hub VSCode — panneau principal
- ✅ Dashboard, options, outils dans le hub
- ✅ Panneau décompilateur avec score de qualité
- ✅ Gestion des décompilateurs (add / edit / remove / test) via UI
- ✅ File watcher sur `decompilers.json` — mise à jour auto de l'UI
- ✅ Toast notifications quand un décompilateur devient disponible
- ✅ Cache statique des analyses

---

## En cours / prioritaire 🔧

### Décompilation — à affiner
- 🔧 Améliorer le score Auto : le scoring actuel est heuristique (compte les lignes, appels, type hints). Il faut le calibrer sur des binaires réels avec un ground truth pour que le mode Auto ait vraiment un sens — mesurer l'écart entre les scores et la qualité perçue, ajuster les poids
- 🔧 Support d'autres décompilateurs via images Docker custom (arm64 natif, x86 émulé, et inversement) — documenter le workflow complet de build multi-arch pour des images tierces
- 🔧 Décompilateur Hex-Rays / IDA Pro via interface externe (si licence disponible)
- 🔧 Décompilateur Binary Ninja via API (si licence disponible)
- 🔧 Améliorer le support Mach-O ARM64 — rizin `pdc` ne produit rien sur ce format, fallback `pdf` (désassemblage) uniquement pour l'instant

### Interface — dette technique
- 🔧 `hub.js` extension trop long — découper en modules
- 🔧 Refaire le gestionnaire de cache (UI) — interface de nettoyage plus claire
- 🔧 Optimiser le user path — réduire les frictions pour les cas d'usage principaux

---

## Professionnels & Chercheurs en Sécurité

### Analyse Dynamique
- Intégration Frida — instrumentation live, tracing d'appels en temps réel
- Support GDB / LLDB — breakpoints depuis le panneau désassemblage
- Enregistrement de traces d'exécution + replay

---

### Interopérabilité
- Import / export annotations depuis IDA (`.idb`) et Ghidra (`.gzf`)
- Symbol server automatique (télécharge les symboles debug depuis Microsoft / GNU)
- CI/CD — lancer l'analyse dans une pipeline GitHub Actions / GitLab

---

### Threat Intel
- Lookup automatique VirusTotal / MalwareBazaar sur le hash du binaire
- Scoring CVSS-like basé sur les vulnérabilités détectées

---

### Cas d'usage avancés
- Mode CTF — détection auto des patterns flag, solvers intégrés (format string, ret2libc...)
- Analyse kernel modules (Linux `.ko`, Windows `.sys`) — APIs kernel spécifiques
- Reverse engineering de protocoles réseau — corrélation pcap + binaire

---

### Workflow Pro
- Historique de session avec timeline des adresses visitées
- Bibliothèque de scripts d'analyse personnels réutilisables
- Export rapport d'analyse en PDF / HTML structuré (utile pour les pentesters)

---

### Session Collaborative *(en réflexion)*
- Plusieurs chercheurs sur le même binaire simultanément
- Synchronisation en temps réel des annotations
- Historique des modifications (git-like)
- Système de commentaires live
- Comme Figma, mais pour le reverse engineering

---

## Grand Public & Accessibilité

### Multi-Platform
- Installation one-click avec téléchargement automatique des dépendances
- Support Windows / Linux / macOS sans configuration manuelle

---

### App Cloud
- Reverse engineering directement dans le navigateur
- Aucune installation requise
- Accessible partout, API REST intégrée

---

### App Desktop
- Version native haute performance
- Travail offline complet
- Synchronisation avec le cloud

---

### Visualisation Avancée
- Graphes interactifs dynamiques et modernes
- Vue mémoire timeline — visualise l'évolution en temps réel
- Heatmap des zones de code les plus exécutées

---

### UI Multi-Langue
- Français, Anglais, Espagnol, Chinois...
- Interface adaptée aux équipes internationales

---

## Ordre de priorité global

| Priorité | Feature | Statut | Audience |
|----------|---------|--------|----------|
| — | Multi-Architecture | ✅ fait | Pro |
| — | Décompilation multi-outil + mode Auto | ✅ fait | Pro |
| — | Analyse statique complète | ✅ fait | Pro |
| — | IA & MCP (Ollama) | ✅ fait | Pro |
| 1 | Calibrage scoring Auto décompilateur | 🔧 en cours | Pro |
| 2 | Images Docker multi-arch (arm64 natif + x86 émulé) | 🔧 en cours | Pro |
| 3 | Refactoring hub.js + cache UI | 🔧 en cours | — |
| 4 | Analyse Dynamique (Frida) | todo | Pro |
| 5 | Multi-Platform + auto dépendances | todo | Grand public |
| 6 | Threat Intel (VirusTotal...) | todo | Pro |
| 7 | Interopérabilité (IDA/Ghidra) | todo | Pro |
| 8 | Workflow Pro (rapports, scripts) | todo | Pro |
| 9 | Visualisation Avancée | todo | Grand public |
| 10 | App Cloud | todo | Grand public |
| 11 | Session Collaborative | todo | Pro |
| 12 | UI Multi-Langue | todo | Grand public |
| 13 | App Desktop | todo | Grand public |
