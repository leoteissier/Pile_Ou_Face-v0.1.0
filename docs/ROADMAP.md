# Roadmap — Pile ou Face

---

## Professionnels & Chercheurs en Sécurité

### Multi-Architecture — PRIORITÉ
- x86 / x64
- ARM / ARM64
- MIPS, RISC-V, PowerPC
- WebAssembly
- Détection automatique de l'architecture

---

### IA & MCP
- MCP (Model Context Protocol) — connecte l'outil à n'importe quel LLM
- Renommage automatique des fonctions
- Explication du code en langage naturel
- Détection de patterns / vulnérabilités
- Chat direct avec le binaire : "Que fait cette fonction ?"

---

### Analyse Dynamique
- Intégration Frida — instrumentation live, tracing d'appels en temps réel
- Support GDB / LLDB — breakpoints depuis le panneau désassemblage
- Enregistrement de traces d'exécution + replay

---

### Interopérabilité
- Import / export annotations depuis IDA (`.idb`) et Ghidra
- Symbol server automatique (télécharge les symboles debug depuis Microsoft / GNU)
- CI/CD — lancer l'analyse dans une pipeline GitHub Actions / GitLab

---

### Threat Intel
- Lookup automatique VirusTotal / MalwareBazaar sur le hash du binaire
- Base de signatures communautaire partagée (MinHash)
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
- Support Windows / Linux / macOS
- Zéro configuration manuelle

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
- Diff visuel entre deux versions d'un binaire
- Heatmap des zones de code les plus exécutées

---

### UI Multi-Langue
- Français, Anglais, Espagnol, Chinois...
- Interface adaptée aux équipes internationales

---

## Ordre de priorité global

| Priorité | Feature | Audience |
|----------|---------|----------|
| 1 | Multi-Architecture | Pro |
| 2 | IA & MCP | Pro |
| 3 | Analyse Dynamique (Frida) | Pro |
| 4 | Multi-Platform + auto dépendances | Grand public |
| 5 | Threat Intel (VirusTotal...) | Pro |
| 6 | Visualisation Avancée | Grand public |
| 7 | App Cloud | Grand public |
| 8 | Interopérabilité (IDA/Ghidra) | Pro |
| 9 | Workflow Pro (rapports, scripts) | Pro |
| 10 | Session Collaborative | Pro |
| 11 | UI Multi-Langue | Grand public |
| 12 | App Desktop | Grand public |


fichier hub.js trop long
refaire l'ui/ux avec un vrai user path optimiser
refaire le gestionaire de cache (ui)
faire une vrai hand free install