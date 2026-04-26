# Architecture du projet Pile ou Face

Ce document décrit l’architecture cible du projet sur la branche **organisation** : vision long terme, principe **static-first** pour la phase actuelle, et découpage des responsabilités pour évoluer vers un outil de pwn/reverse (alternative à GDB/Cutter).

Références : [MOSCOW.md](./MOSCOW.md) (priorisation), [INTERNAL_TECHNICAL_OVERVIEW.md](./INTERNAL_TECHNICAL_OVERVIEW.md) (détails techniques).

---

## 1. Vision et objectifs

### 1.1 Cible long terme

- **Outil pédagogique et opérationnel** pour l’analyse de binaires et la compréhension de la pile (débutants → avancés).
- **À terme** : outil capable de remplacer ou compléter GDB / Cutter pour des scénarios **pwn** et **reverse** (analyse statique + traçage dynamique, dans un même environnement VS Code).

**Binaires tiers (non modifiables)** : l’objectif est de reverse/pwn des binaires qu’on ne possède pas (CTF, challenges). On ne modifie pas le binaire cible : on lance la trace avec notre payload en stdin ; l’émulateur Unicorn injecte ce payload quand le binaire exécute `read(0, ...)` (ou équivalent). Aucune modification du binaire n’est requise.

### 1.2 Deux modes d’usage

| Mode        | Public      | Source principale | Rôle du backend                          |
|------------|-------------|-------------------|------------------------------------------|
| **Statique** | Débutants   | `.asm` / C → asm  | Simulation pile à partir d’un listing asm |
| **Dynamique**| Avancés     | Binaire (ELF/raw) | Émulation Unicorn, syscalls, désassemblage |

- **Static-first** : on structure d’abord la partie statique (parseur asm, simulateur, format de trace unifié), puis on fait évoluer le dynamique et l’UI au-dessus du même contrat (JSON de trace).

---

## 2. Principes d’architecture

1. **Contrat unique** : un seul format de sortie (trace JSON) pour l’UI, que la trace vienne du simulateur statique ou d’Unicorn.
2. **Séparation nette** : tooling (CLI/orchestration) ↔ backends (static / dynamic) ↔ extension VS Code + webview.
3. **Évolutivité** : ajout de fonctionnalités (MCP, calculette d’offset, strings, graphe) sans casser le noyau static/dynamic.
4. **Documentation** : chaque couche a un rôle documenté ; les nouveaux contributeurs peuvent s’appuyer sur ce document et l’overview technique.

---

## 3. Couches et responsabilités

```
┌─────────────────────────────────────────────────────────────────┐
│  Extension VS Code (extension/)                                 │
│  Commandes, webview, chargement output.json, Run Trace / Static  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  Entrées CLI                                                     │
│  backends/dynamic/pipeline/run_pipeline.py → dynamique           │
│  tools/asm_static.py                         → statique          │
└─────────────┬─────────────────────────────┬─────────────────────┘
              │                             │
              ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────────────┐
│  Backend dynamique       │   │  Backend statique                 │
│  backends/dynamic/       │   │  (actuellement dans tools/        │
│  pipeline + engine/      │   │   asm_static.py ; à terme         │
│  unicorn runtime         │   │   backends/static/ si extraction) │
└─────────────────────────┘   └─────────────────────────────────┘
              │                             │
              └─────────────┬───────────────┘
                            ▼
              Format unifié : { snapshots, risks, meta }
```

### 3.1 Couche Tooling (CLI)

- **Rôle** : point d’entrée unique pour lancer une analyse (static ou dynamic) et produire `output.json`.
- **Fichiers** :
  - `tools/asm_static.py` : entrée **statique** (fichier `.asm` → JSON).
  - `backends/dynamic/pipeline/run_pipeline.py` : entrée **dynamique** (binaire → runtime Unicorn → objdump optionnel → JSON).
- **Évolution** : possibilité d’un seul CLI `tools/run.py --mode static|dynamic` qui délègue aux bons backends, sans obligation immédiate.

### 3.2 Backend statique (phase actuelle : static-first)

- **Rôle** : parser un programme assembleur simplifié, simuler registres et pile, émettre des snapshots au format partagé.
- **Implémentation actuelle** : tout dans `tools/asm_static.py` (parse, tokenize, simulate, dump JSON).
- **Évolution possible** :
  - Extraire le cœur (parser + simulateur) dans `backends/static/` (ex. `parser.py`, `simulator.py`, `cli.py`) pour réutilisation et tests, tout en gardant `tools/asm_static.py` comme façade CLI.
  - Enrichir le parseur (plus d’instructions, contrôle de flux) sans changer le format de sortie.

### 3.3 Backend dynamique

- **Rôle** : orchestrer une trace dynamique, enrichir les snapshots et produire le modèle consommé par l'UI.
- **Core** : `backends/dynamic/core/` expose les contrats stables (`ExecutionEngine`, `TraceConfigLike`) entre pipeline et runtimes.
- **Pipeline** : `backends/dynamic/pipeline/` contient l'entrée CLI, l'orchestration et le modèle de stack dynamique.
- **Runtime concret** : `backends/dynamic/engine/unicorn/` charge un binaire (ELF ou raw), initialise la pile, émule les instructions et syscalls nécessaires, puis capture des snapshots.
- **Stabilité** : le format des snapshots et de `meta` doit rester compatible avec celui du mode statique pour que l’UI reste unique.

### 3.4 Extension VS Code et webview

- **Rôle** : commandes (ex. « Run Trace »), chargement de `output.json`, affichage pile/registres/désassemblage, synchronisation avec l’éditeur (surlignage ligne).
- **Fichiers** : `extension/src/extension.js` ; `extension/webview/` (media + app).
- **Évolution** : ajout de commandes (ouvrir trace, calculette d’offset, recherche de strings, MCP) sans mélanger la logique de trace avec l’orchestration.

---

## 4. Structure des dossiers recommandée (organisation)

Structure actuelle, avec une séparation claire des rôles :

```
Pile_Ou_Face/
├── backends/           # Moteurs d’analyse
│   ├── dynamic/        # Domaine dynamique
│   │   ├── core/       # Interfaces moteur et types de trace
│   │   ├── pipeline/   # Orchestration, modèles, enrichissements
│   │   └── engine/     # Runtimes concrets
│   │       └── unicorn/# Traçage dynamique (ELF, raw, syscalls)
│   ├── static/         # Analyse statique (disasm, symbols, strings)
│   └── shared/         # Code partagé
├── tools/              # Points d’entrée CLI
│   ├── static/         # disasm.py, asm_sim.py
│   ├── asm_static.py   # Façade → static/asm_sim.py
│   └── README.md      # Usage et options
├── extension/          # Extension VS Code
│   ├── src/            # extension.js, commandes
│   └── webview/        # UI (media + app)
├── docs/               # Architecture, MOSCOW, guides
├── examples/           # Exemples C / asm pour démo et tests
└── scripts/            # CI, tests, utilitaires
```

- **Static-first** : aucun déplacement obligatoire tout de suite ; on peut garder la logique statique dans `tools/asm_static.py` et documenter qu’à terme le « moteur » peut migrer vers `backends/static/` pour réutilisation (lib, tests, éventuel MCP).

---

## 5. Flux de données

### 5.1 Mode statique (priorité phase actuelle)

```
Source C (optionnel) → génération input.asm
        ↓
input.asm → tools/asm_static.py → output.json (view_mode: static)
        ↓
Extension charge output.json → webview (pile, registres, surlignage asm)
```

### 5.2 Mode dynamique

```
Source C → gcc → binaire
        ↓
Binaire → backends/dynamic/pipeline/run_pipeline.py → engine/unicorn + objdump → output.json (view_mode: dynamic)
        ↓
Extension charge output.json → webview (pile, registres, désassemblage)
```

Le schéma du payload JSON est décrit dans [INTERNAL_TECHNICAL_OVERVIEW.md](./INTERNAL_TECHNICAL_OVERVIEW.md) ; un `docs/json-schema.md` pourra formaliser le contrat quand nécessaire.

---

## 6. Évolution vers un outil pwn/reverse

Pour tendre vers une alternative à GDB/Cutter, les étapes suivantes sont cohérentes avec le MOSCOW et l’architecture ci-dessus :

1. **Court terme (organisation + static)**  
   - Consolider l’architecture (ce document, structure des dossiers).  
   - Renforcer le mode statique : robustesse du parseur/simulateur, exemples, docs.  
   - Garder un seul format de trace et une seule UI pour static et dynamic.

2. **Moyen terme (Should have)**  
   - MCP, point d’entrée unique pour les fonctionnalités.  
   - Calculette d’offset (hex ↔ décimal, offset ↔ adresse).  
   - Recherche de strings, filtrage basique.  
   - Visualisation graphique (graphe de relations, navigation).

3. **Long terme (outil pwn/reverse)**  
   - Enrichir le dynamique : breakpoints, step, inspection mémoire/heap.  
   - Intégration désassemblage avancé (Capstone, Cutter-like).  
   - Scénarios type CTF : injection stdin, suivi buffer/ROP, etc.

En restant **static-first** sur la branche organisation, on pose une base claire (contrat, couches, dossiers) sur laquelle greffer le reste sans refonte majeure.
