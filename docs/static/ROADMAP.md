# Roadmap statique — Ajouts & Améliorations

Ce document liste les fonctionnalités à ajouter et les modules existants à améliorer
pour la partie **analyse statique** de Pile ou Face, dans l'objectif de remplacer IDA Pro / Ghidra.

---

## Légende

| Icône | Signification |
|-------|--------------|
| ❌ | Absent — à créer |
| ⚠️ | Partiel — à améliorer |
| ✅ | Présent et fonctionnel |
| 🔥 | Priorité haute (IDA parity) |
| ⭐ | Différenciateur unique (dépasse IDA) |

---

## 1. Fonctionnalités implémentées

| Feature | Statut | Notes |
|---------|--------|-------|
| Hex View + Patch bytes | ✅ | Navigation offset/vaddr, patch, sections colorées |
| Stack frame / variables locales | ✅ | Nommage `var_N`, intégration DWARF |
| Binary Diff | ✅ | Matching hybride (noms + Jaccard basic blocks) |
| Scripting Python intégré (pof API) | ✅ | REPL + API 15 fonctions + sandbox timeout |
| Labels inline dans le désassemblage | ✅ | Renommage → re-render ASM + CFG + callgraph |
| CFG — nœuds expansibles | ✅ | Compact par défaut, double-clic pour voir le code |
| String déobfuscation | ✅ | XOR 1-byte/multi, ROT, Base64, Stackstring x86-64 + ARM64 |
| FLIRT signatures | ✅ | Index premier-byte, ~150 sigs libc/OpenSSL/zlib |
| DWARF source line comments | ✅ | Commentaires `; src/main.c:42` dans le désassemblage |
| Déobfuscation — adresses virtuelles | ✅ | lief ELF/PE/MachO offset→vaddr |
| Base d'analyse SQLite partagée | ✅ | Cache unifié `instructions/functions/basic_blocks/xrefs/imports/stack_frames` |
| Analyse comportementale (behavior) | ✅ | Indicateurs malware |
| Taint analysis | ✅ | Inter-procédural léger, wrappers source/sink, chemins remontés |
| ROP gadgets | ✅ | Recherche de chaînes ROP |
| Patterns de vulnérabilités | ✅ | CWE, fonctions dangereuses ; signal d'audit, pas preuve de vulnérabilité |
| Anti-analysis detection | ✅ | Anti-debug, anti-VM, obfuscation |
| YARA scan | ✅ | Règles custom + bibliothèque intégrée |
| Capa scan | ✅ | Capacités malware (règles capa) |
| Entropy + packer detection | ✅ | Détection de binaires packés |
| Fonctions découvertes | ✅ | Seeds entrypoint / `.pdata` / DWARF + appels directs + fallback prologues |
| CFG fitToView automatique | ✅ | Ajustement au conteneur à l'ouverture |
| CFG — code visible par défaut | ✅ | Aperçu compact dès l'ouverture, double-clic pour étendre |
| Vue Imports navigable | ✅ | Score suspicion + badges catégories + DLL dépliables |
| Xrefs callsites par import | ✅ | Clic fonction → callsites + navigation vers désassemblage |
| Imports Mach-O par bibliothèque | ✅ | Groupement par `.dylib` réel via `library_ordinal`, préfixe `_` retiré |
| Validation binaire à l'ouverture | ✅ | Magic bytes ELF/PE/Mach-O + proposition d'ouverture en blob brut |
| Similarité de fonctions | ✅ | MinHash opcodes n-grammes, comparaison contre binaire de référence |
| Base packagée de similarité | ✅ | Starter pack embarqué OpenSSL libssl + fusion workspace/base packagée |
| Éditeur de structures C v1 | ✅ | Structs persistées, éditeur UI, application dans Données typées |
| Propagation transverse des structs appliquées | ✅ | Structs persistées et repères visibles dans désasm, xrefs et pseudo-C |
| Exports navigables | ✅ | Tableau exports ELF/PE/Mach-O, démangling C++, navigation vers désassemblage |
| Calling convention detection | ✅ | Colonne dans la liste des fonctions (x86, x64, ARM64) |
| Liste des fonctions enrichie | ✅ | Triable, filtrable, taille, calling convention |
| Gestion patches persistée    | ✅ | Undo/redo entre sessions, JSON dans .pile-ou-face/patches/ |
| Sélecteur binaire global + récents | ✅ | Source de vérité unique pour Static / Dynamic |
| Support blob brut | ✅ | Désassemblage, CFG, Infos, Sections, Hex avec profil `arch/base_addr` |
| Barre de contexte transverse | ✅ | Fonction / adresse actives + raccourcis entre vues |
| Désassemblage enrichi | ✅ | Bannières de fonctions, labels, commentaires inline, hints stack |
| Xrefs enrichies | ✅ | Fonction source + hints stack quand disponibles |
| Types / stack propagation transverse | ✅ | ABI-aware args, frame-pointer-less x86/ARM, propagation vers désasm/CFG/xrefs/pseudo-C/hex/stack |

---

## 2. Fonctionnalités à implémenter

### 🔥⭐ MCP + Analyse IA de fonctions ( a ne pas faire )
**Statut :** ❌ absent
**Impact :** différenciateur majeur — IDA Pro à 4000 $ n'a pas ça nativement

**Architecture :**
```
LLM (Claude local / cloud)
        ↕  appels d'outils MCP
  backends/mcp_server.py
        ↕  appels Python directs
  tous les backends statiques
```

**Cas d'usage IA :**
- "Explique ce que fait la fonction `0x401050`" → appelle `decompile` + `xrefs` + `symbols` automatiquement
- "Y a-t-il des vulnérabilités dans ce binaire ?" → appelle `vuln_patterns` + `behavior` + `taint`
- "Renomme les fonctions de ce binaire strippé" → appelle `symbols` + `decompile` puis `annotate` en boucle
- "Compare ces deux versions du malware" → appelle `bindiff` + `behavior` sur les deux

**MCP server — outils exposés :**
- `disasm`, `decompile`, `symbols`, `xrefs`, `rop_gadgets`, `behavior`
- `vuln_patterns`, `strings`, `hex_view`, `patch`, `bindiff`, `annotate`

**Backend à créer :** `backends/mcp_server.py` (transport stdio + HTTP)
**Config :** `.mcp.json` à la racine + settings extension pour choix local/cloud
**UI :** chat flottant dans le hub, actions 1-clic ("Appliquer les noms suggérés")

---

### ⭐ Similarité de fonctions — base de référence
**Statut :** ⚠️ starter pack livré, corpus packagé encore à élargir
**Impact :** identifier les fonctions connues sans avoir le binaire de référence sous la main

- Base pré-indexée de signatures MinHash : libc, OpenSSL, zlib, malware connus
- Recherche dans la base sans fournir de binaire de référence
- Score + suggestion de nom + lien vers la source

**Backend :** `backends/static/func_similarity.py` (existant) + index `.pfdb`

**Livré dans le lot actuel :**

- Base locale workspace `.pile-ou-face/function_similarity.pfdb` alimentable depuis l'UI
- Indexation d'un binaire de référence sans perdre le mode comparaison binaire-à-binaire
- Recherche dans la base indexée depuis le panneau des fonctions
- Listage et purge de la base locale
- Renommage et suppression sélective des références workspace depuis l'UI
- Starter pack embarqué de références `OpenSSL libssl` consultable sans fournir de binaire de référence
- Fusion automatique `base locale + base packagée` dans la recherche et le panneau UI
- Résultats enrichis avec la source (`workspace` vs `packagée`), le nom du pack et la famille

**Reste à pousser :**

- Élargir le corpus packagé à davantage de familles (`libc`, `zlib`, `libcrypto`, familles malware)

---

### ⭐ Éditeur de structures C
**Statut :** ⚠️ v3 livré sur le noyau actuel, cas avancés encore partiels
**Impact :** important pour analyser des protocoles ou formats binaires

**Livré dans le lot actuel :**

- Définition de structs C simples dans l'UI (`typedef struct ...`)
- Persistance dans `.pile-ou-face/structs.json`
- Backend dédié [structs.py](../../backends/static/structs.py) + parsing / layout simple
- Application d'une struct à un offset dans `Données typées`
- Sélecteur de structs et éditeur intégrés dans l'onglet DATA
- Application d'une struct depuis la sélection active dans `Hex`
- Prévisualisation rapide des champs d'une struct depuis `Hex` avant d'ouvrir `Données typées`
- Support d'application par adresse virtuelle côté backend `typed_data.py`, en plus de l'offset relatif de section
- Persistance des structs appliquées dans le workspace pour servir de repères transverses
- Propagation des champs exacts vers `désasm`, `xrefs` et `pseudo-C` quand une adresse correspond à un champ typé
- Support des `union` dans l'éditeur, le layout et `Données typées`
- Support des `enum` nommés avec décodage symbolique des valeurs
- Labels UI élargis aux `types C` composés (`struct` / `union`) dans `Hex` et `Données typées`

- Définir des structs/enums en C (`struct PacketHeader { uint32_t magic; uint16_t len; }`)
- Appliquer une struct à un offset dans la hex view → affichage des champs nommés
- Persister les structs dans `.pile-ou-face/structs.json`
- Propagation dans le décompilateur (substitution `*(uint32_t*)(ptr+4)` → `hdr.len`)

**Reste à pousser :**

- Cas C plus riches (`enum class` style C++, tableaux multidimensionnels, pointeurs de fonctions)
- Application encore plus directe depuis `Hex View` pour les plages plus grosses et cas imbriqués
- Propagation plus profonde dans `stack` et pour les accès indirects / offsets non triviaux

---

## 3. Améliorations des modules existants

### 🔥 Vuln patterns — niveaux de preuve et confiance
**Fichier :** `backends/static/vuln_patterns.py`
**Statut :** ⚠️ partiel — détecte aujourd'hui des APIs dangereuses, pas des vulnérabilités confirmées
**Objectif :** éviter les conclusions trop fortes : utiliser `strcpy`, `gets` ou `system` ne prouve pas à lui seul qu'un binaire est exploitable.

**Modèle cible :**

- `dangerous_api` : fonction historiquement risquée importée ou référencée (`strcpy`, `system`, `sprintf`, etc.), confiance basse à moyenne.
- `potential_vulnerability` : appel dangereux avec indice de contrôle utilisateur ou taille non bornée, confiance moyenne.
- `confirmed_vulnerability` : flux source→sink confirmé par `taint`, `call_graph`, désassemblage/décompilation ou trace dynamique, confiance haute.

**Champs à ajouter aux résultats :**

- `classification` (`dangerous_api`, `potential_vulnerability`, `confirmed_vulnerability`)
- `confidence` (`LOW`, `MEDIUM`, `HIGH`)
- `evidence` (ex. `import strcpy`, `argv[1] -> strcpy`, `gets -> buffer stack`)
- `needs_review` pour les signaux qui demandent validation humaine

**Reste à pousser :**

- Renommer le wording UI de “vulnérabilité détectée” vers “signal vulnérabilité / API à risque” quand la preuve est faible.
- Croiser `vuln_patterns` avec `taint.py`, `call_graph.py`, `xrefs.py` et `decompile.py` pour remonter les vrais flux source→sink.
- Détecter les cas où une fonction dangereuse est utilisée de façon non exploitable (source constante, taille bornée, wrapper sécurisé).
- Documenter clairement les faux positifs et faux négatifs attendus.

### 🔥 Portabilité multi-arch Capstone — couverture complète des features
**Fichiers :** `backends/static/arch.py` + `disasm.py` + `discover_functions.py` + `cfg.py` + `xrefs.py` + `call_graph.py` + `stack_frame.py` + `calling_convention.py` + `rop_gadgets.py` + `func_similarity.py` + `taint.py` + `behavior.py`
**Statut :** ✅ matrice de support + sémantique multi-ISA de base livrées, portages profonds encore partiels selon ISA
**Objectif :** toutes les features statiques doivent soit fonctionner proprement sur chaque ISA supportée par Capstone, soit annoncer explicitement leur niveau de support au lieu de produire des résultats trompeurs.

**Risques multi-arch à couvrir :**

- `discover_functions` : prologues/épilogues, appels directs, tail-calls, thunks, trampolines, entrypoints et symboles selon ISA
- `CFG` / `call_graph` : mnemonics `call` / `jmp` / `jcc` / `ret`, delay slots, branchements conditionnels, fallthrough, tables de switch et sauts indirects par architecture
- `xrefs` / `import_xrefs` : extraction des cibles de branches/appels, références PC-relative, GOT/PLT/stubs, imports PE/Mach-O/ELF et patterns propres à chaque ABI
- `stack_frame` / `calling_convention` : registres d'arguments, stack pointer, frame pointer, link register, tailles de pointeur, alignement de pile, conventions d'appel et variantes 32/64 bits
- `decompile` / enrichissement pseudo-C : propagation stack/types dépendante des noms de registres et du style des backends externes pour chaque ISA
- `rop_gadgets` : instructions de retour, séquences de pivot, contraintes d'alignement, mode Thumb/MIPS delay slots et gadget endings non x86
- `func_similarity` / `bindiff` : normalisation d'opcodes et registres par famille ISA pour éviter des scores inutilisables entre architectures différentes
- `taint` / `behavior` / vuln patterns : identification des arguments de fonctions, wrappers source/sink, syscalls, imports et patterns anti-analysis non x86
- `string_deobfuscate` / stackstrings : motifs d'écriture mémoire et reconstruction de chaînes pour ARM/Thumb/MIPS/RISC-V/PPC/etc.
- `hex` / `typed_data` / patches : cohérence endian, taille de mot, mapping offset↔vaddr, bornes d'instruction et alignements d'ISA
- UI / hub / MCP : badges de support par feature et par architecture (`full`, `partial`, `disasm-only`, `unsupported`) pour éviter les faux positifs UX

**Livré dans le lot actuel :**

- Matrice `feature × ISA` exposée côté backend via `backends.static.arch.get_feature_support_matrix()` avec niveaux `full`, `partial`, `disasm-only`, `unsupported`.
- Métadonnées `arch.support` dans le mapping de désassemblage pour afficher des badges UI sans inférer côté frontend.
- Tables ISA centralisées dans `arch.py` pour x86/x64, ARM/Thumb, AArch64, MIPS, PPC, SPARC, RISC-V, BPF, WASM, M68K, SH et TriCore : appels, sauts, branches conditionnelles, retours, data refs, registres PC/SP/FP/LR et ABIs d'arguments quand connues.
- `CFG`, `xrefs`, `discover_functions` et `call_graph` consomment les adapters centralisés pour les appels/sauts/retours directs au lieu de chaînes x86/ARM codées localement.
- `rop_gadgets` ne scanne plus les octets `ret` x86 pour les autres ISA et dégrade via les ret mnemonics de l'adapter.
- Tests de fumée synthétiques pour matrice, CFG multi-ISA, xrefs multi-ISA, mapping raw avec support arch et non-régression ROP hors x86.

**Reste à pousser :**

- Faire consommer la matrice par le hub UI pour afficher les badges de support par panneau.
- Porter en profondeur `stack_frame`, `calling_convention`, `taint`, `behavior` et `string_deobfuscate` au-delà de x86/ARM au lieu du niveau `disasm-only`/`partial`.
- Ajouter des fixtures raw et binaires parsés pour davantage de familles Capstone avec cas little/big-endian et Thumb/MIPS delay slots.
- Étendre encore les switch tables, sauts indirects et patterns ABI propres à chaque architecture.

---

### ✅ Discover functions v3 — frontières, tail-calls et thunks
**Fichier :** `backends/static/discover_functions.py`
**Statut :** livré sur le noyau actuel
**Livré :**

- Promotion explicite des `tail-calls`, `thunks`, `plt stubs` et trampolines avec `confidence_score`
- Détection étendue des trampolines `push/ret`, `jmp reg` et chaînes courtes de thunks
- Meilleure fermeture des frontières via bornes estimées + résolution des chevauchements faibles
- Champ `boundary_reason` pour expliquer la borne retenue
- Helper de métriques `precision / recall / overlaps` et option CLI `--expected` pour les corpus synthétiques

**Suite logique :**
- Étendre le corpus réel de binaires strippés / optimisés pour mesurer le gain sur plusieurs ISA

---

### ✅ Types / stack v3 — propagation transverse
**Fichier :** `backends/static/stack_frame.py` + `decompile.py` + `xrefs.py` + `disasm.py`
**Statut :** livré sur le noyau actuel
**Livré :**

- Support plus robuste des fonctions sans frame pointer
- Arguments registres détectés et ordonnés selon l'ABI
- Propagation des noms stack / args vers `désasm`, `CFG`, `xrefs`, `pseudo-C`, `hex` et `stack`
- Support étendu x86 / x64 / ARM64 / ARM32 avec ancrages de frame pointer suivis

**Suite logique :**
- Brancher les futurs structs/enums utilisateur sur cette base unifiée

---

### ⚠️ Décompilateur — qualité du pseudo-C
**Fichier :** `backends/static/decompile.py`
**Problème :** retdec produit du C peu lisible ; Ghidra headless est lent au premier lancement

**Livré dans le lot actuel :**

- Cache plus agressif basé sur le contenu (`sha256_binary`) + annotations + stack signature + qualité
- Option `quality=max` dans le backend, le CLI et le hub pour privilégier Ghidra dans la chaîne auto
- Post-processing étendu pour plus de variantes d'annotations (`DAT_`, `LAB_`, `PTR_`, `code_`)
- Résumé des annotations repérées remonté au payload pour enrichir la lecture côté UI
- Substitutions stack/types plus riches selon le style de sortie du décompilateur (`local_10`, `auStack_20`, `var_18h`, `param_1`, `stack0x...`)
- En `quality=max`, comparaison de plusieurs backends (`ghidra`, `r2ghidra`, `r2pdc`) avec scoring heuristique de la sortie pseudo-C
- Remontée des détails de sélection (`selected_score`, scores/erreurs par backend) vers l'UI

**Reste à pousser :**

- Pousser encore le scoring avec un corpus réel et éventuellement un mode de comparaison encore plus lent incluant davantage d'adapters externes

---

### ⚠️ CFG — tables de switch et sauts indirects
**Fichier :** `backends/static/cfg.py`
**Problème :** les `jmp [rax*8 + table]` cassent le CFG (blocs non reliés)

**Livré dans le lot actuel :**

- Détection des patterns `switch` (comparaison + jmp indirect + table d'adresses)
- Résolution des cibles via analyse de la table de jump
- Annotation des blocs cibles avec `switch case N`
- Remontée des `case` dans les arêtes et badges UI du `CFG` (table + graphe)

**Reste à pousser :**

- Ajouter les tables de mnemonics multi-arch pour les ISA Capstone désormais désassemblables via adapter générique (`call` / `jmp` / `jcc` / `ret` / data refs), afin de rendre `CFG`, `xrefs` et découverte de fonctions plus fiables hors x86/ARM
- Étendre encore les patterns indirects exotiques et les cas limites multi-arch
- Annoter plus finement les cas `default`
- Mieux gérer les énormes jump tables et certains regroupements de cibles

---

### ⚠️ Hex View — sync avec le désassemblage
**Fichier :** `backends/static/hex_view.py` + hub.js
**Problème :** hex et désassemblage sont des vues indépendantes

**Livré dans le lot actuel :**

- Clic / focus dans le désassemblage → recentrage et surlignage de la plage d'octets correspondante dans la hex view
- Sélection d'octets dans `Hex` → navigation vers le désassemblage via double-clic, bouton dédié et raccourci clavier
- Sélection de plage dans `Hex` avec `Shift+clic`, résumé enrichi et conservation de la sélection pendant les rerenders
- Undo/redo des patches (historique de session)

**Reste à pousser :**

- Ajouter une vraie synchro de plages plus riches quand on aura des bornes d'instruction plus explicites depuis toutes les vues
- Étendre la logique aux gros sélecteurs de données typées / structs utilisateur

---

### ⚠️ Support blobs bruts — couverture étendue
**Fichier :** `backends/static/disasm.py` + handlers / hub extension
**Problème :** le mode blob brut existe, mais seules quelques vues sont réellement prêtes

**Livré dans le lot actuel :**

- Corpus de régression dédié `raw shellcode` `x86-64`, `ARM64` et `ARM32` couvrant `désasm`, `discover_functions`, `call_graph`, `xrefs` et `search`
- Fixture réutilisable pour tester le pipeline blob brut bout-en-bout côté backends / CLI
- Détection ARM32 renforcée pour mieux retrouver la fonction d'entrée sur des blobs bruts simples
- Persistance du profil `arch / base_addr / endian` côté extension pour rouvrir un blob avec le bon contexte

**Reste à pousser :**

- Mieux distinguer les vues disponibles / indisponibles pour éviter les faux espoirs UX
- Étendre le corpus de régression aux architectures Capstone ajoutées (`MIPS`, `PPC`, `SPARC`, `RISC-V`, `BPF`, `WASM`, etc.) avec validation des mnemonics de branchement et retour
- Étendre ce corpus à des blobs plus proches de vrais firmwares / dumps partiels et ajouter des cas big-endian

---

### ✅ Taint analysis — inter-procédurale
**Fichier :** `backends/static/taint.py`
**Statut :** livré sur le noyau actuel

**Livré :**

- Suivi source → sink à travers les appels de fonctions sur 2 niveaux
- Détection des wrappers autour des sources et des sinks (`my_read()` → `read()`, `my_system()` → `system()`)
- Remontée des chemins `source_path` / `sink_path`, de la fonction porteuse `via_fn`, et des origines réelles `source_origin` / `sink_origin`
- Préférence automatique pour le mode inter-procédural quand un call graph est disponible, avec fallback propre vers l'analyse legacy

**Suite logique :**
- Ajouter un vrai corpus de binaires réels pour calibrer le scoring et enrichir les patterns de wrappers plus agressifs

---

### ⚠️ String déobfuscation — couverture XOR étendue
**Fichier :** `backends/static/string_deobfuscate.py`
**Problème :** les régions XOR adjacentes avec clés différentes fusionnent en une seule région non décodable

**Livré dans le lot actuel :**

- Découpage des régions non-ASCII en fenêtres glissantes pour tenter XOR sur chaque sous-région
- Arbitrage entre décodage global et sous-fenêtres quand une grosse région contient plusieurs strings XOR adjacentes
- Tests ciblés pour les régions XOR fusionnées avec plusieurs clés
- Extraction de clés hardcodées plausibles depuis le binaire (ASCII + clés hex encodées)
- Déchiffrement `RC4` en pur Python autour des régions voisines des clés détectées
- Support `AES-ECB` quand `cryptography` est disponible, sans en faire une dépendance obligatoire
- Remontée de `key_hint` / `key_addr` pour expliquer quelle constante a servi au décodage

**Reste à pousser :**

- Étendre la détection de clés au-delà des chaînes imprimables proches (const arrays, blocs plus éloignés)
- Relier plus explicitement les indices `behavior.py` (ex. S-box AES) aux tentatives de déchiffrement

---

### ⚠️ Clean / Cleanup transverse
**Fichiers :** `extension/webview/hub.js` + `extension/src/static/hub.js` + `backends/static/cache.py` + `backends/static/analysis_index.py`
**Problème :** une partie du produit repose encore sur des chemins historiques, des fallbacks multiples et un hub trop gros

**Livré dans le lot actuel :**

- Centralisation du flux d'ouverture du désassemblage
- Déduplication de la génération des artefacts (`.asm`, mapping, caches d'analyse)
- Centralisation des fallbacks legacy `.asm/.mapping`
- Résolution binaire / artefacts / mapping factorisée côté extension
- Cache UI d'analyse plus homogène pour `CFG`, `Call Graph`, `Discovered functions`
- Exécution JSON Python et chargement des symboles rationalisés dans le hub static

- Découper `hub.js` en modules lisibles (navigation, graphes, contexte, loaders, actions)
- Faire de la base d'analyse SQLite la source de vérité unique, au lieu de reparcourir `.asm` / mapping dès qu'on peut l'éviter
- Nettoyer les fallbacks legacy et les chemins morts côté UI / backend
- Rationaliser le cache UI vs cache d'analyse pour éviter les incohérences perçues par l'utilisateur
- Formaliser un vrai `user path` d'ouverture binaire / blob / récents / navigation croisée

---

## 4. Améliorations pour maximum de contexte

Objectif : transformer les vues isolées en analyse corrélée. Les modules doivent produire des preuves, des niveaux de confiance et des liens vers les autres vues, pour éviter les résultats superficiels.

| Priorité | Module | Limite actuelle | Amélioration cible | Contexte à croiser |
|----------|--------|-----------------|--------------------|--------------------|
| 🔥🔥🔥 | `vuln_patterns.py` | Liste des APIs dangereuses, faux positifs possibles | Classer `dangerous_api` / `potential_vulnerability` / `confirmed_vulnerability`, ajouter `confidence`, `evidence`, `needs_review` | imports, call graph, taint, xrefs, décompile, stack frame, trace dynamique |
| 🔥🔥🔥 | `taint.py` | Source→sink léger, surtout basé sur imports/call graph | Suivre les arguments réellement passés, distinguer source contrôlée, constante, taille bornée, wrapper sécurisé | ABI, calling convention, xrefs, pseudo-C, stack frame, strings, dynamic argv/stdin |
| 🔥🔥 | `behavior.py` | Indicateurs par strings/IP/URL/constantes | Grouper les indicateurs par fonction, remonter callsites et score expliqué par preuve | strings, imports, xrefs, call graph, capa, yara, sections, entropie |
| 🔥🔥 | `anti_analysis.py` | Strings VM, imports anti-debug, patterns timing simples | Ajouter contexte de fonction, callsites, familles de techniques, contournements reliés aux offsets patchables | imports, xrefs, disasm, patch manager, behavior, strings |
| 🔥🔥 | `packer_detect.py` / `entropy.py` | Signatures + entropie, peut sur-signaler | Expliquer les sections suspectes, comparer entropie section/globale, lier aux imports et ressources anormales | headers, sections, entropy, imports, pe_resources, strings |
| 🔥🔥 | `decompile.py` | Qualité dépendante des backends, sortie parfois bruitée | Afficher score de qualité, origine du backend, placeholders restants, liens vers ASM/CFG/stack | annotations, stack frame, structs, xrefs, typed data |
| 🔥🔥 | `cfg.py` / `call_graph.py` | Sauts indirects, wrappers et thunks encore fragiles | Annoter incertitudes, résoudre plus de tables indirectes, lier chaque arête à son instruction source | disasm, symbols, imports, xrefs, discover_functions |
| 🔥 | `discover_functions.py` | Heuristique de fonctions sur binaires stripped | Ajouter métriques de couverture, conflits, fonctions orphelines et raisons de frontière | symbols, cfg, call graph, disasm, exceptions, exports |
| 🔥 | `stack_frame.py` / `calling_convention.py` | Reconstruction probable, fragile sans frame pointer | Remonter niveau de confiance par variable/argument, source de preuve et offsets ambigus | DWARF, ABI, disasm, decompile, dynamic stack |
| 🔥 | `rop_gadgets.py` | Gadgets candidats, contraintes non vérifiées | Ajouter contraintes pratiques : regs détruits, stack delta, bad bytes, pivot réel, section exécutable | sections, permissions, arch support, disasm |
| 🔥 | `flirt.py` / `func_similarity.py` | Base limitée, matching probable | Étendre corpus, expliquer le score, distinguer signature exacte vs similarité floue | function hash, CFG, symbols, imports, bundled DB |
| 🔥 | `string_deobfuscate.py` | Candidats de chaînes décodées, bruit possible | Lier chaque décodage à une clé, une fonction et un usage en xref | strings, xrefs, behavior, decompile, entropy |
| ⚠️ | `yara_scan.py` / `capa_scan.py` | Dépend des règles et outils installés | Afficher disponibilité, version, règles actives, preuves et liens vers offsets/fonctions | rules_manager, strings, xrefs, behavior |
| ⚠️ | `pe_resources.py` / `exception_handlers.py` | Vues utiles mais peu reliées au reste | Relier ressources/handlers aux indicateurs, imports, sections et anomalies | headers, sections, behavior, packer_detect |

### Modèle de sortie commun à généraliser

Chaque module d'audit devrait tendre vers un format commun :

```json
{
  "kind": "signal | hypothesis | confirmed",
  "confidence": "LOW | MEDIUM | HIGH",
  "evidence": ["import strcpy", "callsite 0x401234", "argv[1] reaches arg1"],
  "addr": "0x401234",
  "function": "main",
  "related": {
    "imports": ["strcpy"],
    "xrefs": ["0x401234"],
    "strings": ["cmd.exe"],
    "sections": [".text"]
  },
  "needs_review": true
}
```

### UX à améliorer

- Remplacer les titres trop affirmatifs par des labels honnêtes : `signal`, `suspect`, `confirmé`.
- Ajouter des badges `confidence` et `source de preuve` dans les vues Malware / Offensif.
- Chaque résultat doit proposer des actions : aller au désassemblage, ouvrir les xrefs, ouvrir la fonction dans le pseudo-C, afficher la stack frame, créer une annotation.
- Ajouter une vue “Dossier de preuve” par fonction : imports, strings, xrefs, comportement, taint, vuln signals, patches possibles.
- Afficher explicitement quand une feature est `partielle`, `heuristique`, `indisponible` ou dépendante d'un outil externe.

---

## 5. Résumé priorisé

### Nouvelles features restantes

| Priorité | Feature | Effort | Impact vs IDA |
|----------|---------|--------|--------------|
| 🔥🔥 | Base de signatures MinHash | Moyen | Identification sans binaire de référence |
| 🔥 | Éditeur de structures C v2 | Moyen | Enum/union + propagation plus profonde |

### Améliorations restantes

| Priorité | Module | Effort | Impact |
|----------|--------|--------|--------|
| 🔥🔥🔥 | Portabilité multi-arch Capstone | Élevé | Toutes les features statiques fiables par ISA |
| 🔥🔥🔥 | Contexte maximal / dossier de preuve | Élevé | Transforme les signaux isolés en analyse exploitable |
| 🔥🔥🔥 | Vuln patterns + taint avec niveaux de preuve | Moyen | Réduit les faux positifs et clarifie l'exploitabilité |
| 🔥🔥 | Clean / cleanup transverse | Moyen | Réduit la dette technique et les régressions UX |
| 🔥🔥 | Support blobs bruts étendu | Moyen | Couvre plus de cas réels de reverse |
| 🔥🔥 | Behavior / anti-analysis / packer contextualisés | Moyen | Moins de résultats superficiels, plus de preuves actionnables |
| 🔥🔥 | Mnemonics ISA Capstone | Moyen | CFG/xrefs fiables hors x86/ARM |
| 🔥🔥 | Hex ↔ Disasm sync | Faible | Workflow critique |
| 🔥 | CFG switch tables | Moyen | Fiabilité analyse |
| 🔥 | Décompilateur post-processing | Faible | Lisibilité immédiate |
| ⚠️ | XOR fenêtres glissantes | Moyen | Couverture malware |

---

*Dernière mise à jour : 2026-04-22 — support Capstone multi-arch générique ✅, portabilité complète des features par ISA à planifier 🔁, mnemonics ISA multi-arch à enrichir 🔁, structs v2 partiel ✅, function similarity DB locale ✅, raw ARM blobs ✅, CFG switch cases ✅, hex↔désasm v2 ✅, cleanup transverse partiel 🔁*
