# Architecture de la partie statique

## Principe general

La partie statique est construite comme une chaine d'analyse modulaire :

```text
Webview VS Code
   -> messages JavaScript
   -> handlers de l'extension
   -> scripts Python backends/static
   -> JSON
   -> rendu dans le hub
```

Chaque analyse statique est un module Python autonome. Cela permet de l'appeler depuis l'interface VS Code, depuis une CLI, depuis des tests, ou depuis l'API de scripting.

## Couches principales

### Interface webview

Fichiers :

- `extension/webview/static/panel-static.html`
- `extension/webview/static/panel-static.css`
- `extension/webview/hub.js`
- `extension/webview/shared/cfgHelpers.js`

Responsabilites :

- afficher les groupes `CODE`, `DATA`, `MALWARE`, `OFFENSIF`;
- gerer les onglets;
- afficher tableaux, graphes, resultats et formulaires;
- envoyer les actions utilisateur a l'extension;
- garder le contexte actif : fonction, adresse, selection.

### Extension VS Code

Fichiers :

- `extension/src/static/hub.js`
- `extension/src/static/staticHandlers.js`
- `extension/src/static/commands.js`
- `extension/src/static/handlers.js`
- `extension/src/shared/staticCache.js`
- `extension/src/shared/fileManager.js`

Responsabilites :

- recevoir les messages de la webview;
- resoudre le chemin du binaire actif;
- lancer les modules Python;
- gerer les artefacts `.asm`, mappings et caches;
- ouvrir les documents dans VS Code;
- faire le pont entre UI et backend.

### Backend Python

Dossier :

- `backends/static/`

Responsabilites :

- parser les binaires;
- desassembler;
- extraire metadonnees, sections, symboles, strings et imports;
- construire CFG, call graph et xrefs;
- lancer analyses malware et offensives;
- produire du JSON stable pour l'interface;
- exposer des CLI testables.

## Flux d'une analyse simple

Exemple : chargement des strings.

```text
1. L'utilisateur ouvre l'onglet Strings.
2. hub.js envoie un message `hubLoadStrings`.
3. extension/src/static/hub.js resout le chemin du binaire.
4. Le handler lance `backends/static/strings.py`.
5. Le module retourne une liste JSON.
6. La webview affiche le tableau et les boutons d'export.
```

## Flux du desassemblage

Le desassemblage est un flux plus riche parce qu'il produit des artefacts reutilises par d'autres vues.

```text
1. L'utilisateur clique `Ouvrir le desassemblage`.
2. L'extension resout le binaire actif.
3. `backends/static/disasm.py` genere un `.asm`.
4. Un mapping JSON relie chaque adresse a une ligne.
5. VS Code ouvre le fichier `.asm`.
6. CFG, call graph, xrefs et navigation utilisent le mapping.
```

Artefacts typiques :

- fichier de desassemblage `.asm`;
- fichier de mapping `.disasm.mapping.json`;
- caches d'analyse;
- annotations;
- patches.

## Backend statique par domaines

### Parsing et metadonnees

- `headers.py`
- `sections.py`
- `symbols.py`
- `entropy.py`
- `packer_detect.py`
- `pe_resources.py`
- `binary_exports.py`
- `exception_handlers.py`

### Code et graphes

- `disasm.py`
- `arch.py`
- `cfg.py`
- `call_graph.py`
- `discover_functions.py`
- `xrefs.py`
- `import_xrefs.py`
- `stack_frame.py`
- `calling_convention.py`
- `decompile.py`
- `ghidra_decompile.py`

### Donnees

- `strings.py`
- `search.py`
- `hex_view.py`
- `typed_data.py`
- `structs.py`
- `typed_struct_refs.py`
- `dwarf.py`

### Malware et securite

- `behavior.py`
- `taint.py`
- `anti_analysis.py`
- `yara_scan.py`
- `capa_scan.py`
- `rules_manager.py`
- `vuln_patterns.py`

### Offensif et enrichissement

- `rop_gadgets.py`
- `flirt.py`
- `func_similarity.py`
- `string_deobfuscate.py`
- `bindiff.py`
- `binary_patch.py`
- `patch_manager.py`
- `annotations.py`
- `export.py`
- `repl.py`

## Cache et persistance

Le projet evite de recalculer certaines analyses lourdes.

Elements persistants :

- `.pile-ou-face/static_cache/` : caches par binaire;
- `.pile-ou-face/annotations/` : labels, commentaires, bookmarks;
- `.pile-ou-face/decompile_cache/` : pseudo-C mis en cache;
- `.pile-ou-face/pfdb/` : base d'analyse SQLite selon les modules;
- `.pile-ou-face/structs.json` : definitions de structs/unions/enums;
- `.pile-ou-face/patches/` : patchs persistants.

## Formats supportes

Formats principaux :

- ELF;
- PE;
- Mach-O;
- blob brut.

Architectures prises en charge selon les modules :

- x86 / x86-64;
- ARM / Thumb;
- AArch64;
- MIPS;
- PowerPC;
- SPARC;
- RISC-V;
- BPF;
- WebAssembly;
- M68K;
- SH;
- TriCore.

Toutes les features n'ont pas le meme niveau de support sur chaque architecture. Le module `backends/static/arch.py` centralise la matrice de support et les conventions propres aux ISA.

## Tests

La partie statique dispose d'une suite pytest dans :

- `backends/static/tests/`

Exemples couverts :

- desassemblage;
- CFG;
- xrefs;
- headers;
- sections;
- strings;
- entropy;
- imports;
- decompilation;
- stack frame;
- binary patch;
- ROP;
- YARA;
- CAPA;
- structs;
- typed data;
- binary diff;
- API `pof`.

Commande :

```bash
python -m pytest backends/static/tests
```

## Extension et tests JavaScript

Les tests de l'extension se trouvent dans :

- `extension/test/`

Ils couvrent notamment :

- payload hex;
- visualiseur;
- handlers statiques;
- modeles de pile;
- helpers CFG;
- profils d'architecture raw.

Commande :

```bash
npm test -C extension
```

## Pourquoi cette architecture est utile

- Les modules Python restent reutilisables hors interface.
- La webview reste concentree sur l'ergonomie.
- Les handlers JavaScript isolent les details VS Code.
- Les resultats JSON facilitent les tests et l'export.
- Le projet peut ajouter une feature en creant un module backend, un handler, puis une vue.

