# Support des plateformes (Windows, macOS, Linux)

L’extension et les backends sont conçus pour **Windows, macOS et Linux**, avec des différences selon le mode (statique vs dynamique) et les outils système. Le MOSCOW indique « Fonctionne sur Windows » en Must have.

---

## Résumé


| Plateforme  | Mode statique | Mode dynamique                            | Remarques                                                                          |
| ----------- | ------------- | ----------------------------------------- | ---------------------------------------------------------------------------------- |
| **Linux**   | ✅ Complet     | ✅ Complet (32-bit possible avec multilib) | Environnement cible principal (gcc, objdump, Unicorn).                             |
| **macOS**   | ✅ Complet     | ✅ Complet (64-bit uniquement)             | Symbole C préfixé `_` (ex. `_main`). Pas de `-z execstack`.                        |
| **Windows** | ✅ Complet     | ⚠️ Sous conditions                        | Python/Node/Unicorn OK. Pour dynamique : gcc et binutils (MinGW/MSYS2/WSL) requis. |


---

## Détails par plateforme

### Linux

- **Mode statique** : `backends/static/asm_sim.py` (Python pur) → aucune dépendance système.
- **Mode dynamique** : `gcc`, Unicorn, optionnellement `objdump`, `addr2line`, `nm`. Build 32-bit possible si `gcc-multilib` et `libc6-dev-i386` installés.
- **Makefile** : cible `make install` / `make pipeline` utilisable directement.

### macOS

- **Mode statique** : idem Linux.
- **Mode dynamique** : l’extension force `-arch x86_64` pour Unicorn. Les symboles C sont préfixés par `_` (ex. `_main`). `-z execstack` et PIE sont gérés différemment (voir `extension.js`).
- **32-bit** : non disponible (désactivé dans l’UI).
- **Makefile** : utilisable (bash fourni par Xcode ou système).

### Windows

- **Mode statique** : Python + `backends/static/asm_sim.py` → OK. Aucun outil externe obligatoire.
- **Mode dynamique** :
  - **Python / Unicorn** : OK (venv avec `backends\.venv\Scripts\python.exe` géré).
  - **Compilation et désassemblage** : nécessite un outilchain de type Unix (gcc, objdump, addr2line) :
    - **Option 1** : [MSYS2](https://www.msys2.org/) ou [MinGW-w64](https://www.mingw-w64.org/) avec `gcc` et binutils dans le `PATH`.
    - **Option 2** : WSL (Windows Subsystem for Linux) : ouvrir le projet dans WSL et utiliser Linux.
- **Makefile** : cibles basées sur un shell Unix. Utiliser Git Bash ou WSL sur Windows. Détection OS (Linux, Darwin, Windows) et chemins adaptés (Scripts vs bin). Cibles `demo-elf` et `capa-docker` requièrent Docker. Sans Make : `python -m venv backends\.venv`, `backends\.venv\Scripts\activate`, `pip install -r requirements.txt`, puis lancer les scripts Python à la main.

---

## Points techniques (extension)

- **Chemins** : `path.join()` (Node) et `os.path.join` (Python) pour des chemins multi‑plateforme.
- **Venv** : détection de `backends/.venv/bin/python3` (Linux/macOS) et `backends/.venv/Scripts/python.exe` (Windows) ; après création automatique d’un venv, l’extension pointe bien vers le Python du venv sur les trois OS.
- **32-bit** : vérification uniquement sur Linux (en-têtes multilib) ; sur macOS/Windows l’UI propose uniquement du 64-bit pour le mode dynamique.
- **Outils optionnels** : `objdump`, `addr2line`, `nm` sont utilisés s’ils sont trouvés (`shutil.which`), sinon le mode dynamique fonctionne avec des champs désassemblage/vignettes vides.

---

## En résumé

- **Oui**, le code est prévu pour **tourner sur Windows, macOS et Linux**.
- **Mode statique** : support complet sur les trois OS sans outil externe (sauf Python).
- **Mode dynamique** : complet sur Linux/macOS ; sur Windows, il faut un environnement de type gcc/binutils (MinGW, MSYS2 ou WSL) pour compiler et désassembler.

