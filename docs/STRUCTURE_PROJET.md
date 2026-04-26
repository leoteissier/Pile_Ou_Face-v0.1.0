# Structure du projet — Python + Node (extension VS Code)

Ce document décrit la gestion correcte de `.venv` et `node_modules` pour une extension VS Code qui utilise Python et JavaScript.

---

## 1. Architecture actuelle

```
Pile_Ou_Face/
├── backends/              # Python (backend)
│   ├── .venv/             # Venv Python (pas à la racine)
│   │   ├── bin/python3
│   │   └── bin/pip
│   ├── static/            # Analyse statique (disasm, headers, cfg, etc.) + CLI
│   │   └── tests/
│   ├── dynamic/           # Pipeline dynamique (run_pipeline Unicorn)
│   └── shared/            # Utilitaires partagés (normalize_addr, addr_to_int)
├── requirements.txt       # Python
└── Makefile
```

---

## 2. Bonnes pratiques

### 2.1 Python (backends)

| Règle | Implémentation |
|-------|----------------|
| **Emplacement** | `.venv` dans **backends/** (partie Python, pas à la racine) |
| **Raison** | Le backend Python est isolé dans `backends/` ; tests et venv y sont regroupés |
| **Création** | `make venv` ou `python3 -m venv backends/.venv` |
| **Installation** | `make install` ou `backends/.venv/bin/pip install -r requirements.txt` |
| **Détection** | `extension/src/shared/utils.js` → `detectPythonExecutable(root)` préfère `backends/.venv/bin/python3` |

### 2.2 Node (node_modules)

| Règle | Implémentation |
|-------|----------------|
| **Emplacement** | `extension/node_modules/` (dans le dossier de l’extension) |
| **Raison** | VS Code charge l’extension depuis `extension/` ; `package.json` et `node_modules` doivent être co-localisés |
| **Installation** | `cd extension && npm install` |
| **CI** | `npm ci` dans `extension/` pour un install reproductible |

### 2.3 Ce qu’il ne faut pas faire

- ❌ `.venv` à la racine → la partie Python est regroupée dans `backends/`
- ❌ `node_modules` à la racine → l’extension ne les trouve pas
- ❌ Mélanger les deux dans le même dossier

---

## 3. Flux d’activation

1. L’utilisateur ouvre le workspace (dossier racine).
2. L’extension s’active (`extension.js` → `activate()`).
3. `detectPythonExecutable(root)` retourne `backends/.venv/bin/python3` si présent, sinon `python3`.
4. `ensurePythonDependencies(pythonExe, root)` :
   - Crée `backends/.venv` si absent (quand `pythonExe` est `python3`/`python`)
   - Exécute `pip install -r requirements.txt` si une dépendance manque
5. L’extension utilise `pythonExe` pour appeler les scripts Python.

---

## 4. .gitignore

```gitignore
# Python
.venv/
backends/.venv/
__pycache__/
*.pyc

# Node
node_modules/
```

- `backends/.venv` et `node_modules` sont ignorés.
- `requirements.txt` et `package.json` sont versionnés.

---

## 5. Commandes recommandées

```bash
# Setup initial
make venv
make install
cd extension && npm install

# Ou manuellement
python3 -m venv backends/.venv
backends/.venv/bin/pip install -r requirements.txt
cd extension && npm install
```

---

## 6. Cas particuliers : capa

Le script `capa` installé par `flare-capa` peut provoquer `Permission denied` sur certains systèmes. L’extension contourne en appelant l’API Python directement :

```python
# backends/static/capa_scan.py
subprocess.run([sys.executable, "-c", "import sys; sys.argv=['capa','-j',path]; from capa.main import main; main()"])
```

Cela évite d’exécuter `backends/.venv/bin/capa` directement.

**Règles capa** : l'installation pip n'inclut pas les règles. Exécutez `make capa-rules` pour cloner capa-rules à la racine, ou définissez `CAPA_RULES_PATH`.

---

## 7. Tests Python

Les tests unitaires static sont dans `backends/static/tests/`.
Les tests du domaine dynamique sont dans `backends/dynamic/tests/`.

| Élément | Détail |
|---------|--------|
| **Static** | `backends/static/tests/` |
| **Dynamic** | `backends/dynamic/tests/` |
| **Lancement static** | `python3 backends/static/tests/run_tests.py` ou `make test` |
| **Lancement dynamic** | `python3 -m unittest discover backends/dynamic/tests -v` |

---

*Document de référence pour la structure du projet Pile ou Face.*
