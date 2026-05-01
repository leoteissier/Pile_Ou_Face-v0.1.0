# Décompilateurs

Pile ou Face expose trois décompilateurs intégrés: `ghidra`, `retdec` et `angr`,
avec un fallback Docker par backend, plus des décompilateurs `custom` déclarés
par l'utilisateur.

## Provider

```bash
python -m backends.static.decompile --list --provider auto
python -m backends.static.decompile --binary ./sample.elf --addr 0x401000 --quality precision
python -m backends.static.decompile --binary ./sample.elf --addr 0x401000 --provider docker --decompiler retdec
```

- `auto` : essaie l'outil local, puis l'image Docker du décompilateur demandé si elle existe.
- `local` : n'utilise que les outils installés sur la machine.
- `docker` : force l'image dédiée au décompilateur demandé.

Les images locales se construisent une par une :

```bash
make decompiler-docker-build DECOMPILER=retdec
make decompiler-docker-list DECOMPILER=retdec
```

Images builtin attendues par défaut :

```text
pile-ou-face/decompiler-ghidra:latest
pile-ou-face/decompiler-retdec:latest
pile-ou-face/decompiler-angr:latest
```

Chaque image peut être surchargée avec une variable d'environnement dédiée :

```bash
export POF_DECOMPILER_IMAGE_RETDEC=my-registry/retdec:latest
export POF_DECOMPILER_IMAGE_GHIDRA=my-registry/ghidra:latest
export POF_DECOMPILER_IMAGE_ANGR=my-registry/angr:latest
```

## Décompilateur Custom

Créez `.pile-ou-face/decompilers.json` :

```json
{
  "decompilers": {
    "my-ghidra": {
      "label": "Mon backend custom",
      "docker_image": "my-registry/my-ghidra:latest",
      "command": [
        "/opt/tools/my-ghidra-wrapper",
        "--binary",
        "{binary}",
        "--addr",
        "{addr}",
        "--out",
        "{out}"
      ],
      "full_command": [
        "/opt/tools/my-ghidra-wrapper",
        "--binary",
        "{binary}",
        "--full",
        "--out",
        "{out}"
      ],
      "docker_command": [
        "/usr/local/bin/my-ghidra-wrapper",
        "--binary",
        "{binary}",
        "--addr",
        "{addr}",
        "--out",
        "{out}"
      ],
      "docker_full_command": [
        "/usr/local/bin/my-ghidra-wrapper",
        "--binary",
        "{binary}",
        "--full",
        "--out",
        "{out}"
      ],
      "supports_full": true,
      "timeout": 180
    }
  }
}
```

La commande doit écrire du JSON sur stdout ou dans `{out}` :

```json
{"addr":"0x401000","code":"int main(){ return 0; }","error":null}
```

Pour une vue globale, elle peut renvoyer :

```json
{"functions":[{"addr":"0x401000","code":"int main(){ return 0; }"}],"error":null}
```

La sélection du backend se fait directement dans la vue `Pseudo-C`. L'interface
propose `Auto` ou un backend précis parmi ceux détectés.

Tu peux déclarer autant de décompilateurs custom que tu veux :

```json
{
  "decompilers": {
    "my-ghidra": { "...": "..." },
    "my-retdec-tuned": { "...": "..." },
    "my-binja": { "...": "..." }
  }
}
```

En mode `docker`, un custom utilise `docker_image` et `docker_command` s'ils
sont présents. Sinon il retombe sur `command`, ce qui est pratique si ton image
embarque déjà exactement le même wrapper.
