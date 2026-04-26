# Implementation MCP

Ce document decrit l'implementation actuelle du serveur MCP backend.

## Emplacement du code

- Serveur principal : `backends/mcp/server.py`
- Wrapper compatibilite : `backends/mcp_server.py`
- Bridge Ollama <-> MCP : `backends/mcp/ollama_bridge.py`

## Transport et protocole

- Transport actif : `stdio`
- Protocole : JSON-RPC 2.0
- Framing : `Content-Length` + payload JSON UTF-8

Methodes supportees :

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

Contexte memoire:

- Le serveur charge `docs/mcp/memory.md` (fallback legacy: `docs/mcp/docs/memory.md` puis `memory.md`).
- Si le fichier existe, `initialize` retourne aussi un champ `instructions` avec ce contexte.
- Le bridge `ollama_bridge.py` ajoute automatiquement ce contenu au `system prompt` pour ameliorer les reponses.

## Couverture des outils

Le serveur expose la matrice complete documentee dans `docs/mcp/modules.md`.

- Nombre total d'outils exposes : `49`
- Noms exposes : `annotations_*`, `cache_*`, `rules_*`, `disassemble`, `build_cfg*`, `build_call_graph`, `get_xrefs`, `get_symbols`, `extract_strings`, `get_binary_info`, `analyze_imports`, `decompile_*`, `find_vulnerabilities`, `taint_analysis`, `detect_packers`, `find_rop_gadgets`, `yara_scan`, `capa_scan`, `find_files`, etc.

Verification rapide :

```bash
python3 backends/mcp/ollama_bridge.py --list-tools
```

## Routage et normalisation des arguments

Le routeur `_call_tool()` dans `backends/mcp/server.py` :

- normalise les chemins (`binary_path`/`binary`) ;
- accepte les offsets/adresses en decimal ou hex (`0x...`) ;
- genere automatiquement un mapping de desassemblage si un outil CFG/XREF en a besoin ;
- execute directement les modules `backends/static/*` (et garde une compatibilite `pof.symbols` pour `get_symbols`).

## Resolution automatique des binaires

- Chemin absolu
- Chemin relatif au workspace
- Nom de fichier seul (ex: `demo_analysis.elf`) via recherche workspace

Cette resolution est utilisee par tous les outils prenant `binary_path`.

## Gestion des erreurs

- Erreurs JSON-RPC standard pour requetes invalides.
- Erreurs outils encapsulees en resultat MCP (`isError: true`) avec payload JSON.
- Le champ `structuredContent` contient toujours la charge utile exploitable par le client.

## Integration Ollama

Le bridge `ollama_bridge.py` :

1. demarre le serveur MCP local ;
2. recupere `tools/list` ;
3. convertit les schemas MCP en tools Ollama (`type=function`) ;
4. execute les `tool_calls` via `tools/call` ;
5. reinjecte les resultats outils dans la conversation.

Le bridge inclut aussi un fallback quand le modele repond sans appeler d'outil sur une demande qui devrait en utiliser.
