# Pile ou Face - VS Code Extension

Extension VS Code pour visualiser graphiquement la pile à partir d'un `output.json` généré par le simulateur C.

## Structure du projet

```
extension/
├── src/
│   └── extension.js       # Code principal de l'extension
├── webview/
│   ├── app/              # Code JavaScript frontend
│   └── media/            # HTML, CSS et assets
├── test/                 # Tests unitaires
├── .eslintrc             # Configuration ESLint
├── .prettierrc            # Configuration Prettier
└── package.json          # Configuration npm
```

## Installation

```bash
cd extension
npm install
```

## Scripts disponibles

- `npm test` - Exécuter les tests
- `npm run test:watch` - Tests en mode watch
- `npm run test:coverage` - Couverture de code
- `npm run lint` - Vérifier le code
- `npm run lint:fix` - Corriger le code automatiquement

## Développement

Pour debugger l'extension, appuyez sur `F5` dans VS Code pour lancer le mode debug.

## Commandes disponibles

- `Pile ou Face: Exécuter la trace...` - Lance la pipeline complète de traçage

## Assistant Ollama dans l'UI

Dans le Hub :

1. Rester sur la page `Dashboard`
2. Utiliser la carte `Discussion Ollama + MCP`
3. Cliquer sur `Rafraîchir` pour charger les modèles Ollama
4. Choisir un modèle, écrire un message, puis `Envoyer`

La discussion garde un historique local pour conserver le contexte entre messages.
`Nouvelle discussion` démarre un nouveau fil, et la zone `Historique des conversations`
permet de rouvrir une discussion précédente ou de tout vider.
Un bouton flottant `IA` est aussi disponible depuis tous les onglets pour discuter sans revenir au Dashboard.
Chaque message est exécuté via `backends/mcp/ollama_bridge.py` et peut appeler les outils MCP sans passer par le terminal.
