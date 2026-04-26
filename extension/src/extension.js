/**
 * @file extension.js
 * @brief Entree principale de l'extension VS Code.
 * @details Charge output.json, cree la webview et relie les commandes.
 */

const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { SidebarSymbolsProvider, SidebarStringsProvider, SidebarSectionsProvider, SidebarCalculatorProvider } = require('./shared/sidebarProvider');
const { ensureStaticAsm } = require('./static/asmBuilder');
const { createVisualizer } = require('./dynamic/visualizer');
const { createHub } = require('./static/hub');
const {
  logChannel,
  getTempDir,
  ensureTempDir,
  runCommand,
  detectPythonExecutable,
  buildRuntimeEnv,
  ensurePythonDependencies,
  check32BitToolchain,
} = require('./shared/utils');
const { readTraceJson, writeTraceJson, setViewMode, loadTraceFromWorkspace } = require('./shared/trace');
const { payloadToHex, parseStdinExpression } = require('./shared/payload');
const { getDisasmScript } = require('./shared/paths');
const { registerSharedCommands } = require('./shared/commands');
const { registerStaticCommands } = require('./static/commands');
const { registerDecompilerCommands } = require('./static/decompilerCommands');

const decorationTypes = new Map();


/**
 * @brief Active l'extension et enregistre les commandes.
 * @param context Contexte VS Code.
 */
function activate(context) {
  // Ensure Python dependencies are installed at startup
  const folders = vscode.workspace.workspaceFolders;
  if (folders && folders.length > 0) {
    const root = folders[0].uri.fsPath;
    const pythonExe = detectPythonExecutable(root);
    ensurePythonDependencies(pythonExe, root).catch((err) => {
      logChannel.appendLine(`[Python setup] Warning: ${err.message}`);
    });
  }

  // checkDecompilerDeps supprimé : l'install est proposé à la demande via le dropdown

  const openVisualizerWebview = createVisualizer({ context, logChannel, decorationTypes });
  const hubConfig = {
    context,
    logChannel,
    getTempDir,
    ensureTempDir,
    runCommand,
    detectPythonExecutable,
    ensureStaticAsm,
    readTraceJson,
    writeTraceJson,
    setViewMode,
    payloadToHex,
    parseStdinExpression,
    check32BitToolchain,
    openVisualizerWebview
  };
  const openHub = createHub(hubConfig);

  // Commandes partagées (open, goToAddress, calculator)
  const sharedSubs = registerSharedCommands(context, { logChannel, openHub });
  context.subscriptions.push(...sharedSubs);

  // Panneau latéral et refresh
  const root = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath || '';
  const savedSettings = context.globalState.get('pof-settings', {});
  const pythonExe = savedSettings.pythonPath || (root ? detectPythonExecutable(root) : 'python3');
  const symbolsProvider = new SidebarSymbolsProvider(root, pythonExe);
  const stringsProvider = new SidebarStringsProvider(root, pythonExe);
  const sectionsProvider = new SidebarSectionsProvider(root, pythonExe);
  const calculatorProvider = new SidebarCalculatorProvider();
  vscode.window.registerTreeDataProvider('pileOuFace.symbols', symbolsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.strings', stringsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.sections', sectionsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.calculator', calculatorProvider);

  const refreshSidebar = (binaryPath) => {
    if (binaryPath) {
      symbolsProvider.refresh(binaryPath);
      stringsProvider.refresh(binaryPath);
      sectionsProvider.refresh(binaryPath);
    }
  };
  const setSidebarMode = (mode) => {
    symbolsProvider.setMode(mode);
    stringsProvider.setMode(mode);
    sectionsProvider.setMode(mode);
  };
  hubConfig.refreshSidebar = refreshSidebar;
  hubConfig.setSidebarMode = setSidebarMode;

  // Commandes statiques (exportDisasm, xrefs, sidebarRefresh, goToSymbolInDisasm, disasmSection)
  const staticDeps = {
    ensureTempDir,
    runCommand,
    detectPythonExecutable,
    logChannel,
  };
  const staticProviders = { root, pythonExe, refreshSidebar };
  const staticSubs = registerStaticCommands(context, staticDeps, staticProviders);
  context.subscriptions.push(...staticSubs);

  // Commandes de gestion des décompilateurs (add, remove, list, test, openConfig)
  const cp = require('child_process');
  const _runPythonForCmds = (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024, cwd } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = require('path').join(cwd || root, scriptRelPath);
      cp.execFile(pythonExe, [scriptPath, ...rest], {
        encoding: 'utf8', cwd: cwd || root, maxBuffer, timeout,
        env: buildRuntimeEnv(cwd || root),
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });
  const decompilerDeps = { runPython: _runPythonForCmds, logChannel };
  const decompilerSubs = registerDecompilerCommands(context, decompilerDeps, root);
  context.subscriptions.push(...decompilerSubs);
}

/**
 * @brief Desactive l'extension (hook VS Code).
 */
function deactivate() {
  for (const deco of decorationTypes.values()) {
    deco.dispose();
  }
  decorationTypes.clear();
}

module.exports = {
  activate,
  deactivate,
  loadTraceFromWorkspace,
  payloadToHex,
  parseStdinExpression
};
