/**
 * @file hub.js
 * @brief Hub principal (UI MOSCOW) et gestion des messages webview.
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { getHubContent } = require('../shared/webview');
const { buildRuntimeEnv } = require('../shared/utils');
const {
  isSupportedBinary,
  inspectBinaryInput,
  getRawArchDescriptor,
  normalizeRawProfile,
} = require('../shared/sharedHandlers');
const {
  findSymbolByCandidates,
  isMachOFormat,
  mainSymbolCandidates,
  normalizeStartSymbolForBinary,
  preferredMainSymbol,
  symbolLookupCandidates,
} = require('../shared/symbols');
const {
  detectPayloadTargetFromSourceText,
  normalizePayloadTargetMode,
  payloadTargetLabel,
  resolvePayloadTarget,
} = require('../shared/dynamicInputTarget');
const { readCache, writeCache } = require('../shared/staticCache');
const { createHandlers } = require('./handlers');
const {
  getDisasmScript,
  getHeadersScript,
  getSymbolsScript,
  getStringsScript,
  getSectionsScript,
  getCfgScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
  getXrefsScript,
  getYaraScanScript,
  getCapaScanScript,
  getRulesManagerScript,
  getSearchScript,
  getOffsetToVaddrScript,
  getAsmStaticScript,
  getRunPipelineScript,
  getPayloadScriptRunnerScript,
  getExampleCandidates,
} = require('../shared/paths');
const { buildTraceSourceEnrichment } = require('../dynamic/sourceCEnrichment');

/**
 * @brief Crée la fonction openHub.
 * @param config Dependencies: context, logChannel, getTempDir, ensureTempDir, runCommand,
 *   detectPythonExecutable, ensureStaticAsm, readTraceJson, writeTraceJson, setViewMode,
 *   payloadToHex, parseStdinExpression, check32BitToolchain, openVisualizerWebview
 * @return openHub(initialPanel)
 */
function createHub(config) {
  const {
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
    openVisualizerWebview,
    refreshSidebar,
    setSidebarMode
  } = config;

  const SETTINGS_DEFAULTS = {
    pythonPath: '',
    decompilerProvider: 'docker',
    decompilerLocalPaths: {},
    bindiffThreshold: 0.60,
    stringsEncoding: 'auto',
    stringsMinLen: 4,
    asmSyntax: 'intel',
    lang: 'fr',
    defaultPanel: 'dashboard',
    codeFontSize: 13,
    interfaceMode: 'advanced',
    enabledStaticFeatures: [],
  };

  const RAW_PROFILE_KEY = 'reverse-workspace.raw-profiles';
  const sanitizeKey = (binaryPath) => path.resolve(binaryPath);
  const loadRawProfiles = () => context.workspaceState.get(RAW_PROFILE_KEY, {});
  const getRawProfile = (binaryPath) => {
    const profiles = loadRawProfiles();
    return normalizeRawProfile(profiles[sanitizeKey(binaryPath)]);
  };
  const setRawProfile = async (binaryPath, profile) => {
    const normalized = normalizeRawProfile(profile);
    const profiles = { ...loadRawProfiles() };
    if (normalized) profiles[sanitizeKey(binaryPath)] = normalized;
    else delete profiles[sanitizeKey(binaryPath)];
    await context.workspaceState.update(RAW_PROFILE_KEY, profiles);
  };
  const clearRawProfile = async (binaryPath) => {
    const profiles = { ...loadRawProfiles() };
    delete profiles[sanitizeKey(binaryPath)];
    await context.workspaceState.update(RAW_PROFILE_KEY, profiles);
  };

  let hubPanelRef = null;
  let latestTraceRunId = 0;
  let activeDynamicTracePath = '';

  return function openHub(initialPanel = 'dashboard', options = {}) {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage('Aucun workspace ouvert.');
      return null;
    }
    const root = folders[0].uri.fsPath;
    const pythonExe = detectPythonExecutable(root);
    const pythonEnv = buildRuntimeEnv(root);

    if (hubPanelRef && !hubPanelRef.disposed) {
      hubPanelRef.reveal(vscode.ViewColumn.Beside);
      hubPanelRef.webview.postMessage({ type: 'showPanel', panel: initialPanel, focusGoToAddr: options.focusGoToAddr });
      return hubPanelRef;
    }

    const panel = vscode.window.createWebviewPanel(
      'pileOuFaceHub',
      'Reverse Workspace',
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    hubPanelRef = panel;
    panel.onDidDispose(() => { hubPanelRef = null; });

    // ── Watcher decompilers.json — actualisation automatique du panneau ─────────
    const _decompilersConfigPath = path.join(root, '.pile-ou-face', 'decompilers.json');
    const _refreshDecompilerList = async () => {
      try {
        const { stdout } = await new Promise((resolve, reject) => {
          cp.execFile(
            pythonExe,
            [path.join(root, 'backends/static/decompile/decompile.py'), '--list', '--provider', 'auto'],
            { encoding: 'utf8', cwd: root, maxBuffer: 2 * 1024 * 1024, timeout: 30000, env: pythonEnv },
            (err, stdout, stderr) => err ? reject(Object.assign(err, { stderr })) : resolve({ stdout }),
          );
        });
        const result = JSON.parse(stdout);
        panel.webview.postMessage({ type: 'hubDecompilerList', result });
      } catch (_) {}
    };

    // Watcher sur le fichier de config — debounce 600 ms pour éviter les doubles triggers
    let _decompilerWatchDebounce = null;
    const _decompilerConfigWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(root, '.pile-ou-face/decompilers.json'),
    );
    const _onDecompilerConfigChange = () => {
      clearTimeout(_decompilerWatchDebounce);
      _decompilerWatchDebounce = setTimeout(_refreshDecompilerList, 600);
    };
    _decompilerConfigWatcher.onDidChange(_onDecompilerConfigChange);
    _decompilerConfigWatcher.onDidCreate(_onDecompilerConfigChange);
    _decompilerConfigWatcher.onDidDelete(_onDecompilerConfigChange);
    panel.onDidDispose(() => { _decompilerConfigWatcher.dispose(); clearTimeout(_decompilerWatchDebounce); });

    // Auto-detect address when user clicks a line in the .disasm.asm file
    const parseDisasmSelectionContext = (lineText) => {
      const text = String(lineText || '');
      const match = text.match(/^\s*(0x[0-9a-fA-F]+)\s*:\s*([0-9a-fA-F ]+)?/);
      if (!match) return null;
      const bytes = String(match[2] || '')
        .trim()
        .split(/\s+/)
        .filter((part) => /^[0-9a-fA-F]{2}$/.test(part));
      return {
        addr: match[1],
        spanLength: Math.max(1, bytes.length || 1),
      };
    };
    const _selectionListener = vscode.window.onDidChangeTextEditorSelection(event => {
      if (!hubPanelRef) { _selectionListener.dispose(); return; }
      const editor = event.textEditor;
      if (!editor.document.fileName.endsWith('.disasm.asm')) return;
      const lineText = editor.document.lineAt(editor.selection.active.line).text;
      const selection = parseDisasmSelectionContext(lineText);
      if (selection?.addr) {
        panel.webview.postMessage({
          type: 'hubActiveAddr',
          addr: selection.addr,
          spanLength: selection.spanLength,
        });
      }
    });
    panel.onDidDispose(() => { _selectionListener.dispose(); });

    panel.webview.html = getHubContent(panel.webview, context.extensionUri, initialPanel);
    if (options.focusGoToAddr) {
      setImmediate(() => {
        panel.webview.postMessage({ type: 'showPanel', panel: initialPanel, focusGoToAddr: true });
      });
    }

    const runPythonJson = (scriptPath, args) => new Promise((resolve, reject) => {
      cp.execFile(pythonExe, [scriptPath, ...args], { encoding: 'utf8', cwd: root, maxBuffer: 4 * 1024 * 1024, timeout: 60000, env: pythonEnv }, (err, stdout) => {
        if (err) { reject(err.message ? err : new Error(String(err))); return; }
        try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
      });
    });
    const runPythonJsonFile = (args, {
      timeout = 30000,
      maxBuffer = 4 * 1024 * 1024,
      fallback = '{}',
    } = {}) => new Promise((resolve, reject) => {
      cp.execFile(
        pythonExe,
        args,
        { encoding: 'utf8', cwd: root, timeout, maxBuffer, env: pythonEnv },
        (err, stdout, stderr) => {
          if (err) {
            const wrapped = err instanceof Error ? err : new Error(String(err || 'Commande Python échouée.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
            return;
          }
          try {
            resolve(JSON.parse(stdout || fallback));
          } catch (parseErr) {
            const wrapped = parseErr instanceof Error ? parseErr : new Error(String(parseErr || 'JSON invalide.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
          }
        }
      );
    });
    const runPythonTextFile = (args, {
      timeout = 30000,
      maxBuffer = 4 * 1024 * 1024,
    } = {}) => new Promise((resolve, reject) => {
      cp.execFile(
        pythonExe,
        args,
        { encoding: 'utf8', cwd: root, timeout, maxBuffer, env: pythonEnv },
        (err, stdout, stderr) => {
          if (err) {
            const wrapped = err instanceof Error ? err : new Error(String(err || 'Commande Python échouée.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
            return;
          }
          resolve(String(stdout || ''));
        }
      );
    });
    const resolvePathFromWorkspace = (inputPath) => (
      path.isAbsolute(inputPath) ? inputPath : path.join(root, inputPath)
    );
    const toWebviewPath = (absolutePath) => {
      const relPath = path.relative(root, absolutePath);
      return relPath.startsWith('..') ? absolutePath : relPath;
    };
    const inferSourcePathForBinary = (binaryPath = '') => {
      const requestedBinaryPath = String(binaryPath || '').trim();
      if (!requestedBinaryPath) return '';
      const absoluteBinaryPath = resolvePathFromWorkspace(requestedBinaryPath);
      const parsed = path.parse(absoluteBinaryPath);
      const baseName = parsed.name.replace(/\.elf$/i, '');
      const candidates = [
        path.join(parsed.dir, `${baseName}.c`),
        path.join(root, 'examples', `${baseName}.c`),
      ];
      const found = candidates.find((candidate) => fs.existsSync(candidate));
      return found ? toWebviewPath(found) : '';
    };
    const readSourceTextForPayloadTarget = (sourcePath = '') => {
      const requestedSourcePath = String(sourcePath || '').trim();
      if (!requestedSourcePath) return '';
      const absoluteSourcePath = resolvePathFromWorkspace(requestedSourcePath);
      if (!fs.existsSync(absoluteSourcePath)) return '';
      try {
        return fs.readFileSync(absoluteSourcePath, 'utf8');
      } catch (_) {
        return '';
      }
    };
    const buildPayloadTargetPreview = ({ sourcePath = '', mode = 'auto' } = {}) => {
      const sourceText = readSourceTextForPayloadTarget(sourcePath);
      const auto = detectPayloadTargetFromSourceText(sourceText);
      const resolved = resolvePayloadTarget({ mode, sourceText });
      return {
        payloadTargetMode: normalizePayloadTargetMode(mode),
        payloadTargetAuto: auto.target,
        payloadTargetEffective: resolved.target,
        payloadTargetReason: resolved.reason
      };
    };
    const buildSourceEnrichmentMeta = ({ sourcePath = '', trace = null, archBits = 64 } = {}) => {
      const requestedSourcePath = String(sourcePath || '').trim();
      if (!requestedSourcePath) return null;

      const absoluteSourcePath = resolvePathFromWorkspace(requestedSourcePath);
      if (!fs.existsSync(absoluteSourcePath)) {
        return {
          sourcePath: toWebviewPath(absoluteSourcePath),
          archBits: Number(archBits) === 32 ? 32 : 64,
          status: 'missing',
          enabled: false,
          message: 'Code source fourni introuvable ; analyse binaire seule.'
        };
      }

      try {
        const sourceContent = fs.readFileSync(absoluteSourcePath, 'utf8');
        return buildTraceSourceEnrichment({
          sourcePath: toWebviewPath(absoluteSourcePath),
          sourceContent,
          trace,
          archBits
        });
      } catch (error) {
        return {
          sourcePath: toWebviewPath(absoluteSourcePath),
          archBits: Number(archBits) === 32 ? 32 : 64,
          status: 'invalid',
          enabled: false,
          message: `Code source non exploitable ; analyse binaire seule. (${error.message || error})`
        };
      }
    };
    const buildTraceRunArtifacts = (tempDir, runId) => {
      const nonce = crypto.randomBytes(6).toString('hex');
      const stem = `output.run-${runId}-${nonce}`;
      return {
        canonicalJsonPath: path.resolve(tempDir, 'output.json'),
        isolatedJsonPath: path.resolve(tempDir, `${stem}.json`)
      };
    };
    const normalizeHistoryPath = (targetPath) => path.normalize(String(targetPath || ''));
    const deriveTraceRunIdFromPath = (targetPath) => {
      const match = path.basename(String(targetPath || '')).match(/^output\.run-(\d+)-/);
      return match ? Number(match[1]) : null;
    };
    const ensureTraceDisasmPath = (trace, jsonPath) => {
      if (!trace || typeof trace !== 'object') return trace;
      trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
      if (trace.meta.disasm_path) return trace;
      if (String(jsonPath || '').endsWith('.json')) {
        const candidate = String(jsonPath).slice(0, -5) + '.disasm.asm';
        if (fs.existsSync(candidate)) trace.meta.disasm_path = candidate;
      }
      return trace;
    };
    const enrichTraceForVisualizer = (trace, {
      jsonPath = '',
      traceRunId = null,
      sourcePath = '',
      archBits = 64,
      viewMode = 'dynamic'
    } = {}) => {
      if (!trace || typeof trace !== 'object') return trace;
      trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
      if (traceRunId !== null && traceRunId !== undefined) {
        trace.meta.trace_run_id = traceRunId;
      } else if (trace.meta.trace_run_id === undefined || trace.meta.trace_run_id === null) {
        const derivedRunId = deriveTraceRunIdFromPath(jsonPath);
        if (derivedRunId !== null) trace.meta.trace_run_id = derivedRunId;
      }
      ensureTraceDisasmPath(trace, jsonPath);
      const effectiveSourcePath = String(
        sourcePath || trace.meta.source || trace.meta.source_enrichment?.sourcePath || ''
      ).trim();
      if (effectiveSourcePath) {
        const sourceEnrichment = buildSourceEnrichmentMeta({
          sourcePath: effectiveSourcePath,
          trace,
          archBits: Number(trace?.meta?.arch_bits || archBits)
        });
        if (sourceEnrichment) {
          trace.meta.source_enrichment = sourceEnrichment;
          trace.meta.source = sourceEnrichment?.sourcePath || effectiveSourcePath;
        }
      }
      setViewMode(trace, trace.meta.view_mode || viewMode);
      return trace;
    };
    const buildDynamicTraceHistoryItems = () => {
      const tempDir = ensureTempDir(root);
      if (!fs.existsSync(tempDir)) return [];
      const activePath = normalizeHistoryPath(activeDynamicTracePath);
      const candidates = fs.readdirSync(tempDir)
        .filter((name) => /^output\.run-\d+-.*\.json$/.test(name));

      return candidates.map((name) => {
        const absolutePath = path.join(tempDir, name);
        let stat = null;
        let trace = null;
        try {
          stat = fs.statSync(absolutePath);
          trace = readTraceJson(absolutePath);
        } catch (_) {
          return null;
        }
        const snapshots = Array.isArray(trace?.snapshots) ? trace.snapshots : [];
        const meta = trace?.meta && typeof trace.meta === 'object' ? trace.meta : {};
        const payloadText = String(meta.payload_text || meta.argv1 || '');
        const payloadLabel = String(meta.payload_label || payloadTargetLabel(meta.payload_target || 'argv1'));
        const runId = Number(meta.trace_run_id || deriveTraceRunIdFromPath(name) || 0);
        const updatedAtMs = Number(stat?.mtimeMs || 0);
        const binaryPath = String(meta.binary || '').trim();
        const sourcePath = String(meta.source || meta.source_enrichment?.sourcePath || '').trim();
        const previewLimit = 22;
        return {
          path: absolutePath,
          fileName: name,
          runId,
          steps: snapshots.length,
          argvBytes: payloadText.length,
          argvPreview: payloadText.length > previewLimit ? `${payloadText.slice(0, previewLimit)}...` : payloadText,
          payloadLabel,
          binaryName: binaryPath ? path.basename(binaryPath) : '',
          sourceName: sourcePath ? path.basename(sourcePath) : '',
          startSymbol: String(meta.start_symbol || '').trim(),
          updatedAtMs,
          updatedAtLabel: updatedAtMs
            ? new Date(updatedAtMs).toLocaleString('fr-FR', {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              day: '2-digit',
              month: '2-digit'
            })
            : '',
          active: normalizeHistoryPath(absolutePath) === activePath
        };
      })
        .filter(Boolean)
        .sort((left, right) => {
          const runDiff = Number(right.runId || 0) - Number(left.runId || 0);
          if (runDiff !== 0) return runDiff;
          return Number(right.updatedAtMs || 0) - Number(left.updatedAtMs || 0);
        });
    };
    const postDynamicTraceHistory = () => {
      panel.webview.postMessage({
        type: 'dynamicTraceHistory',
        activeTracePath: activeDynamicTracePath || '',
        items: buildDynamicTraceHistoryItems()
      });
    };
    const isManagedDynamicTracePath = (targetPath) => {
      const normalized = normalizeHistoryPath(targetPath);
      const tempDir = normalizeHistoryPath(ensureTempDir(root));
      const fileName = path.basename(normalized);
      return Boolean(
        normalized &&
        normalized.startsWith(tempDir + path.sep) &&
        /^output\.run-\d+-.*\.json$/.test(fileName)
      );
    };
    const deleteDynamicTraceArtifacts = (tracePath) => {
      if (!isManagedDynamicTracePath(tracePath)) return false;
      const jsonPath = normalizeHistoryPath(tracePath);
      const disasmPath = jsonPath.endsWith('.json') ? `${jsonPath.slice(0, -5)}.disasm.asm` : '';
      let removed = false;
      [jsonPath, disasmPath].filter(Boolean).forEach((candidate) => {
        if (fs.existsSync(candidate)) {
          fs.unlinkSync(candidate);
          removed = true;
        }
      });
      if (normalizeHistoryPath(activeDynamicTracePath) === jsonPath) {
        activeDynamicTracePath = '';
      }
      return removed;
    };

    const buildDisasmArgs = ({
      binaryPath,
      disasmPath,
      mappingPath,
      syntax = null,
      section = null,
      arch = null,
      rawArch = null,
      rawBaseAddr = null,
      rawEndian = null,
      annotationsJson = null,
      dwarfLines = false,
      useCacheDb = false,
      emitProgress = false,
    }) => {
      const args = [
        getDisasmScript(root),
        '--binary',
        binaryPath,
        '--output',
        disasmPath,
        '--output-mapping',
        mappingPath,
      ];
      if (syntax) args.push('--syntax', syntax);
      if (annotationsJson) args.push('--annotations-json', annotationsJson);
      if (section) args.push('--section', section);
      if (arch) args.push('--arch', arch);
      if (rawArch) args.push('--raw-arch', rawArch);
      if (rawBaseAddr) args.push('--raw-base-addr', rawBaseAddr);
      if (rawEndian) args.push('--raw-endian', rawEndian);
      if (dwarfLines) args.push('--dwarf-lines');
      if (useCacheDb) args.push('--cache-db', 'auto');
      if (emitProgress) args.push('--progress');
      return args;
    };

    panel.webview.onDidReceiveMessage(async (message) => {
      if (!message || !message.type) return;

      const hubPost = (type, data) => panel.webview.postMessage(Object.assign({ type }, data || {}));
      const createDisasmProgressHandler = (progress) => {
        let buffer = '';
        let lastPercent = 0;
        return {
          hook(chunk) {
            buffer += String(chunk || '');
            const lines = buffer.split(/\r?\n/);
            buffer = lines.pop() || '';
            const passthrough = [];
            for (const line of lines) {
              if (line.startsWith('POF_PROGRESS ')) {
                try {
                  const payload = JSON.parse(line.slice('POF_PROGRESS '.length));
                  const nextPercent = Math.max(
                    lastPercent,
                    Math.min(100, Number(payload.percent || 0))
                  );
                  progress.report({
                    increment: nextPercent - lastPercent,
                    message: payload.message || 'Analyse…',
                  });
                  lastPercent = nextPercent;
                  continue;
                } catch (_) {
                  // keep raw line in the log channel below
                }
              }
              passthrough.push(line);
            }
            return passthrough.length > 0 ? `${passthrough.join('\n')}\n` : false;
          },
          finish(message = 'Terminé') {
            if (lastPercent < 100) {
              progress.report({ increment: 100 - lastPercent, message });
              lastPercent = 100;
            }
          },
        };
      };
      const runDisasmWithProgress = async (title, args) => {
        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title,
            cancellable: false,
          },
          async (progress) => {
            progress.report({ increment: 0, message: 'Initialisation…' });
            const progressHandler = createDisasmProgressHandler(progress);
            await runCommand(
              pythonExe,
              args,
              root,
              logChannel,
              { PYTHONPATH: root },
              { onStderrData: progressHandler.hook }
            );
            progressHandler.finish();
          }
        );
      };
      const finalizeDisasmOpen = async ({
        disasmPath,
        pathForWebview,
        binaryMeta,
        openInEditor = true,
        notifyWebview = true,
      }) => {
        if (!fs.existsSync(disasmPath)) {
          throw new Error(`Le backend n'a pas généré ${path.basename(disasmPath)}.`);
        }
        if (openInEditor) {
          const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
          await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, preview: false });
        }
        if (notifyWebview) {
          panel.webview.postMessage({
            type: 'hubSetBinaryPath',
            binaryPath: pathForWebview,
            binaryMeta,
            skipAutoLoad: true,
          });
          panel.webview.postMessage({
            type: 'hubDisasmReady',
            binaryPath: pathForWebview,
          });
        }
        if (refreshSidebar) refreshSidebar(pathForWebview);
      };
      const ensureDisasmArtifacts = async ({
        binaryPath,
        binaryMeta = null,
        section = '',
        syntax = 'intel',
        annotationsJson = null,
        dwarfLines = false,
        emitProgress = false,
        progressTitle = '',
        useCacheDb = null,
      }) => {
        const absPath = resolvePathFromWorkspace(binaryPath);
        if (!fs.existsSync(absPath) || fs.statSync(absPath).isDirectory()) {
          throw new Error(`Binaire introuvable: ${absPath}`);
        }
        const artifacts = getArtifactPaths({ binaryPath: absPath, section, binaryMeta });
        const shouldUseCacheDb = useCacheDb !== null
          ? useCacheDb
          : (artifacts.binaryMeta.kind !== 'raw' && !section && syntax === 'intel');
        if (!fs.existsSync(artifacts.disasmPath) || !fs.existsSync(artifacts.mappingPath)) {
          let disasmArch = null;
          if (artifacts.binaryMeta.kind !== 'raw') {
            try {
              const info = await loadBinaryHeaders(absPath);
              disasmArch = (info.arch || '').trim() || null;
            } catch (_) { /* fallback */ }
          }
          const args = buildDisasmArgs({
            binaryPath: absPath,
            disasmPath: artifacts.disasmPath,
            mappingPath: artifacts.mappingPath,
            syntax,
            section,
            arch: disasmArch,
            rawArch: artifacts.binaryMeta.rawConfig?.arch || null,
            rawBaseAddr: artifacts.binaryMeta.rawConfig?.baseAddr || null,
            rawEndian: artifacts.binaryMeta.rawConfig?.endian || null,
            annotationsJson,
            dwarfLines,
            useCacheDb: shouldUseCacheDb,
            emitProgress,
          });
          if (emitProgress) {
            await runDisasmWithProgress(
              progressTitle || `Désassemblage de ${path.basename(absPath)}`,
              args,
            );
          } else {
            await runCommand(pythonExe, args, root, logChannel, { PYTHONPATH: root });
          }
        }
        return {
          absPath,
          artifacts,
          pathForWebview: toWebviewPath(absPath),
        };
      };
      const resolveLegacyArtifactFallback = ({
        tempDir,
        mappingPath = null,
        disasmPath = null,
        symbolsPath = null,
        discoveredPath = null,
        effectiveAbsPath = null,
        logPrefix = 'Artifacts',
        exampleLimit = null,
      }) => {
        const current = {
          mappingPath,
          disasmPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
        };
        if (current.mappingPath && fs.existsSync(current.mappingPath)) return current;
        if (!fs.existsSync(tempDir)) return current;
        const mappingFiles = fs.readdirSync(tempDir).filter((n) => n.endsWith('.disasm.mapping.json'));
        if (mappingFiles.length === 0) return current;
        const fallbackName = mappingFiles[0];
        const fallbackBase = fallbackName.replace('.disasm.mapping.json', '');
        current.mappingPath = path.join(tempDir, fallbackName);
        if (current.disasmPath !== null) {
          try {
            const mapping = JSON.parse(fs.readFileSync(current.mappingPath, 'utf8'));
            current.disasmPath = mapping?.path || path.join(tempDir, `${fallbackBase}.disasm.asm`);
          } catch (_) {
            current.disasmPath = path.join(tempDir, `${fallbackBase}.disasm.asm`);
          }
        }
        if (current.symbolsPath !== null) {
          current.symbolsPath = path.join(tempDir, `${fallbackBase}.symbols.json`);
        }
        if (current.discoveredPath !== null) {
          current.discoveredPath = path.join(tempDir, `${fallbackBase}.discovered.json`);
        }
        if (current.effectiveAbsPath !== null) {
          const candidates = getExampleCandidates(root, fallbackBase);
          const limited = Number.isInteger(exampleLimit) ? candidates.slice(0, exampleLimit) : candidates;
          current.effectiveAbsPath = limited.find((p) => fs.existsSync(p) && !fs.statSync(p).isDirectory()) || current.effectiveAbsPath;
        }
        logChannel.appendLine(`[${logPrefix}] Mapping fallback: ${fallbackName}`);
        return current;
      };
      const buildAnalysisArtifactContext = (binaryPath, binaryMeta = null) => {
        const absPath = binaryPath ? path.resolve(root, binaryPath) : root;
        const tempDir = ensureTempDir(root);
        const hasFileBinary = !!binaryPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory();
        const artifacts = hasFileBinary
          ? getArtifactPaths({ binaryPath: absPath, binaryMeta })
          : null;
        const baseName = hasFileBinary ? path.basename(absPath, path.extname(absPath)) : 'binary';
        return {
          absPath,
          tempDir,
          artifacts,
          baseName,
          effectiveAbsPath: hasFileBinary ? absPath : null,
          mappingPath: artifacts?.mappingPath || path.join(tempDir, `${baseName}.disasm.mapping.json`),
          symbolsPath: artifacts?.symbolsPath || path.join(tempDir, `${baseName}.symbols.json`),
          discoveredPath: artifacts?.discoveredPath || path.join(tempDir, `${baseName}.discovered.json`),
        };
      };
      const getAnalysisCacheTarget = (effectiveAbsPath, allowCache) => {
        if (!allowCache || !effectiveAbsPath || !fs.existsSync(effectiveAbsPath)) return null;
        try {
          return fs.statSync(effectiveAbsPath).isDirectory() ? null : effectiveAbsPath;
        } catch (_) {
          return null;
        }
      };
      const readAnalysisCacheEntry = (effectiveAbsPath, allowCache, cacheKey) => {
        const target = getAnalysisCacheTarget(effectiveAbsPath, allowCache);
        if (!target) return null;
        return readCache(root, target, cacheKey);
      };
      const writeAnalysisCacheEntry = (effectiveAbsPath, allowCache, cacheKey, value) => {
        const target = getAnalysisCacheTarget(effectiveAbsPath, allowCache);
        if (!target) return false;
        writeCache(root, target, cacheKey, value);
        return true;
      };
      const ensureAnalysisMappingArtifacts = async ({
        binaryPath,
        artifacts = null,
        mappingPath,
        symbolsPath = undefined,
        discoveredPath = undefined,
        useCacheDb = false,
      }) => {
        if (fs.existsSync(mappingPath)) {
          return { mappingPath, symbolsPath, discoveredPath };
        }
        const ensured = await ensureDisasmArtifacts({
          binaryPath,
          binaryMeta: artifacts?.binaryMeta || null,
          useCacheDb,
        });
        return {
          mappingPath: ensured.artifacts.mappingPath,
          symbolsPath: symbolsPath === undefined ? undefined : ensured.artifacts.symbolsPath,
          discoveredPath: discoveredPath === undefined ? undefined : ensured.artifacts.discoveredPath,
        };
      };
      const loadDisasmMapping = (mappingPath) => {
        if (!mappingPath || !fs.existsSync(mappingPath)) {
          throw new Error('Mapping désassemblage introuvable.');
        }
        const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
        if (!Array.isArray(mapping?.lines) || mapping.lines.length === 0) {
          throw new Error('Mapping désassemblage vide.');
        }
        return mapping;
      };
      const getMappingEntrySpanLength = (entry) => {
        const rawBytes = String(entry?.bytes || '').trim();
        if (rawBytes) {
          const count = rawBytes.split(/\s+/).filter(Boolean).length;
          if (count > 0) return count;
        }
        const rawText = String(entry?.text || '');
        const match = rawText.match(/^\s*(?:0x[0-9a-fA-F]+)\s*:\s*([0-9a-fA-F ]+)/);
        if (match) {
          const count = String(match[1] || '')
            .trim()
            .split(/\s+/)
            .filter((part) => /^[0-9a-fA-F]{2}$/.test(part))
            .length;
          if (count > 0) return count;
        }
        return 1;
      };
      const findDisasmMappingEntryByAddress = (lines, addrInput) => {
        const target = normalizeAddress(addrInput);
        if (!target) return null;
        return lines.find((line) => normalizeAddress(line?.addr || '')?.value === target.value) || null;
      };
      const openDisasmAtLine = async (disasmPath, lineNumber) => {
        if (!disasmPath || !fs.existsSync(disasmPath)) {
          throw new Error('Fichier de désassemblage introuvable.');
        }
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
        const editor = await vscode.window.showTextDocument(doc, {
          viewColumn: vscode.ViewColumn.One,
          preview: false,
        });
        const targetLine = Math.max(0, Number(lineNumber || 1) - 1);
        const range = new vscode.Range(targetLine, 0, targetLine, 1000);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
        editor.selection = new vscode.Selection(range.start, range.start);
        return { doc, editor };
      };
      const resolveDisasmMappingContext = async ({
        binaryPath,
        binaryMeta = null,
        logPrefix = 'Mapping',
      }) => {
        const context = buildAnalysisArtifactContext(binaryPath, binaryMeta);
        const { tempDir, artifacts, baseName } = context;
        let { mappingPath, effectiveAbsPath } = context;
        ({ mappingPath, effectiveAbsPath } = resolveLegacyArtifactFallback({
          tempDir,
          mappingPath,
          effectiveAbsPath,
          logPrefix,
        }));
        if (!fs.existsSync(mappingPath) && effectiveAbsPath) {
          ({ mappingPath } = await ensureAnalysisMappingArtifacts({
            binaryPath: effectiveAbsPath,
            artifacts,
            mappingPath,
            useCacheDb: artifacts?.binaryMeta?.kind !== 'raw',
          }));
        }
        const mapping = loadDisasmMapping(mappingPath);
        const disasmPath = mapping.path || artifacts?.disasmPath || path.join(tempDir, `${baseName}.disasm.asm`);
        return {
          ...context,
          effectiveAbsPath,
          mappingPath,
          mapping,
          disasmPath,
        };
      };
      const resolveAnalysisArtifactsContext = async ({
        binaryPath,
        binaryMeta = null,
        logPrefix = 'Artifacts',
        exampleLimit = null,
        ensureMapping = false,
      }) => {
        const context = buildAnalysisArtifactContext(binaryPath, binaryMeta);
        const { absPath, tempDir, artifacts } = context;
        let {
          mappingPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
        } = context;
        ({
          mappingPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
        } = resolveLegacyArtifactFallback({
          tempDir,
          mappingPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
          logPrefix,
          exampleLimit,
        }));
        const hasAnalyzableBinary = !!binaryPath
          && fs.existsSync(absPath)
          && !fs.statSync(absPath).isDirectory();
        const allowCache = !(artifacts?.binaryMeta?.kind === 'raw');
        if (ensureMapping && !fs.existsSync(mappingPath) && hasAnalyzableBinary) {
          ({
            mappingPath,
            symbolsPath,
            discoveredPath,
          } = await ensureAnalysisMappingArtifacts({
            binaryPath: absPath,
            artifacts,
            mappingPath,
            symbolsPath,
            discoveredPath,
            useCacheDb: allowCache,
          }));
        }
        return {
          ...context,
          mappingPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
          allowCache,
          hasAnalyzableBinary,
        };
      };
      const revealDisasmAddress = async ({
        binaryPath,
        binaryMeta = null,
        addr,
        logPrefix = 'GoToAddress',
        syncHex = true,
      }) => {
        const normalized = normalizeAddress(addr);
        if (!normalized) {
          throw new Error('Adresse invalide.');
        }
        const { mapping, disasmPath } = await resolveDisasmMappingContext({
          binaryPath,
          binaryMeta,
          logPrefix,
        });
        const entry = findDisasmMappingEntryByAddress(mapping.lines, normalized.norm);
        if (!entry || typeof entry.line !== 'number') {
          throw new Error(`Adresse ${normalized.norm} introuvable dans le désassemblage.`);
        }
        if (syncHex) {
          panel.webview.postMessage({
            type: 'hubSyncHexToAddr',
            addr: normalized.norm,
            spanLength: getMappingEntrySpanLength(entry),
          });
        }
        await openDisasmAtLine(disasmPath, entry.line);
        return { entry, mapping, addr: normalized.norm };
      };
      const getRulesConfigPath = () => path.join(context.globalStorageUri.fsPath, 'rules-config.json');
      const runRulesManagerJson = (args, options = {}) => runPythonJsonFile(
        [
          getRulesManagerScript(root),
          ...args,
          '--cwd',
          root,
          '--global-config',
          getRulesConfigPath(),
        ],
        {
          timeout: 10000,
          maxBuffer: 512 * 1024,
          ...options,
        },
      );
      const resolveCachedBinaryView = async ({
        absPath,
        cacheKey,
        cacheOptions = undefined,
        logLabel = null,
        isCacheUsable = () => true,
        compute,
      }) => {
        const cached = readCache(root, absPath, cacheKey, cacheOptions);
        if (cached && isCacheUsable(cached)) {
          if (logLabel) logChannel.appendLine(`[cache] ${logLabel} depuis cache`);
          return cached;
        }
        const value = await compute();
        writeCache(root, absPath, cacheKey, value, cacheOptions);
        return value;
      };
      const resolveCachedAnalysisView = async ({
        effectiveAbsPath,
        allowCache,
        cacheKey,
        logLabel = null,
        compute,
      }) => {
        const cached = readAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey);
        if (cached) {
          if (logLabel) logChannel.appendLine(`[cache] ${logLabel} depuis cache`);
          return cached;
        }
        const value = await compute();
        writeAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey, value);
        return value;
      };
      const resolveBinaryInputContext = (binaryPath, binaryMeta = null) => {
        const requestedPath = String(binaryPath || '').trim();
        const absPath = requestedPath ? resolvePathFromWorkspace(requestedPath) : '';
        const exists = !!absPath && fs.existsSync(absPath);
        let isDirectory = false;
        if (exists) {
          try {
            isDirectory = fs.statSync(absPath).isDirectory();
          } catch (_) {
            isDirectory = false;
          }
        }
        return {
          binaryPath: requestedPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta: requestedPath ? getBinaryRuntimeProfile(absPath, binaryMeta) : null,
        };
      };
      const normalizePayloadExpression = (input) => (
        typeof parseStdinExpression === 'function'
          ? parseStdinExpression(input)
          : String(input || '')
      );
      const normalizeInputHex = (value) => {
        const cleaned = String(value || '').replace(/\s+/g, '').replace(/^0x/i, '');
        if (!cleaned) return '';
        if (!/^[0-9a-f]+$/i.test(cleaned) || cleaned.length % 2 !== 0) {
          throw new Error('payloadBytesHex invalide.');
        }
        return cleaned.toLowerCase();
      };
      const hexContainsNullByte = (hex) => (String(hex || '').match(/../g) || []).includes('00');
      const hexToLatin1String = (hex) => Buffer.from(hex, 'hex').toString('latin1');
      const normalizeTraceInputMeta = (input, fallbackMode = 'payload_builder') => {
        const source = input && typeof input === 'object' ? input : {};
        const requestedMode = String(source.mode || fallbackMode || 'payload_builder').trim().toLowerCase();
        const mode = requestedMode === 'simple' || requestedMode === 'python'
          ? 'payload_builder'
          : (['payload_builder', 'file', 'exploit_helper', 'pwntools_script'].includes(requestedMode) ? requestedMode : fallbackMode);
        return {
          mode,
          template: String(source.template || source.sourceFields?.template || '').trim(),
          targetMode: source.targetMode ? normalizePayloadTargetMode(source.targetMode) : '',
          payloadBytesHex: normalizeInputHex(source.payloadBytesHex || ''),
          sourceFields: source.sourceFields && typeof source.sourceFields === 'object' ? source.sourceFields : {},
          generatedSnippet: String(source.generatedSnippet || ''),
          size: Number.isFinite(Number(source.size)) ? Number(source.size) : 0,
          previewHex: String(source.previewHex || '').trim(),
          previewAscii: String(source.previewAscii || ''),
          warnings: Array.isArray(source.warnings) ? source.warnings.map(String) : [],
          sourceFileName: String(source.sourceFileName || source.sourceFields?.sourceFileName || '').trim(),
          selectedCaptureKind: String(source.selectedCaptureKind || source.sourceFields?.selectedCaptureKind || '').trim(),
          target: String(source.target || source.sourceFields?.target || '').trim(),
          builderLevel: String(source.builderLevel || source.sourceFields?.builderLevel || (requestedMode === 'python' ? 'advanced' : 'beginner')).trim(),
        };
      };
      const stageDynamicInputFile = (fileSpec) => {
        const file = fileSpec && typeof fileSpec === 'object' ? fileSpec : null;
        if (!file) return null;
        const source = file.source === 'path' ? 'path' : 'inline';
        const guestPath = String(file.guestPath || '/tmp/pof-input.txt').trim() || '/tmp/pof-input.txt';
        const passAs = file.passAs === 'argv1' ? 'argv1' : 'argv1';
        let hostPath = '';
        if (source === 'path') {
          hostPath = resolvePathFromWorkspace(String(file.hostPath || '').trim());
          if (!hostPath || !fs.existsSync(hostPath)) throw new Error(`Fichier payload introuvable: ${hostPath}`);
        } else {
          const dir = ensureTempDir(root);
          hostPath = path.join(dir, `dynamic-input-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`);
          fs.writeFileSync(hostPath, String(file.inlineContent || ''), 'utf8');
        }
        return { source, guestPath, hostPath, passAs };
      };
      const sanitizeArtifactToken = (value, fallback = 'item') => {
        const text = String(value || '').trim();
        const safe = text.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_');
        return safe || fallback;
      };
      const getBinaryRuntimeProfile = (binaryPath, messageMeta = null) => {
        const absPath = resolvePathFromWorkspace(binaryPath);
        const explicit = normalizeRawProfile(messageMeta?.rawConfig || messageMeta);
        const stored = getRawProfile(absPath);
        const rawProfile = explicit || stored;
        const inspection = inspectBinaryInput(absPath);
        if (rawProfile && !inspection.supported) {
          return {
            kind: 'raw',
            format: 'RAW',
            arch: rawProfile.arch,
            rawConfig: rawProfile,
          };
        }
        return {
          kind: 'native',
          format: inspection.format || '',
          arch: '',
          rawConfig: null,
        };
      };
      const getArtifactPaths = ({ binaryPath, section = '', binaryMeta = null }) => {
        const absPath = resolvePathFromWorkspace(binaryPath);
        const profile = getBinaryRuntimeProfile(absPath, binaryMeta);
        const tempDir = ensureTempDir(root);
        const baseName = path.basename(absPath, path.extname(absPath)) || 'binary';
        const rawSuffix = profile.kind === 'raw'
          ? `.raw.${sanitizeArtifactToken(profile.rawConfig?.arch, 'raw')}.${sanitizeArtifactToken(profile.rawConfig?.endian || 'little')}.${sanitizeArtifactToken(String(profile.rawConfig?.baseAddr || '0x0').replace(/^0x/i, '0x'))}`
          : '';
        const sectionSuffix = section ? `.section.${sanitizeArtifactToken(section)}` : '';
        const stem = `${baseName}${rawSuffix}${sectionSuffix}`;
        return {
          absPath,
          binaryMeta: profile,
          stem,
          disasmPath: path.join(tempDir, `${stem}.disasm.asm`),
          mappingPath: path.join(tempDir, `${stem}.disasm.mapping.json`),
          discoveredPath: path.join(tempDir, `${stem}.discovered.json`),
          symbolsPath: path.join(tempDir, `${stem}.symbols.json`),
          tempDir,
        };
      };
      const buildPseudoRawInfo = (binaryPath, rawProfile) => {
        const stats = fs.statSync(binaryPath);
        const arch = rawProfile?.arch || 'unknown';
        const descriptor = getRawArchDescriptor(arch);
        return {
          format: 'RAW',
          machine: descriptor.displayName || 'Raw blob',
          entry: rawProfile?.baseAddr || '0x0',
          type: 'blob',
          bits: descriptor.bits || '',
          stripped: 'n/a',
          packers: 'n/a',
          arch,
          endianness: rawProfile?.endian || 'little',
          interp: 'n/a',
          size: stats.size,
        };
      };
      const ensureDiscoveredFunctionsArtifact = async ({
        artifacts,
        absPath,
        mappingPath,
        baseName,
      }) => {
        const discoveredPath = artifacts?.discoveredPath || path.join(ensureTempDir(root), `${baseName}.discovered.json`);
        if (fs.existsSync(discoveredPath)) return discoveredPath;
        if (!fs.existsSync(mappingPath)) return null;
        const discScript = getDiscoverFunctionsScript(root);
        const binArg = (artifacts?.binaryMeta?.kind === 'raw')
          ? null
          : ((absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory()) ? absPath : null);
        const args = [discScript, '--mapping', mappingPath];
        if (binArg) args.push('--binary', binArg);
        const functions = await runPythonJson(discScript, args.slice(1));
        fs.writeFileSync(discoveredPath, JSON.stringify(functions, null, 2), 'utf8');
        return discoveredPath;
      };
      const compileCSource = async ({
        sourcePath,
        binaryPath,
        archBits = '64',
        // Anciens params (gardés pour compatibilité avec runTrace)
        useLegacyFlags = false,
        includeExecstack = false,
        pieChoice = 'no',
        // Nouveaux params explicites (hubCompileStaticBinary)
        optim = null,
        debug = null,
        canary = null,
        execstack = null,
        relro = 'off',
        staticLink = false,
        strip = false,
        extraFlags = '',
      }) => {
        if (!sourcePath) throw new Error('Source C requise.');
        if (!binaryPath) throw new Error('Chemin binaire requis.');
        const absoluteSourcePath = resolvePathFromWorkspace(sourcePath);
        if (!fs.existsSync(absoluteSourcePath)) {
          throw new Error(`Source introuvable: ${absoluteSourcePath}`);
        }
        const absoluteBinaryPath = resolvePathFromWorkspace(binaryPath);
        const outputDir = path.dirname(absoluteBinaryPath);
        if (!fs.existsSync(outputDir)) {
          fs.mkdirSync(outputDir, { recursive: true });
        }

        const gccArgs = [];
        if (process.platform === 'darwin') gccArgs.push('-arch', 'x86_64');

        // Architecture 32-bit
        if (archBits === '32') {
          const toolchainCheck = check32BitToolchain(logChannel);
          if (!toolchainCheck.ok) {
            throw new Error(toolchainCheck.message || '32-bit toolchain missing.');
          }
          gccArgs.push('-m32');
        }

        // Optimisation et debug
        if (useLegacyFlags) {
          gccArgs.push('-O0', '-g');
        } else {
          gccArgs.push(optim || '-O0');
          const dbg = debug !== null ? debug : '-g';
          if (dbg) gccArgs.push(dbg);
        }

        // Stack canary
        if (useLegacyFlags) {
          gccArgs.push('-fno-stack-protector');
        } else {
          const c = canary || 'off';
          if (c === 'off')         gccArgs.push('-fno-stack-protector');
          else if (c === 'basic')  gccArgs.push('-fstack-protector');
          else if (c === 'strong') gccArgs.push('-fstack-protector-strong');
          else if (c === 'all')    gccArgs.push('-fstack-protector-all');
        }

        // execstack (Linux seulement)
        const useExecstack = execstack !== null ? execstack : includeExecstack;
        if (useExecstack && process.platform === 'linux') gccArgs.push('-z', 'execstack');

        // PIE
        if (process.platform !== 'darwin') {
          if (pieChoice === 'yes') gccArgs.push('-fpie', '-pie');
          else                     gccArgs.push('-fno-pie', '-no-pie');
        }

        // RELRO (Linux seulement)
        if (process.platform === 'linux') {
          if (relro === 'partial')     gccArgs.push('-Wl,-z,relro');
          else if (relro === 'full')   gccArgs.push('-Wl,-z,relro,-z,now');
        }

        // Linking statique
        if (staticLink) gccArgs.push('-static');

        // Strip
        if (strip) gccArgs.push('-s');

        // Flags custom
        if (extraFlags) {
          const parts = extraFlags.split(/\s+/).filter(Boolean);
          gccArgs.push(...parts);
        }

        gccArgs.push('-o', absoluteBinaryPath, absoluteSourcePath);
        await runCommand('gcc', gccArgs, root, logChannel);
        // macOS crée un bundle .dSYM à côté du binaire — on le supprime
        if (process.platform === 'darwin') {
          const dSYMPath = absoluteBinaryPath + '.dSYM';
          if (fs.existsSync(dSYMPath)) {
            fs.rmSync(dSYMPath, { recursive: true, force: true });
            logChannel.appendLine(`[compile] Suppression ${path.basename(dSYMPath)}`);
          }
        }
        return { absoluteBinaryPath, pathForWebview: toWebviewPath(absoluteBinaryPath) };
      };
      const loadLatestTrace = () => {
        try {
          const outputJsonPath = path.resolve(getTempDir(root), 'output.json');
          if (!fs.existsSync(outputJsonPath)) return null;
          return JSON.parse(fs.readFileSync(outputJsonPath, 'utf8'));
        } catch (_) {
          return null;
        }
      };
      const inferPie = (headerInfo, previousTrace) => {
        if (typeof previousTrace?.meta?.elf_pie === 'boolean') return previousTrace.meta.elf_pie;
        const type = String(headerInfo?.type || '').toLowerCase();
        const format = String(headerInfo?.format || '').toLowerCase();
        if (type.includes('dyn')) return true;
        if (type.includes('exec')) return false;
        if (format.includes('pie executable')) return true;
        return false;
      };
      const loadBinaryHeaders = async (binaryPath) => runPythonJson(getHeadersScript(root), ['--binary', binaryPath]);
      const loadBinarySymbols = async (binaryPath) => {
        const rawSymbols = await runPythonJson(getSymbolsScript(root), ['--binary', binaryPath]).catch(() => []);
        return Array.isArray(rawSymbols) ? rawSymbols : (rawSymbols.symbols || []);
      };
      const collectSymbolNames = (symbols) => {
        const seen = new Set();
        const names = [];
        for (const symbol of symbols || []) {
          const name = String(symbol?.name || '').trim();
          if (!name || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name) || seen.has(name)) continue;
          seen.add(name);
          names.push(name);
        }
        names.sort();
        return names;
      };
      const getBinaryAnnotationsJsonPath = (absPath) => {
        const hash = crypto
          .createHash('sha256')
          .update(absPath)
          .update(fs.existsSync(absPath) ? String(fs.statSync(absPath).mtimeMs) : '')
          .digest('hex')
          .slice(0, 16);
        return path.join(root, '.pile-ou-face', 'annotations', `${hash}.json`);
      };
      const loadOffsetToVaddr = async (binaryPath, fileOffset) => (
        runPythonTextFile([
          getOffsetToVaddrScript(root),
          '--binary',
          binaryPath,
          '--offset',
          String(fileOffset),
        ])
      );

      const buildRunTraceInit = async (forcedBinaryPath = '', preset = null, forcedSourcePath = '', payloadTargetMode = 'auto') => {
        const requestedPayloadTargetMode = normalizePayloadTargetMode(preset?.payloadTargetMode || payloadTargetMode);
        const latestTrace = loadLatestTrace();
        const traceBinary = String(latestTrace?.meta?.binary || '').trim();
        const fallbackBinary = getExampleCandidates(root, 'stack3').find((candidate) => fs.existsSync(candidate)) || '';
        const requestedBinary = String(forcedBinaryPath || '').trim();
        const selectedBinary = requestedBinary || traceBinary || fallbackBinary;
        const absoluteBinaryPath = selectedBinary ? resolvePathFromWorkspace(selectedBinary) : '';

        if (!absoluteBinaryPath || !fs.existsSync(absoluteBinaryPath)) {
          const defaultMain = preferredMainSymbol('');
          return {
            binaryPath: '',
            sourcePath: '',
            sourceEnrichmentEnabled: false,
            sourceEnrichmentStatus: '',
            sourceEnrichmentMessage: '',
            payloadTargetMode: requestedPayloadTargetMode,
            payloadTargetAuto: 'argv1',
            payloadTargetEffective: requestedPayloadTargetMode === 'auto'
              ? 'argv1'
              : requestedPayloadTargetMode,
            payloadTargetReason: requestedPayloadTargetMode === 'auto'
              ? 'Auto: aucune source claire, fallback sur argv[1]'
              : `${payloadTargetLabel(requestedPayloadTargetMode)} force manuellement`,
            archBits: 64,
            pie: false,
            symbols: { startDefault: defaultMain, stopDefault: '' },
            mvpProfile: {
              bufferOffset: -64,
              bufferSize: 64,
              maxSteps: 800,
              startSymbol: defaultMain,
              stopSymbol: ''
            }
          };
        }

        const info = await loadBinaryHeaders(absoluteBinaryPath).catch(() => ({}));
        const symbols = await loadBinarySymbols(absoluteBinaryPath);
        const sameBinaryTrace = (() => {
          const previousBinary = String(latestTrace?.meta?.binary || '').trim();
          if (!previousBinary) return null;
          const resolvedPrevious = path.normalize(resolvePathFromWorkspace(previousBinary));
          if (resolvedPrevious !== path.normalize(absoluteBinaryPath)) return null;
          return latestTrace;
        })();
        const inferredArchBits = Number(
          info?.bits
          || sameBinaryTrace?.meta?.arch_bits
          || (String(info?.arch || '').includes('64') ? 64 : 32)
        );
        const archBits = inferredArchBits === 32 ? 32 : 64;
        const startDefault = findSymbolByCandidates(symbols, mainSymbolCandidates(info)) || preferredMainSymbol(info);
        const stopDefault = '';
        const defaultProfile = {
          bufferOffset: archBits === 32 ? -32 : -64,
          bufferSize: archBits === 32 ? 32 : 64,
          maxSteps: 800,
          startSymbol: startDefault,
          stopSymbol: stopDefault
        };
        const mergedProfile = {
          ...defaultProfile,
          ...(Number.isFinite(Number(sameBinaryTrace?.meta?.buffer_offset)) ? { bufferOffset: Number(sameBinaryTrace.meta.buffer_offset) } : {}),
          ...(Number.isFinite(Number(sameBinaryTrace?.meta?.buffer_size)) ? { bufferSize: Number(sameBinaryTrace.meta.buffer_size) } : {}),
          ...(Number.isFinite(Number(sameBinaryTrace?.meta?.steps)) && Number(sameBinaryTrace.meta.steps) > 0
            ? { maxSteps: Math.max(800, Number(sameBinaryTrace.meta.steps)) }
            : {}),
          ...(preset?.suggestedOffset !== undefined ? { bufferOffset: preset.suggestedOffset } : {}),
          ...(preset?.suggestedCaptureSize !== undefined ? { bufferSize: preset.suggestedCaptureSize } : {}),
          ...(preset?.maxSteps !== undefined ? { maxSteps: preset.maxSteps } : {}),
          ...(preset?.startSymbol ? { startSymbol: preset.startSymbol } : {}),
          ...(preset?.targetSymbol ? { stopSymbol: preset.targetSymbol } : {}),
          ...(typeof preset?.payloadExpr === 'string' ? { argvPayload: preset.payloadExpr } : {})
        };

        const inferredSourcePath = inferSourcePathForBinary(absoluteBinaryPath);
        const selectedSourcePath = String(
          forcedSourcePath
          || preset?.sourcePath
          || sameBinaryTrace?.meta?.source
          || sameBinaryTrace?.meta?.source_enrichment?.sourcePath
          || inferredSourcePath
          || ''
        ).trim();
        const payloadTargetPreview = buildPayloadTargetPreview({
          sourcePath: selectedSourcePath,
          mode: requestedPayloadTargetMode
        });

        return {
          binaryPath: toWebviewPath(absoluteBinaryPath),
          sourcePath: selectedSourcePath,
          sourceEnrichmentEnabled: sameBinaryTrace?.meta?.source_enrichment?.enabled === true,
          sourceEnrichmentStatus: String(sameBinaryTrace?.meta?.source_enrichment?.status || '').trim(),
          sourceEnrichmentMessage: String(sameBinaryTrace?.meta?.source_enrichment?.message || '').trim(),
          ...payloadTargetPreview,
          archBits,
          pie: inferPie(info, sameBinaryTrace),
          symbols: { startDefault, stopDefault },
          mvpProfile: mergedProfile
        };
      };
      const parseIntLiteral = (raw) => {
        const text = String(raw || '').trim().toLowerCase();
        if (!text) return null;
        const sign = text.startsWith('-') ? -1 : 1;
        const body = text.replace(/^[-+]/, '');
        if (/^0x[0-9a-f]+$/.test(body)) return sign * parseInt(body.slice(2), 16);
        if (/^\d+$/.test(body)) return sign * parseInt(body, 10);
        return null;
      };
      const parseBigIntLiteral = (raw) => {
        const text = String(raw || '').trim().toLowerCase();
        if (!text) return null;
        const neg = text.startsWith('-');
        const body = text.replace(/^[-+]/, '');
        if (/^0x[0-9a-f]+$/.test(body)) {
          const val = BigInt(`0x${body.slice(2)}`);
          return neg ? -val : val;
        }
        if (/^\d+$/.test(body)) {
          const val = BigInt(body);
          return neg ? -val : val;
        }
        return null;
      };
      const extractAsm = (text) => {
        const raw = String(text || '');
        const tab = raw.indexOf('\t');
        const asm = tab >= 0 ? raw.slice(tab + 1) : raw;
        return asm.trim().replace(/\s+/g, ' ');
      };
      const normalizeAddress = (addrText) => {
        const value = String(addrText || '').trim();
        if (!value) return null;
        const norm = value.toLowerCase().startsWith('0x') ? value : `0x${value}`;
        const parsed = parseInt(norm, 16);
        if (!Number.isFinite(parsed)) return null;
        return { norm: `0x${parsed.toString(16)}`, value: parsed };
      };
      const extractFrameOffset = (operand) => {
        const op = String(operand || '').toLowerCase();
        const mem = op.match(/\[(?:r|e)bp(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\]/i);
        if (!mem) return null;
        if (!mem[1]) return 0;
        const delta = parseIntLiteral(mem[2]);
        if (delta === null) return null;
        return mem[1] === '-' ? -Math.abs(delta) : Math.abs(delta);
      };
      const regWidthBytes = (regName) => {
        const reg = String(regName || '').toLowerCase();
        if (/^(al|ah|bl|bh|cl|ch|dl|dh|sil|dil|spl|bpl|r\d+b)$/.test(reg)) return 1;
        if (/^(ax|bx|cx|dx|si|di|sp|bp|r\d+w)$/.test(reg)) return 2;
        if (/^(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|r\d+d)$/.test(reg)) return 4;
        if (/^(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|rip|r\d+)$/.test(reg)) return 8;
        return null;
      };
      const parseCmpInfo = (asmText) => {
        const cmp = asmText.match(/^cmp\s+(.+?),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$/i);
        if (!cmp) return null;
        const lhs = cmp[1].trim();
        const rhsToken = cmp[2].trim();
        const rhsValue = parseBigIntLiteral(rhsToken);
        if (rhsValue === null) return null;

        let width = null;
        if (/\bbyte ptr\b/i.test(lhs)) width = 1;
        else if (/\bword ptr\b/i.test(lhs) && !/\bdword ptr\b/i.test(lhs) && !/\bqword ptr\b/i.test(lhs)) width = 2;
        else if (/\bdword ptr\b/i.test(lhs)) width = 4;
        else if (/\bqword ptr\b/i.test(lhs)) width = 8;
        else if (/^[a-z][a-z0-9]*$/i.test(lhs)) width = regWidthBytes(lhs);
        if (!width) return null;

        return {
          lhs,
          rhsToken,
          rhsValue,
          width,
          lhsReg: /^[a-z][a-z0-9]*$/i.test(lhs) ? lhs.toLowerCase() : null,
        };
      };
      const normalizeCalleeName = (rawName) => {
        if (!rawName) return null;
        let name = String(rawName).trim();
        name = name.replace(/@.*/, '');
        name = name.replace(/^__isoc99_/, '');
        name = name.replace(/^__GI_/, '');
        return name;
      };
      const detectArchBitsFromLines = (lines) => {
        const scanCount = Math.min(lines.length, 500);
        for (let i = 0; i < scanCount; i += 1) {
          const asm = extractAsm(lines[i]?.text || '').toLowerCase();
          if (/\br(?:ax|bx|cx|dx|si|di|sp|bp|8|9|10|11|12|13|14|15)\b/.test(asm)) return 64;
          if (/\b(?:ebp|esp|eip|eax|ebx|ecx|edx|esi|edi)\b/.test(asm)) return 32;
        }
        return 64;
      };
      const collectRegOffsets = (lines, fromIdx, toIdx) => {
        const map = {};
        for (let i = fromIdx; i <= toIdx; i += 1) {
          const asm = extractAsm(lines[i]?.text || '');
          let m = asm.match(/^lea\s+([a-z0-9]+)\s*,\s*(?:[a-z]+\s+ptr\s+)?(\[[^\]]+\])$/i);
          if (m) {
            const reg = m[1].toLowerCase();
            const off = extractFrameOffset(m[2]);
            if (off !== null) map[reg] = off;
            continue;
          }
          m = asm.match(/^mov\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)$/i);
          if (m) {
            const dst = m[1].toLowerCase();
            const src = m[2].toLowerCase();
            if (Object.prototype.hasOwnProperty.call(map, src)) map[dst] = map[src];
            continue;
          }
          m = asm.match(/^mov\s+([a-z0-9]+)\s*,\s*(?:0x[0-9a-f]+|\d+)$/i);
          if (m) {
            delete map[m[1].toLowerCase()];
            continue;
          }
          m = asm.match(/^xor\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)$/i);
          if (m && m[1].toLowerCase() === m[2].toLowerCase()) delete map[m[1].toLowerCase()];
        }
        return map;
      };
      const ensureMappingForBinary = async (binaryPath, binaryMeta = null) => {
        const { mapping } = await resolveDisasmMappingContext({
          binaryPath,
          binaryMeta,
          logPrefix: 'Mapping',
        });
        return mapping;
      };
      const buildCmpPayloadSuggestion = (lines, cmpAddrInput) => {
        const addr = normalizeAddress(cmpAddrInput);
        if (!addr) throw new Error('Adresse CMP invalide (ex: 0x4011c7).');
        const cmpIndex = lines.findIndex((l) => normalizeAddress(l?.addr || '')?.value === addr.value);
        if (cmpIndex < 0) throw new Error(`Adresse ${addr.norm} absente du désassemblage.`);
        const cmpAsm = extractAsm(lines[cmpIndex]?.text || '');
        const cmpInfo = parseCmpInfo(cmpAsm);
        if (!cmpInfo) throw new Error(`Instruction non supportée à ${addr.norm}: ${cmpAsm}`);

        let varOffset = extractFrameOffset(cmpInfo.lhs);
        if (varOffset === null && cmpInfo.lhsReg) {
          const tracked = new Set([cmpInfo.lhsReg]);
          for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 90); i -= 1) {
            const asm = extractAsm(lines[i]?.text || '');
            const regs = Array.from(tracked);
            for (const reg of regs) {
              const memRead = asm.match(new RegExp(`^(?:mov|movzx|movsxd)\\s+${reg}\\s*,\\s*(?:[a-z]+\\s+ptr\\s+)?(\\[[^\\]]+\\])$`, 'i'));
              if (memRead) {
                const off = extractFrameOffset(memRead[1]);
                if (off !== null) {
                  varOffset = off;
                  break;
                }
              }
              const alias = asm.match(new RegExp(`^mov\\s+${reg}\\s*,\\s*([a-z0-9]+)$`, 'i'));
              if (alias) tracked.add(alias[1].toLowerCase());
            }
            if (varOffset !== null) break;
          }
        }

        const archBits = detectArchBitsFromLines(lines);
        const vulnCalls = new Set(['strcpy', 'strncpy', 'memcpy', 'memmove', 'gets', 'fgets', 'read', 'scanf', 'sscanf', 'sprintf', 'snprintf']);
        let bufferOffset = null;
        let sourceCall = null;

        for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 140); i -= 1) {
          const asm = extractAsm(lines[i]?.text || '');
          if (!/^call\s+/i.test(asm)) continue;
          const calleeMatch = asm.match(/<([^>]+)>/);
          const callee = normalizeCalleeName(calleeMatch ? calleeMatch[1] : null);
          if (!callee || !vulnCalls.has(callee)) continue;

          const winStart = Math.max(0, i - 16);
          const regOffsets = collectRegOffsets(lines, winStart, i - 1);
          if (archBits === 64) {
            const argReg = callee === 'read' ? 'rsi' : 'rdi';
            if (Object.prototype.hasOwnProperty.call(regOffsets, argReg)) {
              bufferOffset = regOffsets[argReg];
              sourceCall = callee;
              break;
            }
          } else {
            const pushes = [];
            for (let j = i - 1; j >= winStart; j -= 1) {
              const pushAsm = extractAsm(lines[j]?.text || '');
              const pushMatch = pushAsm.match(/^push\s+(.+)$/i);
              if (pushMatch) pushes.push(pushMatch[1].trim());
            }
            if (pushes.length) {
              const arg1 = pushes[0];
              const direct = extractFrameOffset(arg1);
              if (direct !== null) {
                bufferOffset = direct;
                sourceCall = callee;
                break;
              }
              const regName = arg1.toLowerCase();
              if (Object.prototype.hasOwnProperty.call(regOffsets, regName)) {
                bufferOffset = regOffsets[regName];
                sourceCall = callee;
                break;
              }
            }
          }
        }

        if (bufferOffset === null) {
          let best = null;
          for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 120); i -= 1) {
            const asm = extractAsm(lines[i]?.text || '');
            const lea = asm.match(/^lea\s+[a-z0-9]+\s*,\s*(?:[a-z]+\s+ptr\s+)?(\[[^\]]+\])$/i);
            if (!lea) continue;
            const off = extractFrameOffset(lea[1]);
            if (off === null) continue;
            if (varOffset !== null && off === varOffset) continue;
            if (best === null || off < best) best = off;
          }
          bufferOffset = best;
        }

        if (varOffset === null) throw new Error('Variable comparée introuvable (offset stack non résolu).');
        if (bufferOffset === null) throw new Error('Offset buffer introuvable automatiquement près du CMP.');
        const padding = varOffset - bufferOffset;
        if (!Number.isFinite(padding) || padding <= 0) {
          throw new Error(`Padding invalide calculé (${padding}). Vérifiez le CMP choisi.`);
        }

        const bits = cmpInfo.width * 8;
        let masked = BigInt.asUintN(bits, cmpInfo.rhsValue);
        const bytes = [];
        for (let i = 0; i < cmpInfo.width; i += 1) {
          bytes.push(Number(masked & 0xffn));
          masked >>= 8n;
        }
        const suffixSafe = bytes.every((b) => b >= 0x20 && b <= 0x7e && b !== 0x2b && b !== 0x2a);
        const suffix = suffixSafe ? String.fromCharCode(...bytes) : '';
        const fallbackSuffix = 'B'.repeat(Math.max(4, cmpInfo.width));
        const payloadExpr = `A*${padding}+${suffix || fallbackSuffix}`;
        const captureBufferOffset = Math.min(bufferOffset - (archBits === 64 ? 16 : 8), bufferOffset);
        const frameSpan = Math.max(varOffset, bufferOffset + padding + cmpInfo.width) - captureBufferOffset;
        const captureBufferSize = Math.max(96, archBits === 64 ? frameSpan + 32 : frameSpan + 16);

        return {
          cmpAddr: addr.norm,
          cmpInstr: cmpAsm,
          sourceCall,
          archBits,
          bufferOffset,
          varOffset,
          padding,
          cmpWidth: cmpInfo.width,
          cmpImmediate: `0x${BigInt.asUintN(bits, cmpInfo.rhsValue).toString(16).padStart(cmpInfo.width * 2, '0')}`,
          cmpImmediateBytesLe: bytes.map((b) => b.toString(16).padStart(2, '0')).join(''),
          suffix,
          payloadExpr,
          captureBufferOffset,
          captureBufferSize,
          warning: suffix ? null : 'Valeur CMP non printable: suffixe remplacé par des B.'
        };
      };

      const handlerCtx = {
        root,
        panel,
        context,
        getTempDir,
        ensureTempDir,
        refreshSidebar,
        getRawProfile,
        setRawProfile,
        clearRawProfile,
      };
      const handlers = createHandlers(handlerCtx);
      const sharedHandler = handlers[message.type];
      if (sharedHandler) {
        try {
          await sharedHandler(message);
        } catch (e) {
          logChannel.appendLine(`[hub] Handler error (${message.type}): ${e.message || e}`);
        }
        return;
      }
      if (message.type === 'hubModeChange') {
        if (setSidebarMode) setSidebarMode(message.mode || 'other');
        return;
      }
      if (message.type === 'hubDebugLog') {
        const scope = String(message.scope || 'webview').replace(/[^a-z0-9_-]/gi, '_');
        const event = String(message.event || 'event').replace(/[^a-z0-9_.:-]/gi, '_');
        const details = message.details && typeof message.details === 'object' ? message.details : {};
        logChannel.appendLine(`[${scope}] ${event} ${JSON.stringify(details)}`);
        return;
      }
      if (message.type === 'hubInstallDecompiler') {
        const tool = message.tool || '';
        const platform = process.platform;
        const pm = platform === 'linux' ? (() => {
          for (const p of ['apt', 'dnf', 'pacman', 'zypper']) {
            const r = cp.spawnSync('which', [p], { stdio: 'pipe', timeout: 2000 });
            if (r.status === 0) return p;
          }
          return null;
        })() : null;

        const LABELS = {
          ghidra: 'Ghidra headless',
        };
        const INSTALL_LINES = {
          ghidra: [
            'macOS :  brew install ghidra && brew install openjdk@21',
            'Windows: winget install NationalSecurityAgency.Ghidra && winget install EclipseAdoptium.Temurin.21.JDK',
            'Linux  :  téléchargement manuel → https://ghidra-sre.org',
          ],
        };

        const label = LABELS[tool] || tool;
        const lines = INSTALL_LINES[tool] || [
          'Décompilateur custom : ajoutez une entrée dans .pile-ou-face/decompilers.json.',
          'Format : {"decompilers":{"mon-outil":{"command":["mon-outil","--binary","{binary}","--addr","{addr}"]}}}',
          'Fallback Docker : make decompilers-docker-build puis relancez la décompilation.',
        ];
        const detail = lines.join('\n');

        // Pick the best install command for current platform
        let installCmd = null;
        if (tool === 'ghidra') {
          if (platform === 'darwin') installCmd = 'brew install ghidra && brew install openjdk@21';
          else if (platform === 'win32') installCmd = 'winget install NationalSecurityAgency.Ghidra && winget install EclipseAdoptium.Temurin.21.JDK';
        }

        if (!installCmd && !LABELS[tool]) {
          installCmd = 'make decompilers-docker-build';
        }

        const buttons = installCmd ? ['Copier la commande', 'Annuler'] : (tool === 'ghidra' ? ['Ouvrir ghidra-sre.org', 'Annuler'] : ['Annuler']);
        const answer = await vscode.window.showInformationMessage(
          `${label} n'est pas installé`,
          { modal: true, detail },
          ...buttons
        );
        if (answer === 'Copier la commande' && installCmd) {
          await vscode.env.clipboard.writeText(installCmd);
          vscode.window.showInformationMessage(`Commande copiée : ${installCmd}`);
        } else if (answer === 'Ouvrir ghidra-sre.org') {
          vscode.env.openExternal(vscode.Uri.parse('https://ghidra-sre.org/'));
        }
        return;
      }
      if (message.type === 'staticOpen') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!binaryPath || !exists || isDirectory) {
          await handlers.requestBinarySelection();
          return;
        }
        try {
          const { artifacts, pathForWebview } = await ensureDisasmArtifacts({
            binaryPath: absPath,
            binaryMeta,
            emitProgress: true,
            progressTitle: `Désassemblage de ${path.basename(absPath)}`,
            useCacheDb: binaryMeta?.kind !== 'raw',
          });
          await finalizeDisasmOpen({
            disasmPath: artifacts.disasmPath,
            pathForWebview,
            binaryMeta: artifacts.binaryMeta,
            openInEditor: true,
          });
        } catch (err) {
          vscode.window.showErrorMessage(`Static: ${err.message || err}`);
        }
        return;
      }
      if (message.type === 'getSymbols') {
        const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        let symbols = [];
        if (exists && !isDirectory) {
          try {
            symbols = collectSymbolNames(await loadBinarySymbols(absPath));
          } catch (e) { /* symbol extraction failed */ }
        }
        panel.webview.postMessage({ type: 'symbols', symbols });
        return;
      }

      if (message.type === 'hubExportDisasm') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        const tempDir = ensureTempDir(root);
        let disasmPath = null;
        let mappingPath = null;
        if (binaryPath && exists && !isDirectory) {
          const artifacts = getArtifactPaths({ binaryPath: absPath, binaryMeta });
          disasmPath = artifacts.disasmPath;
          mappingPath = artifacts.mappingPath;
        }
        const fallback = resolveLegacyArtifactFallback({
          tempDir,
          mappingPath,
          disasmPath,
          logPrefix: 'ExportDisasm',
        });
        disasmPath = fallback.disasmPath;
        if (!disasmPath || !fs.existsSync(disasmPath)) {
          vscode.window.showWarningMessage('Aucun désassemblage trouvé. Ouvrez d\'abord le désassemblage ou sélectionnez un binaire.');
          return;
        }
        const defaultName = path.basename(disasmPath, '.asm').replace('.disasm', '') + '.disasm.txt';
        const defaultPath = path.join(path.dirname(disasmPath), defaultName);
        vscode.window.showSaveDialog({
          title: 'Exporter le désassemblage',
          defaultUri: vscode.Uri.file(defaultPath),
          filters: { 'Texte': ['txt'], 'Tous': ['*'] }
        }).then(async (saveUri) => {
          if (!saveUri) return;
          try {
            const text = fs.readFileSync(disasmPath, 'utf8');
            await fs.promises.writeFile(saveUri.fsPath, text, 'utf8');
            vscode.window.showInformationMessage(`Exporté: ${path.basename(saveUri.fsPath)}`);
          } catch (err) {
            vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
          }
        });
        return;
      }
      if (message.type === 'hubPayloadToHex') {
        try {
          const hex = payloadToHex(message.payload || '');
          hubPost('hubPayloadHex', { hex });
        } catch (err) {
          hubPost('hubPayloadHex', { error: err.message });
        }
        return;
      }
      if (message.type === 'hubAutoFromCmp') {
        const binaryPath = String(message.binaryPath || '').trim();
        const cmpAddr = String(message.cmpAddr || '').trim();
        if (!binaryPath) {
          hubPost('hubAutoFromCmpResult', { error: 'Binaire manquant.' });
          return;
        }
        if (!cmpAddr) {
          hubPost('hubAutoFromCmpResult', { error: 'Adresse CMP manquante.' });
          return;
        }
        try {
          const mapping = await ensureMappingForBinary(binaryPath);
          const suggestion = buildCmpPayloadSuggestion(mapping.lines || [], cmpAddr);
          hubPost('hubAutoFromCmpResult', suggestion);
        } catch (err) {
          hubPost('hubAutoFromCmpResult', { error: err.message || String(err) });
        }
        return;
      }
      if (message.type === 'hubOpenDisasm') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!exists || isDirectory) {
          vscode.window.showErrorMessage(`Binaire introuvable: ${absPath}`);
          return;
        }
        try {
          const section = (message.section || '').trim();
          const artifacts = getArtifactPaths({
            binaryPath: absPath,
            section,
            binaryMeta,
          });
          const { disasmPath, mappingPath } = artifacts;
          const useCache = message.useCache !== false;
          const requestedArch = (typeof message.arch === 'string' ? message.arch.trim() : '') || null;
          const cacheEligible = artifacts.binaryMeta.kind !== 'raw'
            && !section
            && (message.syntax || 'intel') === 'intel'
            && !requestedArch;
          const cacheValid = useCache && cacheEligible && fs.existsSync(disasmPath) && fs.existsSync(mappingPath);
          if (!cacheValid) {
            const annotationsJsonPath = getBinaryAnnotationsJsonPath(absPath);
            const ensured = await ensureDisasmArtifacts({
              binaryPath: absPath,
              binaryMeta: artifacts.binaryMeta,
              section,
              syntax: message.syntax || 'intel',
              annotationsJson: fs.existsSync(annotationsJsonPath) ? annotationsJsonPath : null,
              dwarfLines: artifacts.binaryMeta.kind !== 'raw',
              emitProgress: true,
              progressTitle: `Désassemblage de ${path.basename(absPath)}`,
              useCacheDb: cacheEligible,
            });
          } else {
            logChannel.appendLine(`[cache] Réutilisation de ${disasmPath}`);
          }
          const pathForWebview = path.relative(root, absPath).startsWith('..') ? absPath : path.relative(root, absPath);
          await finalizeDisasmOpen({
            disasmPath,
            pathForWebview,
            binaryMeta: artifacts.binaryMeta,
            openInEditor: message.openInEditor !== false,
            notifyWebview: !section,
          });
        } catch (err) {
          vscode.window.showErrorMessage(`Désassemblage: ${err.message}`);
        }
        return;
      }
      if (message.type === 'hubGoToEntryPoint') {
        const {
          absPath,
          exists,
          isDirectory,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        const symbolName = message.symbol || 'main';
        let addrVal = null;
        if (!exists || isDirectory) {
          vscode.window.showErrorMessage(`Binaire introuvable: ${absPath}`);
          return;
        }
        if (symbolName === '__entry__') {
          try {
            const info = await loadBinaryHeaders(absPath);
            const entry = (info.entry || '').trim();
            if (!entry) {
              vscode.window.showWarningMessage('Entry point non trouvé dans les headers.');
              return;
            }
            addrVal = parseInt(entry.replace(/^0x/, ''), 16);
          } catch (err) {
            vscode.window.showErrorMessage(`Entry point: ${err.message}`);
            return;
          }
        } else {
          try {
            const info = await loadBinaryHeaders(absPath).catch(() => ({}));
            const symbols = await loadBinarySymbols(absPath);
            const candidates = symbolLookupCandidates(symbolName, info);
            let sym = symbols.find(s => candidates.includes(String(s.name || '')));
            if (!sym && symbolName === '_start' && isMachOFormat(info)) {
              try {
                const entry = (info.entry || '').trim();
                if (entry) {
                  addrVal = parseInt(entry.replace(/^0x/, ''), 16);
                  sym = { addr: entry };
                }
              } catch (_) { /* fallback to warning */ }
            }
            if (!sym) {
              const hint = symbolName === '_start' && isMachOFormat(info)
                ? ' (sur Mach-O, utilisez plutôt « Aller à l\'entry point »)'
                : '';
              vscode.window.showWarningMessage(`Symbole ${symbolName} non trouvé.${hint}`);
              return;
            }
            if (!addrVal && sym.addr) addrVal = parseInt(sym.addr, 16);
            addrVal = parseInt(sym.addr, 16);
          } catch (err) {
            vscode.window.showErrorMessage(`Aller à ${symbolName}: ${err.message}`);
            return;
          }
        }
        try {
          await revealDisasmAddress({
            binaryPath: absPath,
            addr: `0x${addrVal.toString(16)}`,
            logPrefix: 'GoToSymbol',
          });
        } catch (err) {
          vscode.window.showErrorMessage(`Aller à ${symbolName}: ${err.message}`);
        }
        return;
      }
      if (message.type === 'hubLoadSymbols') {
        const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!exists || isDirectory) {
          hubPost('hubSymbols', { symbols: [] });
          return;
        }
        try {
          const symbols = await resolveCachedBinaryView({
            absPath,
            cacheKey: 'symbols',
            logLabel: 'Symboles',
            compute: () => loadBinarySymbols(absPath),
          });
          hubPost('hubSymbols', { symbols });
        } catch (_) {
          hubPost('hubSymbols', { symbols: [] });
        }
        return;
      }
      if (message.type === 'hubLoadStrings') {
        const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        const minLen = Math.max(1, Math.min(64, parseInt(message.minLen, 10) || 4));
        const encoding = message.encoding || 'utf-8';
        const section = (message.section || '').trim() || null;
        if (!exists || isDirectory) {
          hubPost('hubStrings', { strings: [] });
          return;
        }
        try {
          const opts = { minLen, encoding };
          if (section) opts.section = section;
          const strings = await resolveCachedBinaryView({
            absPath,
            cacheKey: 'strings',
            cacheOptions: opts,
            logLabel: 'Strings',
            compute: async () => {
              const args = [getStringsScript(root), '--binary', absPath, '--min-len', String(minLen), '--encoding', encoding];
              if (section) args.push('--section', section);
              return runPythonJson(args[0], args.slice(1));
            },
          });
          hubPost('hubStrings', { strings });
        } catch (_) {
          hubPost('hubStrings', { strings: [] });
        }
        return;
      }
      if (message.type === 'hubLoadInfo') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!binaryPath) {
          hubPost('hubBinaryInfo', { info: { error: 'Indiquez un chemin binaire.' } });
          return;
        }
        if (!exists || isDirectory) {
          hubPost('hubBinaryInfo', { info: { error: `Binaire introuvable: ${binaryPath}` } });
          return;
        }
        try {
          if (binaryMeta.kind === 'raw') {
            hubPost('hubBinaryInfo', { info: buildPseudoRawInfo(absPath, binaryMeta.rawConfig) });
            return;
          }
          const info = await resolveCachedBinaryView({
            absPath,
            cacheKey: 'info',
            logLabel: 'Infos binaire',
            isCacheUsable: (cached) => !!(cached && cached.stripped && cached.stripped !== '—'),
            compute: () => loadBinaryHeaders(absPath),
          });
          hubPost('hubBinaryInfo', { info });
        } catch (err) {
          logChannel.appendLine(`[headers] ${err.message}`);
          hubPost('hubBinaryInfo', { info: { error: err.message || 'Impossible de lire les infos' } });
        }
        return;
      }
      if (message.type === 'hubLoadSections') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!binaryPath) {
          hubPost('hubSections', { sections: [], error: 'Indiquez un chemin binaire.' });
          return;
        }
        if (!exists || isDirectory) {
          hubPost('hubSections', { sections: [], error: `Binaire introuvable: ${binaryPath}` });
          return;
        }
        try {
          if (binaryMeta.kind === 'raw') {
            const stats = fs.statSync(absPath);
            hubPost('hubSections', {
              sections: [{
                name: 'raw',
                offset: '0x0',
                virtual_address: binaryMeta.rawConfig?.baseAddr || '0x0',
                size: stats.size,
                type: 'raw blob',
                entropy: '—',
              }],
            });
            return;
          }
          const sections = await resolveCachedBinaryView({
            absPath,
            cacheKey: 'sections',
            logLabel: 'Sections',
            compute: async () => {
              const rawSections = await runPythonJson(getSectionsScript(root), ['--binary', absPath]);
              return Array.isArray(rawSections) ? rawSections : (rawSections.sections || []);
            },
          });
          hubPost('hubSections', { sections });
        } catch (err) {
          logChannel.appendLine(`[sections] ${err.message}`);
          hubPost('hubSections', { sections: [], error: err.message });
        }
        return;
      }
      if (message.type === 'hubLoadCfg') {
        const binaryPath = (message.binaryPath || '').trim();
        const {
          mappingPath,
          effectiveAbsPath,
          allowCache,
          hasAnalyzableBinary,
        } = await resolveAnalysisArtifactsContext({
          binaryPath,
          binaryMeta: message.binaryMeta || null,
          logPrefix: 'CFG',
          ensureMapping: true,
        });
        if (!fs.existsSync(mappingPath)) {
          if (!hasAnalyzableBinary) {
            hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
            return;
          }
        }
        try {
          if (fs.existsSync(mappingPath)) {
            const cfg = await resolveCachedAnalysisView({
              effectiveAbsPath,
              allowCache,
              cacheKey: 'cfg',
              logLabel: 'CFG',
              compute: () => runPythonJson(getCfgScript(root), ['--mapping', mappingPath]),
            });
            hubPost('hubCfg', { cfg });
          } else {
            logChannel.appendLine(`[CFG] Mapping introuvable: ${mappingPath}`);
            hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
          }
        } catch (err) {
          logChannel.appendLine(`[CFG] Erreur: ${err.message}`);
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
        }
        return;
      }
      if (message.type === 'hubLoadCallGraph') {
        const binaryPath = (message.binaryPath || '').trim();
        const {
          absPath,
          artifacts,
          baseName,
          mappingPath,
          symbolsPath,
          discoveredPath,
          effectiveAbsPath,
          allowCache,
          hasAnalyzableBinary,
        } = await resolveAnalysisArtifactsContext({
          binaryPath,
          binaryMeta: message.binaryMeta || null,
          logPrefix: 'CallGraph',
          exampleLimit: 2,
          ensureMapping: true,
        });
        let resolvedSymbolsPath = symbolsPath;
        let resolvedDiscoveredPath = discoveredPath;
        if (!fs.existsSync(mappingPath)) {
          if (!hasAnalyzableBinary) {
            hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
            return;
          }
        }
        try {
          const binForSymbols = (effectiveAbsPath && fs.existsSync(effectiveAbsPath)) ? effectiveAbsPath : absPath;
          if (artifacts?.binaryMeta?.kind === 'raw') {
            resolvedDiscoveredPath = await ensureDiscoveredFunctionsArtifact({
              artifacts,
              absPath,
              mappingPath,
              baseName,
            }) || resolvedDiscoveredPath;
            if (resolvedDiscoveredPath && fs.existsSync(resolvedDiscoveredPath)) {
              fs.writeFileSync(resolvedSymbolsPath, fs.readFileSync(resolvedDiscoveredPath, 'utf8'), 'utf8');
            } else {
              fs.writeFileSync(resolvedSymbolsPath, '[]', 'utf8');
            }
          } else if (!fs.existsSync(resolvedSymbolsPath) && fs.existsSync(binForSymbols)) {
            const symbols = await loadBinarySymbols(binForSymbols);
            fs.writeFileSync(resolvedSymbolsPath, JSON.stringify(symbols, null, 2), 'utf8');
          }
          if (fs.existsSync(mappingPath) && fs.existsSync(resolvedSymbolsPath)) {
            const callGraph = await resolveCachedAnalysisView({
              effectiveAbsPath,
              allowCache,
              cacheKey: 'callgraph',
              logLabel: 'Call graph',
              compute: () => runPythonJson(getCallGraphScript(root), ['--mapping', mappingPath, '--symbols', resolvedSymbolsPath]),
            });
            hubPost('hubCallGraph', { callGraph });
          } else {
            logChannel.appendLine(`[CallGraph] Fichiers manquants: mapping=${fs.existsSync(mappingPath)}, symbols=${fs.existsSync(resolvedSymbolsPath)}`);
            hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
          }
        } catch (err) {
          logChannel.appendLine(`[CallGraph] Erreur: ${err.message}`);
          hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
        }
        return;
      }
      if (message.type === 'hubLoadDiscoveredFunctions') {
        const binaryPath = (message.binaryPath || '').trim();
        const {
          absPath,
          artifacts,
          mappingPath,
          discoveredPath,
          effectiveAbsPath,
          allowCache,
          hasAnalyzableBinary,
        } = await resolveAnalysisArtifactsContext({
          binaryPath,
          binaryMeta: message.binaryMeta || null,
          logPrefix: 'Discovered',
          ensureMapping: true,
        });
        let resolvedDiscoveredPath = discoveredPath;
        if (!fs.existsSync(mappingPath)) {
          if (!hasAnalyzableBinary) {
            hubPost('hubDiscoveredFunctions', { functions: [] });
            return;
          }
        }
        try {
          if (!allowCache && fs.existsSync(resolvedDiscoveredPath)) {
            const rawCached = JSON.parse(fs.readFileSync(resolvedDiscoveredPath, 'utf8'));
            hubPost('hubDiscoveredFunctions', { functions: rawCached, analyzed: true });
            return;
          }
          if (fs.existsSync(mappingPath)) {
            const discScript = getDiscoverFunctionsScript(root);
            const binArg = (artifacts?.binaryMeta?.kind === 'raw')
              ? null
              : ((effectiveAbsPath && fs.existsSync(effectiveAbsPath) && !fs.statSync(effectiveAbsPath).isDirectory()) ? effectiveAbsPath : (absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory() ? absPath : null));
            const args = [discScript, '--mapping', mappingPath];
            if (binArg) args.push('--binary', binArg);
            const functions = await resolveCachedAnalysisView({
              effectiveAbsPath,
              allowCache,
              cacheKey: 'discovered',
              logLabel: 'Fonctions découvertes',
              compute: async () => {
                const discovered = await runPythonJson(discScript, args.slice(1));
                if (!allowCache && artifacts?.binaryMeta?.kind === 'raw') {
                  fs.writeFileSync(resolvedDiscoveredPath, JSON.stringify(discovered, null, 2), 'utf8');
                }
                return discovered;
              },
            });
            hubPost('hubDiscoveredFunctions', { functions, analyzed: true });
          } else {
            logChannel.appendLine(`[Discovered] Mapping introuvable: ${mappingPath}`);
            hubPost('hubDiscoveredFunctions', { functions: [] });
          }
        } catch (err) {
          logChannel.appendLine(`[Discovered] Erreur: ${err.message}`);
          hubPost('hubDiscoveredFunctions', { functions: [], analyzed: true, error: err.message });
        }
        return;
      }
      if (message.type === 'hubLoadXrefs') {
        const addr = (message.addr || '').trim();
        const binaryPath = (message.binaryPath || '').trim();
        const {
          absPath,
          artifacts,
          baseName,
          mappingPath,
          discoveredPath,
          hasAnalyzableBinary,
        } = await resolveAnalysisArtifactsContext({
          binaryPath,
          binaryMeta: message.binaryMeta || null,
          logPrefix: 'Xrefs',
          ensureMapping: true,
        });
        const mode = (message.mode || 'to') === 'from' ? 'from' : 'to';
        if (!addr) return;
        let resolvedDiscoveredPath = discoveredPath;
        try {
          if (!fs.existsSync(mappingPath)) {
            if (!hasAnalyzableBinary) {
              hubPost('hubXrefs', { addr, refs: [], targets: [], mode, error: 'Mapping introuvable. Ouvrez d\'abord le désassemblage.' });
              return;
            }
          }
          if (artifacts?.binaryMeta?.kind === 'raw' && !fs.existsSync(resolvedDiscoveredPath)) {
            resolvedDiscoveredPath = await ensureDiscoveredFunctionsArtifact({
              artifacts,
              absPath,
              mappingPath,
              baseName,
            }) || resolvedDiscoveredPath;
          }
          const parsed = await runPythonJson(getXrefsScript(root), [
            '--mapping', mappingPath,
            ...(binaryPath && artifacts?.binaryMeta?.kind !== 'raw' ? ['--binary', binaryPath] : []),
            ...(artifacts?.binaryMeta?.kind === 'raw' && fs.existsSync(resolvedDiscoveredPath) ? ['--functions', resolvedDiscoveredPath] : []),
            '--addr', addr,
            '--mode', mode,
          ]);
          hubPost('hubXrefs', {
            addr,
            refs: parsed.refs || [],
            targets: parsed.targets || [],
            mode,
          });
        } catch (err) {
          logChannel.appendLine(`[Xrefs] ${err.message}`);
          hubPost('hubXrefs', { addr, refs: [], targets: [], mode });
        }
        return;
      }
      if (message.type === 'hubGoToFileOffset') {
        const fileOffsetStr = (message.fileOffset || '').trim();
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!fileOffsetStr || !binaryPath) return;
        if (!exists || isDirectory) return;
        const artifacts = getArtifactPaths({ binaryPath: absPath, binaryMeta });
        const fileOffset = fileOffsetStr.toLowerCase().startsWith('0x') ? parseInt(fileOffsetStr, 16) : parseInt(fileOffsetStr, 10);
        if (isNaN(fileOffset)) return;
        if (artifacts?.binaryMeta?.kind === 'raw') {
          const baseAddr = parseIntLiteral(artifacts.binaryMeta.rawConfig?.baseAddr || '0');
          if (baseAddr == null) {
            vscode.window.showInformationMessage(`Impossible de convertir l'offset ${fileOffsetStr} pour ce blob brut.`);
            return;
          }
          message = {
            type: 'hubGoToAddress',
            addr: `0x${(baseAddr + fileOffset).toString(16)}`,
            binaryPath,
            binaryMeta: artifacts.binaryMeta,
          };
        } else {
          try {
            const vaddr = (await loadOffsetToVaddr(absPath, fileOffset)).trim();
            if (vaddr) {
              message = { type: 'hubGoToAddress', addr: vaddr, binaryPath, binaryMeta };
            } else {
              vscode.window.showInformationMessage(`Offset ${fileOffsetStr} : pas d'adresse virtuelle (section non chargée ou binaire non-ELF).`);
              return;
            }
          } catch (_) {
            vscode.window.showInformationMessage(`Impossible de convertir l'offset ${fileOffsetStr} en adresse virtuelle.`);
            return;
          }
        }
      }
      if (message.type === 'hubGoToAddress') {
        const addr = (message.addr || '').trim();
        const binaryPath = (message.binaryPath || '').trim();
        if (!addr) return;
        try {
          await revealDisasmAddress({
            binaryPath,
            binaryMeta: message.binaryMeta || null,
            addr,
            logPrefix: 'GoToAddress',
          });
        } catch (err) {
          vscode.window.showInformationMessage(err.message || `Adresse ${addr} introuvable dans le désassemblage.`);
        }
        return;
      }

      if (message.type === 'hubExportCfgSvg') {
        const svg = message.svg || '';
        if (!svg) return;
        const tempDir = ensureTempDir(root);
        const defaultPath = path.join(tempDir, 'cfg_export.svg');
        vscode.window.showSaveDialog({
          title: 'Exporter le graphe CFG en SVG',
          defaultUri: vscode.Uri.file(defaultPath),
          filters: { 'SVG': ['svg'], 'Tous': ['*'] }
        }).then(async (saveUri) => {
          if (!saveUri) return;
          try {
            await fs.promises.writeFile(saveUri.fsPath, svg, 'utf8');
            vscode.window.showInformationMessage(`CFG exporté: ${path.basename(saveUri.fsPath)}`);
          } catch (err) {
            vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
          }
        });
        return;
      }
      if (message.type === 'hubYaraScan') {
        const {
          absPath,
          exists,
          isDirectory,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        const rulesPath = (message.rulesPath || '').trim();
        const absRules = rulesPath ? (path.isAbsolute(rulesPath) ? rulesPath : path.join(root, rulesPath)) : null;
        if (!exists || isDirectory) {
          hubPost('hubYara', { matches: [], error: 'Binaire introuvable.' });
          return;
        }
        if (absRules && !fs.existsSync(absRules)) {
          hubPost('hubYara', { matches: [], error: 'Fichier de règles introuvable.' });
          return;
        }
        const yaraArgs = [
          getYaraScanScript(root), '--binary', absPath,
          '--cwd', root, '--global-config', getRulesConfigPath(),
        ];
        if (absRules) yaraArgs.push('--rules', absRules);
        try {
          const data = await runPythonJsonFile(yaraArgs, { timeout: 60000, maxBuffer: 1024 * 1024 });
          const matches = Array.isArray(data) ? data : (data.matches || []);
          const error = data.error || null;
          hubPost('hubYara', { matches, error: error || undefined });
        } catch (err) {
          const stderr = String(err.stderr || '').trim();
          hubPost('hubYara', { matches: [], error: stderr || err.message || 'YARA a échoué.' });
        }
        return;
      }
      if (message.type === 'hubSearchBinary') {
        const {
          binaryPath,
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        const artifacts = binaryPath ? getArtifactPaths({ binaryPath: absPath, binaryMeta }) : null;
        const pattern = (message.pattern || '').trim();
        const mode = message.mode || 'text';
        const section = (message.section || '').trim() || null;
        if (!exists || isDirectory || !pattern) {
          hubPost('hubRecherche', { results: [], error: 'Binaire ou motif manquant.' });
          return;
        }
        const args = [getSearchScript(root), '--binary', absPath, '--pattern', pattern, '--mode', mode];
        if (section) args.push('--section', section);
        if (artifacts?.binaryMeta?.kind === 'raw' && artifacts.binaryMeta.rawConfig?.baseAddr) {
          args.push('--raw-base-addr', String(artifacts.binaryMeta.rawConfig.baseAddr));
        }
        if (message.minLength != null) args.push('--min-length', String(message.minLength));
        if (message.maxLength != null) args.push('--max-length', String(message.maxLength));
        if (message.caseSensitive === false) args.push('--case-insensitive');
        if (message.offsetStart != null) args.push('--offset-start', String(message.offsetStart));
        if (message.offsetEnd != null) args.push('--offset-end', String(message.offsetEnd));
        try {
          const data = await runPythonJsonFile(args, { timeout: 30000, maxBuffer: 1024 * 1024, fallback: '[]' });
          const results = Array.isArray(data) ? data : (data.results || []);
          hubPost('hubRecherche', { results });
        } catch (err) {
          const stderr = String(err.stderr || '').trim();
          hubPost('hubRecherche', { results: [], error: stderr || err.message || 'Recherche échouée.' });
        }
        return;
      }
      if (message.type === 'hubCapaScan') {
        const {
          absPath,
          exists,
          isDirectory,
          binaryMeta,
        } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
        if (!exists || isDirectory) {
          hubPost('hubCapa', { capabilities: [], error: 'Binaire introuvable.' });
          return;
        }
        const format = String(binaryMeta?.format || message.binaryMeta?.format || '').trim().toUpperCase();
        if (format.includes('MACH')) {
          hubPost('hubCapa', {
            capabilities: [],
            error: 'CAPA analyse les exécutables PE et ELF. Le binaire actif est un Mach-O macOS: utilise YARA ici ou charge un binaire Linux/Windows pour CAPA.',
          });
          return;
        }
        if (format === 'RAW') {
          hubPost('hubCapa', {
            capabilities: [],
            error: 'CAPA a besoin d’un exécutable PE ou ELF complet. Les blobs bruts restent analysables avec YARA, Hex, Strings et Désassemblage.',
          });
          return;
        }
        try {
          const result = await runPythonJsonFile(
            [getCapaScanScript(root), '--binary', absPath, '--cwd', root, '--global-config', getRulesConfigPath()],
            { timeout: 120000, maxBuffer: 4 * 1024 * 1024 },
          );
          const errMsg = result.error || (result.errors && result.errors.length ? result.errors.join('; ') : '');
          hubPost('hubCapa', { capabilities: result.capabilities || [], error: errMsg || undefined });
        } catch (err) {
          const stderr = String(err.stderr || '').trim();
          hubPost('hubCapa', { capabilities: [], error: stderr || err.message || 'Capa a échoué.' });
        }
        return;
      }
      if (message.type === 'hubListRules') {
        try {
          const data = await runRulesManagerJson(['list']);
          hubPost('hubRulesList', { rules: data.rules || [], error: data.error || null });
        } catch (err) {
          hubPost('hubRulesList', { rules: [], error: err.message });
        }
        return;
      }
      if (message.type === 'hubToggleRule') {
        const { ruleId, enabled } = message;
        try {
          const data = await runRulesManagerJson(
            ['toggle', '--rule-id', ruleId, '--enabled', enabled ? 'true' : 'false'],
            { timeout: 5000 },
          );
          hubPost('hubRuleToggled', data);
        } catch (err) {
          hubPost('hubRuleToggled', { success: false, error: err.message });
        }
        return;
      }
      if (message.type === 'hubAddUserRule') {
        const { name, ruleType, content } = message;
        try {
          const data = await runRulesManagerJson(
            ['add', '--name', name, '--type', ruleType, '--content', content],
            { timeout: 5000 },
          );
          hubPost('hubRuleAdded', data);
        } catch (err) {
          hubPost('hubRuleAdded', { error: err.message });
        }
        return;
      }
      if (message.type === 'hubDeleteUserRule') {
        const { ruleId } = message;
        try {
          const data = await runRulesManagerJson(
            ['delete', '--rule-id', ruleId],
            { timeout: 5000 },
          );
          hubPost('hubRuleDeleted', data);
        } catch (err) {
          hubPost('hubRuleDeleted', { success: false, error: err.message });
        }
        return;
      }
      if (message.type === 'hubCompileStaticBinary') {
        const sourcePath     = String(message.sourcePath || '').trim();
        const binaryPath     = String(message.binaryPath || '').trim();
        const archBits       = String(message.archBits || '64');
        const pieChoice      = String(message.pieChoice || 'no');
        const useLegacyFlags = message.useLegacyFlags === true;
        const optim          = useLegacyFlags ? null : String(message.optim || '-O0');
        const debug          = useLegacyFlags ? null : String(message.debug ?? '-g');
        const canary         = useLegacyFlags ? null : String(message.canary || 'off');
        const execstack      = useLegacyFlags ? true  : (message.execstack !== false);
        const relro          = String(message.relro || 'off');
        const staticLink     = message.static === true;
        const strip          = message.strip === true;
        const extraFlags     = String(message.extraFlags || '').trim();
        try {
          const result = await compileCSource({
            sourcePath,
            binaryPath,
            archBits,
            pieChoice,
            useLegacyFlags,
            includeExecstack: useLegacyFlags,
            optim,
            debug,
            canary,
            execstack,
            relro,
            staticLink,
            strip,
            extraFlags,
          });
          panel.webview.postMessage({
            type: 'hubSetBinaryPath',
            binaryPath: result.pathForWebview,
            binaryMeta: { kind: 'native', format: inspectBinaryInput(result.absoluteBinaryPath).format || '' },
          });
          if (refreshSidebar) refreshSidebar(result.pathForWebview);
          vscode.window.showInformationMessage(`Compilation OK: ${result.pathForWebview}`);
        } catch (err) {
          vscode.window.showErrorMessage(`Compilation échouée: ${err.message || err}`);
        } finally {
          panel.webview.postMessage({ type: 'hubStaticCompileDone' });
        }
        return;
      }

      if (message.type === 'hubSaveScript') {
        const scriptsDir = path.join(root, '.pile-ou-face', 'scripts');
        if (!fs.existsSync(scriptsDir)) fs.mkdirSync(scriptsDir, { recursive: true });
        const name = message.name || 'script.py';
        const filePath = path.join(scriptsDir, name);
        fs.writeFileSync(filePath, message.content, 'utf8');
        panel.webview.postMessage({ type: 'hubScriptSaved', path: filePath });
        return;
      }

      if (message.type === 'hubLoadScript') {
        const picked = await vscode.window.showOpenDialog({
          canSelectFiles: true, canSelectMany: false,
          filters: { 'Python': ['py'] },
          title: 'Charger un script Python',
          defaultUri: vscode.Uri.file(path.join(root, '.pile-ou-face', 'scripts')),
        });
        if (picked && picked[0]) {
          const content = fs.readFileSync(picked[0].fsPath, 'utf8');
          const name = path.basename(picked[0].fsPath);
          panel.webview.postMessage({ type: 'hubScriptLoaded', content, name });
        }
        return;
      }

      if (message.type === 'hubLoadPwntoolsScript') {
        const picked = await vscode.window.showOpenDialog({
          canSelectFiles: true,
          canSelectMany: false,
          filters: { 'Python': ['py'] },
          title: 'Importer un script pwntools',
          defaultUri: vscode.Uri.file(root),
        });
        if (picked && picked[0]) {
          const filePath = picked[0].fsPath;
          const content = fs.readFileSync(filePath, 'utf8');
          panel.webview.postMessage({
            type: 'hubPwntoolsScriptLoaded',
            content,
            path: filePath,
            name: path.basename(filePath),
          });
        }
        return;
      }

      if (message.type === 'hubAnalyzePwntoolsScript') {
        const scriptContent = String(message.scriptContent || '');
        const sourceFileName = String(message.sourceFileName || 'payload.py').trim() || 'payload.py';
        const scriptPathRaw = String(message.scriptPath || '').trim();
        const binaryPathRaw = String(message.binaryPath || '').trim();
        const resolvedScriptPath = scriptPathRaw ? resolvePathFromWorkspace(scriptPathRaw) : '';
        const resolvedBinaryPath = binaryPathRaw ? resolvePathFromWorkspace(binaryPathRaw) : '';
        const scriptRoot = resolvedScriptPath
          ? path.dirname(resolvedScriptPath)
          : (resolvedBinaryPath ? path.dirname(resolvedBinaryPath) : root);
        if (!scriptContent.trim()) {
          panel.webview.postMessage({
            type: 'hubPwntoolsScriptAnalyzed',
            result: {
              ok: false,
              sourceFileName,
              captures: [],
              captured: [],
              globals: {},
              processes: [],
              warnings: ['Script pwntools requis.'],
              error: 'Le script pwntools est vide.',
              stdout: '',
              stderr: '',
            }
          });
          return;
        }
        const tempDir = ensureTempDir(root);
        const nonce = crypto.randomBytes(6).toString('hex');
        const tempScriptPath = path.join(tempDir, `pwntools-script-${nonce}.py`);
        fs.writeFileSync(tempScriptPath, scriptContent, 'utf8');
        let result = null;
        try {
          result = await runPythonJsonFile(
            [
              getPayloadScriptRunnerScript(root),
              '--script-file',
              tempScriptPath,
              '--source-name',
              sourceFileName,
              '--script-root',
              scriptRoot,
              '--timeout-seconds',
              '2.0',
              ...(resolvedBinaryPath ? ['--script-arg', resolvedBinaryPath] : []),
            ],
            {
              timeout: 3000,
              maxBuffer: 8 * 1024 * 1024,
            },
          );
        } catch (err) {
          result = {
            ok: false,
            sourceFileName,
            captures: [],
            captured: [],
            globals: {},
            processes: [],
            warnings: ['Analyse du script pwntools impossible.'],
            error: String(err?.stderr || err?.stdout || err?.message || err || 'Erreur inconnue'),
            stdout: String(err?.stdout || ''),
            stderr: String(err?.stderr || ''),
          };
        } finally {
          try {
            if (fs.existsSync(tempScriptPath)) fs.unlinkSync(tempScriptPath);
          } catch (_) {
            // ignore temp cleanup failures
          }
        }
        const capturesCount = Array.isArray(result?.captures)
          ? result.captures.length
          : (Array.isArray(result?.captured) ? result.captured.length : 0);
        logChannel.appendLine(`[payload] pwntools analysis source=${sourceFileName} ok=${result?.ok !== false} captures=${capturesCount}`);
        panel.webview.postMessage({ type: 'hubPwntoolsScriptAnalyzed', result });
        return;
      }

      if (message.type === 'hubPickFile') {
        const isBinaryTarget = ['bindiffPathA', 'bindiffPathB', 'funcSimilarityRef'].includes(message.target);
        const isSourceTarget = message.fileType === 'sourceC' || message.target === 'dynamicSourcePath';
        const dialogOpts = {
          canSelectFiles: true, canSelectMany: false,
          defaultUri: vscode.Uri.file(root),
        };
        if (isBinaryTarget) {
          dialogOpts.title = 'Sélectionner un binaire (ELF, Mach-O, PE)';
          dialogOpts.filters = { 'Tous les fichiers': ['*'] };
        } else if (isSourceTarget) {
          dialogOpts.title = 'Sélectionner un fichier source C';
          dialogOpts.filters = { 'Source C': ['c', 'h'], 'Tous les fichiers': ['*'] };
        } else {
          dialogOpts.title = 'Sélectionner un fichier';
        }
        const picked = await vscode.window.showOpenDialog(dialogOpts);
        if (picked && picked[0]) {
          if (isBinaryTarget && !isSupportedBinary(picked[0].fsPath)) {
            vscode.window.showErrorMessage('Format non supporté — sélectionnez un binaire ELF, Mach-O ou PE.');
            return;
          }
          panel.webview.postMessage({ type: 'hubPickedFile', target: message.target, path: picked[0].fsPath });
        }
        return;
      }

      if (message.type === 'requestRunTraceInit') {
        const initPayload = await buildRunTraceInit(
          message.binaryPath || '',
          message.preset || null,
          message.sourcePath || '',
          message.payloadTargetMode || 'auto'
        );
        panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
        return;
      }

      if (message.type === 'requestDynamicTraceHistory') {
        postDynamicTraceHistory();
        return;
      }

      if (message.type === 'openDynamicTraceHistory') {
        const requestedTracePath = String(message.tracePath || '').trim();
        if (!isManagedDynamicTracePath(requestedTracePath) || !fs.existsSync(requestedTracePath)) {
          vscode.window.showErrorMessage('Trace historique introuvable.');
          postDynamicTraceHistory();
          return;
        }
        const trace = readTraceJson(requestedTracePath);
        enrichTraceForVisualizer(trace, {
          jsonPath: requestedTracePath,
          viewMode: trace?.meta?.view_mode || 'dynamic'
        });
        activeDynamicTracePath = requestedTracePath;
        writeTraceJson(requestedTracePath, trace);
        openVisualizerWebview(trace);
        postDynamicTraceHistory();
        return;
      }

      if (message.type === 'deleteDynamicTraceHistory') {
        const requestedTracePath = String(message.tracePath || '').trim();
        deleteDynamicTraceArtifacts(requestedTracePath);
        postDynamicTraceHistory();
        return;
      }

      if (message.type === 'clearDynamicTraceHistory') {
        const items = buildDynamicTraceHistoryItems();
        items.forEach((item) => {
          deleteDynamicTraceArtifacts(item.path);
        });
        postDynamicTraceHistory();
        return;
      }

      if (message.type === 'readyRunTrace') {
        const initPayload = await buildRunTraceInit();
        panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
        return;
      }

      if (message.type === 'refreshRunTraceBinary') {
        const initPayload = await buildRunTraceInit(
          message.binaryPath || '',
          null,
          message.sourcePath || '',
          message.payloadTargetMode || 'auto'
        );
        panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
        return;
      }

      if (message.type === 'selectRunTraceBinary') {
        const binaryUri = await vscode.window.showOpenDialog({
          title: 'Pile ou Face — Sélectionner le binaire du projet',
          defaultUri: vscode.Uri.file(root),
          canSelectMany: false,
          filters: { 'Binaires': ['elf', 'out', 'bin'], 'Tous': ['*'] }
        });
        if (!binaryUri?.length) return;
        const binaryPath = binaryUri[0].fsPath;
        const pathForWebview = toWebviewPath(binaryPath);
        panel.webview.postMessage({ type: 'hubSetBinaryPath', binaryPath: pathForWebview });
        const initPayload = await buildRunTraceInit(pathForWebview, null, message.sourcePath || '', message.payloadTargetMode || 'auto');
        panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
        if (refreshSidebar) refreshSidebar(pathForWebview);
        return;
      }

      if (message.type === 'hubGetSettings') {
        const settings = context.globalState.get('pof-settings', SETTINGS_DEFAULTS);
        panel.webview.postMessage({ type: 'hubSettings', settings: { ...SETTINGS_DEFAULTS, ...settings } });
        return;
      }
      if (message.type === 'hubSaveSettings') {
        await context.globalState.update('pof-settings', message.settings);
        panel.webview.postMessage({ type: 'hubSettingsSaved', ok: true });
        return;
      }
      if (message.type === 'hubResetSettings') {
        await context.globalState.update('pof-settings', SETTINGS_DEFAULTS);
        panel.webview.postMessage({ type: 'hubSettings', settings: { ...SETTINGS_DEFAULTS } });
        return;
      }

      if (message.type !== 'runTrace') return;
      const traceRunId = ++latestTraceRunId;
      const payload = (message.payload && typeof message.payload === 'object')
        ? message.payload
        : ((message.config && typeof message.config === 'object') ? message.config : {});

      const sourcePath = (payload.sourcePath || '').trim();
      const binaryPath = (payload.binaryPath || '').trim();
      const useExistingBinary = payload.useExistingBinary !== false;
      const archBits = String(payload.archBits || '64');
      const pieChoice = String(payload.pieChoice || (payload.pie === true ? 'yes' : 'no') || 'no');
      const traceMode = String(payload.traceMode || 'dynamic');
      const bufferOffset = String(payload.bufferOffset || '-64');
      const bufferSize = String(payload.bufferSize || '64');
      const maxSteps = String(payload.maxSteps || '800');

      let startSymbol = String(payload.startSymbol || 'main').trim();
      if (!startSymbol) startSymbol = 'main';
      const stopSymbol = String(payload.stopSymbol || '').trim();
      const useInterp = false;
      const captureBinaryOnly = payload.captureBinaryOnly !== false;

      try {
        const tempDir = ensureTempDir(root);
        const { canonicalJsonPath, isolatedJsonPath } = buildTraceRunArtifacts(tempDir, traceRunId);
        logChannel.appendLine(`[temp] Sortie trace #${traceRunId}: ${isolatedJsonPath}`);

        if (traceMode === 'static') {
          const absoluteAsm = path.join(tempDir, 'input.asm');
          const absoluteSource = sourcePath ? (path.isAbsolute(sourcePath) ? sourcePath : path.join(root, sourcePath)) : null;
          const staticResult = ensureStaticAsm(absoluteAsm, absoluteSource, logChannel);
          if (!staticResult.ok) {
            vscode.window.showErrorMessage(staticResult.error || 'Static: generation input.asm echouee.');
            return;
          }
          const staticArgs = [
            getAsmStaticScript(root),
            '--input', absoluteAsm,
            '--output', isolatedJsonPath
          ];
          await runCommand(pythonExe, staticArgs, root, logChannel, { PYTHONPATH: root });
          if (!fs.existsSync(isolatedJsonPath)) {
            throw new Error(`Trace statique introuvable: ${path.basename(isolatedJsonPath)}`);
          }
          if (traceRunId !== latestTraceRunId) {
            logChannel.appendLine(`[trace] Resultat perime ignore (#${traceRunId}).`);
            return;
          }
          const trace = readTraceJson(isolatedJsonPath);
          enrichTraceForVisualizer(trace, {
            jsonPath: isolatedJsonPath,
            traceRunId,
            viewMode: 'static'
          });
          writeTraceJson(isolatedJsonPath, trace);
          activeDynamicTracePath = isolatedJsonPath;
          writeTraceJson(canonicalJsonPath, trace);
          openVisualizerWebview(trace);
          postDynamicTraceHistory();
        } else {
          if (useExistingBinary && !binaryPath) {
            vscode.window.showErrorMessage('Chemin binaire requis.');
            return;
          }
          if (!useExistingBinary && !sourcePath) {
            vscode.window.showErrorMessage('Source C requise.');
            return;
          }

          let binaryOutPath = '';
          if (useExistingBinary) {
            const absoluteBinaryPath = resolvePathFromWorkspace(binaryPath);
            if (!fs.existsSync(absoluteBinaryPath)) {
              vscode.window.showErrorMessage(`Binaire introuvable: ${absoluteBinaryPath}`);
              return;
            }
            binaryOutPath = absoluteBinaryPath;
          } else {
            const sourceBase = path.parse(sourcePath).name || 'binary';
            const requestedName = binaryPath ? path.basename(binaryPath) : `${sourceBase}.elf`;
            const outputName = requestedName || `${sourceBase}.elf`;
            const outPath = path.resolve(tempDir, outputName);
            const compileResult = await compileCSource({
              sourcePath,
              binaryPath: outPath,
              archBits,
              pieChoice,
              useLegacyFlags: true,
              includeExecstack: true,
            });
            binaryOutPath = compileResult.absoluteBinaryPath;
          }
          const binaryInfoForSymbols = await loadBinaryHeaders(binaryOutPath).catch(() => inspectBinaryInput(binaryOutPath));
          startSymbol = normalizeStartSymbolForBinary(startSymbol, binaryInfoForSymbols);

          const payloadExprRaw = String(payload.payloadExpr || '').trim();
          const inputMeta = normalizeTraceInputMeta(payload.input || null, 'payload_builder');
          const stagedInputFile = inputMeta.mode === 'file'
            ? stageDynamicInputFile(payload.file || payload.input?.file || null)
            : null;
          if (inputMeta.mode === 'file' && !stagedInputFile) {
            throw new Error('Configuration fichier payload manquante.');
          }
          const payloadTargetMode = normalizePayloadTargetMode(
            inputMeta.targetMode || payload.payloadTargetMode || payload.payloadTarget || 'auto'
          );
          const effectiveSourcePath = sourcePath || inferSourcePathForBinary(binaryOutPath);
          const payloadTargetResolution = resolvePayloadTarget({
            mode: payloadTargetMode,
            sourceText: readSourceTextForPayloadTarget(effectiveSourcePath)
          });
          const payloadTarget = stagedInputFile ? 'argv1' : payloadTargetResolution.target;
          const inputPayloadHex = inputMeta.payloadBytesHex;
          const injectPayload = !stagedInputFile
            && ((payloadExprRaw.length > 0 || inputPayloadHex.length > 0)
              && (payload.injectPayload === true || payload.injectPayload === undefined));
          const injectStdin = injectPayload && (payloadTarget === 'stdin' || payloadTarget === 'both');
          const injectArgv = injectPayload && (payloadTarget === 'argv1' || payloadTarget === 'both');
          let payloadString = '';
          let payloadHex = '';
          if (injectPayload && inputPayloadHex) {
            payloadHex = inputPayloadHex;
            payloadString = hexToLatin1String(payloadHex);
          } else if (injectPayload && payloadExprRaw) {
            try {
              payloadString = normalizePayloadExpression(payloadExprRaw);
              payloadHex = typeof payloadToHex === 'function' ? payloadToHex(payloadExprRaw) : '';
            } catch (err) {
              vscode.window.showErrorMessage(`Payload invalide: ${err.message || err}`);
              return;
            }
          }
          if (injectArgv && payloadHex && hexContainsNullByte(payloadHex)) {
            vscode.window.showErrorMessage('Payload invalide pour argv[1]: contient un octet NUL. Utilisez stdin ou Fichier.');
            return;
          }
          logChannel.appendLine(`[payload] runTrace mode=${stagedInputFile ? 'file' : inputMeta.mode} target=${payloadTarget} inject=${injectPayload} size=${payloadHex ? payloadHex.length / 2 : payloadString.length} hex=${payloadHex ? payloadHex.slice(0, 160) : ''}`);

          const pythonArgs = [
            getRunPipelineScript(root),
            '--binary', binaryOutPath,
            '--stdin', injectStdin && !payloadHex ? payloadString : '',
            '--buffer-offset', bufferOffset,
            '--buffer-size', bufferSize,
            '--stack-entries', '40',
            '--output', isolatedJsonPath,
            '--start-symbol', startSymbol,
            '--max-steps', maxSteps
          ];
          if (injectStdin && payloadHex) pythonArgs.push('--stdin-hex', payloadHex);
          if (injectArgv && payloadHex) pythonArgs.push('--argv1-hex', payloadHex);
          else if (injectArgv) pythonArgs.push('--argv1', payloadString);
          if (stagedInputFile) {
            pythonArgs.push('--argv1', stagedInputFile.guestPath);
            pythonArgs.push('--virtual-file', `${stagedInputFile.guestPath}=${stagedInputFile.hostPath}`);
          }
          if (!captureBinaryOnly) pythonArgs.push('--no-capture-binary');
          if (stopSymbol) pythonArgs.push('--stop-symbol', stopSymbol);
          if (useInterp) pythonArgs.push('--start-interp');

          await runCommand(pythonExe, pythonArgs, root, logChannel, { PYTHONPATH: root });
          if (!fs.existsSync(isolatedJsonPath)) {
            throw new Error(`Trace dynamique introuvable: ${path.basename(isolatedJsonPath)}`);
          }
          if (traceRunId !== latestTraceRunId) {
            logChannel.appendLine(`[trace] Resultat perime ignore (#${traceRunId}).`);
            return;
          }
          const trace = readTraceJson(isolatedJsonPath);
          enrichTraceForVisualizer(trace, {
            jsonPath: isolatedJsonPath,
            traceRunId,
            sourcePath: effectiveSourcePath,
            archBits,
            viewMode: 'dynamic'
          });
          trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
          trace.meta.payload_target_mode = payloadTargetMode;
          trace.meta.payload_target = payloadTarget;
          trace.meta.payload_target_auto = payloadTargetResolution.autoTarget;
          trace.meta.payload_target_reason = payloadTargetResolution.reason;
          trace.meta.payload_label = payloadTargetLabel(payloadTarget);
          trace.meta.payload_text = stagedInputFile ? stagedInputFile.guestPath : (injectPayload ? payloadString : '');
          trace.meta.payload_hex = injectPayload ? payloadHex : '';
          const runtimeInputWarnings = Array.isArray(trace.meta.virtual_file_warnings)
            ? trace.meta.virtual_file_warnings.map(String)
            : [];
          trace.meta.input = {
            mode: stagedInputFile ? 'file' : inputMeta.mode,
            template: inputMeta.template,
            targetMode: payloadTargetMode,
            sourceFileName: inputMeta.sourceFileName,
            selectedCaptureKind: inputMeta.selectedCaptureKind,
            target: inputMeta.target || payloadTarget,
            builderLevel: inputMeta.builderLevel,
            sourceFields: inputMeta.sourceFields,
            generatedSnippet: inputMeta.generatedSnippet,
            size: inputMeta.size || (payloadHex ? payloadHex.length / 2 : payloadString.length),
            previewHex: inputMeta.previewHex || payloadHex,
            previewAscii: inputMeta.previewAscii || payloadString,
            warnings: [...inputMeta.warnings, ...runtimeInputWarnings],
            ...(stagedInputFile ? {
              file: {
                source: stagedInputFile.source,
                guestPath: stagedInputFile.guestPath,
                hostPath: stagedInputFile.hostPath,
                passAs: stagedInputFile.passAs,
              }
            } : {})
          };
          writeTraceJson(isolatedJsonPath, trace);
          activeDynamicTracePath = isolatedJsonPath;
          writeTraceJson(canonicalJsonPath, trace);
          openVisualizerWebview(trace);
          postDynamicTraceHistory();
        }
      } catch (err) {
        vscode.window.showErrorMessage(`Trace failed: ${err.message || err}`);
      } finally {
        if (traceRunId === latestTraceRunId) {
          panel.webview.postMessage({ type: 'runTraceDone' });
        }
      }
    });
    return panel;
  };
}

module.exports = { createHub };
