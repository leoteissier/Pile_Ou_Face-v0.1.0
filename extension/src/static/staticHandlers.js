/**
 * @file staticHandlers.js
 * @brief Handlers de messages liés au mode statique (désassemblage, symboles, sections, etc.).
 * @see docs/ARCHITECTURE_AUDIT_PLAN.md Phase 2.2
 */

const vscode = require('vscode');
const cp = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const { detectPythonExecutable, buildRuntimeEnv } = require('../shared/utils');
const { normalizeRawArchName } = require('../shared/sharedHandlers');

function staticHandlers(config) {
  const { root, panel, context } = config;
  const getSavedSettings = () => {
    try {
      return context?.globalState?.get('pof-settings', {}) || {};
    } catch (_) {
      return {};
    }
  };
  const getPythonExecutable = () => getSavedSettings().pythonPath || detectPythonExecutable(root);
  const normalizeInstallDir = (rawPath, executableNames = []) => {
    const value = String(rawPath || '').trim();
    if (!value) return '';
    const lower = value.toLowerCase();
    const match = executableNames.find((name) => lower.endsWith(`/${name}`) || lower.endsWith(`\\${name}`));
    if (match) return path.dirname(value);
    return value;
  };
  const buildPythonEnv = () => {
    const settings = getSavedSettings();
    const localPaths = settings.decompilerLocalPaths && typeof settings.decompilerLocalPaths === 'object'
      ? settings.decompilerLocalPaths
      : {};
    const env = buildRuntimeEnv(root);
    const prependPath = [];
    const radare2Path = String(localPaths.radare2 || '').trim();
    if (radare2Path) prependPath.push(normalizeInstallDir(radare2Path, ['r2']));
    const angrPath = String(localPaths.angr || '').trim();
    if (angrPath) env.PYTHONPATH = `${angrPath}${path.delimiter}${env.PYTHONPATH || ''}`;
    const retdecPath = String(localPaths.retdec || '').trim();
    if (retdecPath) env.RETDEC_INSTALL_DIR = normalizeInstallDir(retdecPath, ['retdec-decompiler']);
    const ghidraPath = String(localPaths.ghidra || '').trim();
    if (ghidraPath) env.GHIDRA_INSTALL_DIR = ghidraPath;
    if (prependPath.length) env.PATH = `${prependPath.join(path.delimiter)}${path.delimiter}${env.PATH || ''}`;
    return env;
  };

  const runPython = (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024 } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = path.join(root, scriptRelPath);
      cp.execFile(getPythonExecutable(), [scriptPath, ...rest], {
        encoding: 'utf8', cwd: root, maxBuffer, timeout, env: buildPythonEnv(),
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });

  const buildTypedDataArgs = (message) => {
    const {
      binaryPath, section, valueType, page, structName, structOffset, structAddr,
    } = message || {};
    const typeName = valueType || null;
    const args = ['backends/static/typed_data.py', '--binary', binaryPath];
    if (section) args.push('--section', section);
    if (typeName) args.push('--type', typeName);
    if (page !== undefined && page !== null) args.push('--page', String(page));
    if (structName) args.push('--struct-name', structName);
    if (structOffset !== undefined && structOffset !== null) args.push('--struct-offset', String(structOffset));
    if (structAddr !== undefined && structAddr !== null && String(structAddr).trim()) {
      args.push('--struct-addr', String(structAddr));
    }
    const rawBaseAddr = message?.binaryMeta?.rawConfig?.baseAddr || message?.rawBaseAddr || null;
    if (rawBaseAddr) args.push('--raw-base-addr', String(rawBaseAddr));
    return args;
  };

  const normalizeRopArch = (message = {}) => {
    const meta = message.binaryMeta || {};
    const rawArch = String(meta.rawConfig?.arch || meta.rawArch || message.rawArch || '').trim();
    if (rawArch) return rawArch;
    const arch = String(meta.arch || message.arch || '').trim().toLowerCase();
    const normalized = normalizeRawArchName(arch);
    return normalized || '';
  };

  const listOllamaModels = (baseUrlRaw) => new Promise((resolve, reject) => {
    const fallbackUrl = 'http://127.0.0.1:11434';
    const input = String(baseUrlRaw || '').trim() || fallbackUrl;
    let parsed;
    try {
      parsed = new URL(input);
    } catch (_) {
      reject(new Error(`URL Ollama invalide: ${input}`));
      return;
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: '/api/tags',
        timeout: 8000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`Ollama a répondu ${res.statusCode}`));
            return;
          }
          try {
            const raw = Buffer.concat(chunks).toString('utf8');
            const payload = JSON.parse(raw);
            const models = Array.isArray(payload.models)
              ? payload.models
                  .map((item) => String(item?.name || '').trim())
                  .filter(Boolean)
              : [];
            models.sort((a, b) => a.localeCompare(b));
            resolve(models);
          } catch (e) {
            reject(new Error(`Réponse Ollama invalide: ${e.message || e}`));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Timeout Ollama')));
    req.on('error', (err) => reject(new Error(`Impossible de joindre Ollama (${input}): ${err.message || err}`)));
    req.end();
  });

  return {
    hubOllamaListModels: async (message) => {
      const baseUrl = String(message?.baseUrl || '').trim() || 'http://127.0.0.1:11434';
      try {
        const models = await listOllamaModels(baseUrl);
        panel.webview.postMessage({ type: 'hubOllamaModels', models, baseUrl });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubOllamaModels',
          models: [],
          baseUrl,
          error: String(e?.message || e),
        });
      }
    },
    hubOllamaPrompt: async (message) => {
      const baseUrl = String(message?.baseUrl || '').trim() || 'http://127.0.0.1:11434';
      const model = String(message?.model || '').trim();
      const prompt = String(message?.prompt || '').trim();
      if (!model) {
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          error: 'Modèle Ollama manquant.',
          output: '',
        });
        return;
      }
      if (!prompt) {
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          error: 'Prompt vide.',
          output: '',
          model,
        });
        return;
      }
      try {
        const { stdout } = await runPython([
          'backends/mcp/ollama_bridge.py',
          '--base-url', baseUrl,
          '--model', model,
          '--prompt', prompt,
          '--timeout', '120',
          '--max-steps', '10',
        ]);
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: true,
          model,
          output: String(stdout || '').trim(),
        });
      } catch (e) {
        const stderr = String(e?.stderr || e?.message || e || '').trim();
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          model,
          error: stderr || 'Échec de l’exécution Ollama.',
          output: '',
        });
      }
    },
    hubListDecompilers: async (message = {}) => {
      const provider = message.provider || 'auto';
      try {
        const { stdout } = await runPython(['backends/static/decompile.py', '--list', '--provider', provider]);
        panel.webview.postMessage({ type: 'hubDecompilerList', result: JSON.parse(stdout) });
      } catch (e) {
        // Fallback minimal si decompile.py échoue
        panel.webview.postMessage({
          type: 'hubDecompilerList',
          result: { ghidra: false, retdec: true, angr: false, _meta: { provider, docker_images: {} } },
        });
      }
    },
    hubHideBuiltinDecompiler: async (message = {}) => {
      const id = String(message?.id || '').trim();
      if (!id) return;
      try {
        await runPython(['backends/static/decompile.py', '--hide-builtin', id]);
        // Rafraîchir la liste après masquage
        const { stdout } = await runPython(['backends/static/decompile.py', '--list', '--provider', 'auto']);
        panel.webview.postMessage({ type: 'hubDecompilerList', result: JSON.parse(stdout) });
      } catch (e) {
        vscode.window.showErrorMessage(`Impossible de masquer le décompilateur '${id}': ${e.message || e}`);
      }
    },
    hubRestoreBuiltinDecompiler: async (message = {}) => {
      const id = String(message?.id || '').trim();
      if (!id) return;
      try {
        await runPython(['backends/static/decompile.py', '--restore-builtin', id]);
        // Rafraîchir la liste après restauration
        const { stdout } = await runPython(['backends/static/decompile.py', '--list', '--provider', 'auto']);
        panel.webview.postMessage({ type: 'hubDecompilerList', result: JSON.parse(stdout) });
      } catch (e) {
        vscode.window.showErrorMessage(`Impossible de restaurer le décompilateur '${id}': ${e.message || e}`);
      }
    },
    hubExecuteCommand: async (message = {}) => {
      // Permet au webview de déclencher une commande VS Code enregistrée
      const commandId = String(message?.command || '').trim();
      const requestId = message?.requestId || null;
      if (!commandId) return;

      const _sendResult = (status, detail = '') => {
        panel.webview.postMessage({ type: 'hubCommandResult', requestId, command: commandId, status, detail });
      };

      // Pour decompilerTest, on peut passer un ID pré-sélectionné depuis le webview
      const args = message?.args ? (Array.isArray(message.args) ? message.args : [message.args]) : [];

      try {
        await vscode.commands.executeCommand(commandId, ...args);
        _sendResult('done');

        // Après add/edit/remove, rafraîchir la liste automatiquement
        const MUTATING = ['pileOuFace.decompilerAdd', 'pileOuFace.decompilerEdit', 'pileOuFace.decompilerRemove'];
        if (MUTATING.includes(commandId)) {
          // Petit délai pour laisser le temps à la config d'être écrite
          await new Promise(r => setTimeout(r, 800));
          try {
            const { stdout } = await runPython(['backends/static/decompile.py', '--list', '--provider', 'auto']);
            panel.webview.postMessage({ type: 'hubDecompilerList', result: JSON.parse(stdout) });
          } catch (_) {}
        }
        // Après test, pas de refresh liste nécessaire
      } catch (err) {
        _sendResult('error', err.message || String(err));
        // Ne pas afficher showErrorMessage pour les annulations (undefined)
        if (err.message && !err.message.includes('cancelled') && !err.message.includes('cancel')) {
          vscode.window.showErrorMessage(`Erreur commande ${commandId}: ${err.message || err}`);
        }
      }
    },
    hubLoadDecompile: async (message) => {
      const { binaryPath, addr, funcName, full, decompiler, quality, provider } = message;
      let args;
      if (full) {
        args = ['backends/static/decompile.py', '--binary', binaryPath, '--full'];
      } else if (funcName) {
        args = ['backends/static/decompile.py', '--binary', binaryPath,
                '--addr', addr, '--func-name', funcName];
      } else {
        args = ['backends/static/decompile.py', '--binary', binaryPath, '--addr', addr];
      }
      if (decompiler) args.push('--decompiler', decompiler);
      if (quality) args.push('--quality', quality);
      if (provider) args.push('--provider', provider);
      // Inject annotation labels into pseudo-C output
      const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
      const _annHash = crypto.createHash('sha256')
        .update(absPath)
        .update(fs.existsSync(absPath) ? String(fs.statSync(absPath).mtimeMs) : '')
        .digest('hex').slice(0, 16);
      const _annPath = path.join(root, '.pile-ou-face', 'annotations', `${_annHash}.json`);
      if (fs.existsSync(_annPath)) args.push('--annotations-json', _annPath);
      try {
        const { stdout } = await runPython(args, { timeout: 120000 });
        panel.webview.postMessage({
          type: 'hubDecompile',
          result: JSON.parse(stdout),
          binaryPath,
          addr: addr || '',
          funcName: funcName || '',
          full: !!full,
          decompiler: decompiler || '',
          quality: quality || 'normal',
          provider: provider || 'auto',
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubDecompile',
          result: { error: String(e) },
          binaryPath,
          addr: addr || '',
          funcName: funcName || '',
          full: !!full,
          decompiler: decompiler || '',
          quality: quality || 'normal',
          provider: provider || 'auto',
        });
      }
    },
    hubLoadBehavior: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/behavior.py', '--binary', binaryPath], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubBehavior', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubBehavior', result: { error: String(e) } });
      }
    },
    hubLoadTaint: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/taint.py', '--binary', binaryPath], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubTaint', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubTaint', result: { error: String(e) } });
      }
    },
    hubLoadRop: async (message) => {
      const { binaryPath } = message;
      try {
        const args = ['backends/static/rop_gadgets.py', '--binary', binaryPath];
        const arch = normalizeRopArch(message);
        if (arch) args.push('--arch', arch);
        const { stdout } = await runPython(args);
        panel.webview.postMessage({ type: 'hubRop', gadgets: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRop', gadgets: [], error: String(e) });
      }
    },
    hubLoadVulns: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/vuln_patterns.py', '--binary', binaryPath], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubVulns', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubVulns', result: { error: String(e) } });
      }
    },
    hubLoadAntiAnalysis: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/anti_analysis.py', '--binary', binaryPath], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubAntiAnalysisDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubAntiAnalysisDone', data: { error: String(e) } });
      }
    },
    hubLoadImports: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/imports_analysis.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubImportsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubImportsDone', data: { error: String(e) } });
      }
    },
    hubLoadExports: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/binary_exports.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubExportsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubExportsDone', data: { error: String(e) } });
      }
    },
    hubLoadImportXrefs: async (message) => {
      const { binaryPath, fnName } = message;
      try {
        const { stdout } = await runPython(['backends/static/import_xrefs.py', '--binary', binaryPath, '--function', fnName]);
        panel.webview.postMessage({ type: 'hubImportXrefsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubImportXrefsDone', data: { function: fnName, callsites: [], error: String(e) } });
      }
    },
    hubLoadFuncSimilarity: async (message) => {
      const {
        binaryPath, referencePath, threshold, top, useDb,
      } = message;
      try {
        const args = ['backends/static/func_similarity.py', '--binary', binaryPath];
        if (useDb) args.push('--search-db');
        else args.push('--reference', referencePath);
        if (threshold != null) args.push('--threshold', String(threshold));
        if (top != null) args.push('--top', String(top));
        const { stdout } = await runPython(args, { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubFuncSimilarityDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDone', data: { matches: [], error: String(e) } });
      }
    },
    hubIndexFuncSimilarityRef: async (message) => {
      const { referencePath, label } = message;
      try {
        const args = ['backends/static/func_similarity.py', '--index-reference', referencePath];
        if (label) args.push('--label', label);
        const { stdout } = await runPython(args, { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: { references: [], error: String(e) } });
      }
    },
    hubListFuncSimilarityDb: async () => {
      try {
        const { stdout } = await runPython(['backends/static/func_similarity.py', '--list-db']);
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: { references: [], error: String(e) } });
      }
    },
    hubClearFuncSimilarityDb: async () => {
      try {
        const { stdout } = await runPython(['backends/static/func_similarity.py', '--clear-db']);
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: { references: [], error: String(e) } });
      }
    },
    hubUpdateFuncSimilarityRef: async (message) => {
      const { referenceId, label } = message;
      try {
        const args = ['backends/static/func_similarity.py', '--update-reference-label', referenceId, '--label', label];
        const { stdout } = await runPython(args);
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: { references: [], error: String(e) } });
      }
    },
    hubRemoveFuncSimilarityRef: async (message) => {
      const { referenceId } = message;
      try {
        const { stdout } = await runPython(['backends/static/func_similarity.py', '--remove-reference', referenceId]);
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFuncSimilarityDbDone', data: { references: [], error: String(e) } });
      }
    },
    hubLoadFlirt: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/flirt.py', '--binary', binaryPath], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubFlirtDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFlirtDone', data: { error: String(e) } });
      }
    },
    hubLoadDeobfuscate: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/string_deobfuscate.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubDeobfuscateDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubDeobfuscateDone', data: { error: String(e) } });
      }
    },
    hubLoadHexView: async (message) => {
      const { binaryPath, offset = 0, length = 512 } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/hex_view.py',
          '--binary', binaryPath,
          '--offset', String(offset),
          '--length', String(length),
        ]);
        panel.webview.postMessage({ type: 'hubHexView', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubHexView',
          result: { error: String(e), rows: [], sections: [] },
        });
      }
    },
    hubPatchBytes: async (message) => {
      const { binaryPath, offset, bytesHex } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/patch_manager.py', 'apply',
          '--binary', binaryPath, '--offset', String(offset), '--bytes', bytesHex,
        ]);
        const result = JSON.parse(stdout);
        // Map to the shape the webview expects for hubPatchResult
        panel.webview.postMessage({
          type: 'hubPatchResult',
          result: {
            ok: result.ok,
            written: result.patch ? result.patch.patched_bytes.split(' ').length : 0,
            offset,
            error: result.error || null,
            patch: result.patch || null,
          },
        });
        if (result.ok) {
          const { stdout: ls } = await runPython(['backends/static/patch_manager.py', 'list', '--binary', binaryPath]);
          panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        }
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPatchResult', result: { ok: false, error: String(e) } });
      }
    },
    hubLoadPatches: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPatchesDone', data: { patches: [], error: String(e) } });
      }
    },
    hubRevertPatch: async (message) => {
      const { binaryPath, patchId } = message;
      try {
        const { stdout } = await runPython(['backends/static/patch_manager.py', 'revert', '--binary', binaryPath, '--id', patchId]);
        const result = JSON.parse(stdout);
        const { stdout: ls } = await runPython(['backends/static/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: true, patch: result.patch || null });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: false, error: String(e) });
      }
    },
    hubRedoPatch: async (message) => {
      const { binaryPath, patchId } = message;
      try {
        const args = ['backends/static/patch_manager.py', 'redo', '--binary', binaryPath];
        if (patchId) args.push('--id', patchId);
        const { stdout } = await runPython(args);
        const result = JSON.parse(stdout);
        const { stdout: ls } = await runPython(['backends/static/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRedoPatchDone', ok: true, patch: result.patch || null });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRedoPatchDone', ok: false, error: String(e) });
      }
    },
    hubRevertAllPatches: async (message) => {
      const { binaryPath } = message;
      try {
        await runPython(['backends/static/patch_manager.py', 'revert-all', '--binary', binaryPath]);
        const { stdout: ls } = await runPython(['backends/static/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: true });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: false, error: String(e) });
      }
    },
    hubLoadStackFrame: async (message) => {
      const { binaryPath, addr } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/stack_frame.py',
          '--binary', binaryPath,
          '--addr', String(addr),
        ]);
        panel.webview.postMessage({
          type: 'hubStackFrame',
          binaryPath,
          addr: String(addr),
          result: JSON.parse(stdout),
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubStackFrame',
          binaryPath,
          addr: String(addr),
          result: { error: String(e), vars: [], args: [], frame_size: 0 },
        });
      }
    },
    hubLoadBindiff: async (message) => {
      const { binaryA, binaryB, threshold = 0.60 } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/bindiff.py',
          '--binary-a', binaryA,
          '--binary-b', binaryB,
          '--threshold', String(threshold),
        ], { timeout: 120000 });
        panel.webview.postMessage({ type: 'hubBindiff', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubBindiff',
          result: { ok: false, error: String(e), functions: [], stats: {} },
        });
      }
    },
    hubRunScript: async (message) => {
      const { code, binaryPath } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/repl.py',
          '--code', code,
          '--binary', binaryPath || '',
        ]);
        panel.webview.postMessage({ type: 'hubScriptResult', result: JSON.parse(stdout) });
      } catch (e) {
        const stderr = e.stderr || String(e);
        panel.webview.postMessage({
          type: 'hubScriptResult',
          result: { ok: false, stdout: '', stderr, duration_ms: 0 },
        });
      }
    },
    hubLoadFunctions: async (message) => {
      const { binaryPath } = message;
      try {
        const [symRes, ccRes] = await Promise.all([
          runPython(['backends/static/symbols.py', '--binary', binaryPath, '--all']),
          runPython(['backends/static/calling_convention.py', '--binary', binaryPath]),
        ]);
        const symbols = JSON.parse(symRes.stdout);
        const cc = JSON.parse(ccRes.stdout);
        panel.webview.postMessage({ type: 'hubFunctionsDone', data: { symbols, cc } });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFunctionsDone', data: { error: String(e) } });
      }
    },
    hubLoadPeResources: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/pe_resources.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPeResourcesDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPeResourcesDone', data: { error: String(e), resources: [], count: 0 } });
      }
    },
    hubLoadExceptionHandlers: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/exception_handlers.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubExceptionHandlersDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubExceptionHandlersDone', data: { error: String(e), entries: [], count: 0 } });
      }
    },
    hubLoadTypedData: async (message) => {
      const args = buildTypedDataArgs(message);
      try {
        const { stdout } = await runPython(args);
        panel.webview.postMessage({ type: 'hubTypedDataDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubTypedDataDone', data: { error: String(e), entries: [], sections: [] } });
      }
    },
    hubPreviewTypedStruct: async (message) => {
      const args = buildTypedDataArgs(message);
      try {
        const { stdout } = await runPython(args);
        panel.webview.postMessage({
          type: 'hubTypedStructPreviewDone',
          data: JSON.parse(stdout),
          request: {
            structName: message.structName || '',
            structAddr: message.structAddr || '',
            binaryPath: message.binaryPath || '',
          },
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubTypedStructPreviewDone',
          data: { error: String(e), entries: [], sections: [] },
          request: {
            structName: message.structName || '',
            structAddr: message.structAddr || '',
            binaryPath: message.binaryPath || '',
          },
        });
      }
    },
    hubLoadStructs: async () => {
      try {
        const { stdout } = await runPython(['backends/static/structs.py', 'list']);
        panel.webview.postMessage({ type: 'hubStructsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubStructsDone', data: { error: String(e), structs: [], source: '' } });
      }
    },
    hubSaveStructs: async (message) => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pof-structs-'));
      const sourceFile = path.join(tmpDir, 'structs.c');
      try {
        await fs.promises.writeFile(sourceFile, String(message.sourceText || ''), 'utf8');
        const { stdout } = await runPython(['backends/static/structs.py', 'save', '--source-file', sourceFile]);
        panel.webview.postMessage({ type: 'hubStructsSaved', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubStructsSaved', data: { error: String(e), structs: [], source: '' } });
      } finally {
        fs.rm(tmpDir, { recursive: true, force: true }, () => {});
      }
    },
    hubSaveTypedStructRef: async (message) => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pof-typed-struct-ref-'));
      const structJson = path.join(tmpDir, 'applied-struct.json');
      try {
        await fs.promises.writeFile(structJson, JSON.stringify(message.appliedStruct || {}, null, 2), 'utf8');
        const { stdout } = await runPython([
          'backends/static/typed_struct_refs.py',
          'save',
          '--binary',
          String(message.binaryPath || ''),
          '--struct-json',
          structJson,
        ]);
        panel.webview.postMessage({ type: 'hubTypedStructRefSaved', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubTypedStructRefSaved', data: { error: String(e), entries: [] } });
      } finally {
        fs.rm(tmpDir, { recursive: true, force: true }, () => {});
      }
    },
  };
}

module.exports = staticHandlers;
