/**
 * @file trace.js
 * @brief Gestion des traces JSON (lecture, écriture, load).
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { getTempDir } = require('./utils');

function resolveOutputJsonPath() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showErrorMessage('Aucun workspace ouvert.');
    return null;
  }
  const root = folders[0].uri.fsPath;
  const tempOutput = path.join(getTempDir(root), 'output.json');
  if (fs.existsSync(tempOutput)) return tempOutput;
  let current = root;
  for (let i = 0; i < 4; i += 1) {
    const candidate = path.join(current, 'output.json');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return tempOutput;
}

function loadTraceFromWorkspace() {
  const jsonPath = resolveOutputJsonPath();
  if (!jsonPath) return { snapshots: [], risks: [], meta: {} };
  if (!fs.existsSync(jsonPath)) {
    vscode.window.showErrorMessage(`output.json introuvable (${jsonPath}).`);
    return { snapshots: [], risks: [], meta: {} };
  }
  try {
    const raw = fs.readFileSync(jsonPath, 'utf8');
    const data = JSON.parse(raw);
    if (Array.isArray(data)) return { snapshots: data, risks: [], meta: {} };
    if (data && Array.isArray(data.snapshots)) {
      const meta = data.meta && typeof data.meta === 'object' ? data.meta : {};
      if (!meta.disasm_path && jsonPath.endsWith('.json')) {
        const candidate = jsonPath.slice(0, -5) + '.disasm.asm';
        if (fs.existsSync(candidate)) meta.disasm_path = candidate;
      }
      return {
        ...data,
        snapshots: data.snapshots,
        risks: Array.isArray(data.risks) ? data.risks : [],
        meta
      };
    }
    vscode.window.showErrorMessage('output.json doit contenir { snapshots, risks }.');
    return { snapshots: [], risks: [], meta: {} };
  } catch (err) {
    vscode.window.showErrorMessage('Erreur lecture output.json.');
    return { snapshots: [], risks: [], meta: {} };
  }
}

function readTraceJson(jsonPath) {
  const raw = fs.readFileSync(jsonPath, 'utf8');
  const data = JSON.parse(raw);
  return Array.isArray(data) ? { snapshots: data, risks: [], meta: {} } : data;
}

function writeTraceJson(jsonPath, trace) {
  fs.writeFileSync(jsonPath, JSON.stringify(trace, null, 2), 'utf8');
}

function setViewMode(trace, mode) {
  if (!trace.meta || typeof trace.meta !== 'object') trace.meta = {};
  trace.meta.view_mode = mode;
  return trace;
}

module.exports = {
  resolveOutputJsonPath,
  loadTraceFromWorkspace,
  readTraceJson,
  writeTraceJson,
  setViewMode
};
