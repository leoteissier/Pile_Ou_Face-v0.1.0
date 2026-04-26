/**
 * @file fileManager.js
 * @brief Gestion centralisée des fichiers générés (.pile-ou-face/).
 * Artifacts (disasm, traces), cache statique, purge automatique.
 */

const fs = require('fs');
const path = require('path');
const { getCacheDir, readMeta } = require('./staticCache');

const ARTIFACTS_DIR = '.pile-ou-face';
const CACHE_DIR_NAME = 'static_cache';
const MANIFEST_FILE = 'manifest.json';

/**
 * Retourne le chemin du dossier pile-ou-face.
 */
function getBaseDir(root) {
  return path.resolve(root, ARTIFACTS_DIR);
}

/**
 * Calcule la taille d'un fichier ou répertoire (récursif).
 */
function getSize(p) {
  try {
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      let total = 0;
      for (const name of fs.readdirSync(p)) {
        total += getSize(path.join(p, name));
      }
      return total;
    }
    return stat.size;
  } catch {
    return 0;
  }
}

/**
 * Supprime récursivement un fichier ou dossier.
 */
function removeRecursive(p) {
  if (!fs.existsSync(p)) return;
  const stat = fs.statSync(p);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(p)) {
      removeRecursive(path.join(p, name));
    }
    fs.rmdirSync(p);
  } else {
    fs.unlinkSync(p);
  }
}

/**
 * Liste les artifacts (disasm, symbols, etc.) à la racine de .pile-ou-face/.
 */
function listArtifacts(root) {
  const baseDir = getBaseDir(root);
  const items = [];
  if (!fs.existsSync(baseDir)) return items;
  for (const name of fs.readdirSync(baseDir)) {
    const fullPath = path.join(baseDir, name);
    if (fs.statSync(fullPath).isFile()) {
      const ext = path.extname(name);
      const base = path.basename(name, ext);
      let type = 'artifact';
      if (name.endsWith('.disasm.asm')) type = 'disasm';
      else if (name.endsWith('.disasm.mapping.json')) type = 'mapping';
      else if (name.endsWith('.symbols.json')) type = 'symbols';
      else if (name === 'output.json') type = 'trace';
      else if (name === 'input.asm') type = 'input';
      items.push({
        name,
        path: fullPath,
        type,
        binary: base.replace(/\.(disasm|symbols)$/, ''),
        size: getSize(fullPath),
        mtime: fs.statSync(fullPath).mtimeMs,
      });
    }
  }
  return items.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Liste les entrées du cache statique (static_cache/).
 */
function listCacheEntries(root) {
  const cacheDir = getCacheDir(root);
  const items = [];
  if (!fs.existsSync(cacheDir)) return items;
  for (const key of fs.readdirSync(cacheDir)) {
    const keyDir = path.join(cacheDir, key);
    if (!fs.statSync(keyDir).isDirectory()) continue;
    const meta = readMeta(cacheDir, key);
    const binaryPath = meta?.path || '—';
    const binaryExists = meta?.path && fs.existsSync(meta.path);
    let size = 0;
    for (const f of fs.readdirSync(keyDir)) {
      size += getSize(path.join(keyDir, f));
    }
    items.push({
      key,
      path: keyDir,
      binaryPath,
      binaryExists,
      size,
      mtime: meta ? (fs.statSync(path.join(keyDir, 'meta.json')).mtimeMs || 0) : 0,
    });
  }
  return items.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Récupère le résumé complet des fichiers générés.
 */
function listAll(root) {
  const baseDir = getBaseDir(root);
  const artifacts = listArtifacts(root);
  const cacheEntries = listCacheEntries(root);
  const totalSize = getSize(baseDir);
  const staleCache = cacheEntries.filter((e) => !e.binaryExists);
  return {
    baseDir,
    artifacts,
    cache: cacheEntries,
    staleCache,
    totalSize,
    totalFiles: artifacts.length + cacheEntries.reduce((n, e) => n + 1, 0),
  };
}

/**
 * Nettoie les artifacts (fichiers à la racine de .pile-ou-face/).
 * Ne touche pas au cache.
 */
function cleanupArtifacts(root) {
  const baseDir = getBaseDir(root);
  if (!fs.existsSync(baseDir)) return { removed: 0 };
  let removed = 0;
  for (const name of fs.readdirSync(baseDir)) {
    const fullPath = path.join(baseDir, name);
    if (fs.statSync(fullPath).isFile()) {
      removeRecursive(fullPath);
      removed++;
    }
  }
  return { removed };
}

/**
 * Purge le cache obsolète (binaires qui n'existent plus).
 */
function purgeStaleCache(root) {
  const cacheDir = getCacheDir(root);
  if (!fs.existsSync(cacheDir)) return { removed: 0 };
  let removed = 0;
  for (const key of fs.readdirSync(cacheDir)) {
    const keyDir = path.join(cacheDir, key);
    if (!fs.statSync(keyDir).isDirectory()) continue;
    const meta = readMeta(cacheDir, key);
    if (meta?.path && !fs.existsSync(meta.path)) {
      removeRecursive(keyDir);
      removed++;
    }
  }
  return { removed };
}

/**
 * Nettoie tout : artifacts + cache.
 */
function cleanupAll(root, options = {}) {
  const { artifactsOnly = false, cacheOnly = false, purgeStale = false } = options;
  let removedArtifacts = 0;
  let removedCache = 0;
  let purgedStale = 0;
  const baseDir = getBaseDir(root);
  const cacheDir = getCacheDir(root);
  if (!cacheOnly && fs.existsSync(baseDir)) {
    for (const name of fs.readdirSync(baseDir)) {
      const fullPath = path.join(baseDir, name);
      if (name === CACHE_DIR_NAME) continue;
      if (fs.statSync(fullPath).isFile()) {
        removeRecursive(fullPath);
        removedArtifacts++;
      }
    }
  }
  if (!artifactsOnly && fs.existsSync(cacheDir)) {
    if (purgeStale) {
      for (const key of fs.readdirSync(cacheDir)) {
        const keyDir = path.join(cacheDir, key);
        if (!fs.statSync(keyDir).isDirectory()) continue;
        const meta = readMeta(cacheDir, key);
        if (meta?.path && !fs.existsSync(meta.path)) {
          removeRecursive(keyDir);
          purgedStale++;
        }
      }
    } else {
      for (const name of fs.readdirSync(cacheDir)) {
        removeRecursive(path.join(cacheDir, name));
        removedCache++;
      }
    }
  }
  return { removedArtifacts, removedCache, purgedStale };
}

/**
 * Formatte une taille en octets en format lisible.
 */
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

module.exports = {
  getBaseDir,
  getSize,
  formatSize,
  listArtifacts,
  listCacheEntries,
  listAll,
  cleanupArtifacts,
  purgeStaleCache,
  cleanupAll,
  removeRecursive,
};
