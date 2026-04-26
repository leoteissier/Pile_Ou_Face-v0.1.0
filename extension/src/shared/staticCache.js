/**
 * @file staticCache.js
 * @brief Cache persistant pour l'analyse statique (sections, infos, symboles, strings, CFG).
 * Similaire à Cutter : évite de relancer les outils à chaque ouverture d'onglet.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CACHE_DIR_NAME = 'static_cache';
const META_FILE = 'meta.json';

/**
 * Génère une clé de cache à partir du chemin absolu et des métadonnées du fichier.
 * Invalide automatiquement si le binaire change (mtime, size).
 */
function getCacheKey(absPath) {
  try {
    const stat = fs.statSync(absPath);
    const input = `${absPath}:${stat.mtimeMs}:${stat.size}`;
    return crypto.createHash('sha256').update(input).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

/**
 * Retourne le répertoire de cache pour un workspace.
 */
function getCacheDir(root) {
  return path.join(root, '.pile-ou-face', CACHE_DIR_NAME);
}

/**
 * Lit le fichier meta.json pour vérifier la validité du cache.
 */
function readMeta(cacheDir, key) {
  const metaPath = path.join(cacheDir, key, META_FILE);
  try {
    const raw = fs.readFileSync(metaPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Vérifie si le cache est valide pour le binaire.
 */
function isCacheValid(cacheDir, key, absPath) {
  const meta = readMeta(cacheDir, key);
  if (!meta) return false;
  try {
    const stat = fs.statSync(absPath);
    return meta.mtimeMs === stat.mtimeMs && meta.size === stat.size && meta.path === absPath;
  } catch {
    return false;
  }
}

/**
 * Lit les données en cache. Retourne null si absent ou invalide.
 * @param {string} root - Racine du workspace
 * @param {string} absPath - Chemin absolu du binaire
 * @param {string} type - 'sections' | 'info' | 'symbols' | 'strings' | 'cfg'
 * @param {object} options - Pour strings: { minLen }
 */
function readCache(root, absPath, type, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return null;

  const cacheDir = getCacheDir(root);
  if (!isCacheValid(cacheDir, key, absPath)) return null;

  let file = type;
  if (type === 'strings') {
    const enc = options.encoding || 'utf-8';
    const sec = (options.section || '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'all';
    file = `strings_${options.minLen || 4}_${enc.replace(/[^a-z0-9-]/g, '_')}_${sec}`;
  }
  const cachePath = path.join(cacheDir, key, `${file}.json`);
  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Écrit les données en cache.
 */
function writeCache(root, absPath, type, data, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return;

  const cacheDir = getCacheDir(root);
  const keyDir = path.join(cacheDir, key);
  if (!fs.existsSync(keyDir)) {
    fs.mkdirSync(keyDir, { recursive: true });
  }

  try {
    const stat = fs.statSync(absPath);
    const meta = { path: absPath, mtimeMs: stat.mtimeMs, size: stat.size };
    fs.writeFileSync(path.join(keyDir, META_FILE), JSON.stringify(meta, null, 2), 'utf8');

    let file = type;
    if (type === 'strings') {
      const enc = options.encoding || 'utf-8';
      const sec = (options.section || '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'all';
      file = `strings_${options.minLen || 4}_${enc.replace(/[^a-z0-9-]/g, '_')}_${sec}`;
    }
    fs.writeFileSync(path.join(keyDir, `${file}.json`), JSON.stringify(data), 'utf8');
  } catch (err) {
    // Silently ignore cache write errors
  }
}

module.exports = {
  readCache,
  writeCache,
  getCacheKey,
  getCacheDir,
  readMeta,
};
