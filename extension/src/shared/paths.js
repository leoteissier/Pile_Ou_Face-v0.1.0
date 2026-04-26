/**
 * @file paths.js
 * @brief Chemins centralisés vers les scripts Python du projet.
 * @details Unifie les chemins pour éviter la duplication et faciliter la maintenance.
 * Voir docs/ARCHITECTURE_AUDIT_PLAN.md.
 */

const path = require('path');

/**
 * @brief Retourne le chemin absolu vers un script Python dans backends/static/.
 */
function backendStatic(root, script) {
  return path.join(root, 'backends', 'static', script);
}

/**
 * @brief Retourne le chemin absolu vers un script Python dans backends/dynamic/.
 */
function backendDynamic(root, ...segments) {
  return path.join(root, 'backends', 'dynamic', ...segments);
}

/** backends/static/disasm.py — Désassemblage (objdump) */
function getDisasmScript(root) {
  return backendStatic(root, 'disasm.py');
}

/** backends/static/symbols.py — Extraction symboles (nm) */
function getSymbolsScript(root) {
  return backendStatic(root, 'symbols.py');
}

/** backends/static/strings.py — Extraction strings */
function getStringsScript(root) {
  return backendStatic(root, 'strings.py');
}

/** backends/static/sections.py — Sections ELF/Mach-O */
function getSectionsScript(root) {
  return backendStatic(root, 'sections.py');
}

/** backends/static/headers.py — Headers binaire */
function getHeadersScript(root) {
  return backendStatic(root, 'headers.py');
}

/** backends/static/cfg.py — Control Flow Graph */
function getCfgScript(root) {
  return backendStatic(root, 'cfg.py');
}

/** backends/static/call_graph.py — Graphe d'appels */
function getCallGraphScript(root) {
  return backendStatic(root, 'call_graph.py');
}

/** backends/static/discover_functions.py — Découverte de fonctions */
function getDiscoverFunctionsScript(root) {
  return backendStatic(root, 'discover_functions.py');
}

/** backends/static/search.py — Recherche binaire */
function getSearchScript(root) {
  return backendStatic(root, 'search.py');
}

/** backends/static/offset_to_vaddr.py — Conversion offset fichier → adresse virtuelle */
function getOffsetToVaddrScript(root) {
  return backendStatic(root, 'offset_to_vaddr.py');
}

/** backends/static/xrefs.py — Cross-références */
function getXrefsScript(root) {
  return backendStatic(root, 'xrefs.py');
}

/** backends/static/yara_scan.py — Scan YARA */
function getYaraScanScript(root) {
  return backendStatic(root, 'yara_scan.py');
}

/** backends/static/capa_scan.py — Capa capabilities */
function getCapaScanScript(root) {
  return backendStatic(root, 'capa_scan.py');
}

/** backends/static/rules_manager.py — Gestionnaire de règles YARA/CAPA */
function getRulesManagerScript(root) {
  return backendStatic(root, 'rules_manager.py');
}

/** backends/static/asm_sim.py — Simulation asm statique */
function getAsmStaticScript(root) {
  return backendStatic(root, 'asm_sim.py');
}

/** backends/dynamic/pipeline/run_pipeline.py — Pipeline dynamique */
function getRunPipelineScript(root) {
  return backendDynamic(root, 'pipeline', 'run_pipeline.py');
}

/** Chemins de fallback pour exemples (examples/foo.elf, foo.elf, etc.) */
function getExampleCandidates(root, baseName) {
  return [
    path.join(root, 'examples', baseName + '.elf'),
    path.join(root, baseName + '.elf'),
    path.join(root, 'examples', baseName),
    path.join(root, baseName),
  ];
}

module.exports = {
  getDisasmScript,
  getSymbolsScript,
  getStringsScript,
  getSectionsScript,
  getHeadersScript,
  getCfgScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
  getSearchScript,
  getOffsetToVaddrScript,
  getXrefsScript,
  getYaraScanScript,
  getCapaScanScript,
  getRulesManagerScript,
  getAsmStaticScript,
  getRunPipelineScript,
  getExampleCandidates,
};
