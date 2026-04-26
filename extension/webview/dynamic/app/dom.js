/**
 * @file dom.js
 * @brief Cache DOM pour la webview Pile ou Face.
 * @details Centralise les elements afin de limiter les queries.
 */
/**
 * @brief References DOM reutilisees par les renderers.
 */
export const dom = {
  status: document.getElementById('status'),
  stack: document.getElementById('stack'),
  registers: document.getElementById('registers'),
  risks: document.getElementById('risks'),
  memoryDump: document.getElementById('memoryDump'),
  explainPanel: document.getElementById('explainPanel'),
  explainBody: document.getElementById('explainBody'),
  explainSubtitle: document.getElementById('explainSubtitle'),
  disasmPanel: document.getElementById('disasmPanel'),
  disasmList: document.getElementById('disasmList'),
  disasmSubtitle: document.getElementById('disasmSubtitle'),
  stepLabel: document.getElementById('stepLabel'),
  stepRange: document.getElementById('stepRange'),
  showAllTrace: document.getElementById('showAllTrace'),
  focusLabel: document.getElementById('focusLabel'),
  btnPrev: document.getElementById('btnPrev'),
  btnNext: document.getElementById('btnNext'),
  legend: document.getElementById('stackLegend'),
  stackSummary: document.getElementById('stackSummary'),
  stackModeFrame: document.getElementById('stackModeFrame'),
  stackModeAdvanced: document.getElementById('stackModeAdvanced'),
  stackWorkspace: document.getElementById('stackWorkspace'),
  stackWorkspaceTitle: document.getElementById('stackWorkspaceTitle'),
  stackWorkspaceSubtitle: document.getElementById('stackWorkspaceSubtitle'),
  stackWorkspaceBack: document.getElementById('stackWorkspaceBack'),
  stackFunctions: document.getElementById('stackFunctions'),
  stackDetail: document.getElementById('stackDetail')
};
