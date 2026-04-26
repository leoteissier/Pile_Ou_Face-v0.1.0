/**
 * @file state.js
 * @brief Etat en memoire partage par la webview.
 * @details Stocke trace et curseur UI pour des renderers stateless.
 */
/**
 * @brief Etat global de la webview.
 */
export const state = {
  traceRunId: null,
  snapshots: [],
  risks: [],
  meta: {},
  disasmLines: [],
  disasmFileText: '',
  disasmFileLines: [],
  disasmFilePath: null,
  memoryMap: null,
  debugMemory: false,
  analysis: null,
  analysisByStep: {},
  mcp: {
    model: null,
    analysis: null,
    explanation: null,
    byStep: {}
  },
  lastRequestedAnalysisStep: null,
  currentStep: 1,
  visibleSteps: [],
  showAllTrace: false,
  stackViewMode: 'frame',
  selectedFunction: '',
  selectedStackSlotKey: null,
  lastHighlightedLine: null,
  lastDisasmLine: null,
  simStackMode: false,
  stackWorkspace: null
};
