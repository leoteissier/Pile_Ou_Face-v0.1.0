/**
 * @file hub.js
 * @brief Contrôleur du hub Pile ou Face — UI alignée MOSCOW.
 */
const vscode = acquireVsCodeApi();
const STORAGE_KEY = 'pile-ou-face-hub';
let loadAllPending = 0;
let stringsCache = [];
// Cache des onglets : évite de recharger à chaque clic si les données sont déjà chargées
let tabDataCache = {};  // tabId -> { binaryPath }
let hexCurrentOffset = 0;
let hexCurrentLength = 512;
let hexSections = [];           // [{name, offset, virtual_address, size, type}] — pour sync disasm↔hex
let hexPendingScrollVaddr = null; // { addr, endAddr, activeAddr, anchorAddr, spanLength } après prochain render hex
let hexRenderSessionId = 0;
let hexRenderInProgress = false;
let hexDomState = {
  rowByOffset: new Map(),
  rowDataByOffset: new Map(),
  byteElsByAddr: new Map(),
  asciiElsByAddr: new Map(),
};
let hexActiveUiState = {
  selectedRowEls: [],
  activeRowEl: null,
  selectedByteEls: [],
  selectedAsciiEls: [],
  activeByteEls: [],
  activeAsciiEls: [],
  startAddr: '',
  endAddr: '',
  addr: '',
  anchorAddr: '',
  spanLength: 1,
};
let hexSelectionModel = {
  startAddr: '',
  endAddr: '',
  activeAddr: '',
  anchorAddr: '',
  spanLength: 1,
};
let hexUiState = {
  compact: _loadStorage().hexCompact !== false,
};
let hexPatchHistory = [];
let hexPatchRedoHistory = [];
let stackFrameCache = {};
const pendingStackFrameRequests = new Set();
let cfgUiState = {
  binaryPath: '',
  viewMode: _loadStorage().cfgViewMode || 'graph',
  search: _loadStorage().cfgSearch || '',
  expandedAddrs: [],
  graphView: null,
  activeAddr: '',
};
let callGraphUiState = {
  binaryPath: '',
  viewMode: _loadStorage().cgViewMode || 'graph',
  search: _loadStorage().cgSearch || '',
  graphView: null,
  activeAddr: '',
};
let decompileUiState = {
  selectedAddr: _loadStorage().decompileAddr || '',
  selectionMode: _loadStorage().decompileSelectionMode || 'context',
  renderedAddr: '',
  renderedBinaryPath: '',
  renderedDecompiler: _loadStorage().decompiler || '',
  renderedProvider: 'auto',
  renderedQuality: _normalizeDecompileQuality(_loadStorage().decompileQuality || 'normal'),
  quality: _normalizeDecompileQuality(_loadStorage().decompileQuality || 'normal'),
  activeStackEntryName: '',
  pendingStackEntryName: '',
  searchQuery: _loadStorage().decompileSearch || '',
  activeSearchHit: -1,
};
let decompileHistoryState = {
  entries: [],
  index: -1,
};
let decompilePeekState = {
  el: null,
  target: null,
};
let decompileHighlightFrame = 0;
let decompileRenderToken = 0;
let decompileSearchDebounce = 0;
let decompileHighlightCache = {
  key: '',
  code: '',
  html: '',
};
const MAX_DECOMPILE_RESULT_CACHE = 12;
let decompileResultCache = new Map();
const pendingDecompileRequests = new Set();
let stackUiState = {
  renderedAddr: '',
  renderedBinaryPath: '',
  activeEntryName: '',
  pendingEntryName: '',
};
let typedDataUiState = {
  structSource: '',
  structs: [],
  structsLoaded: false,
  loadingStructs: false,
  pendingEditorOpen: false,
  appliedStructName: '',
  appliedStructOffset: '0x0',
  appliedStructAddr: '',
  hexStructName: '',
  hexStructPreview: null,
};
let funcSimilarityUiState = {
  db: null,
  results: null,
  pendingText: '',
};
const OLLAMA_CHAT_MAX_MESSAGES = 40;
const OLLAMA_CHAT_CONTEXT_MESSAGES = 12;
const OLLAMA_CHAT_CONTEXT_MAX_CHARS = 1800;
const OLLAMA_HISTORY_MAX_THREADS = 24;

function _normalizeOllamaConversationMessages(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      const role = String(entry?.role || '').trim().toLowerCase();
      const content = String(entry?.content || '').trim();
      if (!content) return null;
      if (!['user', 'assistant', 'system'].includes(role)) return null;
      return {
        role,
        content,
        ts: Number(entry?.ts || Date.now()),
      };
    })
    .filter(Boolean)
    .slice(-OLLAMA_CHAT_MAX_MESSAGES);
}

function _loadStoredOllamaConversation() {
  return _normalizeOllamaConversationMessages(_loadStorage().ollamaConversation);
}

let ollamaUiState = {
  models: [],
  lastModel: _loadStorage().ollamaModel || '',
  busy: false,
  conversation: _loadStoredOllamaConversation(),
  history: [],
  activeConversationId: '',
};
let currentBinaryMeta = null;
let pendingStaticQuickAction = '';
let detectionUiState = {
  capaCapabilities: [],
  capaError: '',
  yaraMatches: [],
  yaraError: '',
};
const MAX_RECENT_BINARIES = 8;
window.discoveredFunctionsCache = window.discoveredFunctionsCache || [];
window.functionListCache = window.functionListCache || [];

const GROUPS = {
  code:     ['disasm','cfg','callgraph','discovered','decompile','hex','stack','bindiff'],
  data:     ['strings','symbols','sections','imports','info','recherche','pe_resources','exceptions','typed_data'],
  malware:  ['behavior','taint','anti_analysis','detection'],
  offensif: ['rop','vulns','flirt','deobfuscate','script'],
};
const GROUP_LABELS = {
  disasm: 'Désassemblage', cfg: 'CFG', callgraph: 'Call Graph',
  discovered: 'Fonctions', decompile: 'Décompilateur', hex: 'Hex View',
  strings: 'Strings', symbols: 'Symboles', sections: 'Sections',
  imports: 'Imports', info: 'Infos binaire', recherche: 'Recherche',
  behavior: 'Comportement', taint: 'Taint',
  anti_analysis: 'Anti-analyse', detection: 'Détection',
  rop: 'ROP Gadgets', vulns: 'Vulnérabilités',
  flirt: 'FLIRT', deobfuscate: 'Déobfuscation', script: 'Script',
  bindiff: 'Diff',
  stack: 'Stack Frame',
  pe_resources: 'Ressources PE', exceptions: 'Exceptions', typed_data: 'Données typées',
};
const STATIC_FEATURE_IDS = Object.values(GROUPS).flat();
const STATIC_SIMPLE_FEATURES = new Set([
  'disasm',
  'cfg',
  'discovered',
  'decompile',
  'strings',
  'symbols',
  'sections',
  'info',
]);
const STATIC_FLOW_HINTS = {
  disasm: 'Commence ici pour lire le point d entree, sauter vers main et annoter les adresses utiles.',
  cfg: 'Passe ensuite sur le CFG pour comprendre les branches, les blocs et les sorties rapides.',
  callgraph: 'Utilise le call graph pour reperer les noeuds centraux avant de zoomer dans les fonctions.',
  discovered: 'Trie les fonctions, choisis une cible interessante puis pivote vers pseudo-C, CFG ou hex.',
  decompile: 'Valide la logique haut niveau ici, puis compare avec le desassemblage si un bloc semble flou.',
  hex: 'Garde cette vue pour verifier offsets, bytes et patches quand une adresse devient concrete.',
  stack: 'Appuie-toi sur la stack frame apres avoir isole une fonction qui merite une lecture precise.',
  bindiff: 'Compare ici une fois la cible comprise pour voir rapidement ce qui diverge entre deux builds.',
  strings: 'Scanne les chaines parlantes en premier, puis remonte vers imports, fonctions ou pseudo-C.',
  symbols: 'Les symboles donnent souvent les meilleurs points d entree avant une lecture plus profonde.',
  sections: 'Regarde les sections pour comprendre la structure du binaire avant d entrer dans le code.',
  imports: 'Observe d abord les API reseau, process et memoire, puis confirme les hypotheses dans le code.',
  info: 'Verifie format, architecture et protections avant de choisir la bonne strategie d exploration.',
  recherche: 'Recherche un motif, puis ouvre le resultat dans la vue technique la plus utile.',
  pe_resources: 'Commence ici pour les artefacts PE embarques, puis pivote vers strings ou hex si besoin.',
  exceptions: 'Les handlers d exceptions aident a comprendre le controle de flux sur des binaires plus tordus.',
  typed_data: 'Cette vue sert bien apres le premier tri quand tu veux donner du sens aux donnees.',
  behavior: 'Pratique pour une vue tactique rapide avant de redescendre vers les fonctions critiques.',
  taint: 'Utilise la taint apres avoir identifie sources et sinks interessants dans le code.',
  anti_analysis: 'Passe ici une fois les premiers indices trouves pour confirmer les techniques de defense.',
  detection: 'Lance cette analyse apres le tri manuel pour confirmer ou infirmer tes hypotheses.',
  rop: 'Va ici quand le binaire est compris et que tu cherches des primitives exploitables.',
  vulns: 'Cette vue vient bien apres l exploration initiale pour concentrer l audit sur les points fragiles.',
  flirt: 'Les signatures FLIRT sont utiles pour separer le bruit des parties vraiment interessantes.',
  deobfuscate: 'Utilise la deobfuscation apres avoir repere des strings ou appels qui semblent caches.',
  script: 'Le panneau script est ideal quand tu veux industrialiser une etape repetable de ton analyse.',
  default: 'Ouvre le desassemblage, identifie les zones interessantes, puis pivote vers graphes, data ou offensif.',
};
const STATIC_QUICK_ACTIONS = {
  disasm: { group: 'code', tab: 'disasm' },
  functions: { group: 'code', tab: 'discovered' },
  strings: { group: 'data', tab: 'strings' },
  hex: { group: 'code', tab: 'hex' },
};
const ACTIVE_CONTEXT_INJECTED_PANELS = [
  'staticStrings',
  'staticSections',
  'staticRecherche',
  'staticInfo',
  'staticPeResources',
  'staticExceptions',
  'staticTypedData',
  'staticBehavior',
  'staticTaint',
  'staticAntiAnalysis',
  'staticDetection',
  'staticRop',
  'staticVulns',
  'staticFlirt',
  'staticDeobfuscate',
];
const RAW_UNSUPPORTED_TABS = {
  decompile: ['decompileContent'],
  stack: ['stackContent'],
  symbols: ['symbolsContent'],
  imports: ['importsContent', 'exportsContent'],
  behavior: ['behaviorContent'],
  taint: ['taintContent'],
  anti_analysis: ['antiAnalysisContent'],
  detection: ['capaContent'],
  vulns: ['vulnsContent'],
  flirt: ['flirtContent'],
  pe_resources: ['peResourcesContent'],
  exceptions: ['exceptionsContent'],
  typed_data: ['typedDataContent'],
};

// Panels
const panels = document.querySelectorAll('.panel');
const iconNavItems = document.querySelectorAll('.icon-nav-item');
const form = document.getElementById('traceForm');
const runBtn = document.getElementById('runBtn');
const binaryPathInput = form?.querySelector('input[name="binaryPath"]');
const dynamicTraceStatus = document.getElementById('dynamicTraceStatus');
const dynamicArchBits = document.getElementById('dynamicArchBits');
const dynamicPie = document.getElementById('dynamicPie');
const dynamicSourcePathInput = document.getElementById('dynamicSourcePath');
const dynamicSourceHint = document.getElementById('dynamicSourceHint');
const argvPayloadInput = document.getElementById('argvPayload');
const argvPayloadHint = document.getElementById('argvPayloadHint');
const dynamicPayloadTargetMode = document.getElementById('dynamicPayloadTargetMode');
const dynamicTraceHistory = document.getElementById('dynamicTraceHistory');
const btnRefreshDynamicTraceHistory = document.getElementById('btnRefreshDynamicTraceHistory');
const btnClearDynamicTraceHistory = document.getElementById('btnClearDynamicTraceHistory');
let currentPlatform = 'linux';
const exploitNotesWidget = document.getElementById('exploitNotesWidget');
const exploitNotesFab = document.getElementById('exploitNotesFab');
const exploitNotesInput = document.getElementById('exploitNotes');
const EXPLOIT_NOTES_UI_KEY = 'pile-ou-face-exploit-notes-ui';
const EXPLOIT_NOTES_TEXT_KEY = 'pile-ou-face-exploit-notes-text';
const OLLAMA_CHAT_WIDGET_KEY = 'pile-ou-face-ollama-chat-widget';
let dynamicTraceInitState = {
  archBits: 64,
  pie: false,
  sourcePath: '',
  sourceEnrichmentEnabled: false,
  sourceEnrichmentStatus: '',
  sourceEnrichmentMessage: '',
  payloadTargetMode: 'auto',
  payloadTargetAuto: 'argv1',
  payloadTargetEffective: 'argv1',
  payloadTargetReason: 'Auto: aucune source claire, fallback sur argv[1]',
  profile: {
    bufferOffset: '',
    bufferSize: '',
    maxSteps: 800,
    startSymbol: 'main',
    stopSymbol: ''
  }
};
let dynamicTraceHistoryState = {
  items: [],
  activeTracePath: ''
};

// localStorage helpers
function _loadStorage() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch(_) { return {}; }
}
function _saveStorage(updates) {
  try {
    const prev = _loadStorage();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...prev, ...updates }));
  } catch(_) {}
}

function _normalizeRawProfile(profile) {
  if (!profile || typeof profile !== 'object') return null;
  const arch = String(profile.arch || '').trim();
  const baseAddr = String(profile.baseAddr || '0x0').trim();
  const requestedEndian = String(profile.endian || 'little').trim().toLowerCase();
  const endian = arch.startsWith('i386') ? 'little' : (requestedEndian === 'big' ? 'big' : 'little');
  if (!arch || !baseAddr) return null;
  return { arch, baseAddr, endian };
}

function _normalizeBinaryMeta(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const kind = meta.kind === 'raw' ? 'raw' : 'native';
  const normalized = {
    kind,
    format: String(meta.format || (kind === 'raw' ? 'RAW' : '')).trim(),
    arch: String(meta.arch || '').trim(),
  };
  if (kind === 'raw') {
    normalized.rawConfig = _normalizeRawProfile(meta.rawConfig || meta);
    if (!normalized.rawConfig) return null;
    normalized.arch = normalized.arch || normalized.rawConfig.arch;
    normalized.format = 'RAW';
  }
  return normalized;
}

function getCurrentBinaryMeta() {
  if (currentBinaryMeta) return currentBinaryMeta;
  currentBinaryMeta = _normalizeBinaryMeta(_loadStorage().binaryMeta || null);
  return currentBinaryMeta;
}

function getRecentBinaries() {
  const recent = _loadStorage().recentBinaries;
  return Array.isArray(recent) ? recent : [];
}

function rememberRecentBinary(binaryPath, binaryMeta) {
  if (!binaryPath) return getRecentBinaries();
  const normalizedMeta = _normalizeBinaryMeta(binaryMeta);
  const nextEntry = {
    path: binaryPath,
    meta: normalizedMeta,
    ts: Date.now(),
  };
  const recent = getRecentBinaries()
    .filter((entry) => entry && entry.path && entry.path !== binaryPath)
    .slice(0, MAX_RECENT_BINARIES - 1);
  return [nextEntry, ...recent];
}

function _binaryStatusText(meta) {
  if (!meta) return '';
  const parts = [];
  if (meta.format) parts.push(meta.format);
  if (meta.arch) parts.push(meta.arch);
  if (meta.kind === 'raw' && meta.rawConfig?.endian) parts.push(meta.rawConfig.endian);
  if (meta.kind === 'raw' && meta.rawConfig?.baseAddr) parts.push(meta.rawConfig.baseAddr);
  return parts.join(' • ');
}

function updateTopBarBinaryDisplay(binaryPath = '', binaryMeta = null, info = null) {
  const topName = document.getElementById('topBarBinaryName');
  const chipFormat = document.getElementById('topBarChipFormat');
  const chipArch = document.getElementById('topBarChipArch');
  if (topName) {
    topName.textContent = binaryPath ? (binaryPath.split('/').pop() || binaryPath) : 'Choisir un fichier…';
    topName.classList.toggle('empty', !binaryPath);
  }
  const formatValue = (info && info.format) || binaryMeta?.format || '';
  const archValue = (info && info.arch) || binaryMeta?.arch || '';
  if (chipFormat) {
    chipFormat.textContent = formatValue;
    chipFormat.style.display = formatValue ? '' : 'none';
  }
  if (chipArch) {
    chipArch.textContent = archValue;
    chipArch.style.display = archValue ? '' : 'none';
  }
}

function saveBinarySelection(binaryPath, binaryMeta) {
  const normalizedMeta = _normalizeBinaryMeta(binaryMeta);
  currentBinaryMeta = normalizedMeta;
  _saveStorage({
    staticBinaryPath: binaryPath,
    binaryMeta: normalizedMeta,
    recentBinaries: binaryPath ? rememberRecentBinary(binaryPath, normalizedMeta) : getRecentBinaries(),
  });
  updateTopBarBinaryDisplay(binaryPath, normalizedMeta);
  renderRecentBinaries();
}

function isStaticTabAvailable(tabId, binaryMeta = getCurrentBinaryMeta()) {
  if (!isStaticFeatureEnabled(tabId)) return false;
  if (tabId === 'pe_resources') {
    const format = String(binaryMeta?.format || '').trim().toUpperCase();
    if (!format) return true;
    return format === 'PE';
  }
  return true;
}

function getStaticInterfaceMode() {
  return _settingsCache?.interfaceMode === 'simple' ? 'simple' : 'advanced';
}

function getAdvancedStaticFeatureSet() {
  const raw = Array.isArray(_settingsCache?.enabledStaticFeatures)
    ? _settingsCache.enabledStaticFeatures
    : [];
  const valid = raw.filter((tabId) => STATIC_FEATURE_IDS.includes(tabId));
  return new Set(valid.length ? valid : STATIC_FEATURE_IDS);
}

function isStaticFeatureEnabled(tabId) {
  if (getStaticInterfaceMode() === 'simple') return STATIC_SIMPLE_FEATURES.has(tabId);
  return getAdvancedStaticFeatureSet().has(tabId);
}

function getAvailableGroupTabs(groupId, binaryMeta = getCurrentBinaryMeta()) {
  const baseTabs = GROUPS[groupId] || GROUPS.code || [];
  return baseTabs.filter((tabId) => isStaticTabAvailable(tabId, binaryMeta));
}

function getFirstAvailableStaticGroup() {
  return Object.keys(GROUPS).find((groupId) => getAvailableGroupTabs(groupId).length > 0) || 'code';
}

function clearRecentBinaries() {
  _saveStorage({ recentBinaries: [] });
  renderRecentBinaries();
}

function removeRecentBinary(binaryPath) {
  const target = String(binaryPath || '').trim();
  if (!target) return;
  const nextRecent = getRecentBinaries().filter((entry) => entry?.path !== target);
  _saveStorage({ recentBinaries: nextRecent });
  renderRecentBinaries();
}

function renderRecentBinaries() {
  const container = document.getElementById('topBarRecentList');
  if (!container) return;
  const recent = getRecentBinaries();
  const activePath = getStaticBinaryPath();
  container.replaceChildren();
  if (!recent.length) {
    const empty = document.createElement('div');
    empty.className = 'top-bar-recent-empty';
    empty.textContent = 'Aucun fichier récent pour le moment.';
    container.appendChild(empty);
    return;
  }
  recent.forEach((entry) => {
    if (!entry?.path) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'top-bar-menu-item';
    if (entry.path === activePath) btn.classList.add('is-active');
    btn.title = entry.path;

    const metaWrap = document.createElement('div');
    metaWrap.className = 'top-bar-recent-meta';
    const copy = document.createElement('div');
    copy.className = 'top-bar-recent-copy';
    const name = document.createElement('span');
    name.className = 'top-bar-recent-name';
    name.textContent = entry.path.split('/').pop() || entry.path;
    const fullPath = document.createElement('span');
    fullPath.className = 'top-bar-recent-path';
    fullPath.textContent = entry.path;
    copy.append(name, fullPath);
    metaWrap.appendChild(copy);

    const status = document.createElement('span');
    status.className = 'top-bar-recent-status';
    status.textContent = _binaryStatusText(_normalizeBinaryMeta(entry.meta || null));

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'top-bar-recent-remove';
    removeBtn.title = `Retirer ${entry.path.split('/').pop() || entry.path} des récents`;
    removeBtn.setAttribute('aria-label', removeBtn.title);
    removeBtn.textContent = '×';
    removeBtn.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      removeRecentBinary(entry.path);
    });

    const trailing = document.createElement('div');
    trailing.className = 'top-bar-recent-actions';
    trailing.append(status, removeBtn);

    btn.append(metaWrap, trailing);
    btn.addEventListener('click', () => {
      closeBinaryMenu();
      showPanel('static');
      vscode.postMessage({
        type: 'hubUseBinaryPath',
        binaryPath: entry.path,
        binaryMeta: _normalizeBinaryMeta(entry.meta || null),
      });
    });
    container.appendChild(btn);
  });
}

function openBinaryMenu() {
  const menu = document.getElementById('topBarBinaryMenu');
  const button = document.getElementById('topBarBinaryButton');
  if (!menu || !button) return;
  renderRecentBinaries();
  menu.hidden = false;
  button.classList.add('is-open');
}

function closeBinaryMenu() {
  const menu = document.getElementById('topBarBinaryMenu');
  const button = document.getElementById('topBarBinaryButton');
  if (!menu || !button) return;
  menu.hidden = true;
  button.classList.remove('is-open');
}

function toggleBinaryMenu() {
  const menu = document.getElementById('topBarBinaryMenu');
  if (!menu) return;
  if (menu.hidden) openBinaryMenu();
  else closeBinaryMenu();
}

// Restore last panel or use initial from body
function initPanel() {
  const saved = _loadStorage();
  const initial = document.body.dataset.initialPanel || 'dashboard';
  const panelId = (saved.panel && document.getElementById(`panel-${saved.panel}`)) ? saved.panel : initial;
  currentBinaryMeta = _normalizeBinaryMeta(saved.binaryMeta || null);
  // Restore static binary path
  if (saved.staticBinaryPath && staticBinaryInput) {
    staticBinaryInput.value = saved.staticBinaryPath;
    if (binaryPathInput && !binaryPathInput.value?.trim()) binaryPathInput.value = saved.staticBinaryPath;
  }
  updateTopBarBinaryDisplay(saved.staticBinaryPath || '', currentBinaryMeta);
  renderRecentBinaries();
  showPanel(panelId);
  updateActiveContextBars(window._lastDisasmAddr);
  vscode.postMessage({ type: 'hubGetSettings' });
}

function showPanel(id) {
  closeBinaryMenu();
  panels.forEach((p) => p.classList.remove('active'));
  iconNavItems.forEach((n) => n.classList.remove('active'));
  const panel = document.getElementById(`panel-${id}`);
  const nav = document.querySelector(`[data-panel="${id}"]`);
  if (panel) panel.classList.add('active');
  if (nav) nav.classList.add('active');
  syncOllamaFloatingWidgetVisibility(id);
  // Top bar mode badge
  const modeEl = document.getElementById('topBarMode');
  if (modeEl) {
    modeEl.className = 'top-bar-mode';
    if (id === 'static')       { modeEl.textContent = 'STATIC';  modeEl.classList.add('static'); }
    else if (id === 'dynamic') { modeEl.textContent = 'DYNAMIC'; modeEl.classList.add('dynamic'); }
    else                       { modeEl.textContent = id.toUpperCase(); modeEl.classList.add('other'); }
  }
  if (id === 'outils') {
    syncToolsBinaryLabel();
    const saved = _loadStorage();
    showOutilsTab(saved.outilsTab || 'outils');
  }
  if (id === 'dashboard') {
    if (!ollamaUiState.models.length) requestOllamaModels();
  }
  if (id === 'static') {
    const bp = getStaticBinaryPath();
    if (bp) {
      postBinaryAwareMessage('hubLoadAnnotations', { binaryPath: bp });
    }
    const saved = _loadStorage();
    showGroup(saved.group || 'code', saved.tab || null);
    syncStaticWorkspaceSummary();
  }
  if (id === 'dynamic') {
    requestRunTraceInit();
  }
  if (id === 'options') {
    vscode.postMessage({ type: 'hubGetSettings' });
  }
  syncStaticBinary();
  vscode.postMessage({ type: 'hubModeChange', mode: id === 'static' ? 'static' : id === 'dynamic' ? 'dynamic' : 'other' });
  _saveStorage({ panel: id });
}

// Icon nav click handlers
iconNavItems.forEach((item) => {
  item.addEventListener('click', () => showPanel(item.dataset.panel));
});

document.getElementById('topBarBinaryButton')?.addEventListener('click', (event) => {
  event.stopPropagation();
  toggleBinaryMenu();
});
document.getElementById('btnTopBarSelectBinary')?.addEventListener('click', () => {
  closeBinaryMenu();
  pendingStaticQuickAction = '';
  vscode.postMessage({ type: 'requestBinarySelection' });
});
document.getElementById('btnClearRecentBinaries')?.addEventListener('click', (event) => {
  event.stopPropagation();
  clearRecentBinaries();
});
document.addEventListener('click', (event) => {
  const menu = document.getElementById('topBarBinaryMenu');
  const button = document.getElementById('topBarBinaryButton');
  if (!menu || menu.hidden) return;
  if (menu.contains(event.target) || button?.contains(event.target)) return;
  closeBinaryMenu();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeBinaryMenu();
});

// Group + sub-tab navigation
function showGroup(groupId, tabId) {
  if (!GROUPS[groupId]) groupId = 'code';
  if (getAvailableGroupTabs(groupId).length === 0) groupId = getFirstAvailableStaticGroup();
  const availableTabs = getAvailableGroupTabs(groupId);
  document.querySelectorAll('.group-tab').forEach((btn) => {
    const hasTabs = getAvailableGroupTabs(btn.dataset.group).length > 0;
    btn.hidden = !hasTabs;
    btn.disabled = !hasTabs;
    btn.style.display = hasTabs ? '' : 'none';
    btn.classList.toggle('active', hasTabs && btn.dataset.group === groupId);
  });
  const bar = document.getElementById('subTabsBar');
  if (!bar) return;
  bar.replaceChildren();
  if (!availableTabs.length) return;
  availableTabs.forEach((tid) => {
    const btn = document.createElement('button');
    btn.className = 'sub-tab';
    btn.dataset.subTab = tid;
    btn.textContent = GROUP_LABELS[tid] || tid;
    btn.addEventListener('click', () => showSubTab(groupId, tid));
    bar.appendChild(btn);
  });
  const targetTab = (tabId && availableTabs.includes(tabId)) ? tabId : availableTabs[0];
  showSubTab(groupId, targetTab);
  _saveStorage({ group: groupId });
}

function showSubTab(groupId, tabId) {
  if (!isStaticTabAvailable(tabId)) {
    const fallbackGroup = getFirstAvailableStaticGroup();
    const fallbackTab = getAvailableGroupTabs(fallbackGroup)[0];
    if (fallbackTab && fallbackTab !== tabId) {
      showGroup(fallbackGroup, fallbackTab);
    }
    return;
  }
  document.querySelectorAll('.sub-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.subTab === tabId);
  });
  document.querySelectorAll('#panel-static .static-panel').forEach((p) => p.classList.remove('active'));
  // Convert snake_case tabId to PascalCase panel ID
  const panelId = 'static' + tabId.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');
  const panel = document.getElementById(panelId);
  if (panel) panel.classList.add('active');
  _autoLoadTab(tabId);
  requestAnimationFrame(() => requestGraphFit(panel || document));
  if (tabId === 'cfg' && window._lastDisasmAddr) {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        syncCfgActiveAddress(window._lastDisasmAddr, {
          reveal: true,
          revealTable: document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      });
    });
  }
  if (tabId === 'callgraph' && window._lastDisasmAddr) {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        syncCallGraphActiveAddress(window._lastDisasmAddr, {
          reveal: true,
          revealTable: document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      });
    });
  }
  if (tabId === 'decompile') {
    requestAnimationFrame(() => {
      const selectedAddr = syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
      const currentBinaryPath = getStaticBinaryPath() || '';
      const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
      const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
      const currentProvider = _getConfiguredDecompilerProvider();
      const shouldRefresh = decompileUiState.renderedBinaryPath !== currentBinaryPath
        || decompileUiState.renderedDecompiler !== currentDecompiler
        || decompileUiState.renderedProvider !== currentProvider
        || decompileUiState.renderedQuality !== currentQuality
        || (decompileUiState.renderedAddr || '') !== (selectedAddr || '');
      if (shouldRefresh && currentBinaryPath) requestDecompileForCurrentSelection();
    });
  }
  updateActiveContextBars(window._lastDisasmAddr);
  syncStaticWorkspaceSummary(tabId);
  _saveStorage({ group: groupId, tab: tabId });
}

document.querySelectorAll('.group-tab').forEach((btn) => {
  btn.addEventListener('click', () => showGroup(btn.dataset.group));
});

document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-context-jump]');
  if (!btn || btn.disabled) return;
  event.preventDefault();
  jumpToContextTab(btn.dataset.contextJump || '');
});

// ── Outils sub-tabs ──────────────────────────────────────────────────────────
function showOutilsTab(tabId) {
  document.querySelectorAll('.outils-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.outils-panel').forEach((p) => p.classList.remove('active'));
  const panelId = 'outilsPanel' + tabId.charAt(0).toUpperCase() + tabId.slice(1);
  document.getElementById(panelId)?.classList.add('active');
  if (tabId === 'fichiers') vscode.postMessage({ type: 'listGeneratedFiles' });
  _saveStorage({ outilsTab: tabId });
}

document.querySelectorAll('.outils-tab').forEach((btn) => {
  btn.addEventListener('click', () => showOutilsTab(btn.dataset.tab));
});

function setOllamaBusy(busy) {
  ollamaUiState.busy = !!busy;
  const runBtn = document.getElementById('btnOllamaRunPrompt');
  const refreshBtn = document.getElementById('btnOllamaRefreshModels');
  const resetBtn = document.getElementById('btnOllamaNewChat');
  const clearHistoryBtn = document.getElementById('btnOllamaClearHistory');
  const quickRunBtn = document.getElementById('btnOllamaQuickSend');
  const quickRefreshBtn = document.getElementById('btnOllamaQuickRefresh');
  const quickNewBtn = document.getElementById('btnOllamaQuickNewChat');
  if (runBtn) {
    runBtn.disabled = ollamaUiState.busy;
    runBtn.classList.toggle('loading', ollamaUiState.busy);
  }
  if (refreshBtn) refreshBtn.disabled = ollamaUiState.busy;
  if (resetBtn) resetBtn.disabled = ollamaUiState.busy;
  if (clearHistoryBtn) clearHistoryBtn.disabled = ollamaUiState.busy;
  if (quickRunBtn) quickRunBtn.disabled = ollamaUiState.busy;
  if (quickRefreshBtn) quickRefreshBtn.disabled = ollamaUiState.busy;
  if (quickNewBtn) quickNewBtn.disabled = ollamaUiState.busy;
}

function setOllamaStatus(text, isError = false) {
  const targets = Array.from(document.querySelectorAll('[data-ollama-status="true"]'));
  if (!targets.length) {
    const fallback = document.getElementById('ollamaPromptStatus');
    if (fallback) targets.push(fallback);
  }
  targets.forEach((el) => {
    el.textContent = text || '';
    el.classList.toggle('error', !!isError);
  });
}

function formatOllamaRoleLabel(role) {
  if (role === 'user') return 'Toi';
  if (role === 'assistant') return 'MCP';
  return 'Système';
}

function createOllamaConversationId() {
  return `conv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function buildOllamaConversationTitle(messages = []) {
  const firstUser = messages.find((item) => item?.role === 'user' && item?.content);
  const fallback = messages.find((item) => item?.content);
  const source = String(firstUser?.content || fallback?.content || '').trim();
  if (!source) return 'Nouvelle discussion';
  return source.length > 72 ? `${source.slice(0, 72)}...` : source;
}

function formatOllamaHistoryTime(ts) {
  const date = new Date(Number(ts || Date.now()));
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function normalizeStoredOllamaHistory(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const normalized = [];
  raw.forEach((entry) => {
    const id = String(entry?.id || '').trim();
    if (!id || seen.has(id)) return;
    seen.add(id);
    const messages = _normalizeOllamaConversationMessages(entry?.messages);
    const updatedAt = Number(entry?.updatedAt || Date.now());
    const title = String(entry?.title || '').trim() || buildOllamaConversationTitle(messages);
    normalized.push({
      id,
      title,
      updatedAt: Number.isFinite(updatedAt) ? updatedAt : Date.now(),
      messages,
    });
  });
  normalized.sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
  return normalized.slice(0, OLLAMA_HISTORY_MAX_THREADS);
}

function syncActiveOllamaConversationInHistory(touch = true) {
  if (!ollamaUiState.activeConversationId) {
    ollamaUiState.activeConversationId = createOllamaConversationId();
  }
  const currentId = ollamaUiState.activeConversationId;
  const now = Date.now();
  const existing = ollamaUiState.history.find((entry) => entry.id === currentId);
  if (!existing) {
    ollamaUiState.history.unshift({
      id: currentId,
      title: buildOllamaConversationTitle(ollamaUiState.conversation),
      updatedAt: now,
      messages: [...ollamaUiState.conversation],
    });
  } else {
    existing.messages = [...ollamaUiState.conversation];
    existing.title = buildOllamaConversationTitle(existing.messages);
    if (touch) existing.updatedAt = now;
  }
  ollamaUiState.history.sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
  if (ollamaUiState.history.length > OLLAMA_HISTORY_MAX_THREADS) {
    ollamaUiState.history = ollamaUiState.history.slice(0, OLLAMA_HISTORY_MAX_THREADS);
  }
}

function persistOllamaConversation() {
  _saveStorage({
    ollamaConversation: ollamaUiState.conversation,
    ollamaConversationHistory: ollamaUiState.history,
    ollamaActiveConversationId: ollamaUiState.activeConversationId,
  });
}

function hydrateOllamaConversationHistory() {
  const stored = _loadStorage();
  let history = normalizeStoredOllamaHistory(stored.ollamaConversationHistory);
  let changed = false;
  if (!history.length) {
    const legacyMessages = _normalizeOllamaConversationMessages(stored.ollamaConversation);
    history = [
      {
        id: createOllamaConversationId(),
        title: buildOllamaConversationTitle(legacyMessages),
        updatedAt: Date.now(),
        messages: legacyMessages,
      },
    ];
    changed = true;
  }
  const savedActiveId = String(stored.ollamaActiveConversationId || '').trim();
  let active = history.find((entry) => entry.id === savedActiveId) || history[0];
  if (!active) {
    active = {
      id: createOllamaConversationId(),
      title: 'Nouvelle discussion',
      updatedAt: Date.now(),
      messages: [],
    };
    history = [active];
    changed = true;
  }
  ollamaUiState.history = history;
  ollamaUiState.activeConversationId = active.id;
  ollamaUiState.conversation = _normalizeOllamaConversationMessages(active.messages);
  if (changed) persistOllamaConversation();
}

function switchOllamaConversation(conversationId) {
  const id = String(conversationId || '').trim();
  if (!id || id === ollamaUiState.activeConversationId) return;
  const target = ollamaUiState.history.find((entry) => entry.id === id);
  if (!target) return;
  syncActiveOllamaConversationInHistory(false);
  ollamaUiState.activeConversationId = target.id;
  ollamaUiState.conversation = _normalizeOllamaConversationMessages(target.messages);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus(`Conversation chargée: ${target.title || 'sans titre'}`);
}

function renderOllamaConversationHistory() {
  const el = document.getElementById('ollamaConversationHistoryList');
  if (!el) return;
  el.replaceChildren();
  if (!ollamaUiState.history.length) {
    const empty = document.createElement('p');
    empty.className = 'ollama-history-empty';
    empty.textContent = 'Pas encore de conversations enregistrées.';
    el.appendChild(empty);
    return;
  }
  const frag = document.createDocumentFragment();
  ollamaUiState.history.forEach((entry) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ollama-history-item';
    if (entry.id === ollamaUiState.activeConversationId) button.classList.add('active');
    button.dataset.conversationId = entry.id;
    button.title = entry.title;
    const title = document.createElement('span');
    title.className = 'ollama-history-title';
    title.textContent = entry.title || 'Nouvelle discussion';
    const meta = document.createElement('span');
    meta.className = 'ollama-history-meta';
    const messageCount = Array.isArray(entry.messages) ? entry.messages.length : 0;
    meta.textContent = `${messageCount} msg • ${formatOllamaHistoryTime(entry.updatedAt)}`;
    button.append(title, meta);
    button.addEventListener('click', () => switchOllamaConversation(entry.id));
    frag.appendChild(button);
  });
  el.appendChild(frag);
}

function renderOllamaConversation() {
  const targets = Array.from(document.querySelectorAll('[data-ollama-chat-history="true"]'));
  if (!targets.length) return;
  targets.forEach((el) => {
    el.replaceChildren();
    if (!ollamaUiState.conversation.length) {
      const empty = document.createElement('p');
      empty.className = 'ollama-chat-empty';
      empty.textContent = 'Aucune discussion pour l’instant. Pose une première question.';
      el.appendChild(empty);
      return;
    }
    const frag = document.createDocumentFragment();
    ollamaUiState.conversation.forEach((entry) => {
      const wrap = document.createElement('article');
      wrap.className = `ollama-chat-message ${entry.role}`;
      const role = document.createElement('span');
      role.className = 'ollama-chat-role';
      role.textContent = formatOllamaRoleLabel(entry.role);
      const content = document.createElement('pre');
      content.className = 'ollama-chat-content';
      content.textContent = entry.content;
      wrap.append(role, content);
      frag.appendChild(wrap);
    });
    el.appendChild(frag);
    el.scrollTop = el.scrollHeight;
  });
}

function pushOllamaMessage(role, text) {
  const normalizedRole = ['user', 'assistant', 'system'].includes(role) ? role : 'system';
  const content = String(text || '').trim();
  if (!content) return;
  ollamaUiState.conversation.push({
    role: normalizedRole,
    content,
    ts: Date.now(),
  });
  if (ollamaUiState.conversation.length > OLLAMA_CHAT_MAX_MESSAGES) {
    ollamaUiState.conversation = ollamaUiState.conversation.slice(-OLLAMA_CHAT_MAX_MESSAGES);
  }
  syncActiveOllamaConversationInHistory(true);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
}

function clearOllamaConversation() {
  if (ollamaUiState.busy) return;
  if (ollamaUiState.conversation.length) {
    syncActiveOllamaConversationInHistory(false);
  } else if (ollamaUiState.activeConversationId) {
    ollamaUiState.history = ollamaUiState.history.filter(
      (entry) => entry.id !== ollamaUiState.activeConversationId
    );
  }
  ollamaUiState.activeConversationId = createOllamaConversationId();
  ollamaUiState.conversation = [];
  syncActiveOllamaConversationInHistory(true);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus('Nouvelle discussion prête.');
}

function clearOllamaConversationHistory() {
  if (ollamaUiState.busy) return;
  ollamaUiState.history = [];
  ollamaUiState.activeConversationId = '';
  clearOllamaConversation();
  setOllamaStatus('Historique vidé. Nouvelle discussion prête.');
}

function buildOllamaPromptWithContext(userPrompt) {
  const prompt = String(userPrompt || '').trim();
  if (!prompt) return '';
  if (!ollamaUiState.conversation.length) return prompt;

  let totalChars = 0;
  const context = [];
  for (let i = ollamaUiState.conversation.length - 1; i >= 0; i -= 1) {
    const item = ollamaUiState.conversation[i];
    if (!item?.content) continue;
    const label = item.role === 'assistant' ? 'Assistant' : (item.role === 'user' ? 'Utilisateur' : 'Système');
    const clippedContent = item.content.length > 700 ? `${item.content.slice(0, 700)}...` : item.content;
    const line = `${label}: ${clippedContent}`;
    totalChars += line.length;
    if (totalChars > OLLAMA_CHAT_CONTEXT_MAX_CHARS && context.length) break;
    context.push(line);
    if (context.length >= OLLAMA_CHAT_CONTEXT_MESSAGES) break;
  }
  context.reverse();

  return [
    'Contexte de conversation à respecter :',
    ...context,
    `Utilisateur: ${prompt}`,
    'Assistant:',
  ].join('\n');
}

function submitOllamaChatPrompt(options = {}) {
  if (ollamaUiState.busy) return;
  const input = options.inputEl || document.getElementById('ollamaPromptInput');
  const prompt = String(options.prompt ?? input?.value ?? '').trim();
  const model = String(options.model || getCurrentOllamaModel() || ollamaUiState.lastModel || '').trim();
  if (!model) {
    setOllamaStatus('Sélectionne d’abord un modèle Ollama.', true);
    return;
  }
  if (!prompt) {
    setOllamaStatus('Écris un message avant d’envoyer.', true);
    return;
  }
  const contextualPrompt = buildOllamaPromptWithContext(prompt);
  pushOllamaMessage('user', prompt);
  if (input && !options.keepInput) {
    input.value = '';
    input.focus();
  }
  setOllamaBusy(true);
  setOllamaStatus(`Exécution avec ${model}…`);
  vscode.postMessage({
    type: 'hubOllamaPrompt',
    model,
    prompt: contextualPrompt,
    baseUrl: getOllamaBaseUrl(),
  });
}

function getOllamaBaseUrl() {
  const input = document.getElementById('ollamaBaseUrl');
  const raw = String(input?.value || '').trim();
  return raw || 'http://127.0.0.1:11434';
}

function getCurrentOllamaModel() {
  const selects = Array.from(document.querySelectorAll('[data-ollama-model-select="true"]'));
  for (const select of selects) {
    const value = String(select?.value || '').trim();
    if (value) return value;
  }
  return String(ollamaUiState.lastModel || '').trim();
}

function renderOllamaModels(models = [], selected = '') {
  const selects = Array.from(document.querySelectorAll('[data-ollama-model-select="true"]'));
  if (!selects.length) return;
  const normalized = Array.isArray(models) ? models.filter(Boolean) : [];
  if (!normalized.length) {
    selects.forEach((select) => {
      select.replaceChildren();
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'Aucun modèle détecté';
      select.appendChild(opt);
      select.disabled = true;
    });
    return;
  }
  selects.forEach((select) => {
    select.replaceChildren();
    normalized.forEach((name) => {
      const opt = document.createElement('option');
      opt.value = String(name);
      opt.textContent = String(name);
      select.appendChild(opt);
    });
    select.disabled = false;
  });
  const target = selected && normalized.includes(selected) ? selected : normalized[0];
  selects.forEach((select) => {
    select.value = target;
  });
  ollamaUiState.lastModel = target;
  _saveStorage({ ollamaModel: target });
}

function requestOllamaModels() {
  if (ollamaUiState.busy) return;
  setOllamaBusy(true);
  setOllamaStatus('Chargement des modèles Ollama…');
  vscode.postMessage({
    type: 'hubOllamaListModels',
    baseUrl: getOllamaBaseUrl(),
  });
}

// Quick actions
document.querySelectorAll('.action-card').forEach((card) => {
  card.addEventListener('click', () => {
    if (card.dataset.action === 'static-open') {
      showPanel('static');
      if (!getStaticBinaryPath()) openBinaryMenu();
    } else if (card.dataset.action === 'dynamic-run') {
      showPanel('dynamic');
    } else if (card.dataset.action === 'outils-open') {
      showPanel('outils');
    }
  });
});

// Static: binary path shared with dynamic form
const staticBinaryInput = document.getElementById('staticBinaryPath');

function setOption32Availability(selectEl, platform) {
  if (!selectEl) return;
  const option32 = selectEl.querySelector('option[value="32"]');
  if (!option32) return;
  if (platform !== 'linux') {
    option32.disabled = true;
    option32.textContent = `32-bit (non dispo sur ${platform === 'darwin' ? 'macOS' : 'Windows'})`;
    if (selectEl.value === '32') selectEl.value = '64';
  } else {
    option32.disabled = false;
    option32.textContent = '32-bit';
  }
}

// Restore static binary path from storage
try {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    const { staticBinaryPath, binaryMeta } = JSON.parse(saved);
    if (staticBinaryPath && staticBinaryInput) {
      staticBinaryInput.value = staticBinaryPath;
      if (binaryPathInput && !binaryPathInput.value?.trim()) binaryPathInput.value = staticBinaryPath;
      currentBinaryMeta = _normalizeBinaryMeta(binaryMeta || null);
      updateTopBarBinaryDisplay(staticBinaryPath, currentBinaryMeta);
    }
  }
} catch (_) {}
function syncStaticBinary() {
  const staticVal = staticBinaryInput?.value?.trim();
  const useExisting = form?.querySelector('[name="useExistingBinary"]')?.checked === true;
  if (useExisting && staticVal && binaryPathInput && binaryPathInput.value !== staticVal) {
    binaryPathInput.value = staticVal;
  }
}
function getStaticBinaryPath() {
  syncStaticBinary();
  return staticBinaryInput?.value?.trim() || '';
}

function getActiveStaticTab() {
  return document.querySelector('#subTabsBar .sub-tab.active')?.dataset.subTab || _loadStorage().tab || 'disasm';
}

function syncStaticWorkspaceSummary(activeTab = getActiveStaticTab()) {
  const bp = getStaticBinaryPath();
  const meta = getCurrentBinaryMeta();
  const hasBinary = !!bp;
  const nameEl = document.getElementById('staticWorkspaceName');
  const metaEl = document.getElementById('staticWorkspaceMeta');
  const hintEl = document.getElementById('staticWorkspaceHint');

  if (nameEl) {
    nameEl.textContent = hasBinary ? (bp.split('/').pop() || bp) : 'Choisir un fichier...';
    nameEl.classList.toggle('empty', !hasBinary);
  }
  if (metaEl) {
    const status = _binaryStatusText(meta);
    metaEl.textContent = hasBinary ? (status || bp) : 'Aucun binaire selectionne.';
  }
  if (hintEl) {
    if (!hasBinary && pendingStaticQuickAction) {
      const pendingTab = STATIC_QUICK_ACTIONS[pendingStaticQuickAction]?.tab || activeTab;
      const pendingLabel = GROUP_LABELS[pendingTab] || 'la vue demandee';
      hintEl.textContent = `Choisis un binaire pour ouvrir ${pendingLabel.toLowerCase()}.`;
    } else if (hasBinary) {
      hintEl.textContent = STATIC_FLOW_HINTS[activeTab] || STATIC_FLOW_HINTS.default;
    } else {
      hintEl.textContent = 'Commence par choisir un binaire, puis ouvre le desassemblage.';
    }
  }
  updateDisasmSessionSummary();
}

const DISASM_UI_STATE_KEY = 'pof-disasm-ui-state-v1';
function _basenameFromPath(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';
  return normalized.split(/[\\/]/).filter(Boolean).pop() || normalized;
}

function _getSelectDisplayText(id, fallback = '—') {
  const el = document.getElementById(id);
  if (!el) return fallback;
  const opt = el.options?.[el.selectedIndex];
  const label = String(opt?.textContent || opt?.label || '').trim();
  return label || fallback;
}

function _selectedRawArchMeta() {
  return getCurrentBinaryMeta();
}

function _getDisasmArchSummaryText() {
  const meta = getCurrentBinaryMeta();
  if (meta?.kind === 'raw') {
    const selectedArch = String(meta.rawConfig?.arch || meta.arch || '').trim();
    if (selectedArch) return selectedArch;
    return 'Blob brut';
  }
  const detectedArch = String(meta?.rawConfig?.arch || meta?.arch || window.lastBinaryArch || '').trim();
  return detectedArch ? `Auto: ${detectedArch}` : 'Auto';
}

function _countVisibleAnnotations() {
  return Object.values(window._annotations || {}).filter((entry) => entry && (entry.name || entry.comment)).length;
}

function _setTextContent(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function _loadDisasmUiState() {
  try {
    return JSON.parse(localStorage.getItem(DISASM_UI_STATE_KEY) || '{}');
  } catch {
    return {};
  }
}

function _saveDisasmUiState(partial) {
  const next = { ..._loadDisasmUiState(), ...partial };
  localStorage.setItem(DISASM_UI_STATE_KEY, JSON.stringify(next));
  return next;
}

function updateDisasmSessionSummary() {
  const binaryPath = getStaticBinaryPath();
  const summary = getActiveContextSummary(window._lastDisasmAddr);
  const selectionAddr = normalizeHexAddress(document.getElementById('annotationAddrBadge')?.dataset.addr || '');
  const annotationsCount = _countVisibleAnnotations();
  const bookmarksCount = document.querySelectorAll('#bookmarksList .bookmark-item').length;
  const functionLabel = summary.functionName
    ? `${summary.functionName}${summary.functionAddr ? ` @ ${summary.functionAddr}` : ''}`
    : (summary.functionAddr || '—');

  _setTextContent('disasmSummaryBinary', binaryPath ? _basenameFromPath(binaryPath) : 'Aucun binaire');
  _setTextContent('disasmSummaryFunction', functionLabel || '—');
  _setTextContent('disasmSummaryAddress', summary.addr || '—');
  _setTextContent('disasmSummarySelection', selectionAddr || '—');
  _setTextContent('disasmSummarySyntax', _getSelectDisplayText('disasmSyntax', 'Intel'));
  _setTextContent('disasmSummarySection', _getSelectDisplayText('disasmSection', 'Toutes'));
  _setTextContent('disasmSummaryArch', _getDisasmArchSummaryText());
  _setTextContent('disasmSummaryAnnotations', String(annotationsCount));
  _setTextContent('disasmSummaryBookmarks', String(bookmarksCount));

  const hintEl = document.getElementById('disasmSessionHint');
  if (!hintEl) return;
  if (!binaryPath) {
    hintEl.textContent = 'Choisis un binaire puis ouvre le désassemblage pour démarrer la session.';
  } else if (summary.addr && summary.functionName) {
    hintEl.textContent = `Tu es positionné sur ${summary.functionName} à ${summary.addr}. Les actions essentielles restent visibles, le reste peut se replier.`;
  } else if (summary.addr) {
    hintEl.textContent = `Adresse active ${summary.addr}. Tu peux naviguer, annoter ou lancer les xrefs depuis ici.`;
  } else {
    hintEl.textContent = 'Utilise Go, les raccourcis ou le sélecteur de symbole pour te déplacer rapidement dans le binaire.';
  }
}

function setDisasmCardCollapsed(cardId, bodyId, buttonId, collapsed) {
  const card = document.getElementById(cardId);
  const body = document.getElementById(bodyId);
  const button = document.getElementById(buttonId);
  if (card) card.classList.toggle('is-collapsed', collapsed);
  if (body) body.hidden = collapsed;
  if (button) {
    button.textContent = collapsed ? 'Afficher' : 'Masquer';
    button.setAttribute('aria-expanded', String(!collapsed));
  }
}

function bindDisasmCardToggle({ stateKey, cardId, bodyId, buttonId }) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  const state = _loadDisasmUiState();
  setDisasmCardCollapsed(cardId, bodyId, buttonId, state[stateKey] === true);
  button.addEventListener('click', () => {
    const currentState = _loadDisasmUiState();
    const collapsed = !(currentState[stateKey] === true);
    _saveDisasmUiState({ [stateKey]: collapsed });
    setDisasmCardCollapsed(cardId, bodyId, buttonId, collapsed);
  });
}

function initDisasmUxState() {
  bindDisasmCardToggle({
    stateKey: 'labelsCollapsed',
    cardId: 'disasmLabelsCard',
    bodyId: 'disasmLabelsBody',
    buttonId: 'btnToggleDisasmLabels',
  });
  ['disasmSyntax', 'disasmSection'].forEach((id) => {
    document.getElementById(id)?.addEventListener('change', () => {
      updateDisasmSessionSummary();
    });
  });
  updateDisasmSessionSummary();
}

function resetStaticBinaryDerivedState() {
  tabDataCache = {};
  stackFrameCache = {};
  window.sectionsCache = [];
  resetHexPatchSessionState();
  hexSelectionModel = {
    startAddr: '',
    endAddr: '',
    activeAddr: '',
    anchorAddr: '',
    spanLength: 1,
  };
  pendingStackFrameRequests.clear();
  stackUiState.renderedAddr = '';
  stackUiState.renderedBinaryPath = '';
  stackUiState.activeEntryName = '';
  stackUiState.pendingEntryName = '';
  decompileUiState.activeStackEntryName = '';
  decompileUiState.pendingStackEntryName = '';
  typedDataUiState.appliedStructName = '';
  typedDataUiState.appliedStructOffset = '0x0';
  typedDataUiState.appliedStructAddr = '';
  typedDataUiState.hexStructPreview = null;
  clearDecompileCaches();
  window._lastDisasmAddr = '';
  window.lastBinaryArch = '';
  window._annotations = {};
  decompileUiState.renderedAddr = '';
  decompileUiState.renderedBinaryPath = '';
  decompileUiState.renderedQuality = _normalizeDecompileQuality(decompileUiState.quality || 'normal');
  updateActiveContextBars('');
  renderBookmarks();
  updateDisasmSessionSummary();
}

function applyStaticBinarySelectionUi(binaryPath, binaryMeta) {
  if (staticBinaryInput) staticBinaryInput.value = binaryPath;
  if (binaryPathInput) binaryPathInput.value = binaryPath;
  currentBinaryMeta = binaryMeta;
  saveBinarySelection(binaryPath, binaryMeta);
  closeBinaryMenu();
  syncDynamicBinaryFieldMode();
  syncToolsBinaryLabel();
  renderBookmarks();
  if (document.getElementById('panel-static')?.classList.contains('active')) {
    showGroup(_loadStorage().group || 'code', getActiveStaticTab() || _loadStorage().tab || 'disasm');
  }
  syncStaticWorkspaceSummary();
  updateActiveContextBars(window._lastDisasmAddr);
}

function queueStaticBinaryAutoload(binaryPath, { skipAutoLoad = false } = {}) {
  if (!binaryPath) return;
  postBinaryAwareMessage('hubLoadAnnotations', { binaryPath });
  const activeTab = getActiveStaticTab();
  const pendingAction = pendingStaticQuickAction;
  pendingStaticQuickAction = '';
  if (pendingAction) {
    triggerStaticQuickAction(pendingAction);
  } else if (!skipAutoLoad) {
    _autoLoadTab(activeTab);
  }
}

function finalizeStaticBinarySelection(binaryPath, binaryMeta, { sameSelection = false, skipAutoLoad = false } = {}) {
  if (binaryMeta?.kind !== 'raw') requestSymbols();
  if (!sameSelection) {
    queueStaticBinaryAutoload(binaryPath, { skipAutoLoad });
  }
  requestRunTraceInit(null, binaryPath);
  setDynamicTraceStatus('Prêt.');
  updateArgvPayloadHint();
}

function triggerStaticQuickAction(action) {
  const config = STATIC_QUICK_ACTIONS[action];
  if (!config) return;
  const hasBinary = !!getStaticBinaryPath();
  pendingStaticQuickAction = hasBinary ? '' : action;
  showGroup(config.group, config.tab);
  if (!hasBinary) {
    vscode.postMessage({ type: 'requestBinarySelection' });
    return;
  }
  if (config.tab === 'disasm') {
    postBinaryAwareMessage('hubOpenDisasm', {
      binaryPath: getStaticBinaryPath(),
      useCache: true,
      openInEditor: false,
    });
  }
}

function postBinaryAwareMessage(type, extra = {}) {
  const payload = { type, ...extra };
  const binaryPath = payload.binaryPath || getStaticBinaryPath();
  if (binaryPath && payload.binaryPath === undefined) payload.binaryPath = binaryPath;
  const meta = getCurrentBinaryMeta();
  if (binaryPath && payload.binaryMeta === undefined && meta) payload.binaryMeta = meta;
  vscode.postMessage(payload);
}

function isRawBinarySelected() {
  return getCurrentBinaryMeta()?.kind === 'raw';
}

function markRawTabUnavailable(tabId) {
  const contentIds = RAW_UNSUPPORTED_TABS[tabId];
  if (!contentIds) return false;
  const message = 'Cette vue n’est pas encore disponible pour un blob brut. Utilisez plutôt Désassemblage, CFG, Call Graph, Fonctions, Xrefs, Strings, Recherche, ROP, Déobfuscation, Infos, Sections ou Hex.';
  contentIds.forEach((id) => setStaticLoading(id, message));
  return true;
}

function syncDynamicBinaryFieldMode() {
  const useExisting = form?.querySelector('[name="useExistingBinary"]')?.checked === true;
  const label = document.getElementById('dynamicBinaryLabel');
  const hint = document.getElementById('dynamicBinaryHint');
  if (label) label.textContent = useExisting ? 'Binaire actif' : 'Binaire de sortie';
  if (hint) {
    hint.textContent = useExisting
      ? 'Le binaire existant se choisit depuis la barre du haut.'
      : 'Chemin du binaire compilé utilisé par la trace.';
  }
  if (binaryPathInput) {
    binaryPathInput.readOnly = useExisting;
    binaryPathInput.title = useExisting ? 'Champ synchronisé avec la barre du haut' : '';
    binaryPathInput.placeholder = useExisting ? 'Choisissez le binaire dans la barre du haut' : 'examples/stack3.elf';
    if (useExisting) {
      binaryPathInput.value = getStaticBinaryPath() || '';
    } else if (!binaryPathInput.value.trim()) {
      binaryPathInput.value = 'examples/stack3.elf';
    }
  }
}

function loadExploitNotesUiState() {
  try {
    return JSON.parse(localStorage.getItem(EXPLOIT_NOTES_UI_KEY) || '{}');
  } catch (_) {
    return {};
  }
}

function saveExploitNotesUiState(state) {
  try {
    const prev = loadExploitNotesUiState();
    localStorage.setItem(EXPLOIT_NOTES_UI_KEY, JSON.stringify({ ...prev, ...state }));
  } catch (_) {}
}

function openExploitNotesWidget() {
  if (!exploitNotesWidget) return;
  exploitNotesWidget.classList.remove('hidden');
  exploitNotesFab?.classList.add('hidden');
  saveExploitNotesUiState({ hidden: false });
}

function closeExploitNotesWidget() {
  if (!exploitNotesWidget) return;
  exploitNotesWidget.classList.add('hidden');
  exploitNotesFab?.classList.remove('hidden');
  saveExploitNotesUiState({ hidden: true });
}

function toggleExploitNotesCollapsed(forceCollapsed = null) {
  if (!exploitNotesWidget) return;
  const next = forceCollapsed === null ? !exploitNotesWidget.classList.contains('collapsed') : !!forceCollapsed;
  exploitNotesWidget.classList.toggle('collapsed', next);
  const btn = document.getElementById('exploitNotesWidgetCollapse');
  if (btn) btn.textContent = next ? '+' : '−';
  saveExploitNotesUiState({ collapsed: next });
}

function initExploitNotesWidget() {
  if (!exploitNotesWidget) return;
  try {
    const savedText = localStorage.getItem(EXPLOIT_NOTES_TEXT_KEY);
    if (savedText && exploitNotesInput && !exploitNotesInput.value) exploitNotesInput.value = savedText;
  } catch (_) {}

  const ui = loadExploitNotesUiState();
  const x = Number.isFinite(ui.x) ? ui.x : null;
  const y = Number.isFinite(ui.y) ? ui.y : null;
  if (x !== null && y !== null) {
    exploitNotesWidget.style.left = `${x}px`;
    exploitNotesWidget.style.top = `${y}px`;
    exploitNotesWidget.style.right = 'auto';
    exploitNotesWidget.style.bottom = 'auto';
  }
  if (Number.isFinite(ui.width) && ui.width >= 260) exploitNotesWidget.style.width = `${ui.width}px`;
  toggleExploitNotesCollapsed(!!ui.collapsed);
  if (ui.hidden) closeExploitNotesWidget();
  else openExploitNotesWidget();

  const header = document.getElementById('exploitNotesWidgetHeader');
  const collapseBtn = document.getElementById('exploitNotesWidgetCollapse');
  const closeBtn = document.getElementById('exploitNotesWidgetClose');
  const openBtn = document.getElementById('btnOpenExploitNotes');
  const openFab = document.getElementById('exploitNotesFab');

  openBtn?.addEventListener('click', openExploitNotesWidget);
  openFab?.addEventListener('click', openExploitNotesWidget);
  closeBtn?.addEventListener('click', closeExploitNotesWidget);
  collapseBtn?.addEventListener('click', () => toggleExploitNotesCollapsed());

  exploitNotesInput?.addEventListener('input', () => {
    try { localStorage.setItem(EXPLOIT_NOTES_TEXT_KEY, exploitNotesInput.value); } catch (_) {}
  });

  let drag = null;
  header?.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    if (e.target?.closest?.('button')) return;
    const rect = exploitNotesWidget.getBoundingClientRect();
    drag = { dx: e.clientX - rect.left, dy: e.clientY - rect.top };
    document.body.classList.add('is-dragging-notes-widget');
    e.preventDefault();
  });

  window.addEventListener('mousemove', (e) => {
    if (!drag) return;
    const maxX = Math.max(0, window.innerWidth - exploitNotesWidget.offsetWidth);
    const maxY = Math.max(0, window.innerHeight - exploitNotesWidget.offsetHeight);
    const left = Math.min(maxX, Math.max(0, e.clientX - drag.dx));
    const top = Math.min(maxY, Math.max(0, e.clientY - drag.dy));
    exploitNotesWidget.style.left = `${left}px`;
    exploitNotesWidget.style.top = `${top}px`;
    exploitNotesWidget.style.right = 'auto';
    exploitNotesWidget.style.bottom = 'auto';
  });

  window.addEventListener('mouseup', () => {
    if (!drag) return;
    drag = null;
    document.body.classList.remove('is-dragging-notes-widget');
    const rect = exploitNotesWidget.getBoundingClientRect();
    saveExploitNotesUiState({ x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width) });
  });
}

function initOllamaChatWidget() {
  const widget = document.getElementById('ollamaChatWidget');
  const fab = document.getElementById('ollamaChatFab');
  if (!widget || !fab) return;
  const closeBtn = document.getElementById('btnOllamaChatWidgetClose');
  const openDashboardBtn = document.getElementById('btnOllamaOpenDashboard');

  const open = () => {
    widget.classList.add('open');
    try { localStorage.setItem(OLLAMA_CHAT_WIDGET_KEY, 'open'); } catch (_) {}
  };
  const close = () => {
    widget.classList.remove('open');
    try { localStorage.setItem(OLLAMA_CHAT_WIDGET_KEY, 'closed'); } catch (_) {}
  };
  const toggle = () => {
    if (widget.classList.contains('open')) close();
    else open();
  };

  try {
    if (localStorage.getItem(OLLAMA_CHAT_WIDGET_KEY) === 'open') open();
    else close();
  } catch (_) {
    close();
  }

  fab.addEventListener('click', toggle);
  closeBtn?.addEventListener('click', close);
  openDashboardBtn?.addEventListener('click', () => {
    showPanel('dashboard');
    const input = document.getElementById('ollamaPromptInput');
    if (input) input.focus();
  });
  const activePanel = document.querySelector('.icon-nav-item.active')?.dataset.panel || 'dashboard';
  syncOllamaFloatingWidgetVisibility(activePanel);
}

function syncOllamaFloatingWidgetVisibility(panelId = '') {
  const widget = document.getElementById('ollamaChatWidget');
  const fab = document.getElementById('ollamaChatFab');
  if (!widget || !fab) return;
  const normalized = String(panelId || '').trim().toLowerCase();
  const hideFloating = normalized === 'dashboard';
  if (hideFloating) {
    fab.style.display = 'none';
    widget.style.display = 'none';
    return;
  }
  fab.style.display = '';
  widget.style.display = '';
}

function requestSymbols() {
  if (isRawBinarySelected()) return;
  const p = getStaticBinaryPath();
  if (p) vscode.postMessage({ type: 'getSymbols', binaryPath: p });
}

function setDynamicTraceStatus(text) {
  if (dynamicTraceStatus) dynamicTraceStatus.textContent = text;
}

function buildDynamicSourceHintText({
  sourcePath = '',
  sourceEnrichmentEnabled = false,
  sourceEnrichmentStatus = '',
  sourceEnrichmentMessage = ''
} = {}) {
  const normalizedPath = String(sourcePath || '').trim();
  const message = String(sourceEnrichmentMessage || '').trim();
  const status = String(sourceEnrichmentStatus || '').trim();

  if (message) return message;
  if (sourceEnrichmentEnabled && normalizedPath) return 'Code source détecté — analyse enrichie activée.';
  if (normalizedPath && status === 'missing') return 'Code source fourni introuvable ; analyse binaire seule.';
  if (normalizedPath) return `Code source sélectionné — enrichissement prêt au prochain run.`;
  return 'Pour une meilleure analyse, ajoutez le code source C du programme.';
}

function normalizeDynamicPayloadTargetMode(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return ['auto', 'argv1', 'stdin', 'both'].includes(normalized) ? normalized : 'auto';
}

function normalizeDynamicEffectiveTarget(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return ['argv1', 'stdin', 'both'].includes(normalized) ? normalized : 'argv1';
}

function dynamicPayloadTargetLabel(target) {
  const normalized = normalizeDynamicEffectiveTarget(target);
  if (normalized === 'stdin') return 'stdin';
  if (normalized === 'both') return 'stdin + argv[1]';
  return 'argv[1]';
}

function getDynamicPayloadTargetMode() {
  return normalizeDynamicPayloadTargetMode(
    dynamicPayloadTargetMode?.value || dynamicTraceInitState.payloadTargetMode || 'auto'
  );
}

function getDynamicEffectivePayloadTarget() {
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return normalizeDynamicEffectiveTarget(mode);
  return normalizeDynamicEffectiveTarget(dynamicTraceInitState.payloadTargetAuto || dynamicTraceInitState.payloadTargetEffective);
}

function buildDynamicPayloadTargetHint() {
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return `${dynamicPayloadTargetLabel(mode)} force manuellement.`;
  return String(dynamicTraceInitState.payloadTargetReason || 'Auto: aucune source claire, fallback sur argv[1]');
}

function requestRunTraceInit(preset = null, forcedBinaryPath = '') {
  vscode.postMessage({
    type: 'requestRunTraceInit',
    binaryPath: forcedBinaryPath || binaryPathInput?.value?.trim() || '',
    sourcePath: dynamicSourcePathInput?.value?.trim() || dynamicTraceInitState.sourcePath || '',
    payloadTargetMode: getDynamicPayloadTargetMode(),
    preset
  });
}

function parsePayloadExpressionPreview(input) {
  const text = String(input || '').trim();
  if (!text) return { bytes: 0, preview: '' };
  if (!/[+*\\]/.test(text)) return { bytes: text.length, preview: text };

  const parts = text.split('+').map((part) => part.trim()).filter(Boolean);
  if (!parts.length) return { bytes: 0, preview: '' };
  let preview = '';
  let bytes = 0;
  const decodedLength = (value) => {
    let count = 0;
    for (let index = 0; index < value.length; index += 1) {
      if (value[index] === '\\' && value[index + 1] === 'x' && /^[0-9a-fA-F]{2}$/.test(value.slice(index + 2, index + 4))) {
        count += 1;
        index += 3;
      } else if (value[index] === '\\' && ['n', 'r', 't', '0', '\\'].includes(value[index + 1])) {
        count += 1;
        index += 1;
      } else {
        count += new TextEncoder().encode(value[index]).length;
      }
    }
    return count;
  };
  for (const part of parts) {
    const match = part.match(/^(.+?)\*(\d+)$/);
    if (match) {
      const count = parseInt(match[2], 10);
      if (!Number.isFinite(count) || count < 0) throw new Error('compteur invalide');
      bytes += decodedLength(match[1]) * count;
      preview += match[1].repeat(Math.min(count, 16));
    } else {
      bytes += decodedLength(part);
      preview += part;
    }
  }
  return { bytes, preview };
}

function bytesToCompactHex(bytes) {
  return `0x${(Array.isArray(bytes) ? bytes : [])
    .map((value) => Number(value).toString(16).padStart(2, '0'))
    .join('')}`;
}

function bytesToSpacedHex(bytes) {
  return (Array.isArray(bytes) ? bytes : [])
    .map((value) => Number(value).toString(16).padStart(2, '0'))
    .join(' ');
}

function bytesToEscapedHex(bytes) {
  return (Array.isArray(bytes) ? bytes : [])
    .map((value) => `\\x${Number(value).toString(16).padStart(2, '0').toUpperCase()}`)
    .join('');
}

function buildPayloadEndianHint(input) {
  const text = String(input || '').trim();
  if (!text) return '';
  const escapedDword = text.match(/(?:\\x[0-9a-fA-F]{2}){4}/);
  if (!escapedDword) return '';
  const bytes = Array.from(
    escapedDword[0].matchAll(/\\x([0-9a-fA-F]{2})/g),
    (match) => parseInt(match[1], 16)
  );
  if (bytes.length !== 4) return '';
  const littleEndianRead = [...bytes].reverse();
  const writtenHex = bytesToCompactHex(bytes);
  const readHex = bytesToCompactHex(littleEndianRead);
  if (writtenHex === readHex) return '';
  return `Endian: ${bytesToSpacedHex(bytes)} donne ${readHex} si le programme relit ce dword en little-endian. Pour viser ${writtenHex}, utilise ${bytesToEscapedHex(littleEndianRead)}.`;
}

function updateArgvPayloadHint() {
  if (!argvPayloadHint) return;
  const raw = argvPayloadInput?.value ?? '';
  const trimmed = raw.trim();
  const targetHint = buildDynamicPayloadTargetHint();
  const currentTarget = dynamicPayloadTargetLabel(getDynamicEffectivePayloadTarget());
  if (!trimmed) {
    argvPayloadHint.textContent = targetHint;
    return;
  }
  try {
    const parsed = parsePayloadExpressionPreview(trimmed);
    const endianHint = buildPayloadEndianHint(trimmed);
    argvPayloadHint.textContent = `Payload courant: ${parsed.bytes} byte(s). Cible effective: ${currentTarget}. ${targetHint}${endianHint ? ` ${endianHint}` : ''}`;
  } catch (_) {
    argvPayloadHint.textContent = 'Expression payload invalide.';
  }
}

function requestDynamicTraceHistory() {
  vscode.postMessage({ type: 'requestDynamicTraceHistory' });
}

function renderDynamicTraceHistory() {
  if (!dynamicTraceHistory) return;
  dynamicTraceHistory.replaceChildren();

  const items = Array.isArray(dynamicTraceHistoryState.items) ? dynamicTraceHistoryState.items : [];
  if (btnClearDynamicTraceHistory) btnClearDynamicTraceHistory.disabled = items.length === 0;
  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = 'Aucune trace temporaire pour le moment.';
    dynamicTraceHistory.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'dynamic-history-item';
    if (item.active) row.classList.add('active');

    const main = document.createElement('div');
    main.className = 'dynamic-history-main';

    const title = document.createElement('div');
    title.className = 'dynamic-history-title';
    const runLabel = item.runId ? `#${item.runId}` : item.fileName || 'run';
    const stepsLabel = `${Number(item.steps || 0)} step(s)`;
    const payloadName = item.payloadLabel || 'payload';
    const argvLabel = item.argvBytes ? `${payloadName}: ${Number(item.argvBytes)} byte(s)` : 'sans payload';
    title.textContent = `${runLabel} • ${stepsLabel} • ${argvLabel}`;

    const meta = document.createElement('div');
    meta.className = 'dynamic-history-meta';
    const binaryLabel = item.binaryName || 'binaire inconnu';
    const whenLabel = item.updatedAtLabel || 'date inconnue';
    meta.textContent = `${binaryLabel} • ${whenLabel}`;

    const subline = document.createElement('div');
    subline.className = 'dynamic-history-subline';
    const extra = [];
    if (item.startSymbol) extra.push(`start ${item.startSymbol}`);
    if (item.sourceName) extra.push(`source ${item.sourceName}`);
    if (item.argvPreview) extra.push(`argv "${item.argvPreview}"`);
    subline.textContent = extra.length ? extra.join(' • ') : (item.path || '');

    main.appendChild(title);
    main.appendChild(meta);
    main.appendChild(subline);

    const actions = document.createElement('div');
    actions.className = 'dynamic-history-actions';

    const openBtn = document.createElement('button');
    openBtn.type = 'button';
    openBtn.className = 'btn btn-secondary btn-sm';
    openBtn.textContent = item.active ? 'Ouverte' : 'Ouvrir';
    openBtn.addEventListener('click', () => {
      setDynamicTraceStatus(`Ouverture de la trace ${runLabel}...`);
      vscode.postMessage({ type: 'openDynamicTraceHistory', tracePath: item.path });
    });

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'btn btn-secondary btn-sm';
    deleteBtn.textContent = 'Supprimer';
    deleteBtn.addEventListener('click', () => {
      setDynamicTraceStatus(`Suppression de la trace ${runLabel}...`);
      vscode.postMessage({ type: 'deleteDynamicTraceHistory', tracePath: item.path });
    });

    actions.appendChild(openBtn);
    actions.appendChild(deleteBtn);

    row.appendChild(main);
    row.appendChild(actions);
    dynamicTraceHistory.appendChild(row);
  });
}

function applyRunTraceInit(msg) {
  const previousArgvPayload = argvPayloadInput?.value ?? '';
  const previousPayloadTargetMode = getDynamicPayloadTargetMode();
  const nextPayloadTargetMode = normalizeDynamicPayloadTargetMode(msg.payloadTargetMode || previousPayloadTargetMode);
  dynamicTraceInitState = {
    archBits: Number(msg.archBits) === 32 ? 32 : 64,
    pie: msg.pie === true,
    sourcePath: String(msg.sourcePath || '').trim(),
    sourceEnrichmentEnabled: msg.sourceEnrichmentEnabled === true,
    sourceEnrichmentStatus: String(msg.sourceEnrichmentStatus || '').trim(),
    sourceEnrichmentMessage: String(msg.sourceEnrichmentMessage || '').trim(),
    payloadTargetMode: nextPayloadTargetMode,
    payloadTargetAuto: normalizeDynamicEffectiveTarget(msg.payloadTargetAuto || 'argv1'),
    payloadTargetEffective: normalizeDynamicEffectiveTarget(msg.payloadTargetEffective || msg.payloadTargetAuto || 'argv1'),
    payloadTargetReason: String(msg.payloadTargetReason || '').trim() || 'Auto: aucune source claire, fallback sur argv[1]',
    profile: {
      bufferOffset: msg?.mvpProfile?.bufferOffset ?? '',
      bufferSize: msg?.mvpProfile?.bufferSize ?? '',
      maxSteps: msg?.mvpProfile?.maxSteps ?? 800,
      startSymbol: msg?.mvpProfile?.startSymbol || msg?.symbols?.startDefault || 'main',
      stopSymbol: msg?.mvpProfile?.stopSymbol || msg?.symbols?.stopDefault || ''
    }
  };

  const profile = msg.mvpProfile || {};
  setTraceField('binaryPath', msg.binaryPath || '');
  setTraceField('sourcePath', dynamicTraceInitState.sourcePath || '');
  setTraceField('argvPayload', typeof profile.argvPayload === 'string' ? profile.argvPayload : previousArgvPayload);
  if (dynamicPayloadTargetMode) dynamicPayloadTargetMode.value = nextPayloadTargetMode;

  if (dynamicArchBits) dynamicArchBits.textContent = `${dynamicTraceInitState.archBits}-bit`;
  if (dynamicPie) dynamicPie.textContent = dynamicTraceInitState.pie ? 'Yes' : 'No';
  if (dynamicSourceHint) {
    dynamicSourceHint.textContent = buildDynamicSourceHintText(dynamicTraceInitState);
  }
  setDynamicTraceStatus(msg.binaryPath ? 'Prêt.' : 'Sélectionnez un binaire pour lancer la trace.');
  updateArgvPayloadHint();
  requestDynamicTraceHistory();
}

function populateDecompileSelect(symbols) {
  const sel = document.getElementById('decompileAddrSelect');
  if (!sel) return;
  const previousValue = sel.value || decompileUiState.selectedAddr || '';
  const entriesByAddr = new Map();
  const appendEntry = (addr, name, sourceRank = 0) => {
    const normalized = normalizeHexAddress(addr);
    if (!normalized) return;
    const current = entriesByAddr.get(normalized);
    if (!current || sourceRank > current.sourceRank || (!current.name && name)) {
      entriesByAddr.set(normalized, {
        addr: normalized,
        name: String(name || '').trim(),
        sourceRank,
      });
    }
  };
  sel.replaceChildren(Object.assign(document.createElement('option'), { value: '', textContent: '⊞ Vue globale' }));
  (symbols || []).filter(s =>
    s.type === 'T' &&
    s.addr && s.addr !== '0x0' &&
    parseInt(s.addr, 16) >= 0x1000 &&
    s.name && !s.name.includes('/')
  ).forEach(s => {
    appendEntry(s.addr, s.name, 30);
  });
  (window.functionListCache || []).forEach((fn) => {
    appendEntry(fn.addr, fn.name, 20);
  });
  (window.discoveredFunctionsCache || []).forEach((fn) => {
    appendEntry(fn.addr, fn.name, 10);
  });
  Array.from(entriesByAddr.values())
    .sort((a, b) => (parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0))
    .forEach((entry) => {
    const opt = document.createElement('option');
    opt.value = entry.addr;
    opt.dataset.name = entry.name || '';
    opt.textContent = `${entry.addr}  ${entry.name || ''}`.trim();
    sel.appendChild(opt);
  });
  const optionValues = Array.from(sel.options).map((opt) => opt.value);
  if (previousValue && optionValues.includes(previousValue)) {
    sel.value = previousValue;
  } else if (window._lastDisasmAddr) {
    syncDecompileSelection(window._lastDisasmAddr, { forceContext: true });
  }
  decompileUiState.selectedAddr = sel.value || '';
}

function ensureDecompileSelectionSourcesLoaded(binaryPath) {
  const bp = binaryPath || getStaticBinaryPath();
  if (!bp) return;
  if (tabDataCache.symbols?.binaryPath !== bp) {
    postBinaryAwareMessage('hubLoadSymbols', { binaryPath: bp });
  }
  if (isRawBinarySelected()) {
    if (tabDataCache.discovered?.binaryPath !== bp) {
      postBinaryAwareMessage('hubLoadDiscoveredFunctions', { binaryPath: bp });
    }
    return;
  }
  if (tabDataCache.discovered?.binaryPath !== bp) {
    postBinaryAwareMessage('hubLoadFunctions', { binaryPath: bp });
  }
}

const _DECOMPILER_LABELS = {
  ghidra:   'Ghidra headless',
  retdec:   'retdec',
  angr:     'angr',
};

const _DECOMPILER_LOCAL_PATH_SPECS = [
  {
    id: 'retdec',
    label: 'retdec',
    hint: 'Dossier d\'installation ou chemin vers retdec-decompiler',
    placeholder: '/opt/retdec',
  },
  {
    id: 'ghidra',
    label: 'Ghidra',
    hint: 'Dossier d\'installation Ghidra / libexec',
    placeholder: '/opt/ghidra',
  },
  {
    id: 'angr',
    label: 'angr',
    hint: 'Dossier Python à ajouter au PYTHONPATH',
    placeholder: '/path/to/site-packages',
  },
];

// Tracks backend availability returned by the backend registry.
let _decompilerAvailability = {};
let _decompilerMeta = {};
let _selectedDecompilerCardId = '';
let _decompilerLocalUiState = {
  visibilityById: {},
};

function _getConfiguredDecompilerProvider() {
  return String(_settingsCache?.decompilerProvider || 'auto').trim() || 'auto';
}

function _getSelectedDecompilerChoice() {
  return String(_loadStorage().decompileSource || 'auto').trim() || 'auto';
}

function _updateDecompilerActionButtons() {
  // Les boutons Modifier/Supprimer sont maintenant directement dans chaque card.
  // On garde seulement la mise à jour des boutons globaux (Ajouter, Tester).
  // Les boutons btnDecompilerEdit et btnDecompilerRemove sont cachés s'ils existent encore.
  const editBtn = document.getElementById('btnDecompilerEdit');
  const removeBtn = document.getElementById('btnDecompilerRemove');
  if (editBtn) editBtn.style.display = 'none';
  if (removeBtn) removeBtn.style.display = 'none';
}

function _getLocalPathSpecForDecompiler(id) {
  const normalized = String(id || '').trim().toLowerCase();
  return _DECOMPILER_LOCAL_PATH_SPECS.find((spec) => spec.id === normalized) || null;
}

function _describeLocalDetectionHint(id, localSpec, localPathValue) {
  if (!localSpec) return '';
  if (localPathValue) return 'Le chemin configuré est prioritaire sur l’auto-détection.';
  const normalized = String(id || '').trim().toLowerCase();
  if (normalized === 'ghidra') {
    return 'Auto-détection: GHIDRA_INSTALL_DIR / GHIDRA_HOME, puis emplacements usuels selon l’OS.';
  }
  if (normalized === 'retdec') {
    return 'Auto-détection: PATH puis RETDEC_INSTALL_DIR.';
  }
  if (normalized === 'angr') {
    return 'Auto-détection: module Python importable dans l’environnement courant.';
  }
  return 'Auto-détection via variables d’environnement, PATH et chemins usuels.';
}

function populateDecompilerProfiles(available) {
  const meta = available?._meta || {};
  const customLabels = meta.custom_labels || {};
  const dockerImages = meta.docker_images || {};
  _decompilerMeta = meta;
  _decompilerAvailability = Object.fromEntries(
    Object.entries(available || {}).filter(([key]) => !key.startsWith('_'))
  );
  const select = document.getElementById('decompileSourceSelect');
  if (!select) return;
  const previous = _getSelectedDecompilerChoice();
  const entries = Object.keys(_decompilerAvailability)
    .sort((a, b) => {
      const builtin = ['ghidra', 'retdec', 'angr'];
      const ai = builtin.indexOf(a);
      const bi = builtin.indexOf(b);
      if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      return a.localeCompare(b);
    });
  select.replaceChildren();
  select.appendChild(Object.assign(document.createElement('option'), {
    value: 'auto',
    textContent: 'Auto',
  }));
  entries.forEach((id) => {
    const option = document.createElement('option');
    const label = customLabels[id] || _DECOMPILER_LABELS[id] || id;
    const availableNow = !!_decompilerAvailability[id];
    option.value = id;
    option.textContent = availableNow ? label : `${label} indisponible`;
    option.disabled = !availableNow;
    select.appendChild(option);
  });
  const titleParts = [`Provider ${_getConfiguredDecompilerProvider()}`];
  const selectedId = previous !== 'auto' ? previous : '';
  if (selectedId && dockerImages[selectedId]) titleParts.push(`Docker ${dockerImages[selectedId]}`);
  select.title = titleParts.filter(Boolean).join(' • ');
  const validValues = new Set(Array.from(select.options).filter((opt) => !opt.disabled).map((opt) => opt.value));
  select.value = validValues.has(previous) ? previous : 'auto';
  if (select.value !== previous) _saveStorage({ decompileSource: select.value });
  _updateDecompilerActionButtons();
}

function updateDecompileSearchUi(count = null) {
  const input = document.getElementById('decompileSearchInput');
  const label = document.getElementById('decompileSearchCount');
  const prevBtn = document.getElementById('btnDecompileSearchPrev');
  const nextBtn = document.getElementById('btnDecompileSearchNext');
  if (input && input.value !== decompileUiState.searchQuery) input.value = decompileUiState.searchQuery || '';
  const resolvedCount = typeof count === 'number'
    ? count
    : document.querySelectorAll('#decompileContent .decompile-search-hit').length;
  if (prevBtn) prevBtn.disabled = resolvedCount <= 1;
  if (nextBtn) nextBtn.disabled = resolvedCount <= 1;
  if (!label) return;
  const query = String(decompileUiState.searchQuery || '').trim();
  if (!query) {
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    label.textContent = 'Recherche inactive';
    return;
  }
  if (typeof resolvedCount === 'number') {
    if (resolvedCount <= 0) {
      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = true;
      label.textContent = 'Aucun hit';
      return;
    }
    const active = Number.isFinite(decompileUiState.activeSearchHit) && decompileUiState.activeSearchHit >= 0
      ? decompileUiState.activeSearchHit + 1
      : 1;
    label.textContent = `${Math.min(active, resolvedCount)}/${resolvedCount}`;
    return;
  }
  label.textContent = 'Recherche…';
}

function isTypingElement(node) {
  const el = node?.nodeType === 1 ? node : node?.parentElement;
  if (!el) return false;
  const tag = String(el.tagName || '').toUpperCase();
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || Boolean(el.isContentEditable);
}

function focusDecompileSearchInput(opts = {}) {
  const input = document.getElementById('decompileSearchInput');
  if (!input) return false;
  input.focus();
  if (opts.select !== false && typeof input.select === 'function') input.select();
  return true;
}

function _setActiveDecompilerSource(source) {
  const normalized = String(source || 'auto').trim() || 'auto';
  const select = document.getElementById('decompileSourceSelect');
  if (select && select.value !== normalized) select.value = normalized;
  _saveStorage({ decompileSource: normalized });
  _updateDecompilerActionButtons();
}

function _getActiveDecompilerSource() {
  const select = document.getElementById('decompileSourceSelect');
  return String(select?.value || _loadStorage().decompileSource || 'auto').trim() || 'auto';
}

function _normalizeDecompileQuality(quality) {
  const normalized = String(quality || decompileUiState.quality || 'normal').trim().toLowerCase();
  if (normalized === 'max' || normalized === 'precision') return 'precision';
  return 'normal';
}

function _formatDecompileQualityLabel(quality) {
  const normalized = _normalizeDecompileQuality(quality);
  if (normalized === 'precision') return 'Précision';
  return 'Rapide';
}

function _getRequestedDecompilerForQuality(quality) {
  const source = _getActiveDecompilerSource();
  if (!source || source === 'auto') return '';
  return source;
}

function getDecompileSelectionContext() {
  const sel = document.getElementById('decompileAddrSelect');
  return {
    sel,
    addr: sel?.value || '',
    funcName: sel?.options[sel.selectedIndex]?.dataset?.name || '',
  };
}

function syncDecompileSelection(addr, options = {}) {
  const sel = document.getElementById('decompileAddrSelect');
  if (!sel) return '';
  const optionAddrs = Array.from(sel.options).map((opt) => opt.value).filter(Boolean);
  const currentValue = sel.value || decompileUiState.selectedAddr || '';
  const preserveManual = options.forceContext !== true
    && decompileUiState.selectionMode === 'manual'
    && currentValue
    && optionAddrs.includes(currentValue);
  if (preserveManual) {
    if (sel.value !== currentValue) sel.value = currentValue;
    decompileUiState.selectedAddr = currentValue;
    return decompileUiState.selectedAddr;
  }
  const targetAddr = findNearestFunctionStart(addr, optionAddrs)
    || (optionAddrs.includes(decompileUiState.selectedAddr) ? decompileUiState.selectedAddr : '');
  if (targetAddr && sel.value !== targetAddr) sel.value = targetAddr;
  if (options.forceContext === true) {
    decompileUiState.selectionMode = 'context';
    _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  }
  decompileUiState.selectedAddr = sel.value || '';
  return decompileUiState.selectedAddr;
}

function updateDecompileHistoryControls() {
  const backBtn = document.getElementById('btnDecompileBack');
  const forwardBtn = document.getElementById('btnDecompileForward');
  const label = document.getElementById('decompileHistoryLabel');
  const { entries, index } = decompileHistoryState;
  const prev = index > 0 ? entries[index - 1] : null;
  const next = index >= 0 && index < entries.length - 1 ? entries[index + 1] : null;
  if (backBtn) {
    backBtn.disabled = !prev;
    backBtn.title = prev ? `Revenir à ${prev.label}` : 'Aucun élément précédent';
  }
  if (forwardBtn) {
    forwardBtn.disabled = !next;
    forwardBtn.title = next ? `Avancer vers ${next.label}` : 'Aucun élément suivant';
  }
  if (label) {
    const current = index >= 0 ? entries[index] : null;
    label.textContent = current ? `Courant: ${current.label}` : 'Historique vide';
  }
}

function resetDecompileHistory() {
  decompileHistoryState = {
    entries: [],
    index: -1,
  };
  updateDecompileHistoryControls();
}

function pushDecompileHistoryEntry(entry) {
  if (!entry?.binaryPath) {
    updateDecompileHistoryControls();
    return;
  }
  const current = decompileHistoryState.index >= 0
    ? decompileHistoryState.entries[decompileHistoryState.index]
    : null;
  const isSameAsCurrent = !!current
    && current.binaryPath === entry.binaryPath
    && current.decompiler === entry.decompiler
    && (current.provider || 'auto') === (entry.provider || 'auto')
    && _normalizeDecompileQuality(current.quality || 'normal') === _normalizeDecompileQuality(entry.quality || 'normal')
    && current.addr === entry.addr
    && current.full === entry.full;
  if (isSameAsCurrent) {
    current.label = entry.label;
    updateDecompileHistoryControls();
    return;
  }
  if (decompileHistoryState.index < decompileHistoryState.entries.length - 1) {
    decompileHistoryState.entries = decompileHistoryState.entries.slice(0, decompileHistoryState.index + 1);
  }
  decompileHistoryState.entries.push(entry);
  if (decompileHistoryState.entries.length > 24) {
    decompileHistoryState.entries.shift();
  }
  decompileHistoryState.index = decompileHistoryState.entries.length - 1;
  updateDecompileHistoryControls();
}

function applyDecompileHistoryStep(delta) {
  const nextIndex = decompileHistoryState.index + delta;
  const entry = decompileHistoryState.entries[nextIndex];
  if (!entry) {
    updateDecompileHistoryControls();
    return;
  }
  if (entry.binaryPath && entry.binaryPath !== getStaticBinaryPath()) {
    resetDecompileHistory();
    return;
  }
  decompileHistoryState.index = nextIndex;
  const select = document.getElementById('decompileAddrSelect');
  if (select) select.value = entry.addr || '';
  if (entry.decompiler) _setActiveDecompilerSource(entry.decompiler);
  const qualitySelect = document.getElementById('decompileQualitySelect');
  if (qualitySelect && entry.quality) {
    qualitySelect.value = _normalizeDecompileQuality(entry.quality);
  }
  decompileUiState.quality = _normalizeDecompileQuality(entry.quality || 'normal');
  _saveStorage({ decompileQuality: decompileUiState.quality });
  decompileUiState.selectedAddr = entry.addr || '';
  updateDecompileHistoryControls();
  requestDecompileForCurrentSelection({ skipHistory: true });
}

function buildDecompileHistoryEntry(binaryPath, decompiler, quality, addr, funcName) {
  return {
    binaryPath,
    decompiler,
    provider: _getConfiguredDecompilerProvider(),
    quality: _normalizeDecompileQuality(quality || 'normal'),
    addr: addr || '',
    full: !addr,
    label: funcName || (addr ? addr : 'Vue globale'),
  };
}

function rerenderCurrentDecompileFromCache() {
  const container = document.getElementById('decompileContent');
  if (!container) return false;
  const bp = getStaticBinaryPath() || '';
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr } = getDecompileSelectionContext();
  const full = !addr;
  if (!bp) return false;
  const cached = getCachedDecompileResult(buildDecompileRequestKey(bp, decompiler, quality, addr, full, provider, funcName));
  if (!cached) return false;
  renderDecompilePayload(container, cached);
  return true;
}

function requestDecompileForCurrentSelection(options = {}) {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const container = document.getElementById('decompileContent');
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr, funcName } = getDecompileSelectionContext();
  const full = !addr;
  const requestKey = buildDecompileRequestKey(bp, decompiler, quality, addr, full, provider, funcName);
  if (!options.preserveStackEntry && !decompileUiState.pendingStackEntryName) {
    decompileUiState.activeStackEntryName = '';
    decompileUiState.pendingStackEntryName = '';
  }
  decompileUiState.quality = quality;
  _saveStorage({ decompileQuality: quality });
  decompileUiState.selectedAddr = addr || '';
  _saveStorage({ decompileAddr: decompileUiState.selectedAddr || '' });
  tabDataCache.decompile = null;
  if (!options.skipHistory) {
    pushDecompileHistoryEntry(buildDecompileHistoryEntry(bp, decompiler, quality, addr, funcName));
  }
  const cached = getCachedDecompileResult(requestKey);
  if (cached && container) {
    renderDecompilePayload(container, cached);
    return;
  }
  if (pendingDecompileRequests.has(requestKey)) return;
  pendingDecompileRequests.add(requestKey);
  cancelPendingDecompileHighlight();
  setStaticLoading('decompileContent', 'Décompilation en cours…');
  if (addr) {
    vscode.postMessage({ type: 'hubLoadDecompile', binaryPath: bp, addr, funcName, full: false, decompiler, quality, provider });
  } else {
    vscode.postMessage({ type: 'hubLoadDecompile', binaryPath: bp, full: true, decompiler, quality, provider });
  }
}

function _onDecompilerSourceChange() {
  const source = _getActiveDecompilerSource();
  const targetDecompiler = _getRequestedDecompilerForQuality(
    document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal'
  );
  if (targetDecompiler && _decompilerAvailability[targetDecompiler] === false) {
    vscode.postMessage({ type: 'hubInstallDecompiler', tool: targetDecompiler });
    return;
  }
  _setActiveDecompilerSource(source);
  syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
  requestDecompileForCurrentSelection();
}

function loadHexView(binaryPath, offset, length) {
  if (offset !== undefined) hexCurrentOffset = offset;
  if (length !== undefined) hexCurrentLength = length;
  resetHexDomState();
  window._lastHexRows = [];
  hexRenderInProgress = false;
  updateHexRenderStatus(0, 0, false);
  const container = document.getElementById('hexContent');
  if (container) {
    container.replaceChildren();
    const hint = document.createElement('p');
    hint.className = 'hint';
    hint.textContent = 'Chargement\u2026';
    container.appendChild(hint);
  }
  vscode.postMessage({
    type: 'hubLoadHexView',
    binaryPath,
    offset: hexCurrentOffset,
    length: hexCurrentLength,
  });
}

// ── Compilateur GCC ──────────────────────────────────────────
function _buildGccCommand() {
  const src   = document.getElementById('gccSourcePath')?.value?.trim() || 'source.c';
  const out   = document.getElementById('gccOutputPath')?.value?.trim() || 'a.out';
  const arch  = document.getElementById('gccArch')?.value || '64';
  const optim = document.getElementById('gccOptim')?.value || '-O0';
  const debug = document.getElementById('gccDebug')?.value || '';
  const pie   = document.getElementById('gccPie')?.value || 'no';
  const canary   = document.getElementById('gccCanary')?.value || 'off';
  const execstack = document.getElementById('gccExecstack')?.checked;
  const relro    = document.getElementById('gccRelro')?.value || 'off';
  const isStatic = document.getElementById('gccStatic')?.checked;
  const strip    = document.getElementById('gccStrip')?.checked;
  const extra    = document.getElementById('gccExtraFlags')?.value?.trim() || '';

  const f = ['gcc'];
  if (arch === '32') f.push('-m32');
  f.push(optim);
  if (debug) f.push(debug);
  if (canary === 'off')    f.push('-fno-stack-protector');
  else if (canary === 'basic')  f.push('-fstack-protector');
  else if (canary === 'strong') f.push('-fstack-protector-strong');
  else if (canary === 'all')    f.push('-fstack-protector-all');
  if (execstack) f.push('-z', 'execstack');
  if (pie === 'no') f.push('-fno-pie', '-no-pie');
  else              f.push('-fpie', '-pie');
  if (relro === 'partial') f.push('-Wl,-z,relro');
  else if (relro === 'full') f.push('-Wl,-z,relro,-z,now');
  if (isStatic) f.push('-static');
  if (strip)    f.push('-s');
  if (extra)    f.push(...extra.split(/\s+/).filter(Boolean));
  f.push('-o', out, src);

  const preview = document.getElementById('compilerCmdPreview');
  if (preview) preview.textContent = f.join(' ');
}

[
  'gccSourcePath', 'gccOutputPath', 'gccExtraFlags'
].forEach((id) => document.getElementById(id)?.addEventListener('input', _buildGccCommand));
[
  'gccArch', 'gccOptim', 'gccDebug', 'gccPie', 'gccCanary', 'gccRelro'
].forEach((id) => document.getElementById(id)?.addEventListener('change', _buildGccCommand));
[
  'gccExecstack', 'gccStatic', 'gccStrip'
].forEach((id) => document.getElementById(id)?.addEventListener('change', _buildGccCommand));

document.getElementById('compilerCmdPreview')?.addEventListener('click', () => {
  const txt = document.getElementById('compilerCmdPreview')?.textContent || '';
  if (txt) navigator.clipboard?.writeText(txt);
});

document.getElementById('btnCompileGcc')?.addEventListener('click', () => {
  const sourcePath = document.getElementById('gccSourcePath')?.value?.trim() || '';
  const outputPath = document.getElementById('gccOutputPath')?.value?.trim() || '';
  if (!sourcePath) { vscode.postMessage({ type: 'hubError', message: 'Source C requise.' }); return; }
  if (!outputPath) { vscode.postMessage({ type: 'hubError', message: 'Binaire de sortie requis.' }); return; }
  const btn = document.getElementById('btnCompileGcc');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }
  vscode.postMessage({
    type: 'hubCompileStaticBinary',
    sourcePath,
    binaryPath: outputPath,
    archBits:   document.getElementById('gccArch')?.value || '64',
    optim:      document.getElementById('gccOptim')?.value || '-O0',
    debug:      document.getElementById('gccDebug')?.value || '-g',
    pieChoice:  document.getElementById('gccPie')?.value || 'no',
    canary:     document.getElementById('gccCanary')?.value || 'off',
    execstack:  document.getElementById('gccExecstack')?.checked !== false,
    relro:      document.getElementById('gccRelro')?.value || 'off',
    static:     document.getElementById('gccStatic')?.checked === true,
    strip:      document.getElementById('gccStrip')?.checked === true,
    extraFlags: document.getElementById('gccExtraFlags')?.value?.trim() || '',
    useLegacyFlags: false,
  });
});

_buildGccCommand();

staticBinaryInput?.addEventListener('change', () => {
  syncDynamicBinaryFieldMode();
  syncStaticWorkspaceSummary();
});

document.getElementById('btnChangeBinary')?.addEventListener('click', () => {
  pendingStaticQuickAction = '';
  vscode.postMessage({ type: 'requestBinarySelection' });
});
document.getElementById('btnStaticQuickDisasm')?.addEventListener('click', () => {
  triggerStaticQuickAction('disasm');
});
document.getElementById('btnStaticQuickFunctions')?.addEventListener('click', () => {
  triggerStaticQuickAction('functions');
});
document.getElementById('btnStaticQuickStrings')?.addEventListener('click', () => {
  triggerStaticQuickAction('strings');
});
document.getElementById('btnStaticQuickHex')?.addEventListener('click', () => {
  triggerStaticQuickAction('hex');
});

document.getElementById('btnDynamicSelectBinary')?.addEventListener('click', () => {
  setDynamicTraceStatus('Sélection du binaire...');
  vscode.postMessage({ type: 'requestBinarySelection' });
});

document.getElementById('btnDynamicSelectSource')?.addEventListener('click', () => {
  setDynamicTraceStatus('Sélection du fichier C...');
  vscode.postMessage({ type: 'hubPickFile', target: 'dynamicSourcePath', fileType: 'sourceC' });
});

btnRefreshDynamicTraceHistory?.addEventListener('click', () => {
  setDynamicTraceStatus('Actualisation des traces...');
  requestDynamicTraceHistory();
});

btnClearDynamicTraceHistory?.addEventListener('click', () => {
  setDynamicTraceStatus('Nettoyage des anciennes traces...');
  vscode.postMessage({ type: 'clearDynamicTraceHistory' });
});

dynamicSourcePathInput?.addEventListener('input', () => {
  dynamicTraceInitState.sourcePath = dynamicSourcePathInput.value.trim();
  if (!dynamicTraceInitState.sourcePath) {
    dynamicTraceInitState.sourceEnrichmentEnabled = false;
    dynamicTraceInitState.sourceEnrichmentStatus = '';
    dynamicTraceInitState.sourceEnrichmentMessage = '';
  } else if (dynamicTraceInitState.sourceEnrichmentEnabled !== true) {
    dynamicTraceInitState.sourceEnrichmentStatus = 'pending';
    dynamicTraceInitState.sourceEnrichmentMessage = '';
  }
  if (dynamicSourceHint) dynamicSourceHint.textContent = buildDynamicSourceHintText(dynamicTraceInitState);
  updateArgvPayloadHint();
});

dynamicSourcePathInput?.addEventListener('blur', () => {
  requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
});


// Auto-load tab content when navigating (uses cache to avoid re-fetching)
function _autoLoadTab(t) {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  if (isRawBinarySelected() && markRawTabUnavailable(t)) {
    tabDataCache[t] = { binaryPath: bp };
    return;
  }
  const allTabIds = Object.values(GROUPS).flat();
  const cacheHit = allTabIds.includes(t) && tabDataCache[t]?.binaryPath === bp;
  if (cacheHit) return;

  if (t === 'disasm') {
    postBinaryAwareMessage('hubOpenDisasm', { binaryPath: bp, useCache: true, openInEditor: false });
  } else if (t === 'sections') {
    setStaticLoading('sectionsContent', 'Chargement sections…');
    postBinaryAwareMessage('hubLoadSections', { binaryPath: bp });
  } else if (t === 'info') {
    setStaticLoading('infoContent', 'Chargement infos…');
    postBinaryAwareMessage('hubLoadInfo', { binaryPath: bp });
  } else if (t === 'symbols') {
    setStaticLoading('symbolsContent', 'Chargement symboles…');
    postBinaryAwareMessage('hubLoadSymbols', { binaryPath: bp });
  } else if (t === 'strings') {
    const enc = document.getElementById('stringsEncoding')?.value || 'auto';
    const sec = document.getElementById('stringsSection')?.value || '';
    setStaticLoading('stringsContent', 'Chargement strings…');
    const minLen = parseInt(document.getElementById('stringsMinLen')?.value || '4', 10);
    postBinaryAwareMessage('hubLoadStrings', { binaryPath: bp, minLen, encoding: enc, section: sec || undefined });
  } else if (t === 'cfg') {
    setStaticLoading('cfgContent', 'Chargement CFG…');
    postBinaryAwareMessage('hubLoadCfg', { binaryPath: bp });
  } else if (t === 'callgraph') {
    setStaticLoading('callgraphContent', 'Chargement call graph…');
    postBinaryAwareMessage('hubLoadCallGraph', { binaryPath: bp });
  } else if (t === 'discovered') {
    setStaticLoading('functionsContent', 'Chargement fonctions…');
    postBinaryAwareMessage(isRawBinarySelected() ? 'hubLoadDiscoveredFunctions' : 'hubLoadFunctions', { binaryPath: bp });
  } else if (t === 'detection') {
    const unsupportedCapa = getCapaUnsupportedReason();
    if (unsupportedCapa) {
      renderCapaUnsupported(unsupportedCapa);
      tabDataCache.detection = { binaryPath: bp };
    } else {
      setStaticLoading('capaContent', 'Analyse Capa…');
      postBinaryAwareMessage('hubCapaScan', { binaryPath: bp });
    }
    vscode.postMessage({ type: 'hubListRules' });
  } else if (t === 'behavior') {
    setStaticLoading('behaviorContent', 'Analyse comportementale…');
    postBinaryAwareMessage('hubLoadBehavior', { binaryPath: bp });
  } else if (t === 'taint') {
    setStaticLoading('taintContent', 'Analyse taint…');
    postBinaryAwareMessage('hubLoadTaint', { binaryPath: bp });
  } else if (t === 'rop') {
    setStaticLoading('ropContent', 'Recherche ROP…');
    postBinaryAwareMessage('hubLoadRop', { binaryPath: bp });
  } else if (t === 'vulns') {
    setStaticLoading('vulnsContent', 'Détection vulnérabilités…');
    postBinaryAwareMessage('hubLoadVulns', { binaryPath: bp });
  } else if (t === 'decompile') {
    setStaticLoading('decompileContent', 'Décompilation…');
    vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
    ensureDecompileSelectionSourcesLoaded(bp);
    syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
    requestDecompileForCurrentSelection();
  } else if (t === 'anti_analysis') {
    setStaticLoading('antiAnalysisContent', 'Analyse anti-analyse…');
    postBinaryAwareMessage('hubLoadAntiAnalysis', { binaryPath: bp });
  } else if (t === 'imports') {
    setStaticLoading('importsContent', 'Analyse imports…');
    setStaticLoading('exportsContent', 'Chargement exports…');
    postBinaryAwareMessage('hubLoadImports', { binaryPath: bp });
    postBinaryAwareMessage('hubLoadExports', { binaryPath: bp });
  } else if (t === 'flirt') {
    setStaticLoading('flirtContent', 'Signatures FLIRT…');
    postBinaryAwareMessage('hubLoadFlirt', { binaryPath: bp });
  } else if (t === 'deobfuscate') {
    setStaticLoading('deobfuscateContent', 'Déobfuscation strings…');
    postBinaryAwareMessage('hubLoadDeobfuscate', { binaryPath: bp });
  } else if (t === 'hex') {
    if (bp && !tabDataCache.hex) loadHexView(bp, 0, hexCurrentLength);
    if (bp && !(tabDataCache.patchList && tabDataCache.patchList.binaryPath === bp)) {
      tabDataCache.patchList = { binaryPath: bp };
      postBinaryAwareMessage('hubLoadPatches', { binaryPath: bp });
    }
  } else if (t === 'stack') {
    syncStackFrameForContext(window._lastDisasmAddr || decompileUiState.selectedAddr);
  } else if (t === 'pe_resources') {
    setStaticLoading('peResourcesContent', 'Extraction ressources PE\u2026');
    postBinaryAwareMessage('hubLoadPeResources', { binaryPath: bp });
  } else if (t === 'exceptions') {
    setStaticLoading('exceptionsContent', 'Chargement gestionnaires d\'exceptions\u2026');
    postBinaryAwareMessage('hubLoadExceptionHandlers', { binaryPath: bp });
  } else if (t === 'typed_data') {
    setStaticLoading('typedDataContent', 'Analyse des donn\u00e9es\u2026');
    vscode.postMessage(buildTypedDataRequest(bp));
  }
}

// Static: disasm, symbols, strings, cfg
document.getElementById('btnOpenDisasm')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  const syntax = document.getElementById('disasmSyntax')?.value || 'intel';
  const section = document.getElementById('disasmSection')?.value?.trim() || '';
  const binaryMeta = _selectedRawArchMeta();
  if (binaryMeta?.kind === 'raw') {
    currentBinaryMeta = binaryMeta;
    saveBinarySelection(bp, binaryMeta);
  }
  const useCache = document.getElementById('useCache')?.checked !== false;
  vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, binaryMeta, syntax, section, useCache });
});

document.getElementById('btnGoToMain')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: 'main' });
});

document.getElementById('btnGoToStart')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: '_start' });
});

document.getElementById('btnGoToEntry')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: '__entry__' });
});

document.getElementById('btnGoToSymbol')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  const sym = document.getElementById('navSymbolSelect')?.value?.trim();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  if (!sym) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un symbole.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: sym });
});

function applyStringsFilter() {
  const container = document.getElementById('stringsContent');
  if (!container || stringsCache.length === 0) return;
  renderStringsTable(container, stringsCache, '', false);
}

function reloadStrings() {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  setStaticLoading('stringsContent', 'Chargement des strings…');
  const enc = document.getElementById('stringsEncoding')?.value || 'auto';
  const sec = document.getElementById('stringsSection')?.value || '';
  const minLen = parseInt(document.getElementById('stringsMinLen')?.value || '4', 10);
  vscode.postMessage({ type: 'hubLoadStrings', binaryPath: bp, minLen, encoding: enc, section: sec || undefined });
}
document.getElementById('stringsEncoding')?.addEventListener('change', reloadStrings);
document.getElementById('stringsSection')?.addEventListener('change', reloadStrings);
document.getElementById('stringsMinLen')?.addEventListener('change', reloadStrings);
// ── Recherche : mode pills (A) ───────────────────────────────────────────────
let searchMode = 'text';
const modePills = document.querySelectorAll('.search-mode-pill');
modePills.forEach(pill => {
  pill.addEventListener('click', () => {
    modePills.forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    searchMode = pill.dataset.mode;
  });
});

// ── Recherche : history localStorage (B) ─────────────────────────────────────
const HISTORY_KEY = 'pof-search-history';
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}
function saveHistory(entries) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
}
function addToHistory(pattern, mode) {
  if (!pattern) return;
  let h = loadHistory().filter(e => !(e.pattern === pattern && e.mode === mode));
  h.unshift({ pattern, mode, ts: Date.now() });
  if (h.length > 10) h = h.slice(0, 10);
  saveHistory(h);
}

const historyDropdown = document.getElementById('searchHistoryDropdown');
function renderHistoryDropdown() {
  const h = loadHistory();
  if (!historyDropdown) return;
  if (!h.length) { historyDropdown.hidden = true; return; }
  historyDropdown.innerHTML = '';
  h.forEach((entry, i) => {
    const item = document.createElement('div');
    item.className = 'search-history-item';
    const label = document.createElement('span');
    label.textContent = `[${entry.mode}] ${entry.pattern}`;
    label.style.cursor = 'pointer';
    label.addEventListener('click', () => {
      const inp = document.getElementById('searchBinaryPattern');
      if (inp) inp.value = entry.pattern;
      if (entry.mode) {
        modePills.forEach(p => {
          p.classList.toggle('active', p.dataset.mode === entry.mode);
        });
        searchMode = entry.mode;
      }
      historyDropdown.hidden = true;
    });
    const del = document.createElement('button');
    del.className = 'search-history-item-delete';
    del.textContent = '×';
    del.title = 'Supprimer';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      let h2 = loadHistory();
      h2.splice(i, 1);
      saveHistory(h2);
      renderHistoryDropdown();
    });
    item.appendChild(label);
    item.appendChild(del);
    historyDropdown.appendChild(item);
  });
  historyDropdown.hidden = false;
}
document.getElementById('searchBinaryPattern')?.addEventListener('focus', renderHistoryDropdown);
document.addEventListener('click', (e) => {
  if (!historyDropdown) return;
  if (!historyDropdown.contains(e.target) && e.target !== document.getElementById('searchBinaryPattern')) {
    historyDropdown.hidden = true;
  }
});

// ── Recherche : filters toggle (C) ───────────────────────────────────────────
const filtersToggle = document.getElementById('searchFiltersToggle');
const filtersPanel = document.getElementById('searchFiltersPanel');
if (filtersToggle && filtersPanel) {
  filtersToggle.addEventListener('click', () => {
    const hidden = filtersPanel.hidden;
    filtersPanel.hidden = !hidden;
    filtersToggle.textContent = hidden ? '▴ Filtres avancés' : '▾ Filtres avancés';
  });
}

// ── Recherche : execution (D) ─────────────────────────────────────────────────
function doSearch() {
  const pattern = document.getElementById('searchBinaryPattern')?.value?.trim();
  if (!pattern) return;
  addToHistory(pattern, searchMode);
  if (historyDropdown) historyDropdown.hidden = true;

  const caseSensitive = document.getElementById('searchCaseSensitive')?.checked || false;
  const minLengthVal = document.getElementById('searchMinLength')?.value || '';
  const maxLengthVal = document.getElementById('searchMaxLength')?.value || '';
  const offsetStartVal = (document.getElementById('searchOffsetStart')?.value || '').trim();
  const offsetEndVal = (document.getElementById('searchOffsetEnd')?.value || '').trim();

  const msg = {
    type: 'hubSearchBinary',
    pattern,
    mode: searchMode,
    caseSensitive,
    binaryPath: getStaticBinaryPath(),
    binaryMeta: getCurrentBinaryMeta(),
  };
  if (minLengthVal) msg.minLength = parseInt(minLengthVal, 10);
  if (maxLengthVal) msg.maxLength = parseInt(maxLengthVal, 10);
  if (offsetStartVal) msg.offsetStart = parseInt(offsetStartVal, 0);
  if (offsetEndVal) msg.offsetEnd = parseInt(offsetEndVal, 0);

  vscode.postMessage(msg);
}
document.getElementById('btnSearchBinary')?.addEventListener('click', doSearch);
document.getElementById('searchBinaryPattern')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); doSearch(); }
});

// ── Recherche : export CSV/JSON (F) ──────────────────────────────────────────
document.getElementById('btnSearchExportCsv')?.addEventListener('click', () => {
  const rows = window._searchResults || [];
  const header = 'Offset,Valeur,Taille,Contexte\n';
  const body = rows.map(r => `${r.offset_hex},${JSON.stringify(String(r.value))},${r.length},${JSON.stringify(String(r.context))}`).join('\n');
  const blob = new Blob([header + body], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'search-results.csv'; a.click();
  URL.revokeObjectURL(url);
});
document.getElementById('btnSearchExportJson')?.addEventListener('click', () => {
  const rows = window._searchResults || [];
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'search-results.json'; a.click();
  URL.revokeObjectURL(url);
});

function _renderRulesList(containerId, rules) {
  const container = document.getElementById(containerId);
  if (!container) return;
  while (container.firstChild) container.removeChild(container.firstChild);

  if (!rules.length) {
    const hint = document.createElement('p');
    hint.className = 'hint-sm rules-empty-hint';
    hint.textContent = 'Aucune règle — cliquez + pour en ajouter.';
    container.appendChild(hint);
    return;
  }

  rules.forEach(function(rule) {
    const row = document.createElement('div');
    row.className = 'rule-item';
    row.dataset.ruleId = rule.id;
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:4px 0';

    const labelEl = document.createElement('label');
    labelEl.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:pointer;flex:1';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'rule-toggle-cb';
    cb.dataset.ruleId = rule.id;
    cb.checked = rule.enabled;
    cb.addEventListener('change', function() {
      vscode.postMessage({ type: 'hubToggleRule', ruleId: rule.id, enabled: cb.checked });
    });

    const nameSpan = document.createElement('span');
    nameSpan.className = 'rule-item-name';
    nameSpan.textContent = rule.name;

    labelEl.appendChild(cb);
    labelEl.appendChild(nameSpan);

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn-rule-delete';
    delBtn.title = 'Supprimer';
    delBtn.textContent = '🗑';
    delBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:2px 6px;opacity:0.6';
    delBtn.addEventListener('mouseenter', function() { delBtn.style.opacity = '1'; });
    delBtn.addEventListener('mouseleave', function() { delBtn.style.opacity = '0.6'; });
    delBtn.addEventListener('click', function() {
      if (!confirm('Supprimer la règle ' + rule.name + ' ?')) return;
      vscode.postMessage({ type: 'hubDeleteUserRule', ruleId: rule.id });
    });

    row.appendChild(labelEl);
    row.appendChild(delBtn);
    container.appendChild(row);
  });
}

function updateDetectionSummaries() {
  const capaEl = document.getElementById('capaSummaryCount');
  const yaraEl = document.getElementById('yaraSummaryCount');
  if (capaEl) {
    capaEl.textContent = detectionUiState.capaError
      ? 'Erreur'
      : String(detectionUiState.capaCapabilities.length || 0);
  }
  if (yaraEl) {
    const hitCount = detectionUiState.yaraMatches.reduce((acc, rule) => acc + (rule.matches || []).length, 0);
    yaraEl.textContent = detectionUiState.yaraError ? 'Erreur' : String(hitCount || 0);
  }
}

function getCapaUnsupportedReason() {
  const meta = getCurrentBinaryMeta();
  const format = String(meta?.format || '').trim().toUpperCase();
  if (!format) return '';
  if (format.includes('MACH')) {
    return 'CAPA analyse les exécutables PE et ELF. Le binaire actif est un Mach-O macOS, donc lance plutôt YARA ici ou charge un binaire Linux/Windows pour CAPA.';
  }
  if (format === 'RAW') {
    return 'CAPA a besoin d’un exécutable PE ou ELF complet. Les blobs bruts restent analysables avec YARA, Hex, Strings et Désassemblage.';
  }
  return '';
}

function renderCapaUnsupported(reason = getCapaUnsupportedReason()) {
  detectionUiState.capaCapabilities = [];
  detectionUiState.capaError = '';
  updateDetectionSummaries();
  const container = document.getElementById('capaContent');
  if (container) {
    container.innerHTML = detectionEmptyHtml('CAPA non disponible pour ce format', reason);
  }
}

function detectionEmptyHtml(title, desc) {
  return `<div class="detection-empty"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(desc)}</span></div>`;
}

function renderCapaResults() {
  const container = document.getElementById('capaContent');
  if (!container) return;
  updateDetectionSummaries();
  if (detectionUiState.capaError) {
    container.innerHTML = detectionEmptyHtml('Erreur CAPA', detectionUiState.capaError);
    return;
  }
  const allCaps = detectionUiState.capaCapabilities || [];
  const query = String(document.getElementById('capaFilterInput')?.value || '').trim().toLowerCase();
  const namespaceSelect = document.getElementById('capaNamespaceFilter');
  const requestedNamespace = String(namespaceSelect?.value || '').trim();
  if (namespaceSelect) {
    const namespaces = Array.from(new Set(allCaps.map((cap) => String(cap.namespace || '').trim()).filter(Boolean))).sort();
    namespaceSelect.replaceChildren(new Option('Tous les namespaces', ''));
    namespaces.forEach((ns) => namespaceSelect.appendChild(new Option(ns, ns)));
    namespaceSelect.value = namespaces.includes(requestedNamespace) ? requestedNamespace : '';
  }
  const namespace = String(namespaceSelect?.value || '').trim();
  const caps = allCaps.filter((cap) => {
    const haystack = `${cap.name || ''} ${cap.namespace || ''} ${cap.matches || ''}`.toLowerCase();
    if (namespace && String(cap.namespace || '') !== namespace) return false;
    return !query || haystack.includes(query);
  });
  if (!allCaps.length) {
    container.innerHTML = detectionEmptyHtml('Aucune capacité détectée', 'Le scan CAPA est terminé sans match exploitable.');
    return;
  }
  if (!caps.length) {
    container.innerHTML = detectionEmptyHtml('Aucun résultat filtré', 'Change le filtre ou le namespace pour revoir les capacités.');
    return;
  }
  const rows = caps.map(c => `<tr><td><code>${escapeHtml(c.name || '')}</code></td><td>${escapeHtml(c.namespace || '')}</td><td>${escapeHtml((c.matches || '').substring(0, 90))}</td></tr>`).join('');
  container.innerHTML = `<div class="detection-results-header"><span class="detection-results-count">${caps.length} / ${allCaps.length} capacité(s)</span></div><table class="data-table"><thead><tr><th>Capacité</th><th>Namespace</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderYaraResults() {
  const container = document.getElementById('yaraContent');
  if (!container) return;
  updateDetectionSummaries();
  if (detectionUiState.yaraError) {
    container.innerHTML = detectionEmptyHtml('Erreur YARA', detectionUiState.yaraError);
    return;
  }
  const allMatches = detectionUiState.yaraMatches || [];
  const query = String(document.getElementById('yaraFilterInput')?.value || '').trim().toLowerCase();
  const filteredRules = allMatches
    .map((rule) => ({
      ...rule,
      matches: (rule.matches || []).filter((match) => {
        const haystack = `${rule.rule || ''} ${match.offset_hex || ''} ${match.matched || ''}`.toLowerCase();
        return !query || haystack.includes(query);
      }),
    }))
    .filter((rule) => (rule.matches || []).length > 0);
  const totalHits = allMatches.reduce((acc, r) => acc + (r.matches || []).length, 0);
  const filteredHits = filteredRules.reduce((acc, r) => acc + (r.matches || []).length, 0);
  if (!totalHits) {
    container.innerHTML = detectionEmptyHtml('Aucune règle ne correspond', 'Le scan YARA est terminé sans signature détectée.');
    return;
  }
  if (!filteredHits) {
    container.innerHTML = detectionEmptyHtml('Aucun résultat filtré', 'Change le filtre pour revoir les correspondances YARA.');
    return;
  }
  const rows = filteredRules.flatMap(r => (r.matches || []).map(m => {
    const hex = escapeHtml((m.matched || '').substring(0, 64));
    return `<tr><td><code class="addr-link" data-addr="${escapeHtml(m.offset_hex)}">${escapeHtml(m.offset_hex)}</code></td><td><span class="yara-rule-badge">${escapeHtml(r.rule)}</span></td><td><code class="yara-match-hex" title="${escapeHtml(m.matched || '')}">${hex}</code></td></tr>`;
  })).join('');
  container.innerHTML = `<div class="yara-results-header"><span class="yara-results-count">${filteredHits} / ${totalHits} correspondance(s) — ${filteredRules.length} règle(s)</span><span class="hint">Clic sur l'offset → navigation</span></div><table class="data-table"><thead><tr><th>Offset</th><th>Règle</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table>`;
  container.querySelectorAll('.addr-link').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', () => {
      const a = el.dataset.addr;
      const bp = getStaticBinaryPath();
      if (a && bp) vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: a, binaryPath: bp });
    });
  });
}

function downloadDetectionJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(s) {
  if (typeof s !== 'string') return String(s);
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function normalizeHexAddress(addr) {
  const raw = String(addr || '').trim();
  if (!raw) return '';
  const hex = raw.toLowerCase().startsWith('0x') ? raw.slice(2) : raw;
  if (!/^[0-9a-f]+$/i.test(hex)) return raw.toLowerCase();
  const trimmed = hex.replace(/^0+/, '') || '0';
  return `0x${trimmed.toLowerCase()}`;
}

function getActiveStaticTabId() {
  return document.querySelector('#panel-static .sub-tab.active')?.dataset?.subTab || '';
}

function isStaticTabActive(tabId) {
  return getActiveStaticTabId() === tabId;
}

function syncCfgActiveAddress(addr, opts = {}) {
  const container = document.getElementById('cfgContent');
  return container?._cfgState?.setActiveAddr?.(addr, opts) || null;
}

function syncCallGraphActiveAddress(addr, opts = {}) {
  const container = document.getElementById('callgraphContent');
  return container?._cgState?.setActiveAddr?.(addr, opts) || null;
}

function getGraphUiState(kind, binaryPath) {
  const state = kind === 'cfg' ? cfgUiState : callGraphUiState;
  if (binaryPath && state.binaryPath !== binaryPath) {
    const preservedViewMode = state.viewMode;
    const preservedSearch = state.search;
    Object.assign(state, {
      binaryPath,
      viewMode: preservedViewMode,
      search: preservedSearch,
      expandedAddrs: [],
      graphView: null,
      activeAddr: '',
    });
  }
  return state;
}

function findNearestFunctionStart(addr, allowedAddrs = null) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  const target = parseInt(normalized, 16);
  if (Number.isNaN(target)) return '';
  const allowed = allowedAddrs ? new Set(allowedAddrs.map((a) => normalizeHexAddress(a))) : null;
  let bestAddr = '';
  let bestValue = -1;
  (window.symbolsCache || []).forEach((sym) => {
    const type = String(sym.type || '').toLowerCase();
    if (type !== 't' && type !== 'f') return;
    const symNorm = normalizeHexAddress(sym.addr);
    if (!symNorm || (allowed && !allowed.has(symNorm))) return;
    const symValue = parseInt(symNorm, 16);
    if (Number.isNaN(symValue) || symValue > target || symValue < bestValue) return;
    bestValue = symValue;
    bestAddr = sym.addr;
  });
  if (bestAddr) return bestAddr;
  return allowed && allowed.has(normalized) ? normalized : '';
}

function findNameForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  for (const [key, ann] of Object.entries(window._annotations || {})) {
    if (normalizeHexAddress(key) === normalized && ann?.name) return ann.name;
  }
  for (const sym of window.symbolsCache || []) {
    if (normalizeHexAddress(sym.addr) === normalized && sym.name) return sym.name;
  }
  return '';
}

function findAnnotationForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return null;
  for (const [key, ann] of Object.entries(window._annotations || {})) {
    if (normalizeHexAddress(key) === normalized) return ann || null;
  }
  return null;
}

function parseAddressLikeValue(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value || '').trim();
  if (!text) return Number.NaN;
  if (/^0x/i.test(text)) return parseInt(text, 16);
  if (/[a-f]/i.test(text)) return parseInt(text, 16);
  return Number(text);
}

function findSectionForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return null;
  const target = parseInt(normalized, 16);
  if (Number.isNaN(target)) return null;
  const sections = Array.isArray(window.sectionsCache) ? window.sectionsCache : [];
  for (const section of sections) {
    const start = parseAddressLikeValue(section.vma_hex || section.vma);
    const size = parseAddressLikeValue(section.size_hex || section.size);
    if (Number.isNaN(start) || Number.isNaN(size)) continue;
    if (target >= start && target < (start + size)) return section;
  }
  return null;
}

function getActiveContextSummary(addr = window._lastDisasmAddr) {
  const normalizedAddr = normalizeHexAddress(addr);
  const binaryPath = getStaticBinaryPath() || '';
  const binaryName = binaryPath ? _basenameFromPath(binaryPath) : '';
  const functionAddr = normalizedAddr ? (findNearestFunctionStart(normalizedAddr) || normalizedAddr) : '';
  const functionName = findNameForAddress(functionAddr) || findNameForAddress(normalizedAddr) || '';
  const exactName = findNameForAddress(normalizedAddr) || '';
  const annotation = findAnnotationForAddress(normalizedAddr);
  const section = findSectionForAddress(normalizedAddr);
  const meta = getCurrentBinaryMeta() || {};
  const arch = String(meta.arch || meta.rawConfig?.arch || '').trim();
  return {
    binaryPath,
    binaryName,
    addr: normalizedAddr,
    functionAddr,
    functionName,
    symbolName: exactName && exactName !== functionName ? exactName : '',
    annotationComment: String(annotation?.comment || '').trim(),
    sectionName: String(section?.name || '').trim(),
    arch,
  };
}

function getStackFrameCacheKey(binaryPath, addr) {
  const normalizedAddr = normalizeHexAddress(addr);
  const normalizedPath = String(binaryPath || '').trim();
  if (!normalizedPath || !normalizedAddr) return '';
  return `${normalizedPath}::${normalizedAddr}`;
}

function getCachedStackFrame(binaryPath, addr) {
  const key = getStackFrameCacheKey(binaryPath, addr);
  return key ? (stackFrameCache[key] || null) : null;
}

function cacheStackFrame(binaryPath, addr, frame) {
  const key = getStackFrameCacheKey(binaryPath, addr);
  if (!key || !frame) return;
  stackFrameCache[key] = frame;
  pendingStackFrameRequests.delete(key);
}

function ensureStackFrameLoaded(binaryPath, addr, opts = {}) {
  const normalizedAddr = normalizeHexAddress(addr);
  const key = getStackFrameCacheKey(binaryPath, normalizedAddr);
  if (!key) return null;
  if (!opts.force && stackFrameCache[key]) return stackFrameCache[key];
  if (pendingStackFrameRequests.has(key)) return null;
  pendingStackFrameRequests.add(key);
  vscode.postMessage({ type: 'hubLoadStackFrame', binaryPath, addr: normalizedAddr });
  return null;
}

function formatStackFrameEntryLocation(entry) {
  if (!entry) return '—';
  if (entry.location) return entry.location;
  if (typeof entry.offset === 'number') {
    const off = entry.offset >= 0
      ? `+0x${entry.offset.toString(16)}`
      : `-0x${Math.abs(entry.offset).toString(16)}`;
    return `[rbp${off}]`;
  }
  return '—';
}

function formatStackFrameEntryPreview(entry) {
  if (!entry) return '';
  const parts = [`${entry.name || 'entry'} @ ${formatStackFrameEntryLocation(entry)}`];
  if (entry.type && entry.type !== 'unknown') parts.push(`: ${entry.type}`);
  return parts.join('');
}

function normalizeStackEntryName(name) {
  return String(name || '').trim();
}

function setPendingStackEntryHighlight(name) {
  const normalized = normalizeStackEntryName(name);
  stackUiState.activeEntryName = normalized;
  stackUiState.pendingEntryName = normalized;
  return normalized;
}

function applyStackEntryHighlight(name, opts = {}) {
  const normalized = normalizeStackEntryName(name);
  const content = document.getElementById('stackContent');
  if (!content) return false;
  content.querySelectorAll('tr.addr-row-active').forEach((row) => row.classList.remove('addr-row-active'));
  if (!normalized) {
    stackUiState.activeEntryName = '';
    stackUiState.pendingEntryName = '';
    return false;
  }
  const rows = Array.from(content.querySelectorAll('tr[data-stack-entry-name]'));
  const target = rows.find((row) => normalizeStackEntryName(row.dataset.stackEntryName) === normalized);
  if (!target) return false;
  target.classList.add('addr-row-active');
  stackUiState.activeEntryName = normalized;
  stackUiState.pendingEntryName = '';
  if (opts.reveal !== false) target.scrollIntoView({ block: 'nearest' });
  return true;
}

function openStackEntryFromDecompile(name) {
  const entryName = setPendingStackEntryHighlight(name);
  if (!entryName) return;
  const targetAddr = normalizeHexAddress(decompileUiState.renderedAddr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const binaryPath = decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  if (!binaryPath || !targetAddr) return;
  window._lastDisasmAddr = targetAddr;
  showGroup('code', 'stack');
  updateActiveContextBars(targetAddr);
  requestAnimationFrame(() => {
    const cached = syncStackFrameForContext(targetAddr, { render: true });
    if (cached) applyStackEntryHighlight(entryName);
  });
}

function setPendingDecompileStackHighlight(name) {
  const normalized = normalizeStackEntryName(name);
  decompileUiState.activeStackEntryName = normalized;
  decompileUiState.pendingStackEntryName = normalized;
  return normalized;
}

function applyDecompileStackHighlight(name, opts = {}) {
  const normalized = normalizeStackEntryName(name);
  const content = document.getElementById('decompileContent');
  if (!content) return false;
  content.querySelectorAll('.decompile-stack-link.is-active, .decompile-link-chip-stack.is-active').forEach((el) => {
    el.classList.remove('is-active');
  });
  if (!normalized) {
    decompileUiState.activeStackEntryName = '';
    decompileUiState.pendingStackEntryName = '';
    return false;
  }
  const targets = Array.from(
    content.querySelectorAll('.decompile-stack-link[data-stack-name], .decompile-link-chip-stack[data-stack-name]'),
  ).filter((el) => normalizeStackEntryName(el.dataset.stackName) === normalized);
  if (!targets.length) return false;
  targets.forEach((el) => el.classList.add('is-active'));
  decompileUiState.activeStackEntryName = normalized;
  decompileUiState.pendingStackEntryName = '';
  if (opts.reveal !== false) targets[0].scrollIntoView({ block: 'nearest' });
  return true;
}

function openDecompileForStackEntry(name) {
  const entryName = setPendingDecompileStackHighlight(name);
  if (!entryName) return;
  const targetAddr = normalizeHexAddress(stackUiState.renderedAddr || decompileUiState.renderedAddr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const binaryPath = stackUiState.renderedBinaryPath || decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  if (!binaryPath || !targetAddr) return;
  window._lastDisasmAddr = targetAddr;
  updateActiveContextBars(targetAddr);
  syncDecompileSelection(targetAddr, { forceContext: true });
  const currentBinaryPath = getStaticBinaryPath() || '';
  const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
  const currentProvider = _getConfiguredDecompilerProvider();
  const shouldRefresh = decompileUiState.renderedBinaryPath !== currentBinaryPath
    || decompileUiState.renderedDecompiler !== currentDecompiler
    || decompileUiState.renderedProvider !== currentProvider
    || decompileUiState.renderedQuality !== currentQuality
    || (decompileUiState.renderedAddr || '') !== targetAddr;
  showGroup('code', 'decompile');
  requestAnimationFrame(() => {
    if (!shouldRefresh) applyDecompileStackHighlight(entryName);
  });
}

function buildHexStackContextHtml(frame) {
  if (!frame || frame.error) return '';
  const args = Array.isArray(frame.args) ? frame.args : [];
  const vars = Array.isArray(frame.vars) ? frame.vars : [];
  const metaChips = [
    frame.arch && frame.arch !== 'unknown' ? `Arch ${frame.arch}` : null,
    frame.abi && frame.abi !== 'unknown' ? `ABI ${frame.abi}` : null,
    typeof frame.frame_size === 'number' ? `Frame ${frame.frame_size}B` : null,
    `Args ${args.length}`,
    `Locals ${vars.length}`,
  ].filter(Boolean);
  const renderEntries = (title, entries, emptyLabel) => {
    const slice = entries.slice(0, 3);
    const remaining = entries.length - slice.length;
    const items = slice.map((entry) => (
      `<span class="hex-selection-stack-entry">${escapeHtml(formatStackFrameEntryPreview(entry))}</span>`
    )).join('');
    const extra = remaining > 0
      ? `<span class="hex-selection-stack-entry hex-selection-stack-entry-more">+${remaining} autre(s)</span>`
      : '';
    return `
      <div class="hex-selection-stack-block">
        <div class="hex-selection-stack-title">${escapeHtml(title)}</div>
        <div class="hex-selection-stack-entries">
          ${items || `<span class="hex-selection-stack-empty">${escapeHtml(emptyLabel)}</span>`}
          ${extra}
        </div>
      </div>
    `.trim();
  };
  const chipsHtml = metaChips.map((chip) => (
    `<span class="hex-selection-chip">${escapeHtml(chip)}</span>`
  )).join('');
  return `
    <div class="hex-selection-stack">
      <div class="hex-selection-stack-head">Contexte stack de la fonction</div>
      ${chipsHtml ? `<div class="hex-selection-chips">${chipsHtml}</div>` : ''}
      <div class="hex-selection-stack-grid">
        ${renderEntries('Arguments', args, 'Aucun argument détecté')}
        ${renderEntries('Locaux', vars, 'Aucune variable locale détectée')}
      </div>
    </div>
  `.trim();
}

function syncStackFrameForContext(addr = window._lastDisasmAddr, opts = {}) {
  const summary = getActiveContextSummary(addr);
  const targetAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  const binaryPath = summary.binaryPath || '';
  if (!binaryPath || !targetAddr || isRawBinarySelected()) return null;
  const shouldSkip = !opts.force
    && stackUiState.renderedBinaryPath === binaryPath
    && stackUiState.renderedAddr === targetAddr;
  if (shouldSkip) return getCachedStackFrame(binaryPath, targetAddr);
  const cached = getCachedStackFrame(binaryPath, targetAddr);
  if (cached) {
    if (opts.render !== false) {
      stackUiState.renderedBinaryPath = binaryPath;
      stackUiState.renderedAddr = targetAddr;
      renderStackFrame(cached);
    }
    return cached;
  }
  if (opts.render !== false) {
    setStaticLoading('stackContent', opts.loadingLabel || 'Analyse stack frame…');
  }
  ensureStackFrameLoaded(binaryPath, targetAddr);
  return null;
}

function createActiveContextBar(id) {
  const bar = document.createElement('div');
  bar.id = id;
  bar.className = 'active-context-bar active-context-bar-injected';
  bar.innerHTML = `
    <span class="active-context-chip active-context-chip-primary" data-role="function">Fonction: —</span>
    <span class="active-context-chip" data-role="address">Adresse: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="symbol" hidden>Symbole: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="section" hidden>Section: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="arch" hidden>Arch: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="binary" hidden>Binaire: —</span>
    <div class="active-context-actions">
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="disasm">Désasm</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="cfg">CFG</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="callgraph">Call Graph</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="decompile">Pseudo-C</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="hex">Hex</button>
    </div>
  `.trim();
  return bar;
}

function ensureActiveContextBarDetails(bar) {
  if (!bar || bar.dataset.enrichedContextBar === 'true') return;
  const actions = bar.querySelector('.active-context-actions');
  const ensureChip = (role, label, className = 'active-context-chip active-context-chip-meta') => {
    if (bar.querySelector(`[data-role="${role}"]`)) return;
    const chip = document.createElement('span');
    chip.className = className;
    chip.dataset.role = role;
    chip.hidden = true;
    chip.textContent = `${label}: —`;
    bar.insertBefore(chip, actions || null);
  };
  ensureChip('symbol', 'Symbole');
  ensureChip('section', 'Section');
  ensureChip('arch', 'Arch');
  ensureChip('binary', 'Binaire');
  bar.dataset.enrichedContextBar = 'true';
}

function injectActiveContextBars() {
  ACTIVE_CONTEXT_INJECTED_PANELS.forEach((panelId) => {
    const panel = document.getElementById(panelId);
    if (!panel || panel.querySelector('.active-context-bar')) return;
    const bar = createActiveContextBar(`${panelId}ContextBar`);
    const first = panel.firstElementChild;
    const insertAfterFirst = !!first && (
      first.classList.contains('form-row')
      || first.classList.contains('export-bar')
      || first.classList.contains('functions-toolbar')
      || first.classList.contains('typed-data-toolbar')
      || first.classList.contains('panel-toolbar')
      || (first.tagName === 'P' && first.classList.contains('hint'))
    );
    if (insertAfterFirst) {
      panel.insertBefore(bar, first.nextSibling);
    } else {
      panel.insertBefore(bar, first || null);
    }
  });
}

function updateActiveContextBars(addr = window._lastDisasmAddr) {
  const summary = getActiveContextSummary(addr);
  const activeTab = getActiveStaticTabId();
  document.querySelectorAll('.active-context-bar').forEach((bar) => {
    ensureActiveContextBarDetails(bar);
    const funcChip = bar.querySelector('[data-role="function"]');
    const addrChip = bar.querySelector('[data-role="address"]');
    const symbolChip = bar.querySelector('[data-role="symbol"]');
    const sectionChip = bar.querySelector('[data-role="section"]');
    const archChip = bar.querySelector('[data-role="arch"]');
    const binaryChip = bar.querySelector('[data-role="binary"]');
    if (funcChip) {
      funcChip.textContent = summary.functionAddr
        ? `Fonction: ${summary.functionName ? `${summary.functionName} @ ${summary.functionAddr}` : summary.functionAddr}`
        : 'Fonction: —';
    }
    if (addrChip) {
      addrChip.textContent = summary.addr ? `Adresse: ${summary.addr}` : 'Adresse: —';
    }
    if (symbolChip) {
      const symbolText = summary.symbolName || summary.annotationComment;
      symbolChip.textContent = symbolText
        ? `Symbole: ${String(symbolText).length > 48 ? `${String(symbolText).slice(0, 48)}…` : symbolText}`
        : 'Symbole: —';
      symbolChip.hidden = !symbolText;
      if (summary.annotationComment) symbolChip.title = summary.annotationComment;
      else symbolChip.removeAttribute('title');
    }
    if (sectionChip) {
      sectionChip.textContent = summary.sectionName ? `Section: ${summary.sectionName}` : 'Section: —';
      sectionChip.hidden = !summary.sectionName;
    }
    if (archChip) {
      archChip.textContent = summary.arch ? `Arch: ${summary.arch}` : 'Arch: —';
      archChip.hidden = !summary.arch;
    }
    if (binaryChip) {
      binaryChip.textContent = summary.binaryName ? `Binaire: ${summary.binaryName}` : 'Binaire: —';
      binaryChip.hidden = !summary.binaryName;
      if (summary.binaryPath) binaryChip.title = summary.binaryPath;
      else binaryChip.removeAttribute('title');
    }
    bar.querySelectorAll('[data-context-jump]').forEach((btn) => {
      const targetTab = btn.dataset.contextJump || '';
      const visible = isStaticTabAvailable(targetTab);
      btn.hidden = !visible;
      btn.disabled = !visible || !summary.binaryPath || !summary.addr || activeTab === targetTab;
    });
  });
  updateActiveNavRows(summary.addr);
  updateDisasmSessionSummary();
}

function updateActiveNavRows(addr = window._lastDisasmAddr) {
  const summary = getActiveContextSummary(addr);
  const exactAddr = normalizeHexAddress(summary.addr);
  const functionAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  document.querySelectorAll('.nav-addr-row[data-addr]').forEach((row) => {
    const rowAddr = normalizeHexAddress(row.dataset.addr || '');
    const matchMode = row.dataset.addrMatch || 'exact';
    const targetAddr = matchMode === 'function' ? functionAddr : exactAddr;
    const isActive = !!rowAddr && !!targetAddr && rowAddr === targetAddr;
    row.classList.toggle('addr-row-active', isActive);
    row.querySelectorAll('.addr-link').forEach((link) => {
      link.classList.toggle('addr-link-active', isActive);
    });
  });
}

function jumpToContextTab(tabId) {
  const summary = getActiveContextSummary();
  if (!summary.binaryPath || !tabId || !summary.addr) return;
  jumpToAddrInContextTab(tabId, summary.addr, summary.binaryPath);
}

function jumpToAddrInContextTab(tabId, addr, binaryPath) {
  const normalized = normalizeHexAddress(addr);
  const bp = binaryPath || getStaticBinaryPath();
  if (!tabId || !normalized || !bp || !isStaticTabAvailable(tabId)) return;
  setActiveAddressContext(normalized, 1);
  showPanel('static');
  showGroup('code', tabId);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      if (tabId === 'disasm') {
        vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp });
      } else if (tabId === 'cfg') {
        syncCfgActiveAddress(normalized, {
          reveal: true,
          revealTable: document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      } else if (tabId === 'callgraph') {
        syncCallGraphActiveAddress(normalized, {
          reveal: true,
          revealTable: document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      } else if (tabId === 'decompile') {
        syncDecompileSelection(normalized || decompileUiState.selectedAddr, { forceContext: true });
        requestDecompileForCurrentSelection();
      } else if (tabId === 'hex') {
        if (!hexSections.length || !tabDataCache.hex || tabDataCache.hex.binaryPath !== bp) {
          hexPendingScrollVaddr = buildHexSelectionDescriptor(normalized, { spanLength: 1 });
          loadHexView(bp, hexCurrentOffset, hexCurrentLength);
        } else {
          scrollHexToVaddr(normalized);
        }
      }
    });
  });
}

function setStaticLoading(containerId, msg) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = msg ? `<p class="loading">${escapeHtml(msg)}</p>` : '';
}

function applyHexLayoutMode() {
  const panel = document.getElementById('staticHex');
  const button = document.getElementById('btnHexToggleMeta');
  if (panel) panel.classList.toggle('hex-compact-mode', !!hexUiState.compact);
  if (button) {
    button.textContent = hexUiState.compact ? 'Voir infos' : 'Masquer infos';
    button.title = hexUiState.compact
      ? 'Afficher le contexte, les patches et la légende'
      : 'Garder un mode plus compact pour voir davantage de hex';
  }
}

function setTypedDataStructStatus(text, isError) {
  const statusEl = document.getElementById('typedDataStructStatus');
  if (!statusEl) return;
  statusEl.textContent = text || '';
  statusEl.style.color = isError ? 'var(--accent-danger, #ff6b6b)' : '';
}

function syncTypedDataStructSelect(structs, preferredName) {
  typedDataUiState.structs = Array.isArray(structs) ? structs.slice() : [];
  const select = document.getElementById('typedDataStructSelect');
  if (!select) return;
  const list = Array.isArray(structs) ? structs : [];
  const currentValue = preferredName !== undefined ? preferredName : (select.value || '');
  select.innerHTML = '';
  select.add(new Option('\u2014 type C \u2014', ''));
  list.forEach((entry) => {
    const name = typeof entry === 'string' ? entry : String((entry && entry.name) || '');
    if (!name) return;
    const kind = typeof entry === 'string' ? 'struct' : String((entry && entry.kind) || 'struct');
    const fieldCount = Number((entry && entry.field_count) || 0);
    const label = typeof entry === 'string'
      ? name
      : `${name} (${kind}, ${fieldCount} champ${fieldCount > 1 ? 's' : ''})`;
    select.add(new Option(label, name));
  });
  const nextValue = list.some((entry) => (typeof entry === 'string' ? entry : entry?.name) === currentValue)
    ? currentValue
    : '';
  select.value = nextValue;
  if (!nextValue && typedDataUiState.appliedStructName) {
    typedDataUiState.appliedStructName = '';
    setTypedDataStructStatus('');
  }
}

function getTypedDataActiveType() {
  return document.querySelector('.typed-type-btn.active')?.dataset.type || 'auto';
}

function buildTypedDataRequest(binaryPath, overrides) {
  const opts = overrides || {};
  const payload = {
    type: 'hubLoadTypedData',
    binaryPath,
    valueType: opts.valueType || getTypedDataActiveType(),
    page: opts.page ?? 0,
  };
  const section = opts.section !== undefined
    ? opts.section
    : document.getElementById('typedDataSection')?.value;
  if (section) payload.section = section;
  const structName = opts.structName !== undefined ? opts.structName : typedDataUiState.appliedStructName;
  const structOffset = opts.structOffset !== undefined
    ? opts.structOffset
    : (typedDataUiState.appliedStructOffset || document.getElementById('typedDataStructOffset')?.value || '0x0');
  if (structName) {
    payload.structName = structName;
    payload.structOffset = structOffset;
    const structAddr = opts.structAddr !== undefined
      ? opts.structAddr
      : typedDataUiState.appliedStructAddr;
    if (structAddr) payload.structAddr = structAddr;
  }
  return payload;
}

function getTypedStructList() {
  return Array.isArray(typedDataUiState.structs) ? typedDataUiState.structs : [];
}

function ensureTypedStructCatalogLoaded() {
  if (typedDataUiState.loadingStructs || typedDataUiState.structsLoaded) return;
  typedDataUiState.loadingStructs = true;
  vscode.postMessage({ type: 'hubLoadStructs' });
}

function getPreferredHexStructName() {
  const preferred = String(
    typedDataUiState.hexStructName
    || typedDataUiState.appliedStructName
    || document.getElementById('typedDataStructSelect')?.value
    || ''
  ).trim();
  const structs = getTypedStructList();
  if (!preferred) return '';
  return structs.some((entry) => (typeof entry === 'string' ? entry : entry?.name) === preferred)
    ? preferred
    : '';
}

function getHexStructSelectionContext(selection = null) {
  const descriptor = selection && typeof selection === 'object'
    ? buildHexSelectionDescriptor(selection.startAddr || selection.addr || selection.activeAddr || '', selection)
    : getCurrentHexSelectionDescriptor();
  if (!descriptor) return null;
  const addr = normalizeHexAddress(descriptor.startAddr || descriptor.activeAddr || '');
  const addrNum = parseNumericAddress(addr);
  if (!Number.isFinite(addrNum)) return null;
  const fileOffset = fileOffsetFromVaddr(addr);
  const section = Number.isFinite(fileOffset) ? findSectionForFileOffset(fileOffset) : null;
  const sectionVaddr = parseNumericAddress(section?.virtual_address);
  const sectionOffset = Number.isFinite(sectionVaddr) ? Math.max(0, addrNum - sectionVaddr) : null;
  return {
    descriptor,
    addr,
    addrNum,
    fileOffset,
    section,
    sectionOffset,
    sectionOffsetHex: Number.isFinite(sectionOffset) ? `0x${sectionOffset.toString(16)}` : '',
  };
}

function syncTypedDataFromActiveSelection(opts = {}) {
  const ctx = getHexStructSelectionContext();
  const targetAddr = normalizeHexAddress(opts.addr || ctx?.addr || window._lastDisasmAddr || '');
  if (!targetAddr) {
    setTypedDataStructStatus('Aucune adresse active à reprendre.', true);
    return null;
  }
  const structOffsetInput = document.getElementById('typedDataStructOffset');
  const sectionSelect = document.getElementById('typedDataSection');
  if (ctx?.section?.name && sectionSelect) sectionSelect.value = String(ctx.section.name);
  if (ctx?.sectionOffsetHex && structOffsetInput) structOffsetInput.value = ctx.sectionOffsetHex;
  typedDataUiState.appliedStructAddr = targetAddr;
  setTypedDataStructStatus(
    ctx?.section?.name
      ? `Sélection active ${targetAddr} prête dans ${ctx.section.name} @ +${ctx.sectionOffsetHex}.`
      : `Sélection active ${targetAddr} prête pour application par adresse.`,
    false,
  );
  return {
    addr: targetAddr,
    section: ctx?.section?.name || '',
    structOffset: ctx?.sectionOffsetHex || '0x0',
  };
}

function requestHexStructPreview(structName, ctx = getHexStructSelectionContext()) {
  const binaryPath = getStaticBinaryPath();
  const normalizedStruct = String(structName || '').trim();
  if (!binaryPath || !ctx?.addr || !normalizedStruct) return;
  typedDataUiState.hexStructName = normalizedStruct;
  typedDataUiState.hexStructPreview = {
    loading: true,
    structName: normalizedStruct,
    addr: ctx.addr,
    section: ctx.section?.name || '',
  };
  updateHexSelectionSummary(ctx.descriptor);
  vscode.postMessage({
    type: 'hubPreviewTypedStruct',
    binaryPath,
    structName: normalizedStruct,
    structAddr: ctx.addr,
    section: ctx.section?.name || undefined,
    structOffset: ctx.sectionOffsetHex || '0x0',
  });
}

function openTypedDataStructFromSelection(structName, ctx = getHexStructSelectionContext()) {
  const binaryPath = getStaticBinaryPath();
  const normalizedStruct = String(structName || '').trim();
  if (!binaryPath || !ctx?.addr || !normalizedStruct) return;
  typedDataUiState.hexStructName = normalizedStruct;
  typedDataUiState.appliedStructName = normalizedStruct;
  typedDataUiState.appliedStructAddr = ctx.addr;
  typedDataUiState.appliedStructOffset = ctx.sectionOffsetHex || '0x0';
  if (ctx.section?.name && document.getElementById('typedDataSection')) {
    document.getElementById('typedDataSection').value = String(ctx.section.name);
  }
  if (document.getElementById('typedDataStructSelect')) {
    document.getElementById('typedDataStructSelect').value = normalizedStruct;
  }
  if (document.getElementById('typedDataStructOffset')) {
    document.getElementById('typedDataStructOffset').value = typedDataUiState.appliedStructOffset;
  }
  showGroup('data', 'typed_data');
  setStaticLoading('typedDataContent', 'Application du type…');
  vscode.postMessage(buildTypedDataRequest(binaryPath, {
    page: 0,
    section: ctx.section?.name || undefined,
    structName: normalizedStruct,
    structOffset: typedDataUiState.appliedStructOffset,
    structAddr: ctx.addr,
  }));
}

function openTypedStructEditor(sourceText) {
  document.getElementById('pof-typed-struct-popup')?.remove();
  const popup = document.createElement('div');
  popup.id = 'pof-typed-struct-popup';
  popup.className = 'note-popup typed-data-struct-editor';
  popup.style.cssText = 'left:50%;top:84px;transform:translateX(-50%);z-index:240;';

  const head = document.createElement('div');
  head.className = 'typed-data-struct-editor-head';
  head.innerHTML = `
    <div class="typed-data-struct-editor-title">Éditeur de types C</div>
    <div class="typed-data-struct-editor-hint">Collez une ou plusieurs definitions du style <code>typedef struct/union/enum ...</code>.</div>
  `;

  const textarea = document.createElement('textarea');
  textarea.className = 'note-popup-input';
  textarea.spellcheck = false;
  textarea.value = sourceText || '';

  const actions = document.createElement('div');
  actions.className = 'typed-data-struct-editor-actions';
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn btn-xs';
  cancelBtn.type = 'button';
  cancelBtn.textContent = 'Fermer';
  cancelBtn.addEventListener('click', () => popup.remove());

  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn btn-xs btn-primary';
  saveBtn.type = 'button';
  saveBtn.textContent = 'Sauvegarder';
  saveBtn.addEventListener('click', () => {
    setTypedDataStructStatus('Sauvegarde des types C…');
    vscode.postMessage({ type: 'hubSaveStructs', sourceText: textarea.value });
    popup.remove();
  });

  actions.appendChild(cancelBtn);
  actions.appendChild(saveBtn);
  popup.appendChild(head);
  popup.appendChild(textarea);
  popup.appendChild(actions);
  document.body.appendChild(popup);
  textarea.focus();
  textarea.setSelectionRange(textarea.value.length, textarea.value.length);
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') popup.remove();
  }, { once: true });
}

function renderFuncSimilarityUi(container) {
  if (!container) return;
  container.querySelector('#funcSimBar')?.remove();
  container.querySelector('#funcSimPanel')?.remove();

  const bar = document.createElement('div');
  bar.id = 'funcSimBar';
  bar.style.cssText = 'margin-top:10px;display:flex;gap:6px;align-items:center;flex-wrap:wrap;';

  const compareBtn = document.createElement('button');
  compareBtn.className = 'btn btn-sm btn-secondary';
  compareBtn.textContent = 'Similarité — Comparer avec…';
  compareBtn.addEventListener('click', () => {
    const bp = getStaticBinaryPath();
    if (!bp) return;
    vscode.postMessage({ type: 'hubPickFile', target: 'funcSimilarityRef', binaryPath: bp });
  });

  const addBtn = document.createElement('button');
  addBtn.className = 'btn btn-sm';
  addBtn.textContent = 'Ajouter à la base…';
  addBtn.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubPickFile', target: 'funcSimilarityDbRef' });
  });

  const searchBtn = document.createElement('button');
  searchBtn.className = 'btn btn-sm';
  searchBtn.textContent = 'Chercher dans la base';
  searchBtn.addEventListener('click', () => {
    const bp = getStaticBinaryPath();
    if (!bp) return;
    funcSimilarityUiState.pendingText = 'Recherche en cours dans la base indexée…';
    renderFuncSimilarityUi(container);
    vscode.postMessage({ type: 'hubLoadFuncSimilarity', binaryPath: bp, useDb: true, threshold: 0.4, top: 1 });
  });

  const refreshBtn = document.createElement('button');
  refreshBtn.className = 'btn btn-sm';
  refreshBtn.textContent = 'Rafraîchir la base';
  refreshBtn.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubListFuncSimilarityDb' });
  });

  const clearBtn = document.createElement('button');
  clearBtn.className = 'btn btn-sm';
  clearBtn.textContent = 'Vider la base locale';
  clearBtn.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubClearFuncSimilarityDb' });
  });

  const hint = document.createElement('span');
  hint.className = 'hint';
  hint.textContent = 'La recherche combine ta base workspace et un starter pack embarqué quand il est disponible.';

  bar.append(compareBtn, addBtn, searchBtn, refreshBtn, clearBtn, hint);
  container.appendChild(bar);

  const panel = document.createElement('div');
  panel.id = 'funcSimPanel';
  panel.className = 'modern-card';
  panel.style.cssText = 'margin-top:10px;';

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:8px;';
  const title = document.createElement('span');
  title.className = 'section-label';
  title.textContent = 'Base de similarité';
  header.appendChild(title);
  panel.appendChild(header);

  if (funcSimilarityUiState.pendingText) {
    const pending = document.createElement('p');
    pending.className = 'hint';
    pending.textContent = funcSimilarityUiState.pendingText;
    panel.appendChild(pending);
  }

  const db = funcSimilarityUiState.db;
  if (db) {
    if (db.error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = db.error;
      panel.appendChild(p);
    } else {
      const stats = db.stats || {};
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = `${stats.reference_binaries || 0} source(s) de référence — ${stats.reference_functions || 0} fonction(s) (${stats.workspace_binaries || 0} workspace, ${stats.bundled_binaries || 0} packagées)`;
      panel.appendChild(p);
      if (db.updated?.label) {
        const status = document.createElement('p');
        status.className = 'hint';
        status.textContent = `Label mis à jour : ${db.updated.label}`;
        panel.appendChild(status);
      } else if (db.removed?.id) {
        const status = document.createElement('p');
        status.className = 'hint';
        status.textContent = 'Référence locale supprimée.';
        panel.appendChild(status);
      }
      const refs = db.references || [];
      if (refs.length > 0) {
        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML =
          '<thead><tr><th>Label</th><th>Famille</th><th>Source</th><th>Binaire</th><th>Fonctions</th><th>Actions</th></tr></thead>';
        const tbody = document.createElement('tbody');
        refs.forEach((ref) => {
          const row = tbody.insertRow();

          const tdLabel = row.insertCell();
          tdLabel.innerHTML = `<code>${escapeHtml(ref.label || ref.name || '')}</code>`;

          const tdFamily = row.insertCell();
          tdFamily.className = 'hint';
          tdFamily.textContent = ref.family || '—';

          const tdSource = row.insertCell();
          tdSource.className = 'hint';
          tdSource.textContent = ref.source === 'bundled' ? (ref.pack || 'packagée') : 'workspace';

          const tdBinary = row.insertCell();
          tdBinary.textContent = ref.name || '';

          const tdFunctions = row.insertCell();
          tdFunctions.textContent = String(ref.function_count || 0);

          const tdActions = row.insertCell();
          tdActions.className = 'func-sim-actions-cell';
          if (ref.editable && ref.id) {
            const renameBtn = document.createElement('button');
            renameBtn.className = 'btn btn-xs btn-secondary';
            renameBtn.textContent = 'Renommer';
            renameBtn.addEventListener('click', () => {
              const currentLabel = String(ref.label || ref.name || '').trim();
              const nextLabel = prompt('Nouveau label pour cette référence :', currentLabel);
              if (nextLabel == null) return;
              const cleaned = String(nextLabel).trim();
              if (!cleaned || cleaned === currentLabel) return;
              funcSimilarityUiState.pendingText = `Renommage en cours — ${currentLabel}...`;
              renderFuncSimilarityUi(container);
              vscode.postMessage({ type: 'hubUpdateFuncSimilarityRef', referenceId: ref.id, label: cleaned });
            });

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-xs btn-secondary';
            deleteBtn.textContent = 'Supprimer';
            deleteBtn.addEventListener('click', () => {
              if (!confirm(`Supprimer la référence locale « ${ref.label || ref.name || 'sans nom'} » ?`)) return;
              funcSimilarityUiState.pendingText = `Suppression en cours — ${ref.label || ref.name || 'référence'}...`;
              renderFuncSimilarityUi(container);
              vscode.postMessage({ type: 'hubRemoveFuncSimilarityRef', referenceId: ref.id });
            });

            tdActions.append(renameBtn, deleteBtn);
          } else {
            const note = document.createElement('span');
            note.className = 'hint';
            note.textContent = ref.source === 'bundled' ? 'Pack lecture seule' : '—';
            tdActions.appendChild(note);
          }
        });
        table.appendChild(tbody);
        panel.appendChild(table);
      }
    }
  }

  const data = funcSimilarityUiState.results;
  if (data) {
    if (db) {
      const sep = document.createElement('div');
      sep.style.cssText = 'height:1px;margin:10px 0;background:var(--border-light);';
      panel.appendChild(sep);
    }
    const resultsTitle = document.createElement('div');
    resultsTitle.className = 'section-label';
    resultsTitle.style.marginBottom = '8px';
    resultsTitle.textContent = 'Résultats';
    panel.appendChild(resultsTitle);
    if (data.error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = data.error;
      panel.appendChild(p);
    } else {
      const matches = data.matches || [];
      const stats = data.stats || {};
      const statLine = document.createElement('p');
      statLine.className = 'hint';
      statLine.textContent = `${matches.length} correspondance(s) trouvée(s) sur ${stats.target_functions || '?'} fonctions analysées (seuil ${stats.threshold || 0.4}, base ${stats.reference_binaries || 0} source(s), dont ${stats.bundled_binaries || 0} packagées)`;
      panel.appendChild(statLine);
      if (matches.length > 0) {
        const table = document.createElement('table');
        table.className = 'data-table';
        const thead = table.createTHead();
        const hr = thead.insertRow();
        ['Adresse', 'Nom (cible)', 'Correspondance', 'Référence', 'Famille', 'Source', 'Score'].forEach((text) => {
          const th = document.createElement('th');
          th.textContent = text;
          hr.appendChild(th);
        });
        const tbody = table.createTBody();
        for (const match of matches) {
          const row = tbody.insertRow();
          const tdAddr = row.insertCell();
          const addrLink = document.createElement('a');
          addrLink.className = 'addr-link';
          addrLink.href = '#';
          addrLink.textContent = match.addr || '?';
          addrLink.addEventListener('click', (event) => {
            event.preventDefault();
            const bp = getStaticBinaryPath();
            if (bp) vscode.postMessage({ type: 'hubGoToAddress', binaryPath: bp, addr: match.addr });
          });
          tdAddr.appendChild(addrLink);
          const tdName = row.insertCell();
          tdName.style.fontFamily = 'var(--font-mono)';
          tdName.style.fontSize = '11px';
          tdName.textContent = match.name || '?';
          const tdMatch = row.insertCell();
          tdMatch.innerHTML = `<code style="color:var(--accent-blue-soft);font-size:11px">${escapeHtml(match.match_name || '?')}</code>`;
          const tdRef = row.insertCell();
          tdRef.className = 'hint';
          tdRef.textContent = match.ref_label || match.ref_binary || '?';
          const tdFamily = row.insertCell();
          tdFamily.className = 'hint';
          tdFamily.textContent = match.ref_family || '—';
          const tdSource = row.insertCell();
          tdSource.className = 'hint';
          tdSource.textContent = match.ref_source === 'bundled' ? (match.ref_pack || 'packagée') : 'workspace';
          const tdScore = row.insertCell();
          tdScore.textContent = `${Math.round((match.score || 0) * 100)}%`;
          tdScore.style.color = 'var(--accent-blue-soft)';
        }
        panel.appendChild(table);
      }
    }
  }

  if (!funcSimilarityUiState.pendingText && !db && !data) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = 'Base non chargée. Utilisez “Rafraîchir la base” ou ajoutez un premier binaire de référence.';
    panel.appendChild(empty);
  }

  container.appendChild(panel);
}

function initCfgZoom(wrapEl) {
  if (!wrapEl) return;
  const state = { scale: 1 };
  let tx = 0;
  let ty = 0;
  let panning = false;
  let lastX = 0;
  let lastY = 0;
  let autoFitScheduled = false;

  const inner = wrapEl.querySelector('.cfg-svg-inner');
  if (!inner) return;

  function applyTransform() {
    inner.style.transform = `translate(${tx}px, ${ty}px) scale(${state.scale})`;
    inner.style.transformOrigin = '0 0';
    if (typeof state.onChange === 'function') state.onChange(state.getViewState());
  }

  wrapEl.addEventListener('wheel', (e) => {
    e.preventDefault();
    const oldScale = state.scale;
    const delta = e.deltaY > 0 ? -0.15 : 0.15;
    state.scale = Math.max(0.2, Math.min(4, oldScale + delta));
    // Cursor-centered zoom: keep the point under the mouse fixed in SVG space
    const rect = wrapEl.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    tx = mouseX - (mouseX - tx) * (state.scale / oldScale);
    ty = mouseY - (mouseY - ty) * (state.scale / oldScale);
    applyTransform();
  }, { passive: false });

  wrapEl.addEventListener('mousedown', (e) => {
    if (e.target.closest('.cfg-node')) return;
    panning = true;
    lastX = e.clientX;
    lastY = e.clientY;
  });
  document.addEventListener('mousemove', (e) => {
    if (!panning) return;
    tx += e.clientX - lastX;
    ty += e.clientY - lastY;
    lastX = e.clientX;
    lastY = e.clientY;
    applyTransform();
  });
  document.addEventListener('mouseup', () => { panning = false; });

  function fitToView() {
    const svg = inner.querySelector('svg');
    if (!svg) return;
    const svgW = parseFloat(svg.getAttribute('width')) || 600;
    const svgH = parseFloat(svg.getAttribute('height')) || 400;
    const wrapRect = wrapEl.getBoundingClientRect();
    if (wrapRect.width === 0 || wrapRect.height === 0) return;
    const pad = 24;
    const usableW = Math.max(80, wrapRect.width - pad * 2);
    const usableH = Math.max(80, wrapRect.height - pad * 2);
    state.scale = Math.min(usableW / svgW, usableH / svgH, 1);
    tx = Math.max(pad, (wrapRect.width - svgW * state.scale) / 2);
    ty = Math.max(pad, (wrapRect.height - svgH * state.scale) / 2);
    applyTransform();
  }

  function requestFit() {
    if (autoFitScheduled) return;
    autoFitScheduled = true;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        autoFitScheduled = false;
        fitToView();
      });
    });
  }

  function centerOnBox(box, opts = {}) {
    if (!box) return;
    const wrapRect = wrapEl.getBoundingClientRect();
    if (wrapRect.width === 0 || wrapRect.height === 0) return;
    let targetScale = typeof opts.scale === 'number' ? opts.scale : (state.scale || 1);
    if (typeof opts.minScale === 'number') targetScale = Math.max(targetScale, opts.minScale);
    if (typeof opts.maxScale === 'number') targetScale = Math.min(targetScale, opts.maxScale);
    state.scale = Math.max(0.2, Math.min(4, targetScale));
    tx = (wrapRect.width / 2) - ((box.x + box.w / 2) * state.scale);
    ty = (wrapRect.height / 2) - ((box.y + box.h / 2) * state.scale);
    applyTransform();
  }

  function getViewState() {
    return { scale: state.scale, tx, ty };
  }

  function setViewState(next) {
    if (!next) return;
    const nextScale = typeof next.scale === 'number' ? next.scale : state.scale;
    const nextTx = typeof next.tx === 'number' ? next.tx : tx;
    const nextTy = typeof next.ty === 'number' ? next.ty : ty;
    state.scale = Math.max(0.2, Math.min(4, nextScale));
    tx = nextTx;
    ty = nextTy;
    applyTransform();
  }

  if (typeof ResizeObserver !== 'undefined') {
    const ro = new ResizeObserver(() => {
      const rect = wrapEl.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) requestFit();
    });
    ro.observe(wrapEl);
    state._resizeObserver = ro;
  }

  state.fitToView = fitToView;
  state.requestFit = requestFit;
  state.centerOnBox = centerOnBox;
  state.getViewState = getViewState;
  state.setViewState = setViewState;
  wrapEl._zoomState = state;
  return state;
}

function requestGraphFit(rootEl = document) {
  const wraps = rootEl.querySelectorAll('.cfg-svg-zoom');
  wraps.forEach((wrap) => {
    if (wrap.offsetParent === null) return;
    const rect = wrap.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    if (wrap._zoomState?.requestFit) wrap._zoomState.requestFit();
    else if (wrap._zoomState?.fitToView) wrap._zoomState.fitToView();
  });
}

function cfgStackHintLabel(hint) {
  if (!hint || typeof hint !== 'object') return '';
  const name = String(hint.name || '').trim();
  if (!name) return '';
  return `${hint.kind === 'arg' ? 'arg' : 'var'} ${name}`;
}

function collectCfgLineMeta(ln) {
  return {
    label: String(ln?.label || '').trim(),
    comment: String(ln?.comment || '').trim(),
    stackHints: Array.isArray(ln?.stack_hints) ? ln.stack_hints.filter(Boolean) : [],
  };
}

function formatCfgLineDisplay(ln, maxLen = 56) {
  const code = String(ln?.text || '').trim();
  if (!code) return '';
  const meta = collectCfgLineMeta(ln);
  const hintLabels = meta.stackHints
    .map(cfgStackHintLabel)
    .filter(Boolean)
    .slice(0, 2);
  if (meta.stackHints.length > 2) hintLabels.push(`+${meta.stackHints.length - 2}`);
  const suffixParts = [];
  if (hintLabels.length) suffixParts.push(hintLabels.join(', '));
  if (meta.comment) suffixParts.push(meta.comment);
  const combined = suffixParts.length ? `${code} ; ${suffixParts.join(' • ')}` : code;
  return combined.length > maxLen ? `${combined.substring(0, maxLen - 1)}…` : combined;
}

function formatSwitchCaseLabel(value) {
  if (value === 'default') return 'default';
  if (typeof value === 'number') return `case ${value}`;
  if (String(value || '').trim()) return `case ${value}`;
  return '';
}

function summarizeSwitchCaseLabels(labels, opts = {}) {
  const values = Array.isArray(labels) ? labels.filter((label) => label !== null && label !== undefined) : [];
  if (!values.length) return '';
  const seen = new Set();
  const display = values
    .map((label) => formatSwitchCaseLabel(label))
    .filter((label) => {
      if (!label || seen.has(label)) return false;
      seen.add(label);
      return true;
    });
  if (!display.length) return '';
  const max = Number.isFinite(opts.max) ? opts.max : 2;
  if (display.length <= max) return display.join(' · ');
  return `${display.slice(0, max).join(' · ')} +${display.length - max}`;
}

function collectGraphNeighborhood(focusAddr, edges, radius = 1) {
  const focus = String(focusAddr || '').trim();
  if (!focus) return null;
  const depth = Math.max(0, Number(radius) || 0);
  const seen = new Set([focus]);
  let frontier = new Set([focus]);
  for (let step = 0; step < depth; step++) {
    const next = new Set();
    edges.forEach((edge) => {
      if (frontier.has(edge.from) && !seen.has(edge.to)) next.add(edge.to);
      if (frontier.has(edge.to) && !seen.has(edge.from)) next.add(edge.from);
    });
    next.forEach((addr) => seen.add(addr));
    frontier = next;
    if (frontier.size === 0) break;
  }
  return seen;
}

/**
 * Renders an interactive SVG graph (CFG or Call Graph).
 * Features: zoom/pan (via initCfgZoom), node drag, Shift+click BFS path highlight.
 *
 * @param {Array<{addr:string, label?:string, sublabel?:string, lines?:Array}>} nodes
 * @param {Array<{from:string, to:string, type?:string}>} edges
 * @param {{nodeW?:number, nodeH?:number, padX?:number, padY?:number, lanePadX?:number,
 *          onNodeClick?:Function, zoomState?:{scale:number}}} opts
 * @returns {SVGElement}
 */
function renderGraphSvg(nodes, edges, opts) {
  // Detect code mode (CFG with instructions) vs simple mode (Call Graph)
  const hasCode = nodes.some(n => n.lines && n.lines.length > 0);
  const initialExpandedSet = new Set((opts && opts.expandedAddrs) || []);
  const LINE_H = 14;
  const HEADER_H = 26;
  const PREVIEW_LINES = 4;
  const MAX_EXPANDED = 20;
  const COMPACT_H = HEADER_H + 12; // minimum block height used by preview/expanded modes
  const ADDR_X = 8;
  const CODE_X = 85;

  const longestLabel = nodes.reduce((max, n) => {
    const lengths = [
      String(n.label || '').length,
      String(n.sublabel || '').length,
    ];
    return Math.max(max, ...lengths);
  }, 0);
  const autoSimpleNodeW = Math.min(320, Math.max(220, 120 + longestLabel * 6));
  const nodeW = (opts && opts.nodeW) || (hasCode ? 360 : autoSimpleNodeW);
  const nodeH = (opts && opts.nodeH) || (hasCode ? 64 : 84);
  const padX = (opts && opts.padX) || (hasCode ? 84 : 96);
  const padY = (opts && opts.padY) || (hasCode ? 72 : 88);
  const onNodeClick = (opts && opts.onNodeClick) || null;
  const onNodeIsolate = (opts && opts.onNodeIsolate) || null;
  const zoomState = (opts && opts.zoomState) || { scale: 1 };

  // Pre-calculate per-node heights.
  // CFG blocks start in preview mode so the opening view stays readable
  // while still showing a few instructions in each block.
  const preHeights = {};
  for (const n of nodes) {
    if (hasCode && n.lines && n.lines.length > 0) {
      preHeights[n.addr] = initialExpandedSet.has(n.addr) ? expandedHeight(n) : previewHeight(n);
    } else {
      preHeights[n.addr] = nodeH;
    }
  }
  const nodeHeights = { ...preHeights };

  function previewHeight(nd) {
    const visibleLines = Math.min((nd.lines || []).length, PREVIEW_LINES);
    const extra = (nd.lines || []).length > PREVIEW_LINES ? LINE_H : 0;
    return Math.max(COMPACT_H, HEADER_H + visibleLines * LINE_H + extra + 10);
  }

  // Compute expanded height for a node
  function expandedHeight(nd) {
    const nLines = Math.min(nd.lines.length, MAX_EXPANDED);
    const extra = nd.lines.length > MAX_EXPANDED ? LINE_H : 0;
    return Math.max(60, HEADER_H + nLines * LINE_H + extra + 10);
  }

  // Use max height for layout spacing
  const maxH = Math.max(nodeH, ...Object.values(preHeights));
  const helpers = window.cfgHelpers;
  const layout = helpers.computeLayout(nodes, edges, {
    nodeW,
    nodeH: maxH,
    padX,
    padY,
    lanePadX: hasCode ? 34 : undefined,
    layoutMode: 'elk',
    maxPerRow: (opts && opts.maxPerRow) || (hasCode ? 4 : 5),
  });
  const nodePositions = {};
  for (const addr of Object.keys(layout.positions)) {
    nodePositions[addr] = { ...layout.positions[addr] };
  }

  const rowGroups = [];
  if (hasCode) {
    const rowMap = new Map();
    for (const n of nodes) {
      const l = layout.levels[n.addr];
      const p = nodePositions[n.addr];
      if (l === undefined || !p) continue;
      const key = `${l}|${p.y}`;
      if (!rowMap.has(key)) rowMap.set(key, { level: l, baseY: p.y, addrs: [] });
      rowMap.get(key).addrs.push(n.addr);
    }
    rowGroups.push(...rowMap.values());
    rowGroups.sort((a, b) => a.baseY - b.baseY || a.level - b.level);
    rowGroups.forEach((row) => {
      row.addrs.sort((a, b) => (nodePositions[a]?.x || 0) - (nodePositions[b]?.x || 0));
    });
  }

  const adj = helpers.buildAdjacency(edges);

  // Classify edges for back-edge (loop) rendering
  const { backEdges } = helpers.classifyEdges(edges, layout.levels);
  const backEdgeSet = new Set(backEdges.map(e => `${e.from}|${e.to}`));
  const forwardSourceLane = new Map();
  const forwardTargetLane = new Map();
  const backEdgeLane = new Map();
  const FORWARD_LANE_GAP = 18;
  const BACK_EDGE_LANE_GAP = 30;
  const MAX_LANE_OFFSET = Math.max(34, Math.floor(nodeW * 0.28));

  function edgeKey(from, to) {
    return `${from}|${to}`;
  }

  function centeredLane(index, count) {
    return index - (count - 1) / 2;
  }

  function clampLaneOffset(value) {
    return Math.max(-MAX_LANE_OFFSET, Math.min(MAX_LANE_OFFSET, value));
  }

  function groupEdgesBy(keySelector, list) {
    const map = new Map();
    list.forEach((edge) => {
      const key = keySelector(edge);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(edge);
    });
    return map;
  }

  function compareNodePosition(addrA, addrB) {
    const a = nodePositions[addrA] || { x: 0, y: 0 };
    const b = nodePositions[addrB] || { x: 0, y: 0 };
    return a.y - b.y || a.x - b.x || String(addrA).localeCompare(String(addrB));
  }

  const forwardEdges = edges.filter((edge) => !backEdgeSet.has(edgeKey(edge.from, edge.to)));
  groupEdgesBy((edge) => edge.from, forwardEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.to, b.to));
    group.forEach((edge, index) => {
      forwardSourceLane.set(edgeKey(edge.from, edge.to), centeredLane(index, group.length));
    });
  });
  groupEdgesBy((edge) => edge.to, forwardEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.from, b.from));
    group.forEach((edge, index) => {
      forwardTargetLane.set(edgeKey(edge.from, edge.to), centeredLane(index, group.length));
    });
  });
  groupEdgesBy((edge) => edge.from, backEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.to, b.to));
    group.forEach((edge, index) => {
      backEdgeLane.set(edgeKey(edge.from, edge.to), index);
    });
  });

  // Compute SVG dimensions from actual positions/heights
  let svgW = 600;
  let svgH = 400;
  for (const addr of Object.keys(nodePositions)) {
    const p = nodePositions[addr];
    const h = preHeights[addr] || nodeH;
    svgW = Math.max(svgW, p.x + nodeW + padX);
    svgH = Math.max(svgH, p.y + h + padY);
  }

  const NS = 'http://www.w3.org/2000/svg';
  const svgEl = document.createElementNS(NS, 'svg');
  svgEl.setAttribute('class', 'cfg-svg');
  svgEl.setAttribute('xmlns', NS);
  svgEl.setAttribute('width', svgW);
  svgEl.setAttribute('height', svgH);
  svgEl.setAttribute('viewBox', `0 0 ${svgW} ${svgH}`);
  svgEl.setAttribute('overflow', 'visible');

  const markerId = `arrow-${Date.now()}`;
  const defs = document.createElementNS(NS, 'defs');
  const marker = document.createElementNS(NS, 'marker');
  marker.id = markerId;
  marker.setAttribute('markerWidth', '10');
  marker.setAttribute('markerHeight', '7');
  marker.setAttribute('refX', '9');
  marker.setAttribute('refY', '3.5');
  marker.setAttribute('orient', 'auto');
  const arrowPoly = document.createElementNS(NS, 'polygon');
  arrowPoly.setAttribute('points', '0 0, 10 3.5, 0 7');
  arrowPoly.setAttribute('fill', '#8b949e');
  marker.appendChild(arrowPoly);
  defs.appendChild(marker);

  const backMarkerId = `arrow-back-${Date.now()}`;
  const backMarker = document.createElementNS(NS, 'marker');
  backMarker.id = backMarkerId;
  backMarker.setAttribute('markerWidth', '10');
  backMarker.setAttribute('markerHeight', '7');
  backMarker.setAttribute('refX', '9');
  backMarker.setAttribute('refY', '3.5');
  backMarker.setAttribute('orient', 'auto');
  const backArrowPoly = document.createElementNS(NS, 'polygon');
  backArrowPoly.setAttribute('points', '0 0, 10 3.5, 0 7');
  backArrowPoly.setAttribute('fill', '#d08770');
  backMarker.appendChild(backArrowPoly);
  defs.appendChild(backMarker);

  svgEl.appendChild(defs);

  if (hasCode && Array.isArray(layout.lanes) && layout.lanes.length > 0) {
    const laneGroup = document.createElementNS(NS, 'g');
    laneGroup.setAttribute('class', 'cfg-lanes');
    layout.lanes.forEach((lane) => {
      const leftX = Math.max(0, lane.x - padX * 0.35);
      const rightX = lane.x + lane.width + padX * 0.35;
      [leftX, rightX].forEach((x) => {
        const line = document.createElementNS(NS, 'line');
        line.setAttribute('x1', String(x));
        line.setAttribute('x2', String(x));
        line.setAttribute('y1', '8');
        line.setAttribute('y2', String(Math.max(0, svgH - 8)));
        line.setAttribute('stroke', 'rgba(255,255,255,0.12)');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('stroke-dasharray', '4,6');
        laneGroup.appendChild(line);
      });
      const label = document.createElementNS(NS, 'text');
      label.setAttribute('x', String(lane.x + lane.width / 2));
      label.setAttribute('y', '24');
      label.setAttribute('fill', '#8b949e');
      label.setAttribute('font-size', '11');
      label.setAttribute('font-family', 'monospace');
      label.setAttribute('font-weight', '700');
      label.setAttribute('text-anchor', 'middle');
      label.textContent = lane.label;
      laneGroup.appendChild(label);
    });
    const flowLane = layout.lanes.find((lane) => lane.id === 'flow');
    if (flowLane) {
      const spineX = flowLane.x + flowLane.width / 2;
      const spine = document.createElementNS(NS, 'line');
      spine.setAttribute('x1', String(spineX));
      spine.setAttribute('x2', String(spineX));
      spine.setAttribute('y1', '32');
      spine.setAttribute('y2', String(Math.max(0, svgH - 12)));
      spine.setAttribute('stroke', 'rgba(136,216,255,0.28)');
      spine.setAttribute('stroke-width', '2');
      spine.setAttribute('stroke-dasharray', '10,8');
      laneGroup.appendChild(spine);
    }
    svgEl.appendChild(laneGroup);
  }

  const edgeGroup = document.createElementNS(NS, 'g');
  svgEl.appendChild(edgeGroup);
  const nodeGroup = document.createElementNS(NS, 'g');
  svgEl.appendChild(nodeGroup);

  function edgeColor(type) {
    return type === 'call' ? '#88c0d0'
      : type === 'jmp' ? '#b48ead'
      : type === 'jumptable' ? '#ebcb8b'
      : '#88d8ff';
  }

  // ── Orthogonal edge routing ───────────────────────────────────────────────
  // When ELK is used, edges carry `sections` with startPoint / bendPoints / endPoint.
  // We build the SVG path directly from those points (pure L segments = orthogonal).
  // For back-edges (loops) or when sections are absent, we fall back to the
  // hand-crafted routing below.

  /**
   * Build an SVG route descriptor from an ordered list of {x, y} points.
   * Returns { d, labelX, labelY, minX, maxX, minY, maxY }.
   */
  function buildEdgeRoute(points, labelPoint = null) {
    const clean = [];
    for (const pt of points) {
      if (!pt || !Number.isFinite(pt.x) || !Number.isFinite(pt.y)) continue;
      const p = { x: Math.round(pt.x * 10) / 10, y: Math.round(pt.y * 10) / 10 };
      const prev = clean[clean.length - 1];
      if (!prev || prev.x !== p.x || prev.y !== p.y) clean.push(p);
    }
    if (!clean.length) return { d: '', labelX: 0, labelY: 0, minX: 0, maxX: 0, minY: 0, maxY: 0 };
    let d = `M ${clean[0].x} ${clean[0].y}`;
    for (let i = 1; i < clean.length; i++) d += ` L ${clean[i].x} ${clean[i].y}`;
    const xs = clean.map(p => p.x);
    const ys = clean.map(p => p.y);
    const mid = clean[Math.floor(clean.length / 2)] || clean[0];
    const lp = labelPoint && Number.isFinite(labelPoint.x) && Number.isFinite(labelPoint.y)
      ? { x: Math.round(labelPoint.x * 10) / 10, y: Math.round(labelPoint.y * 10) / 10 }
      : mid;
    return { d, labelX: lp.x, labelY: lp.y, minX: Math.min(...xs), maxX: Math.max(...xs), minY: Math.min(...ys), maxY: Math.max(...ys) };
  }

  /**
   * Compute a fully dynamic orthogonal SVG path for a forward edge.
   *
   * Always uses live nodePositions + nodeHeights so the path stays connected
   * after expand/collapse, regardless of what ELK computed at layout time.
   *
   * Routing rules:
   *   - Departs from the bottom-center of the source block.
   *   - Arrives at the top-center of the target block.
   *   - A single horizontal bend at the midpoint of the vertical gap → pure orthogonal.
   *   - When multiple edges leave the same source or arrive at the same target,
   *     a small horizontal lane offset separates them so they don't overlap.
   *   - When source and target are at the same Y (or very close), detour right.
   */
  function computeEdgeD(from, to) {
    const fp = nodePositions[from];
    const tp = nodePositions[to];
    if (!fp || !tp) return buildEdgeRoute([]);

    const fromH = nodeHeights[from] || nodeH;
    const toH   = nodeHeights[to]   || nodeH;
    const key   = edgeKey(from, to);

    // Lane offsets separate parallel edges leaving/entering the same node.
    const srcLane = clampLaneOffset((forwardSourceLane.get(key) || 0) * FORWARD_LANE_GAP);
    const dstLane = clampLaneOffset((forwardTargetLane.get(key) || 0) * FORWARD_LANE_GAP);

    // Anchor points — always on the node boundary, never floating
    const x1 = fp.x + nodeW / 2 + srcLane;   // bottom-center of source (± lane offset)
    const y1 = fp.y + fromH;                   // bottom edge of source
    const x2 = tp.x + nodeW / 2 + dstLane;   // top-center of target (± lane offset)
    const y2 = tp.y;                            // top edge of target

    const spanY = y2 - y1;

    // ── Case A: same row or near-miss (spanY tiny) ──────────────────────────
    // Exit from the right side of the source and enter from the left of the target
    // to keep the path readable. Fully orthogonal: H → V → H.
    if (spanY < 16) {
      const rightEdge = Math.max(fp.x + nodeW, tp.x + nodeW);
      const detourX   = rightEdge + 48 + Math.abs(srcLane - dstLane) * 0.5;
      const midY      = (fp.y + fromH / 2 + tp.y + toH / 2) / 2;
      return buildEdgeRoute([
        { x: fp.x + nodeW, y: fp.y + fromH / 2 }, // exit right side of source
        { x: detourX,      y: fp.y + fromH / 2 }, // go right
        { x: detourX,      y: tp.y  + toH  / 2 }, // go down/up (V)
        { x: tp.x,         y: tp.y  + toH  / 2 }, // enter left side of target
      ], { x: detourX + 6, y: midY });
    }

    // ── Case B: normal forward edge — strictly orthogonal 5-point path ──────
    //
    //   x1,y1 ──(V)──> x1,channelY ──(H)──> x2,channelY ──(V)──> x2,y2
    //
    // This produces exactly two 90° turns and zero diagonal segments.
    // The horizontal channel sits halfway between the two nodes' gaps.
    const channelY = y1 + spanY / 2;

    const pts = [
      { x: x1, y: y1        },   // departure  — bottom of source
      { x: x1, y: channelY  },   // drop vertically to channel
      { x: x2, y: channelY  },   // move horizontally to target column
      { x: x2, y: y2        },   // rise vertically into target top
    ];

    const labelPt = { x: (x1 + x2) / 2, y: channelY - 10 };
    return buildEdgeRoute(pts, labelPt);
  }

  /**
   * Compute a fully dynamic orthogonal SVG path for a back-edge (loop).
   *
   * Always uses live nodePositions + nodeHeights.
   * Routes out of the right side of the source, around, and back into
   * the left side of the target to avoid overlapping forward edges.
   */
  function computeBackEdgeD(from, to) {
    const fp = nodePositions[from];
    const tp = nodePositions[to];
    if (!fp || !tp) return buildEdgeRoute([]);

    const fromH = nodeHeights[from] || nodeH;
    const toH   = nodeHeights[to]   || nodeH;
    const key   = edgeKey(from, to);
    const laneIndex = backEdgeLane.get(key) || 0;

    // Exit from bottom-right of source, enter top-left of target
    const x1 = fp.x + nodeW;                                               // right edge of source
    const y1 = fp.y + fromH - Math.min(12, fromH * 0.25);                 // near-bottom of source
    const x2 = tp.x;                                                        // left edge of target
    const y2 = tp.y + Math.min(12, toH * 0.25);                           // near-top of target

    // Detour column: far enough right to clear all nodes in both rows
    const rightEdge = Math.max(fp.x + nodeW, tp.x + nodeW);
    const detourX   = rightEdge + 48 + laneIndex * BACK_EDGE_LANE_GAP;

    return buildEdgeRoute([
      { x: x1,      y: y1 },        // exit right side of source
      { x: detourX, y: y1 },        // go right to detour column
      { x: detourX, y: y2 },        // drop/rise to target row
      { x: x2,      y: y2 },        // enter left side of target
    ], { x: detourX + 6, y: (y1 + y2) / 2 });
  }

  // Track which code nodes are expanded (collapsed by default on first render).
  const expandedNodes = new Set(nodes
    .filter((n) => hasCode && n.lines && n.lines.length > 0 && initialExpandedSet.has(n.addr))
    .map((n) => n.addr));
  let activeNodeAddr = null;
  const nodeEls = {};
  const edgeEls = {};
  const edgeRouteCache = {};
  const edgeLabelEls = [];

  function applyCodeRowLayout() {
    if (!hasCode || rowGroups.length === 0) return;
    let nextY = rowGroups[0].baseY;
    rowGroups.forEach((row) => {
      const rowMaxH = row.addrs.reduce((max, addr) => {
        return Math.max(max, nodeHeights[addr] || preHeights[addr] || nodeH);
      }, COMPACT_H);
      row.addrs.forEach((addr) => {
        const pos = nodePositions[addr];
        if (!pos) return;
        pos.y = nextY;
        nodeEls[addr]?.setAttribute('transform', `translate(${pos.x},${pos.y})`);
      });
      nextY += rowMaxH + padY;
    });
  }

  function updateEdgeGeometry(changedAddr = null) {
    Object.entries(edgeEls).forEach(([key, pathEl]) => {
      const [from, to] = key.split('|');
      if (changedAddr && from !== changedAddr && to !== changedAddr) return;
      const isBack = backEdgeSet.has(key);
      const route = isBack ? computeBackEdgeD(from, to) : computeEdgeD(from, to);
      edgeRouteCache[key] = route;
      pathEl.setAttribute('d', route.d);
    });
    edgeLabelEls.forEach(({ edge, labelEl }) => {
      if (changedAddr && edge.from !== changedAddr && edge.to !== changedAddr) return;
      const key = edgeKey(edge.from, edge.to);
      const route = edgeRouteCache[key]
        || (backEdgeSet.has(key) ? computeBackEdgeD(edge.from, edge.to) : computeEdgeD(edge.from, edge.to));
      edgeRouteCache[key] = route;
      labelEl.setAttribute('x', String(Math.round(route.labelX)));
      labelEl.setAttribute('y', String(Math.round(route.labelY)));
    });
  }

  function resolveNodeAddress(addr) {
    const normalized = normalizeHexAddress(addr);
    if (!normalized) return null;
    for (const n of nodes) {
      if (normalizeHexAddress(n.addr) === normalized) return n.addr;
      if (hasCode && Array.isArray(n.lines) && n.lines.some((ln) => normalizeHexAddress(ln.addr) === normalized)) {
        return n.addr;
      }
    }
    return null;
  }

  function applyActiveNode(addr) {
    if (activeNodeAddr && nodeEls[activeNodeAddr]) nodeEls[activeNodeAddr].classList.remove('is-active');
    activeNodeAddr = addr || null;
    if (activeNodeAddr && nodeEls[activeNodeAddr]) nodeEls[activeNodeAddr].classList.add('is-active');
    svgEl.dataset.activeNodeAddr = activeNodeAddr || '';
    return activeNodeAddr;
  }

  function getNodeBox(addr) {
    const pos = nodePositions[addr];
    if (!pos) return null;
    return {
      x: pos.x,
      y: pos.y,
      w: nodeW,
      h: nodeHeights[addr] || nodeH,
    };
  }

  function appendInstructionLine(group, ln, y) {
    const lineAddr = (ln.addr || '').replace(/^0x0*/, '0x');
    const lineText = formatCfgLineDisplay(ln);

    const addrEl = document.createElementNS(NS, 'text');
    addrEl.setAttribute('x', ADDR_X);
    addrEl.setAttribute('y', y);
    addrEl.setAttribute('fill', '#6a737d');
    addrEl.setAttribute('font-size', '10');
    addrEl.setAttribute('font-family', 'monospace');
    addrEl.textContent = lineAddr;
    group.appendChild(addrEl);

    const codeEl = document.createElementNS(NS, 'text');
    codeEl.setAttribute('x', CODE_X);
    codeEl.setAttribute('y', y);
    codeEl.setAttribute('fill', '#d4d4d4');
    codeEl.setAttribute('font-size', '10');
    codeEl.setAttribute('font-family', 'monospace');
    codeEl.textContent = lineText;
    group.appendChild(codeEl);
  }

  edges.forEach((e) => {
    const key = `${e.from}|${e.to}`;
    const isBack = backEdgeSet.has(key);
    const route = isBack ? computeBackEdgeD(e.from, e.to) : computeEdgeD(e.from, e.to);
    edgeRouteCache[key] = route;
    const pathEl = document.createElementNS(NS, 'path');
    pathEl.setAttribute('class', isBack ? 'cfg-edge cfg-back-edge' : 'cfg-edge');
    pathEl.dataset.from = e.from;
    pathEl.dataset.to = e.to;
    pathEl.setAttribute('d', route.d);
    pathEl.setAttribute('fill', 'none');
    pathEl.setAttribute('stroke', isBack ? '#d08770' : edgeColor(e.type));
    pathEl.setAttribute('stroke-width', '2');
    if (isBack) pathEl.setAttribute('stroke-dasharray', '6,3');
    pathEl.setAttribute('marker-end', `url(#${isBack ? backMarkerId : markerId})`);
    edgeGroup.appendChild(pathEl);
    edgeEls[key] = pathEl;

    if (e.type === 'jumptable' && e.case_label !== undefined && e.case_label !== null) {
      if (route.d) {
        const labelEl = document.createElementNS(NS, 'text');
        labelEl.setAttribute('x', String(Math.round(route.labelX)));
        labelEl.setAttribute('y', String(Math.round(route.labelY)));
        labelEl.setAttribute('fill', '#ebcb8b');
        labelEl.setAttribute('font-size', '9');
        labelEl.setAttribute('font-family', 'monospace');
        labelEl.setAttribute('text-anchor', 'middle');
        labelEl.setAttribute('pointer-events', 'none');
        labelEl.textContent = `case ${e.case_label}`;
        edgeGroup.appendChild(labelEl);
        edgeLabelEls.push({ edge: e, labelEl });
      }
    }
  });

  const nodeDataMap = {};
  nodes.forEach(n => { nodeDataMap[n.addr] = n; });

  nodes.forEach((n) => {
    const p = nodePositions[n.addr] || { x: 0, y: 0 };
    const h = preHeights[n.addr] || nodeH;
    nodeHeights[n.addr] = h;
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', 'cfg-node');
    g.dataset.addr = n.addr;
    g.setAttribute('transform', `translate(${p.x},${p.y})`);
    g.setAttribute('tabindex', '0');
    g.style.cursor = 'pointer';

    const isExt = n.isExternal;
    const strokeColor = isExt ? '#88c0d0' : '#88d8ff';

    // Background rect
    const rect = document.createElementNS(NS, 'rect');
    rect.setAttribute('width', nodeW);
    rect.setAttribute('height', h);
    rect.setAttribute('rx', hasCode ? '2' : '8');
    rect.setAttribute('fill', hasCode ? '#111827' : '#1a1a2e');
    rect.setAttribute('stroke', strokeColor);
    rect.setAttribute('stroke-width', hasCode ? '1.2' : '2');
    if (isExt) rect.setAttribute('stroke-dasharray', '4,2');
    g.appendChild(rect);

    const label = n.label || n.addr.replace(/^0x/, '');

    if (hasCode && n.lines && n.lines.length > 0) {
      // ── Cutter-style: header + collapsible instructions ──
      const hasStackHints = n.lines.some((ln) => Array.isArray(ln.stack_hints) && ln.stack_hints.length > 0);
      const hasComments = n.lines.some((ln) => String(ln.comment || '').trim().length > 0);

      // Header background (accent strip at top)
      const headerBg = document.createElementNS(NS, 'rect');
      headerBg.setAttribute('x', '2');
      headerBg.setAttribute('y', '2');
      headerBg.setAttribute('width', nodeW - 4);
      headerBg.setAttribute('height', HEADER_H - 2);
      headerBg.setAttribute('rx', '1');
      headerBg.setAttribute('fill', strokeColor);
      headerBg.setAttribute('opacity', '0.15');
      g.appendChild(headerBg);

      // Header label (block addr / function name)
      const hLabel = document.createElementNS(NS, 'text');
      hLabel.setAttribute('x', ADDR_X);
      hLabel.setAttribute('y', '17');
      hLabel.setAttribute('fill', strokeColor);
      hLabel.setAttribute('font-size', '11');
      hLabel.setAttribute('font-weight', '700');
      hLabel.setAttribute('font-family', 'monospace');
      hLabel.textContent = label.length > 36 ? label.substring(0, 34) + '\u2026' : label;
      g.appendChild(hLabel);

      const badgeSpecs = [];
      if (n.is_switch) badgeSpecs.push({ text: 'switch', color: '#ebcb8b' });
      const caseSummary = summarizeSwitchCaseLabels(n.caseLabels || [], { max: 2 });
      if (caseSummary) badgeSpecs.push({ text: caseSummary, color: '#ffd166', title: summarizeSwitchCaseLabels(n.caseLabels || [], { max: 12 }) });
      if (hasStackHints) badgeSpecs.push({ text: 'stack', color: '#9cdfff' });
      if (hasComments) badgeSpecs.push({ text: 'notes', color: '#c3e88d' });
      let badgeOffset = 0;
      badgeSpecs.forEach((badge) => {
        const badgeEl = document.createElementNS(NS, 'text');
        badgeEl.setAttribute('x', String(nodeW - 6 - badgeOffset));
        badgeEl.setAttribute('y', '10');
        badgeEl.setAttribute('fill', badge.color);
        badgeEl.setAttribute('font-size', '9');
        badgeEl.setAttribute('font-family', 'monospace');
        badgeEl.setAttribute('text-anchor', 'end');
        badgeEl.setAttribute('pointer-events', 'none');
        badgeEl.textContent = badge.text;
        if (badge.title) badgeEl.setAttribute('title', badge.title);
        g.appendChild(badgeEl);
        badgeOffset += Math.max(46, badge.text.length * 6 + 10);
      });

      // Caret + instruction count (right-aligned) — double-click for more/less code
      const caretEl = document.createElementNS(NS, 'text');
      caretEl.setAttribute('x', nodeW - 6);
      caretEl.setAttribute('y', '17');
      caretEl.setAttribute('text-anchor', 'end');
      caretEl.setAttribute('fill', '#6a737d');
      caretEl.setAttribute('font-size', '11');
      caretEl.setAttribute('font-family', 'monospace');
      caretEl.setAttribute('class', 'cfg-node-caret');
      const startsExpanded = expandedNodes.has(n.addr);
      caretEl.textContent = `${n.lines.length}\u202f${startsExpanded ? '\u25be' : '\u25b8'}`;
      g.appendChild(caretEl);

      // Body group (preview instructions) — visible by default
      const bodyGroup = document.createElementNS(NS, 'g');
      bodyGroup.setAttribute('class', 'cfg-node-body');

      // Separator line inside bodyGroup
      const sep = document.createElementNS(NS, 'line');
      sep.setAttribute('x1', '4');
      sep.setAttribute('y1', HEADER_H);
      sep.setAttribute('x2', nodeW - 4);
      sep.setAttribute('y2', HEADER_H);
      sep.setAttribute('stroke', '#333');
      sep.setAttribute('stroke-width', '1');
      bodyGroup.appendChild(sep);

      const previewCount = Math.min(n.lines.length, PREVIEW_LINES);
      const expandedCount = Math.min(n.lines.length, MAX_EXPANDED);
      for (let i = 0; i < previewCount; i++) {
        const y = HEADER_H + 4 + (i + 1) * LINE_H;
        appendInstructionLine(bodyGroup, n.lines[i], y);
      }

      let previewMoreEl = null;
      if (n.lines.length > PREVIEW_LINES) {
        const moreY = HEADER_H + 4 + (previewCount + 1) * LINE_H;
        previewMoreEl = document.createElementNS(NS, 'text');
        previewMoreEl.setAttribute('x', ADDR_X);
        previewMoreEl.setAttribute('y', moreY);
        previewMoreEl.setAttribute('fill', '#6a737d');
        previewMoreEl.setAttribute('font-size', '10');
        previewMoreEl.setAttribute('font-family', 'monospace');
        previewMoreEl.setAttribute('font-style', 'italic');
        previewMoreEl.textContent = `\u2026 +${n.lines.length - PREVIEW_LINES} lignes`;
        previewMoreEl.style.display = startsExpanded ? 'none' : '';
        bodyGroup.appendChild(previewMoreEl);
      }

      g.appendChild(bodyGroup);

      const extraGroup = document.createElementNS(NS, 'g');
      extraGroup.setAttribute('class', 'cfg-node-extra');
      extraGroup.style.display = startsExpanded ? '' : 'none';

      for (let i = previewCount; i < expandedCount; i++) {
        const y = HEADER_H + 4 + (i + 1) * LINE_H;
        appendInstructionLine(extraGroup, n.lines[i], y);
      }

      let extraMoreEl = null;
      if (n.lines.length > MAX_EXPANDED) {
        const moreY = HEADER_H + 4 + (expandedCount + 1) * LINE_H;
        extraMoreEl = document.createElementNS(NS, 'text');
        extraMoreEl.setAttribute('x', ADDR_X);
        extraMoreEl.setAttribute('y', moreY);
        extraMoreEl.setAttribute('fill', '#6a737d');
        extraMoreEl.setAttribute('font-size', '10');
        extraMoreEl.setAttribute('font-family', 'monospace');
        extraMoreEl.setAttribute('font-style', 'italic');
        extraMoreEl.textContent = `\u2026 +${n.lines.length - MAX_EXPANDED} lignes`;
        extraGroup.appendChild(extraMoreEl);
      }

      g.appendChild(extraGroup);

      // Store refs for toggle handler
      g._bodyGroup = bodyGroup;
      g._extraGroup = extraGroup;
      g._caretEl = caretEl;
      g._previewMoreEl = previewMoreEl;
      g._extraMoreEl = extraMoreEl;
      g._nLines = n.lines.length;

    } else {
      // ── Simple mode: label + sublabel (Call Graph) ──
      const t1 = document.createElementNS(NS, 'text');
      t1.setAttribute('x', nodeW / 2);
      t1.setAttribute('y', h / 2 + (n.sublabel ? -4 : 4));
      t1.setAttribute('text-anchor', 'middle');
      t1.setAttribute('fill', strokeColor);
      t1.setAttribute('font-size', '12');
      t1.setAttribute('font-weight', '600');
      t1.textContent = label.length > 32 ? label.substring(0, 30) + '\u2026' : label;
      g.appendChild(t1);

      if (n.sublabel) {
        const t2 = document.createElementNS(NS, 'text');
        t2.setAttribute('x', nodeW / 2);
        t2.setAttribute('y', h / 2 + 14);
        t2.setAttribute('text-anchor', 'middle');
        t2.setAttribute('fill', '#8b949e');
        t2.setAttribute('font-size', '10');
        t2.textContent = n.sublabel;
        g.appendChild(t2);
      }
    }

    nodeGroup.appendChild(g);
    nodeEls[n.addr] = g;
  });

  // --- Dynamic SVG bounds (no invisible walls) ---
  function updateSvgBounds() {
    const addrs = Object.keys(nodePositions);
    if (addrs.length === 0) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const addr of addrs) {
      const p = nodePositions[addr];
      const h = nodeHeights[addr] || nodeH;
      if (p.x < minX) minX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.x + nodeW > maxX) maxX = p.x + nodeW;
      if (p.y + h > maxY) maxY = p.y + h;
    }
    Object.values(edgeRouteCache).forEach((route) => {
      if (!route || !route.d) return;
      if (route.minX < minX) minX = route.minX;
      if (route.minY < minY) minY = route.minY;
      if (route.maxX > maxX) maxX = route.maxX;
      if (route.maxY > maxY) maxY = route.maxY;
    });
    const pad = 40;
    const vbX = Math.min(0, minX - pad);
    const vbY = Math.min(0, minY - pad);
    const newW = Math.max(600, maxX + pad - vbX);
    const newH = Math.max(400, maxY + pad - vbY);
    if (newW !== svgW || newH !== svgH || vbX < 0 || vbY < 0) {
      svgW = newW;
      svgH = newH;
      svgEl.setAttribute('width', svgW);
      svgEl.setAttribute('height', svgH);
      svgEl.setAttribute('viewBox', `${vbX} ${vbY} ${svgW} ${svgH}`);
    }
  }

  applyCodeRowLayout();
  updateEdgeGeometry();
  updateSvgBounds();
  svgEl._resolveNodeAddress = resolveNodeAddress;
  svgEl._setActiveAddress = (addr) => applyActiveNode(resolveNodeAddress(addr));
  svgEl._setActiveNode = (addr) => applyActiveNode(addr);
  svgEl._getNodeBox = getNodeBox;

  // --- Node drag ---
  let dragAddr = null;
  let dragStart = { cx: 0, cy: 0, nx: 0, ny: 0 };
  let didDrag = false;

  nodeGroup.addEventListener('mousedown', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || e.shiftKey || e.altKey || e.metaKey || e.ctrlKey || e.button !== 0) return;
    e.stopPropagation();
    dragAddr = nodeEl.dataset.addr;
    const p = nodePositions[dragAddr] || { x: 0, y: 0 };
    dragStart = { cx: e.clientX, cy: e.clientY, nx: p.x, ny: p.y };
    didDrag = false;
  });

  document.addEventListener('mousemove', (e) => {
    if (!dragAddr) return;
    const s = zoomState.scale || 1;
    const dx = (e.clientX - dragStart.cx) / s;
    const dy = (e.clientY - dragStart.cy) / s;
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) didDrag = true;
    if (!didDrag) return;
    const nx = dragStart.nx + dx;
    const ny = dragStart.ny + dy;
    nodePositions[dragAddr] = { x: nx, y: ny };
    nodeEls[dragAddr]?.setAttribute('transform', `translate(${nx},${ny})`);
    updateEdgeGeometry(dragAddr);
    updateSvgBounds();
  });

  document.addEventListener('mouseup', () => { dragAddr = null; });

  nodeGroup.addEventListener('contextmenu', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || !onNodeIsolate) return;
    e.preventDefault();
    e.stopPropagation();
    onNodeIsolate(nodeEl.dataset.addr);
  });

  // --- Shift+click BFS path highlight ---
  const HIGHLIGHT = '#ffd700';
  let hlStart = null;

  function clearHighlight() {
    edgeGroup.querySelectorAll('.cfg-edge').forEach((pathEl) => {
      const key = `${pathEl.dataset.from}|${pathEl.dataset.to}`;
      const isBack = backEdgeSet.has(key);
      const e = edges.find((ed) => ed.from === pathEl.dataset.from && ed.to === pathEl.dataset.to);
      pathEl.setAttribute('stroke', isBack ? '#d08770' : edgeColor(e ? e.type : ''));
      pathEl.setAttribute('stroke-width', '2');
      if (isBack) {
        pathEl.setAttribute('stroke-dasharray', '6,3');
      } else {
        pathEl.removeAttribute('stroke-dasharray');
      }
    });
    Object.entries(nodeEls).forEach(([addr, g]) => {
      const nd = nodeDataMap[addr];
      const extNode = nd && nd.isExternal;
      const r = g.querySelector('rect');
      if (r) r.setAttribute('stroke', extNode ? '#88c0d0' : '#88d8ff');
    });
  }

  nodeGroup.addEventListener('click', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || didDrag) return;
    const addr = nodeEl.dataset.addr;

    if (e.altKey && onNodeIsolate) {
      e.preventDefault();
      onNodeIsolate(addr);
      return;
    }

    if (e.shiftKey) {
      if (!hlStart) {
        hlStart = addr;
        nodeEl.querySelector('rect')?.setAttribute('stroke', HIGHLIGHT);
      } else {
        const path = window.cfgHelpers.bfsPath(adj, hlStart, addr);
        clearHighlight();
        hlStart = null;
        if (path && path.length > 1) {
          path.forEach((a) => nodeEls[a]?.querySelector('rect')?.setAttribute('stroke', HIGHLIGHT));
          for (let i = 0; i < path.length - 1; i++) {
            const el = edgeEls[`${path[i]}|${path[i + 1]}`];
            if (el) { el.setAttribute('stroke', HIGHLIGHT); el.setAttribute('stroke-width', '3'); }
          }
        }
      }
      return;
    }

    clearHighlight();
    hlStart = null;
    applyActiveNode(resolveNodeAddress(addr));
    if (onNodeClick && addr !== lastDblClickAddr) onNodeClick(addr);
  });

  // --- Double-click: expand/collapse code node ---
  // Flag to prevent the two rapid clicks of a dblclick from firing onNodeClick
  let lastDblClickAddr = null;
  nodeGroup.addEventListener('dblclick', (e) => {
    if (!hasCode) return;
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || !nodeEl._extraGroup) return;
    e.stopPropagation();
    const addr = nodeEl.dataset.addr;
    lastDblClickAddr = addr;
    setTimeout(() => { if (lastDblClickAddr === addr) lastDblClickAddr = null; }, 300);
    const nd = nodeDataMap[addr];
    if (!nd || !nd.lines || nd.lines.length === 0) return;

    const isExpanded = expandedNodes.has(addr);
    const rect = nodeEl.querySelector('rect');

    if (isExpanded) {
      expandedNodes.delete(addr);
      nodeEl._extraGroup.style.display = 'none';
      if (nodeEl._previewMoreEl) nodeEl._previewMoreEl.style.display = '';
      if (nodeEl._extraMoreEl) nodeEl._extraMoreEl.style.display = 'none';
      nodeEl._caretEl.textContent = `${nd.lines.length}\u202f\u25b8`;
      const h = previewHeight(nd);
      if (rect) rect.setAttribute('height', h);
      nodeHeights[addr] = h;
    } else {
      expandedNodes.add(addr);
      nodeEl._extraGroup.style.display = '';
      if (nodeEl._previewMoreEl) nodeEl._previewMoreEl.style.display = 'none';
      if (nodeEl._extraMoreEl) nodeEl._extraMoreEl.style.display = '';
      nodeEl._caretEl.textContent = `${nd.lines.length}\u202f\u25be`;
      const h = expandedHeight(nd);
      if (rect) rect.setAttribute('height', h);
      nodeHeights[addr] = h;
    }

    if (typeof opts?.onExpandedChange === 'function') {
      opts.onExpandedChange(Array.from(expandedNodes));
    }
    applyCodeRowLayout();
    updateEdgeGeometry();
    updateSvgBounds();
  });

  // --- Rich tooltip ---
  const tooltipEl = document.createElement('div');
  tooltipEl.className = 'cfg-tooltip';

  nodeGroup.addEventListener('mouseover', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl) return;
    nodeEl.querySelector('rect')?.setAttribute('stroke', '#81a1c1');
    const addr = nodeEl.dataset.addr;
    const nd = nodeDataMap[addr];
    if (!nd) return;

    // Build tooltip content
    const titleDiv = document.createElement('div');
    titleDiv.className = 'cfg-tooltip-title';
    titleDiv.textContent = nd.label || nd.addr;

    tooltipEl.replaceChildren(titleDiv);

    if (nd.sublabel) {
      const subDiv = document.createElement('div');
      subDiv.className = 'cfg-tooltip-sub';
      subDiv.textContent = nd.sublabel;
      tooltipEl.appendChild(subDiv);
    }

    if (nd.lines && nd.lines.length > 0) {
      const codeDiv = document.createElement('div');
      codeDiv.className = 'cfg-tooltip-code';
      const maxLines = Math.min(nd.lines.length, 15);
      nd.lines.slice(0, maxLines).forEach((ln) => {
        const lineEl = document.createElement('div');
        lineEl.className = 'cfg-tooltip-line';
        lineEl.textContent = formatCfgLineDisplay(ln, 90);
        codeDiv.appendChild(lineEl);
        const meta = collectCfgLineMeta(ln);
        if (meta.label || meta.comment || meta.stackHints.length) {
          const metaWrap = document.createElement('div');
          metaWrap.className = 'cfg-tooltip-meta';
          if (meta.label) {
            const labelEl = document.createElement('span');
            labelEl.className = 'cfg-tooltip-label';
            labelEl.textContent = `label ${meta.label}`;
            metaWrap.appendChild(labelEl);
          }
          if (meta.comment) {
            const commentEl = document.createElement('span');
            commentEl.className = 'cfg-tooltip-comment';
            commentEl.textContent = meta.comment;
            metaWrap.appendChild(commentEl);
          }
          if (meta.stackHints.length) {
            const hintsEl = document.createElement('div');
            hintsEl.className = 'xref-stack-hints cfg-tooltip-hints';
            meta.stackHints.slice(0, 4).forEach((hint) => {
              const chip = document.createElement('span');
              chip.className = 'xref-stack-chip';
              const label = cfgStackHintLabel(hint);
              chip.textContent = label || 'stack';
              if (hint.location) chip.title = `${chip.textContent} @ ${hint.location}`;
              hintsEl.appendChild(chip);
            });
            metaWrap.appendChild(hintsEl);
          }
          codeDiv.appendChild(metaWrap);
        }
      });
      if (nd.lines.length > maxLines) {
        const moreEl = document.createElement('div');
        moreEl.className = 'cfg-tooltip-more';
        moreEl.textContent = '\u2026';
        codeDiv.appendChild(moreEl);
      }
      tooltipEl.appendChild(codeDiv);
    }

    tooltipEl.style.display = 'block';
  });

  nodeGroup.addEventListener('mousemove', (e) => {
    if (tooltipEl.style.display !== 'block') return;
    const x = e.clientX + 12;
    const y = e.clientY + 12;
    const maxX = window.innerWidth - 380;
    const maxY = window.innerHeight - tooltipEl.offsetHeight - 10;
    tooltipEl.style.left = Math.min(x, maxX) + 'px';
    tooltipEl.style.top = Math.min(y, maxY) + 'px';
  });

  nodeGroup.addEventListener('mouseout', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (nodeEl && nodeEl.dataset.addr !== hlStart) {
      const nd = nodeDataMap[nodeEl.dataset.addr];
      nodeEl.querySelector('rect')?.setAttribute('stroke', (nd && nd.isExternal) ? '#88c0d0' : '#88d8ff');
    }
    tooltipEl.style.display = 'none';
  });

  svgEl._tooltip = tooltipEl;
  return svgEl;
}

function renderStringsTable(container, strings, filterText, useRegex) {
  let filtered = strings;
  let regexError = false;
  if (filterText) {
    if (useRegex) {
      try {
        const re = new RegExp(filterText);
        filtered = strings.filter((s) => re.test(String(s.value)));
      } catch {
        filtered = [];
        regexError = true;
      }
    } else {
      const q = filterText.toLowerCase();
      filtered = strings.filter((s) => String(s.value).toLowerCase().includes(q));
    }
  }
  const toShow = filtered.slice(0, 500);
  const encodingLabel = (encoding) => {
    if (encoding === 'utf-16-le') return 'UTF-16 LE';
    if (encoding === 'utf-16-be') return 'UTF-16 BE';
    return 'UTF-8 / ASCII';
  };
  const rows = toShow.map((s) => {
    const val = String(s.value);
    const display = val.length > 80 ? val.substring(0, 80) + '…' : val;
    const addr = escapeHtml(String(s.addr || ''));
    return `<tr class="nav-addr-row" data-addr="${addr}" data-addr-match="exact"><td><code class="addr-link" data-addr="${addr}">${addr}</code></td><td>${escapeHtml(encodingLabel(String(s.encoding || 'utf-8')))}</td><td>${escapeHtml(String(s.length))}</td><td>${escapeHtml(display)}</td></tr>`;
  }).join('');
  const hintCls = regexError ? 'hint error' : 'hint';
  let hint = regexError ? 'Regex invalide' : (filterText ? `${filtered.length} / ${strings.length} chaîne(s)` : `${strings.length} chaîne(s)`);
  const encodingCounts = filtered.reduce((acc, entry) => {
    const key = String(entry.encoding || 'utf-8');
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const encodingSummary = Object.entries(encodingCounts)
    .map(([encoding, count]) => `${encodingLabel(encoding)}: ${count}`)
    .join(' · ');
  hint += ' — Les adresses sont des adresses virtuelles.';
  if (encodingSummary) hint += ` — ${encodingSummary}`;
  container.innerHTML = `<table class="data-table"><thead><tr><th>Adresse</th><th>Encodage</th><th>Long.</th><th>Valeur</th></tr></thead><tbody>${rows}</tbody></table><p class="${hintCls}">${hint}</p>`;
  container.querySelectorAll('.addr-link[data-addr]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const binaryPath = getStaticBinaryPath();
      const addr = link.dataset.addr || '';
      if (!binaryPath || !addr) return;
      vscode.postMessage({ type: 'hubGoToAddress', binaryPath, addr });
    });
  });
  updateActiveNavRows(window._lastDisasmAddr);
}

// Dynamic: form submit
form?.addEventListener('submit', (e) => {
  e.preventDefault();
  const binaryPath = binaryPathInput?.value?.trim() || '';
  if (!binaryPath) {
    setDynamicTraceStatus('Chemin binaire requis.');
    return;
  }

  if (runBtn) runBtn.disabled = true;
  setDynamicTraceStatus('Trace en cours...');
  vscode.postMessage({
    type: 'runTrace',
    config: {
      traceMode: 'dynamic',
      useExistingBinary: true,
      binaryPath,
      sourcePath: dynamicSourcePathInput?.value?.trim() || '',
      archBits: dynamicTraceInitState.archBits,
      pie: dynamicTraceInitState.pie,
      bufferOffset: String(dynamicTraceInitState.profile.bufferOffset ?? ''),
      bufferSize: String(dynamicTraceInitState.profile.bufferSize ?? ''),
      maxSteps: String(dynamicTraceInitState.profile.maxSteps ?? 800),
      startSymbol: String(dynamicTraceInitState.profile.startSymbol || ''),
      stopSymbol: String(dynamicTraceInitState.profile.stopSymbol || ''),
      injectPayload: !!(argvPayloadInput?.value?.trim()),
      payloadExpr: argvPayloadInput?.value?.trim() || '',
      payloadTargetMode: getDynamicPayloadTargetMode(),
      payloadTarget: getDynamicPayloadTargetMode(),
    }
  });
});

// Offset calculator
function updateOffsetCalc() {
  const hexInput = document.getElementById('offsetHex');
  const decInput = document.getElementById('offsetDec');
  const baseInput = document.getElementById('offsetBase');
  const deltaInput = document.getElementById('offsetDelta');
  const resultInput = document.getElementById('offsetResult');

  function hexToDec(hex) {
    const s = String(hex).replace(/^0x/i, '').trim();
    if (!s) return null;
    const n = parseInt(s, 16);
    return isNaN(n) ? null : n;
  }

  function decToHex(dec) {
    const n = parseInt(dec, 10);
    if (isNaN(n)) return null;
    return '0x' + (n >= 0 ? n : (0xFFFFFFFF + n + 1)).toString(16);
  }

  hexInput?.addEventListener('input', () => {
    const dec = hexToDec(hexInput.value);
    if (dec !== null) decInput.value = dec;
  });

  decInput?.addEventListener('input', () => {
    const hex = decToHex(decInput.value);
    if (hex !== null) hexInput.value = hex;
  });

  function computeAddr() {
    const base = hexToDec(baseInput?.value || '0');
    const delta = hexToDec(deltaInput?.value) ?? parseInt(deltaInput?.value, 10);
    if (base === null || (delta === undefined || isNaN(delta))) return;
    resultInput.value = '0x' + (base + delta).toString(16);
  }

  baseInput?.addEventListener('input', computeAddr);
  deltaInput?.addEventListener('input', computeAddr);
}

updateOffsetCalc();

// Calculette: Enter, copier résultat
document.getElementById('offsetBase')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
document.getElementById('offsetDelta')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
document.getElementById('offsetResult')?.addEventListener('click', () => {
  const v = document.getElementById('offsetResult')?.value;
  if (v && navigator.clipboard) navigator.clipboard.writeText(v).then(() => { /* ok */ });
});
document.getElementById('offsetResult')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });

// Payload conversion
function doPayloadConvert() {
  const input = document.getElementById('payloadInput')?.value?.trim();
  if (!input) {
    vscode.postMessage({ type: 'hubError', message: 'Saisissez une expression.' });
    return;
  }
  vscode.postMessage({ type: 'hubPayloadToHex', payload: input });
}
document.getElementById('btnPayloadToHex')?.addEventListener('click', doPayloadConvert);
document.getElementById('payloadInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doPayloadConvert(); } });

function setTraceField(name, value) {
  const el = form?.querySelector(`[name="${name}"]`);
  if (!el) return;
  if (el.type === 'checkbox') el.checked = !!value;
  else el.value = String(value ?? '');
}

function applyDynamicPreset({
  startSymbol,
  targetSymbol,
  payloadExpr,
  payloadTarget,
  maxSteps,
  suggestedOffset,
  suggestedCaptureSize,
  binaryPath
}) {
  showPanel('dynamic');
  const presetTargetMode = normalizeDynamicPayloadTargetMode(payloadTarget || getDynamicPayloadTargetMode());
  if (dynamicPayloadTargetMode) dynamicPayloadTargetMode.value = presetTargetMode;
  requestRunTraceInit({
    startSymbol,
    targetSymbol,
    payloadExpr,
    payloadTargetMode: presetTargetMode,
    maxSteps,
    suggestedOffset,
    suggestedCaptureSize,
    binaryPath
  }, binaryPath);
  runBtn?.focus();
}

function parseFlexibleInt(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;
  if (/^[+-]?\d+$/.test(raw)) return parseInt(raw, 10);
  if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
    const sign = raw.startsWith('-') ? -1 : 1;
    const normalized = raw.replace(/^[+-]/, '');
    return sign * parseInt(normalized, 16);
  }
  return null;
}

function parseFlexibleBigInt(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;
  try {
    if (/^[+-]?\d+$/.test(raw)) return BigInt(raw);
    if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
      const sign = raw.startsWith('-') ? -1n : 1n;
      const normalized = raw.replace(/^[+-]/, '').toLowerCase();
      return sign * BigInt(normalized);
    }
  } catch (_) {
    return null;
  }
  return null;
}

function normalizeNoteKey(rawKey) {
  return String(rawKey || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '');
}

function parseExploitNotes(rawText) {
  const lines = String(rawText || '').split(/\r?\n|;/g);
  const parsed = {};
  const keyMap = {
    cmp: 'cmpAddr',
    cmp_addr: 'cmpAddr',
    cmpaddr: 'cmpAddr',
    cmp_address: 'cmpAddr',
    padding: 'padding',
    pad: 'padding',
    overflow: 'padding',
    buffer_size: 'bufferSize',
    buffersize: 'bufferSize',
    suffix: 'suffix',
    payload_suffix: 'suffix',
    payload: 'payloadExpr',
    payload_expr: 'payloadExpr',
    payloadexpr: 'payloadExpr',
    buffer_offset: 'bufferOffset',
    bufoffset: 'bufferOffset',
    capture_size: 'captureSize',
    capturesize: 'captureSize',
    start: 'startSymbol',
    start_symbol: 'startSymbol',
    target: 'targetSymbol',
    target_symbol: 'targetSymbol',
    stop: 'targetSymbol',
    stop_symbol: 'targetSymbol',
    max_steps: 'maxSteps',
    maxstep: 'maxSteps',
    steps: 'maxSteps',
    payload_target: 'payloadTarget',
    cmp_value: 'cmpValue',
    cmp_immediate: 'cmpValue',
    immediate: 'cmpValue',
    cmp_width: 'cmpWidth',
    width: 'cmpWidth'
  };

  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const sepIdx = line.search(/[:=]/);
    if (sepIdx <= 0) continue;
    const key = normalizeNoteKey(line.slice(0, sepIdx));
    const value = line.slice(sepIdx + 1).trim();
    if (!value) continue;
    const canonical = keyMap[key];
    if (!canonical) continue;
    parsed[canonical] = value;
  }

  if (parsed.cmpAddr && /^(?:0x)?[0-9a-f]+$/i.test(parsed.cmpAddr)) {
    parsed.cmpAddr = parsed.cmpAddr.startsWith('0x') ? parsed.cmpAddr : `0x${parsed.cmpAddr}`;
  }
  parsed.padding = parseFlexibleInt(parsed.padding);
  parsed.bufferSize = parseFlexibleInt(parsed.bufferSize);
  parsed.bufferOffset = parseFlexibleInt(parsed.bufferOffset);
  parsed.captureSize = parseFlexibleInt(parsed.captureSize);
  parsed.maxSteps = parseFlexibleInt(parsed.maxSteps);
  parsed.cmpWidth = parseFlexibleInt(parsed.cmpWidth);
  parsed.cmpValue = parseFlexibleBigInt(parsed.cmpValue);
  return parsed;
}

function deriveSuffixFromCmpValue(cmpValue, cmpWidthHint) {
  if (cmpValue === null || cmpValue === undefined) return null;
  let width = cmpWidthHint;
  if (![1, 2, 4, 8].includes(width)) {
    if (cmpValue < 0n) width = 4;
    else if (cmpValue <= 0xffn) width = 1;
    else if (cmpValue <= 0xffffn) width = 2;
    else if (cmpValue <= 0xffffffffn) width = 4;
    else width = 8;
  }
  let masked = BigInt.asUintN(width * 8, cmpValue);
  const bytes = [];
  for (let i = 0; i < width; i += 1) {
    bytes.push(Number(masked & 0xffn));
    masked >>= 8n;
  }
  const printable = bytes.every((b) => b >= 0x20 && b <= 0x7e && b !== 0x2b && b !== 0x2a);
  return printable ? String.fromCharCode(...bytes) : 'B'.repeat(Math.max(4, width));
}

document.getElementById('btnPrepareDynamic')?.addEventListener('click', () => {
  const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
  const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
  const payloadSuffix = document.getElementById('exploitPayloadSuffix')?.value?.trim() || 'CCCC';
  const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
  const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
  const bufferSizeRaw = document.getElementById('exploitBufferSize')?.value?.trim() || '64';
  const bufferSize = parseInt(bufferSizeRaw, 10);
  if (!Number.isFinite(bufferSize) || bufferSize <= 0) {
    vscode.postMessage({ type: 'hubError', message: 'Taille buffer invalide.' });
    return;
  }

  const is32Bit = Number(dynamicTraceInitState.archBits) === 32;
  const suggestedOffset = is32Bit
    ? -Math.max(bufferSize + 16, 64)
    : -Math.max(bufferSize + 32, 96);
  const suggestedCaptureSize = is32Bit
    ? Math.max(bufferSize + 48, 96)
    : Math.max(bufferSize + 64, 128);
  const payloadExpr = `A*${bufferSize}+${payloadSuffix}`;
  applyDynamicPreset({
    startSymbol,
    targetSymbol,
    payloadExpr,
    payloadTarget,
    maxSteps,
    suggestedOffset,
    suggestedCaptureSize,
    binaryPath: getStaticBinaryPath()
  });
});

document.getElementById('btnAutoFromCmp')?.addEventListener('click', () => {
  const cmpAddr = document.getElementById('exploitCmpAddr')?.value?.trim();
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  if (!cmpAddr) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez une adresse CMP.' });
    return;
  }
  const hint = document.getElementById('exploitAutoHint');
  if (hint) hint.textContent = 'Analyse du CMP en cours…';
  vscode.postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr });
});

function runAutoFromNotes() {
  const notesText = document.getElementById('exploitNotes')?.value || '';
  const hint = document.getElementById('exploitAutoHint');
  if (!notesText.trim()) {
    vscode.postMessage({ type: 'hubError', message: 'Ajoutez des notes (format key=value).' });
    return false;
  }

  const notes = parseExploitNotes(notesText);
  const bp = getStaticBinaryPath();

  if (notes.cmpAddr) {
    const cmpInput = document.getElementById('exploitCmpAddr');
    if (cmpInput) cmpInput.value = notes.cmpAddr;
  }
  if (notes.startSymbol) {
    const el = document.getElementById('exploitStartSymbol');
    if (el) el.value = notes.startSymbol;
  }
  if (notes.targetSymbol) {
    const el = document.getElementById('exploitTargetSymbol');
    if (el) el.value = notes.targetSymbol;
  }
  if (Number.isFinite(notes.maxSteps) && notes.maxSteps > 0) {
    const el = document.getElementById('exploitMaxSteps');
    if (el) el.value = String(notes.maxSteps);
  }
  if (Number.isFinite(notes.bufferSize) && notes.bufferSize > 0) {
    const el = document.getElementById('exploitBufferSize');
    if (el) el.value = String(notes.bufferSize);
  }
  if (notes.payloadTarget) {
    const targetSel = document.getElementById('exploitPayloadTarget');
    if (targetSel && Array.from(targetSel.options).some((o) => o.value === notes.payloadTarget)) {
      targetSel.value = notes.payloadTarget;
    }
  }

  let payloadExpr = String(notes.payloadExpr || '').trim();
  if (!payloadExpr && Number.isFinite(notes.padding) && notes.padding > 0) {
    let suffix = String(notes.suffix || '').trim();
    if (!suffix) suffix = deriveSuffixFromCmpValue(notes.cmpValue, notes.cmpWidth) || '';
    if (!suffix) suffix = 'CCCC';
    payloadExpr = `A*${notes.padding}+${suffix}`;
    const suffixInput = document.getElementById('exploitPayloadSuffix');
    if (suffixInput) suffixInput.value = suffix;
    const sizeInput = document.getElementById('exploitBufferSize');
    if (sizeInput) sizeInput.value = String(notes.padding);
  }

  if (payloadExpr) {
    const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
    const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
    const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
    const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
    const is32Bit = Number(dynamicTraceInitState.archBits) === 32;
    const padding = Number.isFinite(notes.padding) && notes.padding > 0
      ? notes.padding
      : parseFlexibleInt(document.getElementById('exploitBufferSize')?.value || '64') || 64;
    const suggestedOffset = Number.isFinite(notes.bufferOffset)
      ? notes.bufferOffset
      : (is32Bit ? -Math.max(padding + 16, 64) : -Math.max(padding + 32, 96));
    const suggestedCaptureSize = Number.isFinite(notes.captureSize)
      ? notes.captureSize
      : (is32Bit ? Math.max(padding + 48, 96) : Math.max(padding + 64, 128));

    applyDynamicPreset({
      startSymbol,
      targetSymbol,
      payloadExpr,
      payloadTarget,
      maxSteps,
      suggestedOffset,
      suggestedCaptureSize,
      binaryPath: bp
    });
    if (hint) hint.textContent = `Auto Notes OK: ${payloadExpr} (offset=${suggestedOffset}, capture=${suggestedCaptureSize})`;
    return true;
  }

  if (notes.cmpAddr) {
    if (!bp) {
      vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire pour utiliser cmp=...' });
      return false;
    }
    if (hint) hint.textContent = 'Analyse du CMP (depuis notes) en cours…';
    vscode.postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr: notes.cmpAddr });
    return true;
  }

  vscode.postMessage({
    type: 'hubError',
    message: 'Notes insuffisantes: utilisez payload=..., ou padding=... (+ suffix=.../cmp_value=...), ou cmp=...'
  });
  return false;
}

document.getElementById('btnAutoFromNotes')?.addEventListener('click', runAutoFromNotes);
document.getElementById('btnAutoFromNotesWidget')?.addEventListener('click', runAutoFromNotes);

// Payload result: copier au clic
document.getElementById('payloadHexResult')?.addEventListener('click', function () {
  const v = this.textContent;
  if (v && v !== '—' && !v.startsWith('Error') && navigator.clipboard) {
    navigator.clipboard.writeText(v);
    this.classList.add('copied');
    setTimeout(() => this.classList.remove('copied'), 600);
  }
});

document.getElementById('btnGoToAddr')?.addEventListener('click', () => {
  const val = document.getElementById('goToAddrInput')?.value?.trim();
  if (!val) return;
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  const looksLikeAddr = /^(0x)?[0-9a-fA-F]+$/.test(val);
  if (looksLikeAddr) {
    const norm = val.startsWith('0x') ? val : '0x' + val;
    window._lastDisasmAddr = norm;
    updateActiveContextBars(norm);
    if (typeof navPush === 'function') navPush(norm);
    vscode.postMessage({ type: 'hubGoToAddress', addr: norm, binaryPath: bp });
  } else {
    vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: val });
  }
});

document.getElementById('btnAddAnnotation')?.addEventListener('click', () => {
  const badge = document.getElementById('annotationAddrBadge');
  const addr = badge?.dataset.addr || '';
  const comment = document.getElementById('annotationComment')?.value?.trim();
  const name = (document.getElementById('annotationName')?.value || '').trim();
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Cliquez d\'abord une ligne dans le désassemblage.' });
    return;
  }
  vscode.postMessage({ type: 'hubSaveAnnotation', binaryPath: bp, addr, comment, name });
});

document.getElementById('btnXrefs')?.addEventListener('click', () => {
  const inputAddr = document.getElementById('goToAddrInput')?.value?.trim();
  const selectedAddr = document.getElementById('annotationAddrBadge')?.dataset.addr || '';
  const addr = inputAddr || selectedAddr || window._lastDisasmAddr || '';
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez une adresse ou cliquez une ligne du désassemblage.' });
    return;
  }
  const el = document.getElementById('xrefsResult');
  const contentEl = document.getElementById('xrefsResultContent');
  if (el) {
    el.style.display = 'block';
    (contentEl || el).innerHTML = '<p class="xrefs-msg loading">Analyse des références croisées…</p>';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  const bp = getStaticBinaryPath();
  const norm = addr.startsWith('0x') ? addr : '0x' + addr;
  const input = document.getElementById('goToAddrInput');
  if (input) input.value = norm;
  const mode = document.getElementById('xrefsMode')?.value || 'to';
  vscode.postMessage({ type: 'hubLoadXrefs', addr: norm, binaryPath: bp || '', mode });
});

document.getElementById('btnExportDisasm')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubExportDisasm', binaryPath: getStaticBinaryPath() });
});

function doExportData(dataType, format) {
  let data, suggestedName;
  if (dataType === 'symbols') {
    data = window.symbolsCache || [];
    suggestedName = `symbols_export.${format}`;
  } else if (dataType === 'strings') {
    data = stringsCache || [];
    suggestedName = `strings_export.${format}`;
  } else if (dataType === 'xrefs') {
    data = window.xrefsCache || { refs: [], targets: [], addr: '', mode: '' };
    suggestedName = `xrefs_${(data.addr || 'export').replace(/^0x/, '')}.${format}`;
  } else return;
  if ((Array.isArray(data) && data.length === 0) || (!Array.isArray(data) && !data.refs?.length && !data.targets?.length)) {
    vscode.postMessage({ type: 'hubError', message: 'Aucune donnée à exporter.' });
    return;
  }
  vscode.postMessage({ type: 'hubExportData', dataType, format, data, suggestedName });
}
document.getElementById('btnExportSymbolsJson')?.addEventListener('click', () => doExportData('symbols', 'json'));
document.getElementById('btnExportSymbolsCsv')?.addEventListener('click', () => doExportData('symbols', 'csv'));
document.getElementById('btnExportStringsJson')?.addEventListener('click', () => doExportData('strings', 'json'));
document.getElementById('btnExportStringsCsv')?.addEventListener('click', () => doExportData('strings', 'csv'));
document.getElementById('btnExportXrefsJson')?.addEventListener('click', () => doExportData('xrefs', 'json'));
document.getElementById('btnExportXrefsCsv')?.addEventListener('click', () => doExportData('xrefs', 'csv'));

document.getElementById('btnExportCfgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#cfgContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le graphe CFG.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCfgSvg', svg });
});

document.getElementById('btnExportCgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#callgraphContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le call graph.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCgSvg', svg });
});

document.getElementById('btnHexGo')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const raw = document.getElementById('hexOffsetInput')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10) || 0;
  const length = parseInt(document.getElementById('hexLengthSelect')?.value || '512', 10);
  tabDataCache.hex = null;
  loadHexView(bp, offset, length);
});
document.getElementById('btnHexPrev')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, Math.max(0, hexCurrentOffset - hexCurrentLength), hexCurrentLength);
});
document.getElementById('btnHexNext')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, hexCurrentOffset + hexCurrentLength, hexCurrentLength);
});
document.getElementById('btnHexToggleMeta')?.addEventListener('click', () => {
  hexUiState.compact = !hexUiState.compact;
  _saveStorage({ hexCompact: hexUiState.compact });
  applyHexLayoutMode();
});
document.getElementById('btnHexOpenSelection')?.addEventListener('click', () => {
  openHexSelectionInDisasm();
});
document.getElementById('btnHexResetSelection')?.addEventListener('click', () => {
  collapseHexSelectionToActive();
});
document.getElementById('btnHexPatch')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  const raw = document.getElementById('hexPatchOffset')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10);
  if (isNaN(offset)) {
    const status = document.getElementById('hexPatchStatus');
    if (status) { status.className = 'hex-patch-status error'; status.textContent = 'Offset invalide'; }
    return;
  }
  const bytesHex = document.getElementById('hexPatchBytes')?.value?.trim() || '';
  if (!bytesHex) return;
  vscode.postMessage({ type: 'hubPatchBytes', binaryPath: bp, offset, bytesHex });
});
document.getElementById('btnHexUndo')?.addEventListener('click', () => {
  if (!hexPatchHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const last = hexPatchHistory[hexPatchHistory.length - 1];
  if (!last?.id) return;
  vscode.postMessage({ type: 'hubRevertPatch', binaryPath: bp, patchId: last.id });
});
document.getElementById('btnHexRedo')?.addEventListener('click', () => {
  if (!hexPatchRedoHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const entry = hexPatchRedoHistory[hexPatchRedoHistory.length - 1];
  if (!entry?.id) return;
  vscode.postMessage({ type: 'hubRedoPatch', binaryPath: bp, patchId: entry.id });
});
document.getElementById('hexContent')?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    openHexSelectionInDisasm();
  } else if (event.key === 'Escape') {
    event.preventDefault();
    collapseHexSelectionToActive();
  }
});
document.getElementById('btnRevertAll')?.addEventListener('click', function() {
  const bp = getStaticBinaryPath();
  if (bp) vscode.postMessage({ type: 'hubRevertAllPatches', binaryPath: bp });
});
applyHexLayoutMode();
updateHexSelectionButtons();

document.getElementById('btnYaraBrowse')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'requestRulesSelection' });
});
document.getElementById('btnYaraScan')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  const rules = document.getElementById('yaraRulesPath')?.value?.trim();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un binaire.' });
    return;
  }
  if (!rules) {
    vscode.postMessage({ type: 'hubError', message: 'Cliquez sur Parcourir pour sélectionner des règles (.yar ou dossier).' });
    return;
  }
  setStaticLoading('yaraContent', 'Scan YARA…');
  detectionUiState.yaraError = '';
  updateDetectionSummaries();
  vscode.postMessage({ type: 'hubYaraScan', binaryPath: bp, rulesPath: rules });
});
document.getElementById('btnCapaScan')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un binaire.' });
    return;
  }
  const unsupportedCapa = getCapaUnsupportedReason();
  if (unsupportedCapa) {
    renderCapaUnsupported(unsupportedCapa);
    tabDataCache.detection = { binaryPath: bp };
    return;
  }
  setStaticLoading('capaContent', 'Analyse Capa…');
  detectionUiState.capaError = '';
  updateDetectionSummaries();
  vscode.postMessage({ type: 'hubCapaScan', binaryPath: bp });
});

document.getElementById('capaFilterInput')?.addEventListener('input', renderCapaResults);
document.getElementById('capaNamespaceFilter')?.addEventListener('change', renderCapaResults);
document.getElementById('yaraFilterInput')?.addEventListener('input', renderYaraResults);
document.getElementById('btnCapaExportJson')?.addEventListener('click', () => {
  downloadDetectionJson('capa-results.json', {
    binaryPath: getStaticBinaryPath(),
    capabilities: detectionUiState.capaCapabilities,
    error: detectionUiState.capaError || null,
  });
});
document.getElementById('btnYaraExportJson')?.addEventListener('click', () => {
  downloadDetectionJson('yara-results.json', {
    binaryPath: getStaticBinaryPath(),
    rulesPath: document.getElementById('yaraRulesPath')?.value?.trim() || '',
    matches: detectionUiState.yaraMatches,
    error: detectionUiState.yaraError || null,
  });
});

document.getElementById('btnOllamaRefreshModels')?.addEventListener('click', () => {
  requestOllamaModels();
});

document.getElementById('ollamaBaseUrl')?.addEventListener('change', (event) => {
  const value = String(event.target?.value || '').trim() || 'http://127.0.0.1:11434';
  _saveStorage({ ollamaBaseUrl: value });
  requestOllamaModels();
});

document.querySelectorAll('[data-ollama-model-select="true"]').forEach((selectEl) => {
  selectEl.addEventListener('change', (event) => {
    const value = String(event.target?.value || '').trim();
    if (!value) return;
    ollamaUiState.lastModel = value;
    _saveStorage({ ollamaModel: value });
    renderOllamaModels(ollamaUiState.models, value);
  });
});

document.getElementById('btnOllamaRunPrompt')?.addEventListener('click', () => {
  submitOllamaChatPrompt();
});

document.getElementById('btnOllamaNewChat')?.addEventListener('click', () => {
  clearOllamaConversation();
});

document.getElementById('btnOllamaClearHistory')?.addEventListener('click', () => {
  clearOllamaConversationHistory();
});

document.getElementById('btnOllamaQuickRefresh')?.addEventListener('click', () => {
  requestOllamaModels();
});

document.getElementById('btnOllamaQuickSend')?.addEventListener('click', () => {
  const input = document.getElementById('ollamaQuickPromptInput');
  submitOllamaChatPrompt({ prompt: input?.value || '', inputEl: input });
});

document.getElementById('btnOllamaQuickNewChat')?.addEventListener('click', () => {
  clearOllamaConversation();
});

document.getElementById('ollamaQuickPromptInput')?.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || event.shiftKey) return;
  event.preventDefault();
  const input = document.getElementById('ollamaQuickPromptInput');
  submitOllamaChatPrompt({ prompt: input?.value || '', inputEl: input });
});

document.getElementById('ollamaPromptInput')?.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || event.shiftKey) return;
  event.preventDefault();
  submitOllamaChatPrompt();
});

// Décompilateur : auto-décompile quand on change de fonction
const decompileQualitySelect = document.getElementById('decompileQualitySelect');
const decompileSourceSelect = document.getElementById('decompileSourceSelect');
if (decompileSourceSelect) {
  decompileSourceSelect.value = _getSelectedDecompilerChoice();
}
decompileSourceSelect?.addEventListener('change', () => {
  _setActiveDecompilerSource(_getActiveDecompilerSource());
  _onDecompilerSourceChange();
});
if (decompileQualitySelect) {
  decompileQualitySelect.value = _normalizeDecompileQuality(decompileUiState.quality || 'normal');
}
decompileQualitySelect?.addEventListener('change', (event) => {
  decompileUiState.quality = _normalizeDecompileQuality(String(event.target?.value || 'normal'));
  _saveStorage({ decompileQuality: decompileUiState.quality });
  requestDecompileForCurrentSelection({ skipHistory: false, preserveStackEntry: true });
});
document.getElementById('decompileAddrSelect')?.addEventListener('change', () => {
  decompileUiState.selectionMode = 'manual';
  _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  const { addr } = getDecompileSelectionContext();
  requestDecompileForCurrentSelection();
  const bp = getStaticBinaryPath();
  if (bp && addr) {
    const cached = getCachedStackFrame(bp, addr);
    if (cached) renderStackFrame(cached);
    else ensureStackFrameLoaded(bp, addr);
  } else {
    decompileUiState.selectedAddr = '';
    _saveStorage({ decompileAddr: '' });
  }
});
document.getElementById('btnDecompileBack')?.addEventListener('click', () => {
  applyDecompileHistoryStep(-1);
});
document.getElementById('btnDecompileForward')?.addEventListener('click', () => {
  applyDecompileHistoryStep(1);
});
document.getElementById('decompileSearchInput')?.addEventListener('input', (event) => {
  decompileUiState.searchQuery = String(event.target?.value || '');
  decompileUiState.activeSearchHit = decompileUiState.searchQuery.trim() ? 0 : -1;
  _saveStorage({ decompileSearch: decompileUiState.searchQuery });
  updateDecompileSearchUi();
  if (decompileSearchDebounce) window.clearTimeout(decompileSearchDebounce);
  decompileSearchDebounce = window.setTimeout(() => {
    decompileSearchDebounce = 0;
    if (!rerenderCurrentDecompileFromCache()) {
      requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
    }
  }, 60);
});
document.getElementById('decompileSearchInput')?.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    event.preventDefault();
    if (!decompileUiState.searchQuery) return;
    decompileUiState.searchQuery = '';
    decompileUiState.activeSearchHit = -1;
    _saveStorage({ decompileSearch: '' });
    updateDecompileSearchUi(0);
    if (!rerenderCurrentDecompileFromCache()) {
      requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
    }
    return;
  }
  if (event.key !== 'Enter') return;
  event.preventDefault();
  stepDecompileSearchHit(event.shiftKey ? -1 : 1);
});
document.getElementById('btnDecompileSearchPrev')?.addEventListener('click', () => {
  stepDecompileSearchHit(-1);
});
document.getElementById('btnDecompileSearchNext')?.addEventListener('click', () => {
  stepDecompileSearchHit(1);
});
updateDecompileHistoryControls();
updateDecompileSearchUi();

// Rules Manager — formulaire d'ajout
['btnAddYaraRule', 'btnAddCapaRule'].forEach(function(btnId) {
  var btn = document.getElementById(btnId);
  if (!btn) return;
  btn.addEventListener('click', function() {
    var ruleType = btn.dataset.ruletype;
    document.getElementById('rulesAddType').value = ruleType;
    document.getElementById('rulesAddFormTitle').textContent =
      'Ajouter une règle ' + ruleType.toUpperCase();
    document.getElementById('rulesAddName').value = '';
    document.getElementById('rulesAddContent').value = '';
    document.getElementById('rulesAddName').placeholder =
      ruleType === 'yara' ? 'ma_regle.yar' : 'ma_regle.yml';
    document.getElementById('rulesAddForm').style.display = '';
  });
});

var btnRulesAddCancel = document.getElementById('btnRulesAddCancel');
if (btnRulesAddCancel) {
  btnRulesAddCancel.addEventListener('click', function() {
    document.getElementById('rulesAddForm').style.display = 'none';
  });
}

var btnRulesAddSave = document.getElementById('btnRulesAddSave');
if (btnRulesAddSave) {
  btnRulesAddSave.addEventListener('click', function() {
    var name = (document.getElementById('rulesAddName').value || '').trim();
    var content = document.getElementById('rulesAddContent').value || '';
    var ruleType = document.getElementById('rulesAddType').value;
    if (!name) { alert('Veuillez saisir un nom de fichier.'); return; }
    vscode.postMessage({ type: 'hubAddUserRule', name: name, ruleType: ruleType, content: content });
    document.getElementById('rulesAddForm').style.display = 'none';
  });
}

// Strings search (Outils) — utilise le binaire du projet
// Files
// Outils: sync binary label, select binary
function syncToolsBinaryLabel() {
  const bp = getStaticBinaryPath();
  const el = document.getElementById('toolsBinaryLabel');
  if (el) {
    el.textContent = bp ? `Binaire : ${bp}` : 'Binaire : sélectionnez-en un (Static ou ici)';
    el.classList.toggle('empty', !bp);
  }
}
document.getElementById('btnToolsSelectBinary')?.addEventListener('click', () => {
  pendingStaticQuickAction = '';
  vscode.postMessage({ type: 'requestBinarySelection' });
});

document.getElementById('btnRefreshFiles')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'listGeneratedFiles' });
});

document.getElementById('btnPurgeStale')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'purgeStaleCache' });
});

document.getElementById('btnCleanup')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'cleanupGeneratedFiles', confirm: true });
});

function highlightC(code) {
  // Etape 1 : echapper HTML (XSS prevention — obligatoire avant tout)
  let h = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  // Placeholder system : chaque match est remplace par un token opaque
  // que les passes suivantes ne peuvent pas matcher
  const tokens = [];
  function protect(spanHtml) {
    const id = `\x00T${tokens.length}\x00`;
    tokens.push(spanHtml);
    return id;
  }
  function wrap(regex, cls) {
    h = h.replace(regex, match => protect(`<span class="${cls}">${match}</span>`));
  }

  // Etape 2 : commentaires (en premier — priorite maximale)
  wrap(/(\/\/[^\n]*)/g, 'hl-comment');
  wrap(/(\/\*[\s\S]*?\*\/)/g, 'hl-comment');

  // Etape 3 : chaines litterales (guillemets echappes en &quot;)
  wrap(/(&quot;[^&\n]*&quot;)/g, 'hl-string');

  // Etape 4 : mots-cles C
  const kw = 'if|else|for|while|do|return|break|continue|switch|case|default|goto|sizeof|typedef|struct|union|enum|void|static|extern|const|volatile|register|inline|auto';
  wrap(new RegExp(`\\b(${kw})\\b`, 'g'), 'hl-keyword');

  // Etape 5 : types C courants
  const types = 'int|char|long|short|unsigned|signed|float|double|size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|bool|FILE|NULL';
  wrap(new RegExp(`\\b(${types})\\b`, 'g'), 'hl-type');

  // Etape 6 : nombres (hex et decimal)
  wrap(/\b(0x[0-9a-fA-F]+|\d+)\b/g, 'hl-number');

  // Restauration : remplacer les tokens par leur HTML final
  h = h.replace(/\x00T(\d+)\x00/g, (_, i) => tokens[Number(i)]);

  return h;
}

function cancelPendingDecompileHighlight() {
  decompileRenderToken += 1;
  if (decompileHighlightFrame) {
    cancelAnimationFrame(decompileHighlightFrame);
    decompileHighlightFrame = 0;
  }
}

function buildDecompileHighlightCacheKey(binaryPath, decompiler, addr) {
  return `${binaryPath || ''}\u0001${decompiler || ''}\u0001${addr || ''}`;
}

function scheduleDecompileHighlight(pre, code, opts = {}) {
  const cacheKey = buildDecompileHighlightCacheKey(opts.binaryPath, opts.decompiler, opts.addr);
  const token = ++decompileRenderToken;
  const applyHighlightedHtml = (html) => {
    if (token !== decompileRenderToken || !pre.isConnected) return;
    pre.innerHTML = html;
    decorateDecompileOutput(pre, opts);
  };
  pre.textContent = code;
  if (
    decompileHighlightCache.key === cacheKey &&
    decompileHighlightCache.code === code &&
    decompileHighlightCache.html
  ) {
    decompileHighlightFrame = requestAnimationFrame(() => {
      decompileHighlightFrame = 0;
      applyHighlightedHtml(decompileHighlightCache.html);
    });
    return;
  }
  decompileHighlightFrame = requestAnimationFrame(() => {
    decompileHighlightFrame = requestAnimationFrame(() => {
      decompileHighlightFrame = 0;
      if (token !== decompileRenderToken || !pre.isConnected) return;
      const html = highlightC(code);
      decompileHighlightCache = { key: cacheKey, code, html };
      applyHighlightedHtml(html);
    });
  });
}

function decorateDecompileSearch(pre, query) {
  const needle = String(query || '').trim();
  if (!pre || !needle) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return 0;
  }
  const lowerNeedle = needle.toLowerCase();
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.decompile-search-hit')) return NodeFilter.FILTER_REJECT;
        return node.nodeValue.toLowerCase().includes(lowerNeedle)
          ? NodeFilter.FILTER_ACCEPT
          : NodeFilter.FILTER_REJECT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  let count = 0;
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    const lowerText = text.toLowerCase();
    let cursor = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    while (cursor < text.length) {
      const idx = lowerText.indexOf(lowerNeedle, cursor);
      if (idx === -1) break;
      if (idx > cursor) {
        fragment.appendChild(document.createTextNode(text.slice(cursor, idx)));
      }
      const mark = document.createElement('span');
      mark.className = 'decompile-search-hit';
      mark.textContent = text.slice(idx, idx + needle.length);
      fragment.appendChild(mark);
      cursor = idx + needle.length;
      replaced = true;
      count += 1;
    }
    if (!replaced) return;
    if (cursor < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(cursor)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
  if (count <= 0) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return 0;
  }
  applyActiveDecompileSearchHit(decompileUiState.activeSearchHit >= 0 ? decompileUiState.activeSearchHit : 0, { reveal: false });
  updateDecompileSearchUi(count);
  return count;
}

function getDecompileSearchHits() {
  return Array.from(document.querySelectorAll('#decompileContent .decompile-search-hit'));
}

function applyActiveDecompileSearchHit(index, opts = {}) {
  const hits = getDecompileSearchHits();
  hits.forEach((hit) => hit.classList.remove('is-active'));
  if (!hits.length) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return false;
  }
  let nextIndex = Number(index);
  if (!Number.isFinite(nextIndex)) nextIndex = 0;
  if (nextIndex < 0) nextIndex = hits.length - 1;
  nextIndex = nextIndex % hits.length;
  const target = hits[nextIndex];
  if (!target) return false;
  target.classList.add('is-active');
  decompileUiState.activeSearchHit = nextIndex;
  updateDecompileSearchUi(hits.length);
  if (opts.reveal !== false) {
    target.scrollIntoView({ block: 'center' });
  }
  return true;
}

function stepDecompileSearchHit(delta) {
  const hits = getDecompileSearchHits();
  if (!hits.length) {
    updateDecompileSearchUi(0);
    return false;
  }
  const base = Number.isFinite(decompileUiState.activeSearchHit) ? decompileUiState.activeSearchHit : 0;
  return applyActiveDecompileSearchHit(base + delta);
}

function ensureDecompilePeekEl() {
  if (decompilePeekState.el?.isConnected) return decompilePeekState.el;
  const el = document.createElement('div');
  el.className = 'decompile-peek-tooltip';
  document.body.appendChild(el);
  decompilePeekState.el = el;
  return el;
}

function hideDecompilePeek() {
  if (decompilePeekState.el) decompilePeekState.el.style.display = 'none';
  decompilePeekState.target = null;
}

function positionDecompilePeek(clientX, clientY) {
  const el = ensureDecompilePeekEl();
  const pad = 14;
  const x = Math.min(clientX + 16, Math.max(8, window.innerWidth - el.offsetWidth - pad));
  const y = Math.min(clientY + 18, Math.max(8, window.innerHeight - el.offsetHeight - pad));
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
}

function renderDecompilePeek(target) {
  if (!target) return;
  const el = ensureDecompilePeekEl();
  const isStack = target.classList.contains('decompile-stack-link') || target.classList.contains('decompile-link-chip-stack');
  const isAddr = target.classList.contains('decompile-addr-link') || target.classList.contains('decompile-link-chip-addr');
  const isFn = target.classList.contains('decompile-fn-link') || (target.classList.contains('decompile-link-chip') && !isStack && !isAddr);
  let title = '';
  let subtitle = '';
  let hint = '';
  const rows = [];
  if (isStack) {
    title = target.dataset.stackName || target.textContent || 'Entrée stack';
    subtitle = target.dataset.stackKind === 'arg' ? 'Argument' : 'Variable locale';
    if (target.dataset.stackLocation) rows.push(['Emplacement', target.dataset.stackLocation]);
    if (target.dataset.stackType) rows.push(['Type', target.dataset.stackType]);
    hint = 'Clic: ouvrir Stack Frame';
  } else if (isAddr) {
    title = target.dataset.addr || target.textContent || 'Adresse';
    subtitle = 'Adresse repérée dans le pseudo-C';
    rows.push(['Adresse', target.dataset.addr || target.textContent || '—']);
    hint = 'Clic: désasm • Shift: Hex • Alt: CFG • Cmd/Ctrl: Call Graph';
  } else if (isFn) {
    title = target.dataset.name || target.textContent || 'Fonction';
    subtitle = 'Appel repéré';
    if (target.dataset.addr) rows.push(['Adresse', target.dataset.addr]);
    if (target.dataset.source) rows.push(['Source', target.dataset.source]);
    hint = 'Clic: pseudo-C • Shift: désasm • Alt: CFG • Cmd/Ctrl: Call Graph';
  } else {
    return;
  }
  const rowsHtml = rows.map(([label, value]) => (
    `<div class="decompile-peek-row"><span class="decompile-peek-key">${escapeHtml(label)}</span><span class="decompile-peek-val">${escapeHtml(value || '—')}</span></div>`
  )).join('');
  el.innerHTML = `
    <div class="decompile-peek-title">${escapeHtml(title)}</div>
    ${subtitle ? `<div class="decompile-peek-sub">${escapeHtml(subtitle)}</div>` : ''}
    ${rowsHtml ? `<div class="decompile-peek-grid">${rowsHtml}</div>` : ''}
    ${hint ? `<div class="decompile-peek-hint">${escapeHtml(hint)}</div>` : ''}
  `.trim();
  el.style.display = 'block';
}

function bindDecompilePeek(root) {
  if (!root || root.dataset.peekBound === '1') return;
  root.dataset.peekBound = '1';
  root.addEventListener('mousemove', (event) => {
    const target = event.target.closest('.decompile-fn-link, .decompile-addr-link, .decompile-stack-link, .decompile-link-chip');
    if (!target || !root.contains(target)) {
      hideDecompilePeek();
      return;
    }
    if (decompilePeekState.target !== target) {
      decompilePeekState.target = target;
      renderDecompilePeek(target);
    }
    positionDecompilePeek(event.clientX, event.clientY);
  });
  root.addEventListener('mouseleave', hideDecompilePeek);
  root.addEventListener('click', hideDecompilePeek);
}

function getNavigableDecompileAddr(text) {
  const raw = String(text || '').trim();
  if (!/^0x[0-9a-f]+$/i.test(raw)) return null;
  const normalized = normalizeHexAddress(raw);
  if (!normalized) return null;
  const addrNum = parseInt(normalized, 16);
  if (!Number.isFinite(addrNum) || addrNum < 0x1000) return null;
  if (isRawBinarySelected()) return normalized;
  if (Number.isFinite(fileOffsetFromVaddr(normalized))) return normalized;
  if ((window.symbolsCache || []).some((s) => normalizeHexAddress(s.addr) === normalized)) return normalized;
  return null;
}

function handleDecompileAddressJump(addr, event, binaryPath) {
  const normalized = normalizeHexAddress(addr);
  const bp = binaryPath || getStaticBinaryPath();
  if (!normalized || !bp) return;
  window._lastDisasmAddr = normalized;
  updateActiveContextBars(normalized);
  syncDecompileSelection(normalized, { forceContext: true });
  if (event?.metaKey || event?.ctrlKey) {
    jumpToAddrInContextTab('callgraph', normalized, bp);
    return;
  }
  if (event?.altKey) {
    jumpToAddrInContextTab('cfg', normalized, bp);
    return;
  }
  if (event?.shiftKey) {
    jumpToAddrInContextTab('hex', normalized, bp);
    return;
  }
  if (typeof navPush === 'function') navPush(normalized);
  vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp });
}

function getKnownFunctionMap() {
  const map = new Map();
  (window.symbolsCache || []).forEach((sym) => {
    const addr = normalizeHexAddress(sym.addr);
    const type = String(sym.type || '').toUpperCase();
    if (!addr || !sym.name) return;
    if (!['F', 'T', 'U', 'W'].includes(type)) return;
    if (!map.has(sym.name)) map.set(sym.name, { name: sym.name, addr, source: 'symbols' });
  });
  (window.functionListCache || []).forEach((fn) => {
    const addr = normalizeHexAddress(fn.addr);
    if (!addr || !fn.name) return;
    if (!map.has(fn.name)) map.set(fn.name, { name: fn.name, addr, source: 'functions' });
  });
  (window.discoveredFunctionsCache || []).forEach((fn) => {
    const addr = normalizeHexAddress(fn.addr);
    if (!addr || !fn.name) return;
    if (!map.has(fn.name)) map.set(fn.name, { name: fn.name, addr, source: 'discovered' });
  });
  return map;
}

function extractDecompileCallTargets(code, currentAddr) {
  const functionMap = getKnownFunctionMap();
  if (!functionMap.size) return [];
  const reserved = new Set([
    'if', 'else', 'for', 'while', 'switch', 'case', 'return', 'sizeof', 'typedef',
    'struct', 'union', 'enum', 'do', 'break', 'continue', 'goto',
  ]);
  const targets = [];
  const seen = new Set();
  const regex = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let match;
  while ((match = regex.exec(code))) {
    const name = match[1];
    if (reserved.has(name)) continue;
    const entry = functionMap.get(name);
    if (!entry?.addr) continue;
    if (normalizeHexAddress(currentAddr) === entry.addr) continue;
    if (seen.has(entry.name)) continue;
    seen.add(entry.name);
    targets.push(entry);
    if (targets.length >= 10) break;
  }
  return targets;
}

function extractDecompileAddressTargets(code, currentAddr) {
  const current = normalizeHexAddress(currentAddr);
  const targets = [];
  const seen = new Set();
  const regex = /\b0x[0-9a-fA-F]+\b/g;
  let match;
  while ((match = regex.exec(code))) {
    const addr = getNavigableDecompileAddr(match[0]);
    if (!addr) continue;
    if (current && addr === current) continue;
    if (seen.has(addr)) continue;
    seen.add(addr);
    targets.push(addr);
    if (targets.length >= 12) break;
  }
  return targets.sort((a, b) => (parseInt(a, 16) || 0) - (parseInt(b, 16) || 0));
}

function summarizeDecompileStructure(code) {
  const source = String(code || '');
  const lines = source.split(/\r?\n/);
  const nonEmptyLines = lines.filter((line) => line.trim()).length;
  const ifCount = (source.match(/\bif\s*\(/g) || []).length;
  const switchCount = (source.match(/\bswitch\s*\(/g) || []).length;
  const loopCount = (source.match(/\bfor\s*\(|\bwhile\s*\(|\bdo\b/g) || []).length;
  const returnCount = (source.match(/^\s*return\b/gm) || []).length;
  const gotoCount = (source.match(/\bgoto\b/g) || []).length;
  const caseCount = (source.match(/^\s*(case\b|default\s*:)/gm) || []).length;
  const labelCount = lines.reduce((count, line) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*(case\b|default\s*:)/.test(trimmed)) return count;
    return /^[A-Za-z_][A-Za-z0-9_]*\s*:/.test(trimmed) ? count + 1 : count;
  }, 0);
  const chips = [
    { label: `${nonEmptyLines} lignes`, tone: 'neutral', title: 'Nombre de lignes non vides du pseudo-C courant' },
    ifCount ? { label: `${ifCount} if`, tone: 'flow', title: 'Branches conditionnelles reperees' } : null,
    switchCount ? { label: `${switchCount} switch`, tone: 'flow', title: 'Structures switch reperees' } : null,
    caseCount ? { label: `${caseCount} cas`, tone: 'flow', title: 'Labels case/default repérés' } : null,
    loopCount ? { label: `${loopCount} boucle${loopCount > 1 ? 's' : ''}`, tone: 'flow', title: 'Boucles for / while / do repérées' } : null,
    returnCount ? { label: `${returnCount} retour${returnCount > 1 ? 's' : ''}`, tone: 'data', title: 'Instructions return repérées' } : null,
    gotoCount ? { label: `${gotoCount} goto`, tone: 'warn', title: 'Sauts goto repérés' } : null,
    labelCount ? { label: `${labelCount} label${labelCount > 1 ? 's' : ''}`, tone: 'neutral', title: 'Labels locaux repérés' } : null,
  ].filter(Boolean);
  return chips;
}

function escapeRegexText(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractDecompileStackEntries(stackFrame) {
  if (!stackFrame || stackFrame.error) return [];
  const entries = [];
  const seen = new Set();
  const appendEntries = (items, kind) => {
    (Array.isArray(items) ? items : []).forEach((entry) => {
      const name = normalizeStackEntryName(entry?.name);
      if (!name || seen.has(name)) return;
      seen.add(name);
      entries.push({
        name,
        kind,
        location: formatStackFrameEntryLocation(entry),
        type: entry?.type || '',
      });
    });
  };
  appendEntries(stackFrame.args, 'arg');
  appendEntries(stackFrame.vars, 'var');
  return entries.slice(0, 10);
}

function openDecompileFunction(addr, name, event) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return;
  if (event?.metaKey || event?.ctrlKey) {
    jumpToAddrInContextTab('callgraph', normalized, getStaticBinaryPath());
    return;
  }
  if (event?.altKey) {
    jumpToAddrInContextTab('cfg', normalized, getStaticBinaryPath());
    return;
  }
  if (event?.shiftKey) {
    handleDecompileAddressJump(normalized, event, getStaticBinaryPath());
    return;
  }
  const sel = document.getElementById('decompileAddrSelect');
  if (sel) {
    let option = Array.from(sel.options).find((opt) => opt.value === normalized);
    if (!option) {
      option = document.createElement('option');
      option.value = normalized;
      option.dataset.name = name || normalized;
      option.textContent = `${normalized}  ${name || ''}`.trim();
      sel.appendChild(option);
    }
    sel.value = normalized;
  }
  decompileUiState.selectionMode = 'manual';
  _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  decompileUiState.selectedAddr = normalized;
  showGroup('code', 'decompile');
  requestDecompileForCurrentSelection();
}

function decorateDecompileFunctionCalls(pre, opts = {}) {
  if (!pre) return;
  const functionMap = getKnownFunctionMap();
  if (!functionMap.size) return;
  const currentName = String(opts.currentName || '').trim();
  const currentAddr = normalizeHexAddress(opts.addr);
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.hl-comment, .hl-string, .decompile-fn-link')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    const regex = /\b([A-Za-z_][A-Za-z0-9_]*)\b(?=\s*\()/g;
    let lastIndex = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    let match;
    while ((match = regex.exec(text))) {
      const name = match[1];
      const entry = functionMap.get(name);
      if (!entry?.addr) continue;
      if ((currentName && name === currentName) || (currentAddr && entry.addr === currentAddr)) continue;
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }
      const span = document.createElement('span');
      span.className = 'decompile-fn-link';
      span.dataset.addr = entry.addr;
      span.dataset.name = name;
      span.dataset.source = entry.source || '';
      span.textContent = name;
      span.title = `${entry.addr} — clic: ouvrir en pseudo-C • Shift+clic: désassemblage • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      fragment.appendChild(span);
      lastIndex = match.index + name.length;
      replaced = true;
    }
    if (!replaced) return;
    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
}

function decorateDecompileStackEntries(pre, opts = {}) {
  if (!pre) return;
  const entries = Array.isArray(opts.stackEntries) ? opts.stackEntries : [];
  if (!entries.length) return;
  const stackMap = new Map();
  entries.forEach((entry) => {
    const name = normalizeStackEntryName(entry?.name);
    if (!name || stackMap.has(name)) return;
    stackMap.set(name, entry);
  });
  const names = Array.from(stackMap.keys()).sort((a, b) => b.length - a.length);
  if (!names.length) return;
  const pattern = new RegExp(`\\b(${names.map((name) => escapeRegexText(name)).join('|')})\\b`, 'g');
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.hl-comment, .hl-string, .decompile-fn-link, .decompile-addr-link, .decompile-stack-link')) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    let lastIndex = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    let match;
    while ((match = pattern.exec(text))) {
      const name = match[1];
      const prevChar = match.index > 0 ? text[match.index - 1] : '';
      const nextChar = text[match.index + name.length] || '';
      if (prevChar === '.' || nextChar === '(') continue;
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }
      const entry = stackMap.get(name);
      const span = document.createElement('span');
      span.className = 'decompile-stack-link';
      span.dataset.stackName = name;
      span.dataset.stackKind = entry?.kind || '';
      span.dataset.stackLocation = entry?.location || '';
      span.dataset.stackType = entry?.type || '';
      span.textContent = name;
      span.title = `${entry?.kind === 'arg' ? 'Argument' : 'Variable locale'}${entry?.location ? ` — ${entry.location}` : ''} • clic: ouvrir Stack Frame`;
      fragment.appendChild(span);
      lastIndex = match.index + name.length;
      replaced = true;
    }
    if (!replaced) return;
    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
}

function decorateDecompileOutput(pre, opts = {}) {
  if (!pre) return;
  pre.querySelectorAll('.hl-number').forEach((el) => {
    const addr = getNavigableDecompileAddr(el.textContent);
    if (!addr) return;
    el.classList.add('decompile-addr-link');
    el.dataset.addr = addr;
    el.title = 'Clic: aller au désassemblage • Shift+clic: ouvrir dans Hex • Alt+clic: centrer dans le CFG • Cmd/Ctrl+clic: Call Graph';
  });
  decorateDecompileFunctionCalls(pre, opts);
  decorateDecompileStackEntries(pre, opts);
  decorateDecompileSearch(pre, opts.searchQuery || decompileUiState.searchQuery);
  applyDecompileStackHighlight(opts.activeStackName || decompileUiState.pendingStackEntryName || decompileUiState.activeStackEntryName, { reveal: false });
  if (pre.dataset.navBound === '1') return;
  pre.dataset.navBound = '1';
  pre.addEventListener('click', (event) => {
    const fnTarget = event.target.closest('.decompile-fn-link[data-addr]');
    if (fnTarget && pre.contains(fnTarget)) {
      event.preventDefault();
      openDecompileFunction(fnTarget.dataset.addr, fnTarget.dataset.name || '', event);
      return;
    }
    const target = event.target.closest('.decompile-addr-link[data-addr]');
    if (target && pre.contains(target)) {
      event.preventDefault();
      handleDecompileAddressJump(target.dataset.addr, event, opts.binaryPath);
      return;
    }
    const stackTarget = event.target.closest('.decompile-stack-link[data-stack-name]');
    if (!stackTarget || !pre.contains(stackTarget)) return;
    event.preventDefault();
    openStackEntryFromDecompile(stackTarget.dataset.stackName);
  });
}

function buildDecompileRequestKey(binaryPath, decompiler, quality, addr, full, provider = 'auto', funcName = '') {
  return `${binaryPath || ''}\u0001${decompiler || ''}\u0001${_normalizeDecompileQuality(quality || 'normal')}\u0001${provider || 'auto'}\u0001${full ? '__full__' : (addr || '')}\u0001${String(funcName || '').trim()}`;
}

function getCurrentDecompileRequestContext() {
  const binaryPath = getStaticBinaryPath() || '';
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr, funcName } = getDecompileSelectionContext();
  return {
    binaryPath,
    decompiler,
    quality,
    provider,
    addr: addr || '',
    full: !addr,
    funcName: funcName || '',
  };
}

function getCachedDecompileResult(requestKey) {
  const cached = decompileResultCache.get(requestKey);
  if (!cached) return null;
  decompileResultCache.delete(requestKey);
  decompileResultCache.set(requestKey, cached);
  return cached;
}

function cacheDecompileResult(requestKey, payload) {
  if (!requestKey || !payload || payload.result?.error) return;
  if (decompileResultCache.has(requestKey)) {
    decompileResultCache.delete(requestKey);
  }
  decompileResultCache.set(requestKey, payload);
  while (decompileResultCache.size > MAX_DECOMPILE_RESULT_CACHE) {
    const oldestKey = decompileResultCache.keys().next().value;
    if (!oldestKey) break;
    decompileResultCache.delete(oldestKey);
  }
}

function clearDecompileCaches() {
  cancelPendingDecompileHighlight();
  decompileResultCache = new Map();
  pendingDecompileRequests.clear();
  decompileHighlightCache = {
    key: '',
    code: '',
    html: '',
  };
  decompileUiState.renderedProvider = _getConfiguredDecompilerProvider();
  decompileUiState.renderedQuality = _normalizeDecompileQuality(decompileUiState.quality || 'normal');
  resetDecompileHistory();
}

function renderDecompilePayload(container, payload) {
  if (!container || !payload) return;
  const result = payload.result || {};
  decompileUiState.renderedAddr = payload.full ? '' : (payload.addr || '');
  decompileUiState.renderedBinaryPath = payload.binaryPath || getStaticBinaryPath() || '';
  decompileUiState.renderedQuality = _normalizeDecompileQuality(payload.quality || result.quality || decompileUiState.quality || 'normal');
  decompileUiState.renderedDecompiler = payload.decompiler || _getRequestedDecompilerForQuality(decompileUiState.renderedQuality);
  decompileUiState.renderedProvider = payload.provider || _getConfiguredDecompilerProvider();
  decompileUiState.quality = decompileUiState.renderedQuality;
  decompileUiState.selectedAddr = payload.full ? '' : (payload.addr || decompileUiState.selectedAddr);
  if (result.error) {
    cancelPendingDecompileHighlight();
    container.textContent = `Erreur : ${result.error}`;
    return;
  }
  const code = result.code || (result.functions || []).map((f) => `// ${f.addr}\n${f.code}`).join('\n\n');
  const wrap = document.createElement('div');
  const callTargets = extractDecompileCallTargets(code, payload.addr);
  const addressTargets = extractDecompileAddressTargets(code, payload.addr);
  const structureSummary = summarizeDecompileStructure(code);
  const annotationTargets = Array.isArray(result.annotations) ? result.annotations : [];
  const typedStructTargets = Array.isArray(result.typed_structs) ? result.typed_structs : [];
  const stackFrame = result.stack_frame || null;
  const stackEntries = extractDecompileStackEntries(stackFrame);
  const qualityDetails = result.quality_details || null;
  const stackFrameAddr = normalizeHexAddress(payload.addr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const stackFrameBinaryPath = decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  const metaSummary = document.createElement('div');
  metaSummary.className = 'decompile-frame-summary';
  [
    _formatDecompileQualityLabel(decompileUiState.renderedQuality),
    qualityDetails?.selected_score != null ? `Score ${qualityDetails.selected_score}` : null,
    Array.isArray(qualityDetails?.backends) && qualityDetails.backends.length > 1 ? `Comparé ${qualityDetails.backends.length} backends` : null,
    annotationTargets.length ? `Annotations ${annotationTargets.length}` : null,
    typedStructTargets.length ? `Types ${typedStructTargets.length}` : null,
  ].filter(Boolean).forEach((label) => {
    const chip = document.createElement('span');
    chip.className = 'decompile-frame-chip';
    chip.textContent = label;
    metaSummary.appendChild(chip);
  });
  if (metaSummary.childElementCount) wrap.appendChild(metaSummary);
  if (Array.isArray(qualityDetails?.backends) && qualityDetails.backends.length) {
    const qualitySummary = document.createElement('div');
    qualitySummary.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = decompileUiState.renderedQuality === 'precision' ? 'Précision' : 'Qualité';
    qualitySummary.appendChild(title);
    qualityDetails.backends.forEach((entry) => {
      const chip = document.createElement('span');
      const tone = entry.selected ? 'data' : (entry.ok ? 'flow' : 'warn');
      chip.className = `decompile-outline-chip decompile-outline-chip-${tone}`;
      const backendName = entry.decompiler || 'backend';
      chip.textContent = entry.ok
        ? `${backendName} • ${entry.score ?? '—'}`
        : `${backendName} • erreur`;
      if (entry.ok && entry.metrics) {
        chip.title = [
          `Score ${entry.score ?? '—'}`,
          `lignes ${entry.metrics.lines ?? entry.metrics.functions ?? '—'}`,
          entry.metrics.calls != null ? `calls ${entry.metrics.calls}` : null,
          entry.metrics.control != null ? `control ${entry.metrics.control}` : null,
          entry.metrics.matched_calls != null ? `calls gardés ${entry.metrics.matched_calls}` : null,
          entry.metrics.missed_calls != null ? `calls perdus ${entry.metrics.missed_calls}` : null,
          entry.metrics.warnings != null ? `warnings ${entry.metrics.warnings}` : null,
          entry.metrics.placeholders != null ? `placeholders ${entry.metrics.placeholders}` : null,
          entry.metrics.errors != null ? `erreurs ${entry.metrics.errors}` : null,
        ].filter(Boolean).join(' • ');
      } else if (entry.error) {
        chip.title = String(entry.error);
      }
      qualitySummary.appendChild(chip);
    });
    wrap.appendChild(qualitySummary);
  }
  if (stackFrame) {
    cacheStackFrame(stackFrameBinaryPath, stackFrameAddr, stackFrame);
    if (isStaticTabActive('stack')) renderStackFrame(stackFrame);
    if (isStaticTabActive('hex')) updateHexSelectionSummary(window._lastDisasmAddr);
    const summary = document.createElement('div');
    summary.className = 'decompile-frame-summary';
    [
      stackFrame.arch && stackFrame.arch !== 'unknown' ? `Arch ${stackFrame.arch}` : null,
      stackFrame.abi && stackFrame.abi !== 'unknown' ? `ABI ${stackFrame.abi}` : null,
      typeof stackFrame.frame_size === 'number' ? `Frame ${stackFrame.frame_size}B` : null,
      `Args ${Array.isArray(stackFrame.args) ? stackFrame.args.length : 0}`,
      `Locals ${Array.isArray(stackFrame.vars) ? stackFrame.vars.length : 0}`,
    ].filter(Boolean).forEach((label) => {
      const chip = document.createElement('span');
      chip.className = 'decompile-frame-chip';
      chip.textContent = label;
      summary.appendChild(chip);
    });
    if (summary.childElementCount) wrap.appendChild(summary);
  }
  if (structureSummary.length) {
    const summary = document.createElement('div');
    summary.className = 'decompile-outline-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Sommaire';
    summary.appendChild(title);
    structureSummary.forEach((entry) => {
      const chip = document.createElement('span');
      chip.className = `decompile-outline-chip decompile-outline-chip-${entry.tone || 'neutral'}`;
      chip.textContent = entry.label;
      if (entry.title) chip.title = entry.title;
      summary.appendChild(chip);
    });
    wrap.appendChild(summary);
  }
  if (stackEntries.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Stack repéré';
    links.appendChild(title);
    stackEntries.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `decompile-link-chip decompile-link-chip-stack decompile-link-chip-stack-${entry.kind}`;
      button.dataset.stackName = entry.name;
      button.dataset.stackKind = entry.kind || '';
      button.dataset.stackLocation = entry.location || '';
      button.dataset.stackType = entry.type || '';
      button.textContent = entry.name;
      button.title = `${entry.kind === 'arg' ? 'Argument' : 'Variable locale'}${entry.location ? ` — ${entry.location}` : ''} • clic: ouvrir Stack Frame`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        openStackEntryFromDecompile(entry.name);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (callTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Appels repérés';
    links.appendChild(title);
    callTargets.forEach((target) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip';
      button.dataset.addr = target.addr;
      button.dataset.name = target.name;
      button.dataset.source = target.source || '';
      button.textContent = target.name;
      button.title = `${target.addr} — clic: ouvrir en pseudo-C • Shift+clic: désassemblage • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        openDecompileFunction(target.addr, target.name, event);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (addressTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Adresses repérées';
    links.appendChild(title);
    addressTargets.forEach((addr) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = addr;
      button.textContent = addr;
      button.title = 'Clic: aller au désassemblage • Shift+clic: ouvrir dans Hex • Alt+clic: centrer dans le CFG • Cmd/Ctrl+clic: Call Graph';
      button.addEventListener('click', (event) => {
        event.preventDefault();
        handleDecompileAddressJump(addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (annotationTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Annotations repérées';
    links.appendChild(title);
    annotationTargets.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = entry.addr || '';
      button.textContent = entry.name || entry.addr || 'annotation';
      button.title = `${entry.addr || 'Adresse inconnue'}${entry.comment ? ` — ${entry.comment}` : ''} • clic: désasm • Shift+clic: Hex • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        if (entry.addr) handleDecompileAddressJump(entry.addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (typedStructTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Types repérés';
    links.appendChild(title);
    typedStructTargets.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = entry.addr || '';
      const label = entry.name || entry.addr || 'type';
      const typeKind = entry.struct_kind || entry.kind || 'struct';
      button.textContent = label;
      const titleParts = [
        entry.struct_name ? `${typeKind} ${entry.struct_name}` : null,
        entry.field_name ? `champ ${entry.field_name}` : null,
        entry.field_type || null,
        entry.addr || null,
      ].filter(Boolean);
      button.title = `${titleParts.join(' • ')} • clic: désasm • Shift+clic: Hex • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        if (entry.addr) handleDecompileAddressJump(entry.addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  const pre = document.createElement('pre');
  pre.className = 'decompile-output';
  wrap.appendChild(pre);
  hideDecompilePeek();
  container.replaceChildren(wrap);
  bindDecompilePeek(wrap);
  scheduleDecompileHighlight(pre, code, {
    binaryPath: decompileUiState.renderedBinaryPath,
    decompiler: decompileUiState.renderedDecompiler,
    addr: decompileUiState.renderedAddr,
    currentName: payload.funcName || '',
    activeStackName: decompileUiState.pendingStackEntryName || decompileUiState.activeStackEntryName,
    searchQuery: decompileUiState.searchQuery || '',
    stackEntries,
  });
  tabDataCache.decompile = { binaryPath: decompileUiState.renderedBinaryPath || getStaticBinaryPath() };
}

function resetHexActiveUiState() {
  (hexActiveUiState.selectedRowEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-row-selected');
  });
  if (hexActiveUiState.activeRowEl?.isConnected) {
    hexActiveUiState.activeRowEl.classList.remove('hex-row-active');
  }
  (hexActiveUiState.selectedByteEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-byte-selected');
  });
  (hexActiveUiState.selectedAsciiEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-ascii-char-selected');
  });
  (hexActiveUiState.activeByteEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-byte-active');
  });
  (hexActiveUiState.activeAsciiEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-ascii-char-active');
  });
  hexActiveUiState = {
    selectedRowEls: [],
    activeRowEl: null,
    selectedByteEls: [],
    selectedAsciiEls: [],
    activeByteEls: [],
    activeAsciiEls: [],
    startAddr: '',
    endAddr: '',
    addr: '',
    anchorAddr: '',
    spanLength: 1,
  };
  updateHexSelectionButtons();
}

function resetHexDomState() {
  resetHexActiveUiState();
  hexDomState = {
    rowByOffset: new Map(),
    rowDataByOffset: new Map(),
    byteElsByAddr: new Map(),
    asciiElsByAddr: new Map(),
  };
}

function getHexRowByOffsetHex(rowOffsetHex) {
  const key = String(rowOffsetHex || '').toLowerCase();
  return hexDomState.rowDataByOffset.get(key)
    || (window._lastHexRows || []).find((entry) => String(entry.offset || '').toLowerCase() === key)
    || null;
}

function appendHexDomEntry(map, key, el) {
  if (!key || !el) return;
  const normalized = String(key).toLowerCase();
  const existing = map.get(normalized);
  if (existing) {
    existing.push(el);
  } else {
    map.set(normalized, [el]);
  }
}

function updateHexPatchButtons() {
  const undoBtn = document.getElementById('btnHexUndo');
  if (undoBtn) undoBtn.disabled = hexPatchHistory.length === 0;
  const redoBtn = document.getElementById('btnHexRedo');
  if (redoBtn) redoBtn.disabled = hexPatchRedoHistory.length === 0;
}

function resetHexPatchSessionState() {
  hexPatchHistory = [];
  hexPatchRedoHistory = [];
  updateHexPatchButtons();
}

function parseNumericAddress(value) {
  if (value == null) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const text = String(value).trim().toLowerCase();
  if (!text) return null;
  const parsed = text.startsWith('0x') ? parseInt(text, 16) : parseInt(text, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeSpanLength(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 1;
  return Math.max(1, Math.floor(parsed));
}

function buildHexSelectionDescriptor(addr, opts = {}) {
  const activeAddr = normalizeHexAddress(opts.activeAddr || addr);
  const anchorAddr = normalizeHexAddress(opts.anchorAddr || addr);
  const normalizedStart = normalizeHexAddress(addr);
  if (!normalizedStart) return null;
  const startNum = parseNumericAddress(normalizedStart);
  if (!Number.isFinite(startNum)) return null;

  let endAddr = normalizeHexAddress(opts.endAddr || '');
  let endNum = Number.isFinite(parseNumericAddress(endAddr)) ? parseNumericAddress(endAddr) : null;
  if (!Number.isFinite(endNum)) {
    endNum = startNum + normalizeSpanLength(opts.spanLength) - 1;
    endAddr = `0x${endNum.toString(16)}`;
  }

  const low = Math.min(startNum, endNum);
  const high = Math.max(startNum, endNum);
  return {
    startAddr: `0x${low.toString(16)}`,
    endAddr: `0x${high.toString(16)}`,
    activeAddr: activeAddr || `0x${low.toString(16)}`,
    anchorAddr: anchorAddr || `0x${low.toString(16)}`,
    startNum: low,
    endNum: high,
    spanLength: Math.max(1, (high - low) + 1),
  };
}

function getCurrentHexSelectionDescriptor() {
  if (hexSelectionModel.startAddr) {
    return buildHexSelectionDescriptor(hexSelectionModel.startAddr, {
      endAddr: hexSelectionModel.endAddr,
      activeAddr: hexSelectionModel.activeAddr || hexSelectionModel.startAddr,
      anchorAddr: hexSelectionModel.anchorAddr || hexSelectionModel.startAddr,
      spanLength: hexSelectionModel.spanLength || 1,
    });
  }
  if (!window._lastDisasmAddr) return null;
  return buildHexSelectionDescriptor(window._lastDisasmAddr, {
    activeAddr: window._lastDisasmAddr,
    anchorAddr: window._lastDisasmAddr,
    spanLength: 1,
  });
}

function setHexSelectionModel(descriptor) {
  if (!descriptor) {
    hexSelectionModel = {
      startAddr: '',
      endAddr: '',
      activeAddr: '',
      anchorAddr: '',
      spanLength: 1,
    };
    typedDataUiState.hexStructPreview = null;
    updateHexSelectionButtons();
    return;
  }
  if (
    typedDataUiState.hexStructPreview
    && normalizeHexAddress(typedDataUiState.hexStructPreview.addr || '') !== normalizeHexAddress(descriptor.startAddr)
  ) {
    typedDataUiState.hexStructPreview = null;
  }
  hexSelectionModel = {
    startAddr: descriptor.startAddr,
    endAddr: descriptor.endAddr,
    activeAddr: descriptor.activeAddr,
    anchorAddr: descriptor.anchorAddr,
    spanLength: descriptor.spanLength,
  };
  updateHexSelectionButtons();
}

function updateHexSelectionButtons() {
  const hasSelection = !!hexSelectionModel.startAddr;
  const openBtn = document.getElementById('btnHexOpenSelection');
  if (openBtn) openBtn.disabled = !hasSelection;
  const resetBtn = document.getElementById('btnHexResetSelection');
  if (resetBtn) {
    resetBtn.disabled = !hasSelection || normalizeSpanLength(hexSelectionModel.spanLength) <= 1;
  }
}

function vaddrFromFileOffset(fileOffset, sections = hexSections) {
  const fileOffsetNum = parseNumericAddress(fileOffset);
  if (!Number.isFinite(fileOffsetNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset);
    const secVaddr = parseNumericAddress(sec.virtual_address);
    const secSize = parseNumericAddress(sec.size);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secVaddr) || !Number.isFinite(secSize)) continue;
    if (fileOffsetNum >= secOffset && fileOffsetNum < secOffset + secSize) {
      return `0x${(secVaddr + (fileOffsetNum - secOffset)).toString(16)}`;
    }
  }
  return null;
}

function findSectionForFileOffset(fileOffset, sections = hexSections) {
  const fileOffsetNum = parseNumericAddress(fileOffset);
  if (!Number.isFinite(fileOffsetNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset);
    const secSize = parseNumericAddress(sec.size);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secSize)) continue;
    if (fileOffsetNum >= secOffset && fileOffsetNum < secOffset + secSize) return sec;
  }
  return null;
}

function fileOffsetFromVaddr(vaddr, sections = hexSections) {
  const vaddrNum = parseNumericAddress(vaddr);
  if (!Number.isFinite(vaddrNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset);
    const secVaddr = parseNumericAddress(sec.virtual_address);
    const secSize = parseNumericAddress(sec.size);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secVaddr) || !Number.isFinite(secSize)) continue;
    if (vaddrNum >= secVaddr && vaddrNum < secVaddr + secSize) {
      return secOffset + (vaddrNum - secVaddr);
    }
  }
  return null;
}

function getHexSelectionPreview(descriptor, maxBytes = 64) {
  if (!descriptor) return null;
  const bytes = [];
  const ascii = [];
  for (let addrNum = descriptor.startNum; addrNum <= descriptor.endNum && bytes.length < maxBytes; addrNum += 1) {
    const vaddr = `0x${addrNum.toString(16)}`;
    const fileOffset = fileOffsetFromVaddr(vaddr);
    if (!Number.isFinite(fileOffset)) break;
    const rowOffset = fileOffset - (fileOffset % 16);
    const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
    const row = getHexRowByOffsetHex(rowOffsetHex);
    if (!row) break;
    const rowHexParts = String(row.hex || '').trim().split(/\s+/).filter(Boolean);
    const byteIndex = fileOffset - rowOffset;
    bytes.push(rowHexParts[byteIndex] || '??');
    ascii.push(typeof row.ascii === 'string' ? (row.ascii[byteIndex] || '.') : '.');
  }
  if (!bytes.length) return null;
  return {
    hex: bytes.join(' '),
    ascii: ascii.join(''),
    truncated: descriptor.spanLength > bytes.length,
  };
}

function updateHexPatchInputsForSelection(descriptor) {
  const normalized = normalizeHexAddress(descriptor?.startAddr || descriptor?.activeAddr || '');
  const offsetInput = document.getElementById('hexPatchOffset');
  const status = document.getElementById('hexPatchStatus');
  if (!offsetInput) return;
  if (!normalized) {
    if (!offsetInput.value.trim()) offsetInput.value = '0x0';
    return;
  }
  const fileOffset = fileOffsetFromVaddr(normalized);
  if (!Number.isFinite(fileOffset)) return;
  offsetInput.value = `0x${fileOffset.toString(16)}`;
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const row = getHexRowByOffsetHex(rowOffsetHex);
  const byteIndex = fileOffset - rowOffset;
  const rowHexParts = String(row?.hex || '').trim().split(/\s+/).filter(Boolean);
  const byteValue = rowHexParts[byteIndex] || '';
  if (!status) return;
  status.className = 'hex-patch-status';
  if (descriptor?.spanLength > 1) {
    status.textContent = `Sélection active: ${descriptor.spanLength} octets depuis ${offsetInput.value}`;
  } else if (byteValue) {
    status.textContent = `Octet actif: ${byteValue} @ ${offsetInput.value}`;
  }
}

function buildHexStructPreviewHtml(ctx) {
  const preview = typedDataUiState.hexStructPreview;
  if (!ctx) return '';
  const preferredStruct = getPreferredHexStructName();
  const structs = getTypedStructList();
  const optionsHtml = [
    '<option value="">— type C —</option>',
    ...structs.map((entry) => {
      const name = typeof entry === 'string' ? entry : String((entry && entry.name) || '');
      if (!name) return '';
      const kind = typeof entry === 'string' ? 'struct' : String((entry && entry.kind) || 'struct');
      const fieldCount = Number((entry && entry.field_count) || 0);
      const label = typeof entry === 'string'
        ? name
        : `${name} (${kind}, ${fieldCount} champ${fieldCount > 1 ? 's' : ''})`;
      const selected = preferredStruct && preferredStruct === name ? ' selected' : '';
      return `<option value="${escapeHtml(name)}"${selected}>${escapeHtml(label)}</option>`;
    }),
  ].filter(Boolean).join('');

  let previewHtml = '';
  const previewMatches = preview
    && normalizeHexAddress(preview.addr || '') === ctx.addr
    && String(preview.structName || '') === preferredStruct;
  if (previewMatches && preview.loading) {
    previewHtml = '<p class="hint hex-struct-preview-empty">Prévisualisation du type…</p>';
  } else if (previewMatches && preview.error) {
    previewHtml = `<p class="hint hex-struct-preview-empty">${escapeHtml(preview.error)}</p>`;
  } else if (previewMatches && preview.appliedStruct) {
    const applied = preview.appliedStruct;
    const appliedKind = String(applied.kind || 'struct');
    const previewFields = (applied.fields || []).slice(0, 6).map((field) => (
      `<div class="hex-struct-preview-field">` +
      `<code>${escapeHtml(field.field_name || '')}</code>` +
      `<code>${escapeHtml(field.field_type || '')}</code>` +
      `<span>${escapeHtml(field.decoded || '')}</span>` +
      `</div>`
    )).join('');
    const overflow = (applied.fields || []).length > 6
      ? `<p class="hint hex-struct-preview-empty">${escapeHtml(String((applied.fields || []).length - 6))} champ(s) supplémentaire(s) visibles dans Données typées.</p>`
      : '';
    previewHtml = (
      `<div class="hex-struct-preview">` +
      `<div class="hex-selection-chips">` +
      `<span class="hex-selection-chip hex-selection-chip-primary">${escapeHtml(applied.name || preferredStruct)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(appliedKind)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(applied.section || ctx.section?.name || 'section inconnue')}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(applied.addr || ctx.addr)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(String((applied.fields || []).length))} champ(s)</span>` +
      `</div>` +
      previewFields +
      overflow +
      `</div>`
    );
  } else if (!preferredStruct) {
    previewHtml = '<p class="hint hex-struct-preview-empty">Choisis un type C pour prévisualiser la sélection courante.</p>';
  } else {
    previewHtml = '<p class="hint hex-struct-preview-empty">Prévisualise ou ouvre ce type dans Données typées.</p>';
  }

  const sectionHint = ctx.section?.name
    ? `${ctx.section.name} @ +${ctx.sectionOffsetHex}`
    : `adresse ${ctx.addr}`;
  return (
    `<div class="hex-struct-card">` +
    `<div class="hex-struct-head">` +
    `<span class="section-label">Type rapide</span>` +
    `<span class="hint">${escapeHtml(sectionHint)}</span>` +
    `</div>` +
    `<div class="hex-struct-controls">` +
    `<select id="hexStructSelect" class="select-modern">${optionsHtml}</select>` +
    `<button type="button" class="btn btn-xs btn-secondary" id="btnHexPreviewStruct"${preferredStruct ? '' : ' disabled'}>Aperçu</button>` +
    `<button type="button" class="btn btn-xs btn-secondary" id="btnHexOpenTypedStruct"${preferredStruct ? '' : ' disabled'}>Données typées</button>` +
    `</div>` +
    previewHtml +
    `</div>`
  );
}

function updateHexSelectionSummary(selection = null) {
  const container = document.getElementById('hexSelectionSummary');
  if (!container) return;
  ensureTypedStructCatalogLoaded();
  const descriptor = selection && typeof selection === 'object'
    ? buildHexSelectionDescriptor(selection.startAddr || selection.addr || selection.activeAddr || '', selection)
    : getCurrentHexSelectionDescriptor();
  const normalized = normalizeHexAddress(descriptor?.activeAddr || descriptor?.startAddr || '');
  if (!descriptor || !normalized) {
    container.innerHTML = '<p class="hint">Sélectionnez une ligne hex ou naviguez depuis le désassemblage pour afficher le contexte.</p>';
    return;
  }
  const fileOffset = fileOffsetFromVaddr(descriptor.startAddr);
  if (!Number.isFinite(fileOffset)) {
    container.innerHTML = `<p class="hint">Sélection active ${escapeHtml(descriptor.startAddr)} hors de la fenêtre hex actuelle ou non mappée dans les sections.</p>`;
    return;
  }
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const row = getHexRowByOffsetHex(rowOffsetHex);
  const section = findSectionForFileOffset(fileOffsetFromVaddr(descriptor.activeAddr) ?? fileOffset);
  const summary = getActiveContextSummary(normalized);
  const stackFrameAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  const stackFrameKey = getStackFrameCacheKey(summary.binaryPath, stackFrameAddr);
  let stackFrame = getCachedStackFrame(summary.binaryPath, stackFrameAddr);
  if (!stackFrame && summary.binaryPath && stackFrameAddr && !isRawBinarySelected()) {
    ensureStackFrameLoaded(summary.binaryPath, stackFrameAddr);
  }
  const byteIndex = fileOffset - rowOffset;
  const rowHexParts = String(row?.hex || '').trim().split(/\s+/).filter(Boolean);
  const byteValue = rowHexParts[byteIndex] || '';
  const asciiChar = typeof row?.ascii === 'string' ? (row.ascii[byteIndex] || '') : '';
  const chips = [
    descriptor.spanLength > 1
      ? `Plage ${descriptor.startAddr} → ${descriptor.endAddr}`
      : `Adresse ${normalized}`,
    descriptor.spanLength > 1 ? `Taille ${descriptor.spanLength} octets` : `Offset 0x${fileOffset.toString(16)}`,
    descriptor.spanLength > 1 ? `Actif ${descriptor.activeAddr}` : `Ligne ${rowOffsetHex}`,
    descriptor.spanLength > 1 ? null : (Number.isFinite(byteIndex) ? `Byte +0x${byteIndex.toString(16)}` : null),
    descriptor.spanLength > 1 ? null : (byteValue ? `Valeur ${byteValue}` : null),
    descriptor.spanLength > 1 ? null : (asciiChar ? `ASCII ${asciiChar === ' ' ? 'space' : asciiChar}` : null),
    section?.name ? `Section ${section.name}` : null,
    section?.type ? `Type ${section.type}` : null,
    summary.functionAddr ? `Fonction ${summary.functionName ? `${summary.functionName} @ ${summary.functionAddr}` : summary.functionAddr}` : null,
    stackFrame && !stackFrame.error && typeof stackFrame.frame_size === 'number' ? `Frame ${stackFrame.frame_size}B` : null,
  ].filter(Boolean);
  const chipsHtml = chips.map((chip, index) => `<span class="hex-selection-chip${index === 0 ? ' hex-selection-chip-primary' : ''}">${escapeHtml(chip)}</span>`).join('');
  const actionsHtml = `
    <div class="hex-selection-actions">
      <button type="button" class="btn btn-xs btn-secondary" id="btnHexSelectionJumpDisasm">Désasm</button>
      <button type="button" class="btn btn-xs btn-secondary" id="btnHexSelectionCollapse"${descriptor.spanLength <= 1 ? ' disabled' : ''}>Réduire</button>
      <span class="hint">Shift+clic pour étendre • double-clic pour ouvrir dans le désasm</span>
    </div>
  `;
  const previewParts = [];
  const selectionPreview = getHexSelectionPreview(descriptor);
  if (selectionPreview?.hex) previewParts.push(`Hex : ${selectionPreview.hex}${selectionPreview.truncated ? ' …' : ''}`);
  if (selectionPreview?.ascii) previewParts.push(`ASCII : ${selectionPreview.ascii}${selectionPreview.truncated ? ' …' : ''}`);
  if (!selectionPreview?.hex && row?.hex) previewParts.push(`Hex : ${row.hex}`);
  if (!selectionPreview?.ascii && row?.ascii) previewParts.push(`ASCII : ${row.ascii}`);
  const previewHtml = previewParts.length
    ? `<div class="hex-selection-preview">${escapeHtml(previewParts.join('\n'))}</div>`
    : '<p class="hint">Aperçu indisponible pour cette ligne.</p>';
  const stackHtml = stackFrame
    ? buildHexStackContextHtml(stackFrame)
    : (stackFrameKey && pendingStackFrameRequests.has(stackFrameKey)
      ? '<p class="hint">Chargement du contexte stack de la fonction…</p>'
      : '');
  const structHtml = buildHexStructPreviewHtml(getHexStructSelectionContext(descriptor));
  container.innerHTML = `<div class="hex-selection-chips">${chipsHtml}</div>${actionsHtml}${previewHtml}${stackHtml}${structHtml}`;
  document.getElementById('btnHexSelectionJumpDisasm')?.addEventListener('click', () => openHexSelectionInDisasm());
  document.getElementById('btnHexSelectionCollapse')?.addEventListener('click', () => collapseHexSelectionToActive());
  document.getElementById('hexStructSelect')?.addEventListener('change', (event) => {
    typedDataUiState.hexStructName = String(event.target?.value || '');
    typedDataUiState.hexStructPreview = null;
    updateHexSelectionSummary(descriptor);
  });
  document.getElementById('btnHexPreviewStruct')?.addEventListener('click', () => {
    requestHexStructPreview(getPreferredHexStructName(), getHexStructSelectionContext(descriptor));
  });
  document.getElementById('btnHexOpenTypedStruct')?.addEventListener('click', () => {
    openTypedDataStructFromSelection(getPreferredHexStructName(), getHexStructSelectionContext(descriptor));
  });
}

function setHexActiveAddress(addr, opts = {}) {
  const descriptor = buildHexSelectionDescriptor(addr, {
    endAddr: opts.endAddr,
    activeAddr: opts.activeAddr || addr,
    anchorAddr: opts.anchorAddr || addr,
    spanLength: opts.spanLength || 1,
  });
  resetHexActiveUiState();
  if (!descriptor) {
    setHexSelectionModel(null);
    updateHexSelectionSummary(null);
    updateHexPatchInputsForSelection(null);
    return null;
  }
  setHexSelectionModel(descriptor);
  const fileOffset = fileOffsetFromVaddr(descriptor.activeAddr);
  if (!Number.isFinite(fileOffset)) {
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    return null;
  }
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const rowEl = hexDomState.rowByOffset.get(rowOffsetHex.toLowerCase()) || null;
  const selectedRowEls = [];
  const selectedByteEls = [];
  const selectedAsciiEls = [];
  for (let addrNum = descriptor.startNum; addrNum <= descriptor.endNum && addrNum - descriptor.startNum < 8192; addrNum += 1) {
    const currentAddr = `0x${addrNum.toString(16)}`;
    const currentOffset = fileOffsetFromVaddr(currentAddr);
    if (!Number.isFinite(currentOffset)) continue;
    const currentRowOffset = currentOffset - (currentOffset % 16);
    const currentRowOffsetHex = `0x${currentRowOffset.toString(16).padStart(8, '0')}`;
    const currentRowEl = hexDomState.rowByOffset.get(currentRowOffsetHex.toLowerCase()) || null;
    if (currentRowEl && !selectedRowEls.includes(currentRowEl)) selectedRowEls.push(currentRowEl);
    selectedByteEls.push(...(hexDomState.byteElsByAddr.get(currentAddr.toLowerCase()) || []));
    selectedAsciiEls.push(...(hexDomState.asciiElsByAddr.get(currentAddr.toLowerCase()) || []));
  }
  if (rowEl || selectedRowEls.length) {
    selectedRowEls.forEach((el) => el.classList.add('hex-row-selected'));
    if (rowEl) rowEl.classList.add('hex-row-active');
    selectedByteEls.forEach((el) => el.classList.add('hex-byte-selected'));
    selectedAsciiEls.forEach((el) => el.classList.add('hex-ascii-char-selected'));
    const activeByteEls = hexDomState.byteElsByAddr.get(descriptor.activeAddr.toLowerCase()) || [];
    const activeAsciiEls = hexDomState.asciiElsByAddr.get(descriptor.activeAddr.toLowerCase()) || [];
    activeByteEls.forEach((el) => el.classList.add('hex-byte-active'));
    activeAsciiEls.forEach((el) => el.classList.add('hex-ascii-char-active'));
    hexActiveUiState = {
      selectedRowEls,
      activeRowEl: rowEl,
      selectedByteEls,
      selectedAsciiEls,
      activeByteEls,
      activeAsciiEls,
      startAddr: descriptor.startAddr,
      endAddr: descriptor.endAddr,
      addr: descriptor.activeAddr,
      anchorAddr: descriptor.anchorAddr,
      spanLength: descriptor.spanLength,
    };
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    if (opts.reveal && rowEl) {
      rowEl.scrollIntoView({ behavior: opts.instant ? 'auto' : 'smooth', block: 'center' });
    }
    return rowEl;
  }
  if (hexRenderInProgress) {
    if (opts.reveal) hexPendingScrollVaddr = descriptor;
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    return null;
  }
  if (opts.reveal) {
    const bp = tabDataCache.hex?.binaryPath || getStaticBinaryPath();
    if (bp) {
      hexPendingScrollVaddr = descriptor;
      loadHexView(bp, rowOffset - (rowOffset % 16), hexCurrentLength);
    }
  }
  updateHexSelectionSummary(descriptor);
  updateHexPatchInputsForSelection(descriptor);
  return null;
}

function setActiveAddressContext(addr, spanLength = 1, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  window._lastDisasmAddr = normalized;
  updateActiveContextBars(normalized);
  updateActiveNavRows(normalized);
  updateDisasmSessionSummary();
  if (!opts.preserveHexSelection) {
    setHexSelectionModel(buildHexSelectionDescriptor(normalized, {
      activeAddr: normalized,
      anchorAddr: normalized,
      spanLength,
    }));
  } else if (spanLength > 0) {
    hexSelectionModel.spanLength = normalizeSpanLength(spanLength);
  }
  return normalized;
}

function openHexSelectionInDisasm(addr = hexSelectionModel.activeAddr || hexSelectionModel.startAddr) {
  const normalized = normalizeHexAddress(addr);
  const bp = getStaticBinaryPath();
  if (!normalized || !bp) return;
  vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp });
}

function collapseHexSelectionToActive() {
  const activeAddr = normalizeHexAddress(hexSelectionModel.activeAddr || hexSelectionModel.startAddr || '');
  if (!activeAddr) return;
  setHexActiveAddress(activeAddr, {
    activeAddr,
    anchorAddr: activeAddr,
    spanLength: 1,
    reveal: false,
    instant: true,
  });
}

function handleHexAddressSelection(addr, event = null, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return;
  const extend = !!event?.shiftKey && !!normalizeHexAddress(hexSelectionModel.anchorAddr || '');
  const anchorAddr = extend
    ? normalizeHexAddress(hexSelectionModel.anchorAddr || hexSelectionModel.startAddr || normalized)
    : normalizeHexAddress(opts.anchorAddr || normalized);
  const descriptor = buildHexSelectionDescriptor(anchorAddr, {
    endAddr: extend ? normalized : opts.endAddr,
    activeAddr: normalized,
    anchorAddr,
    spanLength: extend ? undefined : normalizeSpanLength(opts.spanLength || 1),
  });
  if (!descriptor) return;
  setActiveAddressContext(normalized, descriptor.spanLength, { preserveHexSelection: true });
  setHexActiveAddress(descriptor.startAddr, {
    endAddr: descriptor.endAddr,
    activeAddr: descriptor.activeAddr,
    anchorAddr: descriptor.anchorAddr,
    spanLength: descriptor.spanLength,
    reveal: false,
    instant: true,
  });
  document.getElementById('hexContent')?.focus();
  if (opts.openInDisasm || (event && event.detail > 1)) {
    openHexSelectionInDisasm(normalized);
  }
}

function updateHexRenderStatus(done, total, busy = false) {
  const el = document.getElementById('hexRenderStatus');
  if (!el) return;
  if (!total) {
    el.textContent = 'Prêt';
    return;
  }
  if (busy) {
    el.textContent = `Rendu ${done}/${total} lignes…`;
    return;
  }
  el.textContent = `${total} lignes`;
}

function buildHexTableRow(row, sections, tbody) {
  const rowOffNum = parseInt(row.offset, 16);
  let secType = '';
  for (const sec of sections) {
    if (rowOffNum >= sec.offset && rowOffNum < sec.offset + sec.size) {
      secType = sec.type;
      break;
    }
  }
  const tr = document.createElement('tr');
  tbody.appendChild(tr);
  tr.dataset.offset = row.offset;
  hexDomState.rowByOffset.set(String(row.offset || '').toLowerCase(), tr);
  hexDomState.rowDataByOffset.set(String(row.offset || '').toLowerCase(), row);
  const rowVaddr = vaddrFromFileOffset(rowOffNum, sections);
  if (rowVaddr) tr.dataset.vaddr = rowVaddr;
  if (secType) tr.className = 'hex-row-' + secType;
  tr.title = rowVaddr ? `Offset ${row.offset} → ${rowVaddr}` : `Offset ${row.offset}`;

  const hexParts = row.hex.split(' ');
  [
    { cls: 'hex-col-offset', text: row.offset },
    { cls: 'hex-col-vaddr',  text: rowVaddr || '—' },
    { cls: 'hex-col-hex',    text: row.hex },
    { cls: 'hex-col-ascii',  text: row.ascii },
  ].forEach(({ cls, text }, colIdx) => {
    const td = document.createElement('td');
    td.className = cls;
    tr.appendChild(td);
    const code = document.createElement('code');
    td.appendChild(code);
    if (colIdx === 0) {
      code.textContent = text;
      td.style.cursor = 'pointer';
      td.title = 'Aller au désassemblage';
      td.addEventListener('click', () => {
        if (rowVaddr) handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
        const bp = getStaticBinaryPath();
        if (row.offset && bp) vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: row.offset, binaryPath: bp });
      });
    } else if (colIdx === 1 && rowVaddr) {
      code.textContent = text;
      td.style.cursor = 'pointer';
      td.title = 'Aller au désassemblage';
      td.addEventListener('click', () => {
        handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubGoToAddress', addr: rowVaddr, binaryPath: bp });
      });
    } else if (colIdx === 2) {
      hexParts.forEach((part, byteIdx) => {
        const byteVaddr = rowVaddr ? `0x${(parseNumericAddress(rowVaddr) + byteIdx).toString(16)}` : '';
        const span = document.createElement('span');
        span.className = 'hex-byte';
        span.textContent = part;
        if (byteVaddr) span.dataset.vaddr = byteVaddr;
        appendHexDomEntry(hexDomState.byteElsByAddr, byteVaddr, span);
        span.title = byteVaddr ? `${byteVaddr} • ${part}` : part;
        span.addEventListener('click', (event) => {
          event.stopPropagation();
          if (!byteVaddr) return;
          handleHexAddressSelection(byteVaddr, event, { spanLength: 1 });
        });
        code.appendChild(span);
        if (byteIdx !== hexParts.length - 1) code.appendChild(document.createTextNode(byteIdx === 7 ? '  ' : ' '));
      });
    } else if (colIdx === 3) {
      Array.from(String(row.ascii || '')).forEach((ch, byteIdx) => {
        const byteVaddr = rowVaddr ? `0x${(parseNumericAddress(rowVaddr) + byteIdx).toString(16)}` : '';
        const span = document.createElement('span');
        span.className = 'hex-ascii-char';
        span.textContent = ch;
        if (byteVaddr) span.dataset.vaddr = byteVaddr;
        appendHexDomEntry(hexDomState.asciiElsByAddr, byteVaddr, span);
        span.title = byteVaddr ? `${byteVaddr} • ${ch}` : ch;
        span.addEventListener('click', (event) => {
          event.stopPropagation();
          if (!byteVaddr) return;
          handleHexAddressSelection(byteVaddr, event, { spanLength: 1 });
        });
        code.appendChild(span);
      });
    } else {
      code.textContent = text;
    }
  });
  tr.addEventListener('click', () => {
    if (!rowVaddr) return;
    handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
  });
}

function renderHexTable(container, rows, sections) {
  window._lastHexRows = Array.isArray(rows) ? rows : [];
  resetHexDomState();
  container.replaceChildren();
  hexRenderInProgress = false;
  const renderId = ++hexRenderSessionId;
  if (!rows.length) {
    updateHexRenderStatus(0, 0, false);
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = 'Aucune donn\u00e9e \u00e0 cet offset.';
    container.appendChild(p);
    return;
  }
  const table = document.createElement('table');
  table.className = 'hex-table';

  const thead = table.createTHead();
  const hr = thead.insertRow();
  ['Offset', 'VAddr', '00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F', 'ASCII'].forEach((h, i) => {
    const th = document.createElement('th');
    th.textContent = h;
    th.className = ['hex-col-offset', 'hex-col-vaddr', 'hex-col-hex', 'hex-col-ascii'][i];
    hr.appendChild(th);
  });

  const tbody = table.createTBody();
  container.appendChild(table);
  const totalRows = rows.length;
  const batchSize = totalRows > 512 ? 96 : totalRows > 128 ? 64 : totalRows;
  let index = 0;
  const renderBatch = () => {
    if (renderId !== hexRenderSessionId) return;
    const end = Math.min(index + batchSize, totalRows);
    for (; index < end; index += 1) {
      buildHexTableRow(rows[index], sections, tbody);
    }
    const busy = index < totalRows;
    hexRenderInProgress = busy;
    updateHexRenderStatus(index, totalRows, busy);
    if (busy) {
      requestAnimationFrame(renderBatch);
      return;
    }
    const currentSelection = getCurrentHexSelectionDescriptor();
    if (currentSelection) {
      setHexActiveAddress(currentSelection.startAddr, {
        endAddr: currentSelection.endAddr,
        activeAddr: currentSelection.activeAddr,
        anchorAddr: currentSelection.anchorAddr,
        spanLength: currentSelection.spanLength,
        reveal: false,
        instant: true,
      });
    }
    if (hexPendingScrollVaddr) {
      const pending = hexPendingScrollVaddr;
      hexPendingScrollVaddr = null;
      requestAnimationFrame(() => scrollHexToVaddr(pending));
    }
  };
  updateHexRenderStatus(0, totalRows, totalRows > batchSize);
  if (totalRows > batchSize) {
    hexRenderInProgress = true;
    requestAnimationFrame(renderBatch);
  } else {
    renderBatch();
  }
}

function renderHexSectionLegend(sections) {
  const legend = document.getElementById('hexSectionLegend');
  if (!legend) return;
  legend.replaceChildren();
  legend.hidden = !sections.length;
  if (!sections.length) return;
  const label = document.createElement('span');
  label.className = 'hex-legend-label';
  label.textContent = 'Sections\u00a0:';
  legend.appendChild(label);
  const seen = new Set();
  sections.forEach(sec => {
    if (seen.has(sec.type)) return;
    seen.add(sec.type);
    const chip = document.createElement('span');
    chip.className = 'hex-legend-item hex-legend-' + sec.type;
    chip.textContent = sec.type;
    legend.appendChild(chip);
  });
}

function scrollHexToVaddr(vaddrInput) {
  if (!hexSections.length) return;
  const descriptor = typeof vaddrInput === 'object' && vaddrInput
    ? buildHexSelectionDescriptor(vaddrInput.addr || vaddrInput.activeAddr || '', vaddrInput)
    : buildHexSelectionDescriptor(vaddrInput, { spanLength: 1 });
  const normalized = normalizeHexAddress(descriptor?.activeAddr || descriptor?.startAddr || '');
  if (!descriptor || !normalized) return;
  const fileOffset = fileOffsetFromVaddr(normalized);
  if (fileOffset == null) return;
  // Arrondir au début de la ligne (16 octets)
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = '0x' + rowOffset.toString(16).padStart(8, '0');
  // Chercher si la row est déjà visible dans le DOM
  const tr = document.querySelector(`#hexContent tr[data-offset="${rowOffsetHex}"]`);
  if (tr) {
    setHexActiveAddress(descriptor.startAddr, {
      endAddr: descriptor.endAddr,
      activeAddr: descriptor.activeAddr,
      anchorAddr: descriptor.anchorAddr,
      spanLength: descriptor.spanLength,
      reveal: true,
    });
    tr.classList.add('hex-row-highlight');
    setTimeout(() => tr.classList.remove('hex-row-highlight'), 1500);
  } else if (hexRenderInProgress) {
    hexPendingScrollVaddr = descriptor;
  } else if (tabDataCache.hex) {
    // La page hex ne contient pas encore cet offset — on navigue
    const bp = tabDataCache.hex.binaryPath || getStaticBinaryPath();
    loadHexView(bp, rowOffset, hexCurrentLength);
    // Après chargement, le DOM sera reconstruit — un re-scroll sera nécessaire
    // On stocke l'adresse cible pour y revenir après render
    hexPendingScrollVaddr = descriptor;
  }
}

function renderStackFrame(data) {
  const content = document.getElementById('stackContent');
  if (!content) return;
  while (content.firstChild) content.removeChild(content.firstChild);

  const sizeEl = document.getElementById('stackFrameSize');
  if (sizeEl) sizeEl.textContent = '';
  const activeSummary = getActiveContextSummary(window._lastDisasmAddr || decompileUiState.selectedAddr);
  stackUiState.renderedBinaryPath = activeSummary.binaryPath || '';
  stackUiState.renderedAddr = normalizeHexAddress(activeSummary.functionAddr || activeSummary.addr);

  if (!data || data.error) {
    const p = document.createElement('p');
    p.className = 'error-text';
    p.textContent = (data && data.error) ? data.error : 'Erreur inconnue';
    content.appendChild(p);
    return;
  }

  const args = Array.isArray(data.args) ? [...data.args] : [];
  const vars = Array.isArray(data.vars) ? [...data.vars] : [];
  const allEntries = [...args, ...vars];
  const metaParts = [`Frame: ${Number(data.frame_size)} bytes`];
  if (data.arch && data.arch !== 'unknown') metaParts.push(`Arch: ${data.arch}`);
  if (data.abi && data.abi !== 'unknown') metaParts.push(`ABI: ${data.abi}`);
  if (sizeEl) sizeEl.textContent = metaParts.join(' · ');

  if (allEntries.length === 0) {
    const p = document.createElement('p');
    p.className = 'placeholder-text';
    p.textContent = 'Aucune variable ou argument détecté.';
    content.appendChild(p);
    return;
  }

  const registerArgs = args.filter(v => v && (v.source === 'abi' || typeof v.offset !== 'number'));
  const stackArgs = args
    .filter(v => v && !registerArgs.includes(v))
    .sort((a, b) => (a.offset || 0) - (b.offset || 0));

  const summary = document.createElement('div');
  summary.className = 'stack-summary';
  [
    data.arch && data.arch !== 'unknown' ? `Arch ${data.arch}` : null,
    data.abi && data.abi !== 'unknown' ? `ABI ${data.abi}` : null,
    `Args ${args.length}`,
    `Locals ${vars.length}`,
    registerArgs.length ? `Reg ${registerArgs.length}` : null,
  ].filter(Boolean).forEach(label => {
    const chip = document.createElement('span');
    chip.className = 'stack-summary-chip';
    chip.textContent = label;
    summary.appendChild(chip);
  });
  if (summary.childElementCount) content.appendChild(summary);

  const table = document.createElement('table');
  table.className = 'stack-table';

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['Emplacement', 'Nom', 'Taille', 'Type'].forEach(h => {
    const th = document.createElement('th');
    th.textContent = h;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  const appendRow = (v, kind) => {
    const tr = document.createElement('tr');
    tr.className = `stack-${kind}`;
    tr.dataset.stackEntryName = normalizeStackEntryName(v.name);

    const tdOff = document.createElement('td');
    tdOff.className = 'stack-col-offset';
    if (v.location) {
      tdOff.textContent = v.location;
    } else if (typeof v.offset === 'number') {
      const off = v.offset >= 0
        ? `+0x${v.offset.toString(16)}`
        : `-0x${Math.abs(v.offset).toString(16)}`;
      tdOff.textContent = `[rbp${off}]`;
    } else {
      tdOff.textContent = '—';
    }

    const tdName = document.createElement('td');
    tdName.className = 'stack-col-name';
    const nameButton = document.createElement('button');
    nameButton.type = 'button';
    nameButton.className = 'stack-entry-link';
    nameButton.textContent = v.name;
    nameButton.title = 'Clic: ouvrir dans le pseudo-C et surligner cette entrée';
    nameButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      applyStackEntryHighlight(v.name, { reveal: false });
      openDecompileForStackEntry(v.name);
    });
    tdName.appendChild(nameButton);
    if (v.source === 'dwarf') {
      const badge = document.createElement('span');
      badge.className = 'stack-dwarf';
      badge.textContent = ' (DWARF)';
      tdName.appendChild(badge);
    }

    const tdSize = document.createElement('td');
    tdSize.className = 'stack-col-size';
    tdSize.textContent = `${v.size}B`;

    const tdKind = document.createElement('td');
    tdKind.className = 'stack-col-kind';
    tdKind.textContent = kind === 'arg' && v.source === 'abi' ? 'arg(reg)' : kind;

    tr.append(tdOff, tdName, tdSize, tdKind);
    tr.addEventListener('click', () => applyStackEntryHighlight(v.name, { reveal: false }));
    tbody.appendChild(tr);
  };

  registerArgs.forEach(v => appendRow(v, 'arg'));
  stackArgs.forEach(v => appendRow(v, 'arg'));
  vars.forEach(v => appendRow(v, 'var'));

  table.appendChild(tbody);
  content.appendChild(table);
  applyStackEntryHighlight(stackUiState.pendingEntryName || stackUiState.activeEntryName);
}

// ── Binary Diff ─────────────────────────────────────────────────────────────
function _makePill(status, count, label) {
  const pill = document.createElement('span');
  pill.className = `bd-pill bd-pill-${status}`;
  const countEl = document.createElement('span');
  countEl.className = 'bd-pill-count';
  countEl.textContent = count;
  const labelEl = document.createElement('span');
  labelEl.className = 'bd-pill-label';
  labelEl.textContent = label;
  pill.appendChild(countEl);
  pill.appendChild(labelEl);
  return pill;
}

function renderBindiff(result) {
  const statsEl = document.getElementById('bindiffStats');
  const resultsEl = document.getElementById('bindiffResults');
  if (!statsEl || !resultsEl) return;

  while (resultsEl.firstChild) resultsEl.removeChild(resultsEl.firstChild);
  while (statsEl.firstChild) statsEl.removeChild(statsEl.firstChild);

  if (!result || !result.ok) {
    statsEl.hidden = true;
    const p = document.createElement('p');
    p.className = 'error-text';
    p.textContent = (result && result.error) ? result.error : 'Erreur inconnue';
    resultsEl.appendChild(p);
    return;
  }

  // Summary pills
  const s = result.stats || {};
  statsEl.hidden = false;

  // Overall similarity score
  const functions = result.functions || [];
  const totalFuncs = functions.length;
  let overallSim = 0;
  if (totalFuncs > 0) {
    const simSum = functions.reduce((acc, fn) => acc + (fn.similarity || 0), 0);
    overallSim = Math.round((simSum / totalFuncs) * 100);
  }
  const overallEl = document.createElement('div');
  overallEl.className = 'bd-overall-score';
  const overallPct = document.createElement('span');
  overallPct.className = 'bd-overall-pct';
  overallPct.textContent = overallSim + '%';
  overallPct.style.color = overallSim >= 80 ? 'var(--accent-blue-soft)' : overallSim >= 50 ? '#e2b93d' : '#f44747';
  const overallLabel = document.createElement('span');
  overallLabel.className = 'bd-overall-label';
  overallLabel.textContent = 'Similarité';
  overallEl.appendChild(overallPct);
  overallEl.appendChild(overallLabel);
  statsEl.appendChild(overallEl);

  statsEl.appendChild(_makePill('identical', s.identical || 0, 'identiques'));
  statsEl.appendChild(_makePill('modified', s.modified || 0, 'modifiées'));
  statsEl.appendChild(_makePill('added', s.added || 0, 'ajoutées'));
  statsEl.appendChild(_makePill('removed', s.removed || 0, 'supprimées'));
  if (functions.length === 0) {
    const p = document.createElement('p');
    p.className = 'placeholder-text';
    p.textContent = 'Aucune fonction trouvée.';
    resultsEl.appendChild(p);
    return;
  }

  // Sort: modified first, then added/removed, then identical
  const ORDER = { modified: 0, added: 1, removed: 2, identical: 3 };
  const sorted = [...functions].sort((a, b) => (ORDER[a.status] ?? 4) - (ORDER[b.status] ?? 4));

  sorted.forEach((fn) => {
    const row = document.createElement('div');
    row.className = 'bd-fn';
    const hasDiff = fn.diff && fn.diff.length > 0;

    // Header
    const header = document.createElement('div');
    header.className = 'bd-fn-header';
    if (hasDiff) header.setAttribute('data-expandable', '');

    const arrow = document.createElement('span');
    arrow.className = 'bd-fn-arrow';
    arrow.textContent = '▶';

    const name = document.createElement('span');
    name.className = 'bd-fn-name';
    name.textContent = fn.name || '(unknown)';

    // Similarity bar
    const simWrap = document.createElement('span');
    simWrap.className = 'bd-fn-sim';
    const simBar = document.createElement('span');
    simBar.className = 'bd-fn-sim-bar';
    const simFill = document.createElement('span');
    simFill.className = 'bd-fn-sim-fill';
    const pct = fn.similarity != null ? Math.round(fn.similarity * 100) : 0;
    simFill.style.width = pct + '%';
    simBar.appendChild(simFill);
    const simPct = document.createElement('span');
    simPct.className = 'bd-fn-sim-pct';
    simPct.textContent = pct + '%';
    simWrap.appendChild(simBar);
    simWrap.appendChild(simPct);

    // Badge
    const badge = document.createElement('span');
    badge.className = `bd-badge bd-badge-${fn.status}`;
    badge.textContent = fn.status;

    header.appendChild(arrow);
    header.appendChild(name);
    header.appendChild(simWrap);
    header.appendChild(badge);
    row.appendChild(header);

    // Diff lines
    if (hasDiff) {
      const diffEl = document.createElement('div');
      diffEl.className = 'bd-diff';
      diffEl.hidden = true;

      fn.diff.forEach((line) => {
        const lineEl = document.createElement('div');
        lineEl.className = `bd-diff-line bd-diff-line-${line.type}`;

        const gutter = document.createElement('span');
        gutter.className = 'bd-diff-gutter';
        gutter.textContent = line.type === 'added' ? '+' : line.type === 'removed' ? '−' : ' ';

        const code = document.createElement('span');
        code.className = 'bd-diff-code';
        code.textContent = line.asm;

        lineEl.appendChild(gutter);
        lineEl.appendChild(code);
        diffEl.appendChild(lineEl);
      });

      row.appendChild(diffEl);

      header.addEventListener('click', () => {
        const isOpen = row.hasAttribute('data-open');
        if (isOpen) {
          row.removeAttribute('data-open');
          diffEl.hidden = true;
        } else {
          row.setAttribute('data-open', '');
          diffEl.hidden = false;
        }
      });
    }

    resultsEl.appendChild(row);
  });
}

// ── Script panel ──────────────────────────────────────────────────
(function initScriptPanel() {
  const editor = document.getElementById('scriptEditor');
  const output = document.getElementById('scriptOutput');
  const status = document.getElementById('scriptStatus');
  const runBtn = document.getElementById('btnRunScript');
  const saveBtn = document.getElementById('btnSaveScript');
  const loadBtn = document.getElementById('btnLoadScript');
  const clearBtn = document.getElementById('btnClearScript');
  const splitter = document.getElementById('scriptSplitter');
  if (!editor) return;

  const saved = _loadStorage();
  if (saved.scriptCode) editor.value = saved.scriptCode;

  let _saveTimer;
  editor.addEventListener('input', () => {
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => _saveStorage({ scriptCode: editor.value }), 500);
  });

  function runScript() {
    const code = editor.value.trim();
    if (!code) return;
    runBtn.setAttribute('disabled', 'true');
    status.textContent = '⏳ Exécution…';
    output.textContent = '';
    output.className = 'sc-output';

    const binaryPath = document.querySelector('input[name="binaryPath"]')?.value || '';
    const b64 = btoa(unescape(encodeURIComponent(code)));
    vscode.postMessage({ type: 'hubRunScript', code: b64, binaryPath });
  }

  runBtn?.addEventListener('click', runScript);

  editor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runScript();
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = editor.selectionStart;
      editor.value = editor.value.substring(0, start) + '    ' + editor.value.substring(editor.selectionEnd);
      editor.selectionStart = editor.selectionEnd = start + 4;
    }
  });

  saveBtn?.addEventListener('click', () => {
    const name = prompt('Nom du script :', 'script.py');
    if (!name) return;
    vscode.postMessage({ type: 'hubSaveScript', name, content: editor.value });
  });

  loadBtn?.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubLoadScript' });
  });

  clearBtn?.addEventListener('click', () => {
    editor.value = '';
    output.textContent = '';
    output.className = 'sc-output';
    status.textContent = '';
    _saveStorage({ scriptCode: '' });
  });

  if (splitter) {
    const editorWrap = editor.closest('.sc-editor-wrap');
    const outputWrap = output.closest('.sc-output-wrap');
    let dragging = false;

    splitter.addEventListener('mousedown', (e) => {
      e.preventDefault();
      dragging = true;
      document.body.style.cursor = 'row-resize';
      document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging || !editorWrap || !outputWrap) return;
      const container = editorWrap.parentElement;
      const rect = container.getBoundingClientRect();
      const y = e.clientY - rect.top;
      const toolbarH = container.querySelector('.sc-toolbar')?.offsetHeight || 0;
      const splitterH = splitter.offsetHeight;
      const available = rect.height - toolbarH - splitterH;
      const editorH = Math.max(60, Math.min(available - 60, y - toolbarH));
      editorWrap.style.flex = 'none';
      editorWrap.style.height = editorH + 'px';
      outputWrap.style.flex = '1';
      _saveStorage({ scriptSplitH: editorH });
    });

    document.addEventListener('mouseup', () => {
      if (dragging) {
        dragging = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    });

    if (saved.scriptSplitH) {
      editorWrap.style.flex = 'none';
      editorWrap.style.height = saved.scriptSplitH + 'px';
    }
  }
})();

// Messages from extension
window.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg?.type) return;
  if (msg.type === 'showPanel' && msg.panel) {
    showPanel(msg.panel);
    if (msg.focusGoToAddr) {
      setTimeout(() => {
        const input = document.getElementById('goToAddrInput');
        if (input) { input.focus(); input.select(); }
      }, 300);
    }
    return;
  }
  if (msg.type === 'platformInfo') {
    currentPlatform = msg.platform || currentPlatform;
    setOption32Availability(document.getElementById('archBits'), msg.platform);
    setOption32Availability(document.getElementById('gccArch'), msg.platform);
    return;
  }
  if (msg.type === 'hubRulesPath' && msg.rulesPath) {
    const el = document.getElementById('yaraRulesPath');
    if (el) el.value = msg.rulesPath;
    return;
  }
  if (msg.type === 'hubOllamaModels') {
    setOllamaBusy(false);
    if (msg.error) {
      setOllamaStatus(msg.error, true);
      if (!ollamaUiState.models.length) renderOllamaModels([], '');
      return;
    }
    const models = Array.isArray(msg.models) ? msg.models : [];
    ollamaUiState.models = models;
    renderOllamaModels(models, ollamaUiState.lastModel);
    if (!models.length) {
      setOllamaStatus('Aucun modèle trouvé. Vérifie Ollama et le pull du modèle.', true);
      return;
    }
    const selected = getCurrentOllamaModel() || models[0];
    setOllamaStatus(`${models.length} modèle(s) détecté(s). Sélection active: ${selected}`);
    return;
  }
  if (msg.type === 'hubOllamaResult') {
    setOllamaBusy(false);
    if (!msg.ok) {
      setOllamaStatus(msg.error || 'Échec de la requête Ollama.', true);
      pushOllamaMessage('system', msg.error || 'Échec de la requête Ollama.');
      return;
    }
    if (msg.model) {
      ollamaUiState.lastModel = String(msg.model);
      _saveStorage({ ollamaModel: ollamaUiState.lastModel });
    }
    setOllamaStatus(`Réponse reçue (${msg.model || 'modèle inconnu'}).`);
    pushOllamaMessage('assistant', msg.output || '(Réponse vide)');
    return;
  }
  if (msg.type === 'hubAnnotations') {
    const annotations = msg.annotations || {};
    window._annotations = annotations;
    const listEl = document.getElementById('annotationsList');
    if (!listEl) {
      renderBookmarks();
      updateActiveContextBars(window._lastDisasmAddr);
      updateDisasmSessionSummary();
      return;
    }
    const entries = Object.entries(annotations).filter(([, v]) => v && (v.comment || v.name));
    if (entries.length === 0) {
      listEl.replaceChildren();
      const p = document.createElement('p');
      p.className = 'hint annotations-empty';
      p.textContent = 'Aucune annotation.';
      listEl.appendChild(p);
    } else {
      listEl.replaceChildren();
      entries.forEach(([addr, v]) => {
        const item = document.createElement('div');
        item.className = 'annotation-item';

        const addrCode = document.createElement('code');
        addrCode.className = 'addr-link';
        addrCode.dataset.addr = addr;
        addrCode.textContent = addr;
        item.appendChild(addrCode);

        const meta = document.createElement('div');
        meta.className = 'ann-meta';
        if (v.name) {
          const nameSpan = document.createElement('span');
          nameSpan.className = 'ann-name';
          nameSpan.textContent = '→ ' + v.name;
          meta.appendChild(nameSpan);
        }
        if (v.comment) {
          const cmtSpan = document.createElement('span');
          cmtSpan.className = 'ann-comment';
          cmtSpan.textContent = v.comment.length > 80 ? v.comment.substring(0, 80) + '…' : v.comment;
          cmtSpan.title = v.comment;
          meta.appendChild(cmtSpan);
        }
        item.appendChild(meta);

        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-sm ann-delete';
        delBtn.textContent = '×';
        delBtn.title = 'Supprimer cette annotation';
        delBtn.dataset.addr = addr;
        item.appendChild(delBtn);

        listEl.appendChild(item);
      });

      listEl.querySelectorAll('.addr-link').forEach((link) => {
        link.style.cursor = 'pointer';
        link.addEventListener('click', () => {
          const a = link.dataset.addr;
          document.getElementById('goToAddrInput').value = a;
          const badge = document.getElementById('annotationAddrBadge');
          if (badge) { badge.textContent = a; badge.dataset.addr = a; badge.classList.add('has-addr'); }
          const btn = document.getElementById('btnAddAnnotation');
          if (btn) btn.disabled = false;
          const ann = annotations[a];
          const commentEl = document.getElementById('annotationComment');
          if (commentEl) commentEl.value = ann?.comment || '';
          const nameEl = document.getElementById('annotationName');
          if (nameEl) nameEl.value = ann?.name || '';
          vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
        });
      });

      listEl.querySelectorAll('.ann-delete').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          vscode.postMessage({ type: 'hubDeleteAnnotation', binaryPath: getStaticBinaryPath(), addr: btn.dataset.addr });
        });
      });
    }
    renderBookmarks();
    updateActiveContextBars(window._lastDisasmAddr);
    updateDisasmSessionSummary();
    return;
  }
  if (msg.type === 'hubDisasmReady' && msg.binaryPath) {
    tabDataCache.disasm = { binaryPath: msg.binaryPath.trim() };
    return;
  }
  if (msg.type === 'hubSetBinaryPath' && msg.binaryPath) {
    const bp = msg.binaryPath.trim();
    const skipAutoLoad = msg.skipAutoLoad === true;
    const nextMeta = _normalizeBinaryMeta(msg.binaryMeta || getCurrentBinaryMeta());
    const prevBp = staticBinaryInput?.value?.trim();
    const prevMetaKey = JSON.stringify(getCurrentBinaryMeta() || null);
    const nextMetaKey = JSON.stringify(nextMeta || null);
    const sameSelection = prevBp === bp && prevMetaKey === nextMetaKey;
    if (!sameSelection) resetStaticBinaryDerivedState();
    applyStaticBinarySelectionUi(bp, nextMeta);
    if (sameSelection) {
      finalizeStaticBinarySelection(bp, nextMeta, { sameSelection: true, skipAutoLoad });
      return;
    }
    finalizeStaticBinarySelection(bp, nextMeta, { sameSelection: false, skipAutoLoad });
    return;
  }
  if (msg.type === 'initRunTrace') {
    applyRunTraceInit(msg);
    return;
  }
  if (msg.type === 'dynamicTraceHistory') {
    dynamicTraceHistoryState = {
      items: Array.isArray(msg.items) ? msg.items : [],
      activeTracePath: String(msg.activeTracePath || '').trim()
    };
    renderDynamicTraceHistory();
    if (!runBtn?.disabled) {
      setDynamicTraceStatus(binaryPathInput?.value?.trim() ? 'Prêt.' : 'Sélectionnez un binaire pour lancer la trace.');
    }
    return;
  }
  if (msg.type === 'runTraceDone') {
    if (runBtn) runBtn.disabled = false;
    setDynamicTraceStatus('Trace terminée.');
    requestDynamicTraceHistory();
    return;
  }
  if (msg.type === 'hubStaticCompileDone') {
    const btn = document.getElementById('btnCompileGcc');
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    return;
  }
  if (msg.type === 'symbols') {
    const sel = document.getElementById('startSymbol');
    if (!sel) return;
    const preferred = 'main';
    const syms = Array.isArray(msg.symbols) && msg.symbols.length ? msg.symbols : [preferred];
    const cur = sel.value;
    sel.innerHTML = '';
    syms.forEach((s) => {
      const o = document.createElement('option');
      o.value = s;
      o.textContent = s;
      if (s === cur) o.selected = true;
      sel.appendChild(o);
    });
    if (!syms.includes(cur) && syms.length) {
      sel.value = syms.includes(preferred) ? preferred : syms[0];
    }
    return;
  }
  if (msg.type === 'generatedFiles') {
    const data = msg.files;
    if (!data || typeof data !== 'object') return;
    const fmt = (n) => n >= 1024 * 1024 ? `${(n / (1024 * 1024)).toFixed(1)} Mo` : n >= 1024 ? `${(n / 1024).toFixed(1)} Ko` : `${n} o`;
    document.getElementById('filesStatTotal')?.replaceChildren(document.createTextNode(`${(data.artifacts?.length || 0) + (data.cache?.length || 0)} fichier(s)`));
    document.getElementById('filesStatSize')?.replaceChildren(document.createTextNode(fmt(data.totalSize || 0)));
    const staleEl = document.getElementById('filesStatStale');
    if (staleEl) {
      const n = data.staleCache?.length || 0;
      if (n > 0) staleEl.textContent = `${n} cache obsolète(s)`;
      else staleEl.textContent = '';
    }
    const artifactsEl = document.getElementById('filesArtifacts');
    if (artifactsEl) {
      const arts = data.artifacts || [];
      if (arts.length === 0) artifactsEl.innerHTML = '<p class="hint empty-state">Aucun artifact</p>';
      else artifactsEl.innerHTML = `<table class="data-table"><thead><tr><th>Fichier</th><th>Type</th><th>Binaire</th><th>Taille</th></tr></thead><tbody>${arts.map(a => `<tr><td><code>${escapeHtml(a.name)}</code></td><td>${escapeHtml(a.type)}</td><td>${escapeHtml(a.binary || '—')}</td><td>${fmt(a.size || 0)}</td></tr>`).join('')}</tbody></table>`;
    }
    const cacheEl = document.getElementById('filesCache');
    if (cacheEl) {
      const cache = data.cache || [];
      if (cache.length === 0) cacheEl.innerHTML = '<p class="hint empty-state">Aucune entrée de cache</p>';
      else cacheEl.innerHTML = `<table class="data-table"><thead><tr><th>Clé</th><th>Binaire</th><th>Statut</th><th>Taille</th></tr></thead><tbody>${cache.map(c => `<tr${!c.binaryExists ? ' class="cache-stale"' : ''}><td><code>${escapeHtml(c.key)}</code></td><td><code title="${escapeHtml(c.binaryPath)}">${escapeHtml((c.binaryPath || '').split(/[/\\]/).pop() || '—')}</code></td><td>${c.binaryExists ? '<span class="status-ok">OK</span>' : '<span class="status-stale">Obsolète</span>'}</td><td>${fmt(c.size || 0)}</td></tr>`).join('')}</tbody></table>`;
    }
    return;
  }
  // ── Import xrefs panel (inline sous importsContent) ─────────────────────
  function _showImportXrefsPanel(fnName, callsites, error) {
    let panel = document.getElementById('importXrefsPanel');
    if (!panel) {
      panel = document.createElement('div');
      panel.id = 'importXrefsPanel';
      panel.className = 'modern-card';
      panel.style.cssText = 'margin-top:10px;';
      const container = document.getElementById('importsContent');
      if (container) container.appendChild(panel);
    }
    panel.replaceChildren();

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px;';
    const title = document.createElement('span');
    title.className = 'section-label';
    title.textContent = `Xrefs → ${fnName || ''}`;
    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-sm';
    closeBtn.textContent = '✕';
    closeBtn.style.marginLeft = 'auto';
    closeBtn.addEventListener('click', () => panel.remove());
    header.append(title, closeBtn);
    panel.appendChild(header);

    if (!callsites) {
      // Loading state
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Recherche des callsites…';
      panel.appendChild(p);
      return;
    }
    if (error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = error;
      panel.appendChild(p);
      return;
    }
    if (callsites.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucun callsite trouvé (binaire strippé ou PLT non résolu).';
      panel.appendChild(p);
      return;
    }

    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hr = thead.insertRow();
    ['Adresse', 'Instruction'].forEach(t => {
      const th = document.createElement('th');
      th.textContent = t;
      hr.appendChild(th);
    });
    const tbody = table.createTBody();
    for (const cs of callsites) {
      const row = tbody.insertRow();
      row.className = 'nav-addr-row';
      row.dataset.addr = cs.addr || '';
      row.dataset.addrMatch = 'exact';
      const tdAddr = row.insertCell();
      const addrLink = document.createElement('a');
      addrLink.className = 'addr-link';
      addrLink.href = '#';
      addrLink.textContent = cs.addr || '?';
      addrLink.addEventListener('click', (e) => {
        e.preventDefault();
        const bp = getStaticBinaryPath();
        if (!bp) return;
        vscode.postMessage({ type: 'hubGoToAddress', binaryPath: bp, addr: cs.addr });
      });
      tdAddr.appendChild(addrLink);
      const tdText = row.insertCell();
      const code = document.createElement('code');
      code.style.fontSize = '11px';
      // Afficher la partie mnemonic + operands seulement (sans les bytes hex)
      const textParts = (cs.text || '').split(/\s{2,}/);
      code.textContent = textParts.length > 1 ? textParts.slice(1).join(' ').trim() : cs.text;
      tdText.appendChild(code);
    }
    panel.appendChild(table);
    updateActiveNavRows(window._lastDisasmAddr);
  }

  if (msg.type === 'hubImportsDone') {
    tabDataCache.imports = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('importsContent');
    if (!container) return;
    const data = msg.data || {};
    if (data.error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = data.error;
      container.replaceChildren(p);
      return;
    }

    const imports = data.imports || [];
    const suspicious = data.suspicious || [];
    const score = data.score ?? 0;
    const totalFns = imports.reduce((n, d) => n + (d.functions || []).length, 0);

    const _CAT_COLOR = {
      INJECTION: 'var(--accent-red)', SHELLCODE: 'var(--accent-red)',
      EXECUTION: 'var(--accent-orange)', ANTI_DEBUG: '#b48ead',
      NETWORK: '#88c0d0', EVASION: 'var(--accent-orange)',
      PERSISTENCE: 'var(--accent-orange)', CRYPTO: 'var(--accent-blue-soft)',
    };
    const root = document.createDocumentFragment();

    // ── Score bar ──────────────────────────────────────────────────────────
    const scoreCard = document.createElement('div');
    scoreCard.className = 'modern-card';
    scoreCard.style.cssText = 'margin-bottom:10px;display:flex;align-items:center;gap:12px';
    const scoreLabel = document.createElement('span');
    scoreLabel.className = 'hint';
    scoreLabel.textContent = 'Score de suspicion';
    const scoreVal = document.createElement('span');
    scoreVal.style.cssText = `font-size:18px;font-weight:700;color:${score >= 60 ? 'var(--accent-red)' : score >= 30 ? 'var(--accent-orange)' : 'var(--accent-blue-soft)'}`;
    scoreVal.textContent = `${score}/100`;
    const scoreDetail = document.createElement('span');
    scoreDetail.className = 'hint';
    scoreDetail.textContent = `${suspicious.length} import(s) suspect(s) sur ${totalFns}`;
    scoreCard.append(scoreLabel, scoreVal, scoreDetail);
    root.appendChild(scoreCard);

    if (imports.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucun import détecté (binaire statiquement lié ou strippé).';
      root.appendChild(p);
      container.replaceChildren(root);
      return;
    }

    // ── Imports suspects ───────────────────────────────────────────────────
    if (suspicious.length > 0) {
      const h = document.createElement('h4');
      h.className = 'section-label';
      h.style.margin = '10px 0 6px';
      h.textContent = 'Imports suspects';
      root.appendChild(h);

      const table = document.createElement('table');
      table.className = 'data-table';
      const thead = table.createTHead();
      const hr = thead.insertRow();
      ['Fonction', 'DLL', 'Catégorie', 'Description'].forEach(t => {
        const th = document.createElement('th');
        th.textContent = t;
        hr.appendChild(th);
      });
      const tbody = table.createTBody();
      for (const s of suspicious) {
        const row = tbody.insertRow();
        const tdFn = row.insertCell(); tdFn.appendChild(Object.assign(document.createElement('code'), { textContent: s.function }));
        const tdDll = row.insertCell(); tdDll.className = 'hint'; tdDll.textContent = s.dll;
        const tdCat = row.insertCell();
        const badge = document.createElement('span');
        badge.style.cssText = `color:${_CAT_COLOR[s.category] || 'var(--text-muted)'};font-weight:600;font-size:10px`;
        badge.textContent = s.category;
        tdCat.appendChild(badge);
        const tdDesc = row.insertCell(); tdDesc.style.fontSize = '11px'; tdDesc.textContent = s.description;
      }
      root.appendChild(table);
    }

    // ── Imports par DLL ────────────────────────────────────────────────────
    const h2 = document.createElement('h4');
    h2.className = 'section-label';
    h2.style.margin = '10px 0 6px';
    h2.textContent = `Tous les imports (${imports.length} DLL / bibliothèque(s))`;
    root.appendChild(h2);

    const suspSet = new Set(suspicious.map(s => s.function));
    for (const dll of imports) {
      const details = document.createElement('details');
      details.className = 'imports-dll-group';
      const summary = document.createElement('summary');
      const dllName = document.createElement('span');
      dllName.className = 'imports-dll-name';
      dllName.textContent = dll.dll;
      const dllCount = document.createElement('span');
      dllCount.className = 'imports-dll-count';
      dllCount.textContent = ` ${dll.count} fonction(s)`;
      summary.append(dllName, dllCount);
      details.appendChild(summary);
      const fnsDiv = document.createElement('div');
      fnsDiv.className = 'imports-dll-fns';
      for (const fn of (dll.functions || [])) {
        const btn = document.createElement('button');
        btn.className = 'imports-fn-btn' + (suspSet.has(fn) ? ' suspicious' : '');
        btn.textContent = fn;
        btn.title = 'Voir les callsites (xrefs)';
        btn.addEventListener('click', () => {
          const bp = getStaticBinaryPath();
          if (!bp) return;
          _showImportXrefsPanel(fn);
          vscode.postMessage({ type: 'hubLoadImportXrefs', binaryPath: bp, fnName: fn });
        });
        fnsDiv.appendChild(btn);
      }
      details.appendChild(fnsDiv);
      root.appendChild(details);
    }

    container.replaceChildren(root);
    return;
  }
  if (msg.type === 'hubExportsDone') {
    const container = document.getElementById('exportsContent');
    if (!container) return;
    const data = msg.data || {};
    container.replaceChildren();
    const hdr = document.createElement('div');
    hdr.className = 'section-label';
    hdr.style.cssText = 'margin-bottom:8px;';
    hdr.textContent = `Exports (${data.count ?? 0})`;
    container.appendChild(hdr);
    if (data.error) {
      const p = document.createElement('p'); p.className = 'hint error'; p.textContent = data.error;
      container.appendChild(p); return;
    }
    const exports = data.exports || [];
    if (exports.length === 0) {
      const p = document.createElement('p'); p.className = 'hint'; p.textContent = 'Aucun export trouvé.';
      container.appendChild(p); return;
    }
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hr = thead.insertRow();
    ['Adresse', 'Nom', 'Type'].forEach(t => {
      const th = document.createElement('th'); th.textContent = t; hr.appendChild(th);
    });
    const tbody = table.createTBody();
    for (const exp of exports) {
      const row = tbody.insertRow();
      row.className = 'nav-addr-row';
      row.dataset.addr = exp.addr || '';
      row.dataset.addrMatch = 'function';
      const tdAddr = row.insertCell();
      const addrLink = document.createElement('a');
      addrLink.className = 'addr-link'; addrLink.href = '#';
      addrLink.textContent = exp.addr || '?';
      addrLink.title = 'Aller au désassemblage';
      addrLink.addEventListener('click', (e) => {
        e.preventDefault();
        const bp = getStaticBinaryPath();
        if (bp) { vscode.postMessage({ type: 'hubGoToAddress', addr: exp.addr, binaryPath: bp }); }
      });
      tdAddr.appendChild(addrLink);
      const tdName = row.insertCell();
      tdName.style.fontFamily = 'var(--font-mono)';
      tdName.style.fontSize = '11px';
      if (exp.demangled) {
        const span = document.createElement('span');
        span.textContent = exp.demangled;
        span.title = exp.name;
        tdName.appendChild(span);
        const raw = document.createElement('span');
        raw.className = 'hint'; raw.style.marginLeft = '6px'; raw.textContent = `(${exp.name})`;
        tdName.appendChild(raw);
      } else {
        tdName.textContent = exp.name || '?';
      }
      const tdType = row.insertCell();
      const badge = document.createElement('span');
      badge.className = `imports-cat-badge imports-cat-${exp.type === 'data' ? 'data' : 'function'}`;
      badge.textContent = exp.type || 'fn';
      tdType.appendChild(badge);
      if (exp.ordinal != null) {
        const ord = document.createElement('span');
        ord.className = 'hint'; ord.style.marginLeft = '6px'; ord.textContent = `#${exp.ordinal}`;
        tdType.appendChild(ord);
      }
    }
    container.appendChild(table);
    updateActiveNavRows(window._lastDisasmAddr);
    return;
  }
  if (msg.type === 'hubImportXrefsDone') {
    const data = msg.data || {};
    _showImportXrefsPanel(data.function, data.callsites || [], data.error);
    return;
  }
  if (msg.type === 'hubSymbols') {
    tabDataCache.symbols = { binaryPath: getStaticBinaryPath() };
    const syms = msg.symbols || [];
    window.symbolsCache = syms;
    const navSel = document.getElementById('navSymbolSelect');
    if (navSel) {
      const cur = navSel.value;
      navSel.innerHTML = '<option value="">Autre symbole…</option>' +
        syms.filter(s => s.type === 'F' || s.type === 'T' || s.type === 'f' || s.type === 't')
          .slice(0, 50)
          .map(s => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} @ ${escapeHtml(s.addr)}</option>`).join('');
      if (cur && syms.some(s => s.name === cur)) navSel.value = cur;
    }
    const container = document.getElementById('symbolsContent');
    if (!container) return;
    const rows = syms.map(s => {
      const addrNum = parseInt((s.addr || '').trim(), 16);
      const isNavigable = !isNaN(addrNum) && addrNum > 0x1000;
      const addrCell = isNavigable
        ? `<code class="addr-link" data-addr="${escapeHtml(s.addr)}" style="cursor:pointer">${escapeHtml(s.addr)}</code>`
        : `<code class="addr-dim">${escapeHtml(s.addr)}</code>`;
      return `<tr class="nav-addr-row" data-addr="${escapeHtml(s.addr)}" data-addr-match="function"><td>${addrCell}</td><td>${escapeHtml(s.type)}</td><td><code>${escapeHtml(s.name)}</code></td></tr>`;
    }).join('');
    container.innerHTML = `<table class="data-table"><thead><tr><th>Adresse</th><th>Type</th><th>Nom</th></tr></thead><tbody>${rows}</tbody></table><p class="hint">Clic sur une adresse → aller au désassemblage.</p>`;
    container.querySelectorAll('.addr-link').forEach(el => {
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => { const a = el.dataset.addr; if (a) vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() }); });
    });
    updateActiveNavRows(window._lastDisasmAddr);
    populateDecompileSelect(syms);
    updateActiveContextBars(window._lastDisasmAddr);
    if (isStaticTabActive('decompile')) {
      const selectedAddr = document.getElementById('decompileAddrSelect')?.value || '';
      if ((decompileUiState.renderedAddr || '') !== selectedAddr) requestDecompileForCurrentSelection();
    }
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    return;
  }
  if (msg.type === 'hubStrings') {
    tabDataCache.strings = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('stringsContent');
    if (!container) return;
    const allStrings = msg.strings || [];
    stringsCache = allStrings;
    renderStringsTable(container, allStrings, '', false);

    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    return;
  }
  if (msg.type === 'hubPayloadHex') {
    const el = document.getElementById('payloadHexResult');
    const countEl = document.getElementById('payloadByteCount');
    if (el) {
      el.textContent = msg.error || msg.hex || '—';
      el.classList.toggle('error', !!msg.error);
    }
    if (countEl && msg.hex && !msg.error) {
      const len = msg.hex.length / 2;
      countEl.textContent = `(${len} octet${len > 1 ? 's' : ''})`;
    } else if (countEl) countEl.textContent = '';
    return;
  }
  if (msg.type === 'hubAutoFromCmpResult') {
    const hint = document.getElementById('exploitAutoHint');
    if (msg.error) {
      if (hint) hint.textContent = `Auto CMP: ${msg.error}`;
      vscode.postMessage({ type: 'hubError', message: msg.error });
      return;
    }

    const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
    const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
    const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
    const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';

    if (typeof msg.padding === 'number' && Number.isFinite(msg.padding) && msg.padding > 0) {
      const exploitBufferSize = document.getElementById('exploitBufferSize');
      if (exploitBufferSize) exploitBufferSize.value = String(msg.padding);
    }
    if (typeof msg.suffix === 'string' && msg.suffix.length > 0) {
      const suffixInput = document.getElementById('exploitPayloadSuffix');
      if (suffixInput) suffixInput.value = msg.suffix;
    }

    const payloadExpr = String(msg.payloadExpr || '').trim();
    if (!payloadExpr) {
      if (hint) hint.textContent = 'Auto CMP: payload non généré.';
      return;
    }

    applyDynamicPreset({
      startSymbol,
      targetSymbol,
      payloadExpr,
      payloadTarget,
      maxSteps,
      suggestedOffset: msg.captureBufferOffset ?? -96,
      suggestedCaptureSize: msg.captureBufferSize ?? 128,
      binaryPath: getStaticBinaryPath()
    });

    if (hint) {
      const details = [];
      if (typeof msg.bufferOffset === 'number') details.push(`buffer=${msg.bufferOffset}`);
      if (typeof msg.varOffset === 'number') details.push(`cmpVar=${msg.varOffset}`);
      if (typeof msg.padding === 'number') details.push(`padding=${msg.padding}`);
      hint.textContent = `Auto CMP OK: ${payloadExpr}${details.length ? ` (${details.join(', ')})` : ''}`;
    }
    return;
  }
  if (msg.type === 'hubXrefs') {
    const el = document.getElementById('xrefsResult');
    const contentEl = document.getElementById('xrefsResultContent');
    if (!el) return;
    const refs = msg.refs || [];
    const targets = msg.targets || [];
    const addr = msg.addr || '';
    const mode = msg.mode || 'to';
    const hasError = msg.error;
    window.xrefsCache = { refs, targets, addr, mode };
    el.style.display = 'block';
    el.classList.add('xrefs-panel-visible');
    const target = contentEl || el;
    const makeAddrLink = (a) => {
      return `<code class="addr-link" data-addr="${escapeHtml(a)}">${escapeHtml(a)}</code>`;
    };
    const makeJumpButton = (a, label = 'Ouvrir') => {
      return `<button type="button" class="xrefs-jump-btn" data-addr="${escapeHtml(a)}">${escapeHtml(label)}</button>`;
    };
    const renderStackHints = (hints) => {
      if (!Array.isArray(hints) || hints.length === 0) return '';
      const chips = hints.map(h => {
        const label = `${h.kind === 'arg' ? 'arg' : 'var'} ${h.name}`;
        const title = h.location ? `${label} @ ${h.location}` : label;
        return `<span class="xref-stack-chip" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
      }).join('');
      return `<div class="xref-stack-hints">${chips}</div>`;
    };
    const renderTypedStructHints = (hints) => {
      if (!Array.isArray(hints) || hints.length === 0) return '';
      const chips = hints.map((hint) => {
        const label = hint.label || hint.addr || 'type';
        const typeKind = hint.struct_kind || hint.kind || 'struct';
        const title = [
          hint.struct_name ? `${typeKind} ${hint.struct_name}` : null,
          hint.field_name ? `champ ${hint.field_name}` : null,
          hint.field_type || null,
          hint.addr || null,
        ].filter(Boolean).join(' • ');
        return `<span class="xref-stack-chip" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
      }).join('');
      return `<div class="xref-stack-hints">${chips}</div>`;
    };
    const bindAddrLinks = () => {
      target.querySelectorAll('.addr-link, .xrefs-jump-btn').forEach(link => {
        link.style.cursor = 'pointer';
        link.addEventListener('click', () => {
          const a = link.dataset.addr;
          if (a) {
            document.getElementById('goToAddrInput').value = a;
            const badge = document.getElementById('annotationAddrBadge');
            if (badge) { badge.textContent = a; badge.dataset.addr = a; badge.classList.add('has-addr'); }
            const btn = document.getElementById('btnAddAnnotation');
            if (btn) btn.disabled = false;
            vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
          }
        });
      });
    };
    if (hasError) {
      target.innerHTML = `<p class="xrefs-msg xrefs-error">${escapeHtml(hasError)}</p>`;
    } else if (mode === 'from') {
      if (targets.length === 0) {
        target.innerHTML = `<p class="xrefs-msg">L'instruction à ${escapeHtml(addr)} ne référence aucune adresse (pas de jmp/call).</p>`;
      } else {
        const targetLinks = targets.map(t => makeAddrLink(t)).join(', ');
        const source = msg.source || null;
        const sourceMeta = source
          ? `<div class="xrefs-source-card">
              <div class="xrefs-source-head">
                <span class="xrefs-source-title">Source</span>
                ${source.function_name ? `<span class="xrefs-source-fn">${escapeHtml(source.function_name)}</span>` : ''}
                ${source.function_addr ? `<code>${escapeHtml(source.function_addr)}</code>` : ''}
              </div>
              <code class="xrefs-source-instr">${escapeHtml(source.text || '')}</code>
              ${renderStackHints(source.stack_hints)}
              ${renderTypedStructHints(source.typed_struct_hints)}
            </div>`
          : '';
        target.innerHTML = `
          <div class="xrefs-summary">
            <p class="xrefs-title">Références depuis ${escapeHtml(addr)}</p>
            <span class="xrefs-summary-count">${targets.length} cible${targets.length > 1 ? 's' : ''}</span>
          </div>
          <p class="xrefs-explain">Lecture : l'instruction sélectionnée pointe vers les adresses ci-dessous. Clique une cible pour ouvrir le désassemblage à cet endroit.</p>
          ${sourceMeta}
          <p class="xrefs-targets">Cible(s) : ${targetLinks}</p>`;
        bindAddrLinks();
      }
    } else {
      if (refs.length === 0) {
        target.innerHTML = `<p class="xrefs-msg">Aucune instruction (jmp/call) ne cible directement ${escapeHtml(addr)}. Essayez "Xrefs depuis" pour voir ce que cette adresse référence.</p>`;
      } else {
        const rows = refs.map(r => {
          const fnCell = r.function_name
            ? `<div class="xref-function-name">${escapeHtml(r.function_name)}</div>${r.function_addr ? `<code class="xref-function-addr">${escapeHtml(r.function_addr)}</code>` : ''}`
            : '—';
          const instr = `<code>${escapeHtml((r.text || '').substring(0, 90))}</code>${renderStackHints(r.stack_hints)}${renderTypedStructHints(r.typed_struct_hints)}`;
          return `<tr><td>${makeAddrLink(r.from_addr)}</td><td>${fnCell}</td><td><span class="xref-type xref-${r.type}">${escapeHtml(r.type)}</span></td><td>${instr}</td><td class="xrefs-action-cell">${makeJumpButton(r.from_addr, 'Aller au call')}</td></tr>`;
        }).join('');
        target.innerHTML = `
          <div class="xrefs-summary">
            <p class="xrefs-title">Références vers ${escapeHtml(addr)}</p>
            <span class="xrefs-summary-count">${refs.length} callsite${refs.length > 1 ? 's' : ''}</span>
          </div>
          <p class="xrefs-explain">Lecture : l'adresse demandée est ciblée par les instructions listées. Dans ton exemple, les deux lignes <code>call 0x100004059</code> appellent cette même destination.</p>
          <div class="xrefs-table-wrap">
            <table class="data-table">
              <thead><tr><th>Depuis</th><th>Fonction</th><th>Type</th><th>Instruction</th><th>Action</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>`;
        bindAddrLinks();
      }
    }
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    return;
  }
  if (msg.type === 'hubBinaryInfo') {
    tabDataCache.info = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('infoContent');
    if (!container) return;
    const info = msg.info || {};
    if (info.error) {
      container.innerHTML = `<p class="hint error">${escapeHtml(info.error)}</p>`;
    } else {
      window.lastBinaryArch = info.arch || '';
      updateTopBarBinaryDisplay(getStaticBinaryPath(), getCurrentBinaryMeta(), info);
      const rows = [
        ['Format', info.format || '—'],
        ['Machine', info.machine || '—'],
        ['Entry point', info.entry || '—'],
        ['Type', info.type || '—'],
        ['Bits', info.bits ? info.bits + '-bit' : '—'],
        ['Endianness', info.endianness || '—'],
        ['Stripped', info.stripped || '—'],
        ['Packers', info.packers || '—'],
        ['Arch (objdump)', info.arch || '—'],
        ['Interp', info.interp || '—']
      ].map(([k, v]) => `<div class="info-row"><span class="info-key">${escapeHtml(k)}</span><span class="info-val">${escapeHtml(String(v))}</span></div>`).join('');
      container.innerHTML = `<div class="info-grid">${rows}</div>`;
    }
    updateDisasmSessionSummary();
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    return;
  }
  if (msg.type === 'hubSections') {
    tabDataCache.sections = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('sectionsContent');
    const secs = msg.sections || [];
    window.sectionsCache = secs;
    const err = msg.error;
    const bp = getStaticBinaryPath();

    // Mettre à jour le dropdown Section dans l'onglet Désassemblage
    const disasmSectionSel = document.getElementById('disasmSection');
    if (disasmSectionSel) {
      const cur = disasmSectionSel.value;
      disasmSectionSel.innerHTML = '<option value="">Toutes</option>' +
        secs.map(s => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} (${s.type || ''})</option>`).join('');
      if (cur && secs.some(s => s.name === cur)) disasmSectionSel.value = cur;
    }
    updateActiveContextBars(window._lastDisasmAddr);
    updateDisasmSessionSummary();

    if (!container) return;
    if (err) {
      container.innerHTML = `<p class="hint error">${escapeHtml(err)}</p>`;
    } else {
      const rows = secs.map(s => {
        const secName = escapeHtml(s.name);
        return `<tr class="section-row" data-section="${escapeHtml(s.name)}"><td>${s.idx}</td><td><code>${secName}</code></td><td><code>${escapeHtml(s.size_hex || s.size)}</code></td><td><code>${escapeHtml(s.vma_hex || s.vma)}</code></td><td>${escapeHtml(s.type || '')}</td></tr>`;
      }).join('');
      container.innerHTML = `<table class="data-table"><thead><tr><th>Idx</th><th>Nom</th><th>Taille</th><th>VMA</th><th>Type</th></tr></thead><tbody>${rows}</tbody></table><p class="hint">Clic sur une section → désassembler cette section (fichier séparé). Le désasm complet reste intact. ${secs.length} section(s).</p>`;
      container.querySelectorAll('.section-row').forEach((tr) => {
        tr.addEventListener('click', () => {
          const sec = tr.dataset.section;
          if (sec && bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, section: sec });
        });
      });
    }
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    return;
  }
  if (msg.type === 'hubCfg') {
    tabDataCache.cfg = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('cfgContent');
    if (!container) return;
    const currentBinaryPath = getStaticBinaryPath() || '';
    const cfgState = getGraphUiState('cfg', currentBinaryPath);
    const cfg = msg.cfg || { blocks: [], edges: [] };
    const blocks = cfg.blocks || [];
    const edges = cfg.edges || [];
    const isolateFocus = blocks.some((block) => block.addr === cfgState.isolateAddr) ? cfgState.isolateAddr : '';
    if (!isolateFocus) cfgState.isolateAddr = '';
    const isolateRadius = Number.isFinite(Number(cfgState.isolateRadius)) ? Number(cfgState.isolateRadius) : 1;
    const visibleAddrs = isolateFocus ? collectGraphNeighborhood(isolateFocus, edges, isolateRadius) : null;
    if (blocks.length === 0) {
      const bp = getStaticBinaryPath();
      const hint = bp ? 'Aucun bloc détecté. Ouvrez le désassemblage puis rechargez.' : 'Ouvrez d\'abord le désassemblage.';
      container.innerHTML = `<p class="hint">${hint}</p>
        <button type="button" class="btn btn-primary" id="btnCfgOpenDisasm">Ouvrir le désassemblage</button>`;
      document.getElementById('btnCfgOpenDisasm')?.addEventListener('click', () => {
        if (bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: false });
        else vscode.postMessage({ type: 'requestBinarySelection' });
      });
      return;
    }
    // Table view — build with DOM API (no innerHTML with variables)
    const adj2 = window.cfgHelpers.buildAdjacency(edges);
    const tableEl = document.createElement('div');
    tableEl.className = 'cfg-table-view';
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hrow = thead.insertRow();
    ['Bloc', 'Instr.', 'Suivants', 'Première instr.'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    const tbody = table.createTBody();
    const rowEls = {};
    blocks.forEach(b => {
      const succs = (adj2[b.addr] || []).map(e => `${e.type}: ${e.to}`).join(', ') || '\u2014';
      const firstInstr = formatCfgLineDisplay((b.lines || [])[0], 82) || '';
      const row = tbody.insertRow();
      row.dataset.blockAddr = b.addr;
      rowEls[b.addr] = row;
      const td1 = row.insertCell();
      const addrCode = document.createElement('code');
      addrCode.className = 'addr-link';
      addrCode.dataset.addr = b.addr;
      addrCode.textContent = b.addr;
      addrCode.style.cursor = 'pointer';
      addrCode.addEventListener('click', (ev) => {
        ev.stopPropagation();
        syncCfgActiveAddress(b.addr, { reveal: isStaticTabActive('cfg') });
        vscode.postMessage({ type: 'hubGoToAddress', addr: b.addr, binaryPath: getStaticBinaryPath() });
      });
      td1.appendChild(addrCode);
      const incomingCaseSummary = summarizeSwitchCaseLabels(b.incoming_case_labels || [], { max: 2 });
      if (incomingCaseSummary) {
        const badge = document.createElement('span');
        badge.className = 'cfg-case-badge-inline';
        badge.textContent = incomingCaseSummary;
        badge.title = summarizeSwitchCaseLabels(b.incoming_case_labels || [], { max: 12 });
        td1.appendChild(document.createTextNode(' '));
        td1.appendChild(badge);
      }
      row.insertCell().textContent = (b.lines || []).length;
      const td3 = row.insertCell();
      const succsCode = document.createElement('code');
      succsCode.textContent = succs;
      td3.appendChild(succsCode);
      const td4 = row.insertCell();
      td4.title = firstInstr;
      td4.textContent = firstInstr + (firstInstr.length >= 50 ? '\u2026' : '');
    });
    const hintP = document.createElement('p');
    hintP.className = 'hint';
    hintP.textContent = `${blocks.length} bloc(s) \u2014 Clic sur une adresse \u2192 aller au d\u00e9sassemblage.`;
    tableEl.appendChild(table);
    tableEl.appendChild(hintP);
    // Graph view using renderGraphSvg
    const zoomState = { scale: 1 };
    const graphBlocks = visibleAddrs ? blocks.filter((b) => visibleAddrs.has(b.addr)) : blocks;
    const graphEdges = visibleAddrs ? edges.filter((e) => visibleAddrs.has(e.from) && visibleAddrs.has(e.to)) : edges;
    const svgNodes = graphBlocks.map(b => ({
      addr: b.addr,
      label: window._annotations?.[b.addr]?.name || undefined,
      sublabel: `${(b.lines || []).length} instr.`,
      lines: b.lines,
      caseLabels: b.incoming_case_labels || [],
    }));
    const rerenderCfgGraph = () => {
      if (getStaticBinaryPath() === currentBinaryPath) vscode.postMessage({ type: 'hubLoadCfg', binaryPath: currentBinaryPath });
    };
    const svgEl = renderGraphSvg(svgNodes, graphEdges, {
      zoomState,
      padX: 56,
      padY: 52,
      lanePadX: 32,
      maxPerRow: 4,
      expandedAddrs: cfgState.expandedAddrs,
      onExpandedChange: (addrs) => { cfgState.expandedAddrs = addrs; },
      onNodeIsolate: (addr) => {
        cfgState.isolateAddr = addr;
        cfgState.isolateRadius = cfgState.isolateRadius ?? 1;
        rerenderCfgGraph();
      },
      onNodeClick: (addr) => vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() }),
    });
    // Build graph wrapper with DOM API
    const graphEl = document.createElement('div');
    graphEl.className = 'cfg-graph-view';
    const svgWrap = document.createElement('div');
    svgWrap.className = 'cfg-svg-wrap';
    const legendDiv = document.createElement('div');
    legendDiv.className = 'cfg-legend';
    const legendItems = [
      ['#88d8ff', 'solid', 'Fallthrough', 'Encha\u00eenement s\u00e9quentiel vers le bloc suivant'],
      ['#b48ead', 'solid', 'Jmp', 'Saut conditionnel ou inconditionnel (jmp, je, jne\u2026)'],
      ['#88c0d0', 'solid', 'Call', 'Appel de fonction (call)'],
      ['#d08770', 'dashed', 'Boucle', 'Back-edge : retour vers un bloc pr\u00e9c\u00e9dent (boucle)'],
    ];
    legendItems.forEach(([color, style, label, desc]) => {
      const item = document.createElement('span');
      item.className = 'cfg-legend-item';
      item.title = desc;
      const swatch = document.createElement('span');
      swatch.className = 'cfg-legend-swatch';
      swatch.style.background = color;
      if (style === 'dashed') swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 5px, transparent 5px 8px)`;
      item.appendChild(swatch);
      const txt = document.createTextNode(label);
      item.appendChild(txt);
      legendDiv.appendChild(item);
    });
    const isolateControls = document.createElement('span');
    isolateControls.className = 'cfg-isolate-controls';
    const isolateLabel = document.createElement('span');
    isolateLabel.className = 'cfg-legend-hint';
    isolateLabel.textContent = isolateFocus
      ? `Isolé: ${isolateFocus} (${graphBlocks.length}/${blocks.length})`
      : 'Alt+clic/clic droit: isoler';
    isolateControls.appendChild(isolateLabel);
    [1, 2].forEach((radius) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-xs btn-secondary';
      btn.textContent = `±${radius}`;
      btn.disabled = !isolateFocus;
      if (isolateFocus && isolateRadius === radius) btn.classList.add('active');
      btn.addEventListener('click', () => {
        if (!isolateFocus) return;
        cfgState.isolateRadius = radius;
        rerenderCfgGraph();
      });
      isolateControls.appendChild(btn);
    });
    const allBtn = document.createElement('button');
    allBtn.type = 'button';
    allBtn.className = 'btn btn-xs btn-secondary';
    allBtn.textContent = 'Tout';
    allBtn.disabled = !isolateFocus;
    allBtn.addEventListener('click', () => {
      cfgState.isolateAddr = '';
      cfgState.isolateRadius = 1;
      rerenderCfgGraph();
    });
    isolateControls.appendChild(allBtn);
    legendDiv.appendChild(isolateControls);
    const hintSpan = document.createElement('span');
    hintSpan.className = 'cfg-legend-hint';
    hintSpan.textContent = 'Molette: zoom \u2014 Drag n\u0153ud \u2014 Shift+clic: chemin \u2014 Double-clic: plus/moins de code';
    legendDiv.appendChild(hintSpan);
    const zoomWrap = document.createElement('div');
    zoomWrap.className = 'cfg-svg-zoom';
    const innerWrap = document.createElement('div');
    innerWrap.className = 'cfg-svg-inner';
    innerWrap.appendChild(svgEl);
    zoomWrap.appendChild(innerWrap);
    svgWrap.appendChild(legendDiv);
    svgWrap.appendChild(zoomWrap);
    graphEl.appendChild(svgWrap);
    if (svgEl._tooltip) graphEl.appendChild(svgEl._tooltip);
    // Assemble and wire up
    tableEl.style.display = 'none';
    container.replaceChildren(tableEl, graphEl);
    let activeCfgBlockAddr = null;
    let zs = null;

    function findCfgBlockAddr(addr) {
      const normalized = normalizeHexAddress(addr);
      if (!normalized) return null;
      for (const block of blocks) {
        if (normalizeHexAddress(block.addr) === normalized) return block.addr;
        if ((block.lines || []).some((ln) => normalizeHexAddress(ln.addr) === normalized)) return block.addr;
      }
      return null;
    }

    function updateCfgSearchFilter() {
      const rawQuery = String(document.getElementById('cfgSearchInput')?.value || '');
      const q = rawQuery.toLowerCase();
      cfgState.search = rawQuery;
      svgEl.querySelectorAll('.cfg-node').forEach((g) => {
        const addr = (g.dataset.addr || '').toLowerCase();
        const text = (g.textContent || '').toLowerCase();
        const isActive = g.classList.contains('is-active');
        g.style.opacity = (!q || addr.includes(q) || text.includes(q) || isActive) ? '1' : '0.15';
      });
    }

    function setCfgActiveAddr(addr, opts = {}) {
      const blockAddr = findCfgBlockAddr(addr);
      container._cfgState = container._cfgState || {};
      container._cfgState.activeAddr = addr || '';
      cfgState.activeAddr = addr || '';
      if (activeCfgBlockAddr && rowEls[activeCfgBlockAddr]) rowEls[activeCfgBlockAddr].classList.remove('cfg-row-active');
      activeCfgBlockAddr = blockAddr;
      if (activeCfgBlockAddr && rowEls[activeCfgBlockAddr]) {
        rowEls[activeCfgBlockAddr].classList.add('cfg-row-active');
        if (opts.revealTable && tableEl.style.display !== 'none') {
          rowEls[activeCfgBlockAddr].scrollIntoView({ block: 'center', behavior: opts.instant ? 'auto' : 'smooth' });
        }
      }
      const nodeAddr = svgEl._setActiveAddress ? svgEl._setActiveAddress(addr) : null;
      updateCfgSearchFilter();
      if (nodeAddr && opts.reveal && graphEl.style.display !== 'none' && zs?.centerOnBox && svgEl._getNodeBox) {
        const box = svgEl._getNodeBox(nodeAddr);
        if (box) zs.centerOnBox(box, { minScale: 0.75, maxScale: 1.1 });
      }
      return blockAddr;
    }

    container._cfgState = {
      activeAddr: cfgState.activeAddr || window._lastDisasmAddr || '',
      setActiveAddr: setCfgActiveAddr,
    };

    const viewToggle = container.closest('.static-panel')?.querySelectorAll('input[name="cfgView"]');
    const showTable = () => {
      cfgState.viewMode = 'table';
      _saveStorage({ cfgViewMode: 'table' });
      tableEl.style.display = '';
      graphEl.style.display = 'none';
      if (container._cfgState?.activeAddr) setCfgActiveAddr(container._cfgState.activeAddr, { revealTable: true, instant: true });
    };
    const showGraph = () => {
      cfgState.viewMode = 'graph';
      _saveStorage({ cfgViewMode: 'graph' });
      tableEl.style.display = 'none';
      graphEl.style.display = '';
      const restoreView = cfgState.graphView && zs?.setViewState;
      if (restoreView) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => zs.setViewState(cfgState.graphView));
        });
      } else {
        requestGraphFit(graphEl);
      }
      if (container._cfgState?.activeAddr) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => setCfgActiveAddr(container._cfgState.activeAddr, { reveal: !restoreView, instant: true }));
        });
      }
    };
    viewToggle?.forEach((input) => {
      input.addEventListener('change', () => { (input.value === 'table' ? showTable : showGraph)(); });
    });
    zs = initCfgZoom(zoomWrap);
    if (zs) {
      Object.assign(zoomState, zs);
      zs.onChange = (view) => { cfgState.graphView = view; };
    }
    // Search filter
    const cfgSearchInput = document.getElementById('cfgSearchInput');
    if (cfgSearchInput) {
      cfgSearchInput.value = cfgState.search || '';
      cfgSearchInput.addEventListener('input', () => {
        _saveStorage({ cfgSearch: cfgSearchInput.value || '' });
        updateCfgSearchFilter();
      });
    }
    const preferredCfgView = container.closest('.static-panel')?.querySelector(`input[name="cfgView"][value="${cfgState.viewMode === 'table' ? 'table' : 'graph'}"]`);
    if (preferredCfgView) preferredCfgView.checked = true;
    if (cfgState.viewMode === 'table') showTable();
    else showGraph();
    updateCfgSearchFilter();
    // Fit button + auto-fit on first render
    const btnCfgFit = document.getElementById('btnCfgFit');
    if (btnCfgFit && zs) {
      btnCfgFit.addEventListener('click', () => zs.fitToView());
    }
    if (zs?.requestFit) zs.requestFit();
    if (container._cfgState?.activeAddr) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setCfgActiveAddr(container._cfgState.activeAddr, { reveal: isStaticTabActive('cfg'), instant: true }));
      });
    }
    return;
  }
  if (msg.type === 'hubCallGraph') {
    tabDataCache.callgraph = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('callgraphContent');
    if (!container) return;
    const currentBinaryPath = getStaticBinaryPath() || '';
    const cgState = getGraphUiState('callgraph', currentBinaryPath);
    const cg = msg.callGraph || { nodes: [], edges: [] };
    const cgEdges = cg.edges || [];
    const cgNodes = cg.nodes || [];
    if (cgEdges.length === 0 && cgNodes.length === 0) {
      const bp = getStaticBinaryPath();
      const hint = bp ? 'Aucun appel détecté. Ouvrez le désassemblage puis rechargez.' : 'Ouvrez d\'abord le désassemblage.';
      const btnHtml = bp ? '' : `<button type="button" class="btn btn-primary" id="btnCgOpenDisasm">Ouvrir le désassemblage</button>`;
      container.innerHTML = `<p class="hint">${hint}</p>${btnHtml}`;
      document.getElementById('btnCgOpenDisasm')?.addEventListener('click', () => {
        if (bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: false });
        else vscode.postMessage({ type: 'requestBinarySelection' });
      });
      return;
    }
    // Build unique node list from edges, with is_external info
    const nodeMap = {};
    const extSet = new Set();
    cgNodes.forEach(n => {
      const annName = window._annotations?.[n.addr]?.name;
      nodeMap[n.addr] = annName || n.name || n.addr;
      if (n.is_external) extSet.add(n.addr);
    });
    cgEdges.forEach(e => {
      if (!nodeMap[e.from]) nodeMap[e.from] = e.from_name || e.from;
      if (!nodeMap[e.to]) nodeMap[e.to] = e.to_name || e.to;
    });

    // --- Table view ---
    const radj = window.cfgHelpers.buildReverseAdj(cgEdges.map(e => ({ from: e.from, to: e.to })));
    const cgTableEl = document.createElement('div');
    cgTableEl.className = 'cfg-table-view';
    const cgTable = document.createElement('table');
    cgTable.className = 'data-table';
    const cgThead = cgTable.createTHead();
    const cgHrow = cgThead.insertRow();
    ['Fonction', 'Adresse', 'Type', 'Appelants'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      cgHrow.appendChild(th);
    });
    const cgTbody = cgTable.createTBody();
    const cgRowEls = {};
    Object.entries(nodeMap).sort((a, b) => a[1].localeCompare(b[1])).forEach(([addr, name]) => {
      const isExt = extSet.has(addr);
      const callers = (radj[addr] || []).map(a => nodeMap[a] || a).join(', ') || '\u2014';
      const row = cgTbody.insertRow();
      row.dataset.addr = addr;
      cgRowEls[addr] = row;
      const td1 = row.insertCell();
      const nameCode = document.createElement('code');
      nameCode.className = 'addr-link';
      nameCode.dataset.addr = addr;
      nameCode.textContent = name;
      nameCode.style.cursor = 'pointer';
      nameCode.style.color = isExt ? '#88c0d0' : '#88d8ff';
      nameCode.addEventListener('click', (ev) => {
        ev.stopPropagation();
        syncCallGraphActiveAddress(addr, { reveal: isStaticTabActive('callgraph') });
        vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() });
      });
      td1.appendChild(nameCode);
      const td2 = row.insertCell();
      td2.textContent = addr;
      td2.style.fontFamily = 'monospace';
      td2.style.fontSize = '11px';
      const td3 = row.insertCell();
      td3.textContent = isExt ? 'Externe' : 'Interne';
      td3.style.color = isExt ? '#88c0d0' : '#88d8ff';
      const td4 = row.insertCell();
      td4.textContent = callers;
      td4.style.fontSize = '11px';
    });
    const cgHintP = document.createElement('p');
    cgHintP.className = 'hint';
    cgHintP.textContent = `${Object.keys(nodeMap).length} fonction(s) \u2014 ${cgEdges.length} appel(s).`;
    cgTableEl.appendChild(cgTable);
    cgTableEl.appendChild(cgHintP);

    // --- Graph view ---
    const svgNodes = Object.entries(nodeMap).map(([addr, name]) => ({
      addr, label: name, isExternal: extSet.has(addr),
    }));
    const svgEdges = cgEdges.map(e => ({ from: e.from, to: e.to, type: 'call' }));
    const zoomState = { scale: 1 };
    const svgEl = renderGraphSvg(svgNodes, svgEdges, {
      nodeH: 76,
      padX: 104,
      padY: 96,
      maxPerRow: 4,
      zoomState,
      onNodeClick: (addr) => vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() }),
    });
    const graphEl = document.createElement('div');
    graphEl.className = 'cfg-graph-view';
    const svgWrap = document.createElement('div');
    svgWrap.className = 'cfg-svg-wrap';
    const zoomWrap = document.createElement('div');
    zoomWrap.className = 'cfg-svg-zoom';
    const innerWrap = document.createElement('div');
    innerWrap.className = 'cfg-svg-inner';
    innerWrap.appendChild(svgEl);
    zoomWrap.appendChild(innerWrap);
    // Call Graph legend
    const cgLegendDiv = document.createElement('div');
    cgLegendDiv.className = 'cfg-legend';
    const cgLegendItems = [
      ['#88c0d0', 'solid', 'Appel', 'Appel de fonction d\u00e9tect\u00e9 dans le code'],
      ['#d08770', 'dashed', 'Boucle', 'Appel r\u00e9cursif ou cyclique'],
      ['#88c0d0', 'ext', 'Externe', 'Fonction import\u00e9e (PLT/libc) \u2014 bordure pointill\u00e9e'],
      ['#88d8ff', 'int', 'Interne', 'Fonction d\u00e9finie dans le binaire'],
    ];
    cgLegendItems.forEach(([color, style, label, desc]) => {
      const item = document.createElement('span');
      item.className = 'cfg-legend-item';
      item.title = desc;
      const swatch = document.createElement('span');
      swatch.className = 'cfg-legend-swatch';
      if (style === 'ext') {
        swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 4px, transparent 4px 6px)`;
      } else if (style === 'dashed') {
        swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 5px, transparent 5px 8px)`;
      } else {
        swatch.style.background = color;
      }
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(label));
      cgLegendDiv.appendChild(item);
    });
    const cgHintSpan = document.createElement('span');
    cgHintSpan.className = 'cfg-legend-hint';
    cgHintSpan.textContent = 'Molette: zoom \u2014 Drag n\u0153ud \u2014 Shift+clic: chemin';
    cgLegendDiv.appendChild(cgHintSpan);

    svgWrap.appendChild(cgLegendDiv);
    svgWrap.appendChild(zoomWrap);
    graphEl.appendChild(svgWrap);
    if (svgEl._tooltip) graphEl.appendChild(svgEl._tooltip);

    // Assemble and wire up toggle
    cgTableEl.style.display = 'none';
    container.replaceChildren(cgTableEl, graphEl);
    const callGraphAddrs = Object.keys(nodeMap);
    const callGraphAddrMap = Object.fromEntries(callGraphAddrs.map((addr) => [normalizeHexAddress(addr), addr]));
    let activeCallGraphAddr = null;
    let zs = null;

    function resolveCallGraphAddr(addr) {
      const nearest = findNearestFunctionStart(addr, callGraphAddrs);
      return callGraphAddrMap[normalizeHexAddress(nearest)] || null;
    }

    function updateCallGraphSearchFilter() {
      const rawQuery = String(document.getElementById('cgSearchInput')?.value || '');
      const q = rawQuery.toLowerCase();
      cgState.search = rawQuery;
      svgEl.querySelectorAll('.cfg-node').forEach((g) => {
        const addr = (g.dataset.addr || '').toLowerCase();
        const text = (g.textContent || '').toLowerCase();
        const isActive = g.classList.contains('is-active');
        g.style.opacity = (!q || addr.includes(q) || text.includes(q) || isActive) ? '1' : '0.15';
      });
    }

    function setCallGraphActiveAddr(addr, opts = {}) {
      const nodeAddr = resolveCallGraphAddr(addr);
      container._cgState = container._cgState || {};
      container._cgState.activeAddr = addr || '';
      cgState.activeAddr = addr || '';
      if (activeCallGraphAddr && cgRowEls[activeCallGraphAddr]) cgRowEls[activeCallGraphAddr].classList.remove('cfg-row-active');
      activeCallGraphAddr = nodeAddr;
      if (activeCallGraphAddr && cgRowEls[activeCallGraphAddr]) {
        cgRowEls[activeCallGraphAddr].classList.add('cfg-row-active');
        if (opts.revealTable && cgTableEl.style.display !== 'none') {
          cgRowEls[activeCallGraphAddr].scrollIntoView({ block: 'center', behavior: opts.instant ? 'auto' : 'smooth' });
        }
      }
      const selectedNodeAddr = nodeAddr && svgEl._setActiveNode ? svgEl._setActiveNode(nodeAddr) : null;
      updateCallGraphSearchFilter();
      if (selectedNodeAddr && opts.reveal && graphEl.style.display !== 'none' && zs?.centerOnBox && svgEl._getNodeBox) {
        const box = svgEl._getNodeBox(selectedNodeAddr);
        if (box) zs.centerOnBox(box, { minScale: 0.75, maxScale: 1.1 });
      }
      return selectedNodeAddr;
    }

    container._cgState = {
      activeAddr: cgState.activeAddr || window._lastDisasmAddr || '',
      setActiveAddr: setCallGraphActiveAddr,
    };

    const cgViewToggle = container.closest('.static-panel')?.querySelectorAll('input[name="cgView"]');
    const showCgTable = () => {
      cgState.viewMode = 'table';
      _saveStorage({ cgViewMode: 'table' });
      cgTableEl.style.display = '';
      graphEl.style.display = 'none';
      if (container._cgState?.activeAddr) setCallGraphActiveAddr(container._cgState.activeAddr, { revealTable: true, instant: true });
    };
    const showCgGraph = () => {
      cgState.viewMode = 'graph';
      _saveStorage({ cgViewMode: 'graph' });
      cgTableEl.style.display = 'none';
      graphEl.style.display = '';
      const restoreView = cgState.graphView && zs?.setViewState;
      if (restoreView) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => zs.setViewState(cgState.graphView));
        });
      } else {
        requestGraphFit(graphEl);
      }
      if (container._cgState?.activeAddr) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => setCallGraphActiveAddr(container._cgState.activeAddr, { reveal: !restoreView, instant: true }));
        });
      }
    };
    cgViewToggle?.forEach(input => {
      input.addEventListener('change', () => { (input.value === 'table' ? showCgTable : showCgGraph)(); });
    });
    zs = initCfgZoom(zoomWrap);
    if (zs) {
      Object.assign(zoomState, zs);
      zs.onChange = (view) => { cgState.graphView = view; };
    }
    // Search filter
    const cgSearchInput = document.getElementById('cgSearchInput');
    if (cgSearchInput) {
      cgSearchInput.value = cgState.search || '';
      cgSearchInput.addEventListener('input', () => {
        _saveStorage({ cgSearch: cgSearchInput.value || '' });
        updateCallGraphSearchFilter();
      });
    }
    const preferredCgView = container.closest('.static-panel')?.querySelector(`input[name="cgView"][value="${cgState.viewMode === 'table' ? 'table' : 'graph'}"]`);
    if (preferredCgView) preferredCgView.checked = true;
    if (cgState.viewMode === 'graph') showCgGraph();
    else showCgTable();
    updateCallGraphSearchFilter();
    // Fit button + auto-fit on first render
    const btnCgFit = document.getElementById('btnCgFit');
    if (btnCgFit && zs) {
      btnCgFit.addEventListener('click', () => zs.fitToView());
    }
    if (zs?.requestFit && !cgState.graphView && cgState.viewMode === 'graph') zs.requestFit();
    if (container._cgState?.activeAddr) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setCallGraphActiveAddr(container._cgState.activeAddr, { reveal: isStaticTabActive('callgraph'), instant: true }));
      });
    }
    return;
  }
  if (msg.type === 'hubDiscoveredFunctions') {
    tabDataCache.discovered = { binaryPath: getStaticBinaryPath() };
    window.discoveredFunctionsCache = msg.functions || [];
    populateDecompileSelect(window.symbolsCache || []);
    const container = document.getElementById('functionsContent');
    if (!container) return;
    const list = msg.functions || [];
    if (list.length === 0) {
      const bp = getStaticBinaryPath();
      let hint = msg.analyzed ? 'Aucune fonction supplémentaire trouvée (tous les prologues correspondent à des symboles connus).' : 'Ouvrez d\'abord le désassemblage.';
      if (msg.error) hint = `Erreur : ${msg.error}`;
      const btnHtml = msg.analyzed ? '' : `<br/><button type="button" class="btn btn-primary" id="btnDiscOpenDisasm">Ouvrir le désassemblage</button>`;
      container.innerHTML = `<p class="hint">${escapeHtml(hint)}</p>${btnHtml}`;
      document.getElementById('btnDiscOpenDisasm')?.addEventListener('click', () => {
        if (bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: false });
      });
    } else {
      const rows = list.map((f) => {
        const score = Number.isFinite(f.confidence_score) ? `${Math.round(f.confidence_score * 100)}%` : '';
        const targetHint = f.target_addr ? `<div class="hint">→ ${escapeHtml(f.target_addr)}</div>` : '';
        return `<tr class="nav-addr-row" data-addr="${escapeHtml(f.addr)}" data-addr-match="function"><td><code class="addr-link" data-addr="${escapeHtml(f.addr)}">${escapeHtml(f.addr)}</code></td><td>${escapeHtml(f.name)}${targetHint}</td><td>${escapeHtml(f.kind || 'function')}</td><td>${escapeHtml(f.confidence)}</td><td>${escapeHtml(score)}</td><td>${escapeHtml(f.reason || '')}</td></tr>`;
      }).join('');
      container.innerHTML = `<table class="data-table"><thead><tr><th>Adresse</th><th>Nom</th><th>Type</th><th>Confiance</th><th>Score</th><th>Raison</th></tr></thead><tbody>${rows}</tbody></table><p class="hint">${list.length} fonction(s) découverte(s) — Clic sur une adresse → aller au désassemblage.</p>`;
      container.querySelectorAll('.addr-link').forEach(el => {
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => { const a = el.dataset.addr; if (a) vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() }); });
      });
      updateActiveNavRows(window._lastDisasmAddr);
    }
    renderFuncSimilarityUi(container);
    if (!funcSimilarityUiState.db) vscode.postMessage({ type: 'hubListFuncSimilarityDb' });
    return;
  }
  if (msg.type === 'hubFunctionsDone') {
    tabDataCache.discovered = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('functionsContent');
    const countEl = document.getElementById('functionsCount');
    if (!container) return;

    const { symbols, cc, error } = msg.data || {};
    if (error) {
      container.innerHTML = '<p class="hint">Erreur : ' + escapeHtml(error) + '</p>';
      return;
    }

    const symList = (symbols && symbols.symbols) ? symbols.symbols : [];
    const conventions = (cc && cc.conventions) ? cc.conventions : {};

    // Build rows array
    const rows = symList.map(s => {
      const convInfo = conventions[s.addr];
      const conv = (convInfo && convInfo.convention) ? convInfo.convention : '—';
      const sizeStr = (s.size && s.size > 0) ? s.size + ' B' : '—';
      let typeLabel;
      if (s.type === 'T' || s.type === 't') typeLabel = 'local';
      else if (s.type === 'U') typeLabel = 'PLT';
      else typeLabel = s.type || '?';
      return { addr: s.addr, name: s.name, sizeNum: s.size || 0, sizeStr, typeLabel, conv };
    });
    window.functionListCache = rows;
    populateDecompileSelect(window.symbolsCache || symList);

    let sortCol = 'addr';
    let sortDir = 1;

    function renderTable() {
      const filter = (document.getElementById('functionsSearch') || {}).value || '';
      const filterLower = filter.toLowerCase();
      const filtered = rows.filter(function(r) {
        return r.name.toLowerCase().indexOf(filterLower) !== -1 ||
               r.addr.toLowerCase().indexOf(filterLower) !== -1;
      });

      filtered.sort(function(a, b) {
        let va, vb;
        if (sortCol === 'addr') {
          va = parseInt(a.addr, 16) || 0;
          vb = parseInt(b.addr, 16) || 0;
        } else if (sortCol === 'size') {
          va = a.sizeNum; vb = b.sizeNum;
        } else {
          va = (a[sortCol] || '').toString();
          vb = (b[sortCol] || '').toString();
          return sortDir * va.localeCompare(vb);
        }
        return sortDir * (va - vb);
      });

      if (countEl) countEl.textContent = filtered.length + ' fonction(s)';

      const colDefs = [
        { key: 'addr',      label: 'Adresse' },
        { key: 'name',      label: 'Nom' },
        { key: 'size',      label: 'Taille' },
        { key: 'typeLabel', label: 'Type' },
        { key: 'conv',      label: 'Convention' },
      ];

      const thead = colDefs.map(function(c) {
        const cls = sortCol === c.key ? (sortDir === 1 ? 'sort-asc' : 'sort-desc') : '';
        return '<th class="' + cls + '" data-col="' + escapeHtml(c.key) + '">' + escapeHtml(c.label) + '</th>';
      }).join('');

      const tbody = filtered.map(function(r) {
        return '<tr class="nav-addr-row" data-addr="' + escapeHtml(r.addr) + '" data-addr-match="function">' +
          '<td><code class="addr-link" data-addr="' + escapeHtml(r.addr) + '">' + escapeHtml(r.addr) + '</code></td>' +
          '<td>' + escapeHtml(r.name) + '</td>' +
          '<td>' + escapeHtml(r.sizeStr) + '</td>' +
          '<td>' + escapeHtml(r.typeLabel) + '</td>' +
          '<td>' + escapeHtml(r.conv) + '</td>' +
          '</tr>';
      }).join('');

      container.innerHTML = '<table class="data-table functions-table"><thead><tr>' + thead + '</tr></thead><tbody>' + tbody + '</tbody></table>';

      // Sort click handlers
      container.querySelectorAll('th[data-col]').forEach(function(th) {
        th.addEventListener('click', function() {
          const col = th.dataset.col;
          if (sortCol === col) { sortDir = -sortDir; } else { sortCol = col; sortDir = 1; }
          renderTable();
        });
      });

      // Address navigation handlers (no tab switch — existing pattern)
      container.querySelectorAll('.addr-link').forEach(function(el) {
        el.style.cursor = 'pointer';
        el.addEventListener('click', function() {
          const a = el.dataset.addr;
          if (a) vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
        });
      });
      updateActiveNavRows(window._lastDisasmAddr);
      renderFuncSimilarityUi(container);
    }

    renderTable();

    const searchEl = document.getElementById('functionsSearch');
    if (searchEl) {
      const newEl = searchEl.cloneNode(true);
      searchEl.parentNode.replaceChild(newEl, searchEl);
      newEl.addEventListener('input', renderTable);
    }

    renderFuncSimilarityUi(container);
    if (!funcSimilarityUiState.db) vscode.postMessage({ type: 'hubListFuncSimilarityDb' });
    if (typeof tabDataCache !== 'undefined') {
      tabDataCache['discovered'] = { binaryPath: getStaticBinaryPath() };
    }
    return;
  }
  if (msg.type === 'hubFuncSimilarityDone') {
    const container = document.getElementById('functionsContent');
    if (!container) return;
    funcSimilarityUiState.pendingText = '';
    funcSimilarityUiState.results = msg.data || {};
    renderFuncSimilarityUi(container);
    return;
  }
  if (msg.type === 'hubFuncSimilarityDbDone') {
    const container = document.getElementById('functionsContent');
    if (!container) return;
    funcSimilarityUiState.pendingText = '';
    funcSimilarityUiState.db = msg.data || {};
    renderFuncSimilarityUi(container);
    return;
  }
  if (msg.type === 'hubYara') {
    detectionUiState.yaraMatches = msg.matches || [];
    detectionUiState.yaraError = msg.error || '';
    renderYaraResults();
    return;
  }
  if (msg.type === 'hubCapa') {
    tabDataCache.detection = { binaryPath: getStaticBinaryPath() };
    detectionUiState.capaCapabilities = msg.capabilities || [];
    detectionUiState.capaError = msg.error || '';
    renderCapaResults();
    return;
  }
  if (msg.type === 'hubRulesList') {
    const rules = msg.rules || [];
    _renderRulesList('yaraRulesList', rules.filter(function(r) { return r.type === 'yara'; }));
    _renderRulesList('capaRulesList', rules.filter(function(r) { return r.type === 'capa'; }));
    return;
  }
  if (msg.type === 'hubRuleToggled' || msg.type === 'hubRuleAdded' || msg.type === 'hubRuleDeleted') {
    vscode.postMessage({ type: 'hubListRules' });
    return;
  }
  if (msg.type === 'hubDecompilerList') {
    populateDecompilerProfiles(msg.result || {});
    _renderDecompilerStatusList(msg.result || {});
    return;
  }
  if (msg.type === 'hubCommandResult') {
    _onDecompilerCommandResult(msg);
    return;
  }
  if (msg.type === 'hubDecompile') {
    const container = document.getElementById('decompileContent');
    if (!container) return;
    const responseQuality = _normalizeDecompileQuality(msg.quality || msg.result?.quality || decompileUiState.quality || 'normal');
    const payload = {
      result: msg.result || {},
      addr: msg.addr || '',
      full: !!msg.full,
      decompiler: typeof msg.decompiler === 'string' ? msg.decompiler : _getRequestedDecompilerForQuality(responseQuality),
      quality: responseQuality,
      provider: String(msg.provider || _getConfiguredDecompilerProvider() || 'auto'),
      binaryPath: msg.binaryPath || getStaticBinaryPath() || decompileUiState.renderedBinaryPath || '',
      funcName: String(msg.funcName || getDecompileSelectionContext().funcName || '').trim(),
    };
    const requestKey = buildDecompileRequestKey(payload.binaryPath, payload.decompiler, payload.quality, payload.addr, payload.full, payload.provider, payload.funcName);
    pendingDecompileRequests.delete(requestKey);
    cacheDecompileResult(requestKey, payload);
    const current = getCurrentDecompileRequestContext();
    const currentRequestKey = buildDecompileRequestKey(current.binaryPath, current.decompiler, current.quality, current.addr, current.full, current.provider, current.funcName);
    if (requestKey !== currentRequestKey) return;
    renderDecompilePayload(container, payload);
    return;
  }
  if (msg.type === 'hubBehavior') {
    const container = document.getElementById('behaviorContent');
    if (!container) return;
    const result = msg.result || {};
    if (result.error) {
      container.textContent = `Erreur : ${result.error}`;
      return;
    }
    const scoreEl = document.getElementById('behaviorScore');
    if (scoreEl) {
      scoreEl.style.display = '';
      scoreEl.textContent = `Score: ${result.score ?? 0}/100`;
      const s = result.score ?? 0;
      scoreEl.style.background = s >= 70 ? '#c72e2e' : s >= 30 ? '#c47a00' : '#0e639c';
      scoreEl.style.color = '#fff';
      scoreEl.style.padding = '2px 8px';
      scoreEl.style.borderRadius = '4px';
    }
    const indicators = result.indicators || [];
    if (indicators.length === 0) {
      container.textContent = 'Aucun indicateur détecté.';
      return;
    }
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Catégorie', 'Sévérité', 'Evidence', 'Offset'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    indicators.forEach(ind => {
      const tr = document.createElement('tr');
      const offsetStr = ind.offset !== undefined
        ? (typeof ind.offset === 'number' ? '0x' + ind.offset.toString(16) : String(ind.offset))
        : '?';
      [ind.category, ind.severity, ind.evidence, offsetStr].forEach(v => {
        const td = document.createElement('td');
        td.textContent = v ?? '';
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.replaceChildren(table);
    tabDataCache.behavior = { binaryPath: getStaticBinaryPath() };
    return;
  }
  if (msg.type === 'hubTaint') {
    const container = document.getElementById('taintContent');
    if (!container) return;
    const result = msg.result || {};
    if (result.error) {
      container.textContent = `Erreur : ${result.error}`;
      return;
    }
    const scoreEl = document.getElementById('taintScore');
    if (scoreEl) {
      scoreEl.style.display = '';
      scoreEl.textContent = `Risque: ${result.risk_score ?? 0}/100`;
      scoreEl.style.background = '#c72e2e';
      scoreEl.style.color = '#fff';
      scoreEl.style.padding = '2px 8px';
      scoreEl.style.borderRadius = '4px';
    }
    const flows = result.flows || [];
    if (flows.length === 0) {
      container.textContent = 'Aucun flux taint détecté.';
      return;
    }
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Source', 'Sink', 'Via', 'Confiance'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    flows.forEach(flow => {
      const tr = document.createElement('tr');
      [flow.source_fn, flow.sink_fn, flow.via_fn || '—', flow.confidence].forEach(v => {
        const td = document.createElement('td');
        td.textContent = v ?? '';
        tr.appendChild(td);
      });
      if (flow.source_origin || flow.sink_origin || flow.source_path || flow.sink_path) {
        tr.title = [
          flow.source_origin ? `Source réelle: ${flow.source_origin}` : '',
          flow.sink_origin ? `Sink réel: ${flow.sink_origin}` : '',
          Array.isArray(flow.source_path) ? `Chemin source: ${flow.source_path.join(' -> ')}` : '',
          Array.isArray(flow.sink_path) ? `Chemin sink: ${flow.sink_path.join(' -> ')}` : '',
        ].filter(Boolean).join('\n');
      }
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.replaceChildren(table);
    tabDataCache.taint = { binaryPath: getStaticBinaryPath() };
    return;
  }
  if (msg.type === 'hubRop') {
    const container = document.getElementById('ropContent');
    if (!container) return;
    if (msg.error) {
      container.textContent = `Erreur : ${msg.error}`;
      return;
    }
    const gadgets = msg.gadgets || [];
    const countEl = document.getElementById('ropCount');
    if (countEl) {
      countEl.style.display = '';
      countEl.textContent = `${gadgets.length} gadgets`;
      countEl.style.background = '#555';
      countEl.style.color = '#fff';
      countEl.style.padding = '2px 8px';
      countEl.style.borderRadius = '4px';
    }
    if (gadgets.length === 0) {
      container.textContent = 'Aucun gadget ROP trouvé.';
      return;
    }
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Adresse', 'Type', 'Regs', 'Support', 'Instructions'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    gadgets.forEach(g => {
      const tr = document.createElement('tr');
      const tdAddr = document.createElement('td');
      tdAddr.textContent = g.addr || '?';
      tdAddr.className = 'mono';
      tr.appendChild(tdAddr);
      const tdType = document.createElement('td');
      tdType.textContent = g.type || '?';
      tr.appendChild(tdType);
      const tdRegs = document.createElement('td');
      tdRegs.textContent = Array.isArray(g.regs_modified) && g.regs_modified.length
        ? g.regs_modified.join(', ')
        : '—';
      tdRegs.className = 'mono';
      tr.appendChild(tdRegs);
      const tdSupport = document.createElement('td');
      tdSupport.textContent = g.support_level || '—';
      if (g.support_note) tdSupport.title = g.support_note;
      tr.appendChild(tdSupport);
      const tdInsns = document.createElement('td');
      tdInsns.textContent = (g.instructions || []).join(' ; ');
      tdInsns.className = 'mono';
      tr.appendChild(tdInsns);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.replaceChildren(table);
    tabDataCache.rop = { binaryPath: getStaticBinaryPath() };
    return;
  }
  if (msg.type === 'hubVulns') {
    const container = document.getElementById('vulnsContent');
    if (!container) return;
    const result = msg.result || {};
    if (result.error) {
      container.textContent = `Erreur : ${result.error}`;
      return;
    }
    const vulns = result.vulnerabilities || [];
    const countEl = document.getElementById('vulnsCount');
    if (countEl) {
      countEl.style.display = '';
      countEl.textContent = `${vulns.length} vulnérabilité${vulns.length !== 1 ? 's' : ''}`;
      countEl.style.background = vulns.length > 0 ? '#c72e2e' : '#0e639c';
      countEl.style.color = '#fff';
      countEl.style.padding = '2px 8px';
      countEl.style.borderRadius = '4px';
    }
    if (vulns.length === 0) {
      container.textContent = 'Aucune vulnérabilité détectée.';
      return;
    }
    const severityColor = { CRITICAL: '#c72e2e', HIGH: '#c47a00', MEDIUM: '#b5a000', LOW: '#0e639c' };
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Sévérité', 'Type', 'Fonction', 'CWE', 'Description'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    vulns.forEach(v => {
      const tr = document.createElement('tr');
      const tdSev = document.createElement('td');
      tdSev.textContent = v.severity || '?';
      tdSev.style.color = severityColor[v.severity] || '';
      tdSev.style.fontWeight = 'bold';
      tr.appendChild(tdSev);
      [v.type, v.function || '?', v.cwe, v.description].forEach(val => {
        const td = document.createElement('td');
        td.textContent = val ?? '';
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.replaceChildren(table);
    tabDataCache.vulns = { binaryPath: getStaticBinaryPath() };
    return;
  }

  if (msg.type === 'hubAntiAnalysisDone') {
    const el = document.getElementById('antiAnalysisContent');
    if (!el) return;
    if (msg.data?.error) {
      el.replaceChildren();
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = msg.data.error;
      el.appendChild(p);
      return;
    }
    const techniques = Array.isArray(msg.data) ? msg.data : [];
    tabDataCache.anti_analysis = { binaryPath: getStaticBinaryPath() };
    if (!techniques.length) {
      el.replaceChildren();
      const p = document.createElement('p');
      p.className = 'empty-state';
      p.textContent = 'Aucune technique anti-analyse détectée.';
      el.appendChild(p);
      return;
    }
    const table = document.createElement('table');
    const head = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Technique','Description','Bypass','Confiance'].forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    head.appendChild(hrow);
    table.appendChild(head);
    const body = document.createElement('tbody');
    techniques.forEach((t) => {
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.className = 'name'; c1.textContent = t.technique; tr.appendChild(c1);
      const c2 = document.createElement('td'); c2.textContent = t.description; tr.appendChild(c2);
      const c3 = document.createElement('td'); c3.className = 'type'; c3.textContent = t.bypass; tr.appendChild(c3);
      const c4 = document.createElement('td');
      c4.className = t.confidence === 'HIGH' ? 'sev-high' : t.confidence === 'MEDIUM' ? 'sev-medium' : 'sev-low';
      c4.textContent = t.confidence;
      tr.appendChild(c4);
      body.appendChild(tr);
    });
    table.appendChild(body);
    el.replaceChildren(table);
    return;
  }

  if (msg.type === 'hubFlirtDone') {
    const el = document.getElementById('flirtContent');
    if (!el) return;
    const matches = Array.isArray(msg.data) ? msg.data : [];
    tabDataCache.flirt = { binaryPath: getStaticBinaryPath() };
    if (!matches.length) {
      el.replaceChildren();
      const p = document.createElement('p');
      p.className = 'empty-state';
      p.textContent = 'Aucune signature FLIRT trouvée.';
      el.appendChild(p);
      return;
    }
    const table = document.createElement('table');
    const head = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Adresse','Fonction','Bibliothèque','Confiance'].forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    head.appendChild(hrow);
    table.appendChild(head);
    const body = document.createElement('tbody');
    matches.forEach((m) => {
      const tr = document.createElement('tr');
      const c1 = document.createElement('td'); c1.className = 'addr'; c1.textContent = m.addr; tr.appendChild(c1);
      const c2 = document.createElement('td'); c2.className = 'name'; c2.textContent = m.name; tr.appendChild(c2);
      const c3 = document.createElement('td'); c3.className = 'type'; c3.textContent = m.lib; tr.appendChild(c3);
      const c4 = document.createElement('td'); c4.textContent = m.confidence; tr.appendChild(c4);
      body.appendChild(tr);
    });
    table.appendChild(body);
    el.replaceChildren(table);
    return;
  }

  if (msg.type === 'hubDeobfuscateDone') {
    const el = document.getElementById('deobfuscateContent');
    if (!el) return;
    const results = Array.isArray(msg.data) ? msg.data : [];
    tabDataCache.deobfuscate = { binaryPath: getStaticBinaryPath() };
    if (!results.length) {
      el.replaceChildren();
      const p = document.createElement('p');
      p.className = 'empty-state';
      p.textContent = 'Aucune string déobfusquée trouvée.';
      el.appendChild(p);
      return;
    }
    const table = document.createElement('table');
    const head = document.createElement('thead');
    const hrow = document.createElement('tr');
    ['Adresse','Décodé','Méthode','Confiance'].forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    head.appendChild(hrow);
    table.appendChild(head);
    const body = document.createElement('tbody');
    results.forEach((r) => {
      const tr = document.createElement('tr');
      const c1 = document.createElement('td');
      const addrCode = document.createElement('code');
      addrCode.className = 'addr-link';
      addrCode.dataset.addr = r.addr;
      addrCode.textContent = r.addr;
      addrCode.style.cursor = 'pointer';
      addrCode.addEventListener('click', () => {
        vscode.postMessage({ type: 'hubGoToAddress', addr: r.addr, binaryPath: getStaticBinaryPath() });
      });
      c1.appendChild(addrCode);
      tr.appendChild(c1);
      const c2 = document.createElement('td'); c2.className = 'value'; c2.textContent = r.decoded; tr.appendChild(c2);
      const c3 = document.createElement('td'); c3.className = 'type'; c3.textContent = r.method; tr.appendChild(c3);
      const c4 = document.createElement('td');
      const confMap = { high: '🟢 haute', medium: '🟡 moyenne', low: '🔴 basse' };
      c4.textContent = confMap[r.confidence] || r.confidence || '—';
      tr.appendChild(c4);
      body.appendChild(tr);
    });
    table.appendChild(body);
    el.replaceChildren(table);
    return;
  }

  if (msg.type === 'hubRecherche' || msg.type === 'hubSearchBinaryResult') {
    const results = msg.results || [];
    const err = msg.error;
    const tbody = document.getElementById('searchResultsBody');
    const bar = document.getElementById('searchResultsBar');
    const container = document.getElementById('searchResultsContainer');
    const countEl = document.getElementById('searchResultsCount');
    const binaryPath = getStaticBinaryPath();
    const binaryMeta = getCurrentBinaryMeta();
    const isRaw = binaryMeta?.kind === 'raw';
    const goToSearchOffset = (row) => {
      if (!binaryPath) return;
      if (isRaw && row?.vaddr_hex) {
        vscode.postMessage({ type: 'hubGoToAddress', addr: row.vaddr_hex, binaryPath, binaryMeta });
        return;
      }
      const offsetValue = row?.offset_hex || row?.offset;
      if (offsetValue != null) {
        vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: String(offsetValue), binaryPath, binaryMeta });
      }
    };
    const goToSearchAddress = (row) => {
      if (!binaryPath || !row?.vaddr_hex) return;
      vscode.postMessage({ type: 'hubGoToAddress', addr: row.vaddr_hex, binaryPath, binaryMeta });
    };

    // Fallback: if new DOM elements are absent, use legacy rendering
    if (!tbody || !bar || !container || !countEl) {
      const legacyContainer = document.getElementById('searchBinaryContent');
      if (!legacyContainer) return;
      if (err) {
        legacyContainer.innerHTML = `<div class="search-results-empty"><p class="search-results-empty-title">Erreur</p><p class="search-results-empty-desc">${escapeHtml(err)}</p></div>`;
        return;
      }
      if (results.length === 0) {
        legacyContainer.innerHTML = `<div class="search-results-empty"><p class="search-results-empty-title">Aucune correspondance</p></div>`;
        return;
      }
      const rows = results.map(r => {
        const val = escapeHtml(String(r.value || '').substring(0, 48));
        const ctx = escapeHtml(String(r.context || '').substring(0, 80));
        const vaddr = r.vaddr_hex ? `<code class="addr-link" data-vaddr="${escapeHtml(r.vaddr_hex)}">${escapeHtml(r.vaddr_hex)}</code>` : '—';
        return `<tr><td><code class="addr-link" data-offset="${escapeHtml(r.offset_hex)}">${escapeHtml(r.offset_hex)}</code></td><td>${vaddr}</td><td><code>${val}</code></td><td><code>${ctx}</code></td></tr>`;
      }).join('');
      legacyContainer.innerHTML = `<div class="search-results-header"><span>${results.length} correspondance(s)</span></div><table class="data-table"><thead><tr><th>Offset</th><th>Adresse</th><th>Valeur</th><th>Contexte</th></tr></thead><tbody>${rows}</tbody></table>`;
      legacyContainer.querySelectorAll('.addr-link').forEach(el => {
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => {
          const row = {
            offset_hex: el.dataset.offset || '',
            vaddr_hex: el.dataset.vaddr || '',
          };
          if (el.dataset.vaddr) goToSearchAddress(row);
          else goToSearchOffset(row);
        });
      });
      return;
    }

    // ── New DOM rendering (E) ─────────────────────────────────────────────────
    if (err) {
      tbody.innerHTML = '';
      countEl.textContent = 'Erreur : ' + err;
      bar.hidden = false;
      container.hidden = true;
      return;
    }

    tbody.innerHTML = '';
    const display = results.slice(0, 500);
    display.forEach(r => {
      const tr = document.createElement('tr');
      const offsetTd = document.createElement('td');
      const offsetCode = document.createElement('code');
      offsetCode.textContent = String(r.offset_hex || '');
      if (r.offset_hex || r.offset != null) {
        offsetCode.className = 'addr-link';
        offsetCode.style.cursor = 'pointer';
        offsetCode.addEventListener('click', () => goToSearchOffset(r));
      }
      offsetTd.appendChild(offsetCode);

      const vaddrTd = document.createElement('td');
      if (r.vaddr_hex) {
        const vaddrCode = document.createElement('code');
        vaddrCode.textContent = String(r.vaddr_hex);
        vaddrCode.className = 'addr-link';
        vaddrCode.style.cursor = 'pointer';
        vaddrCode.addEventListener('click', () => goToSearchAddress(r));
        vaddrTd.appendChild(vaddrCode);
      } else {
        vaddrTd.textContent = '—';
      }

      const valueTd = document.createElement('td');
      valueTd.className = 'mono';
      valueTd.textContent = String(r.value || '').slice(0, 40);

      const lenTd = document.createElement('td');
      lenTd.textContent = String(r.length ?? '');

      const contextTd = document.createElement('td');
      contextTd.className = 'mono';
      contextTd.textContent = String(r.context || '').slice(0, 32);

      tr.append(offsetTd, vaddrTd, valueTd, lenTd, contextTd);
      tbody.appendChild(tr);
    });

    countEl.textContent = results.length > 500
      ? `${results.length} résultats (500 affichés)`
      : `${results.length} résultat${results.length !== 1 ? 's' : ''}`;
    bar.hidden = false;
    container.hidden = false;

    window._searchResults = results;
    return;
  }
  if (msg.type === 'hubActiveAddr') {
    const badge = document.getElementById('annotationAddrBadge');
    if (badge) {
      badge.textContent = msg.addr;
      badge.dataset.addr = msg.addr;
      badge.classList.add('has-addr');
    }
    const spanLength = normalizeSpanLength(msg.spanLength || 1);
    setActiveAddressContext(msg.addr, spanLength);
    const btn = document.getElementById('btnAddAnnotation');
    if (btn) btn.disabled = false;
    // Pre-fill form with existing annotation for this address
    const ann = window._annotations?.[msg.addr];
    const nameEl = document.getElementById('annotationName');
    const cmtEl = document.getElementById('annotationComment');
    if (nameEl) nameEl.value = ann?.name || '';
    if (cmtEl) cmtEl.value = ann?.comment || '';
    syncCfgActiveAddress(msg.addr, {
      reveal: isStaticTabActive('cfg'),
      revealTable: isStaticTabActive('cfg') && document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
    });
    syncCallGraphActiveAddress(msg.addr, {
      reveal: isStaticTabActive('callgraph'),
      revealTable: isStaticTabActive('callgraph') && document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
    });
    const decompileAddr = syncDecompileSelection(msg.addr, {
      forceContext: isStaticTabActive('decompile') && decompileUiState.selectionMode !== 'manual',
    });
    if (isStaticTabActive('decompile')) {
      const currentBinaryPath = getStaticBinaryPath() || '';
      const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
      const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
      const currentProvider = _getConfiguredDecompilerProvider();
      const renderedAddr = decompileUiState.renderedAddr || '';
      const shouldRefreshDecompile = currentBinaryPath
        && (
          decompileUiState.renderedBinaryPath !== currentBinaryPath
          || decompileUiState.renderedDecompiler !== currentDecompiler
          || decompileUiState.renderedProvider !== currentProvider
          || decompileUiState.renderedQuality !== currentQuality
          || renderedAddr !== (decompileAddr || '')
        );
      if (shouldRefreshDecompile) requestDecompileForCurrentSelection();
    }
    if (hexSections.length) {
      setHexActiveAddress(msg.addr, {
        spanLength,
        reveal: isStaticTabActive('hex'),
        instant: !isStaticTabActive('hex'),
      });
    }
    if (isStaticTabActive('stack')) {
      syncStackFrameForContext(msg.addr);
    }
    updateDisasmSessionSummary();
    return;
  }
  if (msg.type === 'hubAnnotationSaved') {
    const bp = msg.binaryPath;
    clearDecompileCaches();
    if (bp) {
      tabDataCache.cfg = null;
      tabDataCache.callgraph = null;
      vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: false, openInEditor: false });
    }
    return;
  }
  if (msg.type === 'hubAnnotations') {
    // Annotations loaded — could highlight addresses
    window._annotations = msg.annotations || {};
    clearDecompileCaches();
    updateActiveContextBars(window._lastDisasmAddr);
    return;
  }
  if (msg.type === 'hubSyncHexToAddr') {
    const spanLength = normalizeSpanLength(msg.spanLength || 1);
    setActiveAddressContext(msg.addr, spanLength);
    if (hexSections.length) scrollHexToVaddr({ addr: msg.addr, spanLength });
    return;
  }
  if (msg.type === 'hubHexView') {
    tabDataCache.hex = { binaryPath: getStaticBinaryPath() };
    const result = msg.result || {};
    const container = document.getElementById('hexContent');
    if (!container) return;
    if (result.error && !(result.rows?.length)) {
      resetHexDomState();
      window._lastHexRows = [];
      hexSections = result.sections || [];
      hexRenderInProgress = false;
      updateHexRenderStatus(0, 0, false);
      container.replaceChildren();
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = result.error;
      container.appendChild(p);
      return;
    }
    hexSections = result.sections || [];
    renderHexTable(container, result.rows || [], hexSections);
    renderHexSectionLegend(hexSections);
    if (hexPendingScrollVaddr) {
      const pending = hexPendingScrollVaddr;
      hexPendingScrollVaddr = null;
      requestAnimationFrame(() => scrollHexToVaddr(pending));
    }
    const offInput = document.getElementById('hexOffsetInput');
    if (offInput) offInput.value = '0x' + hexCurrentOffset.toString(16);
    const prevBtn = document.getElementById('btnHexPrev');
    const nextBtn = document.getElementById('btnHexNext');
    if (prevBtn) prevBtn.disabled = hexCurrentOffset === 0;
    if (nextBtn) nextBtn.disabled = (result.rows?.length || 0) < Math.ceil(hexCurrentLength / 16);
    return;
  }
  if (msg.type === 'hubPatchResult') {
    const result = msg.result || {};
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (result.ok ? 'ok' : 'error');
      status.textContent = result.ok
        ? `Patched ${result.written} byte(s) at 0x${result.offset?.toString(16)}`
        : `Error: ${result.error}`;
    }
    if (result.ok) {
      tabDataCache.hex = null;
      loadHexView(getStaticBinaryPath(), hexCurrentOffset, hexCurrentLength);
    }
    return;
  }
  if (msg.type === 'hubPatchesDone') {
    const patchList = document.getElementById('patchList');
    const revertAllBtn = document.getElementById('btnRevertAll');
    const patchSection = document.getElementById('patchManagerSection');
    if (!patchList) return;

    const patches = (msg.data && msg.data.patches) ? msg.data.patches : [];
    const redoPatches = (msg.data && msg.data.redo_patches) ? msg.data.redo_patches : [];
    hexPatchHistory = Array.isArray(patches) ? patches.slice() : [];
    hexPatchRedoHistory = Array.isArray(redoPatches) ? redoPatches.slice() : [];
    updateHexPatchButtons();

    if (patches.length === 0 && redoPatches.length === 0) {
      if (patchSection) patchSection.hidden = true;
      patchList.innerHTML = '<p class="hint" style="margin:6px 10px;">Aucun patch appliqué.</p>';
      if (revertAllBtn) revertAllBtn.style.display = 'none';
      return;
    }

    if (patchSection) patchSection.hidden = false;
    if (revertAllBtn) revertAllBtn.style.display = patches.length > 0 ? '' : 'none';

    const thead = '<thead><tr>' +
      '<th style="font-size:11px;padding:3px 6px;">Offset</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Original</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Patché</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Commentaire</th>' +
      '<th></th>' +
      '</tr></thead>';

    const rows = patches.map(function(p) {
      return '<tr>' +
        '<td><code>' + escapeHtml(typeof p.offset === 'number' ? '0x' + p.offset.toString(16) : String(p.offset)) + '</code></td>' +
        '<td><code>' + escapeHtml(p.original_bytes || '') + '</code></td>' +
        '<td><code>' + escapeHtml(p.patched_bytes || '') + '</code></td>' +
        '<td>' + escapeHtml(p.comment || '') + '</td>' +
        '<td><button class="patch-revert-btn" data-id="' + escapeHtml(String(p.id)) + '">Annuler</button></td>' +
      '</tr>';
    }).join('');

    const redoRows = redoPatches.map(function(p) {
      return '<tr>' +
        '<td><code>' + escapeHtml(typeof p.offset === 'number' ? '0x' + p.offset.toString(16) : String(p.offset)) + '</code></td>' +
        '<td><code>' + escapeHtml(p.original_bytes || '') + '</code></td>' +
        '<td><code>' + escapeHtml(p.patched_bytes || '') + '</code></td>' +
        '<td>' + escapeHtml(p.comment || '') + '</td>' +
        '<td><button class="patch-redo-btn" data-id="' + escapeHtml(String(p.id)) + '">Refaire</button></td>' +
        '</tr>';
    }).join('');

    const activeSection = patches.length > 0
      ? '<div class="patch-subsection"><div class="section-label" style="margin:0 0 6px 0;">Patches actifs</div><table>' + thead + '<tbody>' + rows + '</tbody></table></div>'
      : '<p class="hint" style="margin:6px 10px;">Aucun patch actif.</p>';
    const redoSection = redoPatches.length > 0
      ? '<div class="patch-subsection" style="margin-top:10px;"><div class="section-label" style="margin:0 0 6px 0;">Historique annulé</div><table>' + thead + '<tbody>' + redoRows + '</tbody></table></div>'
      : '';

    patchList.innerHTML = activeSection + redoSection;
    tabDataCache.patchList = { binaryPath: getStaticBinaryPath() };

    patchList.querySelectorAll('.patch-revert-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubRevertPatch', binaryPath: bp, patchId: btn.dataset.id });
      });
    });
    patchList.querySelectorAll('.patch-redo-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubRedoPatch', binaryPath: bp, patchId: btn.dataset.id });
      });
    });
    return;
  }
  if (msg.type === 'hubRevertPatchDone') {
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (msg.ok ? 'ok' : 'error');
      status.textContent = msg.ok ? 'Patch annulé.' : `Error: ${msg.error || 'Impossible d’annuler le patch.'}`;
    }
    if (msg.ok) {
      const bp = getStaticBinaryPath();
      if (bp) {
        tabDataCache.hex = null;
        loadHexView(bp, hexCurrentOffset, hexCurrentLength);
      }
    }
    return;
  }
  if (msg.type === 'hubRedoPatchDone') {
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (msg.ok ? 'ok' : 'error');
      status.textContent = msg.ok ? 'Patch réappliqué.' : `Error: ${msg.error || 'Impossible de réappliquer le patch.'}`;
    }
    if (msg.ok) {
      const bp = getStaticBinaryPath();
      if (bp) {
        tabDataCache.hex = null;
        loadHexView(bp, hexCurrentOffset, hexCurrentLength);
      }
    }
    return;
  }
  if (msg.type === 'hubStackFrame') {
    const binaryPath = msg.binaryPath || getStaticBinaryPath() || '';
    const activeSummary = getActiveContextSummary(window._lastDisasmAddr || decompileUiState.selectedAddr);
    const addr = normalizeHexAddress(msg.addr || activeSummary.functionAddr || activeSummary.addr);
    cacheStackFrame(binaryPath, addr, msg.result || {});
    const activeKey = getStackFrameCacheKey(activeSummary.binaryPath, activeSummary.functionAddr || activeSummary.addr);
    const receivedKey = getStackFrameCacheKey(binaryPath, addr);
    if (activeKey && activeKey === receivedKey) {
      renderStackFrame(msg.result);
    }
    if (activeKey && receivedKey && activeKey === receivedKey) {
      updateHexSelectionSummary(activeSummary.addr);
    }
    return;
  }
  if (msg.type === 'hubBindiff') {
    renderBindiff(msg.result);
    document.getElementById('btnRunBindiff')?.removeAttribute('disabled');
    return;
  }
  if (msg.type === 'hubPickedFile') {
    if (msg.target === 'funcSimilarityRef') {
      const bp = getStaticBinaryPath();
      if (!bp || !msg.path) return;
      funcSimilarityUiState.pendingText = `Analyse en cours — comparaison avec ${msg.path.split('/').pop()}...`;
      renderFuncSimilarityUi(document.getElementById('functionsContent'));
      vscode.postMessage({ type: 'hubLoadFuncSimilarity', binaryPath: bp, referencePath: msg.path, threshold: 0.4, top: 1 });
      return;
    }
    if (msg.target === 'funcSimilarityDbRef') {
      if (!msg.path) return;
      funcSimilarityUiState.pendingText = `Indexation en cours — ${msg.path.split('/').pop()}...`;
      renderFuncSimilarityUi(document.getElementById('functionsContent'));
      vscode.postMessage({ type: 'hubIndexFuncSimilarityRef', referencePath: msg.path });
      return;
    }
    const input = document.getElementById(msg.target);
    if (input) {
      input.value = msg.path;
      if (msg.target === 'dynamicSourcePath') {
        dynamicTraceInitState.sourcePath = String(msg.path || '').trim();
        dynamicTraceInitState.sourceEnrichmentEnabled = false;
        dynamicTraceInitState.sourceEnrichmentStatus = 'pending';
        dynamicTraceInitState.sourceEnrichmentMessage = '';
        if (dynamicSourceHint) dynamicSourceHint.textContent = buildDynamicSourceHintText(dynamicTraceInitState);
        updateArgvPayloadHint();
        requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
      }
      if (input.closest('#panel-options')) _scheduleSave();
    }
    return;
  }
  if (msg.type === 'hubSettings') {
    _applySettings(msg.settings);
    return;
  }
  if (msg.type === 'hubSettingsSaved') {
    return;
  }
  if (msg.type === 'hubScriptResult') {
    const r = msg.result || {};
    const output = document.getElementById('scriptOutput');
    const status = document.getElementById('scriptStatus');
    const runBtn = document.getElementById('btnRunScript');
    if (runBtn) runBtn.removeAttribute('disabled');

    if (output) {
      let text = r.stdout || '';
      if (r.stderr) {
        text += r.stderr;
        output.classList.add('sc-output-error');
      } else {
        output.classList.remove('sc-output-error');
      }
      if (r.duration_ms != null) {
        text += '\n── ' + r.duration_ms + ' ms';
      }
      output.textContent = text;
    }
    if (status) status.textContent = r.ok ? '✓' : '✗ Erreur';
    return;
  }

  if (msg.type === 'hubScriptLoaded') {
    const editor = document.getElementById('scriptEditor');
    if (editor && msg.content != null) {
      editor.value = msg.content;
      _saveStorage({ scriptCode: msg.content });
    }
    return;
  }

  if (msg.type === 'hubScriptSaved') {
    const status = document.getElementById('scriptStatus');
    if (status) status.textContent = '💾 Sauvegardé';
    return;
  }
  if (msg.type === 'hubStructsDone' || msg.type === 'hubStructsSaved') {
    const data = msg.data || {};
    typedDataUiState.structSource = String(data.source || '');
    typedDataUiState.structsLoaded = true;
    typedDataUiState.loadingStructs = false;
    syncTypedDataStructSelect(data.structs || [], typedDataUiState.appliedStructName || undefined);
    if (data.error) {
      setTypedDataStructStatus(String(data.error), true);
      typedDataUiState.pendingEditorOpen = false;
      updateHexSelectionSummary();
      return;
    }
    if (typedDataUiState.pendingEditorOpen) {
      typedDataUiState.pendingEditorOpen = false;
      openTypedStructEditor(typedDataUiState.structSource);
      return;
    }
    if (msg.type === 'hubStructsSaved') {
      const structCount = Array.isArray(data.structs) ? data.structs.length : 0;
      setTypedDataStructStatus(`${structCount} type(s) C disponible(s).`);
      const bp = getStaticBinaryPath();
      const section = document.getElementById('typedDataSection')?.value;
      if (bp && section) {
        setStaticLoading('typedDataContent', 'Analyse des donn\u00e9es\u2026');
        vscode.postMessage(buildTypedDataRequest(bp, { page: 0 }));
      }
    }
    updateHexSelectionSummary();
    return;
  }
  if (msg.type === 'hubTypedStructPreviewDone') {
    const data = msg.data || {};
    const request = msg.request || {};
    typedDataUiState.hexStructPreview = {
      loading: false,
      structName: String(request.structName || ''),
      addr: normalizeHexAddress(request.structAddr || ''),
      error: data.error ? String(data.error) : '',
      appliedStruct: data.applied_struct || null,
    };
    updateHexSelectionSummary();
    return;
  }
  if (msg.type === 'hubTypedDataDone') {
    const container = document.getElementById('typedDataContent');
    if (!container) return;
    const {
      section,
      entries,
      sections,
      structs,
      type,
      page,
      page_size,
      total_entries,
      applied_struct: appliedStruct,
      error,
    } = msg.data || {};
    const sectionSel = document.getElementById('typedDataSection');
    const structOffsetInput = document.getElementById('typedDataStructOffset');
    if (sectionSel && sections && sections.length > 0 && sectionSel.options.length <= 1) {
      sections.forEach(s => sectionSel.add(new Option(s, s)));
    }
    if (sectionSel && section) sectionSel.value = section;
    syncTypedDataStructSelect(structs || [], appliedStruct?.name || document.getElementById('typedDataStructSelect')?.value || '');
    if (error) {
      setTypedDataStructStatus(String(error), true);
      container.innerHTML = '<p class="hint">' + escapeHtml(error) + '</p>';
      return;
    }
    if (appliedStruct) {
      typedDataUiState.appliedStructName = String(appliedStruct.name || '');
      typedDataUiState.appliedStructOffset = '0x' + Number(appliedStruct.offset || 0).toString(16);
      typedDataUiState.appliedStructAddr = normalizeHexAddress(appliedStruct.addr || '');
      typedDataUiState.hexStructName = typedDataUiState.appliedStructName;
      const activeBinaryPath = getStaticBinaryPath();
      if (activeBinaryPath) {
        vscode.postMessage({
          type: 'hubSaveTypedStructRef',
          binaryPath: activeBinaryPath,
          appliedStruct,
        });
      }
      if (structOffsetInput) structOffsetInput.value = typedDataUiState.appliedStructOffset;
      setTypedDataStructStatus(
        `${String(appliedStruct.kind || 'struct')} ${typedDataUiState.appliedStructName} @ +${typedDataUiState.appliedStructOffset}`,
        false,
      );
      const summary = `
        <div class="typed-data-struct-summary">
          <strong>${escapeHtml(appliedStruct.name || '')}</strong>
          <span class="typed-data-struct-chip">${escapeHtml(String(appliedStruct.kind || 'struct'))}</span>
          <span class="typed-data-struct-chip">addr ${escapeHtml(appliedStruct.addr || '')}</span>
          <span class="typed-data-struct-chip">section ${escapeHtml(appliedStruct.section || section || '')}</span>
          <span class="typed-data-struct-chip">taille ${escapeHtml(String(appliedStruct.size || 0))} o</span>
          <span class="typed-data-struct-chip">align ${escapeHtml(String(appliedStruct.align || 1))}</span>
          <span class="typed-data-struct-chip">${escapeHtml(String((appliedStruct.fields || []).length))} champ(s)</span>
          ${typedDataUiState.appliedStructAddr ? `<span class="typed-data-quick-chip">sélection ${escapeHtml(typedDataUiState.appliedStructAddr)}</span>` : ''}
        </div>
      `;
      const rows = (appliedStruct.fields || []).map((field) => {
        const decodedCell = field.tag === 'ptr'
          ? '<code class="addr-link" data-addr="' + escapeHtml(field.decoded || '') + '">' + escapeHtml(field.decoded || '') + '</code>'
          : '<span>' + escapeHtml(field.decoded || '') + '</span>';
        return '<tr>' +
          '<td><code>' + escapeHtml(field.field_name || '') + '</code></td>' +
          '<td><code>' + escapeHtml(field.field_type || '') + '</code></td>' +
          '<td><code>0x' + escapeHtml(Number(field.offset || 0).toString(16)) + '</code></td>' +
          '<td><code class="addr-link" data-addr="' + escapeHtml(field.addr || '') + '">' + escapeHtml(field.addr || '') + '</code></td>' +
          '<td><code style="font-size:11px">' + escapeHtml(field.hex || '') + '</code></td>' +
          '<td>' + decodedCell + '</td>' +
          '</tr>';
      }).join('');
      container.innerHTML = summary +
        '<table class="data-table"><thead><tr>' +
        '<th>Champ</th><th>Type</th><th>Offset</th><th>Adresse</th><th>Hex</th><th>Valeur</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
      container.querySelectorAll('.addr-link[data-addr]').forEach((el) => {
        if (!el.dataset.addr) return;
        el.style.cursor = 'pointer';
        el.addEventListener('click', () =>
          vscode.postMessage({ type: 'hubGoToAddress', addr: el.dataset.addr, binaryPath: getStaticBinaryPath() }));
      });
      return;
    }
    typedDataUiState.appliedStructName = '';
    typedDataUiState.appliedStructAddr = '';
    setTypedDataStructStatus('');
    const entryList = entries || [];
    if (entryList.length === 0) {
      container.innerHTML = '<p class="hint">Section vide ou donn\u00e9es insuffisantes.</p>';
      return;
    }
    const TAG_COLORS = {
      string: '#88d8ff', wstring: '#88d8ff', ptr: '#88c0d0',
      u8: '#d8dee9', u16: '#d8dee9', u32: '#d8dee9', u64: '#d8dee9',
      f32: '#ebcb8b', f64: '#ebcb8b',
    };
    const currentPage = page || 0;
    const totalPages = Math.ceil((total_entries || entryList.length) / (page_size || 128));
    const paginHtml = totalPages > 1
      ? '<div class="typed-data-pagination">' +
        '<button id="btnTypedPrev" class="btn btn-sm"' + (currentPage === 0 ? ' disabled' : '') + '>&#9664;</button>' +
        '<span style="font-size:12px">Page ' + (currentPage + 1) + ' / ' + totalPages + '</span>' +
        '<button id="btnTypedNext" class="btn btn-sm"' + (currentPage >= totalPages - 1 ? ' disabled' : '') + '>&#9654;</button>' +
        '</div>'
      : '';
    const rows = entryList.map(e => {
      const tagColor = TAG_COLORS[e.tag] ? 'color:' + TAG_COLORS[e.tag] : '';
      const decodedCell = e.tag === 'ptr'
        ? '<code class="addr-link" data-addr="' + escapeHtml(e.decoded || '') + '" style="' + tagColor + '">' + escapeHtml(e.decoded || '') + '</code>'
        : '<span style="' + tagColor + '">' + escapeHtml(e.decoded || '') + '</span>';
      return '<tr>' +
        '<td><code>' + escapeHtml(e.offset !== undefined ? '0x' + Number(e.offset).toString(16) : '') + '</code></td>' +
        '<td><code class="addr-link" data-addr="' + escapeHtml(e.addr || '') + '">' + escapeHtml(e.addr || '') + '</code></td>' +
        '<td><code style="font-size:11px">' + escapeHtml(e.hex || '') + '</code></td>' +
        '<td>' + decodedCell + '</td>' +
        '</tr>';
    }).join('');
    container.innerHTML = paginHtml +
      '<table class="data-table"><thead><tr>' +
      '<th>Offset</th><th>Adresse</th><th>Hex</th><th>Valeur</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>' + paginHtml;
    container.querySelectorAll('.addr-link[data-addr]').forEach(el => {
      if (!el.dataset.addr) return;
      el.style.cursor = 'pointer';
      el.addEventListener('click', () =>
        vscode.postMessage({ type: 'hubGoToAddress', addr: el.dataset.addr, binaryPath: getStaticBinaryPath() }));
    });
    const bp = getStaticBinaryPath();
    document.getElementById('btnTypedPrev')?.addEventListener('click', () => {
      if (currentPage > 0)
        vscode.postMessage(buildTypedDataRequest(bp, { page: currentPage - 1, valueType: type || 'auto' }));
    });
    document.getElementById('btnTypedNext')?.addEventListener('click', () => {
      if (currentPage < totalPages - 1)
        vscode.postMessage(buildTypedDataRequest(bp, { page: currentPage + 1, valueType: type || 'auto' }));
    });
    return;
  }
  if (msg.type === 'hubExceptionHandlersDone') {
    const container = document.getElementById('exceptionsContent');
    const countEl = document.getElementById('exceptionsCount');
    if (!container) return;
    const { entries, error } = msg.data || {};
    if (error) {
      container.innerHTML = '<p class="hint">' + escapeHtml(error) + '</p>';
      return;
    }
    const list = entries || [];
    if (list.length === 0) {
      container.innerHTML = '<p class="hint">Aucun gestionnaire d\'exception dans ce binaire.</p>';
      if (countEl) countEl.textContent = '';
      return;
    }
    const badgeClass = (t) =>
      t === 'SEH' ? 'exc-badge-seh' : (t && t.includes('C++')) ? 'exc-badge-cpp' : 'exc-badge-dwarf';
    function renderExc(filterStr) {
      const f = (filterStr || '').toLowerCase();
      const visible = f
        ? list.filter(e => (e.func_start || '').toLowerCase().includes(f) ||
                           (e.handler_type || '').toLowerCase().includes(f))
        : list;
      if (countEl) countEl.textContent = visible.length + ' / ' + list.length;
      const rows = visible.map(e =>
        '<tr>' +
        '<td><code class="addr-link" data-addr="' + escapeHtml(e.func_start || '') + '">' + escapeHtml(e.func_start || '\u2014') + '</code></td>' +
        '<td><code>' + escapeHtml(e.func_end || '\u2014') + '</code></td>' +
        '<td><span class="exc-badge ' + badgeClass(e.handler_type) + '">' + escapeHtml(e.handler_type || '\u2014') + '</span></td>' +
        '<td>' + (e.handler ? '<code class="addr-link" data-addr="' + escapeHtml(e.handler) + '">' + escapeHtml(e.handler) + '</code>' : '\u2014') + '</td>' +
        '</tr>'
      ).join('');
      container.innerHTML =
        '<table class="data-table"><thead><tr>' +
        '<th>Fonction</th><th>Fin</th><th>Type</th><th>Handler</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
      container.querySelectorAll('.addr-link[data-addr]').forEach(el => {
        if (!el.dataset.addr) return;
        el.style.cursor = 'pointer';
        el.addEventListener('click', () =>
          vscode.postMessage({ type: 'hubGoToAddress', addr: el.dataset.addr, binaryPath: getStaticBinaryPath() }));
      });
    }
    const searchEl = document.getElementById('exceptionsSearch');
    const currentSearch = searchEl ? searchEl.value : '';
    if (searchEl) {
      const newEl = searchEl.cloneNode(true);
      searchEl.parentNode.replaceChild(newEl, searchEl);
      newEl.addEventListener('input', () => renderExc(newEl.value));
    }
    renderExc(currentSearch);
    return;
  }
  if (msg.type === 'hubPeResourcesDone') {
    const container = document.getElementById('peResourcesContent');
    if (!container) return;
    const { resources, error, applicable, message, format } = msg.data || {};
    if (error) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = error;
      container.replaceChildren(p);
      return;
    }
    if (applicable === false) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = message || `Cette vue s’applique uniquement aux binaires PE${format ? ` (${format})` : ''}.`;
      container.replaceChildren(p);
      return;
    }
    if (!resources || resources.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucune ressource dans ce binaire.';
      container.replaceChildren(p);
      return;
    }
    // Group by type
    const byType = {};
    for (const r of resources) {
      if (!byType[r.type]) byType[r.type] = [];
      byType[r.type].push(r);
    }
    const tree = document.createElement('div');
    tree.className = 'resource-tree';
    const detail = document.createElement('div');
    detail.className = 'resource-detail';
    detail.style.display = 'none';

    for (const [type, items] of Object.entries(byType)) {
      const typeRow = document.createElement('div');
      typeRow.className = 'resource-tree-type';
      typeRow.textContent = '\u25B8 ' + type + ' (' + items.length + ')';
      const itemsDiv = document.createElement('div');
      itemsDiv.className = 'resource-tree-items';
      itemsDiv.style.display = 'none';

      typeRow.addEventListener('click', () => {
        const visible = itemsDiv.style.display !== 'none';
        itemsDiv.style.display = visible ? 'none' : '';
        typeRow.textContent = (visible ? '\u25B8 ' : '\u25BE ') + type + ' (' + items.length + ')';
      });

      items.forEach((r) => {
        const item = document.createElement('div');
        item.className = 'resource-tree-item';
        item.textContent = 'ID ' + r.id + ' \u2014 Lang ' + r.lang + ' \u2014 ' + r.size + ' o';
        item.addEventListener('click', () => {
          detail.style.display = '';
          let text = 'Type: ' + r.type + '\nID: ' + r.id + '\nLang: ' + r.lang + '\nSize: ' + r.size + ' octets\n\n';
          if (r.decoded) text += 'Decoded:\n' + JSON.stringify(r.decoded, null, 2) + '\n\n';
          text += 'Hex preview:\n' + (r.hex_preview || '\u2014');
          detail.textContent = text;
        });
        itemsDiv.appendChild(item);
      });
      tree.appendChild(typeRow);
      tree.appendChild(itemsDiv);
    }
    container.replaceChildren(tree, detail);
    return;
  }
});

// ── Binary Diff buttons ──────────────────────────────────────────────────────
document.getElementById('btnBindiffBrowseA')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubPickFile', target: 'bindiffPathA' });
});
document.getElementById('btnBindiffBrowseB')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubPickFile', target: 'bindiffPathB' });
});
document.getElementById('btnRunBindiff')?.addEventListener('click', () => {
  const binaryA = document.getElementById('bindiffPathA')?.value?.trim();
  const binaryB = document.getElementById('bindiffPathB')?.value?.trim();
  if (!binaryA || !binaryB) {
    const resultsEl = document.getElementById('bindiffResults');
    if (resultsEl) {
      while (resultsEl.firstChild) resultsEl.removeChild(resultsEl.firstChild);
      const p = document.createElement('p');
      p.className = 'error-text';
      p.textContent = 'Renseignez les chemins des deux binaires.';
      resultsEl.appendChild(p);
    }
    return;
  }
  const threshold = parseFloat(document.getElementById('bindiffThreshold')?.value || '0.60');
  document.getElementById('btnRunBindiff')?.setAttribute('disabled', 'true');
  vscode.postMessage({ type: 'hubLoadBindiff', binaryA, binaryB, threshold });
});

// ── Settings ─────────────────────────────────────────────────────────────────
let _settingsCache = null;
let _settingsDebounce = null;

function renderStaticFeatureSettings(settings = _settingsCache || {}) {
  const checklist = document.getElementById('staticFeatureChecklist');
  if (!checklist) return;
  if (checklist.children.length === 0) {
    Object.entries(GROUPS).forEach(([groupId, tabs]) => {
      tabs.forEach((tabId) => {
        const label = document.createElement('label');
        label.className = 'settings-feature-check';
        label.classList.toggle('is-essential', STATIC_SIMPLE_FEATURES.has(tabId));
        label.title = `${GROUP_LABELS[tabId] || tabId} - ${groupId.toUpperCase()}`;

        const input = document.createElement('input');
        input.type = 'checkbox';
        input.dataset.staticFeature = tabId;

        const text = document.createElement('span');
        text.textContent = GROUP_LABELS[tabId] || tabId;

        label.append(input, text);
        checklist.appendChild(label);
      });
    });
  }

  const savedFeatures = Array.isArray(settings.enabledStaticFeatures)
    ? settings.enabledStaticFeatures.filter((tabId) => STATIC_FEATURE_IDS.includes(tabId))
    : [];
  const mode = settings.interfaceMode === 'simple' ? 'simple' : 'advanced';
  const checkedFeatures = mode === 'simple'
    ? STATIC_SIMPLE_FEATURES
    : new Set(savedFeatures.length ? savedFeatures : STATIC_FEATURE_IDS);
  checklist.querySelectorAll('[data-static-feature]').forEach((input) => {
    input.checked = checkedFeatures.has(input.dataset.staticFeature);
  });
}

function syncStaticInterfaceModeControls(settings = _settingsCache || {}) {
  const mode = settings.interfaceMode === 'simple' ? 'simple' : 'advanced';
  const hiddenInput = document.getElementById('settingInterfaceMode');
  const picker = document.getElementById('staticFeatureSettings');
  if (hiddenInput) hiddenInput.value = mode;
  document.querySelectorAll('[data-interface-mode]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.interfaceMode === mode);
    btn.setAttribute('aria-pressed', btn.dataset.interfaceMode === mode ? 'true' : 'false');
  });
  if (picker) {
    picker.classList.toggle('is-disabled', mode === 'simple');
    picker.querySelectorAll('input, button').forEach((control) => {
      control.disabled = mode === 'simple';
    });
  }
}

function refreshStaticNavigationForSettings() {
  updateActiveContextBars(window._lastDisasmAddr);
  if (document.getElementById('panel-static')?.classList.contains('active')) {
    const saved = _loadStorage();
    showGroup(saved.group || 'code', saved.tab || getActiveStaticTab());
  }
}

function _applySettings(settings) {
  _settingsCache = settings;
  document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
    const key = el.dataset.key;
    if (!(key in settings)) return;
    if (el.type === 'checkbox') el.checked = settings[key] === true;
    else el.value = String(settings[key]);
  });
  renderStaticFeatureSettings(settings);
  syncStaticInterfaceModeControls(settings);
  if (settings.codeFontSize) {
    document.documentElement.style.setProperty('--code-font-size', settings.codeFontSize + 'px');
  }
  // Pre-fill existing panel selects with defaults
  const mappings = { stringsEncoding: 'stringsEncoding', stringsMinLen: 'stringsMinLen', asmSyntax: 'disasmSyntax' };
  for (const [settingKey, elId] of Object.entries(mappings)) {
    const el = document.getElementById(elId);
    if (el && settings[settingKey] != null) el.value = String(settings[settingKey]);
  }
  if (Object.keys(_decompilerAvailability).length || Object.keys(_decompilerMeta).length) {
    populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
    _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  }
  refreshStaticNavigationForSettings();
}

function _collectSettings() {
  const settings = { ...(_settingsCache || {}) };
  document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
    const key = el.dataset.key;
    const type = el.dataset.type;
    if (el.type === 'checkbox') settings[key] = el.checked;
    else if (type === 'float') settings[key] = parseFloat(el.value);
    else if (type === 'int') settings[key] = parseInt(el.value, 10);
    else settings[key] = el.value;
  });
  settings.decompilerLocalPaths = {};
  document.querySelectorAll('#panel-options [data-decompiler-local-path]').forEach((el) => {
    const id = String(el.dataset.decompilerLocalPath || '').trim();
    const value = String(el.value || '').trim();
    if (id && value) settings.decompilerLocalPaths[id] = value;
  });
  settings.interfaceMode = document.getElementById('settingInterfaceMode')?.value === 'simple' ? 'simple' : 'advanced';
  const selectedFeatures = settings.interfaceMode === 'simple'
    ? Array.from(STATIC_SIMPLE_FEATURES)
    : Array.from(document.querySelectorAll('[data-static-feature]'))
      .filter((input) => input.checked)
      .map((input) => input.dataset.staticFeature)
      .filter((tabId) => STATIC_FEATURE_IDS.includes(tabId));
  settings.enabledStaticFeatures = selectedFeatures.length ? selectedFeatures : ['disasm'];
  return settings;
}

function _getDecompilerLocalPathVisibility(key, hasCustomPath = false) {
  const normalizedKey = String(key || '').trim();
  if (!normalizedKey) return 'hidden';
  const current = String(_decompilerLocalUiState.visibilityById?.[normalizedKey] || '').trim();
  if (current === 'visible' || current === 'hidden') return current;
  return hasCustomPath ? 'visible' : 'hidden';
}

function _applyDecompilerLocalPathVisibility(key, visibility) {
  const normalizedKey = String(key || '').trim();
  const normalizedVisibility = String(visibility || 'hidden').trim() === 'visible' ? 'visible' : 'hidden';
  if (!normalizedKey) return;
  _decompilerLocalUiState.visibilityById[normalizedKey] = normalizedVisibility;
  document.querySelectorAll(`#panel-options [data-decompiler-local-toggle="${normalizedKey}"]`).forEach((button) => {
    const isVisible = normalizedVisibility === 'visible';
    button.setAttribute('aria-expanded', isVisible ? 'true' : 'false');
    const icon = button.querySelector('.decompiler-card-toggle-icon');
    if (icon) icon.textContent = isVisible ? '−' : '+';
  });
  document.querySelectorAll(`#panel-options [data-decompiler-local-panel="${normalizedKey}"]`).forEach((panel) => {
    const isVisible = normalizedVisibility === 'visible';
    panel.hidden = !isVisible;
    panel.classList.toggle('is-hidden', !isVisible);
  });
}

function _scheduleSave() {
  clearTimeout(_settingsDebounce);
  _settingsDebounce = setTimeout(() => {
    const settings = _collectSettings();
    _settingsCache = settings;
    syncStaticInterfaceModeControls(settings);
    refreshStaticNavigationForSettings();
    vscode.postMessage({ type: 'hubSaveSettings', settings });
    if (isStaticTabActive('decompile')) {
      vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
      requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
    }
  }, 500);
}

document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
  el.addEventListener('change', _scheduleSave);
  el.addEventListener('input', _scheduleSave);
});

document.querySelectorAll('[data-interface-mode]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.interfaceMode === 'simple' ? 'simple' : 'advanced';
    const input = document.getElementById('settingInterfaceMode');
    if (input) input.value = mode;
    _settingsCache = { ...(_settingsCache || {}), interfaceMode: mode };
    if (mode === 'simple') {
      document.querySelectorAll('[data-static-feature]').forEach((featureInput) => {
        featureInput.checked = STATIC_SIMPLE_FEATURES.has(featureInput.dataset.staticFeature);
      });
      _settingsCache.enabledStaticFeatures = Array.from(STATIC_SIMPLE_FEATURES);
    }
    syncStaticInterfaceModeControls(_settingsCache);
    refreshStaticNavigationForSettings();
    _scheduleSave();
  });
});

document.getElementById('staticFeatureChecklist')?.addEventListener('change', (event) => {
  if (!event.target?.matches?.('[data-static-feature]')) return;
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('btnStaticFeaturesAll')?.addEventListener('click', () => {
  document.querySelectorAll('[data-static-feature]').forEach((input) => { input.checked = true; });
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('btnStaticFeaturesEssential')?.addEventListener('click', () => {
  document.querySelectorAll('[data-static-feature]').forEach((input) => {
    input.checked = STATIC_SIMPLE_FEATURES.has(input.dataset.staticFeature);
  });
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('panel-options')?.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-browse]');
  if (!btn) return;
  vscode.postMessage({ type: 'hubPickFile', target: btn.dataset.browse });
});

document.getElementById('decompilerStatusList')?.addEventListener('click', (event) => {
  const localToggle = event.target.closest('[data-decompiler-local-toggle]');
  if (localToggle) {
    event.preventDefault();
    event.stopPropagation();
    const key = String(localToggle.getAttribute('data-decompiler-local-toggle') || '').trim();
    if (!key) return;
    const nextVisibility = _getDecompilerLocalPathVisibility(key) === 'visible' ? 'hidden' : 'visible';
    _applyDecompilerLocalPathVisibility(key, nextVisibility);
    return;
  }
  const interactive = event.target.closest('input, button, select, textarea, option');
  const target = event.target.closest('[data-select-decompiler]');
  if (!target || (interactive && !interactive.hasAttribute('data-select-decompiler'))) return;
  const id = String(target.getAttribute('data-select-decompiler') || '').trim();
  if (!id) return;
  _selectedDecompilerCardId = id;
  if (_decompilerAvailability[id] !== false) {
    _setActiveDecompilerSource(id);
  }
  _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
  if (isStaticTabActive('decompile')) requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
});

document.getElementById('decompilerStatusList')?.addEventListener('keydown', (event) => {
  if (event.target?.matches?.('input, button, select, textarea, option')) return;
  const target = event.target.closest('[data-select-decompiler]');
  if (!target) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  const id = String(target.getAttribute('data-select-decompiler') || '').trim();
  if (!id) return;
  _selectedDecompilerCardId = id;
  if (_decompilerAvailability[id] !== false) {
    _setActiveDecompilerSource(id);
  }
  _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
  if (isStaticTabActive('decompile')) requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
});

document.getElementById('panel-options')?.addEventListener('input', (event) => {
  if (event.target?.matches?.('[data-decompiler-local-path]')) {
    const key = event.target.dataset.decompilerLocalPath;
    const value = event.target.value;
    document.querySelectorAll(`#panel-options [data-decompiler-local-path="${key}"]`).forEach((input) => {
      if (input !== event.target) input.value = value;
    });
    _scheduleSave();
  }
});

document.getElementById('panel-options')?.addEventListener('change', (event) => {
  if (event.target?.matches?.('[data-decompiler-local-path]')) {
    const key = event.target.dataset.decompilerLocalPath;
    const value = event.target.value;
    document.querySelectorAll(`#panel-options [data-decompiler-local-path="${key}"]`).forEach((input) => {
      if (input !== event.target) input.value = value;
    });
    _scheduleSave();
  }
});

document.getElementById('btnResetSettings')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubResetSettings' });
});

// ─── Gestionnaire de décompilateurs (panneau Options) ──────────────────────

/**
 * Construit et affiche la grille de statut des décompilateurs.
 * @param {object} available  — résultat de list_available_decompilers()
 */
function _renderDecompilerStatusList(available) {
  const container = document.getElementById('decompilerStatusList');
  const summary = document.getElementById('decompilerStatusSummary');
  if (!container) return;

  const meta = available._meta || {};
  const dockerImages = meta.docker_images || {};
  const dockerAvail  = meta.docker_images_available || {};
  const localAvail = meta.local_available || {};
  const customLabels = meta.custom_labels || {};
  const hiddenBuiltins = meta.hidden_builtins || [];
  const localPaths = _settingsCache?.decompilerLocalPaths && typeof _settingsCache.decompilerLocalPaths === 'object'
    ? _settingsCache.decompilerLocalPaths
    : {};
  const activeId = _getActiveDecompilerSource();

  const BUILTIN_ORDER = ['ghidra', 'retdec', 'angr'];
  const allIds = [
    ...BUILTIN_ORDER.filter(id => id in available),
    ...Object.keys(available).filter(id => !id.startsWith('_') && !BUILTIN_ORDER.includes(id)),
  ];

  if (_selectedDecompilerCardId && !allIds.includes(_selectedDecompilerCardId)) {
    _selectedDecompilerCardId = '';
  }
  const selectedId = _selectedDecompilerCardId || (activeId !== 'auto' ? activeId : '');

  if (allIds.length === 0 && hiddenBuiltins.length === 0) {
    if (summary) summary.innerHTML = '';
    container.innerHTML = '<div class="decompiler-status-loading">Aucun décompilateur détecté.</div>';
    return;
  }

  const activeProvider = String(meta.provider || _getConfiguredDecompilerProvider() || 'auto').trim() || 'auto';
  const availableCount = allIds.filter((id) => !!available[id]).length;
  const localReadyCount = allIds.filter((id) => !!localAvail[id]).length;
  const dockerConfiguredCount = allIds.filter((id) => !!dockerImages[id]).length;

  if (summary) {
    summary.innerHTML = [
      `<div class="decompiler-summary-chip decompiler-summary-chip--accent"><strong>Provider</strong> ${escapeHtml(activeProvider)}</div>`,
      `<div class="decompiler-summary-chip"><strong>${availableCount}/${allIds.length}</strong> prêts maintenant</div>`,
      `<div class="decompiler-summary-chip"><strong>${localReadyCount}</strong> prêts en local</div>`,
      `<div class="decompiler-summary-chip"><strong>${dockerConfiguredCount}</strong> avec image Docker</div>`,
    ].join('');
  }

  const cards = allIds.map(id => {
    const avail = !!available[id];
    const isCustom = !(BUILTIN_ORDER.includes(id));
    const label = customLabels[id] || _DECOMPILER_LABELS[id] || id;
    const image = dockerImages[id] || '';
    const dockerOk = image ? !!dockerAvail[id] : null;
    const localOk = !!localAvail[id];
    const localSpec = _getLocalPathSpecForDecompiler(id);
    const localPathValue = localSpec ? String(localPaths[localSpec.id] || '') : '';
    const localStatus = localOk
      ? 'Backend prêt'
      : (localSpec ? 'Backend non prêt' : 'Non pris en charge');
    const localStatusClass = localOk
      ? 'decompiler-badge--local-ok'
      : (localSpec ? 'decompiler-badge--local-err' : 'decompiler-badge--docker-off');
    const pathStatus = !localSpec
      ? ''
      : (localPathValue ? 'Chemin configuré' : 'Auto-détection');
    const localDetectionHint = _describeLocalDetectionHint(id, localSpec, localPathValue);
    const dockerStatus = !image
      ? 'Non configuré'
      : (dockerOk ? 'Image prête' : 'Image absente');
    const dockerStatusClass = !image
      ? 'decompiler-badge--docker-off'
      : (dockerOk ? 'decompiler-badge--docker-ok' : 'decompiler-badge--docker-err');
    const availabilityLabel = avail ? 'Prêt' : 'Indisponible';
    const availabilityClass = avail ? 'decompiler-card-state--ready' : 'decompiler-card-state--off';
    const captionBits = [`Provider ${activeProvider}`];
    if (localSpec) captionBits.push(localOk ? 'backend local détecté' : 'backend local indisponible');
    if (image) captionBits.push(dockerOk ? 'image Docker prête' : 'image Docker à préparer');

    const statusDot = avail
      ? '<span class="decompiler-status-dot decompiler-status-dot--ok" title="Disponible"></span>'
      : '<span class="decompiler-status-dot decompiler-status-dot--err" title="Non disponible"></span>';

    const localBadge = `<span class="decompiler-badge ${localStatusClass}">${escapeHtml(localStatus)}</span>`;
    const dockerBadge = `<span class="decompiler-badge ${dockerStatusClass}"${image ? ` title="${escapeHtml(image)}"` : ''}>${escapeHtml(dockerStatus)}</span>`;

    const customTag = isCustom ? ' <span class="decompiler-badge decompiler-badge--custom">custom</span>' : '';
    const isSelected = id === selectedId;
    const isActiveSource = id === activeId && activeId !== 'auto';
    const pathInputId = localSpec ? `settingDecompilerLocalPath_${id}` : '';
    const localVisibility = localSpec
      ? _getDecompilerLocalPathVisibility(localSpec.id, !!localPathValue)
      : 'hidden';
    const pathBlock = localSpec
      ? `<div class="decompiler-card-body">
          <button
            type="button"
            class="decompiler-card-toggle"
            data-decompiler-local-toggle="${localSpec.id}"
            aria-expanded="${localVisibility === 'visible' ? 'true' : 'false'}"
            aria-controls="decompilerLocalPanel_${localSpec.id}"
          >
            <span class="decompiler-card-toggle-copy">
              <span class="decompiler-card-toggle-title">Exécution locale</span>
              <span class="decompiler-card-toggle-subtitle">${escapeHtml(localPathValue ? 'Chemin local configuré' : 'Configurer un chemin local si besoin')}</span>
            </span>
            <span class="decompiler-card-toggle-icon" aria-hidden="true">${localVisibility === 'visible' ? '−' : '+'}</span>
          </button>
          <div id="decompilerLocalPanel_${localSpec.id}" class="decompiler-card-local-panel${localVisibility === 'visible' ? '' : ' is-hidden'}" data-decompiler-local-panel="${localSpec.id}"${localVisibility === 'visible' ? '' : ' hidden'}>
            <div class="decompiler-card-path-hint">${escapeHtml(localSpec.hint)}</div>
            <div class="decompiler-card-path-hint">${escapeHtml(localDetectionHint)}</div>
            <div class="decompiler-card-path-row">
              <input id="${pathInputId}" class="input-inner settings-input settings-mono decompiler-card-path-input" type="text" value="${escapeHtml(localPathValue)}" placeholder="${escapeHtml(localSpec.placeholder)}" data-decompiler-local-path="${localSpec.id}" />
              <button type="button" class="btn btn-secondary btn-sm" data-browse="${pathInputId}">Parcourir</button>
            </div>
          </div>
        </div>`
      : '';

    // Boutons d'actions inline dans la card
    const editBtn = isCustom
      ? `<button type="button" class="btn btn-secondary btn-xs decompiler-card-btn-edit" data-decompiler-edit="${id}" title="Modifier ${escapeHtml(label)}">✎ Modifier</button>`
      : '';
    const hideOrDeleteBtn = isCustom
      ? `<button type="button" class="btn btn-xs btn-danger-soft decompiler-card-btn-remove" data-decompiler-remove="${id}" title="Supprimer ${escapeHtml(label)}">✕ Supprimer</button>`
      : '';

    return `<article class="decompiler-card${isSelected ? ' decompiler-card--selected' : ''}${isActiveSource ? ' decompiler-card--active' : ''}${avail ? '' : ' decompiler-card--disabled'}" data-select-decompiler="${id}" role="button" tabindex="0" title="Sélectionner ${escapeHtml(label)}" aria-pressed="${isActiveSource ? 'true' : 'false'}">
      <div class="decompiler-card-topline">
        <div class="decompiler-card-title-wrap">
          <div class="decompiler-card-head">
            <span class="decompiler-row-status">${statusDot}</span>
            <span class="decompiler-row-name">${escapeHtml(label)}${customTag}</span>
            <span class="decompiler-card-id">${escapeHtml(id)}</span>
          </div>
          <p class="decompiler-card-caption">${escapeHtml(captionBits.join(' • '))}</p>
        </div>
        <div class="decompiler-card-topright">
          ${isActiveSource ? '<span class="decompiler-card-pin decompiler-card-pin--active">✓ actif</span>' : ''}
          <div class="decompiler-card-state ${availabilityClass}">${availabilityLabel}</div>
        </div>
      </div>

      <div class="decompiler-row-badges">${localBadge}${dockerBadge}</div>

      <div class="decompiler-card-grid">
        <div class="decompiler-card-metric">
          <span class="decompiler-card-metric-label">Local</span>
          <span class="decompiler-card-metric-value">${escapeHtml(localStatus)}${pathStatus ? `<br>${escapeHtml(pathStatus)}` : ''}${localSpec && localPathValue ? `<br>${escapeHtml(localPathValue)}` : ''}${localDetectionHint ? `<br>${escapeHtml(localDetectionHint)}` : ''}</span>
        </div>
        <div class="decompiler-card-metric">
          <span class="decompiler-card-metric-label">Docker</span>
          <span class="decompiler-card-metric-value">${escapeHtml(dockerStatus)}${image ? `<br>${escapeHtml(image)}` : ''}${image ? '<br>Container à la demande, supprimé après usage' : ''}</span>
        </div>
      </div>

      ${pathBlock}
      <div class="decompiler-card-actions decompiler-card-actions--inline">
        ${editBtn}
        ${hideOrDeleteBtn}
      </div>
    </article>`;
  });

  // Section builtins masqués (restauration)
  let hiddenSection = '';
  if (hiddenBuiltins.length > 0) {
    const hiddenItems = hiddenBuiltins.map(id => {
      const label = _DECOMPILER_LABELS[id] || id;
      return `<span class="decompiler-hidden-chip">
        ${escapeHtml(label)}
        <button type="button" class="decompiler-hidden-restore" data-decompiler-restore="${id}" title="Restaurer ${escapeHtml(label)}">↩</button>
      </span>`;
    }).join('');
    hiddenSection = `<div class="decompiler-hidden-section">
      <span class="decompiler-hidden-label">Masqués :</span>
      ${hiddenItems}
    </div>`;
  }

  container.innerHTML = cards.join('') + hiddenSection;
  container.querySelectorAll('[data-decompiler-local-toggle]').forEach((button) => {
    _applyDecompilerLocalPathVisibility(
      button.getAttribute('data-decompiler-local-toggle'),
      button.getAttribute('aria-expanded') === 'true' ? 'visible' : 'hidden',
    );
  });
  _updateDecompilerActionButtons();

  // Délégation d'events pour les boutons inline dans les cards
  container.querySelectorAll('[data-decompiler-edit]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerEdit;
      vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerEdit', requestId: null, args: [id] });
    });
  });
  container.querySelectorAll('[data-decompiler-remove]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerRemove;
      vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerRemove', requestId: null, args: [id] });
    });
  });
  container.querySelectorAll('[data-decompiler-hide]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerHide;
      vscode.postMessage({ type: 'hubHideBuiltinDecompiler', id });
    });
  });
  container.querySelectorAll('[data-decompiler-restore]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerRestore;
      vscode.postMessage({ type: 'hubRestoreBuiltinDecompiler', id });
    });
  });
}

// ─── Gestionnaire boutons décompilateurs ──────────────────────────────────────

/** Compteur de requêtes en vol pour gérer les états loading */
let _decompilerCmdPending = new Map(); // requestId → { btnId, label }
let _decompilerCmdSeq = 0;

/**
 * Lance une commande décompilateur depuis le webview avec feedback visuel.
 * @param {string} command   — ID de la commande VS Code à exécuter
 * @param {string} btnId     — ID du bouton HTML à mettre en loading
 * @param {string} loadLabel — Texte affiché pendant le chargement
 */
function _runDecompilerCommand(command, btnId, loadLabel, args = []) {
  const btn = document.getElementById(btnId);
  if (!btn || btn.disabled) return;

  const requestId = `dcmd_${++_decompilerCmdSeq}`;
  _decompilerCmdPending.set(requestId, { btnId, originalLabel: btn.textContent });

  // Désactiver tous les boutons d'action pendant qu'une commande est en vol
  _setDecompilerButtonsLocked(true, btnId);
  btn.textContent = loadLabel;
  btn.classList.add('btn--loading');

  vscode.postMessage({ type: 'hubExecuteCommand', command, requestId, args });
}

/** Callback appelé quand `hubCommandResult` arrive depuis l'extension */
function _onDecompilerCommandResult(msg) {
  const pending = msg.requestId ? _decompilerCmdPending.get(msg.requestId) : null;
  if (pending) {
    _decompilerCmdPending.delete(msg.requestId);
    const btn = document.getElementById(pending.btnId);
    if (btn) {
      btn.textContent = pending.originalLabel;
      btn.classList.remove('btn--loading');
    }
  }
  // Déverrouiller tous les boutons
  _setDecompilerButtonsLocked(false);

  // Feedback visuel bref sur le bouton (flash vert/rouge)
  if (pending) {
    const btn = document.getElementById(pending.btnId);
    if (btn && msg.status === 'done') {
      btn.classList.add('btn--flash-ok');
      setTimeout(() => btn.classList.remove('btn--flash-ok'), 1200);
    } else if (btn && msg.status === 'error') {
      btn.classList.add('btn--flash-err');
      setTimeout(() => btn.classList.remove('btn--flash-err'), 1500);
    }
  }

  // La liste est déjà rafraîchie via hubDecompilerList envoyé par staticHandlers
  // Mais si c'est une action sans refresh (test, openConfig), pas besoin de rien faire
}

/** Verrouille/déverrouille les boutons d'action (sauf le bouton actif lui-même) */
function _setDecompilerButtonsLocked(locked, exceptBtnId = null) {
  const ACTION_BTNS = ['btnDecompilerAdd', 'btnDecompilerEdit', 'btnDecompilerRemove', 'btnDecompilerTest'];
  for (const id of ACTION_BTNS) {
    if (id === exceptBtnId) continue;
    const btn = document.getElementById(id);
    if (btn) btn.disabled = locked;
  }
}

// ── Bouton Actualiser ──────────────────────────────────────────────────────────
document.getElementById('btnDecompilerRefresh')?.addEventListener('click', () => {
  const btn = document.getElementById('btnDecompilerRefresh');
  if (btn) { btn.disabled = true; btn.classList.add('btn--loading'); }
  const list = document.getElementById('decompilerStatusList');
  if (list) list.innerHTML = '<div class="decompiler-status-loading"><span class="decompiler-status-dot decompiler-status-dot--pending"></span> Interrogation…</div>';
  vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
  // Réactiver après réception de hubDecompilerList (géré plus haut)
  // Sécurité : timeout si pas de réponse
  setTimeout(() => {
    if (btn) { btn.disabled = false; btn.classList.remove('btn--loading'); }
  }, 8000);
});

// Réactiver le bouton refresh dès réception de la liste
const _origHandleDecompilerList = window._hubDecompilerListHook;
(function _patchDecompilerListForRefreshBtn() {
  const origHandler = window.addEventListener;
  // On intercepte via l'event hubDecompilerList déjà traité plus haut dans hub.js
  // Le plus simple : on observe quand _renderDecompilerStatusList est appelé
  const _origRender = _renderDecompilerStatusList;
  // Re-définir n'est pas possible (déclaré function), donc on patch via MutationObserver sur le container
  const list = document.getElementById('decompilerStatusList');
  if (list) {
    new MutationObserver(() => {
      const btn = document.getElementById('btnDecompilerRefresh');
      if (btn && !list.querySelector('.decompiler-status-loading')) {
        btn.disabled = false;
        btn.classList.remove('btn--loading');
      }
    }).observe(list, { childList: true });
  }
})();

// ── Bouton Ajouter ─────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerAdd')?.addEventListener('click', () => {
  _runDecompilerCommand('pileOuFace.decompilerAdd', 'btnDecompilerAdd', '…');
});

// ── Bouton Modifier ────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerEdit')?.addEventListener('click', () => {
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();
  if (_decompilerMeta?.custom_labels?.[selectedId]) {
    _runDecompilerCommand('pileOuFace.decompilerEdit', 'btnDecompilerEdit', '…', [selectedId]);
    return;
  }
  _runDecompilerCommand('pileOuFace.decompilerEdit', 'btnDecompilerEdit', '…');
});

// ── Bouton Supprimer ───────────────────────────────────────────────────────────
document.getElementById('btnDecompilerRemove')?.addEventListener('click', () => {
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();
  if (_decompilerMeta?.custom_labels?.[selectedId]) {
    _runDecompilerCommand('pileOuFace.decompilerRemove', 'btnDecompilerRemove', '…', [selectedId]);
    return;
  }
  _runDecompilerCommand('pileOuFace.decompilerRemove', 'btnDecompilerRemove', '…');
});

// ── Bouton Tester ──────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerTest')?.addEventListener('click', () => {
  const btn = document.getElementById('btnDecompilerTest');
  if (!btn || btn.disabled) return;
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();

  const requestId = `dcmd_${++_decompilerCmdSeq}`;
  _decompilerCmdPending.set(requestId, { btnId: 'btnDecompilerTest', originalLabel: btn.textContent });
  _setDecompilerButtonsLocked(true, 'btnDecompilerTest');
  btn.textContent = '…';
  btn.classList.add('btn--loading');

  vscode.postMessage({
    type: 'hubExecuteCommand',
    command: 'pileOuFace.decompilerTest',
    requestId,
    args: selectedId && selectedId !== 'auto' ? [selectedId] : [],
  });
});

// ── Bouton Config JSON ─────────────────────────────────────────────────────────
document.getElementById('btnDecompilerOpenConfig')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerOpenConfig', requestId: null });
});

// ── Actualisation automatique quand on ouvre le panneau Options ───────────────
(function _hookOptionsPanel() {
  let _lastOptionsVisible = false;
  const observer = new MutationObserver(() => {
    const panel = document.getElementById('panel-options');
    const isVisible = panel && !panel.classList.contains('hidden') && panel.style.display !== 'none';
    if (isVisible && !_lastOptionsVisible) {
      // Vient d'être ouvert
      const list = document.getElementById('decompilerStatusList');
      if (list && (list.querySelector('.decompiler-status-loading') || list.children.length === 0)) {
        vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
      }
    }
    _lastOptionsVisible = !!isVisible;
  });
  // Observer le conteneur principal pour détecter les changements de visibilité
  const root = document.querySelector('.hub-panels') || document.body;
  observer.observe(root, { attributes: true, subtree: true, attributeFilter: ['class', 'style'] });
})();

// ─── Fin gestionnaire décompilateurs ───────────────────────────────────────

// Request symbols when binary path changes
binaryPathInput?.addEventListener('blur', () => {
  const bp = binaryPathInput?.value?.trim();
  if (!bp) return;
  setDynamicTraceStatus('Actualisation du profil binaire...');
  requestRunTraceInit(null, bp);
  requestSymbols();
});

binaryPathInput?.addEventListener('input', () => {
  if (staticBinaryInput) staticBinaryInput.value = binaryPathInput.value;
});

argvPayloadInput?.addEventListener('input', () => {
  updateArgvPayloadHint();
  const raw = argvPayloadInput.value.trim();
  if (!raw) {
    setDynamicTraceStatus('Prêt.');
    return;
  }
  try {
    const parsed = parsePayloadExpressionPreview(raw);
    setDynamicTraceStatus(`${dynamicPayloadTargetLabel(getDynamicEffectivePayloadTarget())} prêt: ${parsed.bytes} byte(s).`);
  } catch (_) {
    setDynamicTraceStatus('Expression payload invalide.');
  }
});

dynamicPayloadTargetMode?.addEventListener('change', () => {
  dynamicTraceInitState.payloadTargetMode = getDynamicPayloadTargetMode();
  updateArgvPayloadHint();
  requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
});

// Platform
vscode.postMessage({ type: 'getPlatform' });

// Init
initExploitNotesWidget();
initOllamaChatWidget();
injectActiveContextBars();
initPanel();
syncDynamicBinaryFieldMode();
vscode.postMessage({ type: 'listGeneratedFiles' });

syncToolsBinaryLabel();
syncStaticWorkspaceSummary();
renderRecentBinaries();
updateArgvPayloadHint();
const savedOllamaBaseUrl = String(_loadStorage().ollamaBaseUrl || '').trim();
if (savedOllamaBaseUrl) {
  const baseUrlInput = document.getElementById('ollamaBaseUrl');
  if (baseUrlInput) baseUrlInput.value = savedOllamaBaseUrl;
}
hydrateOllamaConversationHistory();
renderOllamaModels([], ollamaUiState.lastModel || '');
renderOllamaConversation();
renderOllamaConversationHistory();
requestOllamaModels();

// À l'ouverture : si binaire restauré, préparer le mapping sans forcer l'ouverture de boîte de dialogue.
const initialBp = getStaticBinaryPath();
const initialPanelId = document.body.dataset.initialPanel || 'dashboard';
if (initialBp) {
  requestRunTraceInit(null, initialBp);
} else if (initialPanelId === 'dynamic') {
  requestRunTraceInit();
}

// Sidebar sections collapsibles
document.querySelectorAll('.sidebar-section-header').forEach(btn => {
  btn.addEventListener('click', () => {
    const sec = btn.dataset.section;
    const body = document.querySelector(`[data-section-body="${sec}"]`);
    if (!body) return;
    const collapsed = body.style.display === 'none';
    body.style.display = collapsed ? '' : 'none';
    btn.textContent = (collapsed ? '▼ ' : '▶ ') + btn.textContent.slice(2);
    const state = JSON.parse(localStorage.getItem('pof-sidebar-sections') || '{}');
    state[sec] = !collapsed;
    localStorage.setItem('pof-sidebar-sections', JSON.stringify(state));
  });
});
// Restore collapsed state
const _sidebarState = JSON.parse(localStorage.getItem('pof-sidebar-sections') || '{}');
Object.entries(_sidebarState).forEach(([sec, open]) => {
  const body = document.querySelector(`[data-section-body="${sec}"]`);
  const btn = document.querySelector(`.sidebar-section-header[data-section="${sec}"]`);
  if (!body || !btn) return;
  body.style.display = open ? '' : 'none';
  btn.textContent = (open ? '▼ ' : '▶ ') + btn.textContent.slice(2);
});

const MAX_VISIBLE_TABS = 7;

function updateTabOverflow() {
  const tabs = Array.from(document.querySelectorAll('.static-tab'));
  if (tabs.length <= MAX_VISIBLE_TABS) {
    // Remove overflow button if not needed
    const ob = document.getElementById('staticTabOverflow');
    if (ob) ob.style.display = 'none';
    tabs.forEach(t => { t.style.display = ''; });
    return;
  }
  const activeTab = tabs.find(t => t.classList.contains('active'));
  let ordered = [...tabs];
  if (activeTab) {
    ordered = [activeTab, ...ordered.filter(t => t !== activeTab)];
  }
  const visible = ordered.slice(0, MAX_VISIBLE_TABS);
  const hidden = ordered.slice(MAX_VISIBLE_TABS);
  tabs.forEach(t => { t.style.display = 'none'; });
  visible.forEach(t => { t.style.display = ''; });
  let overflowBtn = document.getElementById('staticTabOverflow');
  if (!overflowBtn) {
    overflowBtn = document.createElement('button');
    overflowBtn.id = 'staticTabOverflow';
    overflowBtn.className = 'static-tab-overflow';
    tabs[0]?.parentElement?.appendChild(overflowBtn);
  }
  overflowBtn.style.display = '';
  overflowBtn.textContent = '\u22ef (' + hidden.length + ')';
  overflowBtn.onclick = (e) => {
    e.stopPropagation();
    let menu = document.getElementById('staticTabOverflowMenu');
    if (menu) { menu.remove(); return; }
    menu = document.createElement('div');
    menu.id = 'staticTabOverflowMenu';
    menu.className = 'static-tab-overflow-menu';
    hidden.forEach(t => {
      const item = document.createElement('button');
      item.className = 'overflow-menu-item';
      item.textContent = t.textContent;
      item.addEventListener('click', () => { t.click(); menu.remove(); });
      menu.appendChild(item);
    });
    overflowBtn.parentElement?.appendChild(menu);
    document.addEventListener('click', () => menu.remove(), { once: true });
  };
}

// ── Bookmarks ──────────────────────────────────────────────────────────────
function loadBookmarks() {
  return Object.entries(window._annotations || {})
    .filter(([, entry]) => entry && entry.bookmark)
    .map(([addr, entry]) => ({
      addr,
      label: entry.bookmarkLabel || entry.name || addr,
      color: entry.bookmarkColor || '#4fc1ff',
      timestamp: Date.parse(entry.bookmarkUpdated || entry.updated || '') || 0,
    }))
    .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
}

function addBookmark(addr) {
  if (!getStaticBinaryPath()) return;
  const normalizedAddr = normalizeHexAddress(addr);
  if (!normalizedAddr) return;
  const existing = window._annotations?.[normalizedAddr] || {};
  window._annotations = {
    ...(window._annotations || {}),
    [normalizedAddr]: {
      ...existing,
      bookmark: true,
      bookmarkLabel: existing.bookmarkLabel || existing.name || normalizedAddr,
      bookmarkColor: existing.bookmarkColor || '#4fc1ff',
      bookmarkUpdated: new Date().toISOString(),
    },
  };
  renderBookmarks();
  vscode.postMessage({
    type: 'hubSaveBookmark',
    binaryPath: getStaticBinaryPath(),
    addr: normalizedAddr,
    label: window._annotations[normalizedAddr].bookmarkLabel,
    color: window._annotations[normalizedAddr].bookmarkColor,
  });
}

function renderBookmarks() {
  const container = document.getElementById('bookmarksList');
  if (!container) return;
  const bm = loadBookmarks();
  container.replaceChildren();
  if (bm.length === 0) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.style.padding = '4px 8px';
    p.style.opacity = '0.6';
    p.style.fontSize = '11px';
    p.textContent = 'Aucun bookmark. Ctrl+B dans le désassemblage.';
    container.appendChild(p);
    updateDisasmSessionSummary();
    return;
  }
  bm.forEach(b => {
    const btn = document.createElement('div');
    btn.className = 'bookmark-item';
    btn.style.borderLeft = `2px solid ${b.color || '#4fc1ff'}`;

    const label = document.createElement('span');
    label.className = 'bm-label';
    label.textContent = b.label || b.addr;
    btn.appendChild(label);

    const del = document.createElement('button');
    del.className = 'bm-del';
    del.textContent = '×';
    del.title = 'Supprimer';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = window._annotations?.[b.addr];
      if (entry) {
        const nextEntry = { ...entry };
        delete nextEntry.bookmark;
        delete nextEntry.bookmarkLabel;
        delete nextEntry.bookmarkColor;
        delete nextEntry.bookmarkUpdated;
        window._annotations = { ...(window._annotations || {}) };
        if (!nextEntry.comment && !nextEntry.name) delete window._annotations[b.addr];
        else window._annotations[b.addr] = nextEntry;
      }
      renderBookmarks();
      vscode.postMessage({ type: 'hubDeleteBookmark', binaryPath: getStaticBinaryPath(), addr: b.addr });
    });
    btn.appendChild(del);

    btn.addEventListener('click', () => {
      const a = b.addr;
      document.getElementById('goToAddrInput').value = a;
      const badge = document.getElementById('annotationAddrBadge');
      if (badge) { badge.textContent = a; badge.dataset.addr = a; badge.classList.add('has-addr'); }
      const annotBtn = document.getElementById('btnAddAnnotation');
      if (annotBtn) annotBtn.disabled = false;
      vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
    });
    container.appendChild(btn);
  });
  updateDisasmSessionSummary();
}

document.getElementById('btnClearBookmarks')?.addEventListener('click', () => {
  const nextAnnotations = { ...(window._annotations || {}) };
  Object.keys(nextAnnotations).forEach((addr) => {
    const entry = nextAnnotations[addr];
    if (!entry?.bookmark) return;
    const nextEntry = { ...entry };
    delete nextEntry.bookmark;
    delete nextEntry.bookmarkLabel;
    delete nextEntry.bookmarkColor;
    delete nextEntry.bookmarkUpdated;
    if (!nextEntry.comment && !nextEntry.name) delete nextAnnotations[addr];
    else nextAnnotations[addr] = nextEntry;
  });
  window._annotations = nextAnnotations;
  renderBookmarks();
  vscode.postMessage({ type: 'hubClearBookmarks', binaryPath: getStaticBinaryPath() });
});

document.getElementById('btnBookmarkAddr')?.addEventListener('click', () => {
  const addr = window._lastDisasmAddr;
  if (addr) addBookmark(addr);
});

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'b') {
    const addr = window._lastDisasmAddr;
    if (addr) { addBookmark(addr); e.preventDefault(); }
  }
});

// ── Navigation history ─────────────────────────────────────────────────────
const _navHistory = [];
let _navIndex = -1;

function navPush(addr) {
  if (_navHistory[_navIndex]?.addr === addr) return;
  _navHistory.splice(_navIndex + 1);
  _navHistory.push({ addr, binaryPath: getStaticBinaryPath() });
  if (_navHistory.length > 50) _navHistory.shift();
  _navIndex = _navHistory.length - 1;
  updateNavButtons();
}

function navBack() {
  if (_navIndex <= 0) return;
  _navIndex--;
  const entry = _navHistory[_navIndex];
  vscode.postMessage({ type: 'hubGoToAddress', addr: entry.addr, binaryPath: entry.binaryPath });
  updateNavButtons();
}

function navForward() {
  if (_navIndex >= _navHistory.length - 1) return;
  _navIndex++;
  const entry = _navHistory[_navIndex];
  vscode.postMessage({ type: 'hubGoToAddress', addr: entry.addr, binaryPath: entry.binaryPath });
  updateNavButtons();
}

function updateNavButtons() {
  const btnBack = document.getElementById('btnNavBack');
  const btnFwd = document.getElementById('btnNavForward');
  if (btnBack) btnBack.disabled = _navIndex <= 0;
  if (btnFwd) btnFwd.disabled = _navIndex >= _navHistory.length - 1;
}

document.getElementById('btnNavBack')?.addEventListener('click', navBack);
document.getElementById('btnNavForward')?.addEventListener('click', navForward);
document.addEventListener('keydown', (e) => {
  if (e.altKey && e.key === 'ArrowLeft') { navBack(); e.preventDefault(); }
  if (e.altKey && e.key === 'ArrowRight') { navForward(); e.preventDefault(); }
});

document.addEventListener('keydown', (event) => {
  if (!isStaticTabActive('decompile')) return;
  const isCmdOrCtrl = Boolean(event.metaKey || event.ctrlKey);
  const key = String(event.key || '');
  const lowerKey = key.toLowerCase();
  const typingSomewhereElse = isTypingElement(event.target) && event.target?.id !== 'decompileSearchInput';
  if (isCmdOrCtrl && lowerKey === 'f') {
    event.preventDefault();
    focusDecompileSearchInput();
    return;
  }
  if (typingSomewhereElse) return;
  if (key === 'F3' || (isCmdOrCtrl && lowerKey === 'g')) {
    event.preventDefault();
    stepDecompileSearchHit(event.shiftKey ? -1 : 1);
    return;
  }
  if (!isCmdOrCtrl && !event.altKey && key === '/' && !isTypingElement(event.target)) {
    event.preventDefault();
    focusDecompileSearchInput({ select: false });
  }
});

// Initial render
renderBookmarks();
initDisasmUxState();

updateTabOverflow();

// ── Annotations (Ctrl+click) ───────────────────────────────────────────────
document.addEventListener('click', (e) => {
  if (!e.ctrlKey) return;
  const addrEl = e.target.closest('[data-addr]');
  if (!addrEl) return;
  const addr = addrEl.dataset.addr;
  e.preventDefault();
  showNotePopup(addr, e.clientX, e.clientY);
});

function showNotePopup(addr, x, y) {
  document.getElementById('pof-note-popup')?.remove();
  const popup = document.createElement('div');
  popup.id = 'pof-note-popup';
  popup.className = 'note-popup';
  popup.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:200;` +
    `background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);` +
    `padding:8px;border-radius:4px;min-width:240px;`;
  const label = document.createElement('div');
  label.className = 'note-popup-addr';
  label.style.cssText = 'font-family:monospace;font-size:12px;margin-bottom:6px;opacity:0.8;';
  label.textContent = addr;
  const textarea = document.createElement('textarea');
  textarea.className = 'note-popup-input';
  textarea.rows = 3;
  textarea.style.cssText = 'width:100%;box-sizing:border-box;background:var(--vscode-input-background);' +
    'color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border);padding:4px;';
  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn btn-sm btn-primary';
  saveBtn.style.marginTop = '6px';
  saveBtn.textContent = 'Sauvegarder';
  saveBtn.addEventListener('click', () => {
    vscode.postMessage({
      type: 'hubSaveAnnotation',
      binaryPath: getStaticBinaryPath(),
      addr,
      comment: textarea.value,
    });
    popup.remove();
  });
  popup.appendChild(label);
  popup.appendChild(textarea);
  popup.appendChild(saveBtn);
  document.body.appendChild(popup);
  textarea.focus();
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') popup.remove();
  }, { once: true });
}

// ====== Typed Data toolbar ===================================================
document.getElementById('typedDataSection')?.addEventListener('change', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const section = document.getElementById('typedDataSection').value;
  if (!section) return;
  typedDataUiState.appliedStructAddr = '';
  tabDataCache.typed_data = null;
  vscode.postMessage(buildTypedDataRequest(bp, { section, page: 0 }));
});

document.querySelectorAll('.typed-type-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.typed-type-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const bp = getStaticBinaryPath();
    if (!bp) return;
    const section = document.getElementById('typedDataSection')?.value;
    if (!section) return;
    typedDataUiState.appliedStructName = '';
    typedDataUiState.appliedStructAddr = '';
    setTypedDataStructStatus('');
    tabDataCache.typed_data = null;
    vscode.postMessage(buildTypedDataRequest(bp, {
      section,
      page: 0,
      valueType: btn.dataset.type,
      structName: '',
    }));
  });
});

document.getElementById('btnTypedUseActiveAddr')?.addEventListener('click', () => {
  const synced = syncTypedDataFromActiveSelection();
  if (!synced) return;
  const structName = document.getElementById('typedDataStructSelect')?.value || '';
  if (!structName) return;
  typedDataUiState.appliedStructName = structName;
  typedDataUiState.appliedStructOffset = synced.structOffset || '0x0';
  tabDataCache.typed_data = null;
  setStaticLoading('typedDataContent', 'Application du type…');
  vscode.postMessage(buildTypedDataRequest(getStaticBinaryPath(), {
    page: 0,
    section: synced.section || undefined,
    structName,
    structOffset: synced.structOffset || '0x0',
    structAddr: synced.addr,
  }));
});

document.getElementById('btnTypedApplyStruct')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const section = document.getElementById('typedDataSection')?.value;
  const structName = document.getElementById('typedDataStructSelect')?.value;
  const structOffset = document.getElementById('typedDataStructOffset')?.value || '0x0';
  if (!section || !structName) {
    setTypedDataStructStatus('Choisissez une section et un type C.', true);
    return;
  }
  typedDataUiState.appliedStructName = structName;
  typedDataUiState.appliedStructOffset = structOffset;
  typedDataUiState.appliedStructAddr = '';
  tabDataCache.typed_data = null;
  setStaticLoading('typedDataContent', 'Application du type…');
  vscode.postMessage(buildTypedDataRequest(bp, { section, page: 0, structName, structOffset }));
});

document.getElementById('typedDataStructOffset')?.addEventListener('input', () => {
  typedDataUiState.appliedStructAddr = '';
});

document.getElementById('btnTypedEditStructs')?.addEventListener('click', () => {
  typedDataUiState.pendingEditorOpen = true;
  typedDataUiState.loadingStructs = true;
  vscode.postMessage({ type: 'hubLoadStructs' });
});
