/**
 * @file stackWorkspaceModel.js
 * @brief Construit le workspace canonique de la pile.
 * @details Produit une liste de fonctions et, pour le mode SIMPLE, une frame lineaire
 *          ordonnee par offset BP avec reconstruction canonique stricte.
 */

const NAMELESS_LABELS = new Set([
  'slot',
  'stack slot',
  'local slot',
  'payload slot',
  'sensitive slot',
  'frame'
]);

const GENERIC_ARG_RE = /^arg_[0-9a-z]+h?$/i;
const GENERIC_VAR_RE = /^var_[0-9a-f]+h?$/i;
const GENERIC_STACK_RE = /^stack_[0-9a-f]+h?$/i;
const GENERIC_LOCAL_RE = /^local_[0-9a-f]+h?$/i;
const BUFFER_STYLE_LABEL_RE = /^local_buf_[0-9a-f]+h$/i;
const SPECIAL_SAVED_BP_RE = /^(saved[_\s-]?(?:e|r)?bp|(?:e|r)?bp)$/i;
const SPECIAL_RET_RE = /^(ret|ret_addr|return[_\s-]?address|return[_\s-]?addr)$/i;
const SPECIAL_ARGUMENT_RE = /^(argc|argv|envp)$/i;
const SPECIAL_ARGUMENT_NAMES = ['argc', 'argv', 'envp'];
const POINTER_HEX_RE = /^0x[0-9a-f]+$/i;
const PRINTABLE_ASCII_RE = /[A-Za-z0-9_ ./\\:@$*+\-]/;

const MAIN_ARGUMENT_NAMES = new Map([
  [8, 'argc'],
  [12, 'argv'],
  [16, 'envp']
]);

const KIND_PRIORITY = {
  return_address: 0,
  saved_bp: 1,
  argument: 2,
  buffer: 3,
  modified: 4,
  local: 5,
  padding: 6,
  unknown: 7,
  slot: 8
};

const KIND_LABELS = {
  saved_bp: 'saved bp',
  return_address: 'return address',
  argument: 'argument',
  buffer: 'buffer',
  modified: 'modified',
  local: 'local',
  padding: 'padding',
  unknown: 'unknown',
  slot: 'slot'
};

const SOURCE_PRIORITY = {
  dwarf: 500,
  debug: 480,
  symbol: 470,
  control: 450,
  mcp: 420,
  static: 360,
  auto: 300,
  runtime: 260,
  derived: 220,
  heuristic: 120,
  unknown: 40,
  fallback: 0
};

export function buildStackWorkspaceModel({
  slots,
  snapshots,
  meta,
  currentStep,
  selectedFunction,
  selectedSlotKey,
  snapshot,
  analysis,
  mcp
} = {}) {
  const safeSnapshots = Array.isArray(snapshots) ? snapshots : [];
  const currentFunction = displayFunctionName(snapshot?.func || analysis?.function?.name || '');
  const requestedFunction = displayFunctionName(selectedFunction || '');
  const activeFunction = requestedFunction || currentFunction || pickFallbackFunction(safeSnapshots);
  const functionList = buildFunctionList({
    snapshots: safeSnapshots,
    meta,
    selectedFunction: requestedFunction,
    currentFunction
  });
  const hasFunctionSelection = Boolean(requestedFunction);
  const modelForFunction = resolveModelForFunction(mcp?.model, activeFunction, currentFunction);
  const frameModel = hasFunctionSelection
    ? buildCanonicalFrameModel({
        slots,
        snapshots: safeSnapshots,
        meta,
        analysis,
        snapshot,
        currentStep,
        functionName: activeFunction || currentFunction,
        model: modelForFunction
      })
    : buildEmptyFrameModel({
        meta,
        currentStep,
        functionName: activeFunction || currentFunction
      });
  const detailModel = buildDetailModel(frameModel.entries, selectedSlotKey, frameModel.functionName);
  const panelMode = hasFunctionSelection ? 'frame' : 'functions';

  return {
    functionList,
    frameModel,
    visualSlots: frameModel.entries,
    detailModel,
    hasFunctionSelection,
    panelMode,
    panelTitle: buildPanelTitle(panelMode, frameModel.functionName),
    panelSubtitle: buildPanelSubtitle(panelMode, functionList, frameModel),
    selectedSlotKey: detailModel?.key || '',
    statusText: buildWorkspaceStatus(frameModel)
  };
}

function buildCanonicalFrameModel({
  slots,
  snapshots,
  meta,
  analysis,
  snapshot,
  currentStep,
  functionName,
  model
} = {}) {
  const bpRegister = resolveBpRegister(slots, meta);
  const spRegister = Number(meta?.arch_bits) === 32 ? 'esp' : 'rsp';
  const wordSize = Number(meta?.arch_bits) === 32 ? 4 : 8;
  const bpAddress = parseBigIntAddr(analysis?.frame?.basePointer)
    ?? parseBigIntAddr(analysis?.control?.savedBpAddr)
    ?? parseBigIntAddr(analysis?.frame?.savedBpAddr);
  const spAddress = parseBigIntAddr(analysis?.frame?.stackPointer);
  const registerArguments = Array.isArray(analysis?.frame?.registerArguments)
    ? analysis.frame.registerArguments
        .map((entry) => ({
          location: clean(entry?.location),
          name: clean(entry?.name),
          offset: readNumeric(entry?.offset),
          size: readPositiveInt(entry?.size),
          source: normalizeSource(entry?.source)
        }))
        .filter((entry) => entry.location || entry.name)
    : [];
  const rawObservations = buildRuntimeObservations(slots, bpAddress);

  const controlSeeds = buildControlSeeds({
    analysis,
    bpRegister,
    bpAddress,
    wordSize
  });
  const trustedModelSeeds = buildTrustedModelSeeds({
    model,
    functionName,
    bpRegister,
    bpAddress,
    meta
  });
  const preliminaryFrameScope = buildFrameScope({
    analysis,
    snapshot,
    currentStep,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    seeds: mergeSeedLists(controlSeeds, trustedModelSeeds),
    meta
  });
  const observations = filterRuntimeObservationsForFrame(rawObservations, preliminaryFrameScope);
  const reliableStaticSeeds = buildReliableStaticSeeds({
    analysis,
    observations,
    model,
    trustedModelSeeds,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const normalizedStaticSeeds = normalizeStaticSeeds({
    seeds: reliableStaticSeeds,
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    registerArguments
  });
  const canonicalSeeds = compactCanonicalLayout({
    seeds: mergeSeedLists(controlSeeds, normalizedStaticSeeds),
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const frameScope = buildFrameScope({
    analysis,
    snapshot,
    currentStep,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    seeds: canonicalSeeds,
    meta
  });
  const recoveredSeeds = recoverConcreteObjectExtents({
    seeds: canonicalSeeds,
    observations,
    snapshots,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    frameScope
  });
  const spillClassifiedSeeds = reclassifyNegativeArgumentSpills({
    seeds: recoveredSeeds,
    observations,
    registerArguments,
    snapshot,
    wordSize,
    frameScope
  });
  const runtimeEvidence = buildRuntimeEvidence({
    seeds: spillClassifiedSeeds,
    observations
  });
  const syntheticEntries = buildSyntheticSeeds({
    observations: runtimeEvidence.unmatchedObservations,
    existingEntries: runtimeEvidence.entries,
    functionName,
    bpRegister,
    bpAddress,
    meta,
    frameScope
  });

  const entryBases = [...runtimeEvidence.entries, ...syntheticEntries]
    .map((entry) => finalizeEntryBase(entry, {
      functionName,
      bpRegister,
      bpAddress,
      registerArguments,
      meta
    }))
    .filter(Boolean)
    .filter((entry) => isFinalEntryAllowedInFrame(entry, frameScope))
    .sort(compareFrameEntries);

  assignStableFallbackNames(entryBases, {
    functionName,
    bpRegister,
    meta
  });

  const logicalArguments = buildLogicalArgumentEntries({
    entries: entryBases,
    registerArguments,
    model,
    bpRegister,
    wordSize,
    functionName,
    meta
  });

  const finalizedEntries = entryBases.map((entry) => finalizeDisplayEntry(entry, {
    functionName,
    bpRegister,
    registerArguments,
    allEntries: entryBases,
    allObservations: rawObservations
  }));

  const frameSignature = buildFrameSignature({
    meta,
    functionName,
    bpRegister,
    bpAddress,
    currentStep,
    model,
    entries: finalizedEntries
  });

  return {
    functionName: clean(functionName) || displayFunctionName(snapshot?.func || meta?.start_symbol || '') || 'frame',
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister,
    spRegister,
    spMarker: spAddress !== null
      ? {
          register: spRegister.toUpperCase(),
          addressLabel: toHex(spAddress)
        }
      : {
          register: spRegister.toUpperCase(),
          addressLabel: ''
        },
    entries: finalizedEntries,
    debug: buildFrameDebugModel({
        controlSeeds,
        reliableStaticSeeds: normalizedStaticSeeds,
        compactedSeeds: recoveredSeeds,
        syntheticEntries,
        finalizedEntries,
        logicalArguments,
        bpRegister
      }),
    counts: countEntryBands(finalizedEntries),
    frameSize: readPositiveInt(analysis?.frame?.frameSize),
    emptyText: 'Aucun element visible pour cette frame.',
    frameSignature,
    registerArguments,
    logicalArguments
  };
}

function buildEmptyFrameModel({ meta, currentStep, functionName } = {}) {
  const bpRegister = Number(meta?.arch_bits) === 32 ? 'ebp' : 'rbp';
  const spRegister = Number(meta?.arch_bits) === 32 ? 'esp' : 'rsp';
  return {
    functionName: clean(functionName) || displayFunctionName(meta?.start_symbol || '') || 'frame',
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister,
    spRegister,
    spMarker: { register: spRegister.toUpperCase(), addressLabel: '' },
    entries: [],
    debug: buildFrameDebugModel({
      controlSeeds: [],
      reliableStaticSeeds: [],
      syntheticEntries: [],
      finalizedEntries: [],
      bpRegister
    }),
    counts: countEntryBands([]),
    frameSize: null,
    emptyText: 'Choisissez une fonction pour afficher sa frame.',
    frameSignature: buildFrameSignature({ meta, functionName, bpRegister, bpAddress: null, currentStep, model: null, entries: [] }),
    registerArguments: [],
    logicalArguments: []
  };
}

function buildFrameScope({
  analysis,
  snapshot,
  currentStep,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  seeds,
  meta
} = {}) {
  const ownerName = displayFunctionName(snapshot?.func || analysis?.function?.name || '');
  const ownerMatches = !clean(functionName) || !ownerName || sameFunction(ownerName, functionName);
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  const spAddress = parseBigIntAddr(analysis?.frame?.stackPointer);
  const observedDepth = (
    bpAddress !== null
    && spAddress !== null
    && spAddress <= bpAddress
  ) ? Number(spAddress - bpAddress) : null;
  const seedRanges = [...(Array.isArray(seeds) ? seeds : [])]
    .map((seed) => normalizeSeed(seed))
    .filter(Boolean)
    .map((seed) => ({
      kind: normalizeEntryKind(seed?.kind),
      source: normalizeSource(seed?.source),
      range: seedOffsetRange(seed)
    }))
    .filter((entry) => entry.range);

  let minNegativeOffset = Number.isFinite(frameSize) ? -frameSize : null;
  if (Number.isFinite(observedDepth) && observedDepth < 0) {
    minNegativeOffset = minNegativeOffset === null
      ? observedDepth
      : Math.min(minNegativeOffset, observedDepth);
  }
  let maxPositiveOffset = readPositiveInt(wordSize) ?? 0;
  seedRanges.forEach(({ range }) => {
    if (range.start < 0 && (minNegativeOffset === null || range.start < minNegativeOffset)) {
      minNegativeOffset = range.start;
    }
    if (range.end > 0 && range.end > maxPositiveOffset) {
      maxPositiveOffset = range.end;
    }
  });

  return {
    functionName: clean(functionName) || ownerName || '',
    ownerName,
    ownerMatches,
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister: String(bpRegister || 'rbp').toLowerCase(),
    bpAddress: parseBigIntAddr(bpAddress),
    archBits: Number(meta?.arch_bits) || 0,
    wordSize: readPositiveInt(wordSize) ?? 0,
    frameSize,
    minNegativeOffset,
    maxPositiveOffset,
    seedRanges
  };
}

function filterRuntimeObservationsForFrame(observations, frameScope) {
  return [...(Array.isArray(observations) ? observations : [])]
    .filter((observation) => doesObservationBelongToFrameScope(observation, frameScope));
}

function doesObservationBelongToFrameScope(observation, frameScope) {
  if (!observation || !frameScope?.ownerMatches) return false;
  const range = seedOffsetRange(observation);
  if (!range) return false;
  return isOffsetRangeWithinFrameScope(range, frameScope);
}

function isOffsetRangeWithinFrameScope(range, frameScope) {
  if (!range || !frameScope) return false;
  const minNegative = Number.isFinite(frameScope?.minNegativeOffset) ? frameScope.minNegativeOffset : null;
  const maxPositive = Number.isFinite(frameScope?.maxPositiveOffset) ? frameScope.maxPositiveOffset : null;
  if (range.start < 0) {
    if (minNegative !== null && range.start < minNegative) return false;
    if (range.end > 0) return false;
    return true;
  }
  if (range.start === 0 || range.start === (frameScope.wordSize || 0)) return true;
  if (maxPositive !== null && range.end <= maxPositive) {
    return doesRangeTouchStaticPositiveSeed(range, frameScope);
  }
  return false;
}

function doesRangeTouchStaticPositiveSeed(range, frameScope) {
  if (!range || !frameScope) return false;
  return (Array.isArray(frameScope?.seedRanges) ? frameScope.seedRanges : []).some((entry) => {
    if (!entry?.range || entry.range.start < 0) return false;
    return entry.range.start < range.end && range.start < entry.range.end;
  });
}

function buildControlSeeds({ analysis, bpRegister, bpAddress, wordSize } = {}) {
  const savedBpAddress = parseBigIntAddr(analysis?.control?.savedBpAddr)
    ?? parseBigIntAddr(analysis?.frame?.savedBpAddr)
    ?? bpAddress;
  const retAddress = parseBigIntAddr(analysis?.control?.retAddrAddr)
    ?? parseBigIntAddr(analysis?.frame?.retAddrAddr)
    ?? (savedBpAddress !== null ? savedBpAddress + BigInt(wordSize) : null);

  const seeds = [];
  addSeed(seeds, {
    offset: 0,
    size: wordSize,
    kind: 'saved_bp',
    start: savedBpAddress,
    source: 'control',
    label: canonicalSavedBpName(bpRegister),
    nameSource: 'control',
    confidence: 1,
    isSynthetic: false
  });
  addSeed(seeds, {
    offset: wordSize,
    size: wordSize,
    kind: 'return_address',
    start: retAddress,
    source: 'control',
    label: 'return address',
    nameSource: 'control',
    confidence: 1,
    isSynthetic: false
  });
  return seeds;
}

function buildReliableStaticSeeds({
  analysis,
  observations,
  model,
  trustedModelSeeds,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta
} = {}) {
  const abiSeeds = buildMainAbiArgumentSeeds({
    analysis,
    model,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const seeds = mergeSeedLists(trustedModelSeeds, abiSeeds);

  const runtimeCandidates = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => item.offset !== null && item.size > 0)
    .sort(compareObservationsForSeeding);

  runtimeCandidates.forEach((observation) => {
    if (!shouldCreateNamedSeed(observation, functionName, bpRegister, meta)) return;
    if (isCoveredByStableSeedLayout(seeds, observation)) return;
    if (isCoveredByExistingSeed(seeds, observation)) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: false,
      kindOverride: classifyObservationSeedKind(observation, functionName, bpRegister, meta)
    }));
  });

  runtimeCandidates.forEach((observation) => {
    if (!shouldCreateReliableSeed(observation, functionName, bpRegister, meta)) return;
    if (isCoveredByStableSeedLayout(seeds, observation)) return;
    if (isCoveredByExistingSeed(seeds, observation)) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: false,
      kindOverride: classifyObservationSeedKind(observation, functionName, bpRegister, meta)
    }));
  });

  void analysis;
  void wordSize;
  return seeds;
}

function buildMainAbiArgumentSeeds({ analysis, model, functionName, bpRegister, bpAddress, wordSize, meta } = {}) {
  const isMainFunction = sameFunction(functionName, 'main');
  const is32BitBp = String(bpRegister || '').toLowerCase() === 'ebp' && Number(meta?.arch_bits || 0) === 32;
  if (!isMainFunction || !is32BitBp) return [];

  const existingOffsets = new Set(
    (Array.isArray(model?.locals) ? model.locals : [])
      .map((local) => readNumeric(local?.offset))
      .filter((offset) => Number.isFinite(offset) && offset > 0)
  );
  const seeds = [];
  [
    { offset: 8, label: 'argc', size: 4 },
    { offset: 12, label: 'argv', size: 4 }
  ].forEach((entry) => {
    if (existingOffsets.has(entry.offset)) return;
    addSeed(seeds, {
      offset: entry.offset,
      size: entry.size,
      kind: 'argument',
      start: bpAddress !== null ? bpAddress + BigInt(entry.offset) : null,
      source: 'static',
      label: entry.label,
      nameSource: 'static',
      confidence: 0.92,
      isSynthetic: false
    });
  });
  void analysis;
  void wordSize;
  return seeds;
}

function buildTrustedModelSeeds({
  model,
  functionName,
  bpRegister,
  bpAddress,
  meta
} = {}) {
  const seeds = [];
  (Array.isArray(model?.locals) ? model.locals : []).forEach((local) => {
    const offset = readNumeric(local?.offset);
    if (offset === null) return;
    const size = readPositiveInt(local?.size) ?? 1;
    const source = normalizeSource(local?.source || 'mcp');
    const kind = classifyTrustedSeedKind({
      rawKind: local?.role,
      label: local?.name,
      typeName: local?.cType,
      offset,
      functionName,
      bpRegister,
      meta,
      source
    });
    if (!isStrictStackSeedAllowed({ offset, kind, functionName, bpRegister, meta })) return;
    addSeed(seeds, {
      offset,
      size,
      kind,
      start: bpAddress !== null ? bpAddress + BigInt(offset) : null,
      source,
      label: clean(local?.name),
      nameSource: source,
      typeName: clean(local?.cType),
      confidence: readNumeric(local?.confidence),
      isSynthetic: false
    });
  });
  return seeds;
}

function normalizeStaticSeeds({
  seeds,
  observations,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  registerArguments
} = {}) {
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  return [...(Array.isArray(seeds) ? seeds : [])]
    .map((seed) => normalizeStaticSeed(seed, {
      observations,
      frameSize,
      functionName,
      bpRegister,
      bpAddress,
      wordSize,
      meta,
      registerArguments
    }))
    .filter(Boolean)
    .sort(compareSeedsForLayout)
    .reduce((acc, seed) => {
      const previous = acc[acc.length - 1];
      if (previous && shouldCompactSeeds(previous, seed)) {
        acc[acc.length - 1] = mergeCompactedSeeds(previous, seed);
        return acc;
      }
      if (shouldDropWeakStaticSeed(seed, acc, observations, frameSize, wordSize)) {
        return acc;
      }
      acc.push(seed);
      return acc;
    }, []);
}

function normalizeStaticSeed(seed, {
  observations,
  frameSize,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  registerArguments
} = {}) {
  const normalized = normalizeSeed(seed);
  if (!normalized) return null;
  if (isProtectedKind(normalized.kind)) return normalized;

  const pointerLike = isLikelyPointerSpillSeed(normalized, observations, wordSize, registerArguments);
  const range = seedOffsetRange(normalized);
  if (!range) return null;

  if (pointerLike) {
    normalized.kind = 'argument';
    normalized.size = wordSize;
    normalized.end = normalized.start !== null ? normalized.start + BigInt(wordSize) : null;
  }

  if (normalized.kind === 'buffer') {
    const recoveredSize = resolveNormalizedBufferSize(normalized, observations, frameSize, wordSize);
    if (recoveredSize !== null) {
      normalized.size = recoveredSize;
      normalized.end = normalized.start !== null ? normalized.start + BigInt(recoveredSize) : null;
    }
  }

  if (!isSeedInsideFrameBounds(normalized, frameSize, wordSize)) return null;
  if (crossesFrameBase(normalized) && !pointerLike) return null;

  const supported = countSeedSupport(normalized, observations, {
    functionName,
    bpRegister,
    meta,
    bpAddress
  });
  if (!supported.exact && !supported.named && isWeakStaticSeed(normalized) && normalized.kind !== 'buffer' && normalized.kind !== 'argument') {
    return null;
  }

  return normalized;
}

function compactCanonicalLayout({
  seeds,
  observations,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta
} = {}) {
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  const sorted = [...(Array.isArray(seeds) ? seeds : [])].sort(compareSeedsForLayout);
  return sorted.reduce((acc, seed) => {
    if (!seed) return acc;
    const previous = acc[acc.length - 1];
    if (previous && shouldCompactSeeds(previous, seed)) {
      acc[acc.length - 1] = mergeCompactedSeeds(previous, seed);
      return acc;
    }

    const conflicting = acc.find((candidate) => (
      seedsConflict(candidate, seed)
      && !shouldAllowNestedSeedCoexistence(candidate, seed, observations)
    ));
    if (conflicting) {
      const winner = chooseMoreTrustworthySeed(conflicting, seed, observations, {
        functionName,
        bpRegister,
        bpAddress,
        wordSize,
        meta
      });
      if (winner === conflicting) return acc;
      const index = acc.indexOf(conflicting);
      acc[index] = winner;
      return acc;
    }

    if (!isSeedInsideFrameBounds(seed, frameSize, wordSize)) return acc;
    acc.push(seed);
    return acc;
  }, []);
}

function recoverConcreteObjectExtents({
  seeds,
  observations,
  snapshots,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  frameScope
} = {}) {
  if (!frameScope?.ownerMatches) return Array.isArray(seeds) ? [...seeds] : [];
  const recoveredObjects = collectConcreteObjectExtents({
    snapshots,
    analysis,
    observations,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    frameScope
  });
  if (!recoveredObjects.length) return Array.isArray(seeds) ? [...seeds] : [];

  const currentSeeds = [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  recoveredObjects.forEach((recovered) => {
    const match = chooseRecoveredSeedTarget(currentSeeds, recovered);
    if (match) {
      applyRecoveredExtentToSeed(match, recovered, observations, wordSize);
      return;
    }
    addSeed(currentSeeds, recoveredSeedToStaticSeed(recovered, bpAddress));
  });

  const compacted = compactCanonicalLayout({
    seeds: currentSeeds,
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });

  return compacted.filter((seed) => !isSeedAbsorbedByRecoveredObject(seed, recoveredObjects, observations));
}

function collectConcreteObjectExtents({
  snapshots,
  analysis,
  observations,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  frameScope
} = {}) {
  const byOffset = new Map();

  (Array.isArray(snapshots) ? snapshots : [])
    .filter((snap) => sameFunction(snap?.func, functionName))
    .forEach((snap) => {
      const externalSymbol = clean(snap?.effects?.external_symbol).toLowerCase();
      if (!isConcreteObjectExtentCall(externalSymbol)) return;

      const bpValue = readSnapshotRegisterValue(snap, bpRegister);
      if (bpValue === null) return;

      collectRecoveredExtentCandidatesFromSnapshot({
        snapshot: snap,
        externalSymbol,
        bpValue,
        bpRegister,
        wordSize,
        meta,
        frameScope
      }).forEach((candidate) => {
        pushRecoveredExtentCandidate(byOffset, candidate);
      });
    });

  collectRecoveredExtentCandidatesFromAnalysis({
    analysis,
    observations,
    bpAddress,
    bpRegister,
    wordSize,
    frameScope
  }).forEach((candidate) => {
    pushRecoveredExtentCandidate(byOffset, candidate);
  });

  return [...byOffset.values()].sort((left, right) => left.offset - right.offset);
}

function collectRecoveredExtentCandidatesFromSnapshot({
  snapshot,
  externalSymbol,
  bpValue,
  bpRegister,
  wordSize,
  meta,
  frameScope
} = {}) {
  const candidates = [];
  collectSnapshotWrites(snapshot).forEach((write) => {
    const candidate = recoveredCandidateFromRange({
      start: write?.addr,
      size: write?.size,
      bpValue,
      externalSymbol
    });
    if (candidate && recoveredCandidateBelongsToFrame(candidate, frameScope)) candidates.push(candidate);
  });

  const registerCandidate = recoveredCandidateFromCallRegisters({
    snapshot,
    externalSymbol,
    bpValue,
    bpRegister,
    wordSize,
    meta,
    frameScope
  });
  if (registerCandidate) candidates.push(registerCandidate);
  return candidates;
}

function collectRecoveredExtentCandidatesFromAnalysis({ analysis, observations, bpAddress, bpRegister, wordSize, frameScope } = {}) {
  if (bpAddress === null) return [];
  const writes = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  return writes
    .map((write) => recoveredCandidateFromRange({
      start: write?.addr,
      size: write?.size,
      bpValue: bpAddress,
      externalSymbol: ''
    }))
    .filter((candidate) => recoveredCandidateBelongsToFrame(candidate, frameScope))
    .filter((candidate) => shouldKeepRecoveredAnalysisCandidate(candidate, observations, bpRegister, wordSize));
}

function collectSnapshotWrites(snapshot) {
  const memoryWrites = Array.isArray(snapshot?.memory?.writes) ? snapshot.memory.writes : [];
  const deltaWrites = Array.isArray(snapshot?.delta?.writes) ? snapshot.delta.writes : [];
  return [...memoryWrites, ...deltaWrites];
}

function recoveredCandidateFromCallRegisters({
  snapshot,
  externalSymbol,
  bpValue,
  bpRegister,
  wordSize,
  meta,
  frameScope
} = {}) {
  const normalizedSymbol = clean(externalSymbol).toLowerCase();
  const archBits = Number(meta?.arch_bits) || (Number(wordSize) === 4 ? 32 : 64);
  if (archBits !== 64) return null;

  const destRegister = resolveDestinationRegisterForExternalCall(normalizedSymbol);
  const sizeRegister = resolveSizeRegisterForExternalCall(normalizedSymbol);
  if (!destRegister || !sizeRegister) return null;

  const start = readSnapshotRegisterValue(snapshot, destRegister);
  const sizeValue = readSnapshotRegisterValue(snapshot, sizeRegister);
  const size = sizeValue !== null ? Number(sizeValue) : null;
  if (start === null || !Number.isFinite(size) || size <= 0) return null;

  const candidate = recoveredCandidateFromRange({
    start,
    size,
    bpValue,
    externalSymbol,
    bpRegister
  });
  return recoveredCandidateBelongsToFrame(candidate, frameScope) ? candidate : null;
}

function resolveDestinationRegisterForExternalCall(symbol) {
  switch (clean(symbol).toLowerCase()) {
    case 'read':
      return 'rsi';
    case 'memcpy':
    case 'memmove':
    case 'memset':
    case 'strcpy':
    case 'strncpy':
    case 'gets':
      return 'rdi';
    default:
      return '';
  }
}

function resolveSizeRegisterForExternalCall(symbol) {
  switch (clean(symbol).toLowerCase()) {
    case 'memcpy':
    case 'memmove':
    case 'memset':
    case 'read':
    case 'strncpy':
      return 'rdx';
    default:
      return '';
  }
}

function recoveredCandidateFromRange({ start, size, bpValue, externalSymbol } = {}) {
  const parsedStart = parseBigIntAddr(start);
  const parsedSize = readPositiveInt(size);
  if (parsedStart === null || parsedSize === null || bpValue === null) return null;
  const offset = Number(parsedStart - bpValue);
  if (!Number.isFinite(offset) || offset >= 0) return null;
  return {
    offset,
    size: parsedSize,
    kind: 'buffer',
    label: deriveRecoveredObjectLabel(offset, externalSymbol),
    typeName: '',
    source: 'derived',
    confidence: 1,
    symbol: clean(externalSymbol).toLowerCase()
  };
}

function shouldKeepRecoveredAnalysisCandidate(candidate, observations, bpRegister, wordSize) {
  if (!candidate) return false;
  const size = readPositiveInt(candidate?.size);
  if (size === null || size < Math.max(8, Number(wordSize || 0))) return false;
  return (Array.isArray(observations) ? observations : []).some((observation) => {
    if (readNumeric(observation?.offset) !== readNumeric(candidate?.offset)) return false;
    const kind = classifyObservationSeedKind(observation, '', bpRegister, { arch_bits: Number(wordSize) === 4 ? 32 : 64 });
    return kind === 'buffer' || isStrongBufferObservation(observation);
  });
}

function pushRecoveredExtentCandidate(byOffset, candidate) {
  if (!candidate || !(byOffset instanceof Map)) return;
  const key = `${candidate.offset}`;
  const existing = byOffset.get(key) || null;
  if (!existing) {
    byOffset.set(key, candidate);
    return;
  }

  const existingSize = readPositiveInt(existing?.size) ?? 0;
  const candidateSize = readPositiveInt(candidate?.size) ?? 0;
  if (candidateSize > existingSize) {
    byOffset.set(key, {
      ...candidate,
      label: clean(existing?.label) || clean(candidate?.label),
      source: existing?.source === 'derived' ? candidate.source : existing.source
    });
    return;
  }

  if (!clean(existing?.label) && clean(candidate?.label)) {
    byOffset.set(key, {
      ...existing,
      label: candidate.label
    });
  }
}

function isConcreteObjectExtentCall(symbol) {
  return [
    'memset',
    'memcpy',
    'memmove',
    'strcpy',
    'strncpy',
    'gets',
    'read'
  ].includes(clean(symbol).toLowerCase());
}

function readSnapshotRegisterValue(snapshot, bpRegister) {
  const registerName = String(bpRegister || 'rbp').toLowerCase();
  const cpuBefore = parseBigIntAddr(snapshot?.cpu?.before?.registers?.[registerName]);
  if (cpuBefore !== null) return cpuBefore;
  const listed = Array.isArray(snapshot?.registers)
    ? snapshot.registers.find((entry) => clean(entry?.name).toLowerCase() === registerName)
    : null;
  return parseBigIntAddr(listed?.value);
}

function chooseRecoveredSeedTarget(seeds, recovered) {
  const entries = Array.isArray(seeds) ? seeds : [];
  return entries
    .filter((seed) => !isProtectedKind(seed?.kind))
    .map((seed) => ({
      seed,
      score: scoreRecoveredSeedTarget(seed, recovered)
    }))
    .filter((entry) => Number.isFinite(entry.score))
    .sort((left, right) => right.score - left.score || compareSeedsForLayout(left.seed, right.seed))
    .map((entry) => entry.seed)[0] ?? null;
}

function scoreRecoveredSeedTarget(seed, recovered) {
  if (!seed || !recovered) return -Infinity;
  const seedRange = seedOffsetRange(seed);
  const recoveredRange = seedOffsetRange(recovered);
  if (!seedRange || !recoveredRange) return -Infinity;

  const exactOffset = readNumeric(seed?.offset) === readNumeric(recovered?.offset);
  const overlap = seedRange.start < recoveredRange.end && recoveredRange.start < seedRange.end;
  const contains = recoveredRange.start <= seedRange.start && recoveredRange.end >= seedRange.end;
  if (!exactOffset && !overlap && !contains) return -Infinity;

  let score = 0;
  if (exactOffset) score += 1000;
  if (contains) score += 220;
  if (overlap) score += 120;
  if (normalizeEntryKind(seed?.kind) === 'buffer') score += 120;
  if (normalizeEntryKind(seed?.kind) === 'local') score += 40;
  if (isWeakStaticSeed(seed)) score += 80;
  score += Math.min(100, resolveSourcePriority(seed?.source) / 5);
  score += Math.min(60, overlapByteCount(
    seedRangeStart(seed),
    seedRangeEnd(seed),
    recoveredRange.start !== null ? BigInt(recoveredRange.start) : null,
    recoveredRange.end !== null ? BigInt(recoveredRange.end) : null
  ));
  return score;
}

function applyRecoveredExtentToSeed(seed, recovered, observations, wordSize) {
  if (!seed || !recovered) return;
  const recoveredSize = readPositiveInt(recovered?.size) ?? readPositiveInt(seed?.size) ?? wordSize;
  seed.kind = 'buffer';
  seed.size = recoveredSize;
  if (isWeakStaticSeed(seed) || !clean(seed?.label)) {
    seed.label = clean(recovered?.label) || seed.label;
  }
  seed.source = resolveSourcePriority(seed?.source) >= resolveSourcePriority(recovered?.source) ? seed.source : recovered.source;
  seed.end = seed.start !== null ? seed.start + BigInt(seed.size) : null;
  seed.seedContributors = mergeSeedContributors(seed?.seedContributors, [{
    offset: recovered.offset,
    size: recovered.size,
    kind: 'buffer',
    source: recovered.source,
    label: recovered.label,
    isSynthetic: false
  }]);

  const largerObservation = (Array.isArray(observations) ? observations : []).find((observation) => (
    readNumeric(observation?.offset) === readNumeric(recovered?.offset)
    && readPositiveInt(observation?.size) === recoveredSize
  ));
  if (largerObservation && !clean(seed?.label)) {
    seed.label = firstNonEmpty(largerObservation?.modelName, largerObservation?.label);
  }
}

function recoveredSeedToStaticSeed(recovered, bpAddress) {
  const offset = readNumeric(recovered?.offset);
  const size = readPositiveInt(recovered?.size);
  return {
    offset,
    size,
    kind: 'buffer',
    start: bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null,
    source: 'derived',
    label: clean(recovered?.label),
    nameSource: 'derived',
    typeName: '',
    confidence: 1,
    isSynthetic: false
  };
}

function isSeedAbsorbedByRecoveredObject(seed, recoveredObjects, observations) {
  if (!seed || isProtectedKind(seed?.kind)) return false;
  const seedRange = seedOffsetRange(seed);
  if (!seedRange) return false;
  return (Array.isArray(recoveredObjects) ? recoveredObjects : []).some((recovered) => {
    const recoveredRange = seedOffsetRange(recovered);
    if (!recoveredRange) return false;
    if (readNumeric(seed?.offset) === readNumeric(recovered?.offset)) return false;
    const insideRecovered = seedRange.start >= recoveredRange.start && seedRange.end <= recoveredRange.end;
    if (!insideRecovered) return false;
    if (normalizeEntryKind(seed?.kind) === 'modified') return false;
    if (!isWeakStaticSeed(seed) && normalizeEntryKind(seed?.kind) !== 'slot' && normalizeEntryKind(seed?.kind) !== 'unknown') {
      return false;
    }
    const support = countSeedSupport(seed, observations);
    if (
      support.exact > 0
      && normalizeEntryKind(seed?.kind) !== 'slot'
      && normalizeEntryKind(seed?.kind) !== 'unknown'
      && normalizeEntryKind(seed?.kind) !== 'padding'
    ) {
      return false;
    }
    if (seed?.isSynthetic) return true;
    if (normalizeEntryKind(seed?.kind) === 'slot' || normalizeEntryKind(seed?.kind) === 'unknown') {
      return !support.named;
    }
    return !support.named;
  });
}

function deriveRecoveredObjectLabel(offset, symbol) {
  void offset;
  void symbol;
  return '';
}

function recoveredCandidateBelongsToFrame(candidate, frameScope) {
  if (!candidate || !frameScope?.ownerMatches) return false;
  const range = seedOffsetRange(candidate);
  if (!range) return false;
  return isOffsetRangeWithinFrameScope(range, frameScope);
}

function reclassifyNegativeArgumentSpills({ seeds, observations, registerArguments, snapshot, wordSize, frameScope } = {}) {
  if (!frameScope?.ownerMatches) {
    return [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  }
  const currentSeeds = [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  const abiArguments = normalizeRegisterArguments(registerArguments, snapshot, wordSize);
  if (!abiArguments.length) return currentSeeds;

  const bufferFloor = currentSeeds
    .filter((seed) => normalizeEntryKind(seed?.kind) === 'buffer' && readNumeric(seed?.offset) < 0)
    .map((seed) => readNumeric(seed?.offset))
    .filter((offset) => Number.isFinite(offset))
    .sort((left, right) => left - right)[0] ?? null;

  const candidates = currentSeeds
    .filter((seed) => isPotentialNegativeArgumentSpillSeed(seed, observations, wordSize, bufferFloor))
    .sort((left, right) => readNumeric(left?.offset) - readNumeric(right?.offset));

  if (!candidates.length) return currentSeeds;

  const depthRanks = new Map(candidates.map((seed, index) => [seedIdentity(seed), index]));
  const scoredPairs = [];
  candidates.forEach((seed) => {
    abiArguments.forEach((argument, argIndex) => {
      const score = scoreNegativeArgumentSpillCandidate(seed, argument, {
        observations,
        wordSize,
        depthRank: depthRanks.get(seedIdentity(seed)) ?? 999,
        argIndex
      });
      if (score >= 360) {
        scoredPairs.push({ seed, argument, score });
      }
    });
  });

  const assignedSeedIds = new Set();
  const assignedArgumentIds = new Set();
  scoredPairs
    .sort((left, right) => right.score - left.score || left.argument.index - right.argument.index)
    .forEach(({ seed, argument }) => {
      const seedId = seedIdentity(seed);
      const argumentId = `${argument.location}:${argument.index}`;
      if (assignedSeedIds.has(seedId) || assignedArgumentIds.has(argumentId)) return;
      assignedSeedIds.add(seedId);
      assignedArgumentIds.add(argumentId);
      seed.kind = 'argument';
      if (readPositiveInt(seed?.size) > readPositiveInt(wordSize)) {
        seed.size = readPositiveInt(wordSize);
      }
      if (isGenericName(seed?.label) || matchesRegisterArgumentIdentity(seed?.label, argument)) {
        seed.label = '';
      }
      seed.seedContributors = mergeSeedContributors(seed?.seedContributors, [{
        offset: seed.offset,
        size: seed.size,
        kind: 'argument',
        source: 'derived',
        label: clean(argument?.name),
        isSynthetic: false
      }]);
    });

  return currentSeeds;
}

function normalizeRegisterArguments(registerArguments, snapshot, wordSize) {
  return (Array.isArray(registerArguments) ? registerArguments : [])
    .map((argument, index) => ({
      index,
      location: clean(argument?.location).toLowerCase(),
      name: clean(argument?.name).toLowerCase(),
      size: readPositiveInt(argument?.size) ?? readPositiveInt(wordSize),
      value: readSnapshotRegisterValue(snapshot, clean(argument?.location).toLowerCase())
    }))
    .filter((argument) => argument.location && readPositiveInt(argument?.size));
}

function isPotentialNegativeArgumentSpillSeed(seed, observations, wordSize, bufferFloor) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size);
  const kind = normalizeEntryKind(seed?.kind);
  if (!Number.isFinite(offset) || offset >= 0) return false;
  if (bufferFloor !== null && offset >= bufferFloor) return false;
  if (!size || size > readPositiveInt(wordSize)) return false;
  if (isProtectedKind(kind) || kind === 'buffer' || kind === 'padding') return false;

  const support = countSeedSupport(seed, observations);
  const hasExactEvidence = support.exact > 0 || resolveSourcePriority(seed?.source) >= SOURCE_PRIORITY.static;
  if (!hasExactEvidence) return false;

  const range = seedOffsetRange(seed);
  return Boolean(range && range.end <= 0);
}

function scoreNegativeArgumentSpillCandidate(seed, argument, { observations, wordSize, depthRank, argIndex } = {}) {
  if (!seed || !argument) return -Infinity;
  const size = readPositiveInt(seed?.size) ?? 0;
  const argumentSize = readPositiveInt(argument?.size) ?? readPositiveInt(wordSize) ?? 0;
  if (!size || !argumentSize) return -Infinity;

  let score = 0;
  if (size === argumentSize) score += 240;
  else if (argumentSize === readPositiveInt(wordSize) && size === 4) score += 200;
  else return -Infinity;

  const labelEvidence = collectSeedLabelEvidence(seed, observations);
  if (labelEvidence.some((label) => matchesRegisterArgumentIdentity(label, argument))) {
    score += 1000;
  }

  const observedValue = readSeedObservedValue(seed, observations);
  if (observedValue !== null && argument.value !== null && observedValue === argument.value) {
    score += 900;
  }

  if (!labelEvidence.length || labelEvidence.every((label) => isGenericName(label))) {
    score += 80;
  }

  if (Number.isFinite(depthRank)) {
    score += Math.max(0, 180 - depthRank * 40);
  }
  score += Math.max(0, 40 - argIndex * 5);
  return score;
}

function collectSeedLabelEvidence(seed, observations) {
  const labels = [clean(seed?.label)];
  (Array.isArray(observations) ? observations : [])
    .filter((observation) => readNumeric(observation?.offset) === readNumeric(seed?.offset))
    .forEach((observation) => {
      labels.push(clean(observation?.label));
      labels.push(clean(observation?.modelName));
    });
  return uniqueStrings(labels.filter(Boolean).map((label) => label.toLowerCase()));
}

function readSeedObservedValue(seed, observations) {
  const exactObservation = (Array.isArray(observations) ? observations : [])
    .filter((observation) => readNumeric(observation?.offset) === readNumeric(seed?.offset))
    .sort((left, right) => resolveSourcePriority(right?.source) - resolveSourcePriority(left?.source))[0] ?? null;
  if (!exactObservation) return null;
  return parseComparableScalarValue(firstNonEmpty(exactObservation?.rawValue, exactObservation?.displayValue));
}

function parseComparableScalarValue(value) {
  const raw = clean(value);
  if (!raw) return null;
  const hex = parseBigIntAddr(raw);
  if (hex !== null) return hex;
  const numeric = readNumeric(raw);
  if (numeric === null) return null;
  return BigInt(Math.trunc(numeric));
}

function matchesRegisterArgumentIdentity(label, argument) {
  const cleanedLabel = clean(label).toLowerCase();
  const location = clean(argument?.location).toLowerCase();
  const name = clean(argument?.name).toLowerCase();
  if (!cleanedLabel || !location) return false;
  return cleanedLabel === location || cleanedLabel === name || cleanedLabel === `arg_${location}`;
}

function buildRuntimeEvidence({ seeds, observations } = {}) {
  const entries = (Array.isArray(seeds) ? seeds : []).map((seed) => ({
    ...seed,
    observations: []
  }));
  const unmatchedObservations = [];

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    const target = chooseEntryForObservation(entries, observation);
    if (target) {
      target.observations.push(observation);
      return;
    }
    unmatchedObservations.push(observation);
  });

  return { entries, unmatchedObservations };
}

function buildSyntheticSeeds({ observations, existingEntries, functionName, bpRegister, bpAddress, meta, frameScope } = {}) {
  const seeds = [];
  const candidates = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => item.offset !== null && item.size > 0)
    .sort(compareObservationsForSeeding);

  candidates.forEach((observation) => {
    if (shouldSuppressSyntheticObservation(observation, existingEntries)) return;
    const gap = findStructuralGapForObservation(observation, existingEntries);
    if (!gap) return;
    if (!doesObservationBelongToFrameScope(observation, frameScope)) return;
    const kind = classifySyntheticObservationKind(observation, functionName, bpRegister, meta, gap);
    if (!kind) return;
    if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: true,
      kindOverride: kind
    }));
  });

  const entryState = buildRuntimeEvidence({
    seeds,
    observations: candidates
  });
  return compactAdjacentSyntheticBufferEntries(entryState.entries);
}

function compactAdjacentSyntheticBufferEntries(entries) {
  return [...(Array.isArray(entries) ? entries : [])]
    .sort(compareSeedsForLayout)
    .reduce((acc, entry) => {
      const previous = acc[acc.length - 1];
      if (shouldMergeAdjacentSyntheticBuffers(previous, entry)) {
        acc[acc.length - 1] = mergeAdjacentSyntheticBufferEntries(previous, entry);
        return acc;
      }
      acc.push(entry);
      return acc;
    }, []);
}

function shouldMergeAdjacentSyntheticBuffers(left, right) {
  if (!left || !right) return false;
  if (!left?.isSynthetic || !right?.isSynthetic) return false;
  if (normalizeEntryKind(left?.kind) !== 'buffer' || normalizeEntryKind(right?.kind) !== 'buffer') return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  return leftRange.start === rightRange.end || rightRange.start === leftRange.end;
}

function mergeAdjacentSyntheticBufferEntries(left, right) {
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  const startOffset = Math.min(leftRange.start, rightRange.start);
  const endOffset = Math.max(leftRange.end, rightRange.end);
  const stronger = chooseMoreTrustworthySeed(left, right, [], {});
  return {
    ...stronger,
    offset: startOffset,
    size: endOffset - startOffset,
    start: parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null
      ? parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset)) + BigInt(startOffset)
      : null,
    end: parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null
      ? parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset)) + BigInt(endOffset)
      : null,
    observations: [
      ...(Array.isArray(left?.observations) ? left.observations : []),
      ...(Array.isArray(right?.observations) ? right.observations : [])
    ],
    seedContributors: mergeSeedContributors(left?.seedContributors, right?.seedContributors)
  };
}

function shouldSuppressSyntheticObservation(observation, existingEntries) {
  return (Array.isArray(existingEntries) ? existingEntries : []).some((entry) => {
    if (!entry) return false;
    if (entry?.offset !== null && observation?.offset !== null && entry.offset === observation.offset) return true;
    return rangesOverlap(
      seedRangeStart(entry),
      seedRangeEnd(entry),
      observationRangeStart(observation),
      observationRangeEnd(observation)
    );
  });
}

function fitsStructuralGap(observation, existingEntries) {
  const gap = findStructuralGapForObservation(observation, existingEntries);
  if (!gap) return false;

  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return false;
  return observationRange.start >= gap.start && observationRange.end <= gap.end;
}

function compareSeedsForLayout(left, right) {
  const leftOffset = readNumeric(left?.offset);
  const rightOffset = readNumeric(right?.offset);
  if (leftOffset === null && rightOffset !== null) return 1;
  if (leftOffset !== null && rightOffset === null) return -1;
  if (leftOffset !== null && rightOffset !== null && leftOffset !== rightOffset) {
    return rightOffset - leftOffset;
  }

  const leftPriority = KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99;
  const rightPriority = KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99;
  if (leftPriority !== rightPriority) return leftPriority - rightPriority;

  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  return rightSize - leftSize;
}

function seedOffsetRange(seed) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size);
  if (offset === null || size === null) return null;
  return {
    start: offset,
    end: offset + size
  };
}

function isSeedInsideFrameBounds(seed, frameSize, wordSize) {
  const range = seedOffsetRange(seed);
  if (!range) return false;
  if (range.start < 0 && Number.isFinite(frameSize) && Math.abs(range.start) > frameSize) return false;
  if (normalizeEntryKind(seed?.kind) !== 'argument' && range.start > wordSize) return false;
  if (range.start < 0 && range.end > 0 && !isLikelyPointerSizedSeed(seed, wordSize)) return false;
  return true;
}

function crossesFrameBase(seed) {
  const range = seedOffsetRange(seed);
  if (!range) return false;
  return range.start < 0 && range.end > 0;
}

function isLikelyPointerSizedSeed(seed, wordSize) {
  return readPositiveInt(seed?.size) === readPositiveInt(wordSize);
}

function isWeakStaticSeed(seed) {
  const label = clean(seed?.label);
  return !label || isGenericName(label) || normalizeEntryKind(seed?.kind) === 'slot' || normalizeEntryKind(seed?.kind) === 'unknown';
}

function countSeedSupport(seed, observations, { functionName, bpRegister, meta } = {}) {
  const label = clean(seed?.label).toLowerCase();
  const support = {
    exact: 0,
    named: 0,
    overlap: 0
  };

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    if (readNumeric(observation?.offset) === readNumeric(seed?.offset)) {
      support.exact += 1;
    }

    const observationLabel = clean(firstNonEmpty(observation?.modelName, observation?.label)).toLowerCase();
    if (label && observationLabel && label === observationLabel) {
      support.named += 1;
    }

    if (isObservationCompatible(seed, observation)) {
      support.overlap += 1;
    }
  });

  if (!support.named && resolveRestrictedAbiArgumentName(seed, functionName, bpRegister, meta)) {
    support.named += 1;
  }

  return support;
}

function isLikelyPointerSpillSeed(seed, observations, wordSize, registerArguments) {
  const kind = normalizeEntryKind(seed?.kind);
  const label = clean(seed?.label).toLowerCase();
  const typeName = clean(seed?.typeName).toLowerCase();
  const size = readPositiveInt(seed?.size) ?? 0;
  if (size <= wordSize) return false;

  const hasPointerObservation = (Array.isArray(observations) ? observations : []).some((observation) => (
    readNumeric(observation?.offset) === readNumeric(seed?.offset)
    && (clean(observation?.pointerKind) || POINTER_HEX_RE.test(clean(observation?.displayValue || observation?.rawValue)))
  ));

  const matchesRegisterArgument = Array.isArray(registerArguments) && registerArguments.some((argument) => {
    const name = clean(argument?.name).toLowerCase();
    return Boolean(
      name
      && (
        label === name
        || label === name.replace(/^arg_/, '')
        || (SPECIAL_ARGUMENT_RE.test(label) && name.includes(label))
      )
    );
  });

  return Boolean(
    kind === 'argument'
    || SPECIAL_ARGUMENT_RE.test(label)
    || label.startsWith('arg_')
    || typeName.includes('*')
    || matchesRegisterArgument
    || hasPointerObservation
  );
}

function resolveNormalizedBufferSize(seed, observations, frameSize, wordSize) {
  const currentSize = readPositiveInt(seed?.size);
  if (currentSize === null) return null;

  const candidates = [currentSize];
  const seedLabel = clean(seed?.label).toLowerCase();
  const exactOffset = readNumeric(seed?.offset);

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    const observationSize = readPositiveInt(observation?.size);
    if (observationSize === null) return;
    const observationLabel = clean(firstNonEmpty(observation?.modelName, observation?.label)).toLowerCase();
    const sameLabel = Boolean(seedLabel && observationLabel && seedLabel === observationLabel);
    const exactStart = readNumeric(observation?.offset) === exactOffset;
    const trustedSource = resolveSourcePriority(observation?.modelSource || observation?.source) >= SOURCE_PRIORITY.static;
    const derivedSource = normalizeSource(observation?.modelSource || observation?.source) === 'derived'
      || normalizeSource(observation?.source) === 'derived';
    const strongBuffer = exactStart && (
      sameLabel
      || derivedSource
      || (trustedSource && (looksLikeBufferName(observationLabel) || looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))))
    );
    if (!strongBuffer) return;
    if (!exactStart && !isObservationCompatible(seed, observation)) return;
    candidates.push(observationSize);
  });

  const recovered = Math.max(...candidates);
  if (!Number.isFinite(recovered)) return currentSize;
  if (Number.isFinite(frameSize) && exactOffset !== null) {
    const maxAvailable = exactOffset < 0
      ? Math.abs(exactOffset)
      : Math.max(wordSize, frameSize + exactOffset);
    return Math.min(recovered, maxAvailable);
  }
  return recovered;
}

function shouldDropWeakStaticSeed(seed, compactedSeeds, observations, frameSize, wordSize) {
  if (!isWeakStaticSeed(seed)) return false;
  if (!isSeedInsideFrameBounds(seed, frameSize, wordSize)) return true;
  const support = countSeedSupport(seed, observations);
  if (support.exact || support.named) return false;
  return (Array.isArray(compactedSeeds) ? compactedSeeds : []).some((candidate) => seedsConflict(candidate, seed));
}

function shouldCompactSeeds(left, right) {
  if (!left || !right) return false;
  if (isProtectedKind(left?.kind) || isProtectedKind(right?.kind)) return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  const sameName = normalizedSeedName(left) && normalizedSeedName(left) === normalizedSeedName(right);
  const sameKind = normalizeEntryKind(left?.kind) === normalizeEntryKind(right?.kind);
  const overlapping = leftRange.start < rightRange.end && rightRange.start < leftRange.end;
  const touching = leftRange.end === rightRange.start || rightRange.end === leftRange.start;
  if (sameName) return overlapping || touching;
  return Boolean(sameKind && normalizeEntryKind(left?.kind) === 'buffer' && overlapping);
}

function mergeCompactedSeeds(left, right) {
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  const startOffset = Math.min(leftRange.start, rightRange.start);
  const endOffset = Math.max(leftRange.end, rightRange.end);
  const stronger = chooseMoreTrustworthySeed(left, right, [], {});
  const merged = {
    ...stronger,
    offset: startOffset,
    size: endOffset - startOffset,
    start: null,
    end: null,
    seedContributors: mergeSeedContributors(left?.seedContributors, right?.seedContributors)
  };
  if (parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null) {
    const baseAddress = parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset));
    merged.start = baseAddress + BigInt(startOffset);
    merged.end = merged.start + BigInt(merged.size);
  }
  return normalizeSeed(merged);
}

function seedsConflict(left, right) {
  if (!left || !right) return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  return leftRange.start < rightRange.end && rightRange.start < leftRange.end;
}

function shouldAllowNestedSeedCoexistence(left, right, observations) {
  if (!left || !right) return false;
  const leftKind = normalizeEntryKind(left?.kind);
  const rightKind = normalizeEntryKind(right?.kind);
  if (leftKind === rightKind) return false;

  const bufferSeed = leftKind === 'buffer' ? left : rightKind === 'buffer' ? right : null;
  const nestedSeed = bufferSeed === left ? right : bufferSeed === right ? left : null;
  if (!bufferSeed || !nestedSeed) return false;

  const bufferRange = seedOffsetRange(bufferSeed);
  const nestedRange = seedOffsetRange(nestedSeed);
  if (!bufferRange || !nestedRange) return false;
  if (nestedRange.start < bufferRange.start || nestedRange.end > bufferRange.end) return false;

  const nestedKind = normalizeEntryKind(nestedSeed?.kind);
  if (nestedKind === 'modified') return true;
  if (nestedKind === 'argument' || nestedKind === 'padding' || nestedKind === 'slot' || nestedKind === 'unknown') {
    return false;
  }

  const support = countSeedSupport(nestedSeed, observations);
  if (support.exact > 0) return true;
  return !isWeakStaticSeed(nestedSeed);
}

function chooseMoreTrustworthySeed(left, right, observations, context) {
  const leftScore = scoreStaticSeed(left, observations, context);
  const rightScore = scoreStaticSeed(right, observations, context);
  return rightScore > leftScore ? right : left;
}

function scoreStaticSeed(seed, observations, { functionName, bpRegister, meta } = {}) {
  if (!seed) return -Infinity;
  const support = countSeedSupport(seed, observations, { functionName, bpRegister, meta });
  const sourceScore = resolveSourcePriority(seed?.source);
  const confidenceScore = Number(seed?.confidence || 0) * 100;
  const exactScore = support.exact * 220;
  const namedScore = support.named * 180;
  const overlapScore = support.overlap * 20;
  const weakPenalty = isWeakStaticSeed(seed) ? 120 : 0;
  const pointerBonus = isLikelyPointerSizedSeed(seed, readPositiveInt(seed?.size)) ? 20 : 0;
  return sourceScore + confidenceScore + exactScore + namedScore + overlapScore + pointerBonus - weakPenalty;
}

function normalizedSeedName(seed) {
  const name = clean(seed?.label).toLowerCase();
  if (!name || isGenericName(name)) return '';
  return name;
}

function findStructuralGapForObservation(observation, existingEntries) {
  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return null;

  const realEntries = [...(Array.isArray(existingEntries) ? existingEntries : [])]
    .filter((entry) => !entry?.isSynthetic)
    .filter((entry) => seedOffsetRange(entry))
    .sort(compareSeedsForLayout);

  for (let index = 0; index < realEntries.length - 1; index += 1) {
    const upper = seedOffsetRange(realEntries[index]);
    const lower = seedOffsetRange(realEntries[index + 1]);
    if (!upper || !lower) continue;
    const gap = { start: lower.end, end: upper.start };
    if (gap.end <= gap.start) continue;
    if (observationRange.start >= gap.start && observationRange.end <= gap.end) {
      return gap;
    }
  }
  const lowest = realEntries[realEntries.length - 1];
  const lowestRange = seedOffsetRange(lowest);
  if (lowestRange && observationRange.end <= lowestRange.start) {
    return { start: observationRange.start, end: lowestRange.start };
  }
  return null;
}

function mergeSeedLists(...groups) {
  const merged = [];
  groups.forEach((group) => {
    (Array.isArray(group) ? group : []).forEach((seed) => addSeed(merged, seed));
  });
  return merged;
}

function addSeed(seeds, seed) {
  if (!seed) return;
  const normalized = normalizeSeed(seed);
  if (!normalized) return;
  const existingIndex = (Array.isArray(seeds) ? seeds : []).findIndex((entry) => seedIdentity(entry) === seedIdentity(normalized));
  if (existingIndex < 0) {
    seeds.push(normalized);
    return;
  }
  seeds[existingIndex] = chooseBetterSeed(seeds[existingIndex], normalized);
}

function normalizeSeed(seed) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size) ?? 1;
  const start = parseBigIntAddr(seed?.start);
  const kind = normalizeEntryKind(seed?.kind);
  if (offset === null && start === null) return null;
  return {
    offset,
    size,
    kind,
    start,
    end: start !== null ? start + BigInt(size) : null,
    source: normalizeSource(seed?.source),
    label: clean(seed?.label),
    nameSource: clean(seed?.nameSource) || normalizeSource(seed?.source),
    typeName: clean(seed?.typeName),
    confidence: readNumeric(seed?.confidence),
    isSynthetic: Boolean(seed?.isSynthetic),
    seedContributors: normalizeSeedContributors(seed?.seedContributors, {
      offset,
      size,
      kind,
      source: seed?.source,
      label: seed?.label,
      isSynthetic: seed?.isSynthetic
    })
  };
}

function seedIdentity(seed) {
  return [
    normalizeEntryKind(seed?.kind),
    seed?.offset ?? 'none',
    seed?.size ?? 'none',
    seed?.isSynthetic ? 'synthetic' : 'real'
  ].join(':');
}

function chooseBetterSeed(left, right) {
  const leftProtected = isProtectedKind(left?.kind) ? 1 : 0;
  const rightProtected = isProtectedKind(right?.kind) ? 1 : 0;
  if (rightProtected !== leftProtected) return rightProtected > leftProtected ? right : left;

  const leftSynthetic = left?.isSynthetic ? 1 : 0;
  const rightSynthetic = right?.isSynthetic ? 1 : 0;
  if (leftSynthetic !== rightSynthetic) return rightSynthetic < leftSynthetic ? right : left;

  const leftPriority = resolveSourcePriority(left?.source);
  const rightPriority = resolveSourcePriority(right?.source);
  if (rightPriority > leftPriority) return right;
  if (rightPriority < leftPriority) return left;

  const leftConfidence = Number(left?.confidence || 0);
  const rightConfidence = Number(right?.confidence || 0);
  if (rightConfidence > leftConfidence) return right;
  if (rightConfidence < leftConfidence) return left;

  const winner = String(right?.label || '').length > String(left?.label || '').length ? right : left;
  winner.seedContributors = mergeSeedContributors(left?.seedContributors, right?.seedContributors);
  return winner;
}

function seedFromObservation(observation, bpAddress, { synthetic, kindOverride } = {}) {
  const offset = readNumeric(observation?.offset);
  const size = readPositiveInt(observation?.size) ?? 1;
  const start = parseBigIntAddr(observation?.start)
    ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null);
  const source = normalizeSource(observation?.source);
  const kind = normalizeEntryKind(kindOverride || observation?.kind);
  return {
    offset,
    size,
    kind,
    start,
    source,
    label: synthetic ? '' : firstNonEmpty(observation?.modelName, observation?.label),
    nameSource: synthetic ? 'fallback' : normalizeSource(observation?.modelSource || observation?.source),
    typeName: firstNonEmpty(observation?.modelType, observation?.typeName),
    confidence: readNumeric(observation?.modelConfidence) ?? readNumeric(observation?.confidence),
    isSynthetic: Boolean(synthetic)
  };
}

function shouldCreateNamedSeed(observation, functionName, bpRegister, meta) {
  if (!observation || observation.offset === null) return false;
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind || kind === 'padding') return false;
  if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return false;
  if (observation.offset > 0) {
    return Boolean(resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta));
  }
  return hasTrustedDisplayName(observation);
}

function shouldCreateReliableSeed(observation, functionName, bpRegister, meta) {
  if (!observation || observation.offset === null) return false;
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind || kind === 'padding') return false;
  if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return false;
  if (observation.offset > 0) {
    return Boolean(resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta));
  }
  if (observation.sourcePriority >= SOURCE_PRIORITY.auto) return true;
  if (Boolean(clean(observation?.modelName))) return true;
  return kind === 'buffer' || kind === 'modified' || kind === 'argument' || kind === 'local';
}

function isCoveredByExistingSeed(seeds, observation) {
  return (Array.isArray(seeds) ? seeds : []).some((seed) => isObservationCompatible(seed, observation));
}

function isCoveredByStableSeedLayout(seeds, observation) {
  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return false;
  return (Array.isArray(seeds) ? seeds : []).some((seed) => {
    if (!seed || seed?.isSynthetic) return false;
    const range = seedOffsetRange(seed);
    if (!range) return false;
    if (!isStableGeometrySeed(seed)) return false;
    const exactOffset = readNumeric(seed?.offset) === readNumeric(observation?.offset);
    const contained = observationRange.start >= range.start && observationRange.end <= range.end;
    const overlap = range.start < observationRange.end && observationRange.start < range.end;
    if (exactOffset) return true;
    if (contained && areKindsCompatible(seed?.kind, observation?.kind)) return true;
    return normalizeEntryKind(seed?.kind) === 'buffer' && overlap;
  });
}

function isStableGeometrySeed(seed) {
  const kind = normalizeEntryKind(seed?.kind);
  if (isProtectedKind(kind)) return true;
  if (kind === 'buffer' || kind === 'argument') return true;
  if (resolveSourcePriority(seed?.source) >= SOURCE_PRIORITY.mcp) return true;
  return Boolean(clean(seed?.label) && !isGenericName(seed?.label));
}

function chooseEntryForObservation(entries, observation) {
  const matches = (Array.isArray(entries) ? entries : [])
    .filter((entry) => isObservationCompatible(entry, observation))
    .sort((left, right) => compareEntryMatch(left, right, observation));
  return matches[0] ?? null;
}

function compareEntryMatch(left, right, observation) {
  const leftScore = scoreEntryMatch(left, observation);
  const rightScore = scoreEntryMatch(right, observation);
  if (leftScore !== rightScore) return rightScore - leftScore;

  const leftSynthetic = left?.isSynthetic ? 1 : 0;
  const rightSynthetic = right?.isSynthetic ? 1 : 0;
  if (leftSynthetic !== rightSynthetic) return leftSynthetic - rightSynthetic;

  const leftPriority = resolveSourcePriority(left?.source);
  const rightPriority = resolveSourcePriority(right?.source);
  if (leftPriority !== rightPriority) return rightPriority - leftPriority;

  const leftKindPriority = KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99;
  const rightKindPriority = KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99;
  return leftKindPriority - rightKindPriority;
}

function scoreEntryMatch(entry, observation) {
  let score = 0;
  if (!entry || !observation) return score;

  const exactOffset = entry?.offset !== null && entry.offset === observation?.offset;
  const exactAddress = addressesEqual(entry?.start, observation?.start);
  const sizeCompatible = areSizesCompatible(entry?.size, observation?.size);
  const kindCompatible = areKindsCompatible(entry?.kind, observation?.kind);
  const containedBufferMatch = allowsContainedBufferObservationMatch(entry, observation);
  const overlapBytes = overlapByteCount(
    seedRangeStart(entry),
    seedRangeEnd(entry),
    observationRangeStart(observation),
    observationRangeEnd(observation)
  );

  if (exactOffset) score += 400;
  if (exactAddress) score += 300;
  if (sizeCompatible) score += 120;
  if (containedBufferMatch) score += 180;
  if (kindCompatible) score += 80;
  if (overlapBytes > 0) score += Math.min(60, overlapBytes);
  if (isProtectedKind(entry?.kind)) score += 50;

  const sizeDelta = Math.abs((readPositiveInt(entry?.size) ?? 0) - (readPositiveInt(observation?.size) ?? 0));
  score -= Math.min(40, sizeDelta);

  return score;
}

function isObservationCompatible(entry, observation) {
  if (!entry || !observation) return false;
  const entryStart = seedRangeStart(entry);
  const entryEnd = seedRangeEnd(entry);
  const observationStart = observationRangeStart(observation);
  const observationEnd = observationRangeEnd(observation);
  const exactOffset = entry?.offset !== null && observation?.offset !== null && entry.offset === observation.offset;
  const exactAddress = addressesEqual(entryStart, observationStart);
  const overlapBytes = overlapByteCount(entryStart, entryEnd, observationStart, observationEnd);
  const sizeCompatible = areSizesCompatible(entry?.size, observation?.size);
  const kindCompatible = areKindsCompatible(entry?.kind, observation?.kind);
  const containedBufferMatch = allowsContainedBufferObservationMatch(entry, observation);

  if (isProtectedKind(entry?.kind)) {
    return Boolean(
      exactAddress
      && readPositiveInt(entry?.size) !== null
      && readPositiveInt(entry?.size) === readPositiveInt(observation?.size)
    );
  }

  if (exactOffset) return true;
  if (exactAddress && sizeCompatible) return true;
  if (overlapBytes <= 0) return false;
  if ((!sizeCompatible && !containedBufferMatch) || !kindCompatible) return false;

  const smallest = Math.min(readPositiveInt(entry?.size) ?? 0, readPositiveInt(observation?.size) ?? 0);
  if (smallest <= 0) return false;

  if (containedBufferMatch) {
    const sameRangeClass = entry?.offset !== null && observation?.offset !== null && Math.sign(entry.offset) === Math.sign(observation.offset);
    return sameRangeClass;
  }

  const substantialOverlap = overlapBytes >= Math.max(4, Math.floor(smallest / 2));
  const startInside = observationStart !== null && entryStart !== null && observationStart >= entryStart && observationStart < entryEnd;
  const sameRangeClass = entry?.offset !== null && observation?.offset !== null && Math.sign(entry.offset) === Math.sign(observation.offset);
  return Boolean(substantialOverlap && startInside && sameRangeClass);
}

function allowsContainedBufferObservationMatch(entry, observation) {
  if (normalizeEntryKind(entry?.kind) !== 'buffer') return false;
  const entryStart = seedRangeStart(entry);
  const entryEnd = seedRangeEnd(entry);
  const observationStart = observationRangeStart(observation);
  const observationEnd = observationRangeEnd(observation);
  if (entryStart === null || entryEnd === null || observationStart === null || observationEnd === null) return false;
  return observationStart >= entryStart && observationEnd <= entryEnd;
}

function finalizeEntryBase(entry, { functionName, bpRegister, bpAddress, registerArguments, meta } = {}) {
  if (!entry) return null;
  const kind = normalizeEntryKind(entry.kind);
  const offset = readNumeric(entry.offset);
  const size = readPositiveInt(entry.size) ?? 1;
  const start = parseBigIntAddr(entry.start)
    ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null)
    ?? smallestObservationStart(entry.observations);
  const end = start !== null ? start + BigInt(size) : null;
  const observations = Array.isArray(entry.observations) ? entry.observations : [];
  const primaryObservation = pickPrimaryObservation(observations, offset, start);
  const flags = collectFlags(observations);
  const typeName = resolveEntryType(entry, primaryObservation);
  const probableBuffer = isProbableBuffer(entry, observations);
  const nameInfo = resolveEntryName(entry, {
    functionName,
    bpRegister,
    meta,
    probableBuffer
  });
  const key = buildEntryKey(functionName, bpRegister, offset, size, kind, entry.isSynthetic, start);
  const returnAddressIntegrity = validateReturnAddressIntegrity({
    kind,
    start,
    size,
    observations
  });

  return {
    key,
    kind,
    offset,
    size,
    start,
    end,
    source: normalizeSource(entry?.source),
    typeName,
    typeSource: clean(entry?.typeName) ? normalizeSource(entry?.source) : normalizeSource(primaryObservation?.modelSource || primaryObservation?.source),
    observations,
    primaryObservation,
    flags,
    valuePreview: buildValuePreview(primaryObservation),
    bpRegister,
    offsetLabel: formatCanonicalOffsetLabel(bpRegister, offset),
    offsetBand: resolveOffsetBand(offset),
    isSynthetic: Boolean(entry.isSynthetic),
    isSensitive: kind === 'return_address' || kind === 'saved_bp' || kind === 'buffer' || kind === 'modified',
    preferredName: clean(nameInfo?.name),
    preferredNameSource: clean(nameInfo?.source),
    probableBuffer,
    returnAddressIntegrity,
    registerLink: resolveRegisterArgumentLink(nameInfo?.name, registerArguments),
    commentHints: buildCommentHints({ kind, probableBuffer }),
    seedContributors: Array.isArray(entry?.seedContributors) ? entry.seedContributors : [],
    sortIndex: buildSortIndex(offset, kind)
  };
}

function finalizeDisplayEntry(entry, { functionName, bpRegister, registerArguments, allEntries, allObservations } = {}) {
  const detailPayload = buildDetailPayload({
    entry,
    functionName,
    bpRegister,
    registerArguments,
    allEntries,
    allObservations
  });
  return {
    key: entry.key,
    name: entry.name,
    kind: entry.kind,
    offset: entry.offset,
    offsetLabel: entry.offsetLabel,
    address: entry.start !== null ? toHex(entry.start) : '',
    size: entry.size,
    valuePreview: entry.valuePreview,
    nameSource: entry.nameSource,
    detailPayload,
    sortIndex: entry.sortIndex,
    isSynthetic: entry.isSynthetic,
    bpRegister: entry.bpRegister,
    offsetBand: entry.offsetBand,
    debug: buildEntryDebugMetadata(entry),
    badges: buildEntryBadges(entry),
    changed: entry.flags.includes('changed'),
    recentWrite: entry.flags.includes('recent_write'),
    recentRead: entry.flags.includes('recent_read'),
    isSensitive: Boolean(entry.isSensitive)
  };
}

function isFinalEntryAllowedInFrame(entry, frameScope) {
  if (!entry || !frameScope) return false;
  if (!frameScope.ownerMatches && normalizeEntryKind(entry?.kind) !== 'saved_bp' && normalizeEntryKind(entry?.kind) !== 'return_address') {
    return false;
  }
  const range = seedOffsetRange(entry);
  if (!range || !isOffsetRangeWithinFrameScope(range, frameScope)) return false;
  return true;
}

function assignStableFallbackNames(entries, { functionName, bpRegister, meta } = {}) {
  const counters = new Map();
  (Array.isArray(entries) ? entries : []).forEach((entry) => {
    if (clean(entry?.preferredName)) {
      entry.name = entry.preferredName;
      entry.nameSource = entry.preferredNameSource || 'runtime';
      entry.registerLink = resolveRegisterArgumentLink(entry.name, []);
      return;
    }

    const bucket = resolveFallbackBucket(entry, functionName, bpRegister, meta);
    const index = counters.get(bucket) ?? 0;
    counters.set(bucket, index + 1);
    entry.name = `${bucket}_${index}`;
    entry.nameSource = 'fallback';
  });
}

function buildLogicalArgumentEntries({ entries, registerArguments, model, bpRegister, wordSize, functionName, meta } = {}) {
  const namedArguments = buildNamedLogicalArguments({
    registerArguments,
    model,
    wordSize
  });

  if (!namedArguments.length) return [];

  const positiveNames = new Set(
    (Array.isArray(entries) ? entries : [])
      .filter((entry) => normalizeEntryKind(entry?.kind) === 'argument' && Number.isFinite(entry?.offset) && entry.offset > 0)
      .map((entry) => clean(entry?.name).toLowerCase())
      .filter(Boolean)
  );

  const candidates = [...(Array.isArray(entries) ? entries : [])]
    .filter((entry) => normalizeEntryKind(entry?.kind) === 'argument' && Number.isFinite(entry?.offset) && entry.offset < 0)
    .sort((left, right) => (right.offset ?? 0) - (left.offset ?? 0));

  const usedStorageKeys = new Set();
  const logicalEntries = [];

  namedArguments.forEach((argument) => {
    const normalizedName = clean(argument?.name).toLowerCase();
    if (positiveNames.has(normalizedName)) return;
    const storageEntry = pickLogicalArgumentStorageEntry(candidates, argument, usedStorageKeys);
    if (!storageEntry) return;
    usedStorageKeys.add(storageEntry.key);
    const visualOffset = resolveAbiVisualOffset(argument.name, wordSize, argument.index);
    logicalEntries.push({
      key: [
        normalizeFunctionName(functionName || ''),
        String(bpRegister || 'rbp').toLowerCase(),
        'logical_argument',
        normalizedName || `arg_${argument.index ?? logicalEntries.length}`
      ].join(':'),
      name: clean(argument?.name),
      kind: 'argument',
      size: readPositiveInt(storageEntry?.size) ?? argument.size ?? readPositiveInt(wordSize),
      offset: visualOffset,
      offsetLabel: formatCanonicalOffsetLabel(bpRegister, visualOffset),
      registerLocation: argument.location,
      storageKey: storageEntry.key,
      storageOffset: storageEntry.offset,
      storageOffsetLabel: storageEntry.offsetLabel || formatCanonicalOffsetLabel(bpRegister, storageEntry.offset),
      source: clean(argument?.source) || 'abi',
      cType: clean(argument?.cType),
      functionName: clean(functionName),
      archBits: Number(meta?.arch_bits) || 0
    });
  });

  return logicalEntries.sort(compareFrameEntries);
}

function buildNamedLogicalArguments({ registerArguments, model, wordSize } = {}) {
  const safeWordSize = readPositiveInt(wordSize) ?? 8;
  const sourceParameters = (Array.isArray(model?.parameters) ? model.parameters : [])
    .map((parameter, index) => ({
      index,
      name: clean(parameter?.name),
      location: clean(registerArguments?.[index]?.location).toLowerCase(),
      size: readPositiveInt(parameter?.byteSize) ?? readPositiveInt(registerArguments?.[index]?.size) ?? safeWordSize,
      cType: clean(parameter?.cType),
      source: 'source_c'
    }))
    .filter((parameter) => isMeaningfulLogicalArgumentName(parameter?.name));

  if (sourceParameters.length) return sourceParameters;

  return (Array.isArray(registerArguments) ? registerArguments : [])
    .map((argument, index) => ({
      index,
      name: clean(argument?.name),
      location: clean(argument?.location).toLowerCase(),
      size: readPositiveInt(argument?.size) ?? safeWordSize,
      cType: '',
      source: normalizeSource(argument?.source) || 'abi'
    }))
    .filter((argument) => {
      const normalized = clean(argument?.name).toLowerCase();
      return Boolean(
        normalized
        && (SPECIAL_ARGUMENT_NAMES.includes(normalized) || isMeaningfulLogicalArgumentName(argument?.name))
      );
    });
}

function isMeaningfulLogicalArgumentName(name) {
  const raw = clean(name);
  if (!raw) return false;
  if (GENERIC_ARG_RE.test(raw) || GENERIC_VAR_RE.test(raw) || GENERIC_STACK_RE.test(raw) || GENERIC_LOCAL_RE.test(raw)) {
    return false;
  }
  return !NAMELESS_LABELS.has(raw.toLowerCase());
}

function pickLogicalArgumentStorageEntry(candidates, argument, usedStorageKeys) {
  const scored = [...(Array.isArray(candidates) ? candidates : [])]
    .filter((entry) => !usedStorageKeys.has(entry?.key))
    .map((entry, orderIndex) => ({
      entry,
      score: scoreLogicalArgumentStorageEntry(entry, argument, orderIndex)
    }))
    .filter((entry) => Number.isFinite(entry.score) && entry.score > 0)
    .sort((left, right) => right.score - left.score || compareFrameEntries(left.entry, right.entry));

  return scored[0]?.entry || null;
}

function scoreLogicalArgumentStorageEntry(entry, argument, orderIndex) {
  if (!entry || !argument) return -Infinity;
  let score = 0;
  const size = readPositiveInt(entry?.size) ?? 0;
  const argSize = readPositiveInt(argument?.size) ?? 0;
  const hints = collectLogicalArgumentHints(entry);

  if (hints.includes(argument.name)) score += 1200;
  if (argument.location && hints.includes(argument.location)) score += 900;
  if (entry?.registerLink && clean(entry.registerLink).toLowerCase() === argument.location) score += 500;

  if (argSize && size === argSize) score += 220;
  else if (argument.name === 'argc' && size === 4) score += 180;
  else if (argument.name !== 'argc' && size >= 8) score += 160;

  if (argument.name === 'argv' && pointsToLikelyPointerData(entry)) score += 180;
  if (argument.name === 'argc' && !pointsToLikelyPointerData(entry)) score += 120;

  if (Number.isFinite(Number(argument?.index))) {
    score += Math.max(0, 120 - Math.abs(orderIndex - Number(argument.index)) * 40);
  }
  score += Math.max(0, 140 - orderIndex * 40);
  return score;
}

function collectLogicalArgumentHints(entry) {
  return uniqueStrings([
    clean(entry?.name),
    clean(entry?.preferredName),
    ...(Array.isArray(entry?.seedContributors) ? entry.seedContributors.map((seed) => seed?.label) : []),
    ...(Array.isArray(entry?.observations) ? entry.observations.flatMap((observation) => [observation?.label, observation?.modelName]) : [])
  ].map((value) => clean(value).toLowerCase()).filter(Boolean));
}

function pointsToLikelyPointerData(entry) {
  const value = clean(entry?.valuePreview);
  if (POINTER_HEX_RE.test(value)) return true;
  return (Array.isArray(entry?.observations) ? entry.observations : []).some((observation) => (
    Boolean(clean(observation?.pointerKind))
    || POINTER_HEX_RE.test(clean(observation?.displayValue || observation?.rawValue))
  ));
}

function resolveEntryName(entry, { functionName, bpRegister, meta, probableBuffer } = {}) {
  const kind = normalizeEntryKind(entry?.kind);
  const offset = readNumeric(entry?.offset);
  if (kind === 'saved_bp') {
    return { name: canonicalSavedBpName(bpRegister), source: 'control' };
  }
  if (kind === 'return_address') {
    return { name: 'return address', source: 'control' };
  }

  const abiArgumentName = resolveRestrictedAbiArgumentName(entry, functionName, bpRegister, meta);
  if (abiArgumentName) {
    return { name: abiArgumentName, source: 'abi' };
  }

  const candidates = collectNameCandidates(entry);
  const winner = candidates
    .map((candidate) => scoreNameCandidate(candidate, {
      functionName,
      offset,
      kind,
      bpRegister,
      probableBuffer
    }))
    .filter(Boolean)
    .sort((left, right) => right.score - left.score || left.name.localeCompare(right.name))[0];

  if (winner?.name) {
    return {
      name: winner.name,
      source: winner.source
    };
  }
  return { name: '', source: '' };
}

function collectNameCandidates(entry) {
  const candidates = [];
  const pushCandidate = (raw, source, priority, trusted) => {
    const value = clean(raw);
    if (!value) return;
    candidates.push({
      raw: value,
      source: normalizeSource(source),
      priority: Number(priority || 0),
      trusted: Boolean(trusted)
    });
  };

  pushCandidate(entry?.label, entry?.nameSource || entry?.source, resolveSourcePriority(entry?.source), true);

  (Array.isArray(entry?.observations) ? entry.observations : []).forEach((observation) => {
    pushCandidate(observation?.modelName, observation?.modelSource || observation?.source, resolveSourcePriority(observation?.modelSource || observation?.source), true);
    pushCandidate(observation?.label, observation?.source, observation?.sourcePriority, observation?.sourcePriority >= SOURCE_PRIORITY.auto);
  });

  return candidates;
}

function scoreNameCandidate(candidate, { functionName, offset, kind, bpRegister, probableBuffer } = {}) {
  const raw = clean(candidate?.raw);
  if (!raw) return null;

  const normalized = normalizeDisplayName(raw, kind, bpRegister);
  if (!normalized) return null;
  if (isGenericName(normalized)) return null;
  if (NAMELESS_LABELS.has(normalized.toLowerCase())) return null;

  if (SPECIAL_ARGUMENT_RE.test(normalized)) {
    if (!(kind === 'argument' || Boolean(resolveRestrictedAbiArgumentName({ offset, kind }, functionName, bpRegister)))) {
      return null;
    }
  }

  let bonus = 0;
  if (kind === 'buffer' && normalized === 'buffer') bonus += 160;
  if (kind === 'modified' && normalized === 'modified') bonus += 150;
  if (kind === 'argument' && SPECIAL_ARGUMENT_RE.test(normalized)) bonus += 140;
  if (probableBuffer && normalized === 'buffer') bonus += 60;

  return {
    name: normalized,
    source: clean(candidate?.source) || 'runtime',
    score: Number(candidate?.priority || 0) + (candidate?.trusted ? 60 : 0) + bonus
  };
}

function resolveFallbackBucket(entry, functionName, bpRegister, meta) {
  const kind = normalizeEntryKind(entry?.kind);
  if (kind === 'argument' && resolveRestrictedAbiArgumentName(entry, functionName, bpRegister, meta)) {
    return 'arg';
  }
  if (kind === 'argument') return 'arg';
  if (kind === 'buffer') return 'buffer';
  if (kind === 'padding') return 'padding';
  if (kind === 'unknown') return 'unknown';
  if (kind === 'slot') return 'slot';
  return 'local';
}

function resolveEntryType(entry, primaryObservation) {
  if (clean(entry?.typeName)) return clean(entry.typeName);
  if (clean(primaryObservation?.modelType)) return clean(primaryObservation.modelType);
  if (clean(primaryObservation?.typeName)) return clean(primaryObservation.typeName);
  return '';
}

function validateReturnAddressIntegrity({ kind, start, size, observations } = {}) {
  if (normalizeEntryKind(kind) !== 'return_address') {
    return { corrupted: false, suspect: false, exactObservation: null };
  }
  const slotAddress = parseBigIntAddr(start);
  const width = readPositiveInt(size);
  if (slotAddress === null || width === null) {
    return { corrupted: false, suspect: hasCorruptionSignal(observations), exactObservation: null };
  }

  const exactObservation = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => addressesEqual(item?.start, slotAddress) && readPositiveInt(item?.size) === width)
    .sort((left, right) => resolveSourcePriority(right?.source) - resolveSourcePriority(left?.source))[0] ?? null;

  if (!exactObservation) {
    return { corrupted: false, suspect: hasCorruptionSignal(observations), exactObservation: null };
  }

  const pointerKind = clean(exactObservation?.pointerKind).toLowerCase();
  const hexValue = clean(exactObservation?.displayValue || exactObservation?.rawValue);
  const hasWriteSignal = Boolean(exactObservation?.recentWrite || exactObservation?.changed || uniqueStrings(exactObservation?.flags).includes('corrupted'));
  const looksBadPointer = Boolean(
    hexValue
    && POINTER_HEX_RE.test(hexValue)
    && /(4141|4242|4343|4444|4545|9090)/i.test(hexValue.replace(/^0x/i, ''))
  );

  const corrupted = Boolean(
    hasWriteSignal
    && (!pointerKind || pointerKind !== 'code')
    && (looksBadPointer || pointerKind === 'stack' || pointerKind === 'heap' || pointerKind === 'data' || pointerKind === 'unknown')
  );

  return {
    corrupted,
    suspect: !corrupted && hasCorruptionSignal([exactObservation]),
    exactObservation
  };
}

function buildEntryBadges(entry) {
  const badges = [];
  const integrity = entry?.returnAddressIntegrity || { corrupted: false };
  if (integrity.corrupted) badges.push('CORRUPTED');
  else if (Array.isArray(entry?.flags) && entry.flags.includes('changed')) badges.push('CHANGED');
  else if (Array.isArray(entry?.flags) && entry.flags.includes('recent_write')) badges.push('WRITE');
  else if (Array.isArray(entry?.flags) && entry.flags.includes('recent_read')) badges.push('READ');
  if (normalizeEntryKind(entry?.kind) === 'return_address') badges.push('RET');
  return uniqueStrings(badges).slice(0, 2);
}

function buildDetailPayload({
  entry,
  functionName,
  bpRegister,
  registerArguments,
  allEntries,
  allObservations
} = {}) {
  const observations = Array.isArray(entry?.observations) ? entry.observations : [];
  const primaryObservation = entry?.primaryObservation || null;
  const rows = [
    { label: 'Nom', value: entry?.name || 'slot' },
    { label: 'Categorie', value: KIND_LABELS[normalizeEntryKind(entry?.kind)] || 'local' },
    { label: 'Taille', value: `${entry?.size || 0} octet${Number(entry?.size || 0) > 1 ? 's' : ''}` },
    { label: 'Adresse', value: entry?.start !== null ? toHex(entry.start) : 'n/a' },
    { label: 'Offset', value: entry?.offsetLabel || 'n/a' }
  ];

  if (clean(entry?.typeName)) rows.push({ label: 'Type', value: entry.typeName });
  if (clean(entry?.typeSource)) rows.push({ label: 'Source du type', value: formatSourceLabel(entry.typeSource) });

  const slotValue = clean(primaryObservation?.displayValue || primaryObservation?.rawValue);
  if (slotValue) rows.push({ label: 'Valeur du slot', value: slotValue });

  const pointerValue = pickPointerValue(primaryObservation, entry?.size);
  const pointerLike = Boolean(pointerValue);
  if (pointerLike) rows.push({ label: 'Pointeur', value: pointerValue });

  const pointedEntry = pointerLike ? resolvePointedEntry(pointerValue, allEntries, entry) : null;
  const pointedObservation = !pointedEntry && pointerLike
    ? resolvePointedObservation(pointerValue, allObservations, entry)
    : null;
  if (pointedEntry) {
    rows.push({
      label: 'Memoire pointee',
      value: `${pointedEntry.name}${pointedEntry.offsetLabel ? ` (${pointedEntry.offsetLabel})` : ''}`
    });
    const pointedText = pickAscii(pointedEntry.observations);
    if (pointedText) rows.push({ label: 'Texte pointe', value: pointedText });
  } else if (pointedObservation) {
    const pointedName = firstNonEmpty(
      normalizeDisplayName(pointedObservation.modelName || pointedObservation.label, pointedObservation.kind, bpRegister),
      normalizeDisplayName(pointedObservation.label, pointedObservation.kind, bpRegister),
      pointerValue
    );
    rows.push({
      label: 'Memoire pointee',
      value: `${pointedName}${pointedObservation.offset !== null ? ` (${formatCanonicalOffsetLabel(bpRegister, pointedObservation.offset)})` : ''}`
    });
    const pointedText = firstNonEmpty(pickAscii([pointedObservation]), clean(pointedObservation.displayValue));
    if (pointedText) rows.push({ label: 'Texte pointe', value: pointedText });
  }

  const slotText = !pointerLike ? pickAscii(observations) : '';
  if (slotText) rows.push({ label: 'Texte du slot', value: slotText });

  const hexValue = pickHexValue(primaryObservation, observations);
  if (hexValue) rows.push({ label: 'Hex', value: hexValue });

  rows.push({ label: 'Source du nom', value: formatSourceLabel(entry?.nameSource) || 'fallback' });
  rows.push({ label: 'Fonction', value: functionName ? `${functionName}()` : 'n/a' });

  const registerLink = resolveRegisterArgumentLink(entry?.name, registerArguments);
  if (registerLink) rows.push({ label: 'Registre source', value: registerLink });

  const mutations = buildMutationSummary(entry?.flags);
  if (mutations.length) rows.push({ label: 'Mutation', value: mutations.join(', ') });

  if (entry?.returnAddressIntegrity?.corrupted) {
    rows.push({ label: 'Statut', value: 'corrupted' });
  } else if (entry?.returnAddressIntegrity?.suspect || uniqueStrings(entry?.flags).includes('corrupted')) {
    rows.push({ label: 'Statut', value: 'suspect' });
  }

  const bytes = pickBytes(observations);
  if (bytes) rows.push({ label: 'Bytes', value: bytes });

  const ranges = observedRanges(observations);
  if (ranges.length) rows.push({ label: 'Plage observee', value: ranges.join(', ') });

  const comments = uniqueStrings([
    ...entry.commentHints,
    ...(Array.isArray(observations) ? observations.map((item) => item.comment) : [])
  ]);
  if (comments.length) rows.push({ label: 'Commentaire', value: comments.join(' | ') });

  return {
    rows,
    subtitle: entry?.offsetLabel || KIND_LABELS[normalizeEntryKind(entry?.kind)] || 'slot'
  };
}

function buildCommentHints({ kind, probableBuffer } = {}) {
  const hints = [];
  if (normalizeEntryKind(kind) === 'local' && probableBuffer) {
    hints.push('probable buffer');
  }
  return hints;
}

function buildEntryDebugMetadata(entry) {
  const seedKinds = uniqueStrings((Array.isArray(entry?.seedContributors) ? entry.seedContributors : []).map((seed) => normalizeEntryKind(seed?.kind)));
  const seedSources = uniqueStrings((Array.isArray(entry?.seedContributors) ? entry.seedContributors : []).map((seed) => classifyDebugSource(seed?.source, seed?.isSynthetic, seed?.kind)));
  const observationCount = Array.isArray(entry?.observations) ? entry.observations.length : 0;
  const seedCount = Array.isArray(entry?.seedContributors) && entry.seedContributors.length ? entry.seedContributors.length : 1;
  return {
    identityKey: entry?.key || '',
    primarySource: classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind),
    mergedObservationCount: Math.max(observationCount, seedCount ? 1 : 0),
    seedCount,
    seedKinds,
    seedSources
  };
}

function buildFrameDebugModel({ controlSeeds, reliableStaticSeeds, compactedSeeds, syntheticEntries, finalizedEntries, logicalArguments, bpRegister } = {}) {
  return {
    seeds: [
      ...toDebugSeedSummaries(controlSeeds, 'control', bpRegister),
      ...toDebugSeedSummaries(reliableStaticSeeds, 'static', bpRegister),
      ...toDebugSeedSummaries(compactedSeeds, 'compacted', bpRegister),
      ...toDebugEntrySummaries(syntheticEntries, 'synthetic', bpRegister)
    ],
    items: toDebugItemSummaries(finalizedEntries),
    logicalArguments: toDebugLogicalArgumentSummaries(logicalArguments)
  };
}

function normalizeSeedContributors(seedContributors, fallback) {
  const normalized = Array.isArray(seedContributors) && seedContributors.length
    ? seedContributors
    : [fallback];
  return normalized
    .map((seed) => ({
      offset: readNumeric(seed?.offset),
      size: readPositiveInt(seed?.size) ?? 1,
      kind: normalizeEntryKind(seed?.kind),
      source: normalizeSource(seed?.source),
      label: clean(seed?.label),
      isSynthetic: Boolean(seed?.isSynthetic)
    }))
    .filter((seed) => seed.offset !== null || seed.label || seed.kind !== 'unknown');
}

function mergeSeedContributors(left, right) {
  const seeds = [
    ...(Array.isArray(left) ? left : []),
    ...(Array.isArray(right) ? right : [])
  ];
  const byIdentity = new Map();
  seeds.forEach((seed) => {
    const normalized = normalizeSeedContributors([seed], null)[0];
    if (!normalized) return;
    const identity = [
      normalized.kind,
      normalized.offset ?? 'none',
      normalized.size ?? 'none',
      normalized.source,
      normalized.label || 'nolabel',
      normalized.isSynthetic ? 'synthetic' : 'real'
    ].join(':');
    if (!byIdentity.has(identity)) byIdentity.set(identity, normalized);
  });
  return [...byIdentity.values()];
}

function toDebugSeedSummaries(seeds, stage, bpRegister) {
  return (Array.isArray(seeds) ? seeds : []).map((seed) => ({
    stage,
    kind: normalizeEntryKind(seed?.kind),
    offset: formatCanonicalOffsetLabel(bpRegister || 'rbp', readNumeric(seed?.offset)) || '',
    size: readPositiveInt(seed?.size),
    source: classifyDebugSource(seed?.source, seed?.isSynthetic, seed?.kind),
    label: clean(seed?.label),
    key: seedIdentity(seed)
  }));
}

function toDebugEntrySummaries(entries, stage, bpRegister) {
  return (Array.isArray(entries) ? entries : []).map((entry) => ({
    stage,
    kind: normalizeEntryKind(entry?.kind),
    offset: formatCanonicalOffsetLabel(entry?.bpRegister || bpRegister || 'rbp', readNumeric(entry?.offset)) || '',
    size: readPositiveInt(entry?.size),
    source: classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind),
    label: clean(entry?.label),
    key: seedIdentity(entry)
  }));
}

function toDebugItemSummaries(entries) {
  const sourceOrder = { static: 0, runtime: 1, control: 2, synthetic: 3 };
  return (Array.isArray(entries) ? entries : [])
    .map((entry) => ({
      key: clean(entry?.key),
      name: clean(entry?.name),
      kind: normalizeEntryKind(entry?.kind),
      offset: clean(entry?.offsetLabel),
      rawOffset: readNumeric(entry?.offset),
      size: readPositiveInt(entry?.size),
      source: clean(entry?.debug?.primarySource || classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind)),
      mergedObservationCount: Number(entry?.debug?.mergedObservationCount ?? (Array.isArray(entry?.observations) ? entry.observations.length : 0)) || 0
    }))
    .sort((left, right) => {
      const leftSourceOrder = sourceOrder[left.source] ?? 9;
      const rightSourceOrder = sourceOrder[right.source] ?? 9;
      if (leftSourceOrder !== rightSourceOrder) return leftSourceOrder - rightSourceOrder;

      const leftOffset = left.rawOffset;
      const rightOffset = right.rawOffset;
      const leftPositive = Number.isFinite(leftOffset) && leftOffset > 0;
      const rightPositive = Number.isFinite(rightOffset) && rightOffset > 0;
      if (leftPositive !== rightPositive) return leftPositive ? -1 : 1;
      if (leftPositive && rightPositive && leftOffset !== rightOffset) return leftOffset - rightOffset;

      if (Number.isFinite(leftOffset) && Number.isFinite(rightOffset) && leftOffset !== rightOffset) {
        return rightOffset - leftOffset;
      }
      return String(left.name || '').localeCompare(String(right.name || ''));
    })
    .map(({ rawOffset, ...entry }) => entry);
}

function toDebugLogicalArgumentSummaries(entries) {
  return (Array.isArray(entries) ? entries : []).map((entry) => ({
    name: clean(entry?.name),
    offset: clean(entry?.offsetLabel),
    size: readPositiveInt(entry?.size),
    storageKey: clean(entry?.storageKey),
    storageOffset: clean(entry?.storageOffsetLabel),
    register: clean(entry?.registerLocation)
  }));
}

function classifyDebugSource(source, isSynthetic, kind) {
  if (Boolean(isSynthetic)) return 'synthetic';
  if (isProtectedKind(kind)) return 'control';
  const normalized = normalizeSource(source);
  if (normalized === 'control') return 'control';
  if (normalized === 'heuristic' || normalized === 'runtime' || normalized === 'derived' || normalized === 'unknown') return 'runtime';
  return 'static';
}

function classifyTrustedSeedKind({ rawKind, label, typeName, offset, functionName, bpRegister, meta } = {}) {
  const normalizedRole = normalizeEntryKind(rawKind);
  if (normalizedRole === 'saved_bp' || normalizedRole === 'return_address') return normalizedRole;

  const cleanedLabel = clean(label);
  const type = clean(typeName).toLowerCase();
  if (SPECIAL_ARGUMENT_RE.test(cleanedLabel)) return 'argument';
  if (normalizeDisplayName(cleanedLabel, normalizedRole, bpRegister) === 'modified') return 'modified';
  if (looksLikeBufferName(cleanedLabel) || looksLikeArrayType(type)) return 'buffer';
  if (normalizedRole === 'buffer') return 'buffer';
  if (normalizedRole === 'argument') return 'argument';
  if (normalizedRole === 'modified') return 'modified';
  if (normalizedRole === 'padding') return 'padding';
  if (normalizedRole === 'slot') return 'slot';
  if (normalizedRole === 'local') return 'local';
  if (resolveRestrictedAbiArgumentName({ offset, kind: normalizedRole, label }, functionName, bpRegister, meta)) return 'argument';
  return offset !== null && offset < 0 ? 'local' : normalizedRole;
}

function classifyObservationSeedKind(observation, functionName, bpRegister, meta) {
  const kind = normalizeEntryKind(observation?.kind || observation?.role);
  const label = firstNonEmpty(observation?.modelName, observation?.label);
  const typeName = firstNonEmpty(observation?.modelType, observation?.typeName);

  if (kind === 'saved_bp' || kind === 'return_address') return kind;
  if (kind === 'padding') return 'padding';
  if (kind === 'modified') return 'modified';
  if (kind === 'argument') return 'argument';
  if (kind === 'buffer' && isStrongBufferObservation(observation)) return 'buffer';

  if (SPECIAL_ARGUMENT_RE.test(clean(label))) return 'argument';
  if (resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta)) return 'argument';
  if (normalizeDisplayName(label, kind, bpRegister) === 'modified') return 'modified';
  if (looksLikeBufferName(label) || looksLikeArrayType(typeName) || (kind === 'buffer' && isStrongBufferObservation(observation))) return 'buffer';
  if (GENERIC_ARG_RE.test(clean(label))) return 'argument';
  if (GENERIC_VAR_RE.test(clean(label)) || BUFFER_STYLE_LABEL_RE.test(clean(label)) || GENERIC_LOCAL_RE.test(clean(label))) return 'local';
  if (GENERIC_STACK_RE.test(clean(label))) return 'slot';
  if (kind === 'local') return probableBufferFromObservation(observation) ? 'local' : 'local';
  if (kind === 'unknown' && observation?.offset !== null && observation.offset < 0 && observation?.sourcePriority >= SOURCE_PRIORITY.auto) return 'slot';
  return kind;
}

function classifySyntheticObservationKind(observation, functionName, bpRegister, meta, gap) {
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind) return null;
  if (kind === 'saved_bp' || kind === 'return_address') return null;
  if (kind === 'padding') return 'padding';
  if (kind === 'buffer') {
    if (hasConcreteSyntheticBufferProof(observation)) return 'buffer';
    return classifyStructuralHoleFallback(observation, gap);
  }
  if (kind === 'argument') return isStrictStackSeedAllowed({ offset: observation?.offset, kind, functionName, bpRegister, meta }) ? 'argument' : null;
  if (kind === 'modified') return 'local';
  if (kind === 'local') return 'local';
  if (kind === 'slot') return observation?.sourcePriority >= SOURCE_PRIORITY.auto ? 'slot' : 'unknown';
  return observation?.sourcePriority >= SOURCE_PRIORITY.auto ? 'slot' : 'unknown';
}

function hasConcreteSyntheticBufferProof(observation) {
  const sourcePriority = resolveSourcePriority(observation?.modelSource || observation?.source);
  if (sourcePriority < SOURCE_PRIORITY.static) return false;
  return Boolean(
    looksLikeBufferName(firstNonEmpty(observation?.modelName, observation?.label))
    || looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))
  );
}

function classifyStructuralHoleFallback(observation, gap) {
  const size = readPositiveInt(observation?.size) ?? 0;
  const gapSize = gap ? Math.max(0, Number(gap.end || 0) - Number(gap.start || 0)) : 0;
  const hasMaterial = Boolean(
    clean(observation?.ascii)
    || clean(observation?.bytesHex)
    || clean(observation?.displayValue)
    || clean(observation?.rawValue)
    || observation?.recentWrite
    || observation?.changed
  );
  if (!hasMaterial) return 'padding';
  if (size <= 8 || (gapSize && size >= gapSize)) return 'padding';
  return 'unknown';
}

function isStrictStackSeedAllowed({ offset, kind, functionName, bpRegister, meta } = {}) {
  const numericOffset = readNumeric(offset);
  const normalizedKind = normalizeEntryKind(kind);
  if (numericOffset === null) return false;
  if (normalizedKind === 'saved_bp' || normalizedKind === 'return_address') return true;
  if (numericOffset <= 0) return true;
  if (normalizedKind !== 'argument') return false;
  return Boolean(resolveRestrictedAbiArgumentName({ offset: numericOffset, kind }, functionName, bpRegister, meta));
}

function resolveRestrictedAbiArgumentName(entryLike, functionName, bpRegister, meta) {
  const offset = readNumeric(entryLike?.offset);
  const label = firstNonEmpty(entryLike?.name, entryLike?.label, entryLike?.technicalLabel, entryLike?.modelName);
  const normalizedLabel = clean(normalizeDisplayName(label, entryLike?.kind, bpRegister));
  if (SPECIAL_ARGUMENT_RE.test(normalizedLabel)) return normalizedLabel;

  const isMainFunction = sameFunction(functionName, 'main');
  const is32BitBp = String(bpRegister || '').toLowerCase() === 'ebp' && Number(meta?.arch_bits || 32) === 32;
  if (!isMainFunction || !is32BitBp || !Number.isFinite(offset) || offset <= 0) return '';
  const candidate = MAIN_ARGUMENT_NAMES.get(Number(offset)) || '';
  if (!candidate) return '';

  const sourcePriority = resolveSourcePriority(entryLike?.source || entryLike?.modelSource);
  const semanticKind = normalizeEntryKind(entryLike?.kind || entryLike?.role);
  if (semanticKind === 'argument' || sourcePriority >= SOURCE_PRIORITY.static || GENERIC_ARG_RE.test(clean(label))) {
    return candidate;
  }
  return '';
}

function buildEntryKey(functionName, bpRegister, offset, size, kind, isSynthetic, start) {
  if (offset !== null) {
    return [
      normalizeFunctionName(functionName || ''),
      String(bpRegister || 'rbp').toLowerCase(),
      normalizeEntryKind(kind),
      offset,
      size,
      isSynthetic ? 'synthetic' : 'frame'
    ].join(':');
  }
  return [
    normalizeFunctionName(functionName || ''),
    String(bpRegister || 'rbp').toLowerCase(),
    normalizeEntryKind(kind),
    start !== null ? toHex(start) : 'unknown',
    size,
    isSynthetic ? 'synthetic' : 'frame'
  ].join(':');
}

function buildSortIndex(offset, kind) {
  if (offset === null) return 999999;
  return offset * -1000 + (KIND_PRIORITY[normalizeEntryKind(kind)] ?? 99);
}

function compareFrameEntries(left, right) {
  const leftOffset = left?.offset;
  const rightOffset = right?.offset;
  if (leftOffset === null && rightOffset !== null) return 1;
  if (leftOffset !== null && rightOffset === null) return -1;
  if (leftOffset !== null && rightOffset !== null && leftOffset !== rightOffset) {
    return rightOffset - leftOffset;
  }
  const kindDelta = (KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99) - (KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99);
  if (kindDelta !== 0) return kindDelta;
  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  if (leftSize !== rightSize) return rightSize - leftSize;
  return String(left?.preferredName || left?.name || '').localeCompare(String(right?.preferredName || right?.name || ''));
}

function buildRuntimeObservations(slots, bpAddress) {
  return (Array.isArray(slots) ? slots : [])
    .map((slot, index) => {
      const offset = readNumeric(slot?.offsetFromBp);
      const size = readPositiveInt(slot?.size) ?? 1;
      const start = parseBigIntAddr(slot?.addressLabel)
        ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null);
      const label = firstNonEmpty(slot?.technicalLabel, slot?.modelName);
      const modelName = clean(slot?.modelName);
      const modelRole = clean(slot?.modelRole);
      const semanticKind = normalizeEntryKind(slot?.semanticRole || slot?.rawRole || slot?.visualRole || modelRole);
      return {
        key: clean(slot?.key) || `runtime-${index}`,
        label,
        modelName,
        modelRole,
        modelType: clean(slot?.modelType),
        modelSource: normalizeSource(slot?.modelSource),
        modelConfidence: readNumeric(slot?.modelConfidence),
        role: semanticKind,
        kind: semanticKind,
        source: normalizeSource(slot?.source || slot?.modelSource),
        sourcePriority: resolveSourcePriority(slot?.source || slot?.modelSource),
        confidence: readNumeric(slot?.confidence) ?? readNumeric(slot?.modelConfidence),
        size,
        offset,
        start,
        end: start !== null ? start + BigInt(size) : null,
        addressLabel: start !== null ? toHex(start) : clean(slot?.addressLabel),
        displayValue: cleanValue(slot?.displayValue || slot?.rawValue),
        rawValue: cleanValue(slot?.rawValue),
        typeName: clean(slot?.modelType),
        comment: clean(slot?.comment),
        flags: uniqueStrings(slot?.flags),
        changed: Boolean(slot?.changed),
        recentWrite: Boolean(slot?.recentWrite),
        recentRead: Boolean(slot?.recentRead),
        bytesHex: clean(slot?.bytesHex),
        ascii: clean(slot?.ascii),
        pointerKind: clean(slot?.pointerKind),
        payloadRelated: Boolean(slot?.payloadRelated),
        activePointers: Array.isArray(slot?.activePointers) ? slot.activePointers.map((value) => clean(value)).filter(Boolean) : []
      };
    })
    .filter((item) => item.offset !== null || item.start !== null);
}

function buildDetailModel(entries, selectedSlotKey) {
  const selected = (Array.isArray(entries) ? entries : []).find((entry) => entry.key === String(selectedSlotKey || ''));
  if (!selected) return null;
  return {
    key: selected.key,
    title: selected.name,
    subtitle: selected.detailPayload?.subtitle || selected.offsetLabel || '',
    rows: Array.isArray(selected.detailPayload?.rows) ? selected.detailPayload.rows : [],
    badges: Array.isArray(selected.badges) ? selected.badges : []
  };
}

function buildWorkspaceStatus(frameModel) {
  if (!frameModel || !Array.isArray(frameModel.entries) || !frameModel.entries.length) {
    const stepText = frameModel?.currentStep ? ` • etape ${frameModel.currentStep}` : '';
    return `${frameModel?.functionName || 'frame'}()${stepText} • frame vide`;
  }
  const bits = [`${frameModel.functionName}()`];
  if (frameModel.currentStep) bits.push(`etape ${frameModel.currentStep}`);
  bits.push(`${frameModel.entries.length} element${frameModel.entries.length > 1 ? 's' : ''}`);
  if (frameModel.frameSize) bits.push(`frame ${frameModel.frameSize}B`);
  return bits.join(' • ');
}

function buildPanelTitle(panelMode, functionName) {
  if (panelMode === 'frame') {
    return `Stack Frame de ${clean(functionName) || 'fonction'}()`;
  }
  return '.text';
}

function buildPanelSubtitle(panelMode, functionList, frameModel) {
  if (panelMode === 'frame') {
    return buildWorkspaceStatus(frameModel);
  }
  const count = Array.isArray(functionList) ? functionList.length : 0;
  if (!count) return 'Aucune fonction dans la trace.';
  const sourceBacked = functionList.some((entry) => entry?.sourceBacked);
  const scope = sourceBacked ? 'du code' : 'dans la trace';
  return `${count} fonction${count > 1 ? 's' : ''} ${scope}`;
}

function buildFunctionList({ snapshots, meta, selectedFunction, currentFunction }) {
  const byName = new Map();
  const sourceFunctions = collectSourceFunctionEntries(meta);

  sourceFunctions.forEach((fn, index) => {
    const displayName = displayFunctionName(fn?.name || fn?.normalizedName || '');
    const normalized = normalizeFunctionName(fn?.normalizedName || displayName);
    if (!normalized || byName.has(normalized)) return;
    byName.set(normalized, {
      key: normalized,
      displayName,
      firstStep: null,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: Number.isFinite(Number(fn?.index)) ? Number(fn.index) : index,
      sourceBacked: true
    });
  });

  (Array.isArray(snapshots) ? snapshots : []).forEach((snap, index) => {
    const displayName = displayFunctionName(snap?.func || '');
    const normalized = normalizeFunctionName(displayName);
    if (!normalized) return;
    if (sourceFunctions.length && !byName.has(normalized)) return;
    const existing = byName.get(normalized) || {
      key: normalized,
      displayName,
      firstStep: index + 1,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: null,
      sourceBacked: false
    };
    if (existing.firstStep === null || existing.firstStep === undefined) {
      existing.firstStep = index + 1;
    }
    existing.stepCount += 1;
    byName.set(normalized, existing);
  });

  const symbols = Array.isArray(meta?.functions) ? meta.functions : [];
  symbols.forEach((symbol) => {
    const displayName = displayFunctionName(symbol?.name || '');
    const normalized = normalizeFunctionName(displayName);
    if (!normalized || !byName.has(normalized)) return;
    const entry = byName.get(normalized);
    if (!entry.addressLabel && clean(symbol?.addr)) entry.addressLabel = clean(symbol.addr);
    if (!entry.symbolType && clean(symbol?.type)) entry.symbolType = clean(symbol.type);
  });

  const items = [...byName.values()].sort((left, right) => {
    if (left.sourceBacked || right.sourceBacked) {
      const leftOrder = Number.isFinite(Number(left.sourceOrder)) ? Number(left.sourceOrder) : Number.MAX_SAFE_INTEGER;
      const rightOrder = Number.isFinite(Number(right.sourceOrder)) ? Number(right.sourceOrder) : Number.MAX_SAFE_INTEGER;
      if (leftOrder !== rightOrder) return leftOrder - rightOrder;
    }
    if (left.stepCount && !right.stepCount) return -1;
    if (!left.stepCount && right.stepCount) return 1;
    if (left.firstStep === null && right.firstStep !== null) return 1;
    if (left.firstStep !== null && right.firstStep === null) return -1;
    if (left.firstStep !== right.firstStep) return left.firstStep - right.firstStep;
    return left.displayName.localeCompare(right.displayName);
  });

  if (!items.length) {
    const fallback = displayFunctionName(selectedFunction || currentFunction || '');
    if (!fallback) return [];
    items.push({
      key: normalizeFunctionName(fallback),
      displayName: fallback,
      firstStep: 1,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: null,
      sourceBacked: false
    });
  }

  const selectedKey = normalizeFunctionName(selectedFunction || '');
  const currentKey = normalizeFunctionName(currentFunction || '');
  return items.map((entry) => ({
    ...entry,
    isSelected: entry.key === selectedKey,
    isCurrent: Boolean(currentKey && entry.key === currentKey)
  }));
}

function collectSourceFunctionEntries(meta) {
  const enrichment = meta?.source_enrichment && typeof meta.source_enrichment === 'object'
    ? meta.source_enrichment
    : null;
  if (!enrichment || enrichment.enabled !== true) return [];
  return (Array.isArray(enrichment.functions) ? enrichment.functions : [])
    .filter((entry) => normalizeFunctionName(entry?.normalizedName || entry?.name || ''));
}

function resolveModelForFunction(model, activeFunction, currentFunction) {
  if (!model || !Array.isArray(model.locals)) return null;
  const modelName = displayFunctionName(model.name || '');
  if (sameFunction(modelName, activeFunction) || sameFunction(modelName, currentFunction)) {
    return model;
  }
  return null;
}

function buildFrameSignature({ meta, functionName, bpRegister, bpAddress, currentStep, model, entries } = {}) {
  const signatureParts = {
    binary: clean(meta?.binary),
    archBits: Number(meta?.arch_bits) || 0,
    function: normalizeFunctionName(functionName || ''),
    bpRegister: String(bpRegister || 'rbp').toLowerCase(),
    bpAddress: bpAddress !== null ? toHex(bpAddress) : '',
    step: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    locals: (Array.isArray(model?.locals) ? model.locals : [])
      .map((local) => ({
        name: clean(local?.name),
        offset: readNumeric(local?.offset),
        size: readPositiveInt(local?.size),
        role: normalizeEntryKind(local?.role),
        type: clean(local?.cType)
      }))
      .sort((left, right) => {
        if ((left.offset ?? 0) !== (right.offset ?? 0)) return (left.offset ?? 0) - (right.offset ?? 0);
        return String(left.name || '').localeCompare(String(right.name || ''));
      }),
    entries: (Array.isArray(entries) ? entries : [])
      .map((entry) => ({
        offset: entry?.offset ?? null,
        size: entry?.size ?? null,
        kind: normalizeEntryKind(entry?.kind),
        synthetic: Boolean(entry?.isSynthetic)
      }))
      .sort((left, right) => {
        if ((left.offset ?? 0) !== (right.offset ?? 0)) return (left.offset ?? 0) - (right.offset ?? 0);
        return String(left.kind || '').localeCompare(String(right.kind || ''));
      })
  };
  return JSON.stringify(signatureParts);
}

function buildMutationSummary(flags) {
  const out = [];
  const normalizedFlags = uniqueStrings(flags);
  if (normalizedFlags.includes('changed')) out.push('changed');
  if (normalizedFlags.includes('recent_write')) out.push('recent_write');
  if (normalizedFlags.includes('recent_read')) out.push('recent_read');
  return out;
}

function formatSourceLabel(source) {
  const normalized = clean(source).toLowerCase();
  switch (normalized) {
    case 'source_c':
      return 'C';
    case 'mcp':
      return 'MCP';
    case 'control':
      return 'control';
    case 'static':
      return 'static';
    case 'runtime':
      return 'runtime';
    case 'derived':
      return 'derived';
    case 'heuristic':
      return 'inferred';
    default:
      return clean(source);
  }
}

function collectFlags(observations) {
  const flags = [];
  (Array.isArray(observations) ? observations : []).forEach((item) => {
    uniqueStrings(item?.flags).forEach((flag) => flags.push(flag));
    if (item?.changed) flags.push('changed');
    if (item?.recentWrite) flags.push('recent_write');
    if (item?.recentRead) flags.push('recent_read');
    if (item?.payloadRelated) flags.push('payload');
  });
  return uniqueStrings(flags);
}

function countEntryBands(entries) {
  return {
    positive: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'positive').length,
    base: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'base').length,
    negative: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'negative').length,
    unknown: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'unknown').length
  };
}

function resolveOffsetBand(offset) {
  if (!Number.isFinite(offset)) return 'unknown';
  if (offset > 0) return 'positive';
  if (offset < 0) return 'negative';
  return 'base';
}

function formatCanonicalOffsetLabel(bpRegister, offset) {
  const base = String(bpRegister || 'rbp').toLowerCase();
  if (!Number.isFinite(offset)) return '';
  const numeric = Number(offset);
  const sign = numeric < 0 ? '-' : '+';
  return `${base}${sign}0x${Math.abs(numeric).toString(16)}`;
}

function resolveAbiVisualOffset(name, wordSize, argumentIndex = 0) {
  const normalized = clean(name).toLowerCase();
  switch (normalized) {
    case 'argc':
      return (readPositiveInt(wordSize) ?? 8) * 2;
    case 'argv':
      return (readPositiveInt(wordSize) ?? 8) * 3;
    case 'envp':
      return (readPositiveInt(wordSize) ?? 8) * 4;
    default:
      return (readPositiveInt(wordSize) ?? 8) * (2 + Math.max(0, Number(argumentIndex) || 0));
  }
}

function buildValuePreview(primaryObservation) {
  const text = cleanValue(primaryObservation?.displayValue || primaryObservation?.rawValue);
  if (!text) return '';
  return text.length > 56 ? `${text.slice(0, 53)}...` : text;
}

function pickPrimaryObservation(observations, offset, start) {
  return [...(Array.isArray(observations) ? observations : [])]
    .sort((left, right) => {
      const leftExactOffset = left?.offset === offset ? 0 : 1;
      const rightExactOffset = right?.offset === offset ? 0 : 1;
      if (leftExactOffset !== rightExactOffset) return leftExactOffset - rightExactOffset;

      const leftExactStart = addressesEqual(left?.start, start) ? 0 : 1;
      const rightExactStart = addressesEqual(right?.start, start) ? 0 : 1;
      if (leftExactStart !== rightExactStart) return leftExactStart - rightExactStart;

      const leftPriority = resolveSourcePriority(left?.modelSource || left?.source);
      const rightPriority = resolveSourcePriority(right?.modelSource || right?.source);
      if (leftPriority !== rightPriority) return rightPriority - leftPriority;

      const leftSize = readPositiveInt(left?.size) ?? 0;
      const rightSize = readPositiveInt(right?.size) ?? 0;
      return rightSize - leftSize;
    })[0] ?? null;
}

function pickPointerValue(primaryObservation, size) {
  const value = clean(primaryObservation?.displayValue || primaryObservation?.rawValue);
  const pointerKind = clean(primaryObservation?.pointerKind);
  if (pointerKind && POINTER_HEX_RE.test(value)) return value;
  if (POINTER_HEX_RE.test(value) && Number(size || 0) >= 4) return value;
  return '';
}

function resolvePointedEntry(pointerValue, allEntries, currentEntry) {
  const target = parseBigIntAddr(pointerValue);
  if (target === null) return null;
  return (Array.isArray(allEntries) ? allEntries : []).find((entry) => (
    entry !== currentEntry
    && addressesEqual(entry?.start, target)
  )) || null;
}

function resolvePointedObservation(pointerValue, allObservations, currentEntry) {
  const target = parseBigIntAddr(pointerValue);
  if (target === null) return null;
  return (Array.isArray(allObservations) ? allObservations : []).find((observation) => (
    observation !== currentEntry?.primaryObservation
    && addressesEqual(observation?.start, target)
  )) || null;
}

function pickAscii(observations) {
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.ascii))
    .find((value) => value && value !== '.'.repeat(value.length) && PRINTABLE_ASCII_RE.test(value)) || '';
}

function pickHexValue(primaryObservation, observations) {
  if (clean(primaryObservation?.rawValue).startsWith('0x')) return clean(primaryObservation.rawValue);
  if (clean(primaryObservation?.bytesHex)) return clean(primaryObservation.bytesHex);
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.bytesHex))
    .find(Boolean) || '';
}

function pickBytes(observations) {
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.bytesHex))
    .find(Boolean) || '';
}

function observedRanges(observations) {
  return uniqueStrings((Array.isArray(observations) ? observations : []).map((item) => {
    const start = parseBigIntAddr(item?.start);
    const end = parseBigIntAddr(item?.end);
    if (start === null || end === null) return '';
    return `${toHex(start)}..${toHex(end)}`;
  }));
}

function resolveRegisterArgumentLink(resolvedName, registerArguments) {
  const name = clean(resolvedName).toLowerCase();
  if (!name || !Array.isArray(registerArguments) || !registerArguments.length) return '';
  if (name === 'argc') {
    return registerArguments.find((item) => item.location === 'rdi' || item.location === 'edi')?.location || '';
  }
  if (name === 'argv') {
    return registerArguments.find((item) => item.location === 'rsi' || item.location === 'esi')?.location || '';
  }
  if (name === 'envp') {
    return registerArguments.find((item) => item.location === 'rdx' || item.location === 'edx')?.location || '';
  }
  return '';
}

function compareObservationsForSeeding(left, right) {
  const leftPriority = resolveSourcePriority(left?.modelSource || left?.source);
  const rightPriority = resolveSourcePriority(right?.modelSource || right?.source);
  if (leftPriority !== rightPriority) return rightPriority - leftPriority;

  const leftKindPriority = KIND_PRIORITY[classifyObservationSeedKind(left, '', 'rbp', { arch_bits: 64 })] ?? 99;
  const rightKindPriority = KIND_PRIORITY[classifyObservationSeedKind(right, '', 'rbp', { arch_bits: 64 })] ?? 99;
  if (leftKindPriority !== rightKindPriority) return leftKindPriority - rightKindPriority;

  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  if (leftSize !== rightSize) return rightSize - leftSize;
  return (left?.offset ?? 0) - (right?.offset ?? 0);
}

function normalizeDisplayName(raw, kind, bpRegister) {
  const cleaned = clean(raw);
  if (!cleaned) return '';
  if (SPECIAL_SAVED_BP_RE.test(cleaned)) return canonicalSavedBpName(bpRegister);
  if (SPECIAL_RET_RE.test(cleaned)) return 'return address';
  if (NAMELESS_LABELS.has(cleaned.toLowerCase())) return '';
  if (cleaned.toLowerCase() === 'saved_bp') return canonicalSavedBpName(bpRegister);
  if (cleaned.toLowerCase() === 'return_address') return 'return address';
  if (SPECIAL_ARGUMENT_RE.test(cleaned)) return cleaned.toLowerCase();
  if (kind === 'saved_bp') return canonicalSavedBpName(bpRegister);
  if (kind === 'return_address') return 'return address';
  return cleaned;
}

function isGenericName(name) {
  const raw = clean(name);
  if (!raw) return true;
  return GENERIC_ARG_RE.test(raw)
    || GENERIC_VAR_RE.test(raw)
    || GENERIC_STACK_RE.test(raw)
    || GENERIC_LOCAL_RE.test(raw)
    || BUFFER_STYLE_LABEL_RE.test(raw);
}

function canonicalSavedBpName(bpRegister) {
  const registerName = String(bpRegister || 'rbp').toLowerCase();
  return registerName === 'ebp' ? 'saved ebp' : 'saved rbp';
}

function normalizeEntryKind(kind) {
  const raw = clean(kind).toLowerCase();
  if (!raw) return 'unknown';
  if (raw === 'ret' || raw === 'return_address') return 'return_address';
  if (raw === 'saved_bp' || raw === 'control') return 'saved_bp';
  if (raw === 'arg' || raw === 'argument') return 'argument';
  if (raw === 'buffer') return 'buffer';
  if (raw === 'modified') return 'modified';
  if (raw === 'local' || raw === 'spill') return 'local';
  if (raw === 'padding') return 'padding';
  if (raw === 'slot') return 'slot';
  return 'unknown';
}

function normalizeSource(source) {
  const raw = clean(source).toLowerCase();
  if (!raw) return 'unknown';
  if (raw.includes('dwarf')) return 'dwarf';
  if (raw.includes('debug')) return 'debug';
  if (raw.includes('symbol')) return 'symbol';
  if (raw.includes('control')) return 'control';
  if (raw.includes('mcp')) return 'mcp';
  if (raw.includes('static')) return 'static';
  if (raw.includes('auto')) return 'auto';
  if (raw.includes('runtime')) return 'runtime';
  if (raw.includes('heuristic')) return 'heuristic';
  if (raw.includes('derived')) return 'derived';
  return raw;
}

function resolveSourcePriority(source) {
  const normalized = normalizeSource(source);
  return SOURCE_PRIORITY[normalized] ?? SOURCE_PRIORITY.unknown;
}

function resolveBpRegister(slots, meta) {
  const fromSlot = (Array.isArray(slots) ? slots : [])
    .map((slot) => extractBasePointerName(slot?.offsetFromBpLabel))
    .find(Boolean);
  if (fromSlot) return fromSlot;
  return Number(meta?.arch_bits) === 32 ? 'ebp' : 'rbp';
}

function extractBasePointerName(label) {
  const match = clean(label).match(/^([a-z0-9]+)\s*[+-]/i);
  return match ? match[1].toLowerCase() : '';
}

function areKindsCompatible(entryKind, observationKind) {
  const left = normalizeEntryKind(entryKind);
  const right = normalizeEntryKind(observationKind);
  if (left === right) return true;
  if (left === 'local' && (right === 'slot' || right === 'unknown')) return true;
  if (left === 'buffer' && (right === 'local' || right === 'slot' || right === 'unknown')) return true;
  if (left === 'argument' && right === 'slot') return true;
  if (left === 'padding' && right === 'unknown') return true;
  return false;
}

function areSizesCompatible(entrySize, observationSize) {
  const left = readPositiveInt(entrySize);
  const right = readPositiveInt(observationSize);
  if (left === null || right === null) return false;
  if (left === right) return true;
  const minSize = Math.min(left, right);
  const maxSize = Math.max(left, right);
  return minSize >= 4 && maxSize <= minSize * 2;
}

function rangesOverlap(startA, endA, startB, endB) {
  if (startA === null || endA === null || startB === null || endB === null) return false;
  return startA < endB && startB < endA;
}

function overlapByteCount(startA, endA, startB, endB) {
  if (!rangesOverlap(startA, endA, startB, endB)) return 0;
  const overlapStart = startA > startB ? startA : startB;
  const overlapEnd = endA < endB ? endA : endB;
  return Number(overlapEnd - overlapStart);
}

function seedRangeStart(seed) {
  const start = parseBigIntAddr(seed?.start);
  if (start !== null) return start;
  if (Number.isFinite(seed?.offset)) return BigInt(Math.trunc(Number(seed.offset)));
  return null;
}

function seedRangeEnd(seed) {
  const end = parseBigIntAddr(seed?.end);
  if (end !== null) return end;
  const start = seedRangeStart(seed);
  const size = readPositiveInt(seed?.size);
  if (start === null || size === null) return null;
  return start + BigInt(size);
}

function observationRangeStart(observation) {
  const start = parseBigIntAddr(observation?.start);
  if (start !== null) return start;
  if (Number.isFinite(observation?.offset)) return BigInt(Math.trunc(Number(observation.offset)));
  return null;
}

function observationRangeEnd(observation) {
  const end = parseBigIntAddr(observation?.end);
  if (end !== null) return end;
  const start = observationRangeStart(observation);
  const size = readPositiveInt(observation?.size);
  if (start === null || size === null) return null;
  return start + BigInt(size);
}

function smallestObservationStart(observations) {
  let best = null;
  (Array.isArray(observations) ? observations : []).forEach((item) => {
    const start = parseBigIntAddr(item?.start);
    if (start === null) return;
    if (best === null || start < best) best = start;
  });
  return best;
}

function parseBigIntAddr(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  const raw = clean(value).toLowerCase();
  if (!raw) return null;
  try {
    if (raw.startsWith('0x') || raw.startsWith('-0x')) return BigInt(raw);
    if (/^-?\d+$/.test(raw)) return BigInt(raw);
  } catch (_) {
    return null;
  }
  return null;
}

function toHex(value) {
  const addr = parseBigIntAddr(value);
  if (addr === null) return '';
  return `0x${addr.toString(16)}`;
}

function addressesEqual(left, right) {
  const a = parseBigIntAddr(left);
  const b = parseBigIntAddr(right);
  return a !== null && b !== null && a === b;
}

function readPositiveInt(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return Math.max(1, Math.trunc(numeric));
}

function readNumeric(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.trunc(numeric) : null;
}

function normalizeFunctionName(name) {
  return clean(name)
    .replace(/^_+/, '')
    .replace(/@.*/, '')
    .replace(/[<>]/g, '')
    .toLowerCase();
}

function displayFunctionName(name) {
  const raw = clean(name).replace(/@.*/, '').replace(/[<>]/g, '');
  if (!raw) return '';
  return raw.startsWith('_') && raw.length > 1 ? raw.slice(1) : raw;
}

function sameFunction(left, right) {
  const a = normalizeFunctionName(left);
  const b = normalizeFunctionName(right);
  return Boolean(a && b && a === b);
}

function pickFallbackFunction(snapshots) {
  const first = (Array.isArray(snapshots) ? snapshots : []).find((snap) => clean(snap?.func));
  return displayFunctionName(first?.func || '');
}

function looksLikeBufferName(name) {
  const cleaned = clean(name).toLowerCase();
  if (!cleaned) return false;
  return cleaned === 'buffer'
    || cleaned.startsWith('buffer_')
    || cleaned.includes('buf')
    || BUFFER_STYLE_LABEL_RE.test(cleaned);
}

function looksLikeArrayType(typeName) {
  const raw = clean(typeName).toLowerCase();
  if (!raw) return false;
  return /\[[0-9]+\]/.test(raw);
}

function hasTrustedDisplayName(observation) {
  const candidate = firstNonEmpty(observation?.modelName, observation?.label);
  if (!candidate) return false;
  const cleaned = normalizeDisplayName(candidate, observation?.kind, 'rbp');
  if (!cleaned) return false;
  if (isGenericName(cleaned)) return false;
  return resolveSourcePriority(observation?.modelSource || observation?.source) >= SOURCE_PRIORITY.auto;
}

function isStrongBufferObservation(observation) {
  if (!observation) return false;
  if (looksLikeBufferName(firstNonEmpty(observation?.modelName, observation?.label))) return true;
  if (looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))) return true;
  const size = readPositiveInt(observation?.size) ?? 0;
  const hasWriteSignal = Boolean(observation?.recentWrite || observation?.changed);
  return size >= 16 && hasWriteSignal && PRINTABLE_ASCII_RE.test(clean(observation?.ascii));
}

function probableBufferFromObservation(observation) {
  if (!observation) return false;
  const size = readPositiveInt(observation?.size) ?? 0;
  return size >= 16 && (Boolean(clean(observation?.ascii)) || Boolean(clean(observation?.bytesHex)));
}

function isProbableBuffer(entry, observations) {
  if (normalizeEntryKind(entry?.kind) === 'buffer') return true;
  if (looksLikeArrayType(entry?.typeName)) return true;
  if (looksLikeBufferName(entry?.label)) return true;
  return (Array.isArray(observations) ? observations : []).some((observation) => isStrongBufferObservation(observation));
}

function hasCorruptionSignal(observations) {
  return (Array.isArray(observations) ? observations : []).some((item) => (
    uniqueStrings(item?.flags).includes('corrupted')
    || Boolean(item?.recentWrite)
    || Boolean(item?.changed)
  ));
}

function isProtectedKind(kind) {
  const normalized = normalizeEntryKind(kind);
  return normalized === 'saved_bp' || normalized === 'return_address';
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const cleaned = clean(value);
    if (cleaned) return cleaned;
  }
  return '';
}

function clean(value) {
  return String(value || '').trim();
}

function cleanValue(value) {
  const raw = clean(value);
  if (!raw || raw === '??' || raw === '(unavailable)') return '';
  return raw;
}

function uniqueStrings(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => clean(value)).filter(Boolean))];
}
