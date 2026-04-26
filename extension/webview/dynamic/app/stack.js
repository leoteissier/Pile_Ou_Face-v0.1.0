/**
 * @file stack.js
 * @brief Rendu de la pile pour le visualiseur.
 * @details Construit les blocs, roles, legendaire et repere RBP.
 */
import { dom } from './dom.js';
import { addrKey, readPointer, readU32, toBigIntAddr } from './memory.js';
import { buildSimplifiedStackViewModel } from './stackSimpleModel.js';
import { buildStackWorkspaceModel } from './stackWorkspaceModel.js';
import { toHex } from './utils.js';

// Style + labels for stack block roles.
const ROLE_CONFIG = {
  ret: { label: 'RET', className: 'role-ret', tagClass: 'tag-control' },
  control: { label: 'CONTROL', className: 'role-control', tagClass: 'tag-control' },
  local: { label: 'LOCAL', className: 'role-local', tagClass: 'tag-local' },
  modified: { label: 'MODIFIED', className: 'role-modified', tagClass: 'tag-modified' },
  buffer: { label: 'BUFFER', className: 'role-buffer', tagClass: 'tag-buffer' },
  arg: { label: 'ARG', className: 'role-arg', tagClass: 'tag-arg' },
  padding: { label: 'PADDING', className: 'role-unknown', tagClass: 'tag-unknown' },
  spill: { label: 'SPILL', className: 'role-local', tagClass: 'tag-local' },
  unknown: { label: 'UNKNOWN', className: 'role-unknown', tagClass: 'tag-unknown' },
  default: { label: 'DEFAULT', className: 'role-default', tagClass: 'tag-unknown' }
};

// Tooltip text to explain each role.
const ROLE_TOOLTIPS = {
  ret: 'Return address.',
  control: 'Saved frame/control slot.',
  local: 'Local stack slot inside the current frame.',
  modified: 'DWORD attendu pour la variable modified.',
  buffer: 'Zone buffer.',
  arg: 'Argument sauvegarde dans la frame locale.',
  padding: 'Zone de padding/alignment.',
  spill: 'Valeur spill intermediaire.',
  unknown: 'Slot observe sans semantique fiable.',
  default: 'Slot de pile standard.'
};

// Temporary builder observability for the SIMPLE canonical frame.
const STACK_FRAME_DEBUG = true;
let lastStackFrameDebugConsoleKey = '';

/**
 * @brief Rend la pile sous forme de blocs.
 * @param stackItems Entrees de pile.
 * @param regMap Mapping de registres.
 * @param meta Metadonnees de trace.
 * @param options Options de rendu.
 */
export function renderStack(stackItems, regMap, meta, options = {}) {
  dom.stack.replaceChildren();
  if (dom.stackFunctions) dom.stackFunctions.replaceChildren();
  if (dom.stack) {
    dom.stack.classList.toggle('stack-simple-list', options.displayMode !== 'advanced');
    dom.stack.classList.toggle('stack-advanced-list', options.displayMode === 'advanced');
  }
  if (dom.stackWorkspace) {
    dom.stackWorkspace.classList.toggle('is-advanced', options.displayMode === 'advanced');
  }

  const displayMode = options.displayMode === 'advanced' ? 'advanced' : 'frame';
  updateStackChrome(displayMode, options, '', false);

  // Resolve addresses and display context.
  const analysis = options.analysis && typeof options.analysis === 'object' ? options.analysis : null;
  const mcp = options.mcp && typeof options.mcp === 'object' ? options.mcp : null;
  const model = mcp?.model && Array.isArray(mcp.model.locals) ? mcp.model : null;
  const analysisStackRoles = analysis?.highlights?.stack?.rolesByAddr ?? {};
  const is64 = regMap.rsp != null || regMap.rbp != null;
  const wordSize = is64 ? 8n : 4n;
  const rsp = toBigIntAddr(regMap.rsp ?? regMap.esp);
  const rbp = toBigIntAddr(regMap.rbp ?? regMap.ebp);
  const analysisSavedBpAddr = toBigIntAddr(analysis?.control?.savedBpAddr);
  const analysisRetAddrAddr = toBigIntAddr(analysis?.control?.retAddrAddr);
  const payloadText = String(options.payloadText || '').trim();
  const savedBpAddr = analysisSavedBpAddr ?? rbp;
  const retAddrAddr = analysisRetAddrAddr ?? (rbp != null ? rbp + wordSize : null);
  const spName = is64 ? 'RSP' : 'ESP';
  const bpName = is64 ? 'RBP' : 'EBP';
  void meta;
  const analysisBufferStart = toBigIntAddr(analysis?.buffer?.start);
  const analysisBufferEnd = toBigIntAddr(analysis?.buffer?.end);
  const semanticSlots = buildSemanticStackItems(analysis);
  const modelRegions = buildModelRegions(model, rbp, meta);
  const bufferRegion = modelRegions.find((region) => region.role === 'buffer') ?? null;
  const modifiedRegion = modelRegions.find((region) => region.role === 'modified') ?? null;
  const bufferStart = bufferRegion?.start ?? analysisBufferStart;
  const bufferEnd = bufferRegion?.end ?? analysisBufferEnd;
  const memorySource = { memoryMap: options.memoryMap, stackItems, rsp };
  const modifiedAddr = modifiedRegion?.start ?? (rbp != null ? rbp - 4n : null);
  const modifiedValueBig = modifiedAddr !== null ? readU32(modifiedAddr, memorySource) : null;
  const modifiedValue = modifiedValueBig !== null
    ? `0x${modifiedValueBig.toString(16).padStart(8, '0')}`
    : '(unavailable)';
  const retRawValueBig = retAddrAddr !== null ? readPointer(retAddrAddr, wordSize, memorySource) : null;
  const retValueBig = retRawValueBig === 0n ? null : retRawValueBig;
  const retValue = retValueBig !== null ? `0x${retValueBig.toString(16)}` : '(unavailable)';

  if (options.debugMemory && retAddrAddr !== null) {
    console.log('[RET]', {
      bp: rbp !== null ? addrKey(rbp) : null,
      retSlot: addrKey(retAddrAddr),
      lookupKey: addrKey(retAddrAddr),
      foundBytes: retRawValueBig !== null,
      found: retValueBig !== null
    });
  }
  const stackWithControl = semanticSlots.length
    ? semanticSlots
    : injectControlSlots(stackItems, {
      rsp,
      savedBpAddr,
      retAddrAddr,
      wordSize,
      retValue,
      modifiedAddr,
      modifiedValue
    });

  const sorted = Array.isArray(stackWithControl)
    ? [...stackWithControl].sort((a, b) => compareStackItemsByAddrDesc(a, b, rsp))
    : [];
  const sourceSlots = buildSimpleSourceItems(sorted, {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    payloadText,
    spName,
    bpName
  });
  const workspaceModel = buildStackWorkspaceModel({
    slots: sourceSlots,
    snapshots: options.snapshots,
    meta,
    currentStep: options.currentStep,
    selectedFunction: options.selectedFunction,
    selectedSlotKey: options.selectedSlotKey,
    snapshot: options.snapshot,
    analysis,
    mcp
  });
  updateStackWorkspaceChrome(workspaceModel, {
    onClearSelectedFunction: options.onClearSelectedFunction
  });

  if (!workspaceModel?.hasFunctionSelection) {
    updateStackChrome(displayMode, options, '', false);
    hideDetailPanel();
    renderFunctionList(workspaceModel.functionList, {
      onSelectFunction: options.onSelectFunction
    });
    return workspaceModel;
  }

  if (displayMode === 'frame') {
    updateStackChrome(displayMode, options, workspaceModel.statusText, true);
    renderFrameWorkspace(workspaceModel.frameModel, {
      selectedSlotKey: workspaceModel.selectedSlotKey,
      onSelectSlotKey: options.onSelectSlotKey
    });
    renderDetailPanel(workspaceModel.detailModel, {
      onCloseDetail: options.onSelectSlotKey
    });
    return workspaceModel;
  }

  updateStackChrome(displayMode, options, '', true);
  hideDetailPanel();
  renderAdvancedStack(sorted, {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    payloadText,
    spName,
    bpName
  });
  return workspaceModel;
}

function updateStackWorkspaceChrome(workspaceModel, { onClearSelectedFunction } = {}) {
  const panelMode = workspaceModel?.panelMode === 'frame' ? 'frame' : 'functions';
  if (dom.stackWorkspace) {
    dom.stackWorkspace.dataset.mode = panelMode;
  }
  if (dom.stackWorkspaceTitle) {
    dom.stackWorkspaceTitle.textContent = workspaceModel?.panelTitle || '.text';
  }
  if (dom.stackWorkspaceSubtitle) {
    dom.stackWorkspaceSubtitle.textContent = workspaceModel?.panelSubtitle || '';
  }
  if (dom.stackWorkspaceBack) {
    const canGoBack = panelMode === 'frame' && typeof onClearSelectedFunction === 'function';
    dom.stackWorkspaceBack.hidden = !canGoBack;
    dom.stackWorkspaceBack.onclick = canGoBack ? () => onClearSelectedFunction() : null;
  }
  if (dom.stackFunctions) {
    dom.stackFunctions.hidden = panelMode !== 'functions';
  }
  if (dom.stack) {
    dom.stack.hidden = panelMode !== 'frame';
  }
  if (dom.stackDetail && panelMode !== 'frame') {
    hideDetailPanel();
  }
}

function renderAdvancedStack(sorted, context) {
  const {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    payloadText,
    spName,
    bpName
  } = context;

  if (!Array.isArray(sorted) || !sorted.length) {
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Pile vide a cette etape.';
    dom.stack.appendChild(status);
    return;
  }

  const showAxis = !options.abstractMode;
  const axis = document.createElement('div');
  axis.className = 'stack-axis';
  if (showAxis) {
    const addrRange = getStackAddrRange(sorted, rsp);
    const label = document.createElement('span');
    label.className = 'stack-axis-label';
    label.textContent = buildAxisLabel(rbp, addrRange, bpName);
    axis.appendChild(label);
  }

  let axisInserted = false;
  if (showAxis && rbp === null) {
    dom.stack.appendChild(axis);
    axisInserted = true;
  }

  let displayIndex = 0;
  sorted.forEach((item, index) => {
    const itemKey = buildStackKey(item, index);
    if (
      !item.__forceVisible &&
      options.showOnlyChanged &&
      options.changedKeys &&
      options.alwaysShowKeys &&
      !options.changedKeys.has(itemKey) &&
      !options.alwaysShowKeys.has(itemKey)
    ) {
      return;
    }
    const div = document.createElement('div');
    const addr = resolveStackAddressBigInt(item, rsp);
    if (showAxis && !axisInserted && rbp !== null && addr !== null && addr < rbp) {
      dom.stack.appendChild(axis);
      axisInserted = true;
    }

    const tags = [];
    const modelRegion = findModelRegionForItem(addr, item.size, modelRegions);
    if (!options.abstractMode) {
      if (Array.isArray(item.activePointers)) {
        item.activePointers.forEach((pointerName) => {
          const tagText = String(pointerName || '').toUpperCase();
          if (tagText && !tags.includes(tagText)) tags.push(tagText);
        });
      }
      if (addr !== null && rsp !== null && addr === rsp) tags.push('SP');
      if (addr !== null && rbp !== null && addr === rbp) tags.push('BP');
      if (modelRegion?.role === 'arg') tags.push('ARG');
      if (modelRegion?.role === 'buffer_gap') tags.push('TO MOD');
      if (addr !== null && bufferStart !== null && bufferEnd !== null && addr >= bufferStart && addr < bufferEnd) {
        tags.push('BUF');
      }
    }

    const role = options.abstractMode
      ? 'default'
      : resolveSemanticRole(item, addr, rbp, retAddrAddr, bufferStart, bufferEnd, analysisStackRoles, modelRegions);
    const visualRole = toVisualRole(role);
    const roleConfig = ROLE_CONFIG[visualRole] || ROLE_CONFIG.default;
    div.className = `block ${roleConfig.className}`;
    if (item.changed || (options.changedKeys && options.changedKeys.has(itemKey))) div.classList.add('block-changed');
    if (Array.isArray(item.flags) && item.flags.includes('corrupted')) div.classList.add('block-corrupted');
    if (Array.isArray(item.flags) && item.flags.includes('recent_write')) div.classList.add('block-write');
    if (Array.isArray(item.flags) && item.flags.includes('recent_read')) div.classList.add('block-read');
    div.title = buildItemTooltip(item, visualRole);

    const addrLabel = addr !== null ? toHex(addr) : '??';
    const posValue = item.pos ?? item.posi ?? null;
    const displayName = item.label ?? item.name ?? modelRegion?.name ?? (item.id !== undefined ? `#${item.id}` : '#?');
    const subtitleText = buildHumanSubtitle(item, visualRole, payloadText, modelRegion);
    const offsets = buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName);
    const modifiedOk = visualRole === 'modified' && isModifiedMatch(item.value);
    const payloadRelated = isPayloadRelatedItem(item, visualRole, payloadText);
    if (modifiedOk) div.classList.add('role-modified-ok');
    if (payloadRelated) {
      div.classList.add('block-payload');
      if (!tags.includes('PAYLOAD')) tags.push('PAYLOAD');
    }

    const header = document.createElement('div');
    header.className = 'block-header';
    const titleWrap = document.createElement('div');
    titleWrap.className = 'block-title-wrap';
    const title = document.createElement('span');
    title.className = 'block-title';
    title.textContent = displayName;
    titleWrap.appendChild(title);
    if (subtitleText) {
      const subtitle = document.createElement('span');
      subtitle.className = 'block-subtitle';
      subtitle.textContent = subtitleText;
      titleWrap.appendChild(subtitle);
    }
    header.appendChild(titleWrap);
    if (!options.abstractMode) {
      const roleTag = document.createElement('span');
      roleTag.className = `block-tag ${roleConfig.tagClass}`;
      roleTag.textContent = modifiedOk ? `${roleConfig.label} • OK` : roleConfig.label;
      header.appendChild(roleTag);
    }

    const body = document.createElement('div');
    body.className = 'block-body';
    const valueEl = document.createElement('div');
    valueEl.className = 'block-value';
    body.appendChild(valueEl);
    const metaEl = document.createElement('div');
    metaEl.className = 'block-meta';
    if (options.abstractMode) {
      const offsetEl = document.createElement('div');
      offsetEl.className = 'block-offset primary';
      offsetEl.textContent = posValue !== null ? `Pos ${posValue}` : 'Pos ?';
      metaEl.appendChild(offsetEl);
    } else if (offsets.length) {
      offsets.forEach((offset) => {
        const offsetEl = document.createElement('div');
        offsetEl.className = [
          'block-offset',
          offset.primary ? 'primary' : '',
          offset.secondary ? 'secondary' : ''
        ].filter(Boolean).join(' ');
        offsetEl.textContent = offset.text;
        if (offset.tooltip) offsetEl.title = offset.tooltip;
        metaEl.appendChild(offsetEl);
      });
    } else {
      const offsetEl = document.createElement('div');
      offsetEl.className = 'block-offset primary';
      offsetEl.textContent = 'Offset non fourni';
      metaEl.appendChild(offsetEl);
    }
    const sizeEl = document.createElement('div');
    sizeEl.className = 'block-offset';
    sizeEl.textContent = `Taille: ${item.size ?? 0} bytes`;
    metaEl.appendChild(sizeEl);
    body.appendChild(metaEl);

    const footer = document.createElement('div');
    footer.className = 'block-footer';
    const addrEl = document.createElement('span');
    addrEl.className = 'block-addr';
    addrEl.textContent = options.abstractMode ? 'pile abstraite' : `addr ${addrLabel}`;
    footer.appendChild(addrEl);
    if (tags.length) {
      const tagsEl = document.createElement('span');
      tagsEl.className = 'block-tags';
      tags.forEach((tagText) => {
        const tagEl = document.createElement('span');
        tagEl.className = 'tag';
        tagEl.textContent = tagText;
        tagsEl.appendChild(tagEl);
      });
      footer.appendChild(tagsEl);
    }

    div.appendChild(header);
    div.appendChild(body);
    div.appendChild(footer);

    const rawValue = item.valueDisplay ?? item.value ?? item.bytesHex ?? '??';
    const jumpTarget = typeof options.resolveCodeJumpTarget === 'function'
      ? options.resolveCodeJumpTarget(rawValue)
      : null;
    valueEl.textContent = String(rawValue);
    if (rawValue === '(unavailable)' || rawValue === '??') {
      valueEl.classList.add('block-value-unavailable');
    } else if (jumpTarget && typeof options.onCodeAddressClick === 'function') {
      valueEl.classList.add('block-value-link');
      valueEl.title = 'Adresse code: cliquer pour aller dans le panneau ASM.';
      valueEl.addEventListener('click', () => options.onCodeAddressClick(jumpTarget));
    } else {
      const maybeAddr = toBigIntAddr(rawValue);
      if (maybeAddr !== null) valueEl.title = 'Adresse stack/data: pas de saut ASM.';
    }

    setTimeout(() => {
      div.classList.add('visible');
    }, 60 * displayIndex);

    displayIndex += 1;
    dom.stack.appendChild(div);
  });

  if (showAxis && !axisInserted) dom.stack.appendChild(axis);
}

function renderFunctionList(functionList, { onSelectFunction } = {}) {
  if (!dom.stackFunctions) return;
  dom.stackFunctions.replaceChildren();
  const items = Array.isArray(functionList) ? functionList : [];
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'stack-empty';
    empty.textContent = 'Aucune fonction dans la trace.';
    dom.stackFunctions.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = [
      'stack-function-item',
      item.isSelected ? 'is-selected' : '',
      item.isCurrent ? 'is-current' : ''
    ].filter(Boolean).join(' ');
    button.setAttribute('aria-pressed', item.isSelected ? 'true' : 'false');

    const name = document.createElement('div');
    name.className = 'stack-function-name';
    name.textContent = `${item.displayName}()`;
    button.appendChild(name);

    const meta = document.createElement('div');
    meta.className = 'stack-function-meta';
    const bits = [];
    if (item.addressLabel) bits.push(item.addressLabel);
    if (item.stepCount) bits.push(`${item.stepCount} step${item.stepCount > 1 ? 's' : ''}`);
    meta.textContent = bits.join(' • ') || (item.sourceBacked ? 'non executee' : `step ${item.firstStep}`);
    button.appendChild(meta);

    if (typeof onSelectFunction === 'function') {
      button.addEventListener('click', () => onSelectFunction(item.displayName));
    }

    dom.stackFunctions.appendChild(button);
  });
}

function renderFrameWorkspace(frameModel, { selectedSlotKey, onSelectSlotKey } = {}) {
  if (!dom.stack) return;
  dom.stack.replaceChildren();

  const simpleViewModel = buildSimplifiedStackViewModel({
    frameModel,
    detailModel: { key: selectedSlotKey || '' },
    statusText: frameModel?.statusText || ''
  });
  const entries = Array.isArray(simpleViewModel?.items) ? simpleViewModel.items : [];
  const spMarker = frameModel?.spMarker || null;
  if (spMarker?.register) {
    const marker = document.createElement('div');
    marker.className = 'stack-pointer-marker';

    const label = document.createElement('div');
    label.className = 'stack-pointer-label';
    label.textContent = spMarker.register;
    marker.appendChild(label);

    if (spMarker.addressLabel) {
      const address = document.createElement('div');
      address.className = 'stack-pointer-address';
      address.textContent = spMarker.addressLabel;
      marker.appendChild(address);
    }

    dom.stack.appendChild(marker);
  }

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'stack-empty';
    empty.textContent = frameModel?.emptyText || 'Choisissez une fonction pour afficher sa frame.';
    dom.stack.appendChild(empty);
    if (isStackFrameDebugEnabled()) {
      renderStackFrameDebugPanel(frameModel);
    }
    return;
  }

  entries.forEach((slot, index) => {
    const selectionKey = slot.selectionKey || slot.key;
    const isExpanded = selectionKey === selectedSlotKey;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = [
      'frame-slot',
      `frame-slot-${slot.offsetBand || 'unknown'}`,
      slot.kind === 'return_address' ? 'is-return' : '',
      slot.kind === 'saved_bp' ? 'is-base' : '',
      slot.isSensitive ? 'is-sensitive' : '',
      isExpanded ? 'is-selected' : ''
    ].filter(Boolean).join(' ');
    button.setAttribute('aria-pressed', isExpanded ? 'true' : 'false');
    button.title = buildFrameSlotTooltip(slot);

    const summary = document.createElement('div');
    summary.className = 'frame-slot-summary';

    const main = document.createElement('div');
    main.className = 'frame-slot-main';

    const name = document.createElement('div');
    name.className = 'frame-slot-name';
    name.textContent = slot.title || slot.name;
    main.appendChild(name);

    const offset = document.createElement('div');
    offset.className = 'frame-slot-offset';
    offset.textContent = slot.subtitle || slot.offsetLabel || 'offset inconnu';
    main.appendChild(offset);

    summary.appendChild(main);

    const side = document.createElement('div');
    side.className = 'frame-slot-side';

    const badges = Array.isArray(slot.badges) ? slot.badges : [];
    badges.slice(0, 2).forEach((badgeText) => {
      const badge = document.createElement('span');
      badge.className = 'frame-slot-badge';
      badge.textContent = badgeText;
      side.appendChild(badge);
    });

    const chevron = document.createElement('span');
    chevron.className = 'frame-slot-chevron';
    chevron.setAttribute('aria-hidden', 'true');
    chevron.textContent = '▾';
    side.appendChild(chevron);

    summary.appendChild(side);
    button.appendChild(summary);

    if (typeof onSelectSlotKey === 'function') {
      button.addEventListener('click', () => onSelectSlotKey(isExpanded ? null : selectionKey));
    }

    setTimeout(() => {
      button.classList.add('visible');
    }, 35 * index);

    dom.stack.appendChild(button);

    if (isExpanded) {
      requestAnimationFrame(() => {
        window.setTimeout(() => {
          button.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 90);
      });
    }
  });

  if (isStackFrameDebugEnabled()) {
    renderStackFrameDebugPanel(frameModel);
  }
}

function buildFrameSlotTooltip(slot) {
  return [
    slot?.title || slot?.name,
    slot?.subtitle || slot?.offsetLabel,
    slot?.kind,
    slot?.address
  ].filter(Boolean).join(' • ');
}

function renderInlineFrameDetails(slot, isExpanded) {
  const wrapper = document.createElement('div');
  wrapper.className = 'frame-slot-inline-details';
  wrapper.setAttribute('aria-hidden', isExpanded ? 'false' : 'true');

  const body = document.createElement('div');
  body.className = 'frame-slot-inline-details-body';

  if (slot?.detailPayload?.subtitle) {
    const subtitle = document.createElement('div');
    subtitle.className = 'frame-slot-inline-subtitle';
    subtitle.textContent = slot.detailPayload.subtitle;
    body.appendChild(subtitle);
  }

  const rows = document.createElement('div');
  rows.className = 'frame-slot-inline-rows';
  (Array.isArray(slot?.detailPayload?.rows) ? slot.detailPayload.rows : []).forEach((row) => {
    const item = document.createElement('div');
    item.className = 'stack-detail-row';

    const label = document.createElement('div');
    label.className = 'stack-detail-label';
    label.textContent = row.label;
    item.appendChild(label);

    const value = document.createElement('div');
    value.className = 'stack-detail-value';
    value.textContent = row.value;
    item.appendChild(value);

    rows.appendChild(item);
  });
  body.appendChild(rows);
  wrapper.appendChild(body);
  return wrapper;
}

function renderDetailPanel(detailModel, { onCloseDetail, emptyText } = {}) {
  if (!dom.stackDetail) return;
  dom.stackDetail.replaceChildren();
  if (!detailModel) {
    hideDetailPanel();
    return;
  }
  dom.stackDetail.hidden = false;
  dom.stackDetail.classList.add('is-open');

  const article = document.createElement('article');
  article.className = 'stack-detail-card';

  const header = document.createElement('div');
  header.className = 'stack-detail-header';

  const titleWrap = document.createElement('div');
  titleWrap.className = 'stack-detail-heading';

  const title = document.createElement('div');
  title.className = 'stack-detail-title';
  title.textContent = detailModel.title || 'slot';
  titleWrap.appendChild(title);

  const subtitle = document.createElement('div');
  subtitle.className = 'stack-detail-subtitle';
  subtitle.textContent = detailModel.subtitle || 'slot selectionne';
  titleWrap.appendChild(subtitle);

  header.appendChild(titleWrap);

  const actions = document.createElement('div');
  actions.className = 'stack-detail-actions';

  if (Array.isArray(detailModel.badges) && detailModel.badges.length) {
    const badges = document.createElement('div');
    badges.className = 'stack-detail-badges';
    detailModel.badges.forEach((badgeText) => {
      const badge = document.createElement('span');
      badge.className = 'stack-detail-badge';
      badge.textContent = badgeText;
      badges.appendChild(badge);
    });
    actions.appendChild(badges);
  }

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'stack-detail-close';
  close.textContent = 'Fermer';
  close.addEventListener('click', () => {
    if (typeof onCloseDetail === 'function') {
      onCloseDetail(null);
      return;
    }
    hideDetailPanel();
  });
  actions.appendChild(close);

  header.appendChild(actions);

  article.appendChild(header);

  const body = document.createElement('div');
  body.className = 'stack-detail-body';
  (Array.isArray(detailModel.rows) ? detailModel.rows : []).forEach((row) => {
    const item = document.createElement('div');
    item.className = 'stack-detail-row';

    const label = document.createElement('div');
    label.className = 'stack-detail-label';
    label.textContent = row.label;
    item.appendChild(label);

    const value = document.createElement('div');
    value.className = 'stack-detail-value';
    value.textContent = row.value;
    item.appendChild(value);

    body.appendChild(item);
  });
  article.appendChild(body);

  dom.stackDetail.appendChild(article);
}

function isStackFrameDebugEnabled() {
  return STACK_FRAME_DEBUG || globalThis.__POF_STACK_FRAME_DEBUG === true;
}

function renderStackFrameDebugPanel(frameModel) {
  if (!dom.stack) return;

  const debugModel = frameModel?.debug;
  if (!debugModel) return;

  const details = document.createElement('details');
  details.className = 'stack-debug-panel';

  const summary = document.createElement('summary');
  summary.textContent = `Debug frame (${Array.isArray(debugModel.items) ? debugModel.items.length : 0} items)`;
  details.appendChild(summary);

  const itemsTitle = document.createElement('div');
  itemsTitle.textContent = 'Final items';
  details.appendChild(itemsTitle);

  const itemsPre = document.createElement('pre');
  itemsPre.textContent = formatStackFrameDebugItems(debugModel.items);
  details.appendChild(itemsPre);

  if (Array.isArray(debugModel.seeds) && debugModel.seeds.length) {
    const seedsTitle = document.createElement('div');
    seedsTitle.textContent = 'Seeds';
    details.appendChild(seedsTitle);

    const seedsPre = document.createElement('pre');
    seedsPre.textContent = formatStackFrameDebugSeeds(debugModel.seeds);
    details.appendChild(seedsPre);
  }

  dom.stack.appendChild(details);
  logStackFrameDebug(frameModel);
}

function formatStackFrameDebugItems(items) {
  const lines = (Array.isArray(items) ? items : []).map((item) => (
    [
      padRight(item?.name || 'item', 14),
      `kind=${item?.kind || 'unknown'}`,
      `off=${item?.offset || 'n/a'}`,
      `size=${item?.size ?? 'unknown'}`,
      `source=${item?.source || 'unknown'}`,
      `merged=${item?.mergedObservationCount ?? 0}`,
      `id=${item?.key || 'n/a'}`
    ].join('   ')
  ));
  return lines.length ? lines.join('\n') : '(no final items)';
}

function formatStackFrameDebugSeeds(seeds) {
  const lines = (Array.isArray(seeds) ? seeds : []).map((seed) => (
    [
      `[${seed?.stage || 'seed'}]`,
      `kind=${seed?.kind || 'unknown'}`,
      `off=${seed?.offset || 'n/a'}`,
      `size=${seed?.size ?? 'unknown'}`,
      `source=${seed?.source || 'unknown'}`,
      seed?.label ? `label=${seed.label}` : '',
      `key=${seed?.key || 'n/a'}`
    ].filter(Boolean).join('   ')
  ));
  return lines.length ? lines.join('\n') : '(no seeds)';
}

function logStackFrameDebug(frameModel) {
  const debugModel = frameModel?.debug;
  if (!debugModel) return;
  const consoleKey = [
    frameModel?.functionName || 'frame',
    frameModel?.currentStep || 'na',
    Array.isArray(debugModel.items) ? debugModel.items.length : 0,
    Array.isArray(debugModel.seeds) ? debugModel.seeds.length : 0
  ].join(':');
  if (consoleKey === lastStackFrameDebugConsoleKey) return;
  lastStackFrameDebugConsoleKey = consoleKey;
  console.debug('[stack-frame-debug]', debugModel);
}

function padRight(value, width) {
  const text = String(value || '');
  if (text.length >= width) return text;
  return `${text}${' '.repeat(width - text.length)}`;
}

function renderDetailPlaceholder(emptyText = 'Cliquez sur un slot pour afficher plus de details.') {
  if (!dom.stackDetail) return;
  dom.stackDetail.hidden = false;
  dom.stackDetail.classList.add('is-open');
  const empty = document.createElement('div');
  empty.className = 'stack-detail-empty';
  empty.textContent = emptyText;
  dom.stackDetail.appendChild(empty);
}

function hideDetailPanel() {
  if (!dom.stackDetail) return;
  dom.stackDetail.replaceChildren();
  dom.stackDetail.hidden = true;
  dom.stackDetail.classList.remove('is-open');
}

/**
 * @brief Rend le legendaire des roles.
 * @param options Options de rendu.
 */
function renderLegend(options = {}) {
  if (!dom.legend) return;
  dom.legend.replaceChildren();
  if (options.abstractMode) return;
  const order = ['ret', 'control', 'arg', 'buffer', 'local', 'spill', 'padding', 'unknown'];
  order.forEach((key) => {
    const config = ROLE_CONFIG[key];
    if (!config) return;
    const item = document.createElement('span');
    item.className = 'legend-item';
    const swatch = document.createElement('span');
    swatch.className = `legend-swatch ${config.className}`;
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(config.label));
    dom.legend.appendChild(item);
  });
  const analysis = options.analysis && typeof options.analysis === 'object' ? options.analysis : null;
  const changedCount = Array.isArray(analysis?.delta?.changedSlots) ? analysis.delta.changedSlots.length : 0;
  const writeCount = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes.length : 0;
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  [
    writeCount ? `writes ${writeCount}` : null,
    changedCount ? `diff ${changedCount}` : null,
    overflow?.active ? `overflow ${overflow.progressBytes ?? 0}B` : null
  ]
    .filter(Boolean)
    .forEach((text) => {
      const badge = document.createElement('span');
      badge.className = 'legend-item legend-item-metric';
      badge.textContent = text;
      dom.legend.appendChild(badge);
    });
}

function updateStackChrome(displayMode, options = {}, summaryText = '', hasFrameSelection = true) {
  const showLegend = hasFrameSelection && displayMode === 'advanced' && !options.abstractMode;
  if (dom.legend) {
    dom.legend.hidden = !showLegend;
  }
  if (showLegend) {
    renderLegend(options);
  } else if (dom.legend) {
    dom.legend.replaceChildren();
  }

  if (!dom.stackSummary) return;
  const text = hasFrameSelection && displayMode === 'frame' ? String(summaryText || '').trim() : '';
  dom.stackSummary.hidden = !text;
  dom.stackSummary.textContent = text;
}

function renderSimpleStack(items, { onToggleExpandedKey } = {}) {
  if (!Array.isArray(items) || !items.length) {
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Pile vide a cette etape.';
    dom.stack.appendChild(status);
    return;
  }

  items.forEach((item, index) => {
    const card = document.createElement('article');
    card.className = `simple-stack-card simple-stack-card-${item.category}`;
    if (item.isChanged) card.classList.add('is-changed');
    if (item.isImportant) card.classList.add('is-important');
    if (item.isExpanded) card.classList.add('is-expanded');
    card.title = item.hoverText || item.title;

    const header = document.createElement('div');
    header.className = 'simple-stack-header';

    const titleWrap = document.createElement('div');
    titleWrap.className = 'simple-stack-title-wrap';
    const title = document.createElement('div');
    title.className = 'simple-stack-title';
    title.textContent = item.title;
    titleWrap.appendChild(title);
    if (item.subtitle) {
      const subtitle = document.createElement('div');
      subtitle.className = 'simple-stack-subtitle';
      subtitle.textContent = item.subtitle;
      titleWrap.appendChild(subtitle);
    }
    header.appendChild(titleWrap);

    const category = document.createElement('span');
    category.className = 'simple-stack-category';
    category.textContent = item.categoryLabel;
    header.appendChild(category);
    card.appendChild(header);

    if (Array.isArray(item.badges) && item.badges.length) {
      const badges = document.createElement('div');
      badges.className = 'simple-stack-badges';
      item.badges.forEach((badgeText) => {
        const badge = document.createElement('span');
        badge.className = 'simple-stack-badge';
        badge.textContent = badgeText;
        badges.appendChild(badge);
      });
      card.appendChild(badges);
    }

    if (item.previewValue) {
      const preview = document.createElement('div');
      preview.className = 'simple-stack-preview';
      preview.textContent = item.previewValue;
      card.appendChild(preview);
    }

    const canToggle = typeof onToggleExpandedKey === 'function';
    if (canToggle) {
      card.tabIndex = 0;
      card.setAttribute('role', 'button');
      card.setAttribute('aria-expanded', item.isExpanded ? 'true' : 'false');
      const toggle = () => onToggleExpandedKey(item.key);
      card.addEventListener('click', toggle);
      card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle();
        }
      });
    }

    if (item.isExpanded && Array.isArray(item.details) && item.details.length) {
      const details = document.createElement('div');
      details.className = 'simple-stack-details';
      item.details.forEach((row) => {
        const line = document.createElement('div');
        line.className = 'simple-stack-detail-row';
        const label = document.createElement('span');
        label.className = 'simple-stack-detail-label';
        label.textContent = row.label;
        const value = document.createElement('span');
        value.className = 'simple-stack-detail-value';
        value.textContent = row.value;
        line.appendChild(label);
        line.appendChild(value);
        details.appendChild(line);
      });
      details.addEventListener('click', (event) => event.stopPropagation());
      card.appendChild(details);
    }

    setTimeout(() => {
      card.classList.add('visible');
    }, 40 * index);

    dom.stack.appendChild(card);
  });
}

/**
 * @brief Deduit le role semantique d'un bloc de pile.
 * @details Priorite: RET/CONTROL avant BUFFER.
 */
function resolveSemanticRole(item, addr, rbp, retAddrAddr, bufferStart, bufferEnd, analysisStackRoles = {}, modelRegions = []) {
  const explicitRole = normalizeRoleName(item.semanticRole ?? item.role ?? item.kind ?? item.zone ?? item.type);
  if (explicitRole) return explicitRole;
  if (addr !== null && retAddrAddr !== null && addr === retAddrAddr) return 'ret';
  if (addr !== null && rbp !== null && addr === rbp) return 'control';
  const region = findModelRegionForItem(addr, item.size, modelRegions);
  if (region?.role === 'modified') return 'modified';
  if (region?.role === 'buffer') return 'buffer';
  if (region?.role === 'buffer_gap') return 'buffer_gap';
  if (region?.role === 'arg') return 'arg';
  if (region?.role === 'local') return 'local';
  if (region?.role === 'control') return 'control';
  if (region?.role === 'unknown') return 'unknown';
  const normalizedAddr = addr !== null ? normalizeAddressKey(addr) : null;
  const roleFromAnalysis = normalizedAddr ? analysisStackRoles[normalizedAddr] : null;
  if (roleFromAnalysis === 'ret') return 'ret';
  if (roleFromAnalysis === 'control') return 'control';
  if (roleFromAnalysis === 'local') return 'local';
  if (roleFromAnalysis === 'modified') return 'modified';
  if (roleFromAnalysis === 'buffer') return 'buffer';
  if (roleFromAnalysis === 'arg') return 'arg';
  if (roleFromAnalysis === 'unknown') return 'unknown';
  if (roleFromAnalysis === 'default') return 'default';

  const raw = (item.role ?? item.kind ?? item.zone ?? item.type ?? '').toString().toLowerCase();
  if (raw) {
    if (raw.includes('ret')) return 'ret';
    if (raw.includes('modified')) return 'modified';
    if (raw.includes('control') || raw.includes('saved')) return 'control';
    if (raw.includes('buffer')) return 'buffer';
    if (raw.includes('arg')) return 'arg';
    if (raw.includes('local')) return 'local';
    if (raw.includes('unknown')) return 'unknown';
  }

  const name = (item.name ?? item.label ?? '').toString().toLowerCase();
  if (name.includes('ret')) return 'ret';
  if (name.includes('modified')) return 'modified';
  if (name.includes('saved') || name.includes('ebp') || name.includes('rbp')) return 'control';
  if (name.includes('argument')) return 'arg';

  if (
    addr !== null &&
    bufferStart !== null &&
    bufferEnd !== null &&
    addr >= bufferStart &&
    addr < bufferEnd
  ) {
    return 'buffer';
  }

  return 'default';
}

/**
 * @brief Reduit les roles semantiques vers les 3 roles visuels demandes.
 */
function toVisualRole(role) {
  if (role === 'saved_bp') return 'control';
  if (role === 'return_address') return 'ret';
  if (role === 'argument') return 'arg';
  if (role === 'padding') return 'padding';
  if (role === 'spill') return 'spill';
  if (role === 'ret') return 'ret';
  if (role === 'control') return 'control';
  if (role === 'local') return 'local';
  if (role === 'modified') return 'modified';
  if (role === 'buffer') return 'buffer';
  if (role === 'buffer_gap') return 'buffer';
  if (role === 'arg') return 'arg';
  if (role === 'unknown') return 'unknown';
  return 'default';
}

/**
 * @brief Construit les offsets a afficher.
 * @param item Entree de pile.
 * @param addr Adresse calculee.
 * @param rsp Registre SP.
 * @param rbp Registre BP.
 * @param posValue Position fournie.
 * @param spName Nom SP.
 * @param bpName Nom BP.
 * @return Liste d'offsets.
 */
function buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName) {
  const offsets = [];
  if (typeof item.offsetFromBpHex === 'string' && item.offsetFromBpHex) {
    offsets.push({ text: `${bpName} ${item.offsetFromBpHex}`, primary: true });
  } else if (addr !== null && rbp !== null) {
    offsets.push({ text: `${bpName} ${formatSignedHexBigInt(addr - rbp)}`, primary: true });
  }
  let spOffset = null;
  let hasExplicitSpOffset = false;
  if (typeof item.offsetFromSpHex === 'string' && item.offsetFromSpHex) {
    offsets.push({
      text: `${spName} ${item.offsetFromSpHex}`,
      primary: offsets.length === 0,
      secondary: offsets.length > 0,
      tooltip: 'Position relative au sommet de pile (SP).'
    });
    hasExplicitSpOffset = true;
  } else if (addr !== null && rsp !== null) {
    spOffset = addr - rsp;
  } else if (typeof posValue === 'number') {
    spOffset = BigInt(posValue);
  }

  if (spOffset !== null && !hasExplicitSpOffset) {
      offsets.push({
        text: `${spName} ${formatSignedHexBigInt(spOffset)}`,
        primary: offsets.length === 0,
        secondary: offsets.length > 0,
        tooltip: 'Position relative au sommet de pile (SP).'
      });
  }

  return offsets;
}

/**
 * @brief Construit le label du repere BP.
 * @param rbp Valeur BP.
 * @param range Plage d'adresses.
 * @param bpName Nom BP.
 * @return Texte de label.
 */
function buildAxisLabel(rbp, range, bpName) {
  const base = rbp !== null ? `${bpName} (repere fixe) = ${toHex(rbp)}` : `${bpName} (repere fixe)`;
  if (rbp !== null && range && (rbp < range.min || rbp > range.max)) {
    return `${base} (hors fenetre)`;
  }
  return `${base} • haut=RBP+ / bas=RBP-`;
}

/**
 * @brief Calcule la plage d'adresses de pile.
 * @param items Entrees de pile.
 * @param rsp Registre SP.
 * @return Objet {min,max} ou null.
 */
function getStackAddrRange(items, rsp) {
  let min = null;
  let max = null;
  items.forEach((item) => {
    const addr = resolveStackAddressBigInt(item, rsp);
    if (addr === null) return;
    if (min === null || addr < min) min = addr;
    if (max === null || addr > max) max = addr;
  });
  if (min === null || max === null) return null;
  return { min, max };
}

/**
 * @brief Construit une cle de stabilite pour un item.
 * @param item Entree de pile.
 * @return Cle unique.
 */
function buildStackKey(item, fallbackIndex = 0) {
  if (item.key) return `key:${item.key}`;
  if (item.addr) return `addr:${item.addr}`;
  const posValue = item.pos ?? item.posi ?? null;
  if (posValue !== null) return `pos:${posValue}`;
  if (item.id !== undefined) return `id:${item.id}`;
  const label = String(item.label ?? item.name ?? 'slot').trim() || 'slot';
  const role = String(item.role ?? item.kind ?? 'default').trim() || 'default';
  const size = Number.isFinite(Number(item.size)) ? Math.trunc(Number(item.size)) : 0;
  return `item:${label}:${role}:${size}:${fallbackIndex}`;
}

function resolveStackAddressBigInt(item, rsp) {
  const itemAddr = toBigIntAddr(item.addr);
  if (itemAddr !== null) return itemAddr;
  const pos = typeof item.pos === 'number' ? item.pos : item.posi ?? null;
  if (rsp !== null && pos !== null) {
    return rsp + BigInt(Math.trunc(pos));
  }
  return null;
}

function normalizeAddressKey(value) {
  return addrKey(toBigIntAddr(value));
}

function normalizeRoleName(role) {
  const raw = String(role || '').toLowerCase();
  if (!raw) return null;
  if (raw === 'saved_bp') return 'saved_bp';
  if (raw === 'return_address') return 'return_address';
  if (raw === 'argument' || raw === 'arg') return 'argument';
  if (raw === 'buffer') return 'buffer';
  if (raw === 'local') return 'local';
  if (raw === 'padding') return 'padding';
  if (raw === 'spill') return 'spill';
  if (raw === 'unknown' || raw === 'uninitialized') return 'unknown';
  if (raw === 'control') return 'control';
  if (raw === 'ret') return 'ret';
  return raw;
}

function buildItemTooltip(item, visualRole) {
  const parts = [ROLE_TOOLTIPS[visualRole] || ''];
  if (typeof item.comment === 'string' && item.comment) parts.push(item.comment);
  if (typeof item.valueHex === 'string' && item.valueHex) parts.push(`Value ${item.valueHex}`);
  if (Array.isArray(item.flags) && item.flags.length) parts.push(`Flags: ${item.flags.join(', ')}`);
  return parts.filter(Boolean).join(' • ');
}

function buildHumanSubtitle(item, visualRole, payloadText, modelRegion) {
  const rawLabel = String(item.label ?? item.name ?? modelRegion?.name ?? '').toLowerCase();
  const modelName = String(modelRegion?.name || '').toLowerCase();
  const semanticRole = normalizeRoleName(item.semanticRole ?? item.role ?? item.kind ?? visualRole);
  if (modelName === 'argc' || rawLabel === 'argc') return 'argc';
  if (modelName === 'argv' || rawLabel === 'argv') return 'argv';
  if (modelName === 'modified' || rawLabel === 'modified' || semanticRole === 'modified') return 'modified';
  if (modelName === 'buffer') return 'buffer';
  if (modelRegion?.role === 'buffer_gap') return 'buffer_gap';
  if (semanticRole === 'saved_bp' || rawLabel.includes('saved')) return 'saved_bp';
  if (semanticRole === 'return_address' || visualRole === 'ret' || rawLabel.includes('ret')) return 'ret_addr';
  if (visualRole === 'buffer') return 'buffer';
  if ((semanticRole === 'argument' || visualRole === 'arg') && itemContainsPayload(item, payloadText)) return 'argument';
  if (semanticRole === 'argument' || visualRole === 'arg') return 'argument';
  if (visualRole === 'padding' || visualRole === 'unknown') return 'intermediate';
  if (visualRole === 'local') return 'local';
  return '';
}

function payloadChunks(payloadText) {
  const text = String(payloadText || '').trim();
  if (!text) return [];
  const chunks = new Set();
  if (text.length >= 4) {
    chunks.add(text.slice(0, Math.min(8, text.length)).toLowerCase());
    chunks.add(text.slice(Math.max(0, text.length - 8)).toLowerCase());
  }
  for (let index = 0; index <= text.length - 4; index += 4) {
    chunks.add(text.slice(index, index + Math.min(8, text.length - index)).toLowerCase());
  }
  return [...chunks].filter(Boolean);
}

function itemContainsPayload(item, payloadText) {
  const haystack = [
    item.valueDisplay,
    item.ascii,
    item.bytesHex,
    item.label
  ]
    .map((part) => String(part || ''))
    .join(' ')
    .toLowerCase();
  if (!haystack) return false;
  const chunks = payloadChunks(payloadText);
  if (!chunks.length) {
    return haystack.includes('arg_') && haystack.includes('"');
  }
  return chunks.some((chunk) => haystack.includes(chunk));
}

function isPayloadRelatedItem(item, visualRole, payloadText) {
  if (itemContainsPayload(item, payloadText)) return true;
  return visualRole === 'buffer' && Array.isArray(item.flags) && item.flags.includes('ascii_probable');
}

function formatSignedHexBigInt(value) {
  const v = BigInt(value);
  if (v === 0n) return '+0x0';
  const sign = v < 0n ? '-' : '+';
  const abs = v < 0n ? -v : v;
  return `${sign}0x${abs.toString(16)}`;
}

function compareStackItemsByAddrDesc(a, b, rsp) {
  const addrA = resolveStackAddressBigInt(a, rsp);
  const addrB = resolveStackAddressBigInt(b, rsp);
  if (addrA !== null && addrB !== null) {
    if (addrA === addrB) return 0;
    return addrA > addrB ? -1 : 1;
  }
  const offsetA = typeof a.pos === 'number' ? a.pos : a.posi ?? 0;
  const offsetB = typeof b.pos === 'number' ? b.pos : b.posi ?? 0;
  return offsetB - offsetA;
}

function injectControlSlots(stackItems, {
  rsp,
  savedBpAddr,
  retAddrAddr,
  wordSize,
  retValue,
  modifiedAddr,
  modifiedValue
}) {
  const out = Array.isArray(stackItems) ? stackItems.map((item) => ({ ...item })) : [];
  if (savedBpAddr === null && retAddrAddr === null && modifiedAddr === null) return out;
  const is64 = wordSize === 8n || wordSize === 8;

  const targets = [
    { addr: savedBpAddr, label: is64 ? 'saved_rbp' : 'saved_ebp', role: 'saved_bp', forcedValue: null },
    { addr: retAddrAddr, label: 'ret_addr', role: 'return_address', forcedValue: retValue },
    { addr: modifiedAddr, label: 'modified', role: 'modified', forcedValue: modifiedValue, forcedSize: 4 }
  ];

  targets.forEach((target) => {
    if (target.addr === null) return;
    const idx = out.findIndex((item) => resolveStackAddressBigInt(item, rsp) === target.addr);
    if (idx >= 0) {
      out[idx] = {
        ...out[idx],
        value: chooseDisplayValue(target.forcedValue, out[idx].value),
        label: target.label,
        name: target.label,
        role: target.role,
        kind: target.role,
        size: target.forcedSize ?? out[idx].size,
        __forceVisible: true
      };
      return;
    }

    const value = target.forcedValue ?? findValueByAddress(out, target.addr, rsp);
    out.push({
      addr: `0x${target.addr.toString(16)}`,
      pos: toSafeNumber(target.addr, rsp),
      value,
      size: target.forcedSize ?? Number(wordSize),
      label: target.label,
      name: target.label,
      role: target.role,
      kind: target.role,
      __forceVisible: true
    });
  });

  return out;
}

function findValueByAddress(items, targetAddr, rsp) {
  const match = items.find((item) => resolveStackAddressBigInt(item, rsp) === targetAddr);
  if (!match) return '(unavailable)';
  return match.value ?? match.val ?? '(unavailable)';
}

function chooseDisplayValue(primaryValue, fallbackValue) {
  if (primaryValue != null && primaryValue !== '(unavailable)' && primaryValue !== '??') {
    return primaryValue;
  }
  return fallbackValue ?? primaryValue ?? '(unavailable)';
}

function isModifiedMatch(value) {
  const parsed = toBigIntAddr(value);
  if (parsed === null) return false;
  return BigInt.asUintN(32, parsed) === 0x43434343n;
}

function toSafeNumber(addr, rsp) {
  if (rsp === null) return null;
  const delta = addr - rsp;
  if (delta < BigInt(Number.MIN_SAFE_INTEGER) || delta > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(delta);
}

function buildModelRegions(model, rbp, meta = {}) {
  if (rbp === null) return [];

  const regions = [];
  if (model && Array.isArray(model.locals)) {
    regions.push(...model.locals
      .map((local) => {
        const offset = typeof local?.offset === 'number' ? local.offset : null;
        if (offset === null) return null;
        const size = Number.isFinite(local?.size) && Number(local.size) > 0 ? Math.trunc(Number(local.size)) : 1;
        const start = rbp + BigInt(offset);
        const end = start + BigInt(Math.max(1, size));
        const role = local.name === 'modified'
          ? 'modified'
          : local.role === 'buffer'
          ? 'buffer'
          : local.role === 'arg'
          ? 'arg'
          : 'default';
        return {
          start,
          end,
          role,
          name: local.name ?? null,
          cType: local.cType ?? '',
          source: local.source ?? '',
          confidence: Number.isFinite(Number(local.confidence)) ? Number(local.confidence) : null,
          offset
        };
      })
      .filter(Boolean));
  }

  if (!regions.some((region) => region.role === 'buffer')) {
    const bufferOffset = Number.isFinite(Number(meta?.buffer_offset)) ? Math.trunc(Number(meta.buffer_offset)) : null;
    const bufferSize = Number.isFinite(Number(meta?.buffer_size)) && Number(meta.buffer_size) > 0
      ? Math.trunc(Number(meta.buffer_size))
      : null;
    if (bufferOffset !== null && bufferSize !== null) {
      const start = rbp + BigInt(bufferOffset);
      regions.push({
        start,
        end: start + BigInt(Math.max(1, bufferSize)),
        role: 'buffer',
        name: 'buffer',
        cType: 'char[]',
        source: 'meta',
        confidence: 0.75,
        offset: bufferOffset
      });
    }
  }

  const bufferRegion = regions.find((region) => region.role === 'buffer') ?? null;
  const modifiedRegion = regions.find((region) => region.role === 'modified') ?? null;
  if (
    bufferRegion
    && modifiedRegion
    && modifiedRegion.start > bufferRegion.end
  ) {
    regions.push({
      start: bufferRegion.end,
      end: modifiedRegion.start,
      role: 'buffer_gap',
      name: 'buffer_gap',
      cType: '',
      source: 'derived',
      confidence: null,
      offset: Number(bufferRegion.end - rbp)
    });
  }

  return regions.sort((a, b) => modelRolePriority(a.role) - modelRolePriority(b.role));
}

function buildSemanticStackItems(analysis) {
  const slots = Array.isArray(analysis?.frame?.slots) ? analysis.frame.slots : [];
  if (!slots.length) return [];
  return slots.map((slot, index) => ({
    id: index,
    addr: slot.start ?? null,
    end: slot.end ?? null,
    pos: null,
    size: Number.isFinite(Number(slot.size)) ? Math.trunc(Number(slot.size)) : 1,
    value: slot.valueHex ?? slot.bytesHex ?? slot.valueDisplay ?? '??',
    valueDisplay: slot.valueDisplay ?? slot.valueHex ?? slot.bytesHex ?? '??',
    label: slot.label ?? `slot_${index}`,
    name: slot.label ?? `slot_${index}`,
    role: slot.role ?? 'unknown',
    semanticRole: slot.role ?? 'unknown',
    kind: slot.role ?? 'unknown',
    flags: Array.isArray(slot.flags) ? slot.flags : [],
    changed: Boolean(slot.changed),
    recentWrite: Boolean(slot.recentWrite),
    recentRead: Boolean(slot.recentRead),
    corrupted: Boolean(slot.corrupted),
    comment: slot.comment ?? '',
    source: slot.source ?? '',
    confidence: Number.isFinite(Number(slot.confidence)) ? Number(slot.confidence) : null,
    offsetFromBp: Number.isFinite(Number(slot.offsetFromBp)) ? Number(slot.offsetFromBp) : null,
    offsetFromBpHex: slot.offsetFromBpHex ?? null,
    offsetFromSp: Number.isFinite(Number(slot.offsetFromSp)) ? Number(slot.offsetFromSp) : null,
    offsetFromSpHex: slot.offsetFromSpHex ?? null,
    bytesHex: slot.bytesHex ?? '',
    ascii: slot.ascii ?? '',
    valueHex: slot.valueHex ?? null,
    pointerKind: slot.pointerKind ?? '',
    activePointers: Array.isArray(slot.activePointers) ? slot.activePointers : []
  }));
}

function findModelRegionForItem(addr, itemSize, modelRegions) {
  if (addr === null || !Array.isArray(modelRegions) || !modelRegions.length) return null;
  const size = Number.isFinite(itemSize) && Number(itemSize) > 0 ? Math.trunc(Number(itemSize)) : 1;
  const itemEnd = addr + BigInt(Math.max(1, size));
  return modelRegions.find((region) => addr < region.end && itemEnd > region.start) ?? null;
}

function modelRolePriority(role) {
  switch (role) {
    case 'modified': return 0;
    case 'buffer': return 1;
    case 'buffer_gap': return 2;
    case 'arg': return 3;
    default: return 4;
  }
}

function buildSimpleSourceItems(sorted, context) {
  const {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    payloadText,
    spName,
    bpName
  } = context;

  const items = [];
  sorted.forEach((item, index) => {
    const key = buildStackKey(item, index);
    if (
      !item.__forceVisible &&
      options.showOnlyChanged &&
      options.changedKeys &&
      options.alwaysShowKeys &&
      !options.changedKeys.has(key) &&
      !options.alwaysShowKeys.has(key)
    ) {
      return;
    }

    const addr = resolveStackAddressBigInt(item, rsp);
    const modelRegion = findModelRegionForItem(addr, item.size, modelRegions);
    const semanticRole = resolveSemanticRole(
      item,
      addr,
      rbp,
      retAddrAddr,
      bufferStart,
      bufferEnd,
      analysisStackRoles,
      modelRegions
    );
    const visualRole = toVisualRole(semanticRole);
    const posValue = item.pos ?? item.posi ?? null;
    const offsets = buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName);
    const displayName = item.label ?? item.name ?? modelRegion?.name ?? (item.id !== undefined ? `#${item.id}` : '#?');
    const rawValue = item.valueDisplay ?? item.value ?? item.bytesHex ?? '??';

    items.push({
      key,
      technicalLabel: displayName,
      rawRole: item.role ?? item.kind ?? item.zone ?? item.type ?? semanticRole,
      semanticRole,
      visualRole,
      modelName: modelRegion?.name ?? '',
      modelRole: modelRegion?.role ?? '',
      modelType: modelRegion?.cType ?? '',
      modelSource: modelRegion?.source ?? '',
      modelConfidence: modelRegion?.confidence ?? null,
      size: item.size ?? 0,
      displayValue: String(rawValue),
      rawValue: String(rawValue),
      valueHex: item.valueHex ?? null,
      addressLabel: addr !== null ? toHex(addr) : '',
      offsetFromBp: Number.isFinite(Number(item.offsetFromBp))
        ? Number(item.offsetFromBp)
        : addr !== null && rbp !== null
        ? Number(addr - rbp)
        : null,
      offsetFromBpLabel: offsets.find((offset) => offset.text.startsWith(`${bpName} `))?.text ?? '',
      offsetFromSp: Number.isFinite(Number(item.offsetFromSp))
        ? Number(item.offsetFromSp)
        : addr !== null && rsp !== null
        ? Number(addr - rsp)
        : null,
      offsetFromSpLabel: offsets.find((offset) => offset.text.startsWith(`${spName} `))?.text ?? '',
      positionLabel: options.abstractMode ? (posValue !== null ? `Pos ${posValue}` : 'Pos ?') : '',
      flags: Array.isArray(item.flags) ? item.flags : [],
      comment: item.comment ?? '',
      changed: Boolean(item.changed),
      recentWrite: Boolean(item.recentWrite),
      recentRead: Boolean(item.recentRead),
      payloadRelated: isPayloadRelatedItem(item, visualRole, payloadText),
      isAtSp: !options.abstractMode && addr !== null && rsp !== null && addr === rsp,
      isAtBp: !options.abstractMode && addr !== null && rbp !== null && addr === rbp,
      pointerKind: item.pointerKind ?? '',
      bytesHex: item.bytesHex ?? '',
      ascii: item.ascii ?? '',
      source: item.source ?? '',
      confidence: Number.isFinite(Number(item.confidence)) ? Number(item.confidence) : null,
      activePointers: Array.isArray(item.activePointers) ? item.activePointers : []
    });
  });

  return items;
}
