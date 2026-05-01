/* global module */
(function initPayloadPreview(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PofPayloadPreview = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function buildPayloadPreviewApi() {
  const PREVIEW_TRUNCATE_LIMIT = 256;

  function toByteArray(value) {
    if (Array.isArray(value)) return value.map((byte) => Number(byte) & 0xff);
    if (value == null) return [];
    return Array.from(value, (byte) => Number(byte) & 0xff);
  }

  function bytesToSpacedHex(bytes) {
    return toByteArray(bytes)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join(' ');
  }

  function bytesToAscii(bytes) {
    return toByteArray(bytes)
      .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'))
      .join('');
  }

  function truncateBytes(bytes, limit = PREVIEW_TRUNCATE_LIMIT) {
    const normalized = toByteArray(bytes);
    const max = Math.max(0, Number(limit) || PREVIEW_TRUNCATE_LIMIT);
    return {
      bytes: normalized.slice(0, max),
      truncated: normalized.length > max,
      totalSize: normalized.length,
    };
  }

  function buildPayloadPreviewFingerprint(source) {
    return JSON.stringify(source && typeof source === 'object' ? source : {});
  }

  function createPreviewState(overrides = {}) {
    return {
      status: 'stale',
      fingerprint: '',
      mode: 'simple',
      target: 'argv[1]',
      currentPayloadSource: '',
      resolvedPayloadBytes: [],
      generatedPwntoolsSnippet: '',
      size: 0,
      previewHexDisplay: '—',
      previewAsciiDisplay: '—',
      previewTruncated: false,
      warnings: [],
      payloadExpr: '',
      inputConfig: null,
      error: '',
      ...overrides,
    };
  }

  function createStalePreviewState(overrides = {}) {
    return createPreviewState({ status: 'stale', ...overrides });
  }

  function createErrorPreviewState(error, overrides = {}) {
    return createPreviewState({
      status: 'error',
      error: String(error || 'Erreur inconnue'),
      ...overrides,
    });
  }

  function buildResolvedPreviewState(resolved, overrides = {}) {
    const bytes = toByteArray(resolved?.resolvedPayloadBytes || []);
    const truncated = truncateBytes(bytes);
    return createPreviewState({
      status: 'ready',
      mode: String(resolved?.mode || 'simple'),
      target: String(resolved?.target || 'argv[1]'),
      currentPayloadSource: String(resolved?.currentPayloadSource || ''),
      resolvedPayloadBytes: bytes,
      generatedPwntoolsSnippet: String(resolved?.generatedPwntoolsSnippet || resolved?.generatedSnippet || ''),
      size: Number(resolved?.size ?? bytes.length) || 0,
      previewHexDisplay: truncated.bytes.length ? bytesToSpacedHex(truncated.bytes) : '—',
      previewAsciiDisplay: truncated.bytes.length ? bytesToAscii(truncated.bytes) : '—',
      previewTruncated: truncated.truncated,
      warnings: Array.isArray(resolved?.warnings) ? resolved.warnings.map(String) : [],
      payloadExpr: String(resolved?.payloadExpr || ''),
      inputConfig: resolved?.inputConfig || null,
      ...overrides,
    });
  }

  function isPreviewStateFresh(state, fingerprint) {
    return !!state && state.status === 'ready' && state.fingerprint === String(fingerprint || '');
  }

  return {
    PREVIEW_TRUNCATE_LIMIT,
    buildPayloadPreviewFingerprint,
    buildResolvedPreviewState,
    bytesToAscii,
    bytesToSpacedHex,
    createErrorPreviewState,
    createPreviewState,
    createStalePreviewState,
    isPreviewStateFresh,
    truncateBytes,
  };
});
