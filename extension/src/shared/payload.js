/**
 * @file payload.js
 * @brief Conversion payload (hex, expressions stdin).
 */

function payloadToHex(input) {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('payload vide');
  const hexOnly = trimmed.replace(/\s/g, '').replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(hexOnly)) {
    if (hexOnly.length % 2 !== 0) throw new Error('nombre impair de caracteres hex');
    return hexOnly;
  }
  const str = parseStdinExpression(trimmed);
  return Buffer.from(str, 'utf8').toString('hex');
}

function parseStdinExpression(input) {
  const text = input.trim();
  if (!text) return '';
  if (!/[+*]/.test(text)) return text;
  const parts = text.split('+').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) throw new Error('expression vide');
  let result = '';
  parts.forEach((part) => {
    const match = part.match(/^(.+?)\*(\d+)$/);
    if (match) {
      const count = parseInt(match[2], 10);
      if (!Number.isFinite(count) || count < 0) throw new Error(`compteur invalide: ${match[2]}`);
      result += match[1].repeat(count);
    } else {
      result += part;
    }
  });
  if (result.length > 1000000) throw new Error('payload trop long');
  return result;
}

module.exports = { payloadToHex, parseStdinExpression };
