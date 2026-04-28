/**
 * @file explain.js
 * @brief Rendu du panneau pedagogique en langage humain.
 */
import { dom } from './dom.js';
import { explainStackEffect } from './render.js';

export function renderExplain(snap, prevSnap, regMap = {}, prevRegMap = {}, meta = {}, analysis = null, mcp = null) {
  if (!dom.explainBody) return;
  dom.explainBody.replaceChildren();
  void prevSnap;
  void regMap;
  void prevRegMap;

  if (!snap) {
    const empty = document.createElement('div');
    empty.className = 'status';
    empty.textContent = 'Aucune explication disponible.';
    dom.explainBody.appendChild(empty);
    return;
  }

  const sections = buildSections(snap, meta, analysis, mcp);
  sections.forEach((section) => {
    const card = document.createElement('section');
    card.className = 'explain-section';

    const label = document.createElement('div');
    label.className = 'explain-section-label';
    label.textContent = section.label;

    const body = document.createElement('div');
    body.className = 'explain-section-text';
    body.textContent = section.text;

    card.append(label, body);
    dom.explainBody.appendChild(card);
  });
}

function buildSections(snap, meta, analysis, mcp) {
  const mcpSections = Array.isArray(mcp?.explanation?.sections) ? mcp.explanation.sections : null;
  if (mcpSections && mcpSections.length) {
    return mcpSections.map((section) => ({
      label: String(section?.label || 'Info'),
      text: String(section?.text || '')
    }));
  }

  const instr = typeof snap.instr === 'string' && snap.instr.trim()
    ? snap.instr.trim()
    : '(instruction inconnue)';
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  const writes = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  const reads = Array.isArray(analysis?.delta?.reads) ? analysis.delta.reads : [];
  const payload = String(meta?.payload_text || meta?.argv1 || '').trim();
  const payloadLabel = String(meta?.payload_label || (meta?.payload_target === 'stdin' ? 'stdin' : meta?.payload_target === 'both' ? 'stdin + argv[1]' : 'argv[1]'));

  const stackText = writes.length
    ? `Cette instruction ecrit dans la pile. ${explainStackEffect(instr)}`
    : reads.length
    ? `Cette instruction lit dans la pile. ${explainStackEffect(instr)}`
    : explainStackEffect(instr);

  let payloadText = `${payloadLabel} n'a pas encore d'effet visible ici.`;
  if (payload) {
    payloadText = `${payloadLabel} courant: "${payload}".`;
  }
  if (overflow?.active) {
    const reached = Array.isArray(overflow.reached) && overflow.reached.length
      ? overflow.reached.join(', ')
      : 'les zones de controle';
    payloadText = `Le contenu copie a deja depasse le buffer et touche ${reached}.`;
  }

  return [
    {
      label: 'Maintenant',
      text: snap.func
        ? `Le programme execute ${instr} dans ${snap.func}.`
        : `Le programme execute ${instr}.`
    },
    {
      label: 'Pile',
      text: stackText
    },
    {
      label: payloadLabel,
      text: payloadText
    }
  ];
}
