// ===============================
// devtools/panel.js  (v2.0)
// Il pannello parla solo con il background (le API tabs non sono
// disponibili nelle pagine DevTools). Tutto il contenuto della pagina
// ispezionata viene inserito con textContent: nessun innerHTML.
// ===============================
(() => {
  'use strict';

  const api = browser;
  const $ = (s) => document.querySelector(s);
  const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
  const SEV_LABEL = { critical: 'critico', high: 'alto', medium: 'medio', low: 'basso' };

  const MARKER = 'dxs9q"\'<i>x</i>';
  const state = { drafts: new Map(), pendingRender: false, snap: null, view: 'findings', minSev: 'all', onlyHigh: false, open: new Set() };

  // ---------- tema ----------
  const applyTheme = (t) => { document.documentElement.dataset.theme = t === 'dark' ? 'dark' : 'light'; };
  applyTheme(api.devtools.panels.themeName);
  api.devtools.panels.onThemeChanged.addListener(applyTheme);

  // ---------- comunicazione ----------
  const port = api.runtime.connect({ name: 'panel' });
  port.postMessage({ cmd: 'init', tabId: api.devtools.inspectedWindow.tabId });
  port.onMessage.addListener((m) => {
    if (m.type === 'state') {
      state.snap = m.state;
      // non ridisegnare mentre l'utente sta scrivendo in un campo di prova
      if (document.activeElement && document.activeElement.classList.contains('probe-in')) state.pendingRender = true;
      else render();
    }
    else if (m.type === 'config') { $('#chk-pause').checked = !!m.pause; }
  });
  port.onDisconnect.addListener(() => { $('#lost').hidden = false; });
  const cmd = (c, extra) => port.postMessage({ cmd: c, ...(extra || {}) });

  // ---------- helper DOM ----------
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === false || v == null) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  function copy(text) {
    const done = () => {};
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text));
    } else fallbackCopy(text);
  }
  function fallbackCopy(text) {
    const ta = h('textarea', { style: 'position:fixed;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    ta.remove();
  }

  const short = (s, n) => (s && s.length > n ? s.slice(0, n) + '…' : s || '');
  const where = (u) => { try { const x = new URL(u); return x.pathname.split('/').pop() || x.host; } catch (e) { return u; } };

  // ---------- rendering ----------
  function render() {
    const s = state.snap;
    if (!s) return;
    $('#banner').hidden = !s.hookFailed;

    const high = s.findings.filter((f) => f.confidence === 'high').length;
    $('#c-find').textContent = s.findings.length;
    $('#c-high').textContent = high;
    $('#c-src').textContent = s.sources.length;

    const top = s.frames.find((f) => f.top);
    const hk = $('#hooks');
    if (top && top.hooks && top.hooks.active.length) {
      hk.textContent = 'Hook attivi: ' + top.hooks.active.length +
        (top.hooks.failed.length ? ' (non riusciti: ' + top.hooks.failed.join(', ') + ')' : '');
    } else {
      hk.textContent = 'Hook: in attesa';
    }

    renderFindings();
    renderSources();
  }

  function visibleFindings() {
    const min = state.minSev === 'all' ? -1 : SEV_ORDER[state.minSev];
    return state.snap.findings.filter((f) =>
      SEV_ORDER[f.sink.severity] >= min && (!state.onlyHigh || f.confidence === 'high'));
  }

  function renderFindings() {
    const root = $('#view-findings');
    const list = visibleFindings();
    root.replaceChildren();
    if (!list.length) {
      root.append(h('p', { class: 'empty' },
        state.snap.findings.length
          ? 'Nessun finding con questi filtri.'
          : 'Nessun valore controllabile è arrivato a un sink. Naviga la pagina, usa i suoi controlli, oppure prova il marcatore. Se il marcatore non compare qui, di solito la pagina lo codifica o non lo usa.'));
      return;
    }
    list.forEach((f) => root.append(row(f)));
  }

  function row(f) {
    const sev = f.sink.severity;
    const confirmed = f.confidence === 'high';
    const canHl = f.element && f.element !== 'document';
    const probeable = f.source.kind === 'location.search' || f.source.kind === 'location.hash';
    const note = confirmed
      ? 'Il valore preso da ' + f.source.kind + ' arriva a ' + f.sink.name + ' con caratteri speciali intatti (< > " \' = ( ) ...): la pagina non li neutralizza. È il segnale più forte che questo strumento può dare; resta da verificare che il codice venga eseguito.'
      : 'Il testo preso da ' + f.source.kind + ' finisce in ' + f.sink.name + ', ma contiene solo caratteri innocui. È un flusso, non ancora una vulnerabilità: non sappiamo se la pagina sanifica. "Verifica con marcatore" lo controlla.';
    return h('article', { class: 'row ' + (confirmed ? 'sev-' + sev : 'flowonly') },
      h('div', { class: 'head' },
        h('span', { class: 'tag ' + (confirmed ? 'confirmed' : 'flowtag') }, confirmed ? 'sintassi non neutralizzata' : 'solo flusso'),
        h('span', { class: 'title' }, f.source.kind + ' → ' + f.sink.name),
        h('span', { class: 'tag risk-' + sev, title: 'Pericolosità del sink in sé, non della pagina' }, 'sink: ' + SEV_LABEL[sev]),
        f.count > 1 && h('span', { class: 'count' }, '×' + f.count),
        !f.frame.top && h('span', { class: 'count' }, 'iframe ' + where(f.frameUrl))),
      h('p', { class: 'note' }, note),
      h('div', { class: 'flow' },
        h('div', { class: 'seg src' }, h('small', null, 'Sorgente'), f.source.name + ' = ' + short(f.source.value, 80)),
        h('div', { class: 'seg snk' }, h('small', null, 'Sink'), f.sink.name, h('small', null, where(f.where.replace(/:\d+:\d+$/, '')) + ':' + (f.where.match(/:(\d+):\d+$/) || [, '?'])[1])),
        h('div', { class: 'seg dom' }, h('small', null, 'Elemento'), f.element || '—')),
      h('pre', { class: 'excerpt' }, f.excerpt),
      probeable && probeBox(f),
      h('div', { class: 'btns' },
        canHl && h('button', { onclick: () => cmd('highlight', { id: f.id, frameId: f.frameId }) }, 'Evidenzia nella pagina'),
        h('button', { onclick: () => copy(JSON.stringify(f, null, 2)) }, 'Copia JSON')),
      f.stack.length > 0 && h('details', {
        open: state.open.has(f.gid),
        ontoggle: (e) => { if (e.target.open) state.open.add(f.gid); else state.open.delete(f.gid); }
      },
        h('summary', null, 'Stack (' + f.stack.length + ')'),
        h('ol', { class: 'stack' }, f.stack.map((st) => h('li', null, st.fn + ' — ' + st.url + ':' + st.line + ':' + st.col)))));
  }

  // Campo modificabile: imposta questa sorgente al valore scritto e ricarica la pagina.
  function probeBox(f) {
    const run = () => cmd('probe-source', { kind: f.source.kind, name: f.source.name, value: state.drafts.get(f.gid) || MARKER });
    return h('div', { class: 'probe' },
      h('label', null, 'Valore da provare su ' + f.source.kind + ' · ' + f.source.name),
      h('div', { class: 'probe-row' },
        h('input', {
          type: 'text', class: 'probe-in', spellcheck: 'false', value: state.drafts.get(f.gid) || MARKER,
          'aria-label': 'Valore da provare',
          oninput: (e) => state.drafts.set(f.gid, e.target.value),
          onkeydown: (e) => { if (e.key === 'Enter') run(); }
        }),
        h('button', { title: 'Imposta la sorgente a questo valore e ricarica la pagina', onclick: run }, 'Prova'),
        h('button', {
          title: 'Ripristina il marcatore innocuo',
          onclick: (e) => { state.drafts.delete(f.gid); e.target.closest('.probe').querySelector('input').value = MARKER; }
        }, 'Marcatore')));
  }

  function renderSources() {
    const root = $('#view-sources');
    root.replaceChildren();
    const src = state.snap.sources;
    if (!src.length) { root.append(h('p', { class: 'empty' }, 'Nessuna sorgente rilevata: la pagina non ha query, hash, referrer, cookie o storage utili.')); return; }
    root.append(h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Tipo'), h('th', null, 'Nome'), h('th', null, 'Valore'), h('th', null, 'Frame'))),
      h('tbody', null, src.map((s) => h('tr', null,
        h('td', null, s.kind), h('td', null, s.name), h('td', { class: 'val' }, s.value), h('td', null, s.top ? 'principale' : where(s.frameUrl)))))));
  }

  // ---------- eventi UI ----------
  function setView(v) {
    state.view = v;
    $('#tab-findings').setAttribute('aria-selected', String(v === 'findings'));
    $('#tab-sources').setAttribute('aria-selected', String(v === 'sources'));
    $('#view-findings').hidden = v !== 'findings';
    $('#view-sources').hidden = v !== 'sources';
  }
  $('#tab-findings').addEventListener('click', () => setView('findings'));
  $('#tab-sources').addEventListener('click', () => setView('sources'));
  $('#sev').addEventListener('change', (e) => { state.minSev = e.target.value; if (state.snap) renderFindings(); });
  $('#chk-high').addEventListener('change', (e) => { state.onlyHigh = e.target.checked; if (state.snap) renderFindings(); });
  $('#chk-pause').addEventListener('change', (e) => cmd('config', { pause: e.target.checked }));
  $('#btn-clear').addEventListener('click', () => cmd('clear'));
  $('#btn-reload').addEventListener('click', () => cmd('reload'));
  $('#btn-probe').addEventListener('click', () => cmd('probe'));
  $('#btn-export').addEventListener('click', () => {
    if (!state.snap) return;
    const out = { exported: new Date().toISOString(), version: '2.0.3', url: state.snap.url, findings: state.snap.findings, sources: state.snap.sources };
    const url = URL.createObjectURL(new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' }));
    const a = h('a', { href: url, download: 'dom-xss-' + new Date().toISOString().slice(0, 10) + '.json' });
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  document.addEventListener('focusout', (e) => {
    if (state.pendingRender && e.target.classList && e.target.classList.contains('probe-in')) { state.pendingRender = false; setTimeout(render, 0); }
  });

  setView('findings');
})();
