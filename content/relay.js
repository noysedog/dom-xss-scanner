// ===============================
// content/relay.js  (v2.0)
// Unico compito: iniettare page/page-script.js nel mondo della pagina
// a document_start e fare da ponte verso il background.
// Nessuna logica di analisi qui: gli hook nel mondo isolato non vedono
// le chiamate dello script della pagina.
// ===============================
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;
  const isTop = window === window.top;

  // Nome canale casuale: lo conoscono solo relay e page-script.
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const CH = 'dxs' + Array.from(rnd, (b) => b.toString(16).padStart(2, '0')).join('');

  let ready = false;

  const send = (msg) => {
    try {
      const p = api.runtime.sendMessage(msg);
      if (p && p.catch) p.catch(() => {});
    } catch (e) { /* estensione ricaricata */ }
  };

  const toPage = (cmd) => {
    try {
      window.dispatchEvent(new CustomEvent(CH + ':in', { detail: JSON.stringify(cmd) }));
    } catch (e) { /* ignore */ }
  };

  // Pagina -> relay (detail è sempre una stringa JSON: gli oggetti non
  // attraversano il confine Xray in Firefox).
  window.addEventListener(CH + ':out', (ev) => {
    let batch;
    try { batch = JSON.parse(ev.detail); } catch (e) { return; }
    if (!Array.isArray(batch)) return;

    if (!ready && batch.some((m) => m && m.type === 'ready')) {
      ready = true;
      const p = api.runtime.sendMessage({ kind: 'get-config' });
      if (p && p.then) {
        p.then((cfg) => cfg && toPage({ cmd: 'config', pause: !!cfg.pause })).catch(() => {});
      }
    }
    send({ kind: 'page-batch', events: batch });
  }, true);

  // Background/pannello -> pagina
  api.runtime.onMessage.addListener((msg) => {
    if (msg && msg.kind === 'cmd' && msg.cmd) toPage(msg.cmd);
  });

  // Annuncia il frame (il top frame azzera lo stato del tab)
  send({ kind: 'frame-start', top: isTop, url: location.href });

  // Iniezione.
  // 1) inline e sincrona: il sorgente del motore (caricato come content script
  //    da page/page-script.js) viene eseguito nel mondo della pagina prima di
  //    qualunque script della pagina. Il motore emette 'ready' subito, quindi
  //    `ready` è già vero al ritorno di appendChild se l'esecuzione è riuscita.
  // 2) fallback: <script src> (asincrono, può perdere gli script inline iniziali)
  //    se la CSP della pagina blocca l'inline.
  const pageUrl = api.runtime.getURL('page/page-script.js');

  const injectInline = () => {
    if (typeof window.__dxsMain !== 'function') return;
    const code = '(' + window.__dxsMain.toString() + ')(' + JSON.stringify(CH) + ',' + JSON.stringify(pageUrl) + ');';
    const s = document.createElement('script');
    s.textContent = code;
    (document.documentElement || document).appendChild(s);
    s.remove();
  };

  const injectSrc = () => {
    const s = document.createElement('script');
    s.src = pageUrl;
    s.dataset.ch = CH;
    s.addEventListener('load', () => s.remove());
    (document.documentElement || document).appendChild(s);
  };

  const inject = () => {
    injectInline();
    if (!ready) injectSrc();
  };

  if (document.documentElement) {
    inject();
  } else {
    const mo = new MutationObserver(() => {
      if (document.documentElement) { mo.disconnect(); inject(); }
    });
    mo.observe(document, { childList: true });
  }

  // Se dopo 2,5 s il motore non ha risposto (CSP, pagina speciale) lo segnala.
  setTimeout(() => {
    if (!ready) send({ kind: 'hook-failed', top: isTop, url: location.href });
  }, 2500);
})();
