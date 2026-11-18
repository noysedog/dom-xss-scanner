// ===============================
// page/page-script.js  (v2.0)
// Motore unico per il mondo della pagina. Due modalità:
//  - caricato come content script: espone window.__dxsMain; il relay ne
//    inietta il sorgente come <script> inline => esecuzione SINCRONA,
//    prima di qualsiasi script della pagina;
//  - caricato come <script src> (fallback se la CSP blocca l'inline):
//    parte da solo leggendo il canale da data-ch.
// Funzionamento: raccoglie le SOURCE (query, hash, path, referrer, name,
// cookie, storage, postMessage), aggancia i SINK e segnala quando
// l'argomento di un sink contiene un valore controllabile.
// ===============================
(function () {
  'use strict';

  function main(CH, SELF_URL) {
  'use strict';

  // Opzioni. hookEval=false se sostituire eval/Function rompe il sito:
  // window.eval sostituito rende "indiretta" ogni eval() diretta.
  const CFG = { pause: false, hookEval: true, maxFindings: 300, flushMs: 120 };

  const W = window;
  const _defProp = Object.defineProperty;
  const _getDesc = Object.getOwnPropertyDescriptor;
  const _apply = Reflect.apply;
  const _stringify = JSON.stringify;
  const _parse = JSON.parse;
  const _setTimeout = W.setTimeout.bind(W);
  const _dispatch = W.dispatchEvent.bind(W);
  const _addEL = W.addEventListener.bind(W);
  const _CustomEvent = W.CustomEvent;
  const _URLSP = W.URLSearchParams;
  const _decode = W.decodeURIComponent;
  const _Error = W.Error;
  const _WeakRef = W.WeakRef;
  const _Set = Set;
  const _Map = Map;

  let busy = 0;
  const active = [];
  const failed = [];

  // ---------- mascheramento: le funzioni agganciate sembrano native ----------
  const natives = new WeakMap();
  const _toString = Function.prototype.toString;
  const fakeToString = function toString() {
    const o = natives.get(this);
    return _apply(_toString, o || this, []);
  };
  natives.set(fakeToString, _toString);
  _defProp(Function.prototype, 'toString', { value: fakeToString, writable: true, configurable: true });

  function mask(fn, orig) {
    natives.set(fn, orig);
    try {
      _defProp(fn, 'name', { value: orig.name, configurable: true });
      _defProp(fn, 'length', { value: orig.length, configurable: true });
    } catch (e) { /* ignore */ }
  }

  // ---------- utilità ----------
  const META = /[<>"'`=(){};\\]/;
  const trunc = (s, n) => (typeof s === 'string' && s.length > n ? s.slice(0, n) + '…' : s);

  function excerpt(value, token) {
    const i = value.indexOf(token);
    const a = Math.max(0, i - 60);
    const b = Math.min(value.length, i + token.length + 60);
    return (a > 0 ? '…' : '') + value.slice(a, b) + (b < value.length ? '…' : '');
  }

  function parseStack(raw, skip) {
    const out = [];
    if (!raw) return out;
    for (const ln of String(raw).split('\n')) {
      let m = /^(.*?)@(.+?):(\d+):(\d+)$/.exec(ln.trim());          // Firefox
      let fn, url, line, col;
      if (m) { fn = m[1]; url = m[2]; line = +m[3]; col = +m[4]; }
      else {
        m = /^\s*at\s+(?:(.*?)\s+\()?(.+?):(\d+):(\d+)\)?$/.exec(ln); // Chrome
        if (!m) continue;
        fn = m[1]; url = m[2]; line = +m[3]; col = +m[4];
      }
      if (skip > 0) { skip--; continue; }  // frame interni: record, inspect, wrapper
      if (url === SELF_URL || (fn && fn.indexOf('__dxs_') !== -1)) continue;
      out.push({ fn: fn || '(anonima)', url: url, line: line, col: col });
      if (out.length >= 8) break;
    }
    return out;
  }

  function pathOf(el) {
    try {
      if (el === document) return 'document';
      if (!el || el.nodeType !== 1) return null;
      const parts = [];
      let c = el;
      for (let i = 0; c && c.nodeType === 1 && i < 6; i++) {
        let s = c.tagName.toLowerCase();
        if (typeof c.id === 'string' && c.id) { parts.unshift(s + '#' + c.id); break; }
        if (typeof c.className === 'string' && c.className.trim()) {
          s += '.' + c.className.trim().split(/\s+/).slice(0, 2).join('.');
        }
        parts.unshift(s);
        c = c.parentElement;
      }
      return parts.join(' > ');
    } catch (e) { return null; }
  }

  // ---------- outbox verso il relay ----------
  let outbox = [];
  let flushT = 0;
  const dirty = new _Set();

  function push(m) {
    outbox.push(m);
    if (!flushT) flushT = _setTimeout(flush, CFG.flushMs);
  }

  function flush() {
    flushT = 0;
    dirty.forEach((f) => outbox.push({ type: 'finding', finding: f }));
    dirty.clear();
    if (!outbox.length) return;
    const b = outbox;
    outbox = [];
    try { _dispatch(new _CustomEvent(CH + ':out', { detail: _stringify(b) })); } catch (e) { /* ignore */ }
  }

  // ---------- SOURCE ----------
  const S = (kind, name, value) => ({ kind: kind, name: name, value: typeof value === 'string' ? value.slice(0, 2000) : '' });
  const MIN = {
    'location.search': 3, 'location.hash': 3, 'location.pathname': 4, 'window.name': 3, 'postMessage': 3,
    'document.referrer': 8, 'document.cookie': 8, 'localStorage': 8, 'sessionStorage': 8
  };
  const NOISE = new _Set(['true', 'false', 'null', 'undefined', 'none', 'auto', 'http', 'https', 'html', 'text', 'json']);

  const dyn = [];
  let dynVer = 0;
  let storageSources = [];
  let storTs = 0;
  let cache = { sig: '', ts: 0, tokens: [], json: '' };

  function addDyn(origin, name, value) {
    if (typeof value !== 'string' || value.length < 3) return;
    dyn.push(S('postMessage', name + ' (' + origin + ')', value));
    if (dyn.length > 30) dyn.shift();
    dynVer++;
  }

  function refreshStorage() {
    const out = [];
    try {
      const c = document.cookie;
      if (c) c.split(/;\s*/).slice(0, 30).forEach((p) => {
        const i = p.indexOf('=');
        if (i > 0) out.push(S('document.cookie', p.slice(0, i), p.slice(i + 1)));
      });
    } catch (e) { /* ignore */ }
    ['localStorage', 'sessionStorage'].forEach((kind) => {
      try {
        const st = W[kind];
        for (let i = 0; i < Math.min(st.length, 30); i++) {
          const k = st.key(i);
          out.push(S(kind, k, st.getItem(k)));
        }
      } catch (e) { /* ignore */ }
    });
    storageSources = out;
  }

  function collect() {
    const list = [];
    const L = location;
    const q = L.search;
    if (q.length > 1) {
      list.push(S('location.search', '(query)', q.slice(1)));
      try { new _URLSP(q).forEach((v, k) => list.push(S('location.search', k, v))); } catch (e) { /* ignore */ }
    }
    const h = L.hash.slice(1);
    if (h) {
      list.push(S('location.hash', '(hash)', h));
      const qi = h.indexOf('?');
      const frag = qi >= 0 ? h.slice(qi + 1) : h;
      if (/[=&]/.test(frag)) {
        try { new _URLSP(frag).forEach((v, k) => list.push(S('location.hash', k, v))); } catch (e) { /* ignore */ }
      }
      h.split('/').forEach((seg, i) => { if (seg.length >= 4) list.push(S('location.hash', 'segmento ' + i, seg)); });
    }
    L.pathname.split('/').forEach((seg, i) => { if (seg.length >= 4) list.push(S('location.pathname', 'segmento ' + i, seg)); });
    if (document.referrer) list.push(S('document.referrer', '(referrer)', document.referrer));
    if (W.name) list.push(S('window.name', '(name)', W.name));
    return list.concat(storageSources, dyn);
  }

  function variants(v) {
    const out = new _Set([v]);
    [false, true].forEach((plus) => {
      let cur = plus ? v.replace(/\+/g, ' ') : v;
      if (plus && cur !== v) out.add(cur);
      for (let i = 0; i < 3; i++) {
        let d;
        try { d = _decode(cur); } catch (e) { break; }
        if (d === cur) break;
        out.add(d);
        cur = d;
      }
    });
    return out;
  }

  function getTokens() {
    const now = Date.now();
    const sig = location.href + '\u0001' + W.name + '\u0001' + document.referrer + '\u0001' + dynVer;
    if (cache.sig === sig && now - cache.ts < 2000) return cache.tokens;
    if (now - storTs > 2000) { refreshStorage(); storTs = now; }

    const list = collect();
    const tokens = [];
    const seenT = new _Set();
    for (const s of list) {
      const min = MIN[s.kind] || 4;
      const big = (s.kind === 'document.cookie' || s.kind === 'localStorage' || s.kind === 'sessionStorage') ? 500 : 2000;
      variants(s.value).forEach((v) => {
        if (v.length < min || v.length > big || NOISE.has(v.toLowerCase())) return;
        const k = v + '\u0001' + s.kind + s.name;
        if (seenT.has(k)) return;
        seenT.add(k);
        tokens.push({ src: s, token: v });
      });
    }
    tokens.sort((a, b) => b.token.length - a.token.length);
    if (tokens.length > 200) tokens.length = 200;

    const json = _stringify(list.map((s) => [s.kind, s.name, s.value.slice(0, /cookie|Storage/.test(s.kind) ? 60 : 200)]));
    if (json !== cache.json) {
      push({ type: 'sources', list: list.slice(0, 200).map((s) => ({ kind: s.kind, name: s.name, value: s.value.slice(0, /cookie|Storage/.test(s.kind) ? 60 : 200) })) });
    }
    cache = { sig: sig, ts: now, tokens: tokens, json: json };
    return tokens;
  }

  // ---------- registro finding ----------
  const seen = new _Map();
  const refs = new _Map();
  let seq = 0;

  function __dxs_record(sink, sev, conf, t, value, el) {
    const frames = parseStack(new _Error().stack, 3);
    const where = frames[0] ? frames[0].url + ':' + frames[0].line + ':' + frames[0].col : 'sconosciuto';
    const key = [sink, t.src.kind, t.src.name, where].join('|');
    const now = Date.now();
    let f = seen.get(key);
    if (f) {
      f.count++;
      f.lastTs = now;
      dirty.add(f);
      if (!flushT) flushT = _setTimeout(flush, CFG.flushMs);
      return;
    }
    if (seen.size >= CFG.maxFindings) return;
    const path = pathOf(el);
    f = {
      id: 'f' + (++seq), key: key, ts: now, lastTs: now, count: 1,
      sink: { name: sink, severity: sev },
      source: { kind: t.src.kind, name: t.src.name, value: trunc(t.src.value, 200), token: trunc(t.token, 120) },
      confidence: conf,
      excerpt: excerpt(value, t.token),
      stack: frames, where: where,
      element: path, tag: el && el.tagName ? el.tagName.toLowerCase() : null,
      frame: { url: location.href, top: W === W.top }
    };
    seen.set(key, f);
    if (path && el.nodeType === 1 && _WeakRef) refs.set(f.id, new _WeakRef(el));
    push({ type: 'finding', finding: f });
  }

  // Ritorna true se il chiamante deve fermarsi con `debugger`.
  function __dxs_inspect(sink, sev, value, el, mode) {
    if (busy || typeof value !== 'string' || value.length < 3) return false;
    busy++;
    let pause = false;
    try {
      const toks = getTokens();
      if (!toks.length) return false;
      const usedTok = [];
      let found = 0;
      for (let i = 0; i < toks.length && found < 2; i++) {
        const t = toks[i];
        if (value.indexOf(t.token) === -1) continue;
        if (usedTok.some((u) => u.indexOf(t.token) !== -1)) continue; // già coperto da un token più lungo
        let s = sev;
        let conf = null;
        if (mode === 'url') {
          const n = value.replace(/^[\u0000-\u0020]+/, '').replace(/[\t\n\r]/g, '');
          if (/^(javascript|vbscript|data):/i.test(n)) { s = 'high'; conf = 'high'; }
          else if (value.indexOf(t.token) === 0) { s = 'medium'; }
          else continue;
        }
        usedTok.push(t.token);
        found++;
        conf = conf || (META.test(t.token) ? 'high' : 'medium');
        __dxs_record(sink, s, conf, t, value, el);
        if (CFG.pause && conf === 'high' && (s === 'critical' || s === 'high')) pause = true;
      }
    } catch (e) { /* mai rompere la pagina */ } finally { busy--; }
    return pause;
  }

  // ---------- helper di hooking ----------
  function wrapSetter(proto, prop, label, sev, o) {
    o = o || {};
    try {
      if (!proto) return false;
      const d = _getDesc(proto, prop);
      if (!d || !d.set || !d.configurable) return false;
      const set = function __dxs_w(v) {
        let pause = false;
        try {
          if (typeof v === 'string' && (!o.guard || o.guard(this))) pause = __dxs_inspect(label, sev, v, this, o.mode);
        } catch (e) { /* ignore */ }
        if (pause) debugger;
        return _apply(d.set, this, [v]);
      };
      mask(set, d.set);
      _defProp(proto, prop, { get: d.get, set: set, enumerable: d.enumerable, configurable: true });
      return true;
    } catch (e) { return false; }
  }

  function wrapMethod(obj, name, label, sev, getValue, o) {
    o = o || {};
    try {
      if (!obj) return false;
      const d = _getDesc(obj, name);
      const orig = d ? d.value : obj[name];
      if (typeof orig !== 'function' || (d && !d.configurable)) return false;
      const holder = {
        __dxs_w(...a) {
          let pause = false;
          try {
            const v = getValue(a, this);
            if (typeof v === 'string') pause = __dxs_inspect(label, sev, v, this && this.nodeType ? this : null, o.mode);
          } catch (e) { /* ignore */ }
          if (pause) debugger;
          return _apply(orig, this, a);
        }
      };
      const wrapped = holder.__dxs_w;
      mask(wrapped, orig);
      _defProp(obj, name, { value: wrapped, writable: true, configurable: true, enumerable: d ? d.enumerable : false });
      return true;
    } catch (e) { return false; }
  }

  const note = (name, okk) => (okk ? active : failed).push(name);
  const P = (n) => (W[n] ? W[n].prototype : null);

  // ---------- installazione hook ----------
  // HTML sink
  note('innerHTML', wrapSetter(P('Element'), 'innerHTML', 'innerHTML', 'high'));
  note('outerHTML', wrapSetter(P('Element'), 'outerHTML', 'outerHTML', 'high'));
  note('ShadowRoot.innerHTML', wrapSetter(P('ShadowRoot'), 'innerHTML', 'ShadowRoot.innerHTML', 'high'));
  note('insertAdjacentHTML', wrapMethod(P('Element'), 'insertAdjacentHTML', 'insertAdjacentHTML', 'high', (a) => a[1]));
  note('document.write', wrapMethod(P('Document'), 'write', 'document.write', 'high', (a) => a.filter((x) => typeof x === 'string').join('')));
  note('document.writeln', wrapMethod(P('Document'), 'writeln', 'document.writeln', 'high', (a) => a.filter((x) => typeof x === 'string').join('')));
  note('createContextualFragment', wrapMethod(P('Range'), 'createContextualFragment', 'createContextualFragment', 'high', (a) => a[0]));
  if (P('Element') && P('Element').setHTMLUnsafe) {
    note('setHTMLUnsafe', wrapMethod(P('Element'), 'setHTMLUnsafe', 'setHTMLUnsafe', 'high', (a) => a[0]));
  }
  if (W.Document && W.Document.parseHTMLUnsafe) {
    note('parseHTMLUnsafe', wrapMethod(W.Document, 'parseHTMLUnsafe', 'parseHTMLUnsafe', 'high', (a) => a[0]));
  }
  note('iframe.srcdoc', wrapSetter(P('HTMLIFrameElement'), 'srcdoc', 'iframe.srcdoc', 'high'));

  // Script come sink
  note('script.text', wrapSetter(P('HTMLScriptElement'), 'text', 'script.text', 'critical'));
  note('script.src', wrapSetter(P('HTMLScriptElement'), 'src', 'script.src', 'high'));
  const isScript = (n) => W.HTMLScriptElement && n instanceof W.HTMLScriptElement;
  note('script.textContent', wrapSetter(P('Node'), 'textContent', 'script.textContent', 'critical', { guard: isScript }));
  note('script.innerText', wrapSetter(P('HTMLElement'), 'innerText', 'script.innerText', 'critical', { guard: isScript }));

  // Attributi
  const URLATTR = new _Set(['href', 'src', 'action', 'formaction', 'data', 'xlink:href']);
  note('setAttribute', (function () {
    try {
      const d = _getDesc(P('Element'), 'setAttribute');
      const orig = d.value;
      const holder = {
        __dxs_w(...a) {
          let pause = false;
          try {
            const n = String(a[0]).toLowerCase();
            const v = a[1];
            if (typeof v === 'string') {
              if (n.indexOf('on') === 0) pause = __dxs_inspect('setAttribute(' + n + ')', 'high', v, this);
              else if (n === 'srcdoc') pause = __dxs_inspect('setAttribute(srcdoc)', 'high', v, this);
              else if (URLATTR.has(n)) pause = __dxs_inspect('setAttribute(' + n + ')', 'medium', v, this, 'url');
            }
          } catch (e) { /* ignore */ }
          if (pause) debugger;
          return _apply(orig, this, a);
        }
      };
      mask(holder.__dxs_w, orig);
      _defProp(P('Element'), 'setAttribute', { value: holder.__dxs_w, writable: true, configurable: true, enumerable: d.enumerable });
      return true;
    } catch (e) { return false; }
  })());

  // Proprietà URL
  [['HTMLAnchorElement', 'href'], ['HTMLAreaElement', 'href'], ['HTMLFormElement', 'action'],
   ['HTMLIFrameElement', 'src'], ['HTMLEmbedElement', 'src'], ['HTMLObjectElement', 'data'],
   ['HTMLInputElement', 'formAction'], ['HTMLButtonElement', 'formAction']].forEach((p) => {
    note(p[0] + '.' + p[1], wrapSetter(P(p[0]), p[1], p[0].replace('HTML', '').replace('Element', '').toLowerCase() + '.' + p[1], 'medium', { mode: 'url' }));
  });
  note('window.open', wrapMethod(W, 'open', 'window.open', 'medium', (a) => a[0], { mode: 'url' }));

  // Esecuzione di codice
  const timer = (name) => {
    try {
      const d = _getDesc(W, name);
      const orig = d.value;
      const holder = {
        __dxs_w(h, ...rest) {
          let pause = false;
          try { if (typeof h === 'string') pause = __dxs_inspect(name + '(stringa)', 'critical', h, null); } catch (e) { /* ignore */ }
          if (pause) debugger;
          return _apply(orig, this, [h].concat(rest));
        }
      };
      mask(holder.__dxs_w, orig);
      _defProp(W, name, { value: holder.__dxs_w, writable: true, configurable: true, enumerable: d.enumerable });
      return true;
    } catch (e) { return false; }
  };
  note('setTimeout', timer('setTimeout'));
  note('setInterval', timer('setInterval'));

  if (CFG.hookEval) {
    try {
      const d = _getDesc(W, 'eval');
      const origEval = d.value;
      const holder = {
        __dxs_w(x) {
          let pause = false;
          try { if (typeof x === 'string') pause = __dxs_inspect('eval', 'critical', x, null); } catch (e) { /* ignore */ }
          if (pause) debugger;
          return _apply(origEval, this, arguments);
        }
      };
      mask(holder.__dxs_w, origEval);
      _defProp(W, 'eval', { value: holder.__dxs_w, writable: true, configurable: true, enumerable: d.enumerable });
      note('eval', true);
    } catch (e) { note('eval', false); }

    try {
      const OF = W.Function;
      const NF = function __dxs_w(...a) {
        let pause = false;
        try { pause = __dxs_inspect('Function()', 'critical', a.map((x) => (typeof x === 'string' ? x : '')).join('\n'), null); } catch (e) { /* ignore */ }
        if (pause) debugger;
        return new.target ? Reflect.construct(OF, a, new.target === NF ? OF : new.target) : _apply(OF, this, a);
      };
      NF.prototype = OF.prototype;
      _defProp(OF.prototype, 'constructor', { value: NF, writable: true, configurable: true });
      mask(NF, OF);
      W.Function = NF;
      note('Function', true);
    } catch (e) { note('Function', false); }
  }

  // jQuery (caricato dopo di noi: intercetta l'assegnazione del global)
  function patchJQuery(jq) {
    if (!jq || jq.__dxsp || !jq.fn || typeof jq.fn.jquery !== 'string') return;
    try { _defProp(jq, '__dxsp', { value: true }); } catch (e) { return; }
    ['html', 'append', 'prepend', 'after', 'before', 'replaceWith', 'wrap', 'wrapAll', 'wrapInner'].forEach((m) => {
      const o = jq.fn[m];
      if (typeof o !== 'function') return;
      jq.fn[m] = function __dxs_w() {
        let pause = false;
        try {
          for (let i = 0; i < arguments.length; i++) {
            if (typeof arguments[i] === 'string') {
              const el = this && this[0] && this[0].nodeType === 1 ? this[0] : null;
              pause = __dxs_inspect('jQuery.' + m, 'high', arguments[i], el) || pause;
            }
          }
        } catch (e) { /* ignore */ }
        if (pause) debugger;
        return _apply(o, this, arguments);
      };
      mask(jq.fn[m], o);
    });
    const ph = jq.parseHTML;
    if (typeof ph === 'function') {
      jq.parseHTML = function __dxs_w(d) {
        let pause = false;
        try { if (typeof d === 'string') pause = __dxs_inspect('jQuery.parseHTML', 'high', d, null); } catch (e) { /* ignore */ }
        if (pause) debugger;
        return _apply(ph, this, arguments);
      };
      mask(jq.parseHTML, ph);
    }
    push({ type: 'hooks', add: ['jQuery ' + jq.fn.jquery] });
  }

  function watchGlobal(name) {
    try {
      let val = W[name];
      if (val) patchJQuery(val);
      const d = _getDesc(W, name);
      if (d && !d.configurable) return;
      _defProp(W, name, {
        configurable: true, enumerable: true,
        get() { return val; },
        set(v) { val = v; try { patchJQuery(v); } catch (e) { /* ignore */ } }
      });
    } catch (e) { /* ignore */ }
  }
  watchGlobal('jQuery');
  watchGlobal('$');

  // postMessage come source (listener in cattura, registrato prima di quelli della pagina)
  _addEL('message', (ev) => {
    try {
      const v = ev.data;
      const origin = ev.origin || '?';
      if (typeof v === 'string') addDyn(origin, '(data)', v);
      else if (v && typeof v === 'object') {
        addDyn(origin, '(json)', _stringify(v));
        Object.keys(v).slice(0, 20).forEach((k) => { if (typeof v[k] === 'string') addDyn(origin, k, v[k]); });
      }
    } catch (e) { /* ignore */ }
  }, true);

  // ---------- comandi dal relay ----------
  function highlight(el) {
    try {
      el.scrollIntoView({ block: 'center' });
      const po = el.style.outline;
      const pf = el.style.outlineOffset;
      el.style.outline = '3px solid #e5484d';
      el.style.outlineOffset = '2px';
      _setTimeout(() => { el.style.outline = po; el.style.outlineOffset = pf; }, 3000);
    } catch (e) { /* ignore */ }
  }

  _addEL(CH + ':in', (ev) => {
    let c;
    try { c = _parse(ev.detail); } catch (e) { return; }
    if (!c) return;
    if (c.cmd === 'config') {
      if ('pause' in c) CFG.pause = !!c.pause;
    } else if (c.cmd === 'highlight') {
      const r = refs.get(c.id);
      const el = r && r.deref();
      if (el) highlight(el);
    } else if (c.cmd === 'reset') {
      seen.clear();
      refs.clear();
      cache = { sig: '', ts: 0, tokens: [], json: '' };
    }
  }, true);

  // aggiorna l'elenco source quando cambia l'URL
  const refresh = () => { try { getTokens(); } catch (e) { /* ignore */ } };
  _addEL('hashchange', refresh, true);
  _addEL('popstate', refresh, true);
  _addEL('DOMContentLoaded', refresh, true);

  push({ type: 'ready', hooks: { active: active.slice(), failed: failed.slice() }, url: location.href, top: W === W.top });
  refresh();
  flush();
  }

  const cs = document.currentScript;
  if (cs && cs.dataset && cs.dataset.ch) {
    const ch = cs.dataset.ch;
    cs.removeAttribute('data-ch');
    main(ch, cs.src);
  } else {
    window.__dxsMain = main;
  }
})();
