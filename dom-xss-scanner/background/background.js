// ===============================
// background/background.js  (v2.0)
// Tiene lo stato per tab (persistente), aggiorna il badge e fa da hub
// tra relay (content script) e pannello DevTools.
// ===============================
'use strict';

const api = typeof browser !== 'undefined' ? browser : chrome;

// Marcatore innocuo per il pulsante "Prova marcatore": contiene metacaratteri
// HTML e un <i>, nessuno script.
const MARKER = 'dxs9q"\'<i>x</i>';
const SEV = { low: 0, medium: 1, high: 2, critical: 3 };
const COLORS = ['#2da44e', '#d29922', '#e8590c', '#d1242f'];
const MAX_FINDINGS = 500;

const tabs = new Map();   // tabId -> stato
const ports = new Map();  // tabId -> Set<Port>
const pending = new Set();

function newState(url) {
  return { url: url || '', findings: new Map(), frames: new Map(), hookFailed: false };
}

function stateOf(tabId) {
  let s = tabs.get(tabId);
  if (!s) { s = newState(); tabs.set(tabId, s); }
  return s;
}

function frameOf(s, frameId) {
  let f = s.frames.get(frameId);
  if (!f) { f = { url: '', top: false, hooks: { active: [], failed: [] }, sources: [] }; s.frames.set(frameId, f); }
  return f;
}

// ---------- snapshot e broadcast ----------
function snapshot(tabId) {
  const s = tabs.get(tabId) || newState();
  const findings = Array.from(s.findings.values()).sort((a, b) =>
    (SEV[b.sink.severity] - SEV[a.sink.severity]) || (b.lastTs - a.lastTs));
  const sources = [];
  s.frames.forEach((f, frameId) => f.sources.forEach((x) => sources.push({ ...x, frameId: frameId, top: f.top, frameUrl: f.url })));
  return {
    tabId: tabId,
    url: s.url,
    hookFailed: s.hookFailed,
    frames: Array.from(s.frames.entries()).map(([frameId, f]) => ({ frameId: frameId, url: f.url, top: f.top, hooks: f.hooks })),
    findings: findings,
    sources: sources
  };
}

function schedule(tabId) {
  if (pending.has(tabId)) return;
  pending.add(tabId);
  setTimeout(() => {
    pending.delete(tabId);
    setBadge(tabId);
    const set = ports.get(tabId);
    if (!set || !set.size) return;
    const state = snapshot(tabId);
    set.forEach((p) => { try { p.postMessage({ type: 'state', state: state }); } catch (e) { /* porta chiusa */ } });
  }, 150);
}

function setBadge(tabId) {
  const s = tabs.get(tabId);
  let n = 0;
  let max = -1;
  if (s) s.findings.forEach((f) => { if (f.confidence === 'high') { n++; max = Math.max(max, SEV[f.sink.severity]); } });
  const act = api.browserAction;
  if (!act) return;
  const ig = () => {};
  try {
    act.setBadgeText({ tabId: tabId, text: n ? String(n) : '' }).catch(ig);
    act.setBadgeBackgroundColor({ tabId: tabId, color: COLORS[max] || '#888888' }).catch(ig);
  } catch (e) { /* tab chiuso */ }
}

// ---------- messaggi dai relay ----------
api.runtime.onMessage.addListener((msg, sender) => {
  if (!msg) return undefined;

  if (msg.kind === 'get-config') {
    return api.storage.local.get({ pauseOnTaint: false }).then((c) => ({ pause: c.pauseOnTaint }));
  }

  const tabId = sender.tab && sender.tab.id;
  if (tabId == null || tabId < 0) return undefined;
  const frameId = sender.frameId || 0;

  switch (msg.kind) {
    case 'frame-start': {
      if (msg.top) {
        tabs.set(tabId, newState(msg.url));
        frameOf(tabs.get(tabId), 0).top = true;
        frameOf(tabs.get(tabId), 0).url = msg.url;
      } else {
        const f = frameOf(stateOf(tabId), frameId);
        f.url = msg.url;
      }
      schedule(tabId);
      break;
    }
    case 'hook-failed': {
      const s = stateOf(tabId);
      const f = frameOf(s, frameId);
      if (!f.hooks.active.length && msg.top) s.hookFailed = true;
      schedule(tabId);
      break;
    }
    case 'page-batch': {
      const s = stateOf(tabId);
      const f = frameOf(s, frameId);
      for (const ev of msg.events || []) {
        if (!ev) continue;
        if (ev.type === 'ready') {
          f.url = ev.url || f.url;
          f.top = !!ev.top;
          f.hooks = ev.hooks || f.hooks;
          if (f.top) s.hookFailed = false;
        } else if (ev.type === 'hooks') {
          (ev.add || []).forEach((h) => f.hooks.active.push(h));
        } else if (ev.type === 'sources') {
          f.sources = ev.list || [];
        } else if (ev.type === 'finding' && ev.finding) {
          const fi = ev.finding;
          const k = frameId + '|' + fi.key;
          if (!s.findings.has(k) && s.findings.size >= MAX_FINDINGS) continue;
          s.findings.set(k, { ...fi, gid: frameId + ':' + fi.id, frameId: frameId, frameUrl: sender.url || f.url });
        }
      }
      schedule(tabId);
      break;
    }
    default:
  }
  return undefined;
});

// ---------- pannello DevTools ----------
api.runtime.onConnect.addListener((port) => {
  if (port.name !== 'panel') return;
  let tabId = null;

  port.onMessage.addListener((m) => {
    if (!m) return;
    if (m.cmd === 'init') {
      tabId = m.tabId;
      if (!ports.has(tabId)) ports.set(tabId, new Set());
      ports.get(tabId).add(port);
      port.postMessage({ type: 'state', state: snapshot(tabId) });
      api.storage.local.get({ pauseOnTaint: false }).then((c) => port.postMessage({ type: 'config', pause: c.pauseOnTaint }));
      return;
    }
    if (tabId != null) command(tabId, m);
  });

  port.onDisconnect.addListener(() => {
    if (tabId != null && ports.has(tabId)) ports.get(tabId).delete(port);
  });
});

function toTab(tabId, cmd, options) {
  api.tabs.sendMessage(tabId, { kind: 'cmd', cmd: cmd }, options || {}).catch(() => {});
}

function command(tabId, m) {
  switch (m.cmd) {
    case 'clear': {
      const old = tabs.get(tabId);
      const s = newState(old && old.url);
      if (old) old.frames.forEach((f, id) => s.frames.set(id, { ...f, sources: f.sources }));
      tabs.set(tabId, s);
      toTab(tabId, { cmd: 'reset' });
      schedule(tabId);
      break;
    }
    case 'config':
      api.storage.local.set({ pauseOnTaint: !!m.pause });
      toTab(tabId, { cmd: 'config', pause: !!m.pause });
      break;
    case 'highlight':
      toTab(tabId, { cmd: 'highlight', id: m.id }, { frameId: m.frameId });
      break;
    case 'reload':
      api.tabs.reload(tabId, { bypassCache: true }).catch(() => {});
      break;
    case 'probe':
      api.tabs.get(tabId).then((tab) => {
        const u = new URL(tab.url);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
        u.searchParams.set('dxsprobe', MARKER);
        if (!u.hash) u.hash = '#' + MARKER;
        return api.tabs.update(tabId, { url: u.toString() });
      }).catch(() => {});
      break;
    default:
  }
}

api.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
  ports.delete(tabId);
  pending.delete(tabId);
});
