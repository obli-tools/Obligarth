import en from './i18n/en.json';
import fr from './i18n/fr.json';
import { FAVICON_PNG_BASE64 } from './favicon';

/**
 * Obligarth bench station — the page (lot BANC §5.3, §5.4): vanilla HTML, CSS and JS, no external resource (the CSP
 * allows none). Every text goes through `t('ns.key') || 'Fallback'` with the en and fr catalogs built in (deliberate
 * difference with Obliwan, whose page was written in French only); the language follows Edge's, and can be switched.
 * The page receives codes and parameters from the local server and translates them; it never sees a token.
 */
export const CATALOGS = { en, fr } as const;

/** The catalogs as a script literal: `<` escaped so that no text can close the script element. */
export function catalogsLiteral(): string {
  return JSON.stringify(CATALOGS).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

export function renderPage(version: string): string {
  return `<!doctype html>
<html lang="en" translate="no">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="google" content="notranslate">
<title>Obligarth Bench</title>
<link rel="icon" type="image/png" href="data:image/png;base64,${FAVICON_PNG_BASE64}">
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#6b7280;--line:#e5e7eb;--hover:#f1f3f6;--accent:#2563eb;
--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--wait:#7c3aed;--hold:#ea580c;--idle:#9ca3af;--act:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--panel:#1a1d24;--text:#e5e7eb;--muted:#9ca3af;--line:#2a2f3a;--hover:#222733}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:2}
header h1{font-size:16px;margin:0;font-weight:600}
header .grow{flex:1}
main{padding:16px 20px;max-width:1400px;margin:0 auto}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;background:var(--hover);color:var(--muted)}
.pill::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.t-ok{color:var(--ok)}.t-warn{color:var(--warn)}.t-bad{color:var(--bad)}.t-wait{color:var(--wait)}.t-hold{color:var(--hold)}.t-act{color:var(--act)}.t-idle{color:var(--idle)}
.banner{background:var(--panel);border-left:4px solid var(--warn);padding:10px 14px;margin:0 0 12px;border-radius:6px}
.banner.bad{border-color:var(--bad)}.banner.info{border-color:var(--accent)}.banner.ok{border-color:var(--ok)}
.banner p{margin:4px 0}
.code{font:600 28px/1.2 Consolas,monospace;letter-spacing:2px}
button{font:inherit;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:6px;padding:6px 12px;cursor:pointer}
button:hover{background:var(--hover)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
input,select{font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;min-width:0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px}
.card{background:var(--panel);border-radius:10px;padding:12px 14px;border-top:4px solid var(--idle)}
.card.tone-ok{border-color:var(--ok)}.card.tone-warn{border-color:var(--warn)}.card.tone-bad{border-color:var(--bad)}
.card.tone-wait{border-color:var(--wait)}.card.tone-hold{border-color:var(--hold)}.card.tone-act{border-color:var(--act)}
.card.attention{animation:blink 1s step-start 6}
@keyframes blink{50%{box-shadow:0 0 0 3px var(--hold)}}
.card h2{font-size:15px;margin:0 0 2px}
.muted{color:var(--muted)}
.steps{list-style:none;margin:8px 0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:2px 10px}
.steps li{display:flex;align-items:center;gap:6px;font-size:12.5px;padding:2px 4px;border-radius:4px}
.steps li:hover{background:var(--hover)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--line);flex:none}
.s-ok .dot{background:var(--ok)}.s-warn .dot{background:var(--warn)}.s-failed .dot{background:var(--bad)}.s-running .dot{background:var(--act)}.s-skipped .dot{background:var(--idle)}
.prompt{background:var(--hover);border-radius:6px;padding:8px 10px;margin:8px 0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:6px}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);font-size:13px}
tr:hover td{background:var(--hover)}
h3{font-size:14px;margin:20px 0 8px}
a{color:var(--accent)}
</style>
</head>
<body>
<header>
  <h1 id="title">Obligarth Bench</h1>
  <span id="phase" class="pill t-idle"></span>
  <span id="session" class="muted"></span>
  <span class="grow"></span>
  <span class="muted" id="ver"></span>
  <button id="lang" data-action="lang"></button>
</header>
<main>
  <div id="banners"></div>
  <div id="gate"></div>
  <div id="cards" class="grid"></div>
  <h3 id="histTitle"></h3>
  <div id="history"></div>
</main>
<script>
"use strict";
const CATALOGS = ${catalogsLiteral()};
const VERSION = ${JSON.stringify(version)};
const TOKEN = new URLSearchParams(location.search).get('t') || '';
let lang = 'en';
try { lang = localStorage.getItem('bench.lang') || ((navigator.language || '').toLowerCase().startsWith('fr') ? 'fr' : 'en'); } catch (e) { lang = (navigator.language || '').toLowerCase().startsWith('fr') ? 'fr' : 'en'; }
function t(key, params) {
  const s = (CATALOGS[lang] && CATALOGS[lang][key]) || CATALOGS.en[key] || '';
  return s.replace(/\\{\\{(\\w+)\\}\\}/g, (_, k) => (params && params[k] !== undefined && params[k] !== null ? String(params[k]) : ''));
}
const esc = (v) => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function api(path, opts) {
  const o = opts || {};
  const res = await fetch(path, { method: o.method || 'GET', headers: Object.assign({ 'x-bench-token': TOKEN }, o.body !== undefined ? { 'content-type': 'application/json' } : {}, o.headers || {}), body: o.body !== undefined ? JSON.stringify(o.body) : undefined });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  return { status: res.status, ok: res.ok, body: body || {} };
}
let state = null, cards = [], targets = [], targetsAt = 0, historyRows = [], seenAttention = {};
function errText(code, params) { return t('bench.error.' + code, params) || t('bench.local.' + code, params) || (t('bench.error.internal') || 'Unexpected error') + ' (' + code + ')'; }
function toast(text) { alert(text); }
function beep() {
  try { const c = new AudioContext(); const o = c.createOscillator(); const g = c.createGain(); o.frequency.value = 880; o.connect(g); g.connect(c.destination); g.gain.value = 0.08; o.start(); setTimeout(() => { o.stop(); c.close(); }, 250); } catch (e) { /* no audio */ }
}
function phaseTone(p) { return ({ approved: 'ok', pending: 'warn', suspended: 'hold', revoked: 'bad', unreachable: 'bad', redirected: 'bad', refused: 'bad', localError: 'bad', checking: 'idle', 'need-url': 'idle' })[p] || 'idle'; }
function hhmm(iso) { try { return new Date(iso).toLocaleTimeString(lang === 'fr' ? 'fr-FR' : 'en-GB', { hour: '2-digit', minute: '2-digit' }); } catch (e) { return iso; } }

function renderHeader() {
  document.documentElement.lang = lang;
  document.getElementById('title').textContent = t('bench.app.title') || 'Obligarth Bench';
  document.title = (t('bench.app.title') || 'Obligarth Bench');
  document.getElementById('ver').textContent = 'v' + VERSION;
  document.getElementById('lang').textContent = lang === 'fr' ? 'English' : 'Français';
  document.getElementById('histTitle').textContent = t('bench.history.title') || 'Today on this station';
  const ph = document.getElementById('phase');
  ph.className = 'pill t-' + phaseTone(state.phase);
  ph.textContent = t('bench.phase.' + state.phase) || state.phase;
  const s = state.station && state.station.session;
  document.getElementById('session').textContent = state.phase === 'approved'
    ? (s ? (t('bench.session.open', { technician: s.technician || '?', until: hhmm(s.expiresAt) }) || ('Session until ' + hhmm(s.expiresAt))) : (t('bench.session.none') || 'No bench session open: open one in the console'))
    : '';
}

function renderBanners() {
  const out = [];
  const a = state.adb;
  if (a.status === 'error') {
    // The tools are there, their server did not start: start it again, never download again.
    out.push('<div class="banner bad"><strong>' + esc(t('bench.error.adb_server') || 'The ADB server of the station did not start.') + '</strong>'
      + (a.reason ? '<p class="muted">' + esc(t('bench.adb.reason', { reason: a.reason }) || a.reason) + '</p>' : '')
      + '<div class="row"><button class="primary" data-action="adb-retry">' + esc(t('bench.adb.retry') || 'Start ADB again') + '</button></div></div>');
  } else if (a.status === 'missing') {
    out.push('<div class="banner bad"><strong>' + esc(t('bench.adb.missingTitle') || 'adb is not installed on this station') + '</strong>'
      + '<p>' + esc(t('bench.adb.license', { version: a.version }) || 'The station downloads Google platform-tools and checks it.') + ' <a href="' + esc(a.licenseUrl) + '" target="_blank" rel="noreferrer">' + esc(t('bench.adb.licenseLink') || 'Android SDK licence') + '</a></p>'
      + (a.reason ? '<p class="muted">' + esc(t('bench.adb.reason', { reason: a.reason }) || a.reason) + '</p>' : '')
      + '<div class="row"><button class="primary" data-action="adb-install">' + esc(t('bench.adb.accept') || 'Accept the licence and download') + '</button>'
      + '<input id="zipPath" size="40" placeholder="' + esc(t('bench.adb.zipPlaceholder') || 'or the path of a downloaded zip') + '">'
      + '<button data-action="adb-zip">' + esc(t('bench.adb.useZip') || 'Use this zip') + '</button></div></div>');
  } else if (a.status === 'downloading') {
    out.push('<div class="banner info">' + esc(t('bench.adb.downloading') || 'Downloading and checking platform-tools…') + '</div>');
  }
  if (a.conflict && a.conflict.conflict) {
    out.push('<div class="banner bad"><strong>' + esc(t('bench.error.adb_conflict') || 'Another ADB tool holds the devices') + '</strong>'
      + '<p>' + esc(t('bench.adb.conflictHelp') || 'Close Android Studio, scrcpy or the Samsung tool.') + '</p>'
      + '<p class="muted">' + a.conflict.foreign.map((f) => esc((f.path || 'adb.exe') + ' (pid ' + f.pid + ')')).join('<br>') + (a.conflict.listener5037 ? '<br>' + esc(t('bench.adb.listener') || 'A server listens on port 5037') : '') + '</p>'
      + '<div class="row"><button class="danger" data-action="stop-conflicts">' + esc(t('bench.adb.stop') || 'Stop these processes') + '</button></div></div>');
  }
  if (a.usbUnseen && a.usbUnseen.length) {
    out.push('<div class="banner"><strong>' + esc(t('bench.adb.usbUnseen', { serials: a.usbUnseen.join(', ') }) || ('Samsung phone on USB not seen by ADB: ' + a.usbUnseen.join(', '))) + '</strong>'
      + '<p>' + esc(t('bench.error.auto_blocker_suspected') || 'Auto Blocker seems active.') + '</p>'
      + '<p class="muted">' + esc(t('bench.error.adb_blocked_by_policy') || 'USB debugging may be blocked by a policy.') + '</p></div>');
  }
  if (a.smartSwitch) out.push('<div class="banner">' + esc(t('bench.adb.smartSwitch') || 'Close Samsung Smart Switch: it holds the phones.') + '</div>');
  if (a.samsungDriver === false) out.push('<div class="banner info">' + esc(t('bench.adb.driver') || 'Windows has no driver for the Samsung phone plugged in.') + '</div>');
  if (a.status === 'ready' && a.keyLocation === 'profile') out.push('<div class="banner info">' + esc(t('bench.adb.keyProfile') || 'The ADB key of this station is the one of your Windows profile.') + '</div>');
  if (!state.pinPresent) out.push('<div class="banner bad">' + esc(t('bench.local.no_pin') || 'This build has no pinned agent signer: no APK can be installed.') + '</div>');
  if (state.update && state.update.available) out.push('<div class="banner ok">' + esc(t('bench.update.available', { version: state.update.available }) || ('Version ' + state.update.available + ' is available')) + ' <button data-action="update">' + esc(t('bench.update.apply') || 'Update') + '</button></div>');
  if (Math.abs(state.clockOffsetMs || 0) > 300000) out.push('<div class="banner">' + esc(t('bench.local.clock') || 'The clock of this PC is off by more than 5 minutes.') + '</div>');
  if (state.refusedSerials && state.refusedSerials.length) out.push('<div class="banner">' + esc(errText('too_many_cards')) + '</div>');
  document.getElementById('banners').innerHTML = out.join('');
}

function renderGate() {
  const p = state.phase;
  let h = '';
  if (p === 'need-url' || (state.urlEditable && ['unreachable', 'redirected', 'refused', 'localError'].includes(p))) {
    h += '<div class="banner info"><strong>' + esc(t('bench.url.title') || 'Address of Obligarth') + '</strong><p>' + esc(t('bench.url.help') || 'The address of the Obligarth console, e.g. https://obligarth.example.test') + '</p>'
      + '<div class="row"><input id="url" size="48" value="' + esc(state.url || '') + '" placeholder="https://obligarth.example.test"><button class="primary" data-action="url">' + esc(t('bench.url.save') || 'Connect') + '</button></div></div>';
  }
  if (p === 'pending') {
    h += '<div class="banner"><strong>' + esc(t('bench.station.pendingTitle') || 'This station awaits its approval') + '</strong>'
      + '<p>' + esc(t('bench.station.pendingHelp', { name: state.station.name }) || 'A platform administrator approves it in the console, Bench stations, after typing this code:') + '</p>'
      + '<p class="code">' + esc(state.station.verificationCode || '—') + '</p></div>';
  } else if (p === 'suspended') {
    h += '<div class="banner bad">' + esc(t('bench.station.suspended') || 'This station is suspended: nothing can be done on a device.') + '</div>';
  } else if (p === 'revoked') {
    h += '<div class="banner bad"><strong>' + esc(t('bench.station.revoked') || 'This station is revoked.') + '</strong><p>' + esc(t('bench.station.renewHelp') || 'Renew it: a new token is drawn and must be approved again.') + '</p><button data-action="renew">' + esc(t('bench.station.renew') || 'Renew') + '</button></div>';
  } else if (['unreachable', 'redirected', 'refused', 'localError'].includes(p)) {
    const r = state.refusal || {};
    h += '<div class="banner bad">' + esc(errText(r.code || 'server_unreachable', r)) + (r.suggestedUrl ? '<p>' + esc(t('bench.url.suggested', { url: r.suggestedUrl }) || r.suggestedUrl) + '</p>' : '') + '</div>';
  } else if (p === 'approved' && cards.length === 0) {
    h += '<div class="banner info">' + esc(t('bench.cards.empty') || 'Plug a device with USB debugging enabled.') + '</div>';
  }
  document.getElementById('gate').innerHTML = h;
}

function stepLabel(id) { return t('bench.step.' + id) || id; }

function renderCard(c) {
  const tone = c.tone || 'idle';
  const attention = c.prompt && c.prompt.attention;
  let h = '<div class="card tone-' + esc(tone) + (attention ? ' attention' : '') + '" data-serial="' + esc(c.serial) + '">';
  h += '<h2>' + esc(c.model || c.serial) + ' <span class="pill t-' + esc(tone) + '">' + esc(t('bench.tone.' + tone) || tone) + '</span></h2>';
  h += '<div class="muted">' + esc((c.android ? 'Android ' + c.android : '') + (c.oneUi ? ' · One UI ' + c.oneUi : '') + ' · ' + c.serial + (c.present ? '' : ' · ' + (t('bench.cards.unplugged') || 'unplugged'))) + '</div>';
  if (c.targetLabel) h += '<div>' + esc(c.targetLabel) + (c.deviceName ? ' · ' + esc(c.deviceName) : '') + '</div>';
  if (c.roleChosen) h += '<div class="muted">' + esc(t('bench.role.' + c.roleChosen) || c.roleChosen) + (c.kind === 'convert' ? ' · ' + esc(t('bench.cards.convert') || 'conversion') : '') + '</div>';
  if (!c.provisioningId && !c.busy && c.outcome === 'open') {
    const opts = targets.map((tg) => '<option value="' + tg.tenantId + ':' + tg.groupId + '"' + (c.tenantId === tg.tenantId && c.groupId === tg.groupId ? ' selected' : '') + '>' + esc(tg.tenantName + ' › ' + tg.groupPath + ' — ' + (t('bench.rolePolicy.' + tg.rolePolicy) || tg.rolePolicy)) + '</option>').join('');
    h += '<div class="row"><select data-field="target"><option value="">' + esc(t('bench.cards.chooseTarget') || 'Choose the target…') + '</option>' + opts + '</select>'
      + '<input data-field="name" size="14" maxlength="100" value="' + esc(c.deviceName || '') + '" placeholder="' + esc(t('bench.cards.namePlaceholder') || 'Name (optional)') + '">'
      + '<button class="primary" data-action="start"' + (state.phase !== 'approved' ? ' disabled' : '') + '>' + esc(t('bench.cards.start') || 'Start') + '</button></div>';
  }
  h += '<ul class="steps">' + c.steps.map((s) => '<li class="s-' + esc(s.status) + '" title="' + esc(s.code ? (t('bench.code.' + s.code) || s.code) : '') + '"><span class="dot"></span>' + esc(stepLabel(s.id)) + '</li>').join('') + '</ul>';
  if (c.prompt) {
    const p = c.prompt.params || {};
    h += '<div class="prompt"><strong>' + esc(t('bench.prompt.' + c.prompt.code, p) || errText(c.prompt.code, p)) + '</strong>';
    if (p.blockers) h += '<div>' + p.blockers.split(',').map((b) => esc(t('bench.blocker.' + b) || b)).join('<br>') + '</div>';
    if (p.types) h += '<div class="muted">' + esc(t('bench.prompt.accountTypes', { types: p.types }) || p.types) + '</div>';
    if (p.owners) h += '<div class="muted">' + esc(t('bench.prompt.accountApps', { owners: p.owners }) || p.owners) + '</div>';
    h += '<div class="row">' + c.prompt.choices.map((ch) => '<button data-action="choice" data-choice="' + esc(ch) + '"' + (ch === 'recheck' || ch === 'retry' || ch === 'reissue' ? ' class="primary"' : '') + '>' + esc(t('bench.choice.' + ch) || ch) + '</button>').join('') + '</div></div>';
  }
  if (c.outcome === 'failed' && c.errorCode) h += '<div class="prompt"><strong class="t-bad">' + esc(errText(c.errorCode, c.errorParams || {})) + '</strong></div>';
  if (c.outcome === 'completed') h += '<div class="prompt">' + esc(t('bench.cards.completed') || 'Done.') + (c.adbCut === 'pending_agent' ? ' ' + esc(t('bench.hint.adb_cut_pending') || 'ADB switched off: awaiting the confirmation of the agent.') : '') + '</div>';
  if (c.hint) h += '<div class="muted">' + esc(t('bench.hint.' + c.hint) || c.hint) + '</div>';
  if (c.pendingSteps) h += '<div class="muted">' + esc(t('bench.cards.pendingSteps', { count: c.pendingSteps }) || '') + '</div>';
  h += '<div class="row">';
  if (c.outcome === 'open' && c.provisioningId && !c.busy && !c.prompt) h += '<button data-action="choice" data-choice="retry">' + esc(t('bench.cards.resume') || 'Resume') + '</button>';
  if (c.outcome === 'open' && c.provisioningId && !c.busy) h += '<button class="danger" data-action="abandon">' + esc(t('bench.cards.abandon') || 'Abandon') + '</button>';
  // « Rendre l'appareil »: the owner this station set, whatever the state of the card (the agent refuses once enrolled).
  if (c.ownerSetHere && !c.busy && c.outcome !== 'completed') h += '<button class="danger" data-action="release">' + esc(t('bench.cards.release') || 'Give the device back') + '</button>';
  if (!c.busy && (c.outcome !== 'open' || !c.provisioningId)) h += '<button data-action="close">' + esc(t('bench.cards.close') || 'Close') + '</button>';
  h += '<button data-action="export">' + esc(t('bench.cards.export') || 'Export the raw log') + '</button>';
  h += '</div></div>';
  if (attention && !seenAttention[c.serial + c.prompt.code]) { seenAttention[c.serial + c.prompt.code] = true; beep(); }
  return h;
}

function renderCards() { document.getElementById('cards').innerHTML = cards.map(renderCard).join(''); }

function renderHistory() {
  if (!historyRows.length) { document.getElementById('history').innerHTML = '<p class="muted">' + esc(t('bench.history.empty') || 'Nothing yet today.') + '</p>'; return; }
  const head = ['time', 'tenant', 'serial', 'model', 'role', 'outcome'].map((k) => '<th>' + esc(t('bench.history.' + k) || k) + '</th>').join('');
  const rows = historyRows.map((r) => '<tr><td>' + esc(hhmm(r.at)) + '</td><td>' + esc((r.tenant || '') + (r.group ? ' › ' + r.group : '')) + '</td><td>' + esc(r.serial || '') + '</td><td>' + esc(r.model || '') + (r.android ? ' · ' + esc(r.android) : '') + '</td><td>' + esc(r.roleObtained ? (t('bench.role.' + r.roleObtained) || r.roleObtained) : '') + '</td><td>' + esc(t('bench.outcome.' + r.outcome) || r.outcome) + (r.errorCode ? ' — ' + esc(errText(r.errorCode)) : '') + '</td></tr>').join('');
  document.getElementById('history').innerHTML = '<table><thead><tr>' + head + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderAll() { if (!state) return; renderHeader(); renderBanners(); renderGate(); renderCards(); renderHistory(); }

let loading = false, again = false;
async function load() {
  if (loading) { again = true; return; }
  loading = true;
  try {
    state = (await api('/api/state')).body;
    cards = ((await api('/api/cards')).body.cards) || [];
    if (state.phase === 'approved' && Date.now() - targetsAt > 60000) {
      const r = await api('/api/targets');
      if (r.ok) { targets = r.body.targets || []; targetsAt = Date.now(); }
    }
    historyRows = ((await api('/api/history/today')).body.history) || [];
    renderAll();
  } finally {
    loading = false;
    if (again) { again = false; load(); }
  }
}

async function act(fn) {
  try {
    const r = await fn();
    if (r && !r.ok && r.status !== 202) toast(errText(r.body.code || 'internal', r.body));
  } catch (e) { toast(errText('internal')); }
  load();
}

document.addEventListener('click', (ev) => {
  const el = ev.target.closest('[data-action]');
  if (!el) return;
  const action = el.dataset.action;
  const card = el.closest('[data-serial]');
  const serial = card ? card.dataset.serial : null;
  const enc = serial ? encodeURIComponent(serial) : '';
  if (action === 'lang') { lang = lang === 'fr' ? 'en' : 'fr'; try { localStorage.setItem('bench.lang', lang); } catch (e) { /* none */ } renderAll(); return; }
  if (action === 'url') act(() => api('/api/url', { method: 'POST', body: { url: document.getElementById('url').value } }));
  if (action === 'renew') act(() => api('/api/station/renew', { method: 'POST', body: {} }));
  if (action === 'adb-retry') act(() => api('/api/adb/retry', { method: 'POST', body: {} }));
  if (action === 'release' && confirm(t('bench.cards.releaseConfirm') || 'Give the device back (remove the owner set by this station)?')) {
    act(() => api('/api/cards/' + enc + '/abandon', { method: 'POST', body: { release: true } }));
  }
  if (action === 'adb-install') act(() => api('/api/adb/install', { method: 'POST', body: { accept: true } }));
  if (action === 'adb-zip') act(() => api('/api/adb/install', { method: 'POST', body: { accept: true, zipPath: document.getElementById('zipPath').value } }));
  if (action === 'stop-conflicts' && confirm(t('bench.adb.stopConfirm') || 'Stop the other ADB processes?')) act(() => api('/api/adb/stop-conflicts', { method: 'POST', body: { confirm: true } }));
  if (action === 'update') act(() => api('/api/update/apply', { method: 'POST', body: {} }));
  if (action === 'start') {
    const sel = card.querySelector('[data-field=target]').value;
    if (!sel) { toast(t('bench.cards.chooseTarget') || 'Choose the target'); return; }
    const [tenantId, groupId] = sel.split(':').map(Number);
    const deviceName = card.querySelector('[data-field=name]').value;
    act(async () => {
      const p = await api('/api/cards/' + enc + '/plan', { method: 'POST', body: { tenantId, groupId, deviceName } });
      if (!p.ok) return p;
      return api('/api/cards/' + enc + '/run', { method: 'POST', body: {} });
    });
  }
  if (action === 'choice') {
    const choice = el.dataset.choice;
    if (choice === 'continue_admin' && !confirm(t('bench.choice.continueAdminConfirm') || 'Continue as device administrator?')) return;
    if (choice === 'confirm_admin' && !confirm(t('bench.choice.confirmAdminConfirm') || 'Android 15+: Knox is restricted for an administrator. Continue anyway?')) return;
    act(() => api('/api/cards/' + enc + '/run', { method: 'POST', body: { choice } }));
  }
  if (action === 'abandon') {
    if (!confirm(t('bench.cards.abandonConfirm') || 'Abandon this provisioning?')) return;
    const c = cards.find((x) => x.serial === serial);
    const release = !!(c && c.ownerSetHere) && confirm(t('bench.cards.releaseConfirm') || 'Give the device back (remove the owner set by this station)?');
    act(() => api('/api/cards/' + enc + '/abandon', { method: 'POST', body: { release } }));
  }
  if (action === 'close') act(() => api('/api/cards/' + enc + '/close', { method: 'POST', body: {} }));
  if (action === 'export') act(async () => { const r = await api('/api/cards/' + enc + '/export', { method: 'POST', body: {} }); if (r.ok) toast((t('bench.cards.exported') || 'Exported to') + ' ' + r.body.path); return r; });
});
document.addEventListener('change', (ev) => {
  const sel = ev.target.closest('[data-field=target]');
  if (!sel) return;
  const card = sel.closest('[data-serial]');
  const tg = targets.find((x) => x.tenantId + ':' + x.groupId === sel.value);
  const name = card.querySelector('[data-field=name]');
  if (tg && name && !name.value && tg.namePrefix) name.placeholder = tg.namePrefix + '…';
});

try {
  const es = new EventSource('/api/events?t=' + encodeURIComponent(TOKEN));
  es.addEventListener('change', () => load());
} catch (e) { /* the heartbeat keeps the window known */ }
setInterval(() => { api('/api/heartbeat', { method: 'POST' }); }, 5000);
setInterval(load, 15000);
load();
</script>
</body>
</html>`;
}
