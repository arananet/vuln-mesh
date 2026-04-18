'use strict';

// ── Config ─────────────────────────────────────────────────
const BASE = (window.APP_CONFIG?.backendUrl || '').replace(/\/$/, '');

// API key is never hard-coded or injected — it lives only in sessionStorage
// so it is cleared when the browser tab closes.
let API_KEY = '';

function authHeaders() {
  return API_KEY ? { Authorization: 'Bearer ' + API_KEY } : {};
}

// ── State ──────────────────────────────────────────────────
const state = {
  startedAt: null,
  files: new Map(),     // path → { path, score, status }
  findings: [],
  logEntries: [],
  stats: {},
  timerHandle: null,
};

// ── DOM refs ───────────────────────────────────────────────
const $ = id => document.getElementById(id);
const els = {
  status:    $('status-badge'),
  elapsed:   $('elapsed'),
  target:    $('target-path'),
  ingested:  $('stat-ingested'),
  ranked:    $('stat-ranked'),
  active:    $('stat-active'),
  rawFound:  $('stat-raw'),
  confirmed: $('stat-confirmed'),
  fileList:  $('file-list'),
  fileCount: $('file-count'),
  findings:  $('findings-list'),
  findCount: $('find-count'),
  logBody:   $('log-body'),
  stages: {
    ingestion: $('stage-ingestion'),
    ranker:    $('stage-ranker'),
    agents:    $('stage-agents'),
    oracle:    $('stage-oracle'),
    report:    $('stage-report'),
  },
};

// ── Helpers ────────────────────────────────────────────────
function fmtTime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  return [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
}

function shortPath(p) {
  const parts = p.replace(/\\/g, '/').split('/');
  if (parts.length <= 3) return p;
  return '…/' + parts.slice(-3).join('/');
}

function severityOf(bugClass) {
  const cls = (bugClass || '').toLowerCase();
  if (/format.string|command.inject|heap.overflow/.test(cls)) return 'critical';
  if (/buffer.overflow|use.after.free|double.free/.test(cls))  return 'high';
  if (/integer.overflow|race.condition|null.deref/.test(cls))  return 'medium';
  return 'low';
}

function severityLabel(sev) {
  return { critical: 'CRITICAL', high: 'HIGH', medium: 'MED', low: 'LOW' }[sev] || 'LOW';
}

function nowTs() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function setStageState(name, st) {  // st: '' | 'active' | 'done'
  const el = els.stages[name];
  if (!el) return;
  el.className = 'stage ' + st;
}

// ── Render functions ───────────────────────────────────────
function renderStats(stats) {
  els.ingested.textContent  = stats.files_ingested ?? 0;
  els.ranked.textContent    = stats.files_ranked   ?? 0;
  els.active.textContent    = stats.active_agents  ?? 0;
  els.rawFound.textContent  = stats.findings_raw   ?? 0;
  els.confirmed.textContent = stats.findings_confirmed ?? 0;
  if (stats.target) els.target.textContent = shortPath(stats.target);
}

function renderFileItem(file) {
  const el = document.createElement('div');
  el.className = `file-item ${file.status}`;
  el.id = `file-${CSS.escape(file.path)}`;
  el.innerHTML = `
    <div class="file-status-icon"></div>
    <div class="file-info">
      <div class="file-path" title="${file.path}">${shortPath(file.path)}</div>
      <div class="file-meta">
        <span class="file-score">score ${(file.score || 0).toFixed(3)}</span>
        <span class="file-state-label">${file.status}</span>
      </div>
    </div>`;
  return el;
}

function updateFileItem(file) {
  const existing = document.getElementById(`file-${CSS.escape(file.path)}`);
  if (existing) {
    existing.className = `file-item ${file.status}`;
    const label = existing.querySelector('.file-state-label');
    if (label) label.textContent = file.status;
  } else {
    const item = renderFileItem(file);
    if (els.fileList.firstChild) {
      els.fileList.insertBefore(item, els.fileList.firstChild);
    } else {
      els.fileList.appendChild(item);
    }
    // Remove empty state if present
    const empty = els.fileList.querySelector('.empty-state');
    if (empty) empty.remove();
  }
  els.fileCount.textContent = `${state.files.size} files`;
}

function renderFinding(finding) {
  const sev = severityOf(finding.bug_class);
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-header">
      <span class="severity-badge sev-${sev}">${severityLabel(sev)}</span>
      <span class="finding-type">${finding.bug_class || 'unknown'}</span>
    </div>
    <div class="finding-path" title="${finding.path}">${shortPath(finding.path)}${finding.line_hint ? ':' + finding.line_hint : ''}</div>
    <div class="finding-desc">${finding.description || ''}</div>`;

  if (els.findings.querySelector('.empty-state')) {
    els.findings.innerHTML = '';
  }
  els.findings.insertBefore(card, els.findings.firstChild);
  els.findCount.textContent = `${state.findings.length} confirmed`;
}

function addLog(tag, tagClass, msg) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-ts">${nowTs()}</span>
    <span class="log-tag ${tagClass}">${tag}</span>
    <span class="log-msg">${msg}</span>`;
  els.logBody.appendChild(entry);
  els.logBody.scrollTop = els.logBody.scrollHeight;
  // Cap log at 500 entries
  while (els.logBody.children.length > 500) {
    els.logBody.removeChild(els.logBody.firstChild);
  }
}

// ── Event handlers ─────────────────────────────────────────
function onEvent(evt) {
  const { type, data, stats } = evt;
  if (stats) renderStats(stats);

  switch (type) {
    case 'state':
      renderStats(stats || data?.stats || {});
      break;

    case 'scan_started':
      state.startedAt = Date.now();
      els.status.className = 'status-badge scanning';
      els.status.innerHTML = '<div class="status-dot"></div>SCANNING';
      if (data.target) els.target.textContent = shortPath(data.target);
      startTimer();
      setStageState('ingestion', 'active');
      addLog('SYSTEM', 'system', `Scan started → ${data.target || ''}`);
      break;

    case 'ingestion_complete':
      setStageState('ingestion', 'done');
      setStageState('ranker', 'active');
      addLog('SYSTEM', 'system', `Ingested ${data.count} C/C++ files`);
      break;

    case 'ranking_complete':
      setStageState('ranker', 'done');
      setStageState('agents', 'active');
      addLog('SYSTEM', 'system', `Ranked ${data.count} files for analysis`);
      break;

    case 'file_started': {
      const file = { path: data.path, score: data.score, status: 'hunting' };
      state.files.set(data.path, file);
      updateFileItem(file);
      addLog('HUNT', 'hunt', shortPath(data.path));
      break;
    }

    case 'finding':
      addLog('FINDING', 'hunt', `${data.bug_class} — ${shortPath(data.path)}`);
      break;

    case 'verified': {
      const file = state.files.get(data.path);
      if (file) { file.status = 'verified'; updateFileItem(file); }
      addLog('VERIFY', 'verify', `✓ ${data.bug_class} in ${shortPath(data.path)}`);
      break;
    }

    case 'discarded': {
      const file = state.files.get(data.path);
      if (file) { file.status = 'done'; updateFileItem(file); }
      addLog('DISCARD', 'discard', `${shortPath(data.path)} — ${data.reason || ''}`);
      break;
    }

    case 'oracle_result':
      setStageState('oracle', 'active');
      if (data.status === 'crashed') {
        state.findings.push(data);
        renderFinding(data);
        addLog('ORACLE', 'confirm', `CONFIRMED ${data.bug_class} in ${shortPath(data.path)}`);
      } else {
        addLog('ORACLE', 'oracle', `${data.status} — ${shortPath(data.path)}`);
      }
      break;

    case 'scan_complete':
      stopTimer();
      setStageState('agents', 'done');
      setStageState('oracle', 'done');
      setStageState('report', 'done');
      els.status.className = 'status-badge complete';
      els.status.innerHTML = '<div class="status-dot"></div>COMPLETE';
      addLog('SYSTEM', 'confirm', `Scan complete — ${data.confirmed} confirmed finding(s)`);
      break;

    case 'error':
      addLog('ERROR', 'error', data.message || JSON.stringify(data));
      break;
  }
}

// ── Timer ──────────────────────────────────────────────────
function startTimer() {
  if (state.timerHandle) return;
  state.timerHandle = setInterval(() => {
    if (!state.startedAt) return;
    els.elapsed.textContent = fmtTime((Date.now() - state.startedAt) / 1000);
  }, 1000);
}

function stopTimer() {
  if (state.timerHandle) clearInterval(state.timerHandle);
}

// ── History drawer ─────────────────────────────────────────
function toggleHistory() {
  const drawer = document.getElementById('history-drawer');
  const open = drawer.classList.toggle('open');
  if (open) loadHistory();
}

async function loadHistory() {
  const list = document.getElementById('history-list');
  try {
    const resp = await fetch(BASE + '/api/scans', { headers: authHeaders() });
    if (!resp.ok) { list.innerHTML = '<div class="empty-state"><div>Failed to load history</div></div>'; return; }
    const scans = await resp.json();
    if (!scans.length) {
      list.innerHTML = '<div class="empty-state"><div class="empty-icon">◎</div><div>No past scans found</div></div>';
      return;
    }
    list.innerHTML = '';
    scans.forEach(scan => {
      const item = document.createElement('div');
      item.className = 'scan-item';
      const started = scan.started_at ? new Date(scan.started_at).toLocaleString() : '—';
      item.innerHTML = `
        <div class="scan-item-id">${scan.id}</div>
        <div class="scan-item-target">${scan.target || '—'}</div>
        <div class="scan-item-meta">${started} · ${scan.status} · ${scan.findings_confirmed ?? 0} confirmed</div>`;
      list.appendChild(item);
    });
  } catch (e) {
    list.innerHTML = '<div class="empty-state"><div>Error loading history</div></div>';
    console.warn('history fetch failed', e);
  }
}

// ── Login ───────────────────────────────────────────────────
function showLogin() {
  document.getElementById('login-overlay').hidden = false;
  document.getElementById('login-key').focus();
}

function hideLogin() {
  document.getElementById('login-overlay').hidden = true;
}

function setLoginError(msg) {
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.hidden = !msg;
}

async function validateToken(token) {
  try {
    const resp = await fetch(BASE + '/api/scans', {
      headers: { Authorization: 'Bearer ' + token },
    });
    return resp.status !== 401;
  } catch {
    return true;
  }
}

document.getElementById('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn      = document.getElementById('login-btn');
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;

  setLoginError('');
  btn.disabled    = true;
  btn.textContent = 'Connecting…';

  try {
    const resp = await fetch(BASE + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (resp.ok) {
      const { token } = await resp.json();
      API_KEY = token;
      sessionStorage.setItem('vm_api_key', token);
      hideLogin();
      start();
    } else {
      setLoginError('Invalid credentials — access denied.');
      document.getElementById('login-pass').value = '';
      document.getElementById('login-pass').focus();
    }
  } catch {
    setLoginError('Cannot reach backend. Check your connection.');
  }

  btn.disabled    = false;
  btn.textContent = 'Connect';
});

// ── SSE connection ─────────────────────────────────────────
function connect() {
  const qs = API_KEY ? '?token=' + encodeURIComponent(API_KEY) : '';
  const es = new EventSource(BASE + '/events' + qs);
  es.onmessage = e => {
    try { onEvent(JSON.parse(e.data)); }
    catch (err) { console.warn('parse error', err, e.data); }
  };
  es.onerror = () => {
    addLog('SYSTEM', 'error', 'Connection lost — reconnecting…');
    es.close();
    setTimeout(connect, 3000);
  };
}

function start() {
  connect();
}

// ── Init ───────────────────────────────────────────────────
(async function init() {
  els.fileList.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">◈</div>
      <div>Waiting for scan to start…</div>
    </div>`;
  els.findings.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">◎</div>
      <div>No confirmed findings yet</div>
    </div>`;

  // Probe the backend to determine auth state:
  //   200  → auth disabled (open mode) — connect directly
  //   401  → auth required — show login
  //   anything else (404, 502, network error) → backend not reachable or
  //           frontend served without backend (nginx-only deploy) — show login
  //           so the user gets clear feedback instead of a silent blank state
  let authRequired = true;
  try {
    const probe = await fetch(BASE + '/api/scans');
    if (probe.status === 200) authRequired = false;
  } catch { /* network error → leave authRequired = true */ }

  if (!authRequired) {
    start();
    return;
  }

  // Auth required — try a saved session token first
  const saved = sessionStorage.getItem('vm_api_key');
  if (saved && await validateToken(saved)) {
    API_KEY = saved;
    start();
  } else {
    sessionStorage.removeItem('vm_api_key');
    showLogin();
  }
})();
