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
  if (/format.string|command.inject|heap.overflow|sql.inject|ssrf|insecure.deser/.test(cls)) return 'critical';
  if (/buffer.overflow|use.after.free|double.free|path.traversal|xss/.test(cls))  return 'high';
  if (/integer.overflow|race.condition|null.deref|prototype.pollut|insecure.eval/.test(cls))  return 'medium';
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

function setStageSub(name, text) {
  const el = document.getElementById('stage-sub-' + name);
  if (el) el.textContent = text;
}

function updateMeshSub() {
  const files = [...state.files.values()];
  const hunting  = files.filter(f => f.status === 'hunting').length;
  const verified = files.filter(f => f.status === 'verified').length;
  const done     = files.filter(f => f.status === 'done').length;
  const total    = files.length;
  if (total === 0) return;
  setStageSub('agents', `${hunting} hunting · ${verified} verified · ${done} done`);
}

// ── Mesh Visualiser ────────────────────────────────────────
const _DIM_COLOR = {
  triage: '#94a3b8', surface: '#22d3ee', influence: '#a78bfa',
  reachability: '#f59e0b', synth: '#34d399',
};

class MeshViz {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx    = canvas.getContext('2d');
    this.nodes  = new Map();
    this.edges  = [];
    this._frame = null;
    this._ro = new ResizeObserver(() => this._resize());
    this._ro.observe(canvas.parentElement);
    this._resize();
    this._loop();
  }

  _resize() {
    const p = this.canvas.parentElement;
    this.canvas.width  = p.clientWidth  || 400;
    this.canvas.height = p.clientHeight || 300;
    const root = this.nodes.get('__root__');
    if (root) { root.x = this.canvas.width / 2; root.y = this.canvas.height / 2; }
  }

  _loop() {
    this._tick();
    this._render();
    this._frame = requestAnimationFrame(() => this._loop());
  }

  stop()  { if (this._frame) { cancelAnimationFrame(this._frame); this._frame = null; } }
  start() { if (!this._frame) this._loop(); }

  reset() {
    this.nodes.clear();
    this.edges = [];
    this._resize();
    this._addRoot();
  }

  _addRoot() {
    this.nodes.set('__root__', {
      id: '__root__', type: 'root', label: '◈',
      x: this.canvas.width / 2, y: this.canvas.height / 2,
      vx: 0, vy: 0, ax: 0, ay: 0,
      r: 20, status: 'idle', dim: 'root', pulse: 0, pinned: true,
    });
  }

  addAgent(agentId, path, dim) {
    const fileId = 'f:' + path;
    if (!this.nodes.has(fileId)) {
      const { width: W, height: H } = this.canvas;
      // Golden-angle placement so files spread naturally
      const angle = this.nodes.size * 2.399;
      const r = 95 + (this.nodes.size % 4) * 18;
      this.nodes.set(fileId, {
        id: fileId, type: 'file', label: path.split('/').pop(),
        x: W / 2 + r * Math.cos(angle), y: H / 2 + r * Math.sin(angle),
        vx: (Math.random() - .5) * 2, vy: (Math.random() - .5) * 2,
        ax: 0, ay: 0,
        r: 13, status: 'idle', dim: 'file', pulse: 0,
      });
      this.edges.push({ from: '__root__', to: fileId, type: 'trunk' });
    }

    if (!this.nodes.has(agentId)) {
      const fn    = this.nodes.get(fileId);
      const sibs  = this.edges.filter(e => e.from === fileId && e.type === 'branch').length;
      const angle = sibs * (Math.PI * 2 / 4) + 0.4;
      this.nodes.set(agentId, {
        id: agentId, type: 'agent', label: dim.slice(0, 4).toUpperCase(),
        x: fn.x + 58 * Math.cos(angle), y: fn.y + 58 * Math.sin(angle),
        vx: (Math.random() - .5), vy: (Math.random() - .5),
        ax: 0, ay: 0,
        r: 9, status: 'hunting', dim, pulse: 1,
      });
      this.edges.push({ from: fileId, to: agentId, type: 'branch' });

      // Cross-mesh edges between sibling agents of the same file
      for (const [, n] of this.nodes) {
        if (n.type === 'agent' && n.id !== agentId &&
            this.edges.some(e => e.from === fileId && e.to === n.id)) {
          this.edges.push({ from: agentId, to: n.id, type: 'mesh' });
        }
      }
    }
  }

  updateAgent(agentId, status) {
    const n = this.nodes.get(agentId);
    if (!n) return;
    n.status = status;
    if (status !== 'done') n.pulse = 1;
    if (status === 'verified') {
      const fe = this.edges.find(e => e.to === agentId && e.type === 'branch');
      if (fe) {
        const fn = this.nodes.get(fe.from);
        if (fn) fn.status = 'verified';
      }
    }
  }

  _tick() {
    const nodes = [...this.nodes.values()];
    if (nodes.length < 2) return;

    const K_REP   = 4000;
    const K_TRUNK = 0.07;  const L_TRUNK = 90;
    const K_BRNCH = 0.10;  const L_BRNCH = 55;
    const K_MESH  = 0.015; const L_MESH  = 72;
    const DAMP    = 0.84;

    nodes.forEach(n => { if (!n.pinned) { n.ax = 0; n.ay = 0; } });

    // Pairwise repulsion
    for (let i = 0; i < nodes.length; i++) {
      if (nodes[i].pinned) continue;
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x || .01, dy = b.y - a.y || .01;
        const d2 = dx * dx + dy * dy, d = Math.sqrt(d2);
        const f  = K_REP / d2;
        const nx = dx / d, ny = dy / d;
        a.ax -= f * nx; a.ay -= f * ny;
        if (!b.pinned) { b.ax += f * nx; b.ay += f * ny; }
      }
    }

    // Spring forces along edges
    for (const e of this.edges) {
      const a = this.nodes.get(e.from), b = this.nodes.get(e.to);
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d  = Math.sqrt(dx * dx + dy * dy) || 1;
      const K  = e.type === 'trunk' ? K_TRUNK : e.type === 'branch' ? K_BRNCH : K_MESH;
      const L  = e.type === 'trunk' ? L_TRUNK : e.type === 'branch' ? L_BRNCH : L_MESH;
      const f  = K * (d - L);
      const nx = dx / d, ny = dy / d;
      if (!a.pinned) { a.ax += f * nx; a.ay += f * ny; }
      if (!b.pinned) { b.ax -= f * nx; b.ay -= f * ny; }
    }

    // Weak gravity toward canvas center
    const cx = this.canvas.width / 2, cy = this.canvas.height / 2;
    nodes.forEach(n => {
      if (n.pinned) return;
      n.ax += (cx - n.x) * .003;
      n.ay += (cy - n.y) * .003;
    });

    // Euler integrate + boundary clamp
    const W = this.canvas.width, H = this.canvas.height;
    nodes.forEach(n => {
      if (n.pinned) return;
      n.vx = (n.vx + n.ax) * DAMP;
      n.vy = (n.vy + n.ay) * DAMP;
      n.x += n.vx; n.y += n.vy;
      const pad = n.r + 10;
      n.x = Math.max(pad, Math.min(W - pad, n.x));
      n.y = Math.max(pad, Math.min(H - pad, n.y));
    });

    nodes.forEach(n => { if (n.pulse > 0) n.pulse -= .016; });
  }

  _render() {
    const { ctx, canvas } = this;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    this._drawEdges();
    for (const type of ['file', 'agent', 'root']) {
      for (const n of this.nodes.values()) {
        if (n.type === type) this._drawNode(n);
      }
    }
  }

  _drawEdges() {
    const { ctx } = this;
    for (const e of this.edges) {
      const a = this.nodes.get(e.from), b = this.nodes.get(e.to);
      if (!a || !b) continue;
      const active = b.status === 'hunting';
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      if (e.type === 'mesh') {
        ctx.strokeStyle = 'rgba(37,41,69,0.55)';
        ctx.lineWidth   = 0.75;
      } else if (active) {
        ctx.strokeStyle = 'rgba(34,211,238,0.38)';
        ctx.lineWidth   = 1.2;
      } else {
        ctx.strokeStyle = 'rgba(37,41,69,0.80)';
        ctx.lineWidth   = 1;
      }
      ctx.stroke();
    }
  }

  _nodeColor(n) {
    if (n.status === 'verified') return '#10b981';
    if (n.status === 'error')    return '#f43f5e';
    if (n.type   === 'root')     return '#7c5cfc';
    if (n.type   === 'file')     return '#4f46e5';
    return _DIM_COLOR[n.dim] || '#6366f1';
  }

  _drawNode(n) {
    const { ctx } = this;
    const color      = this._nodeColor(n);
    const isDone     = n.status === 'done';
    const isHunting  = n.status === 'hunting';
    const isVerified = n.status === 'verified';
    const pulse      = Math.max(0, n.pulse);

    // Glow for active / newly changed nodes
    if ((isHunting || pulse > 0) && !isDone) {
      ctx.save();
      ctx.shadowBlur  = 14 + pulse * 22;
      ctx.shadowColor = color;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r * (1 + pulse * .55), 0, Math.PI * 2);
      ctx.fillStyle = color + '18';
      ctx.fill();
      ctx.restore();
    }

    // Outer ring for verified findings
    if (isVerified) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
      ctx.strokeStyle = color + '55';
      ctx.lineWidth   = 2;
      ctx.stroke();
    }

    // Node body
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    if (isDone) {
      ctx.fillStyle   = color + '28';
      ctx.strokeStyle = color + '30';
    } else {
      const g = ctx.createRadialGradient(
        n.x - n.r * .28, n.y - n.r * .28, 0,
        n.x, n.y, n.r,
      );
      g.addColorStop(0, color + 'f2');
      g.addColorStop(1, color + '9a');
      ctx.fillStyle   = g;
      ctx.strokeStyle = color + 'cc';
    }
    ctx.lineWidth = 1.5;
    ctx.fill();
    ctx.stroke();

    // Label inside node
    ctx.font          = `bold ${n.type === 'root' ? 13 : n.type === 'file' ? 8 : 7}px monospace`;
    ctx.fillStyle     = isDone ? color + '40' : '#ffffffcc';
    ctx.textAlign     = 'center';
    ctx.textBaseline  = 'middle';
    ctx.fillText(
      n.type === 'root' ? '◈' : n.type === 'file' ? n.label.slice(0, 6) : n.label,
      n.x, n.y,
    );

    // Filename below file node
    if (n.type === 'file' && !isDone) {
      ctx.font         = '7px monospace';
      ctx.fillStyle    = '#4a5270';
      ctx.textBaseline = 'top';
      ctx.fillText(n.label.slice(0, 14), n.x, n.y + n.r + 3);
    }
  }
}

// ── View toggle ─────────────────────────────────────────────
let _meshViz      = null;
let _currentView  = 'mesh';

function setView(view) {
  _currentView = view;
  const canvas = document.getElementById('mesh-canvas');
  const grid   = document.getElementById('agent-grid');
  const body   = document.getElementById('file-list');
  const btnM   = document.getElementById('btn-view-mesh');
  const btnC   = document.getElementById('btn-view-cards');
  if (view === 'mesh') {
    canvas.hidden = false;
    grid.hidden   = true;
    body.classList.add('mesh-view');
    btnM.classList.add('active');
    btnC.classList.remove('active');
    if (_meshViz) _meshViz.start();
  } else {
    canvas.hidden = true;
    grid.hidden   = false;
    body.classList.remove('mesh-view');
    btnM.classList.remove('active');
    btnC.classList.add('active');
    if (_meshViz) _meshViz.stop();
  }
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

function _agentLabel(status) {
  return { hunting: 'HUNTING', verified: 'FOUND', done: 'CLEAN', error: 'ERROR' }[status] || status.toUpperCase();
}

const _DIM_LABEL = {
  triage: 'TRIAGE', surface: 'SURFACE', influence: 'INFLUENCE',
  reachability: 'REACH', synth: 'SYNTH',
};

function renderAgentCard(file) {
  const grid = document.getElementById('agent-grid');
  const idx  = state.files.size;
  const dim  = file.dimension || 'triage';
  const el   = document.createElement('div');
  el.className = `agent-card ${file.status}`;
  el.id = `agent-${CSS.escape(file.agentId || file.path)}`;
  el.dataset.dim = dim;
  el.innerHTML = `
    <div class="agent-card-header">
      <span class="agent-id">AGENT #${idx}</span>
      <span class="agent-dim-badge">${_DIM_LABEL[dim] || dim.toUpperCase()}</span>
      <span class="agent-status-dot"></span>
    </div>
    <div class="agent-file" title="${file.path}">${shortPath(file.path)}</div>
    <div class="agent-card-footer">
      <span class="agent-score">${(file.score || 0).toFixed(3)}</span>
      <span class="agent-state-label">${_agentLabel(file.status)}</span>
    </div>`;
  const empty = document.getElementById('agent-grid')?.querySelector('.empty-state');
  if (empty) empty.remove();
  if (grid) grid.appendChild(el);
  return el;
}

function updateFileItem(file) {
  const cardId = `agent-${CSS.escape(file.agentId || file.path)}`;
  const existing = document.getElementById(cardId);
  if (existing) {
    existing.className = `agent-card ${file.status}`;
    const label = existing.querySelector('.agent-state-label');
    if (label) label.textContent = _agentLabel(file.status);
  } else {
    renderAgentCard(file);
  }
  els.fileCount.textContent = `${state.files.size} agents`;
}

function renderFinding(finding) {
  const sev = severityOf(finding.bug_class);
  const oracleStatus = finding.status || 'crashed';
  const statusBadge = oracleStatus === 'crashed'
    ? '<span class="oracle-badge crashed">CRASH</span>'
    : oracleStatus === 'skipped'
    ? '<span class="oracle-badge verified">VERIFIED</span>'
    : '<span class="oracle-badge compile-err">COMPILE ERR</span>';
  const cweTag = finding.cwe_id ? `<span class="finding-cwe">${finding.cwe_id}</span>` : '';
  const owaspTag = finding.owasp_category ? `<span class="finding-owasp">${finding.owasp_category}</span>` : '';
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-header">
      <span class="severity-badge sev-${sev}">${severityLabel(sev)}</span>
      ${statusBadge}
      <span class="finding-type">${finding.bug_class || 'unknown'}</span>
    </div>
    <div class="finding-path" title="${finding.path}">${shortPath(finding.path)}${finding.line_hint ? ':' + finding.line_hint : ''}</div>
    ${(cweTag || owaspTag) ? '<div class="finding-tags">' + cweTag + owaspTag + '</div>' : ''}
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
      if (data?.findings?.length) {
        state.findings = [];
        els.findings.innerHTML = '';
        data.findings.forEach(f => {
          state.findings.push(f);
          renderFinding(f);
        });
      }
      break;

    case 'scan_started':
      state.startedAt = Date.now();
      els.status.className = 'status-badge scanning';
      els.status.innerHTML = '<div class="status-dot"></div>SCANNING';
      if (data.target) els.target.textContent = shortPath(data.target);
      startTimer();
      setStageState('ingestion', 'active');
      setStageSub('ingestion', 'walking source tree…');
      addLog('SYSTEM', 'system', `Scan started → ${data.target || ''}`);
      if (_meshViz) _meshViz.reset();
      break;

    case 'ingestion_complete':
      setStageState('ingestion', 'done');
      setStageState('ranker', 'active');
      setStageSub('ranker', 'scoring by risk…');
      if (data.count === 0) {
        setStageSub('ingestion', '0 files — check language');
        addLog('WARN', 'error', 'No supported source files found — expected .c .cpp .py .js .ts .go .rs .php .rb .java');
      } else {
        setStageSub('ingestion', `${data.count} files found`);
        addLog('SYSTEM', 'system', `Ingested ${data.count} source files`);
      }
      break;

    case 'ranking_complete':
      setStageState('ranker', 'done');
      setStageState('agents', 'active');
      setStageSub('ranker', `${data.count} files ranked`);
      setStageSub('agents', `0 hunting · 0 verified · 0 done`);
      addLog('SYSTEM', 'system', `Ranked ${data.count} files · sending to agent mesh`);
      break;

    case 'file_started': {
      const agentId = data.agent_id || data.path;
      const dim = data.dimension || 'triage';
      const file = { path: data.path, score: data.score, status: 'hunting', dimension: dim, agentId };
      state.files.set(agentId, file);
      updateFileItem(file);
      updateMeshSub();
      if (_meshViz) _meshViz.addAgent(agentId, data.path, dim);
      addLog('HUNT', 'hunt', `[${(dim).toUpperCase()}] ${shortPath(data.path)}`);
      break;
    }

    case 'finding':
      addLog('FINDING', 'hunt', `${data.bug_class} — ${shortPath(data.path)}`);
      break;

    case 'verified': {
      const agentId = data.agent_id || data.path;
      const file = state.files.get(agentId) || state.files.get(data.path);
      if (file) { file.status = 'verified'; updateFileItem(file); }
      updateMeshSub();
      if (_meshViz) _meshViz.updateAgent(agentId, 'verified');
      setStageState('oracle', 'active');
      setStageSub('oracle', `verifying ${shortPath(data.path)}…`);
      addLog('VERIFY', 'verify', `✓ ${data.bug_class} in ${shortPath(data.path)}`);
      break;
    }

    case 'discarded': {
      const agentId = data.agent_id || data.path;
      const file = state.files.get(agentId) || state.files.get(data.path);
      if (file) { file.status = 'done'; updateFileItem(file); }
      updateMeshSub();
      if (_meshViz) _meshViz.updateAgent(agentId, 'done');
      const dimLabel = data.dimension ? `[${data.dimension.toUpperCase()}] ` : '';
      addLog('DISCARD', 'discard', `${dimLabel}${shortPath(data.path)} — ${data.reason || ''}`);
      break;
    }

    case 'oracle_result':
      setStageState('oracle', 'active');
      if (data.status === 'crashed' || data.status === 'skipped' || data.status === 'compile_error') {
        state.findings.push(data);
        renderFinding(data);
        setStageSub('oracle', `${state.findings.length} confirmed`);
        const statusLabel = data.status === 'crashed' ? 'CONFIRMED'
          : data.status === 'skipped' ? 'VERIFIED (no oracle)'
          : 'COMPILE_ERROR';
        addLog('ORACLE', 'confirm', `${statusLabel} ${data.bug_class} in ${shortPath(data.path)}`);
      } else {
        addLog('ORACLE', 'oracle', `${data.status} — ${shortPath(data.path)}`);
      }
      break;

    case 'scan_complete': {
      stopTimer();
      const confirmed = data.confirmed ?? 0;
      const total = state.files.size;
      setStageState('agents', 'done');
      updateMeshSub();
      setStageState('oracle', 'done');
      setStageSub('oracle', `${confirmed} confirmed`);
      setStageState('report', 'done');
      setStageSub('report', confirmed > 0 ? `${confirmed} finding(s) written` : 'no findings');
      els.status.className = 'status-badge complete';
      els.status.innerHTML = '<div class="status-dot"></div>COMPLETE';
      addLog('SYSTEM', 'confirm', `Scan complete — ${confirmed} confirmed finding(s) across ${total} file(s)`);
      break;
    }

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

// ── Scan modal ─────────────────────────────────────────────
function openScanModal() {
  document.getElementById('scan-modal').hidden = false;
  document.getElementById('scan-source').focus();
}

function closeScanModal() {
  document.getElementById('scan-modal').hidden = true;
  document.getElementById('scan-error').hidden = true;
  document.getElementById('scan-source').value = '';
  document.getElementById('scan-output').value = '';
  document.getElementById('scan-token').value = '';
}

document.getElementById('scan-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn    = document.getElementById('scan-btn');
  const source = document.getElementById('scan-source').value.trim();
  const output = document.getElementById('scan-output').value.trim();
  const token  = document.getElementById('scan-token').value.trim();
  const errEl  = document.getElementById('scan-error');

  errEl.hidden    = true;
  btn.disabled    = true;
  btn.textContent = 'Starting…';

  try {
    const resp = await fetch(BASE + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ source, ...(output && { output }), ...(token && { github_token: token }) }),
    });
    if (resp.ok) {
      closeScanModal();
    } else {
      const { detail } = await resp.json().catch(() => ({ detail: resp.statusText }));
      errEl.textContent = detail;
      errEl.hidden = false;
    }
  } catch {
    errEl.textContent = 'Cannot reach backend.';
    errEl.hidden = false;
  }

  btn.disabled    = false;
  btn.textContent = 'Start Analysis';
});

document.getElementById('scan-source').addEventListener('input', e => {
  const isUrl = /^https?:\/\/|^github\.com\//.test(e.target.value.trim());
  document.getElementById('token-field').hidden = !isUrl;
});

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
let _reconnectDelay = 3000;

function connect() {
  const qs = API_KEY ? '?token=' + encodeURIComponent(API_KEY) : '';
  const es = new EventSource(BASE + '/events' + qs);
  es.onopen = () => { _reconnectDelay = 3000; };
  es.onmessage = e => {
    try { onEvent(JSON.parse(e.data)); }
    catch (err) { console.warn('parse error', err, e.data); }
  };
  es.onerror = () => {
    es.close();
    const secs = Math.round(_reconnectDelay / 1000);
    addLog('SYSTEM', 'error', `Connection lost — reconnecting in ${secs}s…`);
    setTimeout(connect, _reconnectDelay);
    _reconnectDelay = Math.min(_reconnectDelay * 2, 30000);
  };
}

function start() {
  connect();
}

// ── Init ───────────────────────────────────────────────────
(async function init() {
  const canvas = document.getElementById('mesh-canvas');
  if (canvas) {
    _meshViz = new MeshViz(canvas);
    _meshViz.reset();  // seeds root node immediately
  }

  const grid = document.getElementById('agent-grid');
  if (grid) grid.innerHTML = `
    <div class="empty-state" style="grid-column:1/-1">
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
