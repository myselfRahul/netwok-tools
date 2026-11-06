'use strict';

const $ = (id) => document.getElementById(id);
let csrf = '';
let socket = null;
let currentJob = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const results = new Map();

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3500);
}
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (csrf && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function setAuthenticated(username, token) {
  csrf = token || '';
  $('loginView').hidden = true;
  $('appView').hidden = false;
  $('userLabel').textContent = username || '';
  connectSocket();
  loadHistory();
}
async function checkSession() {
  try {
    const session = await api('/api/session');
    if (session.authenticated) setAuthenticated(session.username, session.csrf);
  } catch { /* Login form remains visible. */ }
}
$('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('loginError').textContent = '';
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: $('username').value, password: $('password').value }) });
    $('password').value = '';
    setAuthenticated(data.username, data.csrf);
  } catch (err) { $('loginError').textContent = err.message; }
});
$('logoutBtn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST', body: '{}' }); } catch {}
  socket?.close();
  csrf = '';
  $('appView').hidden = true;
  $('loginView').hidden = false;
});
function connectSocket() {
  if (socket && [WebSocket.OPEN, WebSocket.CONNECTING].includes(socket.readyState)) return;
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${scheme}//${location.host}/ws`);
  socket.onopen = () => { reconnectDelay = 1000; $('connectionState').textContent = 'Live connection'; };
  socket.onclose = () => {
    $('connectionState').textContent = 'Disconnected — reconnecting';
    if (!document.hidden && !$('appView').hidden) {
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connectSocket, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 15000);
    }
  };
  socket.onerror = () => { $('connectionState').textContent = 'Connection error'; };
  socket.onmessage = (event) => {
    let message;
    try { message = JSON.parse(event.data); } catch { return toast('Received an invalid server message'); }
    handleMessage(message);
  };
}
function send(cmd, data) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return toast('Live connection is not available');
  socket.send(JSON.stringify({ cmd, data }));
}
function handleMessage(message) {
  const { type, payload } = message || {};
  if (type === 'error') return toast(payload?.message || 'Server error');
  if (type === 'job_started') {
    currentJob = payload.id;
    $('scanStatus').textContent = 'Running';
    $('startBtn').disabled = true;
    $('pauseBtn').disabled = false;
    $('resumeBtn').disabled = true;
    $('cancelBtn').disabled = false;
    $('resultsBody').replaceChildren();
    results.clear();
    updateProgress(0, payload.total);
    toast('Assessment started');
  }
  if (type === 'result') {
    results.set(payload.result.ip, payload.result);
    renderResults();
    updateMetricsFromResults();
  }
  if (type === 'progress') updateProgress(payload.completed, payload.total);
  if (type === 'paused') {
    $('scanStatus').textContent = 'Paused';
    $('pauseBtn').disabled = true;
    $('resumeBtn').disabled = false;
  }
  if (type === 'resumed') {
    $('scanStatus').textContent = 'Running';
    $('pauseBtn').disabled = false;
    $('resumeBtn').disabled = true;
  }
  if (type === 'cancelling') $('scanStatus').textContent = 'Cancelling…';
  if (type === 'job_done') {
    $('scanStatus').textContent = payload.status;
    $('startBtn').disabled = false;
    $('pauseBtn').disabled = true;
    $('resumeBtn').disabled = true;
    $('cancelBtn').disabled = true;
    loadHistory();
    toast(`Assessment ${payload.status.toLowerCase()}`);
  }
}
function updateProgress(done, total) {
  const percent = total ? Math.round(done / total * 100) : 0;
  $('progressBar').style.width = `${percent}%`;
  $('progressText').textContent = `${done} of ${total} assets assessed (${percent}%)`;
}
function cell(text, className) {
  const td = document.createElement('td');
  td.textContent = String(text ?? '');
  if (className) td.className = className;
  return td;
}
function renderResults() {
  const body = $('resultsBody');
  body.replaceChildren();
  if (!results.size) {
    const tr = document.createElement('tr');
    const td = cell('Waiting for results…', 'empty');
    td.colSpan = 4; tr.append(td); body.append(tr); return;
  }
  for (const result of results.values()) {
    const tr = document.createElement('tr');
    tr.append(cell(result.ip));
    const state = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `state ${result.reachable ? 'state-open' : 'state-closed'}`;
    badge.textContent = result.reachable ? 'OPEN SERVICE(S)' : 'NO OPEN PORTS';
    state.append(badge); tr.append(state);
    tr.append(cell(result.openPorts.map((p) => `${p.port}/${p.service}`).join(', ') || '—'));
    const findings = result.openPorts.flatMap((p) => p.findings || []);
    const indicator = document.createElement('td');
    indicator.textContent = findings.length ? findings.map((f) => f.title).join('; ') : 'No configured exposure indicator';
    if (findings.length) indicator.className = 'severity';
    tr.append(indicator);
    body.append(tr);
  }
}
function updateMetricsFromResults() {
  $('metricAssets').textContent = results.size;
  $('metricPorts').textContent = [...results.values()].reduce((sum, r) => sum + r.openPorts.length, 0);
}
$('startBtn').addEventListener('click', () => {
  const target = $('targetInput').value.trim();
  const raw = $('portInput').value.trim();
  const ports = raw.split(',').map((part) => part.trim());
  if (!target) return toast('Enter an authorized IPv4 target');
  if (!raw || ports.some((p) => !/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535)) return toast('Ports must be comma-separated integers from 1 to 65535');
  if (new Set(ports).size !== ports.length || ports.length > 32) return toast('Remove duplicate ports; maximum is 32');
  send('start', { target, ports: ports.map(Number), concurrency: Number($('concurrency').value) });
});
$('pauseBtn').addEventListener('click', () => currentJob && send('pause', { jobId: currentJob }));
$('resumeBtn').addEventListener('click', () => currentJob && send('resume', { jobId: currentJob }));
$('cancelBtn').addEventListener('click', () => currentJob && send('cancel', { jobId: currentJob }));
$('refreshHistory').addEventListener('click', loadHistory);

async function loadHistory() {
  try {
    const data = await api('/api/jobs');
    const body = $('historyBody');
    body.replaceChildren();
    let assets = 0, active = 0;
    for (const job of data.jobs) {
      assets += Number(job.completed || 0);
      if (['RUNNING','PAUSED','QUEUED','CANCELLING'].includes(job.status)) active++;
      const tr = document.createElement('tr');
      tr.append(cell(job.id.slice(0, 8)));
      tr.append(cell(job.target_input));
      tr.append(cell(job.status));
      tr.append(cell(`${job.completed}/${job.total}`));
      tr.append(cell(job.created_at));
      const td = document.createElement('td');
      const link = document.createElement('a');
      link.className = 'link'; link.href = `/api/jobs/${job.id}/csv`; link.textContent = 'CSV';
      td.append(link); tr.append(td); body.append(tr);
    }
    if (!data.jobs.length) {
      const tr = document.createElement('tr'); const td = cell('No assessment history.', 'empty'); td.colSpan = 6; tr.append(td); body.append(tr);
    }
    $('metricJobs').textContent = data.jobs.length;
    $('metricAssets').textContent = assets;
    $('metricActive').textContent = active;
  } catch (err) { toast(err.message); }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && !$('appView').hidden) connectSocket(); });
checkSession();
