// Ethernet Packet Lab — web dashboard (app.js)
// Works with EthernetPacketGenerator WPF backend on port 8080.

const $ = (id) => document.getElementById(id);

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  interfaces: [],          // [{name, mac, state, ipv4}]
  selectedSenderIfaces: [], // [ifaceName]
  autoPolling: null,        // setInterval handle
  lastAutoTest: '',
};

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(message, kind = '', timeoutMs = 4500) {
  const tray = $('toastTray');
  if (!tray) return;
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  const icon = kind === 'ok' ? '✓' : kind === 'warn' ? '⚠' : kind === 'fail' ? '✕' : 'ⓘ';
  el.innerHTML = `<span class="icon">${icon}</span><span class="body"></span><button class="close" aria-label="Dismiss">×</button>`;
  el.querySelector('.body').textContent = message;
  el.querySelector('.close').addEventListener('click', dismiss);
  tray.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  let t = setTimeout(dismiss, timeoutMs);
  function dismiss() {
    clearTimeout(t);
    el.classList.remove('show');
    setTimeout(() => el.remove(), 240);
  }
}

function setStatus(msg, isError = false) {
  const el = $('status');
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('error', isError);
}

// ── API helper ────────────────────────────────────────────────────────────────
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) }
  });
  const data = await res.json();
  if (!res.ok || data.ok === false)
    throw new Error(data.error || 'request failed');
  return data;
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.modeTab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.modeTab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.roleView').forEach(v => v.classList.remove('active'));
      btn.classList.add('active');
      const view = btn.dataset.view;
      const section = $(view);
      if (section) section.classList.add('active');
    });
  });

  // Keyboard: 1/2/3/4
  document.addEventListener('keydown', e => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
    const map = { '1': 0, '2': 1, '3': 2, '4': 3 };
    if (map[e.key] !== undefined) {
      const tabs = document.querySelectorAll('.modeTab');
      if (tabs[map[e.key]]) tabs[map[e.key]].click();
    }
    if (e.key === '?') $('helpButton')?.click();
  });
}

// ── Interface loading ─────────────────────────────────────────────────────────
async function loadInterfaces() {
  try {
    const data = await api('/api/interfaces');
    state.interfaces = data.interfaces || [];
    renderSenderIfaceList();
    setStatus(`${state.interfaces.length} interfaces loaded`);
    $('interfaceInfo').textContent =
      `${state.interfaces.filter(i => i.state === 'up').length} up / ${state.interfaces.length} total`;
  } catch (err) {
    setStatus('Cannot reach server', true);
    toast('Cannot reach API server: ' + err.message, 'fail');
    $('senderIfaceList').textContent = '— server offline —';
  }
}

function renderSenderIfaceList() {
  const list = $('senderIfaceList');
  if (!list) return;
  list.innerHTML = '';
  if (state.interfaces.length === 0) {
    list.textContent = '— no interfaces —';
    return;
  }
  state.interfaces.forEach(iface => {
    const chip = document.createElement('button');
    chip.className = 'ifaceChip' + (iface.state !== 'up' ? ' ifaceDown' : '');
    const ip = iface.ipv4?.[0]?.local || '';
    chip.textContent = iface.name + (ip ? ` (${ip})` : '');
    chip.title = `MAC: ${iface.mac} · ${iface.state}`;
    chip.dataset.iface = iface.name;
    chip.addEventListener('click', () => {
      chip.classList.toggle('selected');
      updateSenderIfaceCount();
      updateFirstIface();
    });
    list.appendChild(chip);
  });
}

function updateSenderIfaceCount() {
  const selected = document.querySelectorAll('#senderIfaceList .ifaceChip.selected');
  state.selectedSenderIfaces = Array.from(selected).map(c => c.dataset.iface);
  const el = $('senderIfaceCount');
  if (el) el.textContent = `${state.selectedSenderIfaces.length} selected`;
}

function updateFirstIface() {
  // auto-fill source MAC from first selected interface
  if (state.selectedSenderIfaces.length === 0) return;
  const name = state.selectedSenderIfaces[0];
  const iface = state.interfaces.find(i => i.name === name);
  if (!iface) return;
  const srcMacEl = $('srcMac');
  if (srcMacEl && !srcMacEl.value) srcMacEl.value = iface.mac;
  const srcIpEl = $('srcIp');
  if (srcIpEl && !srcIpEl.value && iface.ipv4?.[0]?.local)
    srcIpEl.value = iface.ipv4[0].local;
}

// ── Template examples ─────────────────────────────────────────────────────────
const EXAMPLES = {
  udp: {
    protocol: 'udp',
    dstMac: 'ff:ff:ff:ff:ff:ff',
    srcIp: '192.168.1.1',
    dstIp: '192.168.1.255',
    srcPort: 12345,
    dstPort: 50000,
    payload: 'Hello KETI UDP',
  },
  icmp: {
    protocol: 'icmp',
    dstMac: 'ff:ff:ff:ff:ff:ff',
    srcIp: '192.168.1.1',
    dstIp: '192.168.1.2',
    payload: 'ICMP ping from KETI lab',
  },
  arp: {
    protocol: 'arp',
    dstMac: 'ff:ff:ff:ff:ff:ff',
    srcIp: '192.168.1.1',
    dstIp: '192.168.1.2',
    payload: '',
  },
};

function applyExample(name) {
  const ex = EXAMPLES[name];
  if (!ex) return;
  if (ex.protocol) $('protocol').value = ex.protocol;
  if (ex.dstMac !== undefined) $('dstMac').value = ex.dstMac;
  if (ex.srcIp !== undefined) $('srcIp').value = ex.srcIp;
  if (ex.dstIp !== undefined) $('dstIp').value = ex.dstIp;
  if (ex.srcPort !== undefined) $('srcPort').value = ex.srcPort;
  if (ex.dstPort !== undefined) $('dstPort').value = ex.dstPort;
  if (ex.payload !== undefined) $('payload').value = ex.payload;
}

// ── Build profile from form ───────────────────────────────────────────────────
function buildProfile() {
  const iface = state.selectedSenderIfaces[0] || null;
  const profile = {
    protocol:  $('protocol').value,
    dstMac:    $('dstMac').value.trim() || 'ff:ff:ff:ff:ff:ff',
    srcMac:    $('srcMac').value.trim() || null,
    srcIp:     $('srcIp').value.trim()  || '0.0.0.0',
    dstIp:     $('dstIp').value.trim()  || '255.255.255.255',
    srcPort:   parseInt($('srcPort').value) || 12345,
    dstPort:   parseInt($('dstPort').value) || 50000,
    count:     parseInt($('count').value)   || 1,
    intervalMs:parseFloat($('intervalMs').value) || 0,
    payload:   { mode: 'text', data: $('payload').value },
    interface: iface,
  };
  if ($('vlanEnabled').checked) {
    profile.vlan = {
      id:       parseInt($('vlanId').value) || 100,
      priority: parseInt($('vlanPriority').value) || 0,
    };
  }
  return profile;
}

function formatHexDump(hex) {
  if (!hex) return '—';
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2)
    bytes.push(hex.slice(i, i + 2));
  const lines = [];
  for (let row = 0; row < bytes.length; row += 16) {
    const chunk = bytes.slice(row, row + 16);
    const addr  = row.toString(16).padStart(4, '0');
    const hex16 = chunk.join(' ').padEnd(47, ' ');
    const ascii = chunk.map(b => {
      const c = parseInt(b, 16);
      return c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }).join('');
    lines.push(`${addr}  ${hex16}  ${ascii}`);
  }
  return lines.join('\n');
}

function formatDecoded(decoded) {
  if (!decoded) return '—';
  if (typeof decoded === 'string') return decoded;
  return JSON.stringify(decoded, null, 2);
}

// ── Sender ────────────────────────────────────────────────────────────────────
async function doBuild() {
  const profile = buildProfile();
  try {
    const data = await api('/api/build', {
      method: 'POST',
      body: JSON.stringify(profile)
    });
    const out = data.stdout || data;
    $('hexdump').textContent = formatHexDump(out.frameHex);
    $('decoded').textContent = formatDecoded(out.decoded);
    setStatus('Preview updated');
  } catch (err) {
    toast('Build error: ' + err.message, 'fail');
    setStatus('Build error', true);
  }
}

async function doSend() {
  if (state.selectedSenderIfaces.length === 0) {
    toast('Select an interface first', 'warn');
    return;
  }
  const profile = buildProfile();
  setStatus('Sending…');
  const sendBtn = $('send');
  sendBtn.disabled = true;
  try {
    const data = await api('/api/send', {
      method: 'POST',
      body: JSON.stringify(profile)
    });
    const out = data.stdout || data;
    const msg = `Sent ${out.framesSent ?? 1} frame(s), ${out.bytesSent ?? '?'} bytes`;
    setStatus(msg);
    toast(msg, 'ok');
    if (out.decoded) $('decoded').textContent = formatDecoded(out.decoded);
  } catch (err) {
    toast('Send error: ' + err.message, 'fail');
    setStatus('Send error', true);
  } finally {
    sendBtn.disabled = false;
  }
}

// ── Automation ────────────────────────────────────────────────────────────────
const TEST_IDS = {
  'tx-sanity':   { prog: 'progTxSanity',   status: 'statusTxSanity' },
  'fdb-test':    { prog: 'progFdbTest',     status: 'statusFdbTest' },
  'flood-check': { prog: 'progFloodCheck',  status: 'statusFloodCheck' },
};

function setProgress(progId, pct, label) {
  const track = $(progId);
  if (!track) return;
  const fill = track.querySelector('.progressFill');
  const lbl  = track.querySelector('.progressLabel');
  if (fill) fill.style.width = `${pct}%`;
  if (lbl)  lbl.textContent  = label || `${pct}%`;
}

function resetAutoUI() {
  Object.values(TEST_IDS).forEach(({ prog, status }) => {
    setProgress(prog, 0, '0%');
    const el = $(status);
    if (el) { el.textContent = 'idle'; el.className = 'actionStatus'; }
  });
  document.querySelectorAll('.autoRunBtn').forEach(b => b.disabled = false);
  const stopBtn = $('autoStopBtn');
  if (stopBtn) stopBtn.disabled = true;
  $('autoOverallStatus').textContent = 'idle';
}

async function runAutoTest(testName) {
  try {
    state.lastAutoTest = testName;
    document.querySelectorAll('.autoRunBtn').forEach(b => b.disabled = true);
    $('autoStopBtn').disabled = false;

    const ids = TEST_IDS[testName];
    if (ids) {
      setProgress(ids.prog, 10, 'starting…');
      $(ids.status).textContent = 'starting';
    }
    $('autoOverallStatus').textContent = 'running';

    await api('/api/auto/run', {
      method: 'POST',
      body: JSON.stringify({ test: testName })
    });

    startAutoPolling(testName);
  } catch (err) {
    toast('Could not start test: ' + err.message, 'fail');
    resetAutoUI();
  }
}

function startAutoPolling(testName) {
  if (state.autoPolling) clearInterval(state.autoPolling);
  state.autoPolling = setInterval(() => pollAutoStatus(testName), 800);
}

async function pollAutoStatus(testName) {
  try {
    const data = await api('/api/auto/status');
    const ids = TEST_IDS[testName];

    if (data.running) {
      if (ids) {
        setProgress(ids.prog, 50, 'running…');
        $(ids.status).textContent = data.statusText || 'running';
      }
      $('autoOverallStatus').textContent = data.statusText || 'running';
    } else {
      // Done
      clearInterval(state.autoPolling);
      state.autoPolling = null;

      const result = (data.result || '').toUpperCase();
      const pct    = result === 'PASS' ? 100 : result === 'FAIL' ? 100 : 0;
      const lbl    = result || 'done';

      if (ids) {
        setProgress(ids.prog, pct, lbl);
        const el = $(ids.status);
        if (el) {
          el.textContent = lbl;
          el.className   = 'actionStatus ' + (result === 'PASS' ? 'pass' : result === 'FAIL' ? 'fail' : '');
        }
      }

      $('autoOverallStatus').textContent = result || 'done';
      toast(`${testName}: ${lbl}${data.reason ? ' — ' + data.reason : ''}`,
            result === 'PASS' ? 'ok' : result === 'FAIL' ? 'fail' : '');

      document.querySelectorAll('.autoRunBtn').forEach(b => b.disabled = false);
      $('autoStopBtn').disabled = true;

      await loadAutoResults();
    }
  } catch (err) {
    // network hiccup — keep polling
  }
}

async function loadAutoResults() {
  try {
    const data = await api('/api/auto/results');
    const rows = data.rows || [];
    const tbody = $('autoResultRows');
    if (!tbody) return;

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty">No results yet</td></tr>';
      $('autoResultSummary').textContent = 'No results yet';
      return;
    }

    const pass = rows.filter(r => r.result === 'PASS').length;
    $('autoResultSummary').textContent = `${rows.length} steps · ${pass} PASS · ${rows.length - pass} FAIL`;

    tbody.innerHTML = rows.map(r => `
      <tr class="${r.result === 'PASS' ? 'rowPass' : r.result === 'FAIL' ? 'rowFail' : ''}">
        <td>${r.step}</td>
        <td>${r.testType || ''}</td>
        <td>${r.expectedMode || ''}</td>
        <td>${r.expectedPort ?? ''}</td>
        <td>${r.txMatch ?? ''}</td>
        <td>${r.port1Match ?? ''}</td>
        <td>${r.port2Match ?? ''}</td>
        <td>${r.port3Match ?? ''}</td>
        <td><strong style="color:${r.result === 'PASS' ? 'var(--accent)' : 'var(--danger, #e53e3e)'}">${r.result || ''}</strong></td>
        <td>${r.reason || ''}</td>
      </tr>
    `).join('');
  } catch (err) {
    // ignore
  }
}

// ── Help overlay ──────────────────────────────────────────────────────────────
function initHelp() {
  $('helpButton')?.addEventListener('click', () => {
    $('helpOverlay')?.classList.toggle('hidden');
  });
  $('helpClose')?.addEventListener('click', () => {
    $('helpOverlay')?.classList.add('hidden');
  });
  $('helpOverlay')?.addEventListener('click', e => {
    if (e.target === $('helpOverlay')) $('helpOverlay').classList.add('hidden');
  });
}

// ── Extra CSS for result rows (injected) ─────────────────────────────────────
function injectResultStyles() {
  const style = document.createElement('style');
  style.textContent = `
    .rowPass { background: rgba(16,185,129,0.06); }
    .rowFail { background: rgba(239,68,68,0.07); }
    .actionStatus.pass { color: #0f6f78; font-weight: 600; }
    .actionStatus.fail { color: #e53e3e; font-weight: 600; }
    .ifaceChip {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 3px 10px; border-radius: 14px;
      border: 1px solid var(--border, #c8d0d8);
      background: var(--panel, #fff);
      font-size: 12px; cursor: pointer; margin: 2px;
      transition: background .15s, border-color .15s;
    }
    .ifaceChip:hover { border-color: var(--accent, #0f6f78); }
    .ifaceChip.selected { background: var(--accent, #0f6f78); color: #fff; border-color: var(--accent, #0f6f78); }
    .ifaceChip.ifaceDown { opacity: 0.45; }
    .ifacePickerList { display: flex; flex-wrap: wrap; gap: 4px; padding: 4px 0; }
    .badge.wire { background: #dbeafe; color: #1d4ed8; }
    .badge.offline { background: #f3f4f6; color: #6b7280; }
  `;
  document.head.appendChild(style);
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  injectResultStyles();
  initTabs();
  initHelp();

  // Template buttons
  document.querySelectorAll('[data-example]').forEach(btn => {
    btn.addEventListener('click', () => applyExample(btn.dataset.example));
  });

  // Sender buttons
  $('build')?.addEventListener('click', doBuild);
  $('send')?.addEventListener('click', doSend);

  // Ctrl+Enter to send
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') doSend();
  });

  // Auto-build on field change
  ['protocol', 'dstMac', 'srcMac', 'srcIp', 'dstIp', 'srcPort', 'dstPort', 'payload', 'vlanEnabled', 'vlanId', 'vlanPriority'].forEach(id => {
    $(id)?.addEventListener('change', doBuild);
  });

  // Automation run buttons
  document.querySelectorAll('.autoRunBtn').forEach(btn => {
    btn.addEventListener('click', () => runAutoTest(btn.dataset.test));
  });

  // Refresh
  $('refreshInterfaces')?.addEventListener('click', loadInterfaces);

  // Load on start
  await loadInterfaces();

  // Health check
  try {
    await api('/api/health');
    setStatus('Server connected');
  } catch {
    setStatus('Server offline', true);
  }

  // Load any existing results
  await loadAutoResults();
}

init();
