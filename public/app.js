const $ = (id) => document.getElementById(id);

const state = {
  examples: {},
  exampleItems: [],
  interfaces: [],
  packets: [],
  report: null,
  nodes: {
    sender: null,
    receiver: null
  },
  peer: {
    url: localStorage.getItem('peerUrl') || '',
    interface: localStorage.getItem('peerInterface') || '',
    interfaces: [],
    iface: null
  },
  testCases: [],
  testProfiles: [],
  currentCase: {
    id: '',
    name: 'Untitled Test Case',
    description: '',
    steps: []
  },
  selectedStep: -1,
  localRole: localStorage.getItem('localRole') || 'sender',
  locked: localStorage.getItem('autoLock') !== '0'
};

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function slugify(value) {
  return String(value || 'test-case')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9가-힣_-]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || `test-case-${Date.now()}`;
}

function setStatus(message, isError = false) {
  $('status').textContent = message;
  $('status').classList.toggle('error', isError);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) }
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || data.stderr || 'request failed');
  }
  return data;
}

function payloadData(profile) {
  const payload = profile.payload || {};
  if (typeof payload === 'string') return { mode: 'text', data: payload };
  return payload;
}

function setProfile(profile) {
  const payload = payloadData(profile);
  $('protocol').value = profile.protocol || 'udp';
  if (!state.locked) {
    $('dstMac').value = profile.dstMac || '';
    $('srcMac').value = profile.srcMac || '';
    $('srcIp').value = profile.ipv4?.src || profile.arp?.senderIp || '';
    $('dstIp').value = profile.ipv4?.dst || profile.arp?.targetIp || '';
  }
  $('srcPort').value = profile.udp?.srcPort || 40000;
  $('dstPort').value = profile.udp?.dstPort || 50000;
  $('payloadMode').value = payload.mode || 'text';
  $('payload').value = payload.data || payload.template || '';
  $('payloadSize').value = payload.size ?? '';
  $('payloadByte').value = payload.byte ?? '';
  $('targetFrameLength').value = profile.targetFrameLength ?? '';
  $('count').value = profile.count || 1;
  $('intervalMs').value = profile.intervalMs || 1000;
  $('vlanEnabled').checked = Boolean(profile.vlan?.enabled);
  $('vlanId').value = profile.vlan?.id ?? 10;
  $('vlanPriority').value = profile.vlan?.priority ?? 0;
  // Capture page is Wireshark-style "sniff all by default" - never auto-fill the
  // pre-decode filter inputs from the loaded profile. Otherwise loading the ARP
  // profile would silently lock captureEtherType=0x0806 and drop every UDP frame.
  $('profileDescription').textContent = profile.description || profile.name || '-';
}

function cidrFromInterface(iface) {
  const ipv4 = iface?.ipv4?.[0];
  if (!ipv4?.local || !ipv4?.prefixlen) return '';
  return `${ipv4.local}/${ipv4.prefixlen}`;
}

function currentPayload() {
  const mode = $('payloadMode').value;
  const payload = { mode };
  const text = $('payload').value;
  const size = $('payloadSize').value;
  const byte = $('payloadByte').value.trim();
  if (mode === 'sequence') {
    payload.template = text || 'KETI_TEST_SEQ_{seq:06d}';
    payload.start = 1;
  } else if (mode === 'hex') {
    payload.data = text;
  } else if (mode === 'counter' || mode === 'random') {
    payload.size = Number(size || 32);
  } else if (mode === 'repeat') {
    payload.byte = byte || '0x00';
    payload.size = Number(size || 32);
  } else {
    payload.data = text;
  }
  return payload;
}

function getProfile() {
  const protocol = $('protocol').value;
  const targetFrameLength = $('targetFrameLength').value;
  const profile = {
    interface: $('interfaceSelect').value,
    protocol,
    dstMac: $('dstMac').value.trim(),
    srcMac: $('srcMac').value.trim(),
    count: Number($('count').value || 1),
    intervalMs: Number($('intervalMs').value || 0),
    payload: currentPayload(),
    vlan: {
      enabled: $('vlanEnabled').checked,
      id: Number($('vlanId').value || 0),
      priority: Number($('vlanPriority').value || 0)
    }
  };
  if (targetFrameLength) profile.targetFrameLength = Number(targetFrameLength);
  if (protocol === 'udp') {
    profile.ipv4 = { src: $('srcIp').value.trim(), dst: $('dstIp').value.trim(), ttl: 64 };
    profile.udp = { srcPort: Number($('srcPort').value), dstPort: Number($('dstPort').value) };
  } else if (protocol === 'icmp') {
    profile.ipv4 = { src: $('srcIp').value.trim(), dst: $('dstIp').value.trim(), ttl: 64 };
    profile.icmp = { type: 8, code: 0, id: 8230, seq: 1 };
  } else if (protocol === 'arp') {
    profile.arp = {
      operation: 1,
      senderMac: $('srcMac').value.trim(),
      senderIp: $('srcIp').value.trim(),
      targetMac: '00:00:00:00:00:00',
      targetIp: $('dstIp').value.trim()
    };
  } else {
    profile.etherType = '0x88b5';
  }
  return profile;
}

function showResult(result) {
  const body = result.stdout || result;
  $('decoded').textContent = JSON.stringify(body.decoded || body, null, 2);
  $('hexdump').textContent = body.hexdump || '';
}

function protocolName(decoded) {
  if (decoded.arp) return 'ARP';
  if (decoded.icmp) return 'ICMP';
  if (decoded.udp) return 'UDP';
  if (decoded.ipv4) return `IPv4/${decoded.ipv4.protocol}`;
  return decoded.ethernet?.etherType || 'Ethernet';
}

function packetInfo(decoded) {
  if (decoded.arp) return `${decoded.arp.senderIp} is at ${decoded.arp.senderMac}`;
  if (decoded.udp) return `${decoded.udp.srcPort} -> ${decoded.udp.dstPort}`;
  if (decoded.icmp) return `type ${decoded.icmp.type}, seq ${decoded.icmp.seq}`;
  return decoded.ethernet?.etherType || '';
}

const capture = {
  packets: [],
  reader: null,
  abort: null,
  selectedIdx: -1,
  startedAtMs: 0,
  totalBytes: 0,
  lastWindow: { t: 0, count: 0, pps: 0 },
  filter: '',
  maxRows: 5000
};

function rowProtoClass(decoded) {
  if (decoded.arp) return 'proto-arp';
  if (decoded.icmp) return 'proto-icmp';
  if (decoded.udp) return 'proto-udp';
  if (decoded.ipv4?.protocol === 6) return 'proto-tcp';
  return '';
}

function frameMatchesFilter(packet, filter) {
  if (!filter) return true;
  const f = filter.trim().toLowerCase();
  if (!f) return true;
  const d = packet.decoded || {};
  // Tokens: udp / tcp / icmp / arp / vlan / ipv4
  if (f === 'udp') return Boolean(d.udp);
  if (f === 'tcp') return d.ipv4?.protocol === 6;
  if (f === 'icmp') return Boolean(d.icmp);
  if (f === 'arp') return Boolean(d.arp);
  if (f === 'vlan') return Boolean(d.vlan);
  if (f === 'ipv4') return Boolean(d.ipv4);
  if (f.startsWith('mac:')) {
    const m = f.slice(4).trim();
    return (d.ethernet?.srcMac || '').toLowerCase().includes(m)
      || (d.ethernet?.dstMac || '').toLowerCase().includes(m);
  }
  if (f.startsWith('ip:')) {
    const m = f.slice(3).trim();
    return (d.ipv4?.src || '').includes(m) || (d.ipv4?.dst || '').includes(m);
  }
  if (f.startsWith('port:')) {
    const m = Number(f.slice(5).trim());
    return d.udp?.srcPort === m || d.udp?.dstPort === m;
  }
  // default: substring match against the JSON
  return JSON.stringify(d).toLowerCase().includes(f);
}

function appendPacketRow(packet) {
  const tbody = $('packetRows');
  const empty = $('packetEmpty');
  if (empty) empty.classList.add('hidden');
  const decoded = packet.decoded || {};
  const src = decoded.ipv4?.src || decoded.arp?.senderIp || decoded.ethernet?.srcMac || '-';
  const dst = decoded.ipv4?.dst || decoded.arp?.targetIp || decoded.ethernet?.dstMac || '-';
  const t = packet.timestamp;
  const d = new Date(t * 1000);
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  const tStr = `${d.toLocaleTimeString('en-GB')}.${ms}`;
  const proto = protocolName(decoded);
  const idx = packet._idx;
  const tr = document.createElement('tr');
  tr.dataset.idx = String(idx);
  tr.className = rowProtoClass(decoded);
  tr.innerHTML = `<td class="colNum">${idx + 1}</td><td class="colTime">${tStr}</td><td>${src}</td><td>${dst}</td><td class="colProto">${proto}</td><td class="colLen">${packet.length}</td><td>${packetInfo(decoded)}</td>`;
  tr.addEventListener('click', () => selectPacket(idx));
  tbody.appendChild(tr);
  // cap rows in DOM
  while (tbody.children.length > capture.maxRows) tbody.removeChild(tbody.firstChild);
  if ($('captureFollow').checked) {
    const list = $('packetRows').parentElement.parentElement;
    list.scrollTop = list.scrollHeight;
  }
}

function selectPacket(idx) {
  capture.selectedIdx = idx;
  const pkt = capture.packets[idx];
  if (!pkt) return;
  $('captureDecoded').textContent = JSON.stringify(pkt.decoded, null, 2);
  $('captureHexdump').textContent = pkt.hexdump || '';
  document.querySelectorAll('#packetRows tr').forEach((r) => r.classList.toggle('selected', r.dataset.idx === String(idx)));
}

function refreshCaptureStats() {
  $('capStatPkts').textContent = capture.packets.filter((p) => frameMatchesFilter(p, capture.filter)).length || capture.packets.length;
  $('capStatBytes').textContent = humanBytes(capture.totalBytes);
  $('capStatPps').textContent = capture.lastWindow.pps.toFixed(0);
}

function humanBytes(b) {
  if (b < 1024) return `${b}`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

function clearCapture() {
  capture.packets = [];
  capture.totalBytes = 0;
  capture.selectedIdx = -1;
  capture.lastWindow = { t: 0, count: 0, pps: 0 };
  $('packetRows').innerHTML = '';
  $('captureDecoded').textContent = '';
  $('captureHexdump').textContent = '';
  $('packetEmpty')?.classList.remove('hidden');
  refreshCaptureStats();
}

async function startCaptureStream() {
  if (capture.reader) return;
  clearCapture();
  $('capStatState').textContent = 'capturing';
  $('capStatState').classList.add('running');
  $('captureStart').disabled = true;
  $('captureStop').disabled = false;
  capture.startedAtMs = performance.now();
  capture.lastWindow = { t: capture.startedAtMs, count: 0, pps: 0 };
  capture.filter = $('captureDisplayFilter').value.trim();
  // Pre-decode filters are manual only (collapsed advanced panel). Default = sniff all.
  const body = {
    interface: $('interfaceSelect').value,
    timeoutSec: 0,
    maxFrames: 0,
    srcMac: $('captureSrcMac')?.value.trim() || '',
    dstMac: $('captureDstMac')?.value.trim() || '',
    etherType: $('captureEtherType')?.value.trim() || ''
  };
  const ctrl = new AbortController();
  capture.abort = ctrl;
  let res;
  try {
    res = await fetch('/api/capture-stream', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
  } catch (err) {
    finishCaptureStream(`error: ${err.message}`);
    throw err;
  }
  if (!res.ok || !res.body) {
    finishCaptureStream(`error: HTTP ${res.status}`);
    return;
  }
  const reader = res.body.getReader();
  capture.reader = reader;
  const dec = new TextDecoder();
  let buf = '';
  const statTimer = setInterval(() => {
    const now = performance.now();
    const dt = (now - capture.lastWindow.t) / 1000;
    capture.lastWindow.pps = dt > 0 ? capture.lastWindow.count / dt : 0;
    capture.lastWindow.t = now;
    capture.lastWindow.count = 0;
    refreshCaptureStats();
  }, 1000);
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let ev;
        try { ev = JSON.parse(line); } catch { continue; }
        if (ev.type === 'frame') {
          ev._idx = capture.packets.length;
          capture.packets.push(ev);
          capture.totalBytes += ev.length;
          capture.lastWindow.count += 1;
          if (frameMatchesFilter(ev, capture.filter)) appendPacketRow(ev);
        } else if (ev.type === 'log') {
          setStatus(`agent: ${ev.stderr}`, true);
        }
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError') setStatus(err.message, true);
  } finally {
    clearInterval(statTimer);
    finishCaptureStream('stopped');
  }
}

function finishCaptureStream(label) {
  capture.reader = null;
  capture.abort = null;
  $('captureStart').disabled = false;
  $('captureStop').disabled = true;
  $('capStatState').classList.remove('running');
  $('capStatState').textContent = label || 'idle';
  refreshCaptureStats();
}

function stopCaptureStream() {
  try { capture.abort?.abort(); } catch {}
  try { capture.reader?.cancel(); } catch {}
}

function reapplyFilter() {
  capture.filter = $('captureDisplayFilter').value.trim();
  $('packetRows').innerHTML = '';
  $('packetEmpty')?.classList.toggle('hidden', capture.packets.length > 0);
  for (const p of capture.packets) {
    if (frameMatchesFilter(p, capture.filter)) appendPacketRow(p);
  }
  refreshCaptureStats();
}

function renderPackets() {
  // legacy entry point kept for compatibility: reapplies filter on existing buffer
  reapplyFilter();
}

function protocolSummary(profile) {
  if (!profile) return '-';
  const parts = [];
  if (profile.vlan?.enabled) parts.push(`VLAN ${profile.vlan.id} PCP ${profile.vlan.priority}`);
  parts.push(String(profile.protocol || 'udp').toUpperCase());
  if (profile.udp) parts.push(`${profile.udp.srcPort || '-'}→${profile.udp.dstPort || '-'}`);
  return parts.join(' / ');
}

function payloadSummary(profile) {
  const payload = payloadData(profile || {});
  if (!payload) return '-';
  if (payload.mode === 'sequence') return payload.template || 'sequence';
  if (payload.mode === 'repeat') return `${payload.size || 0}B ${payload.byte || '0x00'}`;
  if (payload.mode === 'counter' || payload.mode === 'random' || payload.mode === 'benchmark') return `${payload.mode} ${payload.size || 0}B`;
  if (payload.mode === 'hex') return 'hex';
  return String(payload.data || '').slice(0, 38) || '-';
}

function syncCaseForm() {
  $('caseName').value = state.currentCase.name || '';
  $('caseDescription').value = state.currentCase.description || '';
}

function caseFromForm() {
  const name = $('caseName').value.trim() || 'Untitled Test Case';
  return {
    ...state.currentCase,
    id: state.currentCase.id || slugify(name),
    name,
    description: $('caseDescription').value.trim(),
    steps: state.currentCase.steps || []
  };
}

function renderCaseSelect() {
  if (!state.testCases.length) {
    $('caseSelect').innerHTML = '<option value="">No saved test cases</option>';
    return;
  }
  $('caseSelect').innerHTML = state.testCases.map((item) => (
    `<option value="${item.id}">${item.name} (${item.stepCount})</option>`
  )).join('');
  if (state.currentCase.id && state.testCases.find((item) => item.id === state.currentCase.id)) {
    $('caseSelect').value = state.currentCase.id;
  }
}

function renderProfileSuiteSelect() {
  if (!state.testProfiles.length) {
    $('profileSuiteSelect').innerHTML = '<option value="">No standard profiles</option>';
    return;
  }
  $('profileSuiteSelect').innerHTML = '<option value="">Load standard profile...</option>' + state.testProfiles.map((item) => (
    `<option value="${item.id}">${item.profileGroup} - ${item.name} (${item.stepCount})</option>`
  )).join('');
}

function renderCaseRows() {
  const steps = state.currentCase.steps || [];
  if (!steps.length) {
    $('caseRows').innerHTML = '<tr><td colspan="9" class="empty">No packet list rows yet</td></tr>';
    $('caseStepPreview').textContent = '';
    updateCaseEstimate();
    return;
  }
  $('caseRows').innerHTML = steps.map((step, index) => {
    const profile = step.profile || {};
    const selected = index === state.selectedStep ? ' class="selectedRow"' : '';
    if (step.kind === 'delay') {
      return `
        <tr data-step-index="${index}"${selected}>
          <td><input type="checkbox" data-step-check="${index}" ${step.checked !== false ? 'checked' : ''}></td>
          <td>${index}</td>
          <td class="eventName">${step.name || 'Delay'}</td>
          <td></td>
          <td></td>
          <td>DELAY</td>
          <td>${step.delayMs || 0} ms wait event</td>
          <td>-</td>
          <td><input class="miniInput" data-step-delay="${index}" type="number" min="0" value="${step.delayMs || 0}"> ms</td>
        </tr>
      `;
    }
    const src = profile.srcMac || profile.arp?.senderMac || '-';
    const dst = profile.dstMac || profile.arp?.targetMac || '-';
    return `
      <tr data-step-index="${index}"${selected}>
        <td><input type="checkbox" data-step-check="${index}" ${step.checked !== false ? 'checked' : ''}></td>
        <td>${index}</td>
        <td>${step.name || profile.name || 'Packet'}</td>
        <td><code>${src}</code></td>
        <td><code>${dst}</code></td>
        <td>${protocolSummary(profile)}</td>
        <td>${payloadSummary(profile)}</td>
        <td><input class="miniInput" data-step-count="${index}" type="number" min="1" value="${step.count || profile.count || 1}"></td>
        <td><input class="miniInput" data-step-interval="${index}" type="number" min="0" value="${step.intervalMs ?? profile.intervalMs ?? 0}"> ms</td>
      </tr>
    `;
  }).join('');

  document.querySelectorAll('[data-step-index]').forEach((row) => {
    row.addEventListener('click', () => {
      state.selectedStep = Number(row.dataset.stepIndex);
      $('caseStepPreview').textContent = JSON.stringify(state.currentCase.steps[state.selectedStep], null, 2);
      renderCaseRows();
    });
  });
  document.querySelectorAll('[data-step-check]').forEach((input) => {
    input.addEventListener('click', (event) => event.stopPropagation());
    input.addEventListener('change', () => {
      state.currentCase.steps[Number(input.dataset.stepCheck)].checked = input.checked;
    });
  });
  document.querySelectorAll('[data-step-count]').forEach((input) => {
    input.addEventListener('change', () => {
      state.currentCase.steps[Number(input.dataset.stepCount)].count = Math.max(1, Number(input.value || 1));
      updateCaseEstimate();
    });
  });
  document.querySelectorAll('[data-step-interval]').forEach((input) => {
    input.addEventListener('change', () => {
      state.currentCase.steps[Number(input.dataset.stepInterval)].intervalMs = Math.max(0, Number(input.value || 0));
      updateCaseEstimate();
    });
  });
  document.querySelectorAll('[data-step-delay]').forEach((input) => {
    input.addEventListener('change', () => {
      const step = state.currentCase.steps[Number(input.dataset.stepDelay)];
      step.delayMs = Math.max(0, Number(input.value || 0));
      step.name = `Delay ${step.delayMs} ms`;
      renderCaseRows();
    });
  });

  if (state.selectedStep >= 0 && state.currentCase.steps[state.selectedStep]) {
    $('caseStepPreview').textContent = JSON.stringify(state.currentCase.steps[state.selectedStep], null, 2);
  }
  updateCaseEstimate();
}

function setCurrentCase(testCase) {
  state.currentCase = cloneJson(testCase || {
    id: '',
    name: 'Untitled Test Case',
    description: '',
    steps: []
  });
  state.selectedStep = -1;
  syncCaseForm();
  renderCaseSelect();
  renderCaseRows();
}

async function loadTestCases() {
  const result = await api('/api/test-cases');
  state.testCases = result.items || [];
  renderCaseSelect();
  if (state.testCases.length && !state.currentCase.steps.length) {
    setCurrentCase(state.testCases[0].testCase);
  } else {
    renderCaseRows();
  }
}

async function loadTestProfiles() {
  try {
    const result = await api('/api/test-profiles');
    state.testProfiles = result.items || [];
  } catch (err) {
    state.testProfiles = [];
    console.warn('test-profiles unavailable:', err.message);
  }
  renderProfileSuiteSelect();
}

function addCurrentPacketToCase() {
  const profile = getProfile();
  const selected = state.exampleItems.find((entry) => entry.key === $('profileSelect').value);
  const insertAt = state.selectedStep >= 0 ? state.selectedStep + 1 : state.currentCase.steps.length;
  state.currentCase.steps.splice(insertAt, 0, {
    kind: 'packet',
    name: selected?.name || profile.name || `${String(profile.protocol || 'udp').toUpperCase()} packet`,
    enabled: true,
    checked: true,
    count: Number($('count').value || profile.count || 1),
    intervalMs: Number($('intervalMs').value || profile.intervalMs || 0),
    profile
  });
  state.selectedStep = insertAt;
  renderCaseRows();
}

function addDelayToCase() {
  const delayMs = Math.max(0, Number($('caseDelayMs').value || 100));
  const insertAt = state.selectedStep >= 0 ? state.selectedStep + 1 : state.currentCase.steps.length;
  state.currentCase.steps.splice(insertAt, 0, { kind: 'delay', name: `Delay ${delayMs} ms`, delayMs, checked: true });
  state.selectedStep = insertAt;
  renderCaseRows();
}

function selectedStep() {
  return state.selectedStep >= 0 ? state.currentCase.steps[state.selectedStep] : null;
}

function loadSelectedStep() {
  const step = selectedStep();
  if (step?.profile) setProfile(step.profile);
}

function duplicateSelectedStep() {
  const step = selectedStep();
  if (!step) return;
  const insertAt = state.selectedStep + 1;
  state.currentCase.steps.splice(insertAt, 0, cloneJson(step));
  state.selectedStep = insertAt;
  renderCaseRows();
}

function removeSelectedStep() {
  if (state.selectedStep < 0) return;
  state.currentCase.steps.splice(state.selectedStep, 1);
  state.selectedStep = Math.min(state.selectedStep, state.currentCase.steps.length - 1);
  renderCaseRows();
}

function moveSelectedStep(delta) {
  const index = state.selectedStep;
  const next = index + delta;
  if (index < 0 || next < 0 || next >= state.currentCase.steps.length) return;
  const tmp = state.currentCase.steps[next];
  state.currentCase.steps[next] = state.currentCase.steps[index];
  state.currentCase.steps[index] = tmp;
  state.selectedStep = next;
  renderCaseRows();
}

function estimatedWireMsForProfile(profile) {
  const len = Number(profile?.targetFrameLength || 64);
  return ((8 + Math.max(64, len) + 4 + 12) * 8) / 1_000_000;
}

function updateCaseEstimate() {
  const steps = state.currentCase.steps || [];
  let totalMs = 0;
  let packets = 0;
  for (const step of steps) {
    if (step.kind === 'delay') totalMs += Number(step.delayMs || 0);
    else {
      const count = Number(step.count || step.profile?.count || 1);
      totalMs += count * estimatedWireMsForProfile(step.profile);
      totalMs += Math.max(0, count - 1) * Number(step.intervalMs ?? step.profile?.intervalMs ?? 0);
      packets += count;
    }
  }
  const loops = $('caseRepeat')?.checked ? Math.max(1, Number($('caseLoopCount')?.value || 1)) : 1;
  const cycleMs = Math.max(0, Number($('caseCycleMs')?.value || 0));
  const repeatedMs = loops > 1 ? Math.max(totalMs, cycleMs) * loops : totalMs;
  if ($('caseEstimatedTime')) $('caseEstimatedTime').textContent = `${repeatedMs.toFixed(3)} ms`;
  if ($('caseSentPackets')) $('caseSentPackets').textContent = String(packets);
}

function caseForRun({ selectedOnly = false } = {}) {
  const testCase = caseFromForm();
  if (selectedOnly) {
    testCase.steps = testCase.steps.filter((step) => step.checked !== false);
  }
  return testCase;
}

async function saveCurrentCase() {
  const testCase = caseFromForm();
  const result = await api('/api/test-cases', { method: 'POST', body: JSON.stringify(testCase) });
  setCurrentCase(result.testCase);
  await loadTestCases();
  setStatus(`Saved test case: ${result.testCase.name}`);
}

async function deleteCurrentCase() {
  const id = state.currentCase.id || $('caseSelect').value;
  if (!id) return;
  if (!confirm(`Delete test case "${state.currentCase.name || id}"?`)) return;
  await api(`/api/test-cases/${encodeURIComponent(id)}`, { method: 'DELETE' });
  setCurrentCase({ id: '', name: 'Untitled Test Case', description: '', steps: [] });
  await loadTestCases();
  setStatus('Test case deleted');
}

async function runCurrentCase({ selectedOnly = false } = {}) {
  const started = new Date();
  $('caseStartTime').textContent = started.toLocaleTimeString();
  $('caseEndTime').textContent = '-';
  $('caseCycleStatus').textContent = 'running';
  setStatus(selectedOnly ? 'Sending selected packet list rows...' : 'Sending full packet list...');
  await ensurePeerReady();
  syncControlFromPeer();
  const testCase = caseForRun({ selectedOnly });
  const result = await api('/api/run-test-case', {
    method: 'POST',
    body: JSON.stringify({
      senderUrl: $('senderNodeUrl').value,
      receiverUrl: $('receiverNodeUrl').value,
      senderInterface: $('senderNodeInterface').value,
      receiverInterface: $('receiverNodeInterface').value,
      testCase,
      loopCount: $('caseRepeat').checked ? Number($('caseLoopCount').value || 1) : 1,
      cyclePeriodMs: Number($('caseCycleMs').value || 0)
    })
  });
  $('caseEndTime').textContent = new Date().toLocaleTimeString();
  $('caseCycleStatus').textContent = `${Date.now() - started.getTime()} ms`;
  $('caseSentPackets').textContent = String(result.report.summary.framesSent);
  $('caseSentBytes').textContent = String(result.report.steps.reduce((sum, step) => sum + ((step.framesSent || 0) * (step.txProfile?.targetFrameLength || 64)), 0));
  $('caseRunSummary').textContent = JSON.stringify(result.report.summary, null, 2);
  $('reportSummary').innerHTML = `
    <div><span>Status</span><strong>${result.report.ok ? 'PASS' : 'FAIL'}</strong></div>
    <div><span>Sent</span><strong>${result.report.summary.framesSent}</strong></div>
    <div><span>Matched</span><strong>${result.report.summary.matched}</strong></div>
  `;
  $('reportRows').innerHTML = result.report.steps.map((step, index) => `
    <tr>
      <td>${index + 1}</td>
      <td>Case</td>
      <td>${step.name}</td>
      <td class="${step.ok ? 'passText' : 'failText'}">${step.ok ? 'PASS' : 'FAIL'}</td>
      <td>${step.framesSent ?? '-'}</td>
      <td>${step.kind}</td>
      <td>${step.kind === 'delay' ? `${step.delayMs} ms` : `${step.matchCount || 0} match`}</td>
    </tr>
  `).join('');
  $('openCaseReport').classList.remove('disabled');
  setStatus(`Test case ${result.report.ok ? 'PASS' : 'FAIL'}: ${result.report.summary.matched} match(es)`, !result.report.ok);
}

async function loadInterfaces() {
  setStatus('Loading interfaces...');
  const result = await api('/api/interfaces');
  state.interfaces = (result.stdout.interfaces || []).sort((a, b) => {
    const score = (iface) => {
      if (iface.name === 'lo') return 20;
      if (iface.name.startsWith('docker')) return 15;
      return iface.state === 'up' ? 0 : 10;
    };
    return score(a) - score(b) || a.name.localeCompare(b.name);
  });
  $('interfaceSelect').innerHTML = state.interfaces
    .map((iface) => `<option value="${iface.name}">${iface.name} (${iface.state})</option>`)
    .join('');
  updateInterfaceInfo();
  setStatus(`${state.interfaces.length} interfaces loaded`);
}

function updateInterfaceInfo() {
  const selected = state.interfaces.find((iface) => iface.name === $('interfaceSelect').value);
  if (!selected) {
    $('interfaceInfo').textContent = '';
    $('selectedInterfaceName').textContent = '-';
    $('selectedInterfaceMac').textContent = '-';
    return;
  }
  const v4 = firstV4(selected);
  const cidr = v4 && selected.ipv4[0]?.prefixlen ? `${v4}/${selected.ipv4[0].prefixlen}` : v4;
  $('interfaceInfo').textContent = `MAC ${selected.mac} / MTU ${selected.mtu} / ${selected.state}${cidr ? ` / ${cidr}` : ''}`;
  $('selectedInterfaceName').textContent = selected.name;
  $('selectedInterfaceMac').textContent = `${selected.mac}${cidr ? ` / ${cidr}` : ''}`;
  if (selected.state !== 'up' && selected.name !== 'lo') setStatus(`${selected.name} is ${selected.state}`, true);
  if (state.locked) {
    $('srcMac').value = selected.mac;
    if (v4) $('srcIp').value = v4;
  } else {
    if (!$('srcMac').value || $('srcMac').value === '02:00:00:00:00:01') $('srcMac').value = selected.mac;
    if (v4 && (!$('srcIp').value || $('srcIp').value === '192.168.100.10')) $('srcIp').value = v4;
  }
}

function renderProfileSelect() {
  $('profileSelect').innerHTML = state.exampleItems.map((item) => (
    `<option value="${item.key}">${item.priority}. ${item.category} - ${item.name}</option>`
  )).join('');
}

async function loadExamples() {
  const data = await api('/api/examples');
  state.examples = data.profiles;
  state.exampleItems = data.items || Object.entries(data.profiles).map(([key, profile]) => ({ key, profile, name: profile.name || key, category: 'General', priority: 99 }));
  renderProfileSelect();
  const first = state.exampleItems[0];
  if (first) {
    $('profileSelect').value = first.key;
    setProfile(first.profile);
  }
}

async function build() {
  setStatus('Preparing frame preview...');
  const result = await api('/api/build', { method: 'POST', body: JSON.stringify(getProfile()) });
  showResult(result);
  setStatus(`Preview ready: ${result.stdout.decoded.length} bytes`);
}

async function send() {
  setStatus('Sending packet...');
  const result = await api('/api/send', { method: 'POST', body: JSON.stringify(getProfile()) });
  showResult(result);
  setStatus(`Sent ${result.stdout.framesSent} frame(s), ${result.stdout.bytesSent} bytes`);
}

// `capture()` legacy function removed; use startCaptureStream / stopCaptureStream.

function renderReport(report) {
  state.report = report;
  $('reportSummary').innerHTML = `
    <div><span>Total</span><strong>${report.summary.total}</strong></div>
    <div><span>Pass</span><strong>${report.summary.pass}</strong></div>
    <div><span>Fail</span><strong>${report.summary.fail}</strong></div>
  `;
  $('reportRows').innerHTML = report.results.map((item) => `
    <tr>
      <td>${item.priority}</td>
      <td>${item.category}</td>
      <td>${item.name}</td>
      <td class="${item.ok ? 'passText' : 'failText'}">${item.ok ? 'PASS' : 'FAIL'}</td>
      <td>${item.length ?? '-'}</td>
      <td>${item.protocol || '-'}</td>
      <td>${item.error || item.info || ''}</td>
    </tr>
  `).join('');
  $('openReport')?.classList.remove('disabled');
  $('openReportJson')?.classList.remove('disabled');
}

function renderInterfaceOptions(selectId, interfaces) {
  $(selectId).innerHTML = interfaces.map((iface) => {
    const ip = iface.ipv4?.[0]?.local || '';
    return `<option value="${iface.name}">${iface.name} (${iface.state})${ip ? ` - ${ip}` : ''}</option>`;
  }).join('');
}

function renderNodeGrid() {
  const sender = state.nodes.sender;
  const receiver = state.nodes.receiver;
  const senderIface = sender?.interfaces?.find((iface) => iface.name === $('senderNodeInterface').value);
  const receiverIface = receiver?.interfaces?.find((iface) => iface.name === $('receiverNodeInterface').value);
  $('nodeGrid').innerHTML = `
    <div>
      <span>Sender</span>
      <strong>${senderIface?.name || '-'}</strong>
      <small>${sender?.url || '-'} ${senderIface?.ipv4?.[0]?.local || ''}</small>
    </div>
    <div>
      <span>Receiver</span>
      <strong>${receiverIface?.name || '-'}</strong>
      <small>${receiver?.url || '-'} ${receiverIface?.ipv4?.[0]?.local || ''}</small>
    </div>
  `;
}

async function probeNode(url, role) {
  const result = await api('/api/probe-node', {
    method: 'POST',
    body: JSON.stringify({ url })
  });
  state.nodes[role] = { url: result.url, interfaces: result.interfaces };
  renderInterfaceOptions(role === 'sender' ? 'senderNodeInterface' : 'receiverNodeInterface', result.interfaces);
}

async function probeNodes() {
  setStatus('Probing remote nodes...');
  await Promise.all([
    probeNode($('senderNodeUrl').value, 'sender'),
    probeNode($('receiverNodeUrl').value, 'receiver')
  ]);
  renderNodeGrid();
  setStatus('Nodes ready');
}

function renderE2EReport(report) {
  $('reportSummary').innerHTML = `
    <div><span>Status</span><strong>${report.ok ? 'PASS' : 'FAIL'}</strong></div>
    <div><span>Captured</span><strong>${report.captureSummary.total}</strong></div>
    <div><span>Matched</span><strong>${report.matchCount}</strong></div>
  `;
  $('reportRows').innerHTML = report.capturedFrames.length
    ? report.capturedFrames.map((frame, index) => {
      const decoded = frame.decoded || {};
      return `
        <tr>
          <td>${index + 1}</td>
          <td>E2E</td>
          <td>${decoded.arp ? 'ARP' : decoded.icmp ? 'ICMP' : decoded.udp ? 'UDP' : decoded.ethernet?.etherType || '-'}</td>
          <td class="passText">MATCH</td>
          <td>${frame.length}</td>
          <td>${decoded.ethernet?.srcMac || '-'}</td>
          <td>${decoded.ipv4?.src || decoded.arp?.senderIp || ''} -> ${decoded.ipv4?.dst || decoded.arp?.targetIp || ''}</td>
        </tr>
      `;
    }).join('')
    : '<tr><td colspan="7" class="empty">No matching frames captured</td></tr>';
  $('openE2EReport')?.classList.remove('disabled');
  $('openE2EJson')?.classList.remove('disabled');
}

async function runE2E() {
  const prog = progressFor('progE2E');
  setActionStatus('statusE2E', 'running', 'running');
  prog.start(7);
  setStatus('Running end-to-end test...');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const senderUrl = $('senderNodeUrl').value;
    const receiverUrl = $('receiverNodeUrl').value;
    const senderIf = $('senderNodeInterface').value;
    const receiverIf = $('receiverNodeInterface').value;
    if (!senderUrl || !receiverUrl || !senderIf || !receiverIf) throw new Error('Missing pair (peer not set?)');
    const burst = Number($('e2eBurst').value || 5);
    const e2eInterval = Number($('e2eInterval').value || 200);
    const profile = { ...getProfile(), count: burst, intervalMs: e2eInterval };
    const result = await api('/api/e2e-test', {
      method: 'POST',
      body: JSON.stringify({
        senderUrl, receiverUrl,
        senderInterface: senderIf,
        receiverInterface: receiverIf,
        profile,
        timeoutSec: Math.max(5, Math.ceil((burst * e2eInterval) / 1000) + 3),
        maxFrames: Math.max(50, burst + 20)
      })
    });
    renderE2EReport(result.report);
    const txCount = result.report.sent?.framesSent ?? burst;
    setActionStatus('statusE2E', result.report.ok ? 'ok' : 'fail', `tx ${txCount} · rx ${result.report.matchCount}`);
    prog.finish();
    setStatus(`E2E ${result.report.ok ? 'PASS' : 'FAIL'}: ${result.report.matchCount} matching frame(s)`, !result.report.ok);
  } catch (err) {
    setActionStatus('statusE2E', 'fail', 'fail');
    prog.fail();
    throw err;
  }
}

async function runReport() {
  const prog = progressFor('progReport');
  setActionStatus('statusReport', 'running', 'running');
  prog.start(25);
  setStatus('Running on-wire standard validation...');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const result = await api('/api/wire-validation', {
      method: 'POST',
      body: JSON.stringify({
        senderUrl: $('senderNodeUrl').value,
        receiverUrl: $('receiverNodeUrl').value,
        senderInterface: $('senderNodeInterface').value,
        receiverInterface: $('receiverNodeInterface').value,
        count: 2,
        intervalMs: 100
      })
    });
    const fail = result.report.summary.failed;
    $('reportSummary').innerHTML = `
      <div><span>Status</span><strong>${result.report.ok ? 'PASS' : 'FAIL'}</strong></div>
      <div><span>Sent</span><strong>${result.report.summary.framesSent}</strong></div>
      <div><span>Matched</span><strong>${result.report.summary.matched}</strong></div>
    `;
    $('reportRows').innerHTML = result.report.steps.map((step, index) => `
      <tr>
        <td>${index + 1}</td>
        <td>Wire</td>
        <td>${step.name}</td>
        <td class="${step.ok ? 'passText' : 'failText'}">${step.ok ? 'PASS' : 'FAIL'}</td>
        <td>${step.framesSent ?? '-'}</td>
        <td>${step.protocol || step.kind}</td>
        <td>${step.kind === 'delay' ? `${step.delayMs} ms` : `${step.matchCount || 0} match`}</td>
      </tr>
    `).join('');
    $('openReport')?.classList.remove('disabled');
    $('openCaseReport')?.classList.remove('disabled');
    setActionStatus('statusReport', fail === 0 ? 'ok' : 'fail', `${result.report.summary.matched}/${result.report.summary.framesSent}`);
    prog.finish();
    setStatus(`Wire validation ${result.report.ok ? 'PASS' : 'FAIL'}: ${result.report.summary.matched}/${result.report.summary.framesSent} matched`, fail > 0);
  } catch (err) {
    setActionStatus('statusReport', 'fail', 'fail');
    prog.fail();
    throw err;
  }
}

document.querySelectorAll('[data-example]').forEach((button) => {
  button.addEventListener('click', () => {
    const item = state.exampleItems.find((entry) => entry.key.includes(button.dataset.example));
    if (item) {
      $('profileSelect').value = item.key;
      setProfile(item.profile);
    }
  });
});

$('profileSelect').addEventListener('change', () => {
  const item = state.exampleItems.find((entry) => entry.key === $('profileSelect').value);
  if (item) setProfile(item.profile);
});

document.querySelectorAll('[data-view]').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('[data-view]').forEach((item) => item.classList.remove('active'));
    document.querySelectorAll('.roleView').forEach((view) => view.classList.remove('active'));
    button.classList.add('active');
    $(button.dataset.view).classList.add('active');
    if (button.dataset.view === 'controlView') renderPairCard();
    document.body.classList.toggle('captureMode', button.dataset.view === 'captureView');
  });
});

$('refreshInterfaces').addEventListener('click', () => loadInterfaces().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('interfaceSelect').addEventListener('change', updateInterfaceInfo);
$('build').addEventListener('click', () => build().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('send').addEventListener('click', () => send().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('captureStart').addEventListener('click', () => startCaptureStream().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('captureStop').addEventListener('click', stopCaptureStream);
$('captureClear').addEventListener('click', clearCapture);
$('captureDisplayFilter').addEventListener('input', () => {
  // debounce
  clearTimeout(window._capFilterTimer);
  window._capFilterTimer = setTimeout(reapplyFilter, 120);
});
$('runReport').addEventListener('click', () => runReport().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('runE2E').addEventListener('click', () => runE2E().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));

async function ensurePeerReady() {
  if (!state.peer.url) throw new Error('Peer URL not set. Fill the Peer field in the top link strip.');
  if (!state.peer.interfaces.length) await probePeer();
  if (!state.peer.iface) throw new Error('Peer interface not selected.');
}

async function runBenchmark() {
  const prog = progressFor('progBench');
  const count = Number($('benchCount').value || 500);
  const intervalMs = Number($('benchInterval').value || 1);
  const estSec = Math.max(1.2, (count * intervalMs) / 1000 + 0.7);
  setActionStatus('statusBench', 'running', 'running');
  prog.start(estSec);
  setStatus('Running benchmark...');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const senderUrl = $('senderNodeUrl').value;
    const receiverUrl = $('receiverNodeUrl').value;
    const senderIf = $('senderNodeInterface').value;
    const receiverIf = $('receiverNodeInterface').value;
    if (!senderUrl || !receiverUrl || !senderIf || !receiverIf) {
      throw new Error(`Missing pair: sender ${senderUrl || '?'}/${senderIf || '?'} -> receiver ${receiverUrl || '?'}/${receiverIf || '?'}`);
    }
    const res = await fetch('/api/benchmark', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        senderUrl, receiverUrl,
        senderInterface: senderIf,
        receiverInterface: receiverIf,
        profile: getProfile(),
        count: Number($('benchCount').value || 500),
        intervalMs: Number($('benchInterval').value || 1),
        payloadSize: Number($('benchPayloadSize').value || 64)
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const s = data.report.stats;
    $('reportSummary').innerHTML = `
      <div><span>Sent</span><strong>${s.txCount}</strong></div>
      <div><span>Recv</span><strong>${s.rxCount}</strong></div>
      <div><span>Loss</span><strong>${s.lossPct.toFixed(2)}%</strong></div>
      <div><span>Tx Mbps</span><strong>${s.throughputMbps.toFixed(2)}</strong></div>
      <div><span>Lat p95 µs (skew-adj.)</span><strong>${(s.latencyAdjustedUs?.p95||0).toFixed(1)}</strong></div>
      <div><span>Jitter µs</span><strong>${(s.jitterUs.mean||0).toFixed(2)}</strong></div>
    `;
    const okFlag = s.rxCount > 0;
    setActionStatus('statusBench', okFlag ? 'ok' : 'fail', `${s.rxCount}/${s.txCount} · ${s.throughputMbps.toFixed(1)}Mbps`);
    if (okFlag) prog.finish(); else prog.fail();
    setStatus(`Benchmark done: ${s.rxCount}/${s.txCount} rx, ${s.throughputMbps.toFixed(2)} Mbps`, !okFlag);
    if (okFlag) window.open('/reports/benchmark-latest.html', '_blank');
    else {
      alert(`Benchmark received 0 packets.\n\nChecklist:\n - Wire/link between ${senderIf} and ${receiverIf} is up\n - Peer agent is reachable at ${receiverUrl}\n - Sender MAC ${state.interfaces.find(i=>i.name===senderIf)?.mac} matches what the peer expects\n\nThe benchmark always uses UDP+IPv4 internally regardless of the profile selected on the Sender tab.`);
    }
  } catch (err) {
    setActionStatus('statusBench', 'fail', 'fail');
    prog.fail();
    throw err;
  }
}

async function runSweep() {
  const prog = progressFor('progSweep');
  const count = Number($('benchCount').value || 200);
  const intervalMs = Number($('benchInterval').value || 1);
  // Per-slot wall time observed: send_ms + ~700ms HTTP/agent overhead. Strict
  // srcMac filter + maxFrames=count makes the receiver exit immediately when
  // all frames arrive instead of running to capture timeout.
  const perSlot = Math.max(1.2, (count * intervalMs) / 1000 + 0.7);
  const estSec = 7 * perSlot + 0.5;
  setActionStatus('statusSweep', 'running', 'running');
  prog.start(estSec);
  setStatus('Running frame-size sweep (this can take a while)...');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const result = await api('/api/sweep', {
      method: 'POST',
      body: JSON.stringify({
        senderUrl: $('senderNodeUrl').value,
        receiverUrl: $('receiverNodeUrl').value,
        senderInterface: $('senderNodeInterface').value,
        receiverInterface: $('receiverNodeInterface').value,
        count, intervalMs
      })
    });
    const sizes = result.report.results.length;
    setActionStatus('statusSweep', 'ok', `${sizes} sizes`);
    prog.finish();
    setStatus(`Sweep done: ${sizes} sizes`);
    window.open('/reports/sweep-latest.html', '_blank');
  } catch (err) {
    setActionStatus('statusSweep', 'fail', 'fail');
    prog.fail();
    throw err;
  }
}

$('runBenchmark').addEventListener('click', () => runBenchmark().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('runSweep').addEventListener('click', () => runSweep().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('caseSelect').addEventListener('change', () => {
  const item = state.testCases.find((entry) => entry.id === $('caseSelect').value);
  if (item) setCurrentCase(item.testCase);
});
$('profileSuiteSelect').addEventListener('change', () => {
  const item = state.testProfiles.find((entry) => entry.id === $('profileSuiteSelect').value);
  if (!item) return;
  setCurrentCase(item.testCase);
  $('caseName').value = item.name;
  $('caseDescription').value = item.description || '';
  setStatus(`Loaded standard profile: ${item.name}`);
});
$('newCase').addEventListener('click', () => setCurrentCase({ id: '', name: 'Untitled Test Case', description: '', steps: [] }));
$('saveCase').addEventListener('click', () => saveCurrentCase().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('deleteCase').addEventListener('click', () => deleteCurrentCase().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('addCurrentPacket').addEventListener('click', addCurrentPacketToCase);
$('addDelay').addEventListener('click', addDelayToCase);
$('duplicateStep').addEventListener('click', duplicateSelectedStep);
$('removeStep').addEventListener('click', removeSelectedStep);
$('moveStepUp').addEventListener('click', () => moveSelectedStep(-1));
$('moveStepDown').addEventListener('click', () => moveSelectedStep(1));
$('sendSelectedSteps').addEventListener('click', () => runCurrentCase({ selectedOnly: true }).catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('runCase').addEventListener('click', () => runCurrentCase().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
$('caseCycleMs').addEventListener('change', updateCaseEstimate);
$('caseRepeat').addEventListener('change', updateCaseEstimate);
$('caseLoopCount').addEventListener('change', updateCaseEstimate);
$('senderNodeInterface').addEventListener('change', renderNodeGrid);
$('receiverNodeInterface').addEventListener('change', renderNodeGrid);

function localIface() {
  return state.interfaces.find((i) => i.name === $('interfaceSelect').value) || null;
}

function firstV4(iface) {
  return iface?.ipv4?.find((a) => a.local && !a.local.includes(':'))?.local || '';
}

function applyLock() {
  if (!state.locked) return;
  const local = localIface();
  const peer = state.peer.iface;
  const localIp = firstV4(local);
  const peerIp = firstV4(peer);
  // Sender form (always reflects the locked pair)
  if (local) {
    $('srcMac').value = local.mac;
    if (localIp) $('srcIp').value = localIp;
    $('srcMac').readOnly = true;
    $('srcIp').readOnly = true;
  }
  if (peer) {
    $('dstMac').value = peer.mac;
    if (peerIp) $('dstIp').value = peerIp;
    $('dstMac').readOnly = true;
    $('dstIp').readOnly = true;
  }
  // Note: Capture page is now Wireshark-style (sniff all by default), so we
  // intentionally do NOT auto-fill captureSrcMac / captureDstMac from the
  // pinned pair. Pre-decode filters in the collapsed "Capture filters" panel
  // remain manual so the user can explicitly narrow the sniff.
}

function setLockUi() {
  const btn = $('lockToggle');
  if (!btn) return;
  btn.textContent = state.locked ? '🔒 Locked to peer' : '🔓 Manual';
  btn.classList.toggle('locked', state.locked);
  ['srcMac','srcIp','dstMac','dstIp'].forEach((id) => {
    const el = $(id);
    if (el) el.readOnly = state.locked;
  });
}

function renderLinkStrip() {
  const local = localIface();
  if (local) {
    $('localIfName').textContent = local.name;
    $('localIp').textContent = firstV4(local);
    $('localMac').textContent = local.mac;
  }
  const peer = state.peer.iface;
  if (peer) {
    $('peerIfName').textContent = peer.name;
    $('peerIp').textContent = firstV4(peer);
    $('peerMac').textContent = peer.mac;
  } else {
    $('peerIfName').textContent = state.peer.url ? '(probe to load)' : '-';
    $('peerIp').textContent = '';
    $('peerMac').textContent = '--:--:--:--:--:--';
  }
  const localTag = state.localRole === 'sender' ? 'SENDER' : 'RECEIVER';
  const peerTag = state.localRole === 'sender' ? 'RECEIVER' : 'SENDER';
  $('localRoleTag').textContent = localTag;
  $('peerRoleTag').textContent = peerTag;
  syncControlFromPeer();
  applyLock();
  setLockUi();
  const hint = $('e2eHint');
  if (hint) {
    const local = localIface();
    const peer = state.peer.iface;
    if (local && peer) {
      hint.textContent = `tcpdump -i ${local.name} -nn ether host ${peer.mac}`;
    } else {
      hint.textContent = 'tcpdump -i $iface -nn ether host PEER_MAC';
    }
  }
}

function setActionStatus(id, kind, text) {
  const el = $(id);
  if (!el) return;
  el.className = `actionStatus ${kind}`;
  el.textContent = text;
}

function progressFor(progId) {
  const track = $(progId);
  if (!track) return { start() {}, set() {}, finish() {}, fail() {} };
  const fill = track.querySelector('.progressFill');
  const label = track.querySelector('.progressLabel');
  let timer = null;
  let card = track.closest('.actionCard');
  return {
    start(estimatedSec) {
      track.classList.add('show');
      card?.classList.add('running');
      const t0 = performance.now();
      fill.style.width = '0%';
      label.textContent = '0%';
      track.classList.remove('indeterminate');
      if (!estimatedSec || estimatedSec <= 0) {
        track.classList.add('indeterminate');
        return;
      }
      const tick = () => {
        const elapsed = (performance.now() - t0) / 1000;
        const pct = Math.min(95, (elapsed / estimatedSec) * 100);
        fill.style.width = pct.toFixed(1) + '%';
        label.textContent = `${pct.toFixed(0)}% · ${elapsed.toFixed(1)}s / ~${estimatedSec.toFixed(1)}s`;
      };
      tick();
      timer = setInterval(tick, 100);
    },
    set(pct, text) {
      if (timer) { clearInterval(timer); timer = null; }
      track.classList.remove('indeterminate');
      fill.style.width = `${pct}%`;
      if (text) label.textContent = text;
    },
    finish() {
      if (timer) { clearInterval(timer); timer = null; }
      track.classList.remove('indeterminate');
      fill.style.width = '100%';
      label.textContent = '100% · done';
      card?.classList.remove('running');
      setTimeout(() => track.classList.remove('show'), 1200);
    },
    fail() {
      if (timer) { clearInterval(timer); timer = null; }
      track.classList.remove('indeterminate');
      fill.style.background = 'linear-gradient(90deg, #ef4444, #b91c1c)';
      label.textContent = 'failed';
      card?.classList.remove('running');
      setTimeout(() => {
        track.classList.remove('show');
        fill.style.background = '';
      }, 1500);
    }
  };
}

function renderPairCard() {
  const local = localIface();
  const peer = state.peer.iface;
  const localUrl = window.location.origin;
  const peerUrl = state.peer.url || '';
  const senderIs = state.localRole === 'sender';
  const sender = senderIs ? local : peer;
  const receiver = senderIs ? peer : local;
  const sUrl = senderIs ? localUrl : peerUrl;
  const rUrl = senderIs ? peerUrl : localUrl;
  const fmtMac = (m) => m || '--:--:--:--:--:--';
  const fmtIp = (i) => i?.ipv4?.[0]?.local || '-';
  if ($('ctrlSenderName')) {
    $('ctrlSenderName').textContent = sender?.name || '-';
    $('ctrlSenderMac').textContent = fmtMac(sender?.mac);
    $('ctrlSenderIp').textContent = fmtIp(sender);
    $('ctrlSenderUrl').textContent = sUrl || '(this PC)';
    $('ctrlReceiverName').textContent = receiver?.name || '-';
    $('ctrlReceiverMac').textContent = fmtMac(receiver?.mac);
    $('ctrlReceiverIp').textContent = fmtIp(receiver);
    $('ctrlReceiverUrl').textContent = rUrl || '(set peer above)';
    const ready = sender && receiver && sUrl && rUrl;
    $('pairWarning').classList.toggle('hidden', Boolean(ready));
  }
}

function syncControlFromPeer() {
  const localUrl = window.location.origin;
  const peerUrl = state.peer.url;
  const localIfName = $('interfaceSelect').value;
  const peerIfName = state.peer.iface?.name || state.peer.interface || '';
  const localPack = { url: localUrl, interfaces: state.interfaces };
  const peerPack = state.peer.interfaces.length ? { url: peerUrl, interfaces: state.peer.interfaces } : null;
  if (state.localRole === 'sender') {
    state.nodes.sender = localPack;
    if (peerPack) state.nodes.receiver = peerPack;
    $('senderNodeUrl').value = localUrl;
    $('receiverNodeUrl').value = peerUrl;
  } else {
    state.nodes.receiver = localPack;
    if (peerPack) state.nodes.sender = peerPack;
    $('senderNodeUrl').value = peerUrl;
    $('receiverNodeUrl').value = localUrl;
  }
  if (state.nodes.sender) {
    renderInterfaceOptions('senderNodeInterface', state.nodes.sender.interfaces);
    $('senderNodeInterface').value = state.localRole === 'sender' ? localIfName : peerIfName;
  }
  if (state.nodes.receiver) {
    renderInterfaceOptions('receiverNodeInterface', state.nodes.receiver.interfaces);
    $('receiverNodeInterface').value = state.localRole === 'sender' ? peerIfName : localIfName;
  }
  renderNodeGrid();
  renderPairCard();
}

async function probePeer() {
  const url = $('peerUrlPin').value.trim();
  if (!url) { alert('peer URL is required'); return; }
  setStatus('Probing peer...');
  state.peer.url = url;
  localStorage.setItem('peerUrl', url);
  const result = await api('/api/probe-node', { method: 'POST', body: JSON.stringify({ url }) });
  state.peer.interfaces = result.interfaces;
  const sel = $('peerInterfacePin');
  const sorted = [...result.interfaces].sort((a, b) => {
    const score = (i) => (i.name === 'lo' ? 20 : i.name.startsWith('docker') ? 15 : i.state === 'up' ? 0 : 10);
    return score(a) - score(b);
  });
  sel.innerHTML = sorted.map((i) => {
    const ip = i.ipv4?.[0]?.local || '';
    return `<option value="${i.name}">${i.name} (${i.state})${ip ? ' - ' + ip : ''}</option>`;
  }).join('');
  if (state.peer.interface && sorted.find((i) => i.name === state.peer.interface)) {
    sel.value = state.peer.interface;
  }
  state.peer.iface = sorted.find((i) => i.name === sel.value) || null;
  if (state.localRole === 'sender') state.nodes.receiver = { url, interfaces: result.interfaces };
  else state.nodes.sender = { url, interfaces: result.interfaces };
  renderLinkStrip();
  setStatus(`Peer probed: ${result.interfaces.length} interfaces`);
}

function lockToPeer() {
  const peer = state.peer.iface;
  if (!peer) { alert('probe peer first'); return; }
  if (state.localRole === 'sender') {
    $('dstMac').value = peer.mac;
    if (peer.ipv4?.[0]?.local) $('dstIp').value = peer.ipv4[0].local;
    $('captureSrcMac').value = peer.mac;
    setStatus(`Locked: dst MAC = ${peer.mac}`);
  } else {
    $('captureSrcMac').value = peer.mac;
    setStatus(`Locked: capture src MAC filter = ${peer.mac}`);
  }
}

$('peerProbeBtn').addEventListener('click', () => probePeer().catch((err) => { setStatus(err.message, true); alert(err.message); }));
$('peerInterfacePin').addEventListener('change', () => {
  state.peer.interface = $('peerInterfacePin').value;
  state.peer.iface = state.peer.interfaces.find((i) => i.name === state.peer.interface) || null;
  localStorage.setItem('peerInterface', state.peer.interface);
  renderLinkStrip();
});
$('linkArrow').addEventListener('click', () => {
  state.localRole = state.localRole === 'sender' ? 'receiver' : 'sender';
  localStorage.setItem('localRole', state.localRole);
  renderLinkStrip();
});
$('useMacBtn').addEventListener('click', lockToPeer);
$('lockToggle').addEventListener('click', () => {
  state.locked = !state.locked;
  localStorage.setItem('autoLock', state.locked ? '1' : '0');
  if (state.locked) applyLock();
  setLockUi();
});
$('interfaceSelect').addEventListener('change', () => {
  localStorage.setItem('localInterface', $('interfaceSelect').value);
  renderLinkStrip();
});

$('senderNodeInterface').addEventListener('change', () => {
  if (state.localRole === 'sender') {
    const name = $('senderNodeInterface').value;
    if (state.interfaces.find((i) => i.name === name)) {
      $('interfaceSelect').value = name;
      localStorage.setItem('localInterface', name);
      updateInterfaceInfo();
      renderLinkStrip();
    }
  } else {
    state.peer.interface = $('senderNodeInterface').value;
    state.peer.iface = state.peer.interfaces.find((i) => i.name === state.peer.interface) || null;
    localStorage.setItem('peerInterface', state.peer.interface);
    if ($('peerInterfacePin').querySelector(`option[value="${state.peer.interface}"]`)) {
      $('peerInterfacePin').value = state.peer.interface;
    }
    renderLinkStrip();
  }
});

$('receiverNodeInterface').addEventListener('change', () => {
  if (state.localRole === 'receiver') {
    const name = $('receiverNodeInterface').value;
    if (state.interfaces.find((i) => i.name === name)) {
      $('interfaceSelect').value = name;
      localStorage.setItem('localInterface', name);
      updateInterfaceInfo();
      renderLinkStrip();
    }
  } else {
    state.peer.interface = $('receiverNodeInterface').value;
    state.peer.iface = state.peer.interfaces.find((i) => i.name === state.peer.interface) || null;
    localStorage.setItem('peerInterface', state.peer.interface);
    if ($('peerInterfacePin').querySelector(`option[value="${state.peer.interface}"]`)) {
      $('peerInterfacePin').value = state.peer.interface;
    }
    renderLinkStrip();
  }
});

// Switch tab early based on URL hash, before any async loads
(() => {
  const hash = location.hash.replace('#', '');
  const target = { capture: 'captureView', control: 'controlView', sender: 'senderView' }[hash];
  if (!target) return;
  const btn = document.querySelector(`[data-view="${target}"]`);
  if (btn) btn.click();
})();
// ?autoStart=1 — used for headless verification of the capture pipeline
const _autoStart = new URLSearchParams(location.search).get('autoStart') === '1';
await loadExamples();
await loadTestProfiles();
await loadTestCases();
await loadInterfaces();
const savedLocalIf = localStorage.getItem('localInterface');
if (savedLocalIf && state.interfaces.find((i) => i.name === savedLocalIf)) {
  $('interfaceSelect').value = savedLocalIf;
  updateInterfaceInfo();
}
$('peerUrlPin').value = state.peer.url;
renderLinkStrip();
if (state.peer.url) probePeer().catch(() => {});
try { await build(); } catch (err) { console.warn('initial build skipped:', err.message); }
clearCapture();
if (_autoStart) setTimeout(() => $('captureStart')?.click(), 800);
// Honour URL hash like #capture / #control / #sender to jump to a tab on load
(() => {
  const hash = location.hash.replace('#', '');
  const target = { capture: 'captureView', control: 'controlView', sender: 'senderView' }[hash];
  if (!target) return;
  const btn = document.querySelector(`[data-view="${target}"]`);
  if (btn) btn.click();
})();
