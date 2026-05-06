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
  localRole: localStorage.getItem('localRole') || 'sender'
};

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
  $('dstMac').value = profile.dstMac || '';
  $('srcMac').value = profile.srcMac || '';
  $('srcIp').value = profile.ipv4?.src || profile.arp?.senderIp || '';
  $('dstIp').value = profile.ipv4?.dst || profile.arp?.targetIp || '';
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
  $('captureSrcMac').value = '';
  $('captureDstMac').value = '';
  $('captureEtherType').value = profile.protocol === 'arp' ? '0x0806' : profile.protocol === 'raw' ? '' : '0x0800';
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

function renderPackets() {
  if (state.packets.length === 0) {
    $('packetRows').innerHTML = '<tr><td colspan="7" class="empty">No captured packets yet</td></tr>';
    return;
  }
  $('packetRows').innerHTML = state.packets.map((packet, index) => {
    const decoded = packet.decoded;
    const src = decoded.ipv4?.src || decoded.arp?.senderIp || decoded.ethernet?.srcMac || '-';
    const dst = decoded.ipv4?.dst || decoded.arp?.targetIp || decoded.ethernet?.dstMac || '-';
    const time = new Date(packet.timestamp * 1000).toLocaleTimeString();
    return `
      <tr data-packet-index="${index}">
        <td>${index + 1}</td>
        <td>${time}</td>
        <td>${src}</td>
        <td>${dst}</td>
        <td>${protocolName(decoded)}</td>
        <td>${packet.length}</td>
        <td>${packetInfo(decoded)}</td>
      </tr>
    `;
  }).join('');
  document.querySelectorAll('[data-packet-index]').forEach((row) => {
    row.addEventListener('click', () => {
      const packet = state.packets[Number(row.dataset.packetIndex)];
      $('captureDecoded').textContent = JSON.stringify(packet.decoded, null, 2);
      $('captureHexdump').textContent = packet.hexdump || '';
    });
  });
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
  const cidr = cidrFromInterface(selected);
  $('interfaceInfo').textContent = `MAC ${selected.mac} / MTU ${selected.mtu} / ${selected.state}${cidr ? ` / ${cidr}` : ''}`;
  $('selectedInterfaceName').textContent = selected.name;
  $('selectedInterfaceMac').textContent = `${selected.mac}${cidr ? ` / ${cidr}` : ''}`;
  if (selected.state !== 'up' && selected.name !== 'lo') setStatus(`${selected.name} is ${selected.state}`, true);
  if (!$('srcMac').value || $('srcMac').value === '02:00:00:00:00:01') $('srcMac').value = selected.mac;
  if (selected.ipv4?.[0]?.local && (!$('srcIp').value || $('srcIp').value === '192.168.100.10')) {
    $('srcIp').value = selected.ipv4[0].local;
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

async function capture() {
  const timeoutSec = Number($('captureTimeout').value || 10);
  setStatus(`Capture running for ${timeoutSec}s...`);
  const result = await api('/api/capture', {
    method: 'POST',
    body: JSON.stringify({
      interface: $('interfaceSelect').value,
      timeoutSec,
      timeoutMs: (timeoutSec * 1000) + 2000,
      maxFrames: Number($('captureMaxFrames').value || 30),
      srcMac: $('captureSrcMac').value.trim(),
      dstMac: $('captureDstMac').value.trim(),
      etherType: $('captureEtherType').value.trim()
    })
  });
  const frames = result.stdout.frames || [];
  state.packets = frames;
  renderPackets();
  if (frames[0]) {
    $('captureDecoded').textContent = JSON.stringify(frames[0].decoded, null, 2);
    $('captureHexdump').textContent = frames[0].hexdump || '';
  } else {
    $('captureDecoded').textContent = '';
    $('captureHexdump').textContent = '';
  }
  setStatus(`Capture complete: ${frames.length} frame(s)`);
}

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
  $('openReport').classList.remove('disabled');
  $('openReportJson').classList.remove('disabled');
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
  $('openE2EReport').classList.remove('disabled');
  $('openE2EJson').classList.remove('disabled');
}

async function runE2E() {
  setActionStatus('statusE2E', 'running', 'running...');
  setStatus('Running end-to-end test...');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const senderUrl = $('senderNodeUrl').value;
    const receiverUrl = $('receiverNodeUrl').value;
    const senderIf = $('senderNodeInterface').value;
    const receiverIf = $('receiverNodeInterface').value;
    if (!senderUrl || !receiverUrl || !senderIf || !receiverIf) throw new Error('Missing pair (peer not set?)');
    const result = await api('/api/e2e-test', {
      method: 'POST',
      body: JSON.stringify({
        senderUrl, receiverUrl,
        senderInterface: senderIf,
        receiverInterface: receiverIf,
        profile: getProfile(),
        timeoutSec: 5,
        maxFrames: 50
      })
    });
    renderE2EReport(result.report);
    setActionStatus('statusE2E', result.report.ok ? 'ok' : 'fail', `${result.report.matchCount} matched`);
    setStatus(`E2E ${result.report.ok ? 'PASS' : 'FAIL'}: ${result.report.matchCount} matching frame(s)`, !result.report.ok);
  } catch (err) {
    setActionStatus('statusE2E', 'fail', 'fail');
    throw err;
  }
}

async function runReport() {
  setActionStatus('statusReport', 'running', 'running...');
  setStatus('Running validation report...');
  try {
    const result = await api('/api/run-report', { method: 'POST', body: '{}' });
    renderReport(result.report);
    const fail = result.report.summary.fail;
    setActionStatus('statusReport', fail === 0 ? 'ok' : 'fail', `${result.report.summary.pass}/${result.report.summary.total}`);
    setStatus(`Report complete: ${result.report.summary.pass}/${result.report.summary.total} pass`, fail > 0);
  } catch (err) {
    setActionStatus('statusReport', 'fail', 'fail');
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
$('capture').addEventListener('click', () => capture().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));
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
  setActionStatus('statusBench', 'running', 'running...');
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
    setStatus(`Benchmark done: ${s.rxCount}/${s.txCount} rx, ${s.throughputMbps.toFixed(2)} Mbps`, !okFlag);
    if (okFlag) window.open('/reports/benchmark-latest.html', '_blank');
    else {
      alert(`Benchmark received 0 packets.\n\nChecklist:\n - Wire/link between ${senderIf} and ${receiverIf} is up\n - Peer agent is reachable at ${receiverUrl}\n - Sender MAC ${state.interfaces.find(i=>i.name===senderIf)?.mac} matches what the peer expects\n\nThe benchmark always uses UDP+IPv4 internally regardless of the profile selected on the Sender tab.`);
    }
  } catch (err) {
    setActionStatus('statusBench', 'fail', 'fail');
    throw err;
  }
}

async function runSweep() {
  setActionStatus('statusSweep', 'running', 'running...');
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
        count: Number($('benchCount').value || 200),
        intervalMs: Number($('benchInterval').value || 1)
      })
    });
    const sizes = result.report.results.length;
    setActionStatus('statusSweep', 'ok', `${sizes} sizes`);
    setStatus(`Sweep done: ${sizes} sizes`);
    window.open('/reports/sweep-latest.html', '_blank');
  } catch (err) {
    setActionStatus('statusSweep', 'fail', 'fail');
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
$('senderNodeInterface').addEventListener('change', renderNodeGrid);
$('receiverNodeInterface').addEventListener('change', renderNodeGrid);

function localIface() {
  return state.interfaces.find((i) => i.name === $('interfaceSelect').value) || null;
}

function renderLinkStrip() {
  const local = localIface();
  if (local) {
    $('localIfName').textContent = local.name;
    $('localIp').textContent = local.ipv4?.[0]?.local || '';
    $('localMac').textContent = local.mac;
  }
  const peer = state.peer.iface;
  if (peer) {
    $('peerIfName').textContent = peer.name;
    $('peerIp').textContent = peer.ipv4?.[0]?.local || '';
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
}

function setActionStatus(id, kind, text) {
  const el = $(id);
  if (!el) return;
  el.className = `actionStatus ${kind}`;
  el.textContent = text;
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

await loadExamples();
await loadInterfaces();
const savedLocalIf = localStorage.getItem('localInterface');
if (savedLocalIf && state.interfaces.find((i) => i.name === savedLocalIf)) {
  $('interfaceSelect').value = savedLocalIf;
  updateInterfaceInfo();
}
$('peerUrlPin').value = state.peer.url;
renderLinkStrip();
if (state.peer.url) probePeer().catch(() => {});
await build();
renderPackets();
