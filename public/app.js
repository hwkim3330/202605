const $ = (id) => document.getElementById(id);

const state = {
  examples: {},
  exampleItems: [],
  interfaces: [],
  packets: []
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

await loadExamples();
await loadInterfaces();
await build();
renderPackets();
