const $ = (id) => document.getElementById(id);
const state = { examples: {}, interfaces: [], packets: [], scanHosts: [] };

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

function setProfile(profile) {
  $('protocol').value = profile.protocol || 'udp';
  $('dstMac').value = profile.dstMac || '';
  $('srcMac').value = profile.srcMac || '';
  $('srcIp').value = profile.ipv4?.src || profile.arp?.senderIp || '';
  $('dstIp').value = profile.ipv4?.dst || profile.arp?.targetIp || '';
  $('srcPort').value = profile.udp?.srcPort || 40000;
  $('dstPort').value = profile.udp?.dstPort || 50000;
  $('payload').value = profile.payload?.data || '';
  $('count').value = profile.count || 1;
  $('intervalMs').value = profile.intervalMs || 1000;
  $('vlanEnabled').checked = Boolean(profile.vlan?.enabled);
  $('vlanId').value = profile.vlan?.id ?? 10;
  $('vlanPriority').value = profile.vlan?.priority ?? 0;
  $('captureSrcMac').value = '';
  $('captureDstMac').value = '';
  $('captureEtherType').value = profile.protocol === 'arp' ? '0x0806' : profile.protocol === 'raw' ? '' : '0x0800';
}

function cidrFromInterface(iface) {
  const ipv4 = iface?.ipv4?.[0];
  if (!ipv4?.local || !ipv4?.prefixlen) return '';
  return `${ipv4.local}/${ipv4.prefixlen}`;
}

function scanCidrFromInterface(iface) {
  const ipv4 = iface?.ipv4?.[0];
  if (!ipv4?.local) return '';
  const parts = ipv4.local.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return '';
  const prefix = Math.max(Number(ipv4.prefixlen || 24), 24);
  if (prefix <= 24) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  return `${ipv4.local}/${prefix}`;
}

function getProfile() {
  const protocol = $('protocol').value;
  const profile = {
    interface: $('interfaceSelect').value,
    protocol,
    dstMac: $('dstMac').value.trim(),
    srcMac: $('srcMac').value.trim(),
    count: Number($('count').value || 1),
    intervalMs: Number($('intervalMs').value || 0),
    vlan: {
      enabled: $('vlanEnabled').checked,
      id: Number($('vlanId').value || 0),
      priority: Number($('vlanPriority').value || 0)
    },
    payload: {
      mode: 'text',
      data: $('payload').value
    }
  };
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

function renderTopology() {
  const svg = d3.select('#topology');
  const node = svg.node();
  const width = node.clientWidth || 360;
  const height = node.clientHeight || 260;
  svg.selectAll('*').remove();

  const iface = state.interfaces.find((item) => item.name === $('interfaceSelect').value);
  const root = {
    id: iface?.name || 'local',
    label: iface?.name || 'local',
    sublabel: iface?.ipv4?.[0]?.local || iface?.mac || '',
    type: 'local'
  };
  const hosts = state.scanHosts.map((host) => ({
    id: host.ip,
    label: host.ip,
    sublabel: host.mac,
    type: 'host'
  }));
  const nodes = [root, ...hosts];
  const links = hosts.map((host) => ({ source: root.id, target: host.id }));

  if (hosts.length === 0) {
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height / 2)
      .attr('text-anchor', 'middle')
      .attr('fill', '#62707f')
      .text('Run Scan to discover ARP neighbors');
    return;
  }

  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id((d) => d.id).distance(105))
    .force('charge', d3.forceManyBody().strength(-420))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(38));

  const link = svg.append('g')
    .attr('stroke', '#9aabb8')
    .attr('stroke-width', 1.4)
    .selectAll('line')
    .data(links)
    .join('line');

  const group = svg.append('g')
    .selectAll('g')
    .data(nodes)
    .join('g');

  group.append('circle')
    .attr('r', (d) => d.type === 'local' ? 18 : 14)
    .attr('fill', (d) => d.type === 'local' ? '#0f6f78' : '#f0b429')
    .attr('stroke', '#ffffff')
    .attr('stroke-width', 2);

  group.append('text')
    .attr('class', 'nodeLabel')
    .attr('x', 22)
    .attr('y', 4)
    .text((d) => d.label);

  group.append('title')
    .text((d) => `${d.label}\n${d.sublabel}`);

  simulation.on('tick', () => {
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);
    group.attr('transform', (d) => `translate(${d.x},${d.y})`);
  });
}

function renderScanResults(result = null) {
  if (!state.scanHosts.length) {
    $('scanResults').textContent = result ? `No hosts found. Probed ${result.probed} address(es).` : 'No scan results yet';
    renderTopology();
    return;
  }
  $('scanResults').innerHTML = state.scanHosts.map((host) => `
    <div class="host">
      <strong>${host.ip}</strong>
      <span>${host.mac}</span>
    </div>
  `).join('');
  renderTopology();
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
  const scanCidr = scanCidrFromInterface(selected);
  $('interfaceInfo').textContent = `MAC ${selected.mac} / MTU ${selected.mtu} / ${selected.state}${cidr ? ` / ${cidr}` : ''}`;
  $('selectedInterfaceName').textContent = selected.name;
  $('selectedInterfaceMac').textContent = `${selected.mac}${cidr ? ` / ${cidr}` : ''}`;
  if (scanCidr) $('scanCidr').value = scanCidr;
  if (selected.state !== 'up' && selected.name !== 'lo') {
    setStatus(`${selected.name} is ${selected.state}`, true);
  }
  if (!$('srcMac').value || $('srcMac').value === '02:00:00:00:00:01') {
    $('srcMac').value = selected.mac;
  }
  if (selected.ipv4?.[0]?.local && (!$('srcIp').value || $('srcIp').value === '192.168.100.10')) {
    $('srcIp').value = selected.ipv4[0].local;
  }
  renderTopology();
}

async function loadExamples() {
  const data = await api('/api/examples');
  state.examples = data.profiles;
  setProfile(state.examples.udp);
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

async function scan() {
  const iface = state.interfaces.find((item) => item.name === $('interfaceSelect').value);
  const srcIp = iface?.ipv4?.[0]?.local || $('srcIp').value.trim();
  const timeoutSec = Number($('scanTimeout').value || 3);
  setStatus(`Scanning ${$('scanCidr').value}...`);
  const result = await api('/api/scan', {
    method: 'POST',
    body: JSON.stringify({
      interface: $('interfaceSelect').value,
      cidr: $('scanCidr').value.trim(),
      srcMac: $('srcMac').value.trim(),
      srcIp,
      timeoutSec,
      timeoutMs: (timeoutSec * 1000) + 8000,
      maxHosts: Number($('scanMaxHosts').value || 512)
    })
  });
  state.scanHosts = result.stdout.hosts || [];
  renderScanResults(result.stdout);
  setStatus(`Scan found ${state.scanHosts.length} host(s)`);
}

document.querySelectorAll('[data-example]').forEach((button) => {
  button.addEventListener('click', () => setProfile(state.examples[button.dataset.example]));
});

document.querySelectorAll('[data-view]').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('[data-view]').forEach((item) => item.classList.remove('active'));
    document.querySelectorAll('.roleView').forEach((view) => view.classList.remove('active'));
    button.classList.add('active');
    $(button.dataset.view).classList.add('active');
    if (button.dataset.view === 'discoveryView') renderTopology();
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
$('scan').addEventListener('click', () => scan().catch((err) => {
  setStatus(err.message, true);
  alert(err.message);
}));

await loadExamples();
await loadInterfaces();
await build();
renderPackets();
renderTopology();
