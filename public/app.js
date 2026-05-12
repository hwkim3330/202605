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

// Toast notifications — replace alert() so the page never blocks.
function toast(message, kind = '', timeoutMs = 4500) {
  const tray = document.getElementById('toastTray');
  if (!tray) return;
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  const icon = kind === 'ok' ? '✓' : kind === 'warn' ? '⚠' : kind === 'fail' ? '✕' : 'ⓘ';
  el.innerHTML = `<span class="icon">${icon}</span><span class="body"></span><button class="close" aria-label="Dismiss">×</button>`;
  el.querySelector('.body').textContent = message;
  el.querySelector('.close').addEventListener('click', () => dismiss());
  tray.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  let t = setTimeout(dismiss, timeoutMs);
  function dismiss() {
    clearTimeout(t);
    el.classList.remove('show');
    setTimeout(() => el.remove(), 240);
  }
  return dismiss;
}
function toastError(err) {
  const msg = err?.message || String(err);
  setStatus(msg, true);
  toast(msg, 'fail');
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
  if (decoded.lldp) return 'LLDP';
  if (decoded.ptp) return 'PTP';
  if (decoded.lacp) return 'LACP';
  if (decoded.arp) return 'ARP';
  if (decoded.icmpv6) return 'ICMPv6';
  if (decoded.icmp) return 'ICMP';
  if (decoded.tls) return 'TLS';
  if (decoded.tcp) return decoded.ipv6 ? 'TCP/IPv6' : 'TCP';
  if (decoded.dns) return 'DNS';
  if (decoded.dhcp) return 'DHCP';
  if (decoded.ntp) return 'NTP';
  if (decoded.vxlan) return 'VXLAN';
  if (decoded.udp) {
    const sp = decoded.udp.srcPort, dp = decoded.udp.dstPort;
    if (sp === 5353 || dp === 5353) return 'mDNS';
    if (sp === 319 || dp === 319 || sp === 320 || dp === 320) return 'PTP/UDP';
    return decoded.ipv6 ? 'UDP/IPv6' : 'UDP';
  }
  if (decoded.ipv6) return `IPv6/${decoded.ipv6.nextHeader}`;
  if (decoded.ipv4) return `IPv4/${decoded.ipv4.protocol}`;
  return decoded.ethernet?.etherType || 'Ethernet';
}

function packetInfoExtra(decoded) {
  if (decoded.tls?.sni) return ` SNI=${decoded.tls.sni}`;
  if (decoded.dns) return ` ${decoded.dns.qr} ${decoded.dns.rcode ? 'rcode=' + decoded.dns.rcode : ''}`;
  if (decoded.dhcp?.messageType) return ` ${decoded.dhcp.messageType} xid=${decoded.dhcp.xid}`;
  if (decoded.ntp) return ` v${decoded.ntp.version} stratum=${decoded.ntp.stratum}`;
  if (decoded.vxlan) return ` VNI=${decoded.vxlan.vni}`;
  return '';
}

function packetInfo(decoded) {
  if (decoded.lldp) {
    const sysName = decoded.lldp.tlvs?.find((t) => t.name === 'SystemName')?.value;
    const portId = decoded.lldp.tlvs?.find((t) => t.name === 'PortID')?.value;
    return `LLDP ${sysName ? sysName + ' / ' : ''}${portId || decoded.lldp.tlvCount + ' TLVs'}`;
  }
  if (decoded.ptp) return `${decoded.ptp.messageName} seq=${decoded.ptp.sequenceId} dom=${decoded.ptp.domain}`;
  if (decoded.arp) return decoded.arp.operation === 1 ? `Who has ${decoded.arp.targetIp}? Tell ${decoded.arp.senderIp}` : `${decoded.arp.senderIp} is at ${decoded.arp.senderMac}`;
  if (decoded.tcp) return `${decoded.tcp.srcPort} → ${decoded.tcp.dstPort} [${(decoded.tcp.flags || []).join(',') || '-'}] seq=${decoded.tcp.seq} ack=${decoded.tcp.ack} win=${decoded.tcp.window}` + packetInfoExtra(decoded);
  if (decoded.udp) return `${decoded.udp.srcPort} → ${decoded.udp.dstPort}  Len=${decoded.udp.length}` + packetInfoExtra(decoded);
  if (decoded.icmpv6) return `${decoded.icmpv6.typeName} (type ${decoded.icmpv6.type})`;
  if (decoded.icmp) return `type ${decoded.icmp.type}, seq ${decoded.icmp.seq}`;
  if (decoded.ipv6) return `IPv6 next=${decoded.ipv6.nextHeader}`;
  return decoded.ethernet?.etherType || '';
}

const capture = {
  packets: [],
  reader: null,
  readers: [],
  abort: null,
  selectedIdx: -1,
  startedAtMs: 0,
  totalBytes: 0,
  lastWindow: { t: 0, count: 0, pps: 0 },
  filter: '',
  maxRows: 2000,
  maxBuffer: 50000,
  truncated: 0,
  pendingRows: [],
  flushScheduled: false
};

function rowProtoClass(decoded) {
  if (decoded.lldp) return 'proto-lldp';
  if (decoded.ptp) return 'proto-ptp';
  if (decoded.arp) return 'proto-arp';
  if (decoded.icmp || decoded.icmpv6) return 'proto-icmp';
  if (decoded.tcp) return 'proto-tcp';
  if (decoded.udp) return 'proto-udp';
  if (decoded.ipv6) return 'proto-ipv6';
  return '';
}

function frameMatchesFilter(packet, filter) {
  if (!filter) return true;
  const f = filter.trim().toLowerCase();
  if (!f) return true;
  const d = packet.decoded || {};
  // Tokens: udp / tcp / icmp / icmpv6 / arp / vlan / ipv4 / ipv6 / lldp / ptp / lacp / dns / dhcp / ntp / mdns
  if (f === 'udp') return Boolean(d.udp);
  if (f === 'tcp') return Boolean(d.tcp);
  if (f === 'icmp') return Boolean(d.icmp);
  if (f === 'icmpv6') return Boolean(d.icmpv6);
  if (f === 'arp') return Boolean(d.arp);
  if (f === 'vlan') return Boolean(d.vlan);
  if (f === 'ipv4') return Boolean(d.ipv4);
  if (f === 'ipv6') return Boolean(d.ipv6);
  if (f === 'lldp') return Boolean(d.lldp);
  if (f === 'ptp') return Boolean(d.ptp);
  if (f === 'lacp') return Boolean(d.lacp);
  if (f === 'dns') return d.udp && (d.udp.srcPort === 53 || d.udp.dstPort === 53);
  if (f === 'dhcp') return d.udp && [67,68].some((p) => d.udp.srcPort === p || d.udp.dstPort === p);
  if (f === 'ntp') return d.udp && (d.udp.srcPort === 123 || d.udp.dstPort === 123);
  if (f === 'mdns') return d.udp && (d.udp.srcPort === 5353 || d.udp.dstPort === 5353);
  if (f === 'tls') return Boolean(d.tls);
  if (f === 'vxlan') return Boolean(d.vxlan);
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
  // Free-text substring against a precomputed haystack — *one* JSON.stringify
  // per frame at ingest, not one per filter-keystroke. Drops filter-input CPU
  // from O(N × payload-size) to O(N × search-len).
  if (!packet._hay) packet._hay = JSON.stringify(d).toLowerCase();
  return packet._hay.includes(f);
}

function buildPacketRow(packet) {
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
  // No per-row listener — tbody-level delegation handles clicks.
  tr.innerHTML = `<td class="colNum">${idx + 1}</td><td class="colTime">${tStr}</td><td>${src}</td><td>${dst}</td><td class="colProto">${proto}</td><td class="colLen">${packet.length}</td><td>${packetInfo(decoded)}</td>`;
  return tr;
}

function flushPendingRows() {
  capture.flushScheduled = false;
  const tbody = $('packetRows');
  if (!tbody || !capture.pendingRows.length) return;
  const empty = $('packetEmpty');
  if (empty) empty.classList.add('hidden');
  // Batch into a DocumentFragment so the browser does ONE layout pass per
  // animation frame regardless of incoming frame rate.
  const frag = document.createDocumentFragment();
  for (const pkt of capture.pendingRows) frag.appendChild(buildPacketRow(pkt));
  capture.pendingRows.length = 0;
  tbody.appendChild(frag);
  // Cap DOM rows; remove from front in one bulk op to avoid N reflows.
  let over = tbody.children.length - capture.maxRows;
  if (over > 0) {
    const range = document.createRange();
    range.setStart(tbody, 0);
    range.setEnd(tbody, over);
    range.deleteContents();
  }
  if ($('captureFollow').checked) {
    const list = tbody.parentElement.parentElement;
    list.scrollTop = list.scrollHeight;
  }
}

function appendPacketRow(packet) {
  capture.pendingRows.push(packet);
  if (!capture.flushScheduled) {
    capture.flushScheduled = true;
    requestAnimationFrame(flushPendingRows);
  }
}

function computeFrameLayers(decoded, hexLen) {
  // Walk the decoded structure and return [{name, color, start, end}] byte ranges.
  const layers = [];
  layers.push({ name: 'Ethernet', color: '#0ea5e9', start: 0, end: 14 });
  let off = 14;
  if (decoded.vlan) { layers.push({ name: 'VLAN', color: '#f59e0b', start: 12, end: 16 }); off = 18; }
  if (decoded.vlanInner) { layers.push({ name: 'VLAN inner', color: '#fbbf24', start: off - 4, end: off + 4 }); off += 4; }
  if (decoded.ipv4) {
    const ihl = 20; // simplification; works for default-no-options frames
    layers.push({ name: 'IPv4', color: '#16a34a', start: off, end: off + ihl });
    if (decoded.udp) {
      layers.push({ name: 'UDP', color: '#7c3aed', start: off + ihl, end: off + ihl + 8 });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + ihl + 8, end: hexLen });
    } else if (decoded.tcp) {
      const tcpLen = decoded.tcp.dataOffset || 20;
      layers.push({ name: 'TCP', color: '#7c3aed', start: off + ihl, end: off + ihl + tcpLen });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + ihl + tcpLen, end: hexLen });
    } else if (decoded.icmp) {
      layers.push({ name: 'ICMP', color: '#a855f7', start: off + ihl, end: off + ihl + 8 });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + ihl + 8, end: hexLen });
    }
  } else if (decoded.ipv6) {
    layers.push({ name: 'IPv6', color: '#6366f1', start: off, end: off + 40 });
    if (decoded.udp) {
      layers.push({ name: 'UDP', color: '#7c3aed', start: off + 40, end: off + 48 });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + 48, end: hexLen });
    } else if (decoded.tcp) {
      const tcpLen = decoded.tcp.dataOffset || 20;
      layers.push({ name: 'TCP', color: '#7c3aed', start: off + 40, end: off + 40 + tcpLen });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + 40 + tcpLen, end: hexLen });
    } else if (decoded.icmpv6) {
      layers.push({ name: 'ICMPv6', color: '#a855f7', start: off + 40, end: off + 44 });
      layers.push({ name: 'Payload', color: '#94a3b8', start: off + 44, end: hexLen });
    }
  } else if (decoded.arp) {
    layers.push({ name: 'ARP', color: '#f97316', start: off, end: off + 28 });
  } else if (decoded.lldp) {
    layers.push({ name: 'LLDP', color: '#ec4899', start: off, end: hexLen });
  } else if (decoded.ptp) {
    layers.push({ name: 'PTP', color: '#d946ef', start: off, end: hexLen });
  }
  return layers;
}

function renderColoredHex(frameHex, layers) {
  // Build a hexdump where each byte is wrapped in a span coloured by the layer it belongs to.
  const bytes = [];
  for (let i = 0; i < frameHex.length / 2; i += 1) bytes.push(frameHex.substr(i * 2, 2));
  const colorAt = new Array(bytes.length).fill('#94a3b8');
  for (const L of layers) {
    for (let i = L.start; i < Math.min(L.end, bytes.length); i += 1) colorAt[i] = L.color;
  }
  let out = '';
  for (let row = 0; row < bytes.length; row += 16) {
    let hex = ''; let ascii = '';
    for (let i = 0; i < 16 && row + i < bytes.length; i += 1) {
      const b = bytes[row + i];
      hex += `<span style="color:${colorAt[row + i]}">${b}</span> `;
      const v = parseInt(b, 16);
      ascii += (v >= 32 && v < 127) ? String.fromCharCode(v).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;') : '·';
    }
    out += `<span class="hexOff">${row.toString(16).padStart(4, '0')}</span>  ${hex.padEnd(16 * 4 - 1, ' ')}  <span class="hexAscii">${ascii}</span>\n`;
  }
  return out;
}

function renderLegend(layers) {
  const seen = new Set();
  const unique = layers.filter((L) => !seen.has(L.name) && seen.add(L.name));
  return '<div class="layerLegend">' + unique.map((L) => `<span><i style="background:${L.color}"></i>${L.name}</span>`).join('') + '</div>';
}

function selectPacket(idx) {
  capture.selectedIdx = idx;
  const pkt = capture.packets[idx];
  if (!pkt) return;
  $('captureDecoded').textContent = JSON.stringify(pkt.decoded, null, 2);
  const hex = pkt.frameHex || '';
  const layers = computeFrameLayers(pkt.decoded || {}, hex.length / 2);
  const bytesEl = $('captureHexdump');
  bytesEl.innerHTML = renderLegend(layers) + renderColoredHex(hex, layers);
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

function selectedInterfaceNames() {
  const el = $('interfaceSelect');
  if (!el) return [];
  if (el.multiple) return Array.from(el.selectedOptions).map((o) => o.value).filter(Boolean);
  return el.value ? [el.value] : [];
}

async function spawnCaptureStream(ifaceName, signal, statTimer) {
  const body = {
    interface: ifaceName,
    timeoutSec: 0,
    maxFrames: 0,
    srcMac: $('captureSrcMac')?.value.trim() || '',
    dstMac: $('captureDstMac')?.value.trim() || '',
    etherType: $('captureEtherType')?.value.trim() || ''
  };
  const res = await fetch('/api/capture-stream', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal
  });
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status} on ${ifaceName}`);
  const reader = res.body.getReader();
  capture.readers.push(reader);
  const dec = new TextDecoder();
  let buf = '';
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
        ev._iface = ifaceName; // tag origin so the user can tell where it came from
        capture.packets.push(ev);
        capture.totalBytes += ev.length;
        capture.lastWindow.count += 1;
        if (capture.packets.length > capture.maxBuffer) {
          capture.packets.shift();
          capture.truncated += 1;
          if (capture.truncated === 1) toast(`Capture buffer hit ${capture.maxBuffer} packets — oldest are now being dropped to keep memory bounded.`, 'warn', 6000);
        }
        if (frameMatchesFilter(ev, capture.filter)) appendPacketRow(ev);
      } else if (ev.type === 'stats') {
        $('capStatDrops').textContent = String(ev.kernelDrops || 0);
        if ((ev.kernelDrops || 0) > 0) {
          $('capStatDrops').parentElement.style.background = 'rgba(155, 28, 28, 0.12)';
          $('capStatDrops').parentElement.style.color = '#9b1c1c';
        }
      } else if (ev.type === 'log') {
        setStatus(`agent[${ifaceName}]: ${ev.stderr}`, true);
      }
    }
  }
}

async function startCaptureStream() {
  if (capture.readers && capture.readers.length) return;
  const ifaces = selectedInterfaceNames();
  if (!ifaces.length) { setStatus('No interface selected', true); return; }
  clearCapture();
  $('capStatState').textContent = ifaces.length > 1 ? `capturing × ${ifaces.length}` : 'capturing';
  $('capStatState').classList.add('running');
  $('captureStart').disabled = true;
  $('captureStop').disabled = false;
  capture.startedAtMs = performance.now();
  capture.lastWindow = { t: capture.startedAtMs, count: 0, pps: 0 };
  capture.filter = $('captureDisplayFilter').value.trim();
  capture.readers = [];
  capture.abort = new AbortController();
  const statTimer = setInterval(() => {
    const now = performance.now();
    const dt = (now - capture.lastWindow.t) / 1000;
    capture.lastWindow.pps = dt > 0 ? capture.lastWindow.count / dt : 0;
    capture.lastWindow.t = now;
    capture.lastWindow.count = 0;
    const elapsed = (now - capture.startedAtMs) / 1000;
    const stateEl = $('capStatState');
    if (stateEl?.classList.contains('running')) stateEl.textContent = ifaces.length > 1
      ? `capturing × ${ifaces.length} · ${elapsed.toFixed(1)}s`
      : `capturing · ${elapsed.toFixed(1)}s`;
    refreshCaptureStats();
  }, 500);
  try {
    // Each spawnCaptureStream call hits /api/capture-stream which spawns its own
    // packet_agent.py subprocess on the server, so N interfaces == N parallel
    // agents on the same machine. Frames are merged into capture.packets and
    // tagged with the originating interface (frame._iface) so the user can
    // tell rows apart.
    await Promise.all(ifaces.map((iface) =>
      spawnCaptureStream(iface, capture.abort.signal, statTimer)
        .catch((err) => { if (err.name !== 'AbortError') setStatus(`${iface}: ${err.message}`, true); })
    ));
  } finally {
    clearInterval(statTimer);
    finishCaptureStream('stopped');
  }
}

function finishCaptureStream(label) {
  capture.readers = [];
  capture.abort = null;
  $('captureStart').disabled = false;
  $('captureStop').disabled = true;
  $('capStatState').classList.remove('running');
  $('capStatState').textContent = label || 'idle';
  refreshCaptureStats();
}

function stopCaptureStream() {
  try { capture.abort?.abort(); } catch {}
  for (const r of capture.readers || []) { try { r.cancel(); } catch {} }
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
      const step = state.currentCase.steps[state.selectedStep];
      $('caseStepPreview').textContent = JSON.stringify(step, null, 2);
      renderCaseRows();
      // Load the selected step's profile into the Sender form so its values
      // are editable and the Frame Details / Bytes preview rebuilds automatically.
      if (step?.kind === 'packet' && step.profile) {
        setProfile(step.profile);
        schedulePreview();
      }
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
  // Hidden <select multiple> stays so legacy callers reading .value still work
  // (it always reflects the first checked checkbox).
  const sel = $('interfaceSelect');
  sel.multiple = true;
  sel.innerHTML = state.interfaces
    .map((iface) => `<option value="${iface.name}">${iface.name} (${iface.state})</option>`)
    .join('');
  // Default: pick the first 'up' non-virtual NIC for both pickers so the UI
  // starts with one selection (matches the old single-select default).
  const def = state.interfaces.find((i) => i.state === 'up' && !/^(lo|docker|veth|br|virbr|tap|wlan|wlp|wlx)/.test(i.name))
           || state.interfaces[0];
  if (def) {
    if (!ifaceSel.sender.size)  ifaceSel.sender.add(def.name);
    if (!ifaceSel.capture.size) ifaceSel.capture.add(def.name);
  }
  renderInterfacePickers();
  updateInterfaceInfo();
  setStatus(`${state.interfaces.length} interfaces loaded`);
}

// Per-tab interface picker state. The Sender tab picks 'which NICs to
// transmit on'; the Capture tab picks 'which NICs to sniff on'. The hidden
// <select id=interfaceSelect> always mirrors the *active* tab's pick set so
// the rest of the app (which still reads interfaceSelect) stays correct.
const ifaceSel = { sender: new Set(), capture: new Set() };

function ifacePickerScope() {
  // 'capture' while the Capture tab is up, otherwise 'sender' (Control / Serial
  // share the sender NIC selection — sending from the Control SBF card etc.).
  return document.body.classList.contains('captureMode') ? 'capture' : 'sender';
}

function renderInterfacePickers() {
  renderOneIfacePicker('sender');
  renderOneIfacePicker('capture');
  mirrorIfaceSelectionToHiddenSelect();
}

function renderOneIfacePicker(scope) {
  const listId = scope === 'sender' ? 'senderIfaceList' : 'captureIfaceList';
  const countId = scope === 'sender' ? 'senderIfaceCount' : 'captureIfaceCount';
  const host = document.getElementById(listId);
  if (!host) return;
  if (!state.interfaces.length) {
    host.textContent = '— probe to load —';
    document.getElementById(countId).textContent = '0 selected';
    return;
  }
  const picked = ifaceSel[scope];
  host.innerHTML = state.interfaces.map((iface) => {
    const isChecked = picked.has(iface.name);
    const stateCls = iface.state === 'up' ? 'up' : iface.state === 'down' ? 'down' : 'unknown';
    const speed = iface.speedMbps ? `${iface.speedMbps} Mbps` : '';
    const ipv4 = (iface.ipv4 || [])[0];
    const ipText = ipv4 ? `${ipv4.local}/${ipv4.prefixlen}` : '';
    const extras = [speed, ipText].filter(Boolean).join(' · ');
    return `<label class="ifaceItem${isChecked ? ' checked' : ''}" data-iface="${iface.name}" data-scope="${scope}">
      <span class="ifaceCheck"></span>
      <input type="checkbox" value="${iface.name}"${isChecked ? ' checked' : ''}>
      <div class="ifaceMain">
        <div class="ifaceNameLine">
          <span class="ifaceName">${iface.name}</span>
          <span class="ifaceState ${stateCls}">${iface.state || '?'}</span>
        </div>
        <div class="ifaceMac">${iface.mac || '—'}</div>
        ${extras ? `<div class="ifaceExtras">${extras}</div>` : ''}
      </div>
    </label>`;
  }).join('');
  host.querySelectorAll('.ifaceItem').forEach((lab) => {
    lab.addEventListener('click', (e) => {
      // Avoid double-toggle when the inner checkbox itself emits a change.
      if (e.target.tagName === 'INPUT') return;
      e.preventDefault();
      toggleIface(scope, lab.dataset.iface);
    });
    lab.querySelector('input[type=checkbox]').addEventListener('change', () => {
      toggleIface(scope, lab.dataset.iface, true);
    });
  });
  document.getElementById(countId).textContent =
    `${picked.size}/${state.interfaces.length} selected`;
}

function toggleIface(scope, name, fromInputEvent = false) {
  const set = ifaceSel[scope];
  if (set.has(name)) set.delete(name); else set.add(name);
  renderOneIfacePicker(scope);
  if (scope === ifacePickerScope()) mirrorIfaceSelectionToHiddenSelect();
  if (scope === 'sender') autofillSenderFromPickedIface();
}

// When the user picks a NIC in the Sender picker, fill in Source MAC and
// Source IP from that NIC's properties — but only if the field is empty or
// matches the previously-picked NIC. Never clobber a value the user typed.
function autofillSenderFromPickedIface() {
  if (!document.body.classList.contains('senderMode')
      && document.body.classList.contains('captureMode')) return;
  const picked = Array.from(ifaceSel.sender)[0];
  if (!picked) return;
  const iface = state.interfaces.find((i) => i.name === picked);
  if (!iface) return;
  const srcMac = $('srcMac');
  const srcIp  = $('srcIp');
  if (srcMac && (!srcMac.value || srcMac.dataset.autofill === '1')) {
    srcMac.value = iface.mac || '';
    srcMac.dataset.autofill = '1';
  }
  if (srcIp && (!srcIp.value || srcIp.dataset.autofill === '1')) {
    const v4 = (iface.ipv4 || [])[0];
    srcIp.value = v4 ? v4.local : '';
    srcIp.dataset.autofill = '1';
  }
}
// Clear the autofill flag when the user actually types into the field.
document.addEventListener('input', (e) => {
  if (e.target && (e.target.id === 'srcMac' || e.target.id === 'srcIp')) {
    e.target.dataset.autofill = '';
  }
}, true);

function mirrorIfaceSelectionToHiddenSelect() {
  const sel = $('interfaceSelect');
  if (!sel) return;
  const scope = ifacePickerScope();
  const names = Array.from(ifaceSel[scope]);
  Array.from(sel.options).forEach((o) => { o.selected = names.includes(o.value); });
  sel.value = names[0] || '';
  sel.dispatchEvent(new Event('change', { bubbles: true }));
}

// Backward-compat shim — many call sites still call renderInterfaceCheckboxes().
function renderInterfaceCheckboxes() { renderInterfacePickers(); }

// Initial body-class state — Sender tab is active on load.
document.body.classList.add('senderMode');

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

function validateProfileFields() {
  const p = $('protocol').value;
  if (p === 'arp' || p === 'udp' || p === 'icmp') {
    if (!$('srcMac').value || !$('dstMac').value) return 'Source / Destination MAC is empty. Lock the peer in the top link strip, or fill manually.';
    if (p !== 'arp' && (!$('srcIp').value || !$('dstIp').value)) return 'Source / Destination IP is empty.';
  }
  return null;
}

async function build() {
  setStatus('Preparing frame preview...');
  const result = await api('/api/build', { method: 'POST', body: JSON.stringify(getProfile()) });
  showResult(result);
  setStatus(`Preview ready: ${result.stdout.decoded.length} bytes`);
}

async function send() {
  const err = validateProfileFields();
  if (err) { setStatus(err, true); toast(err, 'fail'); return; }
  const ifaces = selectedInterfaceNames();
  if (!ifaces.length) { setStatus('No interface selected', true); return; }
  if (ifaces.length === 1) {
    setStatus('Sending packet...');
    const result = await api('/api/send', { method: 'POST', body: JSON.stringify(getProfile()) });
    showResult(result);
    setStatus(`Sent ${result.stdout.framesSent} frame(s), ${result.stdout.bytesSent} bytes on ${ifaces[0]}`);
    return;
  }
  // Multi-interface fan-out: each NIC sends independently, with its own srcMac.
  setStatus(`Sending on ${ifaces.length} interface(s)...`);
  let totalFrames = 0, totalBytes = 0;
  const errors = [];
  for (const name of ifaces) {
    const iface = state.interfaces.find((i) => i.name === name);
    const profile = { ...getProfile(), interface: name, srcMac: iface?.mac || getProfile().srcMac };
    try {
      const r = await api('/api/send', { method: 'POST', body: JSON.stringify(profile) });
      totalFrames += Number(r.stdout?.framesSent || 0);
      totalBytes += Number(r.stdout?.bytesSent || 0);
      showResult(r);
    } catch (e) {
      errors.push(`${name}: ${e.message}`);
    }
  }
  if (errors.length) setStatus(`Sent ${totalFrames} frames across ${ifaces.length - errors.length}/${ifaces.length}; errors: ${errors.join('; ')}`, true);
  else setStatus(`Sent ${totalFrames} frames / ${totalBytes} bytes across ${ifaces.length} interfaces`);
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
}

async function runE2E() {
  if ($('runE2E').disabled) return;
  $('runE2E').disabled = true;
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
  } finally {
    $('runE2E').disabled = false;
  }
}

async function runReport() {
  if ($('runReport').disabled) return;
  $('runReport').disabled = true;
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
  } finally {
    $('runReport').disabled = false;
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
    if (button.dataset.view === 'serialView' && !state.serial.ports.length) refreshTtyList().catch(() => {});
    document.body.classList.toggle('captureMode', button.dataset.view === 'captureView');
    document.body.classList.toggle('serialMode', button.dataset.view === 'serialView');
    document.body.classList.toggle('controlMode', button.dataset.view === 'controlView');
    document.body.classList.toggle('senderMode', button.dataset.view === 'senderView');
    // When switching tabs, mirror the active tab's picker into the hidden
    // <select id=interfaceSelect> so legacy callers (send/capture handlers,
    // peer-locking code, localStorage) see the correct selection.
    mirrorIfaceSelectionToHiddenSelect();
  });
});

// ----------- Serial / TTY console -----------
state.serial = { ports: [], sessionId: null, reader: null, abort: null, rxCount: 0, txCount: 0 };

const HEX_ESCAPE_RE = /\\x([0-9a-fA-F]{2})/g;
function expandEscapes(s) {
  return s
    .replace(/\\r/g, '\r')
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\0/g, ' ')
    .replace(HEX_ESCAPE_RE, (_m, h) => String.fromCharCode(parseInt(h, 16)));
}

function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function appendSerialLog(text, cls) {
  const log = $('serialLog');
  if (!log) return;
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = text;
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
}

function renderRxBytes(bytes) {
  if ($('serialHex').checked) {
    appendSerialLog(bytesToHex(bytes).match(/.{1,2}/g).join(' ') + ' ');
  } else {
    let s = '';
    for (const b of bytes) {
      if (b === 0x0d) continue;             // collapse CRLF for terminal feel
      if (b === 0x0a) { s += '\n'; continue; }
      if (b === 0x09) { s += '\t'; continue; }
      if (b >= 0x20 && b < 0x7f) s += String.fromCharCode(b);
      else s += `·`; // middle dot for non-printable
    }
    appendSerialLog(s);
  }
}

async function refreshTtyList() {
  const r = await api('/api/tty/list');
  state.serial.ports = r.ttys || [];
  const sel = $('serialPort');
  if (!state.serial.ports.length) {
    sel.innerHTML = '<option value="">no TTY found (plug in a USB serial adapter and click ↻)</option>';
    $('serialPortHint').textContent = 'No /dev/tty(USB|ACM)* devices visible. Plug in a USB-serial / FTDI / CDC-ACM adapter and refresh.';
    return;
  }
  sel.innerHTML = state.serial.ports.map((p) => {
    const label = [p.name, p.usbProduct || p.product || p.driver, p.usbId, p.serial]
      .filter(Boolean).join(' · ');
    return `<option value="${p.path}">${label}</option>`;
  }).join('');
  const sel0 = state.serial.ports[0];
  $('serialPortHint').textContent = `${sel0.path}  ${sel0.manufacturer || ''} ${sel0.usbProduct || ''} ${sel0.usbId ? '['+sel0.usbId+']' : ''}`.trim();
  sel.addEventListener('change', () => {
    const p = state.serial.ports.find((x) => x.path === sel.value);
    if (!p) return;
    $('serialPortHint').textContent = `${p.path}  ${p.manufacturer || ''} ${p.usbProduct || ''} ${p.usbId ? '['+p.usbId+']' : ''}`.trim();
  }, { once: true });
}

async function serialConnect() {
  if (state.serial.sessionId) return;
  const path = $('serialPort').value;
  if (!path) { toast('Pick a TTY first.','warn'); return; }
  state.serial.rxCount = 0; state.serial.txCount = 0;
  $('serRx').textContent = '0'; $('serTx').textContent = '0';
  $('serState').textContent = 'opening…'; $('serState').className = 'statChip';
  try {
    const r = await api('/api/tty/open', {
      method: 'POST',
      body: JSON.stringify({
        path,
        baudRate: Number($('serialBaud').value),
        dataBits: Number($('serialData').value),
        parity: $('serialParity').value,
        stopBits: Number($('serialStop').value),
        hwFlow: $('serialFlow').checked
      })
    });
    state.serial.sessionId = r.sessionId;
  } catch (err) {
    appendSerialLog(`open failed: ${err.message}\n`, 'err');
    $('serState').textContent = 'idle';
    return;
  }
  $('serialConnect').disabled = true;
  $('serialDisconnect').disabled = false;
  $('serialInput').disabled = false;
  $('serialBreak').disabled = false;
  $('serState').textContent = 'connected';
  $('serState').className = 'statChip connected';
  appendSerialLog(`-- opened ${path} @ ${$('serialBaud').value} ${$('serialData').value}${$('serialParity').value}${$('serialStop').value} --\n`, 'info');

  const ctrl = new AbortController();
  state.serial.abort = ctrl;
  const res = await fetch(`/api/tty/stream?session=${state.serial.sessionId}`, { signal: ctrl.signal });
  const reader = res.body.getReader();
  state.serial.reader = reader;
  const dec = new TextDecoder();
  let buf = '';
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
        let ev; try { ev = JSON.parse(line); } catch { continue; }
        if (ev.type === 'rx' && ev.hex) {
          const bytes = hexToBytes(ev.hex);
          state.serial.rxCount += bytes.length;
          $('serRx').textContent = state.serial.rxCount;
          renderRxBytes(bytes);
        } else if (ev.type === 'error') {
          appendSerialLog(`[err] ${ev.message}\n`, 'err');
        } else if (ev.type === 'closed') {
          appendSerialLog(`-- closed --\n`, 'info');
        }
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError') appendSerialLog(`[stream err] ${err.message}\n`, 'err');
  } finally {
    serialFinish();
  }
}

function serialFinish() {
  state.serial.sessionId = null;
  state.serial.reader = null;
  state.serial.abort = null;
  $('serialConnect').disabled = false;
  $('serialDisconnect').disabled = true;
  $('serialInput').disabled = true;
  $('serialBreak').disabled = true;
  $('serState').textContent = 'idle';
  $('serState').className = 'statChip';
}

async function serialDisconnect() {
  if (!state.serial.sessionId) return;
  const id = state.serial.sessionId;
  try { state.serial.abort?.abort(); } catch {}
  try { state.serial.reader?.cancel(); } catch {}
  try { await api('/api/tty/close', { method: 'POST', body: JSON.stringify({ sessionId: id }) }); } catch {}
  serialFinish();
}

async function serialSendInput() {
  if (!state.serial.sessionId) return;
  const inp = $('serialInput');
  const eol = $('serialEol').value;
  const text = expandEscapes(inp.value) + expandEscapes(eol);
  if (!text) return;
  const enc = new TextEncoder();
  const bytes = enc.encode(text);
  const hex = bytesToHex(bytes);
  try {
    await api('/api/tty/write', { method: 'POST', body: JSON.stringify({ sessionId: state.serial.sessionId, hex }) });
    state.serial.txCount += bytes.length;
    $('serTx').textContent = state.serial.txCount;
    if ($('serialEcho').checked) appendSerialLog(`> ${inp.value}\n`, 'tx');
    inp.value = '';
  } catch (err) {
    appendSerialLog(`tx fail: ${err.message}\n`, 'err');
  }
}

$('serialRefresh')?.addEventListener('click', () => refreshTtyList().catch((e) => toastError(e)));
$('serialConnect')?.addEventListener('click', () => serialConnect().catch((e) => { toastError(e); }));
$('serialDisconnect')?.addEventListener('click', () => serialDisconnect());
$('serialClear')?.addEventListener('click', () => { $('serialLog').innerHTML = ''; });
$('serialBreak')?.addEventListener('click', async () => {
  if (!state.serial.sessionId) return;
  try { await api('/api/tty/control', { method:'POST', body: JSON.stringify({ sessionId: state.serial.sessionId, cmd: 'break' }) }); appendSerialLog('-- break --\n', 'info'); } catch {}
});
$('serialInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); serialSendInput().catch(() => {}); }
});

$('refreshInterfaces').addEventListener('click', () => loadInterfaces().catch((err) => {
  toastError(err);
}));
$('interfaceSelect').addEventListener('change', updateInterfaceInfo);
$('build').addEventListener('click', () => build().catch((err) => {
  toastError(err);
}));

// Auto-preview: rebuild the frame whenever the operator changes any sender input.
// Debounced so rapid typing doesn't spam the agent.
let _previewTimer = null;
function schedulePreview() {
  clearTimeout(_previewTimer);
  _previewTimer = setTimeout(() => {
    // Persist the live form state back into the selected Packet List step
    // so subsequent row clicks reload the user's edits, not the original profile.
    if (state.currentCase && state.selectedStep >= 0) {
      const step = state.currentCase.steps[state.selectedStep];
      if (step?.kind === 'packet') {
        const live = getProfile();
        step.profile = { ...step.profile, ...live };
        $('caseStepPreview').textContent = JSON.stringify(step, null, 2);
      }
    }
    build().catch(() => {});
  }, 250);
}
const SENDER_INPUT_IDS = [
  'protocol','dstMac','srcMac','srcIp','dstIp','srcPort','dstPort',
  'vlanEnabled','vlanId','vlanPriority',
  'payloadMode','payload','payloadSize','payloadByte','targetFrameLength'
];
SENDER_INPUT_IDS.forEach((id) => {
  const el = $(id); if (!el) return;
  const ev = (el.tagName === 'SELECT' || el.type === 'checkbox') ? 'change' : 'input';
  el.addEventListener(ev, schedulePreview);
});
$('send').addEventListener('click', () => send().catch((err) => {
  toastError(err);
}));
$('captureStart').addEventListener('click', () => startCaptureStream().catch((err) => {
  toastError(err);
}));
// Event delegation: one listener for the whole packet table replaces
// per-row listeners (which scaled O(N) and held memory for evicted rows).
$('packetRows')?.addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-idx]');
  if (tr) selectPacket(Number(tr.dataset.idx));
});
$('captureStop').addEventListener('click', stopCaptureStream);
$('captureClear').addEventListener('click', clearCapture);
function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('captureSavePcap')?.addEventListener('click', () => {
  if (!capture.packets.length) { toast('No packets buffered yet — start a capture first.','warn'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  downloadBlob(buildPcap(capture.packets), `keti-capture-${ts}.pcap`);
});
$('captureSavePcapNg')?.addEventListener('click', () => {
  if (!capture.packets.length) { toast('No packets buffered yet — start a capture first.','warn'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  downloadBlob(buildPcapNg(capture.packets), `keti-capture-${ts}.pcapng`);
});

// --- Open .pcap / .pcapng client-side ---------------------------------
$('captureOpenPcap')?.addEventListener('click', () => $('pcapFileInput')?.click());
$('pcapFileInput')?.addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  if (file) await loadPcapFile(file);
  e.target.value = '';
});

async function loadPcapFile(file) {
  if (capture.reader) {
    toast('Stop the live capture first before opening a file.', 'warn');
    return;
  }
  try {
    const buf = await file.arrayBuffer();
    const frames = parsePcapOrPcapNg(new DataView(buf));
    if (!frames.length) { toast(`${file.name}: no frames parsed.`, 'warn'); return; }
    clearCapture();
    let i = 0;
    for (const f of frames) {
      f._idx = i++;
      f.frameHex = f.frameHex || bytesToHex(new Uint8Array(buf, f._dataOffset, f._dataLength));
      f.length = f.frameHex.length / 2;
      // decode in-browser using a slim decoder for at least Ethernet headers;
      // we keep the bytes raw and let the existing UI decode through the
      // existing path (decoded already attached if we have it).
      f.decoded = clientDecode(hexToBytes(f.frameHex));
      capture.packets.push(f);
      capture.totalBytes += f.length;
      if (capture.packets.length > capture.maxBuffer) capture.packets.shift();
    }
    reapplyFilter();
    $('capStatState').textContent = `file · ${frames.length} frames`;
    $('capStatState').className = 'statChip ok';
    toast(`Loaded ${frames.length} frames from ${file.name}`, 'ok');
  } catch (err) {
    toast(`Failed to parse ${file.name}: ${err.message}`, 'fail');
  }
}

// Minimal browser-side decoder (subset of agent decoder, enough for the
// list view + hex highlighting). Covers Ethernet / VLAN / IPv4 / IPv6 /
// UDP / TCP / ICMP / ARP / LLDP / PTP at top level. Server-side decoder
// is still richer; this is "good enough for an offline pcap viewer".
function clientDecode(b) {
  if (b.length < 14) return { length: b.length };
  const macStr = (off) => Array.from(b.slice(off, off + 6)).map((x) => x.toString(16).padStart(2, '0')).join(':');
  const decoded = {
    length: b.length,
    ethernet: { dstMac: macStr(0), srcMac: macStr(6), etherType: '0x' + ((b[12] << 8) | b[13]).toString(16).padStart(4, '0') },
  };
  let off = 14;
  let etype = (b[12] << 8) | b[13];
  if (etype === 0x8100 || etype === 0x88a8) {
    const tci = (b[14] << 8) | b[15];
    decoded.vlan = { tpid: '0x' + etype.toString(16), priority: (tci >> 13) & 0x7, dei: !!(tci & 0x1000), id: tci & 0xfff, etherType: '0x' + ((b[16] << 8) | b[17]).toString(16).padStart(4, '0') };
    etype = (b[16] << 8) | b[17];
    off = 18;
  }
  if (etype === 0x0800 && b.length >= off + 20) {
    const ihl = (b[off] & 0x0f) * 4;
    decoded.ipv4 = {
      src: `${b[off + 12]}.${b[off + 13]}.${b[off + 14]}.${b[off + 15]}`,
      dst: `${b[off + 16]}.${b[off + 17]}.${b[off + 18]}.${b[off + 19]}`,
      ttl: b[off + 8], protocol: b[off + 9],
    };
    const l4 = off + ihl;
    const proto = b[off + 9];
    if (proto === 17 && b.length >= l4 + 8) {
      decoded.udp = { srcPort: (b[l4] << 8) | b[l4 + 1], dstPort: (b[l4 + 2] << 8) | b[l4 + 3], length: (b[l4 + 4] << 8) | b[l4 + 5] };
    } else if (proto === 6 && b.length >= l4 + 20) {
      const offflags = (b[l4 + 12] << 8) | b[l4 + 13];
      const flagBits = [[0x100, 'NS'], [0x80, 'CWR'], [0x40, 'ECE'], [0x20, 'URG'], [0x10, 'ACK'], [0x8, 'PSH'], [0x4, 'RST'], [0x2, 'SYN'], [0x1, 'FIN']];
      decoded.tcp = {
        srcPort: (b[l4] << 8) | b[l4 + 1], dstPort: (b[l4 + 2] << 8) | b[l4 + 3],
        seq: ((b[l4 + 4] << 24) >>> 0) + (b[l4 + 5] << 16) + (b[l4 + 6] << 8) + b[l4 + 7],
        ack: ((b[l4 + 8] << 24) >>> 0) + (b[l4 + 9] << 16) + (b[l4 + 10] << 8) + b[l4 + 11],
        flags: flagBits.filter(([m]) => offflags & m).map(([, n]) => n),
        window: (b[l4 + 14] << 8) | b[l4 + 15], dataOffset: ((offflags >> 12) & 0xf) * 4,
      };
    } else if (proto === 1 && b.length >= l4 + 8) {
      decoded.icmp = { type: b[l4], code: b[l4 + 1], id: (b[l4 + 4] << 8) | b[l4 + 5], seq: (b[l4 + 6] << 8) | b[l4 + 7] };
    }
  } else if (etype === 0x86dd && b.length >= off + 40) {
    const v6 = (start) => {
      const parts = [];
      for (let i = 0; i < 8; i += 1) parts.push(((b[start + i * 2] << 8) | b[start + i * 2 + 1]).toString(16));
      // simple :: collapse for one longest zero run
      const s = parts.join(':');
      return s.replace(/(^|:)(?:0:){2,}/, '::').replace(/^0::/, '::').replace(/::0$/, '::');
    };
    decoded.ipv6 = { src: v6(off + 8), dst: v6(off + 24), hopLimit: b[off + 7], nextHeader: b[off + 6] };
  } else if (etype === 0x0806 && b.length >= off + 28) {
    decoded.arp = {
      operation: (b[off + 6] << 8) | b[off + 7],
      senderMac: macStr(off + 8), senderIp: `${b[off + 14]}.${b[off + 15]}.${b[off + 16]}.${b[off + 17]}`,
      targetMac: macStr(off + 18), targetIp: `${b[off + 24]}.${b[off + 25]}.${b[off + 26]}.${b[off + 27]}`,
    };
  } else if (etype === 0x88cc) decoded.lldp = { tlvs: [] };
  else if (etype === 0x88f7) decoded.ptp = { messageType: b[off] & 0xf };
  return decoded;
}

// libpcap / pcap-ng parser. Returns array of { timestamp, rxTimestampNs, frameHex, length }.
function parsePcapOrPcapNg(view) {
  const magic = view.getUint32(0, true);
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d || magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    return parsePcap(view, magic);
  }
  if (magic === 0x0a0d0d0a) return parsePcapNg(view);
  throw new Error(`unknown magic 0x${magic.toString(16)}`);
}

function parsePcap(view, magic) {
  const LE = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const nanoTs = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  // skip 24-byte global header
  let off = 24;
  const out = [];
  while (off + 16 <= view.byteLength) {
    const sec = view.getUint32(off, LE);
    const subsec = view.getUint32(off + 4, LE);
    const captured = view.getUint32(off + 8, LE);
    off += 16;
    if (off + captured > view.byteLength) break;
    const ns = BigInt(sec) * 1_000_000_000n + BigInt(subsec) * (nanoTs ? 1n : 1000n);
    out.push({ rxTimestampNs: Number(ns), timestamp: Number(ns) / 1e9, _dataOffset: view.byteOffset + off, _dataLength: captured });
    off += captured;
  }
  return out;
}

function parsePcapNg(view) {
  // Section Header Block + Interface Description Blocks + Enhanced/Simple Packet Blocks.
  const out = [];
  let off = 0;
  let tsResol = 6; // default: microseconds (10^-6) per pcapng spec
  while (off + 12 <= view.byteLength) {
    const blockType = view.getUint32(off, true);
    const blockLen = view.getUint32(off + 4, true);
    if (blockLen < 12 || off + blockLen > view.byteLength) break;
    if (blockType === 0x00000001) {
      // IDB — parse options to find if_tsresol
      let p = off + 16; // 8 hdr + 8 (linktype+reserved+snaplen)
      const end = off + blockLen - 4;
      while (p + 4 <= end) {
        const code = view.getUint16(p, true);
        const len = view.getUint16(p + 2, true);
        if (code === 0) break;
        if (code === 9 && len >= 1) {
          const raw = view.getUint8(p + 4);
          tsResol = raw & 0x80 ? (raw & 0x7f) : raw; // bit7 set means base-2; we treat as exponent
        }
        p += 4 + Math.ceil(len / 4) * 4;
      }
    } else if (blockType === 0x00000006 || blockType === 0x00000003) {
      // EPB or SPB
      let dataOff, dataLen, tsNs;
      if (blockType === 0x00000006) {
        const tsHi = view.getUint32(off + 12, true);
        const tsLo = view.getUint32(off + 16, true);
        dataLen = view.getUint32(off + 20, true);
        dataOff = off + 28;
        const tick = BigInt((tsHi >>> 0)) * 0x100000000n + BigInt(tsLo >>> 0);
        // tick × 10^-tsResol seconds → nanoseconds:  ns = tick × 10^(9 - tsResol)
        const expo = 9 - tsResol;
        tsNs = expo >= 0 ? Number(tick * BigInt(10 ** expo)) : Number(tick / BigInt(10 ** -expo));
      } else {
        dataLen = view.getUint32(off + 8, true);
        dataOff = off + 12;
        tsNs = 0;
      }
      if (dataOff + dataLen <= off + blockLen - 4) {
        out.push({ rxTimestampNs: tsNs, timestamp: tsNs / 1e9, _dataOffset: view.byteOffset + dataOff, _dataLength: dataLen });
      }
    }
    off += blockLen;
  }
  return out;
}

// Drag & drop support: drop a .pcap or .pcapng onto the capture pane.
(function attachPcapDnd() {
  const tgt = document.getElementById('captureView');
  if (!tgt) return;
  let depth = 0;
  tgt.addEventListener('dragenter', (e) => { e.preventDefault(); depth += 1; tgt.classList.add('dropping'); });
  tgt.addEventListener('dragover',  (e) => { e.preventDefault(); });
  tgt.addEventListener('dragleave', (e) => { e.preventDefault(); depth -= 1; if (depth <= 0) tgt.classList.remove('dropping'); });
  tgt.addEventListener('drop',      (e) => {
    e.preventDefault(); depth = 0; tgt.classList.remove('dropping');
    const f = e.dataTransfer?.files?.[0];
    if (f) loadPcapFile(f);
  });
})();

// Build a libpcap-format file from buffered frames.
// Global header (24 B) + per-packet record (16 B + frame bytes).
// Magic 0xa1b2c3d4 (microsecond timestamps, big-endian write but we use little-endian magic).
function buildPcap(packets) {
  // Compute total size
  let total = 24;
  for (const p of packets) total += 16 + (p.frameHex.length / 2);
  const buf = new ArrayBuffer(total);
  const view = new DataView(buf);
  // Global header — little-endian magic 0xa1b2c3d4 means LE byte order, microsecond resolution
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);          // version major
  view.setUint16(6, 4, true);          // version minor
  view.setInt32(8, 0, true);           // thiszone (GMT)
  view.setUint32(12, 0, true);         // sigfigs
  view.setUint32(16, 65535, true);     // snaplen
  view.setUint32(20, 1, true);         // LINKTYPE_ETHERNET
  let off = 24;
  for (const p of packets) {
    const ns = p.rxTimestampNs ?? Math.round((p.timestamp || 0) * 1e9);
    const sec = Math.floor(ns / 1_000_000_000);
    const usec = Math.floor((ns % 1_000_000_000) / 1000);
    const len = p.frameHex.length / 2;
    view.setUint32(off, sec, true);
    view.setUint32(off + 4, usec, true);
    view.setUint32(off + 8, len, true);   // captured length
    view.setUint32(off + 12, len, true);  // original length
    off += 16;
    for (let i = 0; i < len; i += 1) {
      view.setUint8(off + i, parseInt(p.frameHex.substr(i * 2, 2), 16));
    }
    off += len;
  }
  return new Blob([buf], { type: 'application/vnd.tcpdump.pcap' });
}

// PCAP-NG (next-generation, RFC-draft format that Wireshark prefers).
// Keeps full nanosecond precision via the if_tsresol option = 9 (10^-9 s).
// We emit one Section Header Block + one Interface Description Block with
// link_type Ethernet + snaplen 65535 + tsresol=9 + a friendly if_name option,
// then one Enhanced Packet Block per captured frame. Packet data is padded to
// a 4-byte boundary as the spec requires.
function buildPcapNg(packets) {
  const enc = new TextEncoder();
  const ifName = enc.encode('keti-lab-capture');
  const pad4 = (n) => (4 - (n & 3)) & 3;

  // Section Header Block (Block Type 0x0a0d0d0a) — version 1.0, section length unknown (-1)
  const shbBody = 28; // BT(4)+TotalLen(4)+ByteOrderMagic(4)+Major(2)+Minor(2)+SectionLen(8)+TotalLen(4)
  const shb = new ArrayBuffer(shbBody);
  const shbV = new DataView(shb);
  shbV.setUint32(0, 0x0a0d0d0a, true);  // Block Type
  shbV.setUint32(4, shbBody, true);     // Block Total Length
  shbV.setUint32(8, 0x1a2b3c4d, true);  // Byte-Order Magic
  shbV.setUint16(12, 1, true);          // Major version
  shbV.setUint16(14, 0, true);          // Minor version
  shbV.setBigInt64(16, -1n, true);      // Section length: unknown
  shbV.setUint32(24, shbBody, true);    // Block Total Length (trailer)

  // Interface Description Block (BT 0x00000001)
  // Body: link_type(2) reserved(2) snaplen(4) [options...]
  // Options: if_name (code 2), if_tsresol (code 9, length 1, value 9 (ns))
  // Each option header: code(2) length(2) value(padded to 4)
  const ifNameOptLen = 4 + ifName.length + pad4(ifName.length);
  const ifTsResOptLen = 4 + 1 + 3; // code+len+value(1)+pad(3) = 8
  const optEnd = 4; // opt_endofopt code 0 length 0
  const idbBodyLen = 8 + ifNameOptLen + ifTsResOptLen + optEnd; // 8 = link_type+reserved+snaplen
  const idbTotal = 4 + 4 + idbBodyLen + 4; // BT + Total + body + Total trailer
  const idb = new ArrayBuffer(idbTotal);
  const idbV = new DataView(idb);
  let p = 0;
  idbV.setUint32(p, 0x00000001, true); p += 4; // BT IDB
  idbV.setUint32(p, idbTotal, true);   p += 4;
  idbV.setUint16(p, 1, true);          p += 2; // LinkType: LINKTYPE_ETHERNET
  idbV.setUint16(p, 0, true);          p += 2; // Reserved
  idbV.setUint32(p, 65535, true);      p += 4; // SnapLen
  // if_name option (code 2)
  idbV.setUint16(p, 2, true);          p += 2;
  idbV.setUint16(p, ifName.length, true); p += 2;
  new Uint8Array(idb, p, ifName.length).set(ifName); p += ifName.length;
  p += pad4(ifName.length);
  // if_tsresol option (code 9): 1 byte = 9 (powers-of-ten resolution, 10^-9 = ns)
  idbV.setUint16(p, 9, true);          p += 2;
  idbV.setUint16(p, 1, true);          p += 2;
  idbV.setUint8 (p, 9);                p += 1;
  p += 3; // pad to 4
  // opt_endofopt (code 0, len 0)
  idbV.setUint16(p, 0, true);          p += 2;
  idbV.setUint16(p, 0, true);          p += 2;
  idbV.setUint32(p, idbTotal, true);            // trailer

  // Enhanced Packet Blocks
  const epbs = [];
  for (const pk of packets) {
    const ns = pk.rxTimestampNs ?? Math.round((pk.timestamp || 0) * 1e9);
    const len = pk.frameHex.length / 2;
    const padLen = pad4(len);
    const total = 4 + 4 + 4 + 4 + 4 + 4 + 4 + len + padLen + 4;
    // BT(4)+Total(4)+IfaceID(4)+TsHi(4)+TsLo(4)+CapLen(4)+OrigLen(4)+data+pad+TotalTrailer(4)
    const buf = new ArrayBuffer(total);
    const v = new DataView(buf);
    let q = 0;
    v.setUint32(q, 0x00000006, true); q += 4; // BT EPB
    v.setUint32(q, total, true);      q += 4;
    v.setUint32(q, 0, true);          q += 4; // Interface ID 0
    // 64-bit ns timestamp split into high/low for endian-safe write
    const big = BigInt(ns);
    v.setUint32(q,     Number(big >> 32n) >>> 0, true); q += 4; // tsHigh
    v.setUint32(q,     Number(big & 0xffffffffn) >>> 0, true); q += 4; // tsLow
    v.setUint32(q, len, true);        q += 4; // captured len
    v.setUint32(q, len, true);        q += 4; // original len
    const u8 = new Uint8Array(buf, q, len);
    for (let i = 0; i < len; i += 1) u8[i] = parseInt(pk.frameHex.substr(i * 2, 2), 16);
    q += len + padLen;
    v.setUint32(q, total, true);      // trailer
    epbs.push(buf);
  }

  return new Blob([shb, idb, ...epbs], { type: 'application/x-pcapng' });
}
$('captureDisplayFilter').addEventListener('input', () => {
  // debounce
  clearTimeout(window._capFilterTimer);
  window._capFilterTimer = setTimeout(reapplyFilter, 120);
});
$('runReport').addEventListener('click', () => runReport().catch((err) => {
  toastError(err);
}));
$('runE2E').addEventListener('click', () => runE2E().catch((err) => {
  toastError(err);
}));

// ----------- Simple Bidirectional Forwarding Test (Control tab) -----------
const sbf = { a: { interfaces: [] }, b: { interfaces: [] }, local: { interfaces: [] } };
function sbfIsSinglePc() { return $('sbfSinglePc')?.checked === true; }
function sbfLocalUrl() { return window.location.origin; }

function sbfFillSelect(selectId, interfaces, fallbackIndex) {
  const sel = $(selectId);
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = '<option value="">— select —</option>' + interfaces.map((iface) =>
    `<option value="${iface.name}">${iface.name} — ${iface.mac || '?'}${iface.state === 'up' ? ' · up' : ''}</option>`
  ).join('');
  if (prev && interfaces.find((i) => i.name === prev)) sel.value = prev;
  else if (fallbackIndex != null && interfaces[fallbackIndex]) sel.value = interfaces[fallbackIndex].name;
}

function sbfPrimary(side) {
  const sel = $(side === 'a' ? 'sbfNodeAPrimary' : 'sbfNodeBPrimary');
  return sbf[side].interfaces.find((i) => i.name === sel.value) || null;
}
function sbfMonitor(side) {
  const sel = $(side === 'a' ? 'sbfNodeAMonitor' : 'sbfNodeBMonitor');
  return sbf[side].interfaces.find((i) => i.name === sel.value) || null;
}
function sbfMonitor2(side) {
  const sel = $(side === 'a' ? 'sbfNodeAMonitor2' : 'sbfNodeBMonitor2');
  return sbf[side].interfaces.find((i) => i.name === sel.value) || null;
}
function sbfMonitorList(side) {
  const seen = new Set();
  const primary = sbfPrimary(side)?.name;
  return [sbfMonitor(side), sbfMonitor2(side)]
    .filter((m) => m && m.name !== primary && !seen.has(m.name) && (seen.add(m.name), true));
}

function sbfSyncTopology() {
  if (sbfIsSinglePc()) {
    const url = sbfLocalUrl();
    $('sbfTopoAUrl').textContent = url + ' (this PC)';
    $('sbfTopoBUrl').textContent = url + ' (this PC)';
    const s = sbfUnifiedSend(), r = sbfUnifiedRecv(), mons = sbfUnifiedMonitors();
    $('sbfTopoAPrimary').innerHTML  = `<span class="sbfBadge sbf-primary">Send</span> ${s ? `${s.name} <small style="color:var(--muted)">${s.mac}</small>` : '—'}`;
    $('sbfTopoAMonitors').innerHTML = `<span class="sbfBadge sbf-monitor">Monitors (${mons.length})</span> ${mons.length ? mons.map((m) => m.name).join(', ') : '—'}`;
    $('sbfTopoBPrimary').innerHTML  = `<span class="sbfBadge sbf-primary">Receive</span> ${r ? `${r.name} <small style="color:var(--muted)">${r.mac}</small>` : '—'}`;
    $('sbfTopoBMonitors').innerHTML = `<span class="sbfBadge sbf-monitor">(all captures on this PC)</span>`;
    return;
  }
  $('sbfTopoAUrl').textContent = $('sbfNodeAUrl').value || '-';
  $('sbfTopoBUrl').textContent = $('sbfNodeBUrl').value || '-';
  $('sbfNodeAEcho').textContent = $('sbfNodeAUrl').value || '';
  $('sbfNodeBEcho').textContent = $('sbfNodeBUrl').value || '';
  const ap = sbfPrimary('a'), bp = sbfPrimary('b');
  const aMons = sbfMonitorList('a'), bMons = sbfMonitorList('b');
  $('sbfTopoAPrimary').innerHTML = `<span class="sbfBadge sbf-primary">Primary</span> ${ap ? `${ap.name} <small style="color:var(--muted)">${ap.mac}</small>` : '—'}`;
  $('sbfTopoAMonitors').innerHTML = `<span class="sbfBadge sbf-monitor">Monitors</span> ${aMons.length ? aMons.map((m) => m.name).join(', ') : '—'}`;
  $('sbfTopoBPrimary').innerHTML = `<span class="sbfBadge sbf-primary">Primary</span> ${bp ? `${bp.name} <small style="color:var(--muted)">${bp.mac}</small>` : '—'}`;
  $('sbfTopoBMonitors').innerHTML = `<span class="sbfBadge sbf-monitor">Monitors</span> ${bMons.length ? bMons.map((m) => m.name).join(', ') : '—'}`;
}

async function sbfProbe() {
  setActionStatus('sbfProbeStatus', 'running', 'probing...');
  $('sbfProbe').disabled = true;
  try {
    if (sbfIsSinglePc()) {
      const url = sbfLocalUrl();
      const r = await api('/api/probe-node', { method: 'POST', body: JSON.stringify({ url }) });
      sbf.local.interfaces = r.interfaces;
      sbfRenderUnifiedTable(r.interfaces);
      sbfSyncTopology();
      setActionStatus('sbfProbeStatus', 'ok', `local: ${r.interfaces.length} IF`);
      return;
    }
    const aUrl = $('sbfNodeAUrl').value.trim();
    const bUrl = $('sbfNodeBUrl').value.trim();
    if (!aUrl || !bUrl) throw new Error('Node A URL과 Node B URL을 모두 입력하세요.');
    const [a, b] = await Promise.all([
      api('/api/probe-node', { method: 'POST', body: JSON.stringify({ url: aUrl }) }),
      api('/api/probe-node', { method: 'POST', body: JSON.stringify({ url: bUrl }) })
    ]);
    sbf.a.interfaces = a.interfaces;
    sbf.b.interfaces = b.interfaces;
    const realA = a.interfaces.findIndex((i) => !/^(lo|docker|veth|br|virbr|tap|wlan|wlp|wlx)/.test(i.name));
    const realB = b.interfaces.findIndex((i) => !/^(lo|docker|veth|br|virbr|tap|wlan|wlp|wlx)/.test(i.name));
    sbfFillSelect('sbfNodeAPrimary',  a.interfaces, realA >= 0 ? realA : 0);
    sbfFillSelect('sbfNodeAMonitor',  a.interfaces, realA + 1 < a.interfaces.length ? realA + 1 : null);
    sbfFillSelect('sbfNodeAMonitor2', a.interfaces, realA + 2 < a.interfaces.length ? realA + 2 : null);
    sbfFillSelect('sbfNodeBPrimary',  b.interfaces, realB >= 0 ? realB : 0);
    sbfFillSelect('sbfNodeBMonitor',  b.interfaces, realB + 1 < b.interfaces.length ? realB + 1 : null);
    sbfFillSelect('sbfNodeBMonitor2', b.interfaces, realB + 2 < b.interfaces.length ? realB + 2 : null);
    sbfSyncTopology();
    setActionStatus('sbfProbeStatus', 'ok', `A: ${a.interfaces.length} IF · B: ${b.interfaces.length} IF`);
  } finally {
    $('sbfProbe').disabled = false;
  }
}

function sbfSingleSender() { return sbf.local.interfaces.find((i) => i.name === $('sbfSingleSender').value) || null; }
function sbfSingleReceiver() { return sbf.local.interfaces.find((i) => i.name === $('sbfSingleReceiver').value) || null; }
function sbfSingleMonitors() {
  const seen = new Set();
  const used = new Set([sbfSingleSender()?.name, sbfSingleReceiver()?.name]);
  return [$('sbfSingleMonitor').value, $('sbfSingleMonitor2').value]
    .map((n) => sbf.local.interfaces.find((i) => i.name === n))
    .filter((m) => m && !used.has(m.name) && !seen.has(m.name) && (seen.add(m.name), true));
}

function sbfSetSinglePcMode(on) {
  $('sbfTwoPcUrls').style.display = on ? 'none' : '';
  $('sbfSinglePcUrl').style.display = on ? '' : 'none';
  $('sbfUnifiedBlock').style.display = on ? '' : 'none';
  $('sbfTwoPcIfaces').style.display = on ? 'none' : '';
  const btnBoth = $('sbfRunBoth'); const btnBtoA = $('sbfRunBtoA');
  if (on) {
    if (btnBoth) btnBoth.style.display = 'none';
    if (btnBtoA) btnBtoA.style.display = 'none';
    $('sbfRunAtoB').textContent = '▶ Run (Send → Receive)';
    $('sbfLocalUrl').value = sbfLocalUrl();
    $('sbfUnifiedEcho').textContent = sbfLocalUrl();
  } else {
    if (btnBoth) btnBoth.style.display = '';
    if (btnBtoA) btnBtoA.style.display = '';
    $('sbfRunAtoB').textContent = '▶ Run A to B';
  }
  sbfSyncTopology();
}

function sbfRenderUnifiedTable(interfaces) {
  const tbody = $('sbfUnifiedTable').querySelector('tbody');
  if (!interfaces.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:12px">Probe Nodes 누른 뒤 인터페이스가 표시됩니다.</td></tr>';
    return;
  }
  // Auto-select defaults: first non-virtual = Send, next = Receive
  const real = interfaces.findIndex((i) => !/^(lo|docker|veth|br|virbr|tap|wlan|wlp|wlx)/.test(i.name));
  tbody.innerHTML = interfaces.map((iface, idx) => {
    const isSend = idx === real;
    const isRecv = idx === real + 1;
    return `<tr>
      <td class="name">${iface.name}</td>
      <td class="mac">${iface.mac || '—'}</td>
      <td class="state">${iface.state || ''}</td>
      <td style="text-align:center"><input type="radio" name="sbfUSend" value="${iface.name}"${isSend ? ' checked' : ''}></td>
      <td style="text-align:center"><input type="radio" name="sbfURecv" value="${iface.name}"${isRecv ? ' checked' : ''}></td>
      <td style="text-align:center"><input type="checkbox" class="sbfUMon" value="${iface.name}"></td>
    </tr>`;
  }).join('');
  tbody.querySelectorAll('input').forEach((el) => el.addEventListener('change', sbfSyncTopology));
}

function sbfUnifiedSend() {
  const v = document.querySelector('input[name=sbfUSend]:checked')?.value;
  return sbf.local.interfaces.find((i) => i.name === v) || null;
}
function sbfUnifiedRecv() {
  const v = document.querySelector('input[name=sbfURecv]:checked')?.value;
  return sbf.local.interfaces.find((i) => i.name === v) || null;
}
function sbfUnifiedMonitors() {
  const used = new Set([sbfUnifiedSend()?.name, sbfUnifiedRecv()?.name]);
  return Array.from(document.querySelectorAll('input.sbfUMon:checked'))
    .map((el) => sbf.local.interfaces.find((i) => i.name === el.value))
    .filter((m) => m && !used.has(m.name));
}

function sbfRenderResult(report) {
  const el = $('sbfResult');
  el.classList.remove('hidden');
  const overallCls = report.overall === 'PASS' ? 'pass' : 'fail';
  const dirs = report.directions.map((d) => {
    const capRows = d.captures.map((c) => `
      <tr class="${c.pass ? 'pass' : 'fail'}">
        <td>${c.role}</td>
        <td>${c.node}</td>
        <td><code>${c.interface.name}</code></td>
        <td><code>${c.interface.mac}</code></td>
        <td>${c.expectMatch ? '≥ ' + d.count : '== 0'}</td>
        <td>${c.matched}</td>
        <td><span class="sbfBadge ${c.pass ? 'sbf-primary' : 'sbf-monitor'}" style="background:${c.pass ? '#dcfce7' : '#fee2e2'};color:${c.pass ? '#14532d' : '#9b1c1c'}">${c.pass ? 'PASS' : 'FAIL'}</span></td>
        <td>${c.error || ''}</td>
      </tr>
    `).join('');
    return `
      <div class="sbfDirection">
        <h5>${d.direction} — <span class="sbfBadge ${d.result === 'PASS' ? 'sbf-primary' : 'sbf-monitor'}" style="background:${d.result === 'PASS' ? '#dcfce7' : '#fee2e2'};color:${d.result === 'PASS' ? '#14532d' : '#9b1c1c'}">${d.result}</span></h5>
        <div style="color:var(--muted);font-size:12px">
          ${d.senderUrl} / <code>${d.senderInterface.name}</code> → ${d.receiverUrl} / <code>${d.expectedInterface.name}</code>
          · marker <code>${d.marker}</code> · UDP ${d.udpSrcPort}→${d.udpDstPort} · sent ${d.sent}/${d.count}
        </div>
        <table class="sbfCapTable">
          <thead><tr><th>Role</th><th>Node</th><th>Interface</th><th>MAC</th><th>Expect</th><th>Matched</th><th>Result</th><th>Error</th></tr></thead>
          <tbody>${capRows}</tbody>
        </table>
        <div class="sbfSeq">missing sequences (${d.missingSequences.length}): ${d.missingSequences.slice(0, 100).join(', ') || '<em>none</em>'}${d.missingSequences.length > 100 ? ' …' : ''}</div>
      </div>
    `;
  }).join('');
  el.innerHTML = `
    <div class="sbfResultSummary">
      <div class="box ${overallCls}"><span>Overall</span><strong>${report.overall}</strong></div>
      <div class="box"><span>Directions</span><strong>${report.directions.length}</strong></div>
      <div class="box"><span>Generated</span><strong style="font-size:12px">${new Date(report.generatedAt).toLocaleString()}</strong></div>
    </div>
    ${dirs}
  `;
  $('sbfOpenReport').classList.remove('disabled');
  $('sbfOpenJson').classList.remove('disabled');
}

async function sbfRun(direction) {
  const singlePc = sbfIsSinglePc();
  const count = Number($('sbfCount').value || 10);
  const intervalMs = Number($('sbfInterval').value || 100);
  const captureTimeoutMs = Number($('sbfCaptureTimeout').value || 3000);
  const params = {
    count, intervalMs,
    udpSrcPort: Number($('sbfUdpSrc').value || 40000),
    udpDstPort: Number($('sbfUdpDst').value || 50000),
    payloadMarkerPrefix: $('sbfMarker').value.trim() || 'KETI_SIMPLE_FORWARD',
    captureTimeoutMs
  };
  let body;
  if (singlePc) {
    const send = sbfUnifiedSend(), recv = sbfUnifiedRecv();
    if (!send) throw new Error('Send 인터페이스(라디오)를 선택하세요.');
    if (!recv) throw new Error('Receive 인터페이스(라디오)를 선택하세요.');
    if (send.name === recv.name) throw new Error('Send와 Receive는 다른 인터페이스여야 합니다.');
    const monitors = sbfUnifiedMonitors().map((m) => m.name);
    const url = sbfLocalUrl();
    body = {
      ...params,
      nodeAUrl: url, nodeBUrl: url,
      nodeAPrimaryInterface: send.name,
      nodeBPrimaryInterface: recv.name,
      // All checked monitors land on the receive side so they're checked against
      // the same expected dst MAC (receiver primary). Backend treats them as
      // "must == 0" captures.
      nodeAMonitorInterfaces: [],
      nodeBMonitorInterfaces: monitors,
      direction: 'A_TO_B'
    };
  } else {
    const aPrimary = sbfPrimary('a'), bPrimary = sbfPrimary('b');
    if (!aPrimary) throw new Error('Node A의 Primary 인터페이스를 선택하세요.');
    if (!bPrimary) throw new Error('Node B의 Primary 인터페이스를 선택하세요.');
    body = {
      ...params,
      nodeAUrl: $('sbfNodeAUrl').value.trim(),
      nodeBUrl: $('sbfNodeBUrl').value.trim(),
      nodeAPrimaryInterface: aPrimary.name,
      nodeBPrimaryInterface: bPrimary.name,
      nodeAMonitorInterfaces: sbfMonitorList('a').map((m) => m.name),
      nodeBMonitorInterfaces: sbfMonitorList('b').map((m) => m.name),
      direction
    };
  }
  const buttons = ['sbfRunAtoB', 'sbfRunBtoA', 'sbfRunBoth', 'sbfProbe'];
  buttons.forEach((id) => { const b = $(id); if (b) b.disabled = true; });
  const prog = progressFor('progSimpleBidir');
  const passes = body.direction === 'BOTH' ? 2 : 1;
  const estSec = passes * Math.max(1, (count * intervalMs + captureTimeoutMs) / 1000 + 1);
  setActionStatus('statusSimpleBidir', 'running', `${body.direction} running...`);
  prog.start(estSec);
  setStatus(`Simple bidir forward ${body.direction}...`);
  try {
    const result = await api('/api/simple-bidir-forward-test', { method: 'POST', body: JSON.stringify(body) });
    sbfRenderResult(result.report);
    const overall = result.report.overall;
    setActionStatus('statusSimpleBidir', overall === 'PASS' ? 'ok' : 'fail',
      result.directions.map((d) => `${d.direction}:${d.result}`).join(' · '));
    if (overall === 'PASS') prog.finish(); else prog.fail();
    setStatus(`Simple bidir forward ${overall}`, overall !== 'PASS');
  } catch (err) {
    setActionStatus('statusSimpleBidir', 'fail', 'fail');
    prog.fail();
    throw err;
  } finally {
    buttons.forEach((id) => { const b = $(id); if (b) b.disabled = false; });
  }
}

(function sbfInit() {
  const b = $('sbfNodeBUrl');
  if (b && !b.value) b.value = window.location.origin;
  if ($('sbfLocalUrl')) $('sbfLocalUrl').value = window.location.origin;
  const syncIds = [
    'sbfNodeAUrl','sbfNodeBUrl',
    'sbfNodeAPrimary','sbfNodeAMonitor','sbfNodeAMonitor2',
    'sbfNodeBPrimary','sbfNodeBMonitor','sbfNodeBMonitor2',
    'sbfSingleSender','sbfSingleReceiver','sbfSingleMonitor','sbfSingleMonitor2'
  ];
  syncIds.forEach((id) => {
    $(id)?.addEventListener('input', sbfSyncTopology);
    $(id)?.addEventListener('change', sbfSyncTopology);
  });
  $('sbfSinglePc')?.addEventListener('change', (e) => sbfSetSinglePcMode(e.target.checked));
  sbfSetSinglePcMode(false);
  sbfSyncTopology();
  $('sbfProbe')?.addEventListener('click', () => sbfProbe().catch(toastError));
  $('sbfRunAtoB')?.addEventListener('click', () => sbfRun('A_TO_B').catch(toastError));
  $('sbfRunBtoA')?.addEventListener('click', () => sbfRun('B_TO_A').catch(toastError));
  $('sbfRunBoth')?.addEventListener('click', () => sbfRun('BOTH').catch(toastError));
})();

async function ensurePeerReady() {
  if (!state.peer.url) throw new Error('Peer URL not set. Fill the Peer field in the top link strip.');
  if (!state.peer.interfaces.length) await probePeer();
  if (!state.peer.iface) throw new Error('Peer interface not selected.');
}

async function runBenchmark() {
  if ($('runBenchmark').disabled) return;
  $('runBenchmark').disabled = true;
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
      toast(`Benchmark received 0 packets — check link & peer.\n\nChecklist:\n - Wire/link between ${senderIf} and ${receiverIf} is up\n - Peer agent is reachable at ${receiverUrl}\n - Sender MAC ${state.interfaces.find(i=>i.name===senderIf)?.mac} matches what the peer expects\n\nThe benchmark always uses UDP+IPv4 internally regardless of the profile selected on the Sender tab.`);
    }
  } catch (err) {
    setActionStatus('statusBench', 'fail', 'fail');
    prog.fail();
    throw err;
  } finally {
    $('runBenchmark').disabled = false;
  }
}

async function runRfc2544() {
  if ($('runRfc').disabled) return;
  $('runRfc').disabled = true;
  const prog = progressFor('progRfc');
  const trial = Number($('rfcTrial').value || 2);
  const link = Number($('rfcLink').value || 1000);
  const tol = Number($('rfcTol').value || 100);
  // 7 sizes × ~7 binary-search iterations × trial seconds, generous estimate
  const estSec = 7 * 7 * (trial + 0.7);
  setActionStatus('statusRfc', 'running', 'binary-searching');
  prog.start(estSec);
  setStatus('Running RFC 2544 throughput…');
  try {
    await ensurePeerReady();
    syncControlFromPeer();
    const result = await api('/api/rfc2544', {
      method: 'POST',
      body: JSON.stringify({
        senderUrl: $('senderNodeUrl').value,
        receiverUrl: $('receiverNodeUrl').value,
        senderInterface: $('senderNodeInterface').value,
        receiverInterface: $('receiverNodeInterface').value,
        trialDurationSec: trial,
        linkRateMbps: link,
        tolerancePps: tol
      })
    });
    const sizes = result.report.results.length;
    const avgUtil = (result.report.results.reduce((s, r) => s + (r.utilizationPct || 0), 0) / sizes).toFixed(1);
    setActionStatus('statusRfc', 'ok', `${sizes} sizes · avg ${avgUtil}% util`);
    prog.finish();
    setStatus(`RFC 2544 done: ${sizes} sizes, avg ${avgUtil}% utilization`);
    window.open('/reports/rfc2544-latest.html', '_blank');
  } catch (err) {
    setActionStatus('statusRfc', 'fail', 'fail');
    prog.fail();
    throw err;
  } finally {
    $('runRfc').disabled = false;
  }
}

async function runSweep() {
  if ($('runSweep').disabled) return;
  $('runSweep').disabled = true;
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
  } finally {
    $('runSweep').disabled = false;
  }
}

$('runBenchmark').addEventListener('click', () => runBenchmark().catch((err) => {
  toastError(err);
}));
$('runSweep').addEventListener('click', () => runSweep().catch((err) => {
  toastError(err);
}));
$('runRfc')?.addEventListener('click', () => runRfc2544().catch((err) => {
  toastError(err);
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
  toastError(err);
}));
$('deleteCase').addEventListener('click', () => deleteCurrentCase().catch((err) => {
  toastError(err);
}));
$('addCurrentPacket').addEventListener('click', addCurrentPacketToCase);
$('addDelay').addEventListener('click', addDelayToCase);
$('duplicateStep').addEventListener('click', duplicateSelectedStep);
$('removeStep').addEventListener('click', removeSelectedStep);
$('moveStepUp').addEventListener('click', () => moveSelectedStep(-1));
$('moveStepDown').addEventListener('click', () => moveSelectedStep(1));
$('sendSelectedSteps').addEventListener('click', () => runCurrentCase({ selectedOnly: true }).catch((err) => {
  toastError(err);
}));
$('runCase').addEventListener('click', () => runCurrentCase().catch((err) => {
  toastError(err);
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
    $('ctrlSenderName').textContent = sender?.name || '— set in Interface picker —';
    $('ctrlSenderMac').textContent = fmtMac(sender?.mac);
    $('ctrlSenderIp').textContent = fmtIp(sender);
    $('ctrlSenderUrl').textContent = sUrl || '(this PC)';
    $('ctrlReceiverName').textContent = receiver?.name || '— probe peer in the link strip above —';
    $('ctrlReceiverMac').textContent = fmtMac(receiver?.mac);
    $('ctrlReceiverIp').textContent = fmtIp(receiver);
    $('ctrlReceiverUrl').textContent = rUrl || '(peer not set)';
    const ready = sender && receiver && sUrl && rUrl;
    $('pairWarning').classList.toggle('hidden', Boolean(ready));
    document.querySelector('.pairCard')?.classList.toggle('pairIncomplete', !ready);
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
  if (!url) { toast('Peer URL is required.','warn'); return; }
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
  if (!peer) { toast('Probe the peer first.','warn'); return; }
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

$('peerProbeBtn').addEventListener('click', () => probePeer().catch((err) => { toastError(err); }));

// First-run welcome banner — show until user dismisses or sets a peer URL.
(function maybeShowFirstRun() {
  if (localStorage.getItem('firstRunDismissed') === '1') return;
  if (state.peer.url) return;
  document.getElementById('firstRunHint')?.classList.remove('hidden');
})();
document.getElementById('firstRunDismiss')?.addEventListener('click', () => {
  localStorage.setItem('firstRunDismissed', '1');
  document.getElementById('firstRunHint')?.classList.add('hidden');
});
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
      Array.from($('interfaceSelect').options).forEach((o) => { o.selected = (o.value === name); });
      renderInterfaceCheckboxes();
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
      Array.from($('interfaceSelect').options).forEach((o) => { o.selected = (o.value === name); });
      renderInterfaceCheckboxes();
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
  const target = { capture: 'captureView', control: 'controlView', sender: 'senderView', serial: 'serialView' }[hash];
  if (!target) return;
  const btn = document.querySelector(`[data-view="${target}"]`);
  if (btn) btn.click();
})();
// ?autoStart=1 — used for headless verification of the capture pipeline
const _autoStart = new URLSearchParams(location.search).get('autoStart') === '1';
// Decorate the topbar version chip
fetch('/api/version').then((r) => r.json()).then((j) => {
  const el = document.getElementById('versionTag');
  if (el && j?.commit) el.textContent = j.commit;
}).catch(() => {});

// Help overlay
function toggleHelp(force) {
  const ov = document.getElementById('helpOverlay');
  if (!ov) return;
  const show = force === undefined ? ov.classList.contains('hidden') : force;
  ov.classList.toggle('hidden', !show);
}
document.getElementById('helpButton')?.addEventListener('click', () => toggleHelp(true));
document.getElementById('helpClose')?.addEventListener('click', () => toggleHelp(false));
document.getElementById('helpOverlay')?.addEventListener('click', (e) => { if (e.target.id === 'helpOverlay') toggleHelp(false); });

// Global keyboard shortcuts. Skip when the user is typing into a text input.
document.addEventListener('keydown', (e) => {
  const tag = (e.target && e.target.tagName) || '';
  const isTyping = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
  if (e.key === 'Escape') {
    if (!document.getElementById('helpOverlay')?.classList.contains('hidden')) { toggleHelp(false); e.preventDefault(); return; }
    if (state.serial?.sessionId) { serialDisconnect(); return; }
    if (capture.reader) { stopCaptureStream(); return; }
  }
  if (isTyping) {
    if (e.ctrlKey && e.key.toLowerCase() === 's' && document.getElementById('senderView')?.classList.contains('active')) {
      e.preventDefault(); $('saveCase')?.click(); return;
    }
    if (e.ctrlKey && e.key === 'Enter' && document.getElementById('senderView')?.classList.contains('active')) {
      e.preventDefault(); $('send')?.click(); return;
    }
    return;
  }
  if (e.key === '?') { e.preventDefault(); toggleHelp(); return; }
  const tabMap = { '1': 'senderView', '2': 'captureView', '3': 'controlView', '4': 'serialView' };
  if (tabMap[e.key]) { e.preventDefault(); document.querySelector(`[data-view="${tabMap[e.key]}"]`)?.click(); return; }
  if (document.getElementById('captureView')?.classList.contains('active')) {
    if (e.key.toLowerCase() === 's') { e.preventDefault(); ($('captureStart').disabled ? $('captureStop') : $('captureStart'))?.click(); return; }
    if (e.key.toLowerCase() === 'c') { e.preventDefault(); $('captureClear')?.click(); return; }
    if (e.key.toLowerCase() === 'p') { e.preventDefault(); $('captureSavePcap')?.click(); return; }
    if (e.key === '/')              { e.preventDefault(); $('captureDisplayFilter')?.focus(); return; }
  }
});

await loadExamples();
await loadTestProfiles();
await loadTestCases();
await loadInterfaces();
const savedLocalIf = localStorage.getItem('localInterface');
if (savedLocalIf && state.interfaces.find((i) => i.name === savedLocalIf)) {
  Array.from($('interfaceSelect').options).forEach((o) => { o.selected = (o.value === savedLocalIf); });
  renderInterfaceCheckboxes();
  updateInterfaceInfo();
}
$('peerUrlPin').value = state.peer.url;
renderLinkStrip();
if (state.peer.url) probePeer().catch(() => {});
try {
  await build();
} catch (err) {
  console.warn('initial build skipped:', err.message);
  $('decoded').textContent = '// Build needs Source MAC / Source IP / Destination MAC.\n// Lock to peer above (or pick a profile) and press "Preview Frame".';
  $('hexdump').textContent = '';
}
setStatus('Ready');
clearCapture();
if (_autoStart) {
  setTimeout(() => $('captureStart')?.click(), 800);
  // Auto-click first packet after some traffic accumulates
  setTimeout(() => {
    fetch('/api/send', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
      interface: $('interfaceSelect').value, protocol:'udp',
      dstMac:'c8:4d:44:20:40:5b', srcMac: localIface()?.mac,
      ipv4:{src:firstV4(localIface()), dst:'169.254.148.199', ttl:64},
      udp:{srcPort:40000,dstPort:50000},
      payload:{mode:'counter', size:1400}, targetFrameLength:1500,
      count:3, intervalMs:300
    })});
  }, 1500);
  setTimeout(() => $('packetRows')?.firstElementChild?.click(), 5500);
}
// Honour URL hash like #capture / #control / #sender to jump to a tab on load
(() => {
  const hash = location.hash.replace('#', '');
  const target = { capture: 'captureView', control: 'controlView', sender: 'senderView' }[hash];
  if (!target) return;
  const btn = document.querySelector(`[data-view="${target}"]`);
  if (btn) btn.click();
})();
