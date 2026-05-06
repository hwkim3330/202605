const $ = (id) => document.getElementById(id);
const state = { examples: {}, interfaces: [] };

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

async function loadInterfaces() {
  const result = await api('/api/interfaces');
  state.interfaces = result.stdout.interfaces || [];
  $('interfaceSelect').innerHTML = state.interfaces
    .map((iface) => `<option value="${iface.name}">${iface.name} (${iface.state})</option>`)
    .join('');
  updateInterfaceInfo();
}

function updateInterfaceInfo() {
  const selected = state.interfaces.find((iface) => iface.name === $('interfaceSelect').value);
  if (!selected) {
    $('interfaceInfo').textContent = '';
    return;
  }
  $('interfaceInfo').textContent = `MAC ${selected.mac} / MTU ${selected.mtu} / ${selected.state}`;
  if (!$('srcMac').value || $('srcMac').value === '02:00:00:00:00:01') {
    $('srcMac').value = selected.mac;
  }
}

async function loadExamples() {
  const data = await api('/api/examples');
  state.examples = data.profiles;
  setProfile(state.examples.udp);
}

async function build() {
  const result = await api('/api/build', { method: 'POST', body: JSON.stringify(getProfile()) });
  showResult(result);
}

async function send() {
  const result = await api('/api/send', { method: 'POST', body: JSON.stringify(getProfile()) });
  showResult(result);
}

async function capture() {
  const profile = getProfile();
  const result = await api('/api/capture', {
    method: 'POST',
    body: JSON.stringify({
      interface: profile.interface,
      timeoutSec: 10,
      timeoutMs: 12000,
      maxFrames: 30,
      dstMac: profile.srcMac
    })
  });
  const frames = result.stdout.frames || [];
  $('captures').innerHTML = frames.length
    ? frames.map((frame) => `
      <article class="captureItem">
        <strong>${new Date(frame.timestamp * 1000).toLocaleTimeString()} ${frame.length} bytes</strong>
        <pre>${JSON.stringify(frame.decoded, null, 2)}</pre>
      </article>
    `).join('')
    : '<div class="muted">No matching frames captured.</div>';
}

document.querySelectorAll('[data-example]').forEach((button) => {
  button.addEventListener('click', () => setProfile(state.examples[button.dataset.example]));
});

$('refreshInterfaces').addEventListener('click', () => loadInterfaces().catch((err) => alert(err.message)));
$('interfaceSelect').addEventListener('change', updateInterfaceInfo);
$('build').addEventListener('click', () => build().catch((err) => alert(err.message)));
$('send').addEventListener('click', () => send().catch((err) => alert(err.message)));
$('capture').addEventListener('click', () => capture().catch((err) => alert(err.message)));

await loadExamples();
await loadInterfaces();
await build();
