import { createServer } from 'node:http';
import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { createReadStream, existsSync, statSync } from 'node:fs';

function fsStatIsFile(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}
import { extname, join, normalize } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readdirSync, readFileSync, readlinkSync } from 'node:fs';

const root = fileURLToPath(new URL('.', import.meta.url));
const publicDir = join(root, 'public');
const reportsDir = join(root, 'reports');
const testCasesDir = join(root, 'testcases');
const testProfilesDir = join(root, 'testprofiles');
const agentPath = join(root, 'tools', 'packet_agent.py');
const port = Number(process.env.PORT || 8080);

const mimeTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml; charset=utf-8']
]);

function sendJson(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload)
  });
  res.end(payload);
}

const MAX_BODY_BYTES = 32 * 1024 * 1024; // 32 MB — protects against accidental / hostile huge POSTs.
async function readRequestJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw.trim() ? JSON.parse(raw) : {};
}

function runAgent(args, stdinJson = null, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const child = spawn('python3', [agentPath, ...args], {
      cwd: root,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 1500).unref();
    }, timeoutMs);

    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('close', (code) => {
      clearTimeout(timer);
      const out = Buffer.concat(stdout).toString('utf8').trim();
      const err = Buffer.concat(stderr).toString('utf8').trim();
      let parsed = null;
      if (out) {
        try {
          parsed = JSON.parse(out);
        } catch {
          parsed = { raw: out };
        }
      }
      resolve({ code, ok: code === 0, stdout: parsed, stderr: err });
    });

    if (stdinJson) child.stdin.end(JSON.stringify(stdinJson));
    else child.stdin.end();
  });
}

async function loadExampleItems() {
  const files = (await readdir(join(root, 'examples'))).filter((file) => file.endsWith('.json')).sort();
  const profiles = {};
  const items = [];
  for (const file of files) {
    const profile = JSON.parse(await readFile(join(root, 'examples', file), 'utf8'));
    const key = file.replace(/\.json$/, '');
    profiles[key] = profile;
    items.push({
      key,
      file,
      name: profile.name || key,
      category: profile.category || 'General',
      priority: profile.priority || 99,
      description: profile.description || '',
      profile
    });
  }
  items.sort((a, b) => a.priority - b.priority || a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  return { profiles, items };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function normalizeBaseUrl(value) {
  const raw = String(value || '').trim().replace(/\/+$/, '');
  if (!raw) throw new Error('node URL is required');
  return raw.startsWith('http://') || raw.startsWith('https://') ? raw : `http://${raw}`;
}

async function remoteJson(baseUrl, path, options = {}) {
  const url = `${normalizeBaseUrl(baseUrl)}${path}`;
  let response;
  try {
    response = await fetch(url, {
      method: options.method || 'GET',
      headers: { 'content-type': 'application/json' },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
  } catch (err) {
    throw new Error(`fetch failed: ${url} (${err.cause?.code || err.message})`);
  }
  let body;
  try { body = await response.json(); }
  catch (err) { throw new Error(`bad json from ${url}: ${err.message}`); }
  if (!response.ok || body.ok === false) {
    throw new Error(body.error || body.stderr || `remote request failed: ${url}`);
  }
  return body;
}

function selectInterface(interfaces, name) {
  const iface = interfaces.find((item) => item.name === name);
  if (!iface) throw new Error(`interface not found: ${name}`);
  return iface;
}

function firstIpv4(iface) {
  return iface?.ipv4?.[0]?.local || '';
}

/**
 * On-wire Ethernet timing. Matches the WPF companion's
 * Services/EthernetTiming.cs so the two products report the same numbers.
 *
 * Wire frame structure (IEEE 802.3):
 *   Preamble          7 bytes  (0x55 × 7)
 *   SFD               1 byte   (0xD5)
 *   Frame body        max(payloadBytes, 60) + FCS(4) bytes
 *   IFG               12 bytes
 *
 * @param {number} payloadBytes  frame bytes excluding FCS (i.e., what AF_PACKET sees)
 * @returns {{ wireBytes: number, wireBits: number }}
 */
function ethernetWireBytes(payloadBytes) {
  const PREAMBLE_SFD = 8, FCS = 4, IFG = 12, MIN_FRAME = 64;
  const frameBody = Math.max(payloadBytes + FCS, MIN_FRAME);
  const wireBytes = PREAMBLE_SFD + frameBody + IFG;
  return { wireBytes, wireBits: wireBytes * 8 };
}
function theoreticalFps(wireSize, linkRateMbps) {
  // wireSize is the RFC 2544 wire size (includes FCS). We need preamble+SFD+IFG on top.
  const { wireBits } = ethernetWireBytes(wireSize - 4);
  return Math.floor((linkRateMbps * 1e6) / wireBits);
}

function slugifyId(value) {
  const base = String(value || 'test-case')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9가-힣_-]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return base || `test-case-${Date.now()}`;
}

function testCasePath(id) {
  const safe = slugifyId(id);
  return join(testCasesDir, `${safe}.json`);
}

function profileForE2E(profile, senderIface, receiverIface) {
  const next = JSON.parse(JSON.stringify(profile));
  const senderIp = firstIpv4(senderIface);
  const receiverIp = firstIpv4(receiverIface);
  next.interface = senderIface.name;
  next.srcMac = senderIface.mac;
  if (next.protocol === 'arp') {
    next.dstMac = 'ff:ff:ff:ff:ff:ff';
    next.arp = {
      ...(next.arp || {}),
      operation: 1,
      senderMac: senderIface.mac,
      senderIp,
      targetMac: '00:00:00:00:00:00',
      targetIp: receiverIp
    };
  } else {
    next.dstMac = receiverIface.mac;
    next.ipv4 = {
      ...(next.ipv4 || {}),
      src: senderIp,
      dst: receiverIp,
      ttl: next.ipv4?.ttl || 64,
      id: next.ipv4?.id ?? 0x2026
    };
  }
  return next;
}

function decodedProtocol(decoded) {
  if (decoded?.arp) return 'arp';
  if (decoded?.udp) return 'udp';
  if (decoded?.icmp) return 'icmp';
  return decoded?.ethernet?.etherType || 'ethernet';
}

function sameValue(left, right) {
  return String(left ?? '').toLowerCase() === String(right ?? '').toLowerCase();
}

function isExpectedFrame(frame, sentDecoded, senderIface, receiverIface) {
  const decoded = frame.decoded || {};
  // Length tolerance: hardware can pad short frames or, with VLAN offload, the
  // 4-byte tag may be stripped from the visible buffer. Allow ±8 bytes.
  if (sentDecoded?.length) {
    const diff = Math.abs(decoded.length - sentDecoded.length);
    if (diff > 8) return false;
  }
  if (!sameValue(decoded.ethernet?.srcMac, senderIface.mac)) return false;
  if (sentDecoded?.ethernet?.dstMac && !sameValue(decoded.ethernet?.dstMac, sentDecoded.ethernet.dstMac)) return false;
  if (decodedProtocol(decoded) !== decodedProtocol(sentDecoded)) return false;

  if (sentDecoded?.vlan) {
    // VLAN id/priority match if the receiver also saw the tag; many NICs strip
    // 802.1Q on RX (rxvlan offload) so the tag is invisible to AF_PACKET. In
    // that case fall through and rely on L3/L4 matching.
    if (decoded.vlan) {
      if (decoded.vlan.id !== sentDecoded.vlan.id) return false;
      if (decoded.vlan.priority !== sentDecoded.vlan.priority) return false;
    }
  }

  if (sentDecoded?.arp) {
    return sameValue(decoded.arp?.senderIp, sentDecoded.arp.senderIp)
      && sameValue(decoded.arp?.targetIp, sentDecoded.arp.targetIp)
      && sameValue(decoded.arp?.senderMac, senderIface.mac);
  }

  if (sentDecoded?.ipv4) {
    if (!sameValue(decoded.ipv4?.src, sentDecoded.ipv4.src)) return false;
    if (!sameValue(decoded.ipv4?.dst, sentDecoded.ipv4.dst || firstIpv4(receiverIface))) return false;
  }

  if (sentDecoded?.udp) {
    return decoded.udp?.srcPort === sentDecoded.udp.srcPort
      && decoded.udp?.dstPort === sentDecoded.udp.dstPort;
  }

  if (sentDecoded?.icmp) {
    return decoded.icmp?.type === sentDecoded.icmp.type
      && decoded.icmp?.id === sentDecoded.icmp.id
      && decoded.icmp?.seq === sentDecoded.icmp.seq;
  }

  return true;
}

async function loadTestCases() {
  await mkdir(testCasesDir, { recursive: true });
  const files = (await readdir(testCasesDir)).filter((file) => file.endsWith('.json')).sort();
  const items = [];
  for (const file of files) {
    try {
      const testCase = JSON.parse(await readFile(join(testCasesDir, file), 'utf8'));
      items.push({
        id: file.replace(/\.json$/, ''),
        name: testCase.name || file.replace(/\.json$/, ''),
        description: testCase.description || '',
        stepCount: Array.isArray(testCase.steps) ? testCase.steps.length : 0,
        updatedAt: testCase.updatedAt || '',
        testCase
      });
    } catch {
      // Ignore broken draft files so one bad test case does not break the UI.
    }
  }
  return items;
}

async function expandTestProfile(profileSuite) {
  const { profiles } = await loadExampleItems();
  const steps = [];
  for (const step of profileSuite.steps || []) {
    if (step.kind === 'delay') {
      steps.push({
        kind: 'delay',
        name: step.name || `Delay ${Number(step.delayMs || 100)} ms`,
        delayMs: Number(step.delayMs || 100)
      });
      continue;
    }
    const profile = step.profile || profiles[step.profileKey];
    if (!profile) continue;
    steps.push({
      kind: 'packet',
      name: step.name || profile.name || step.profileKey,
      enabled: step.enabled !== false,
      checked: step.checked !== false,
      count: Math.max(1, Number(step.count || profile.count || 1)),
      intervalMs: Math.max(0, Number(step.intervalMs ?? profile.intervalMs ?? 0)),
      profile
    });
  }
  return {
    schemaVersion: 1,
    id: profileSuite.id || slugifyId(profileSuite.name),
    name: profileSuite.name || profileSuite.id || 'Standard Profile',
    description: profileSuite.description || '',
    standardRefs: profileSuite.standardRefs || [],
    profileGroup: profileSuite.profileGroup || 'Standard',
    steps
  };
}

async function loadTestProfiles() {
  await mkdir(testProfilesDir, { recursive: true });
  const files = (await readdir(testProfilesDir)).filter((file) => file.endsWith('.json')).sort();
  const items = [];
  for (const file of files) {
    try {
      const raw = JSON.parse(await readFile(join(testProfilesDir, file), 'utf8'));
      const testCase = await expandTestProfile(raw);
      items.push({
        id: file.replace(/\.json$/, ''),
        name: testCase.name,
        description: testCase.description,
        profileGroup: testCase.profileGroup,
        standardRefs: testCase.standardRefs,
        stepCount: testCase.steps.length,
        testCase
      });
    } catch {
      // Ignore malformed profile files.
    }
  }
  return items;
}

function normalizeTestCase(input) {
  const now = new Date().toISOString();
  const id = slugifyId(input.id || input.name);
  const steps = Array.isArray(input.steps) ? input.steps.map((step, index) => {
    if (step.kind === 'delay') {
      return {
        kind: 'delay',
        name: step.name || `Delay ${Number(step.delayMs || 100)} ms`,
        delayMs: Math.max(0, Number(step.delayMs || 100))
      };
    }
    return {
      kind: 'packet',
      name: step.name || step.profile?.name || `Packet ${index + 1}`,
      enabled: step.enabled !== false,
      count: Math.max(1, Number(step.count || step.profile?.count || 1)),
      intervalMs: Math.max(0, Number(step.intervalMs ?? step.profile?.intervalMs ?? 0)),
      profile: step.profile || {}
    };
  }) : [];
  return {
    schemaVersion: 1,
    id,
    name: input.name || id,
    description: input.description || '',
    createdAt: input.createdAt || now,
    updatedAt: now,
    steps
  };
}

async function saveTestCase(input) {
  await mkdir(testCasesDir, { recursive: true });
  const testCase = normalizeTestCase(input);
  await writeFile(testCasePath(testCase.id), JSON.stringify(testCase, null, 2));
  return testCase;
}

function reportHtml(report) {
  const rows = report.results.map((item) => `
    <tr class="${item.ok ? 'pass' : 'fail'}">
      <td>${item.priority}</td>
      <td>${escapeHtml(item.category)}</td>
      <td>${escapeHtml(item.name)}</td>
      <td>${item.ok ? 'PASS' : 'FAIL'}</td>
      <td>${item.length ?? '-'}</td>
      <td>${escapeHtml(item.protocol || '-')}</td>
      <td>${escapeHtml(item.error || item.info || '')}</td>
    </tr>
  `).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Ethernet Packet Lab Report</title>
  <style>
    body { margin: 24px; font: 14px/1.45 system-ui, sans-serif; color: #17202a; }
    h1 { margin: 0 0 4px; }
    .meta { color: #62707f; margin-bottom: 18px; }
    .summary { display: flex; gap: 12px; margin: 16px 0; }
    .box { border: 1px solid #d2dae3; border-radius: 8px; padding: 10px 12px; min-width: 130px; }
    .box strong { display: block; font-size: 22px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #d2dae3; padding: 8px; text-align: left; }
    th { background: #eef5f6; }
    tr.pass td:nth-child(4) { color: #14532d; font-weight: 700; }
    tr.fail td:nth-child(4) { color: #9b1c1c; font-weight: 700; }
  </style>
</head>
<body>
  <h1>Ethernet Packet Lab Report</h1>
  <div class="meta">Generated ${escapeHtml(report.generatedAt)} on ${escapeHtml(report.node.hostname || 'local node')}</div>
  <div class="summary">
    <div class="box"><span>Total</span><strong>${report.summary.total}</strong></div>
    <div class="box"><span>Pass</span><strong>${report.summary.pass}</strong></div>
    <div class="box"><span>Fail</span><strong>${report.summary.fail}</strong></div>
  </div>
  <table>
    <thead>
      <tr><th>#</th><th>Category</th><th>Profile</th><th>Status</th><th>Length</th><th>Protocol</th><th>Info</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}

async function runProfileReport() {
  const { items } = await loadExampleItems();
  const interfaces = await runAgent(['interfaces']);
  const results = [];
  for (const item of items) {
    const result = await runAgent(['build'], item.profile, 10000);
    const decoded = result.stdout?.decoded;
    const protocol = decoded?.arp ? 'ARP' : decoded?.icmp ? 'ICMP' : decoded?.udp ? 'UDP' : decoded?.ethernet?.etherType;
    results.push({
      key: item.key,
      priority: item.priority,
      category: item.category,
      name: item.name,
      description: item.description,
      ok: result.ok && Boolean(decoded),
      length: decoded?.length,
      protocol,
      info: decoded?.vlan ? `VLAN ${decoded.vlan.id} PCP ${decoded.vlan.priority}` : decoded?.ethernet?.etherType,
      error: result.ok ? '' : (result.stdout?.error || result.stderr || 'build failed')
    });
  }
  const pass = results.filter((item) => item.ok).length;
  const report = {
    generatedAt: new Date().toISOString(),
    node: {
      hostname: process.env.HOSTNAME || '',
      cwd: root
    },
    interfaces: interfaces.stdout?.interfaces || [],
    summary: {
      total: results.length,
      pass,
      fail: results.length - pass
    },
    results
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'latest.html'), reportHtml(report));
  return report;
}

function e2eReportHtml(report) {
  const rows = report.capturedFrames.map((frame, index) => {
    const decoded = frame.decoded || {};
    const proto = decoded.arp ? 'ARP' : decoded.icmp ? 'ICMP' : decoded.udp ? 'UDP' : decoded.ethernet?.etherType || '-';
    const src = decoded.ipv4?.src || decoded.arp?.senderIp || decoded.ethernet?.srcMac || '-';
    const dst = decoded.ipv4?.dst || decoded.arp?.targetIp || decoded.ethernet?.dstMac || '-';
    return `<tr><td>${index + 1}</td><td>${escapeHtml(proto)}</td><td>${escapeHtml(src)}</td><td>${escapeHtml(dst)}</td><td>${frame.length}</td><td>${escapeHtml(decoded.ethernet?.srcMac || '-')}</td></tr>`;
  }).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Ethernet Packet Lab E2E Report</title>
  <style>
    body { margin: 24px; font: 14px/1.45 system-ui, sans-serif; color: #17202a; }
    .pass { color: #14532d; font-weight: 800; }
    .fail { color: #9b1c1c; font-weight: 800; }
    .box { border: 1px solid #d2dae3; border-radius: 8px; padding: 10px 12px; margin: 12px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border-bottom: 1px solid #d2dae3; padding: 8px; text-align: left; }
    th { background: #eef5f6; }
  </style>
</head>
<body>
  <h1>Ethernet Packet Lab E2E Report</h1>
  <div>Generated ${escapeHtml(report.generatedAt)}</div>
  <div class="box">
    <div>Status: <span class="${report.ok ? 'pass' : 'fail'}">${report.ok ? 'PASS' : 'FAIL'}</span></div>
    <div>Profile: ${escapeHtml(report.profileName)}</div>
    <div>Sender: ${escapeHtml(report.sender.url)} / ${escapeHtml(report.sender.interface)}</div>
    <div>Receiver: ${escapeHtml(report.receiver.url)} / ${escapeHtml(report.receiver.interface)}</div>
    <div>Captured matching frames: ${report.matchCount}</div>
  </div>
  <table>
    <thead><tr><th>No.</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th>Source MAC</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6">No frames captured</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

async function runE2ETest(reqBody) {
  const senderUrl = normalizeBaseUrl(reqBody.senderUrl);
  const receiverUrl = normalizeBaseUrl(reqBody.receiverUrl);
  const profile = reqBody.profile;
  if (!profile) throw new Error('profile is required');

  const [senderInfo, receiverInfo] = await Promise.all([
    remoteJson(senderUrl, '/api/interfaces'),
    remoteJson(receiverUrl, '/api/interfaces')
  ]);
  const senderInterfaces = senderInfo.stdout?.interfaces || [];
  const receiverInterfaces = receiverInfo.stdout?.interfaces || [];
  const senderIface = selectInterface(senderInterfaces, reqBody.senderInterface);
  const receiverIface = selectInterface(receiverInterfaces, reqBody.receiverInterface);
  const txProfile = profileForE2E(profile, senderIface, receiverIface);
  const captureBody = {
    interface: receiverIface.name,
    timeoutSec: Number(reqBody.timeoutSec || 5),
    timeoutMs: Number(reqBody.timeoutMs || 8000),
    maxFrames: Number(reqBody.maxFrames || 50),
    srcMac: senderIface.mac
  };

  const capturePromise = remoteJson(receiverUrl, '/api/capture', { method: 'POST', body: captureBody });
  await new Promise((resolve) => setTimeout(resolve, Number(reqBody.captureLeadMs || 500)));
  const sendResult = await remoteJson(senderUrl, '/api/send', { method: 'POST', body: txProfile });
  const captureResult = await capturePromise;
  const frames = captureResult.stdout?.frames || [];
  const sentDecoded = sendResult.stdout?.decoded;
  const matching = frames.filter((frame) => isExpectedFrame(frame, sentDecoded, senderIface, receiverIface));
  const report = {
    generatedAt: new Date().toISOString(),
    ok: sendResult.ok && matching.length > 0,
    profileName: profile.name || profile.protocol || 'custom profile',
    sender: { url: senderUrl, interface: senderIface.name, mac: senderIface.mac, ip: firstIpv4(senderIface) },
    receiver: { url: receiverUrl, interface: receiverIface.name, mac: receiverIface.mac, ip: firstIpv4(receiverIface) },
    sent: sendResult.stdout,
    expectedProtocol: decodedProtocol(sentDecoded),
    captureSummary: { total: frames.length, matching: matching.length },
    matchCount: matching.length,
    capturedFrames: matching,
    txProfile
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'e2e-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'e2e-latest.html'), e2eReportHtml(report));
  return report;
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor((p / 100) * (sorted.length - 1))));
  return sorted[idx];
}

function summarize(arr) {
  if (!arr.length) return { count: 0 };
  const sorted = [...arr].sort((a, b) => a - b);
  const sum = sorted.reduce((s, v) => s + v, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((s, v) => s + (v - mean) ** 2, 0) / sorted.length;
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
    stddev: Math.sqrt(variance),
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99)
  };
}

function extractBenchmarkFromHex(frameHex) {
  // Fallback for old receiver agents that don't decode the KETI marker.
  // Locate "4b455449" (b"KETI") in the hex, then the next 4 bytes are seq, the next 8 are tx ns.
  if (typeof frameHex !== 'string') return null;
  const idx = frameHex.indexOf('4b455449');
  if (idx < 0 || frameHex.length < idx + 8 + 8 + 16) return null;
  const seqHex = frameHex.slice(idx + 8, idx + 8 + 8);
  const tsHex = frameHex.slice(idx + 8 + 8, idx + 8 + 8 + 16);
  const seq = parseInt(seqHex, 16);
  const txTimestampNs = BigInt('0x' + tsHex);
  return { seq, txTimestampNs: Number(txTimestampNs) };
}

function analyzeBenchmark(txRecords, frames, sentBytes, elapsedSec) {
  const txBySeq = new Map();
  for (const rec of txRecords) txBySeq.set(rec.seq, rec);
  const matched = [];
  const rxByCapture = [];
  for (const frame of frames) {
    let bench = frame.decoded?.benchmark;
    if (!bench) bench = extractBenchmarkFromHex(frame.frameHex);
    if (!bench) continue;
    rxByCapture.push(frame);
    const tx = txBySeq.get(bench.seq);
    if (!tx) continue;
    const rxNs = frame.rxTimestampNs ?? Math.round((frame.timestamp || 0) * 1e9);
    matched.push({
      seq: bench.seq,
      txTimestampNs: tx.txTimestampNs,
      rxTimestampNs: rxNs,
      latencyNs: rxNs - tx.txTimestampNs,
      length: frame.length
    });
  }
  matched.sort((a, b) => a.seq - b.seq);
  const latenciesUs = matched.map((m) => m.latencyNs / 1000);
  const minLat = latenciesUs.length ? Math.min(...latenciesUs) : 0;
  const adjustedUs = latenciesUs.map((v) => v - minLat);
  const interArrivalUs = [];
  for (let i = 1; i < matched.length; i += 1) {
    interArrivalUs.push((matched[i].rxTimestampNs - matched[i - 1].rxTimestampNs) / 1000);
  }
  const jitterUs = [];
  for (let i = 1; i < latenciesUs.length; i += 1) {
    jitterUs.push(Math.abs(latenciesUs[i] - latenciesUs[i - 1]));
  }
  const txCount = txRecords.length;
  const rxCount = matched.length;
  const lossPct = txCount ? ((txCount - rxCount) / txCount) * 100 : 0;
  const throughputMbps = elapsedSec > 0 ? (sentBytes * 8) / (elapsedSec * 1e6) : 0;
  return {
    txCount,
    rxCount,
    lossPct,
    elapsedSec,
    sentBytes,
    throughputMbps,
    rxThroughputMbps: elapsedSec > 0
      ? (matched.reduce((s, m) => s + m.length, 0) * 8) / (elapsedSec * 1e6)
      : 0,
    latencyUs: summarize(latenciesUs),
    latencyAdjustedUs: summarize(adjustedUs),
    interArrivalUs: summarize(interArrivalUs),
    jitterUs: summarize(jitterUs),
    samples: matched.slice(0, 5000),
    interArrivalSamples: interArrivalUs.slice(0, 5000),
    capturedTotal: rxByCapture.length
  };
}

function benchmarkReportHtml(report) {
  const seqLabels = report.stats.samples.map((s) => s.seq);
  const latencies = report.stats.samples.map((s) => (s.latencyNs / 1000).toFixed(3));
  const adjusted = (() => {
    const min = Math.min(...report.stats.samples.map((s) => s.latencyNs)) || 0;
    return report.stats.samples.map((s) => ((s.latencyNs - min) / 1000).toFixed(3));
  })();
  const interArrival = report.stats.interArrivalSamples.map((v) => v.toFixed(3));
  const cdfSorted = [...report.stats.samples.map((s) => s.latencyNs / 1000)].sort((a, b) => a - b);
  const cdfPoints = cdfSorted.map((v, i) => ({ x: v, y: ((i + 1) / cdfSorted.length) * 100 }));
  const fmt = (v, d = 2) => (typeof v === 'number' ? v.toFixed(d) : '-');
  const s = report.stats;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Ethernet Packet Lab Benchmark</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
body{margin:24px;font:14px/1.45 system-ui,sans-serif;color:#17202a;}
h1{margin:0 0 4px}
.meta{color:#62707f;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:12px 0}
.box{border:1px solid #d2dae3;border-radius:8px;padding:10px 14px}
.box span{color:#62707f;font-size:12px}
.box strong{display:block;font-size:22px;margin-top:2px}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}
.chartCard{border:1px solid #d2dae3;border-radius:10px;padding:12px;background:#fff}
.chartCard h3{margin:0 0 8px;font-size:14px}
canvas{max-height:280px}
table{width:100%;border-collapse:collapse;margin-top:18px;font-size:12px}
th,td{border-bottom:1px solid #e2e8f0;padding:6px;text-align:right}
th:first-child,td:first-child{text-align:left}
th{background:#eef5f6}
@media(max-width:900px){.charts{grid-template-columns:1fr}}
</style></head><body>
<h1>Ethernet Packet Lab Benchmark</h1>
<div class="meta">Generated ${escapeHtml(report.generatedAt)} — Profile: ${escapeHtml(report.profileName)}</div>
<div class="meta">Sender ${escapeHtml(report.sender.url)}/${escapeHtml(report.sender.interface)} → Receiver ${escapeHtml(report.receiver.url)}/${escapeHtml(report.receiver.interface)}</div>
<div class="grid">
  <div class="box"><span>Sent</span><strong>${s.txCount}</strong></div>
  <div class="box"><span>Received</span><strong>${s.rxCount}</strong></div>
  <div class="box"><span>Loss</span><strong>${fmt(s.lossPct, 2)}%</strong></div>
  <div class="box"><span>Tx Throughput</span><strong>${fmt(s.throughputMbps)} Mbps</strong></div>
  <div class="box"><span>Rx Throughput</span><strong>${fmt(s.rxThroughputMbps)} Mbps</strong></div>
  <div class="box"><span>Latency p50 (skew-adj.)</span><strong>${fmt(s.latencyAdjustedUs.p50)} µs</strong></div>
  <div class="box"><span>Latency p95 (skew-adj.)</span><strong>${fmt(s.latencyAdjustedUs.p95)} µs</strong></div>
  <div class="box"><span>Latency p99 (skew-adj.)</span><strong>${fmt(s.latencyAdjustedUs.p99)} µs</strong></div>
  <div class="box"><span>Jitter (mean |Δlat|)</span><strong>${fmt(s.jitterUs.mean)} µs</strong></div>
  <div class="box"><span>Inter-arrival σ</span><strong>${fmt(s.interArrivalUs.stddev)} µs</strong></div>
</div>
<div class="charts">
  <div class="chartCard"><h3>Latency per packet (µs, clock-skew adjusted)</h3><canvas id="latChart"></canvas></div>
  <div class="chartCard"><h3>Latency CDF (µs)</h3><canvas id="cdfChart"></canvas></div>
  <div class="chartCard"><h3>Inter-arrival time (µs)</h3><canvas id="iaChart"></canvas></div>
  <div class="chartCard"><h3>Latency histogram</h3><canvas id="histChart"></canvas></div>
</div>
<h3>Statistics summary</h3>
<table><thead><tr><th>Metric</th><th>min</th><th>p50</th><th>mean</th><th>p95</th><th>p99</th><th>max</th><th>σ</th></tr></thead>
<tbody>
<tr><td>Latency µs</td><td>${fmt(s.latencyUs.min)}</td><td>${fmt(s.latencyUs.p50)}</td><td>${fmt(s.latencyUs.mean)}</td><td>${fmt(s.latencyUs.p95)}</td><td>${fmt(s.latencyUs.p99)}</td><td>${fmt(s.latencyUs.max)}</td><td>${fmt(s.latencyUs.stddev)}</td></tr>
<tr><td>Inter-arrival µs</td><td>${fmt(s.interArrivalUs.min)}</td><td>${fmt(s.interArrivalUs.p50)}</td><td>${fmt(s.interArrivalUs.mean)}</td><td>${fmt(s.interArrivalUs.p95)}</td><td>${fmt(s.interArrivalUs.p99)}</td><td>${fmt(s.interArrivalUs.max)}</td><td>${fmt(s.interArrivalUs.stddev)}</td></tr>
<tr><td>|Δlatency| µs</td><td>${fmt(s.jitterUs.min)}</td><td>${fmt(s.jitterUs.p50)}</td><td>${fmt(s.jitterUs.mean)}</td><td>${fmt(s.jitterUs.p95)}</td><td>${fmt(s.jitterUs.p99)}</td><td>${fmt(s.jitterUs.max)}</td><td>${fmt(s.jitterUs.stddev)}</td></tr>
</tbody></table>
<script>
const seqLabels = ${JSON.stringify(seqLabels)};
const adjusted = ${JSON.stringify(adjusted)}.map(Number);
const interArrival = ${JSON.stringify(interArrival)}.map(Number);
const cdfPoints = ${JSON.stringify(cdfPoints)};
const lineOpts = { responsive:true, animation:false, plugins:{legend:{display:false}}, scales:{x:{ticks:{maxTicksLimit:10}}}};
new Chart(document.getElementById('latChart'), { type:'line', data:{labels:seqLabels, datasets:[{data:adjusted, borderColor:'#0ea5e9', borderWidth:1, pointRadius:0}]}, options:lineOpts });
new Chart(document.getElementById('iaChart'), { type:'line', data:{labels:seqLabels.slice(1), datasets:[{data:interArrival, borderColor:'#16a34a', borderWidth:1, pointRadius:0}]}, options:lineOpts });
new Chart(document.getElementById('cdfChart'), { type:'line', data:{datasets:[{data:cdfPoints, parsing:false, borderColor:'#7c3aed', borderWidth:1.5, pointRadius:0, showLine:true}]}, options:{responsive:true, animation:false, plugins:{legend:{display:false}}, scales:{x:{type:'linear', title:{display:true,text:'latency µs'}}, y:{min:0,max:100, title:{display:true,text:'percentile %'}}}}});
const lat = adjusted.slice();
const bins = 30;
const minV = Math.min(...lat), maxV = Math.max(...lat);
const step = (maxV - minV) / bins || 1;
const histLabels = [], histCounts = new Array(bins).fill(0);
for (let i=0;i<bins;i++) histLabels.push((minV + i*step).toFixed(1));
for (const v of lat) { let i = Math.min(bins-1, Math.floor((v-minV)/step)); histCounts[i]++; }
new Chart(document.getElementById('histChart'), { type:'bar', data:{labels:histLabels, datasets:[{data:histCounts, backgroundColor:'#f59e0b'}]}, options:{responsive:true, animation:false, plugins:{legend:{display:false}}}});
</script>
</body></html>`;
}

async function runBenchmark(reqBody) {
  const senderUrl = normalizeBaseUrl(reqBody.senderUrl);
  const receiverUrl = normalizeBaseUrl(reqBody.receiverUrl);
  const baseProfile = reqBody.profile;
  if (!baseProfile) throw new Error('profile is required');

  const [senderInfo, receiverInfo] = await Promise.all([
    remoteJson(senderUrl, '/api/interfaces'),
    remoteJson(receiverUrl, '/api/interfaces')
  ]);
  const senderIface = selectInterface(senderInfo.stdout?.interfaces || [], reqBody.senderInterface);
  const receiverIface = selectInterface(receiverInfo.stdout?.interfaces || [], reqBody.receiverInterface);

  // Benchmark always rides UDP+IPv4: the KETI marker (seq + tx ns) lives in the UDP payload, so any other protocol (ARP, ICMP, raw) would yield zero matches at the receiver.
  const baseUdp = { ...baseProfile, protocol: 'udp' };
  baseUdp.udp = { srcPort: 40000, dstPort: 50000, ...(baseProfile.udp || {}) };
  baseUdp.ipv4 = { ttl: 64, ...(baseProfile.ipv4 || {}) };
  delete baseUdp.arp;
  delete baseUdp.icmp;
  delete baseUdp.etherType;
  const profile = profileForE2E(baseUdp, senderIface, receiverIface);
  const count = Number(reqBody.count || profile.count || 500);
  const intervalMs = Number(reqBody.intervalMs ?? profile.intervalMs ?? 1);
  profile.count = count;
  profile.intervalMs = intervalMs;
  profile.recordTimestamps = true;
  profile.payload = { mode: 'benchmark', size: Number(reqBody.payloadSize || profile.payload?.size || 64), start: 1 };

  // Stop the receiver agent as soon as our frames arrive. srcMac filter is
  // strict, so the agent only counts the sender's own frames; +20 grace lets
  // any in-flight stragglers in but doesn't make us wait a full timeout when
  // there is no background traffic to top up the bucket.
  const captureTimeoutSec = Number(reqBody.captureTimeoutSec || Math.max(4, Math.ceil((count * intervalMs) / 1000) + 2));
  const captureBody = {
    interface: receiverIface.name,
    timeoutSec: captureTimeoutSec,
    timeoutMs: captureTimeoutSec * 1000 + 5000,
    maxFrames: count, // strict srcMac filter means we only count our own frames; stop right when all arrive
    srcMac: senderIface.mac,
    lite: true // analysis only needs frameHex + decoded; skip the per-frame hexdump dump that bloats high-count benchmarks
  };

  const capturePromise = remoteJson(receiverUrl, '/api/capture', { method: 'POST', body: captureBody });
  await new Promise((resolve) => setTimeout(resolve, Number(reqBody.captureLeadMs || 800)));
  const sendResult = await remoteJson(senderUrl, '/api/send', {
    method: 'POST',
    body: { ...profile, timeoutMs: captureTimeoutSec * 1000 + 10000 }
  });
  const captureResult = await capturePromise;

  const txRecords = sendResult.stdout?.txRecords || [];
  const frames = captureResult.stdout?.frames || [];
  const elapsedSec = sendResult.stdout?.elapsedSec || (intervalMs * count) / 1000;
  const sentBytes = sendResult.stdout?.bytesSent || 0;
  const stats = analyzeBenchmark(txRecords, frames, sentBytes, elapsedSec);

  const report = {
    generatedAt: new Date().toISOString(),
    profileName: baseProfile.name || 'benchmark',
    sender: { url: senderUrl, interface: senderIface.name, mac: senderIface.mac, ip: firstIpv4(senderIface) },
    receiver: { url: receiverUrl, interface: receiverIface.name, mac: receiverIface.mac, ip: firstIpv4(receiverIface) },
    config: { count, intervalMs, payloadSize: profile.payload.size },
    stats
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'benchmark-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'benchmark-latest.html'), benchmarkReportHtml(report));
  return report;
}

async function runRfc2544Throughput(reqBody) {
  // RFC 2544 §26 Throughput: for each frame size, binary-search the highest
  // offered rate (frames/sec) at which the receiver still observes 0 loss.
  // We approximate the IFG via the Python agent's intervalMs (ms between
  // frames). For Linux usermode userland, sub-microsecond IFG isn't possible,
  // so we report the maximum *demonstrable* loss-free rate up to the kernel's
  // achievable cadence. Real RFC 2544 boxes use hardware schedulers.
  const sizes = reqBody.sizes || [64, 128, 256, 512, 1024, 1280, 1518];
  const trialDurationSec = Number(reqBody.trialDurationSec || 2);
  const tolerance = Number(reqBody.tolerancePps || 100); // pps width to stop
  const linkRateMbps = Number(reqBody.linkRateMbps || 1000);
  const results = [];
  for (const wireSize of sizes) {
    // RFC 2544 sizes (64 .. 1518) include the 4-byte FCS that AF_PACKET hides
    // from us. We program the agent with the in-buffer length (wireSize − 4)
    // and report results against the wire size for comparability.
    const size = Math.max(60, wireSize - 4);
    // Theoretical line-rate frames/sec — uses ethernetWireBytes() so the
    // companion WPF app and this server agree to the bit on the formula.
    const theoFps = theoreticalFps(wireSize, linkRateMbps);
    // Linux usermode AF_PACKET in Python tops out around ~30k pps depending on
    // CPU; clamp the upper bound so binary search doesn't waste iterations on
    // unreachable rates.
    const userlandCap = Number(reqBody.userlandCapPps || 30000);
    let lo = 500;
    let hi = Math.min(theoFps, userlandCap);
    let best = { fps: 0, throughputMbps: 0, lossPct: 100, txCount: 0, rxCount: 0 };
    const iterations = [];
    for (let iter = 0; iter < 8 && (hi - lo) > tolerance; iter += 1) {
      const fps = Math.floor((lo + hi) / 2);
      const intervalMs = 1000 / fps;
      const count = Math.max(50, Math.min(8000, Math.floor(fps * trialDurationSec)));
      const profile = {
        name: `RFC2544 ${size}B @ ${fps} fps`,
        protocol: 'udp',
        udp: { srcPort: 40000, dstPort: 50000 },
        ipv4: { ttl: 64 },
        payload: { mode: 'benchmark', size: Math.max(16, size - 42), start: 1 },
        targetFrameLength: size,
        count, intervalMs
      };
      const single = await runBenchmark({ ...reqBody, profile, count, intervalMs });
      const loss = single.stats.lossPct;
      iterations.push({ fps, intervalMs: Number(intervalMs.toFixed(3)), txCount: single.stats.txCount, rxCount: single.stats.rxCount, lossPct: Number(loss.toFixed(3)), throughputMbps: Number(single.stats.throughputMbps.toFixed(2)) });
      if (loss === 0) {
        if (fps > best.fps) {
          best = {
            fps,
            throughputMbps: Number(single.stats.throughputMbps.toFixed(2)),
            rxThroughputMbps: Number(single.stats.rxThroughputMbps.toFixed(2)),
            lossPct: 0,
            txCount: single.stats.txCount,
            rxCount: single.stats.rxCount,
            latencyUs: single.stats.latencyAdjustedUs,
            jitterUs: single.stats.jitterUs
          };
        }
        lo = fps;
      } else {
        hi = fps;
      }
    }
    results.push({
      size: wireSize,
      bufferSize: size,
      theoreticalFps: theoFps,
      bestFps: best.fps,
      utilizationPct: theoFps ? Number((100 * best.fps / theoFps).toFixed(2)) : 0,
      best,
      iterations
    });
  }
  const report = {
    generatedAt: new Date().toISOString(),
    standard: 'RFC 2544 §26 (throughput) — quick mode',
    config: { sizes, trialDurationSec, tolerance, linkRateMbps },
    note: 'Linux usermode AF_PACKET cannot deliver hardware-precise IFG; results are an upper bound on what the agent + kernel can sustain loss-free.',
    results
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'rfc2544-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'rfc2544-latest.html'), rfc2544ReportHtml(report));
  return report;
}

function rfc2544ReportHtml(report) {
  const sizes = report.results.map((r) => r.size);
  const theo = report.results.map((r) => r.theoreticalFps);
  const got = report.results.map((r) => r.bestFps);
  const util = report.results.map((r) => r.utilizationPct);
  const mbps = report.results.map((r) => r.best.throughputMbps || 0);
  const rows = report.results.map((r) => `<tr><td>${r.size}</td><td>${r.theoreticalFps.toLocaleString()}</td><td>${r.bestFps.toLocaleString()}</td><td>${r.utilizationPct.toFixed(2)}%</td><td>${(r.best.throughputMbps || 0).toFixed(2)}</td><td>${(r.best.latencyUs?.p95 || 0).toFixed(2)}</td><td>${(r.best.jitterUs?.mean || 0).toFixed(2)}</td><td>${r.iterations.length}</td></tr>`).join('');
  const detail = report.results.map((r) => {
    const itRows = r.iterations.map((it) => `<tr><td>${it.fps.toLocaleString()}</td><td>${it.intervalMs}</td><td>${it.txCount}</td><td>${it.rxCount}</td><td class="${it.lossPct === 0 ? 'pass' : 'fail'}">${it.lossPct.toFixed(2)}%</td><td>${it.throughputMbps.toFixed(2)}</td></tr>`).join('');
    return `<h3>Frame size ${r.size} B — best ${r.bestFps.toLocaleString()} fps (${r.utilizationPct.toFixed(2)}% of line)</h3><table class="iter"><thead><tr><th>offered fps</th><th>interval ms</th><th>tx</th><th>rx</th><th>loss</th><th>Mbps</th></tr></thead><tbody>${itRows}</tbody></table>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>RFC 2544 Throughput</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>body{margin:24px;font:14px/1.5 system-ui;color:#17202a}h1{margin:0 0 4px}.meta{color:#62707f;margin-bottom:18px}.charts{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:16px 0}.chartCard{border:1px solid #d2dae3;border-radius:10px;padding:12px}canvas{max-height:280px}table{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}th,td{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:right}th:first-child,td:first-child{text-align:left}th{background:#eef5f6}.iter{margin:8px 0 18px;font-size:12px}.pass{color:#14532d;font-weight:700}.fail{color:#9b1c1c;font-weight:700}.note{background:#fff5e8;border-left:4px solid #b9651a;padding:10px 14px;border-radius:6px;color:#6b4111;margin:12px 0}</style></head><body>
<h1>RFC 2544 Throughput Report</h1>
<div class="meta">Generated ${escapeHtml(report.generatedAt)} · ${escapeHtml(report.standard)}</div>
<div class="meta">Trial ${report.config.trialDurationSec}s per iteration · tolerance ${report.config.tolerance} fps · link assumed ${report.config.linkRateMbps} Mbps</div>
<div class="note">${escapeHtml(report.note)}</div>
<table><thead><tr><th>Size B</th><th>Theoretical fps</th><th>Loss-free fps</th><th>Utilization</th><th>Mbps</th><th>p95 lat µs</th><th>jitter µs</th><th>iters</th></tr></thead><tbody>${rows}</tbody></table>
<div class="charts">
  <div class="chartCard"><h3>Frames/sec achieved vs theoretical line rate</h3><canvas id="fpsChart"></canvas></div>
  <div class="chartCard"><h3>Utilization (%)</h3><canvas id="utilChart"></canvas></div>
  <div class="chartCard"><h3>Throughput (Mbps)</h3><canvas id="mbpsChart"></canvas></div>
</div>
<h2>Per-frame-size binary-search history</h2>
${detail}
<script>
const sizes=${JSON.stringify(sizes)};
const opts={responsive:true,animation:false,plugins:{legend:{position:'bottom'}}};
new Chart(document.getElementById('fpsChart'),{type:'line',data:{labels:sizes,datasets:[{label:'theoretical',data:${JSON.stringify(theo)},borderColor:'#94a3b8',borderDash:[5,5]},{label:'loss-free',data:${JSON.stringify(got)},borderColor:'#0ea5e9'}]},options:opts});
new Chart(document.getElementById('utilChart'),{type:'bar',data:{labels:sizes,datasets:[{label:'%',data:${JSON.stringify(util)},backgroundColor:'#0f6f78'}]},options:opts});
new Chart(document.getElementById('mbpsChart'),{type:'line',data:{labels:sizes,datasets:[{label:'Mbps',data:${JSON.stringify(mbps)},borderColor:'#16a34a'}]},options:opts});
</script></body></html>`;
}

async function runFrameSizeSweep(reqBody) {
  const sizes = reqBody.sizes || [64, 128, 256, 512, 1024, 1280, 1514];
  const count = Number(reqBody.count || 200);
  const intervalMs = Number(reqBody.intervalMs ?? 1);
  const results = [];
  for (const size of sizes) {
    const profile = {
      name: `Sweep ${size}B`,
      protocol: 'udp',
      udp: { srcPort: 40000, dstPort: 50000 },
      ipv4: { ttl: 64 },
      payload: { mode: 'benchmark', size: Math.max(16, size - 42), start: 1 },
      targetFrameLength: size,
      count,
      intervalMs
    };
    const single = await runBenchmark({ ...reqBody, profile, count, intervalMs });
    results.push({
      size,
      stats: {
        txCount: single.stats.txCount,
        rxCount: single.stats.rxCount,
        lossPct: single.stats.lossPct,
        throughputMbps: single.stats.throughputMbps,
        rxThroughputMbps: single.stats.rxThroughputMbps,
        latencyUs: single.stats.latencyUs,
        latencyAdjustedUs: single.stats.latencyAdjustedUs,
        jitterUs: single.stats.jitterUs
      }
    });
  }
  const report = {
    generatedAt: new Date().toISOString(),
    config: { count, intervalMs, sizes },
    results
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'sweep-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'sweep-latest.html'), sweepReportHtml(report));
  return report;
}

function testCaseReportHtml(report) {
  const statusClass = report.ok ? 'pass' : 'fail';
  const rows = report.steps.map((step, index) => `
    <tr class="${step.ok ? 'pass' : step.kind === 'delay' ? '' : 'fail'}">
      <td>${index + 1}</td>
      <td>${escapeHtml(step.kind)}</td>
      <td>${escapeHtml(step.name)}</td>
      <td>${step.kind === 'delay' ? `${step.delayMs} ms` : `${step.framesSent}/${step.expectedCount}`}</td>
      <td>${step.kind === 'delay' ? '-' : step.matchCount}</td>
      <td>${step.ok ? 'PASS' : step.kind === 'delay' ? 'DONE' : 'FAIL'}</td>
      <td>${escapeHtml(step.error || step.protocol || '')}</td>
    </tr>
  `).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Ethernet Packet Lab Test Case</title>
  <style>
    body{margin:24px;font:14px/1.45 system-ui,sans-serif;color:#17202a}
    h1{margin:0 0 4px}.meta{color:#62707f;margin-bottom:16px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:14px 0}
    .box{border:1px solid #d2dae3;border-radius:8px;padding:10px 12px;background:#fff}
    .box span{display:block;color:#62707f;font-size:12px}.box strong{font-size:24px}
    .pass{color:#14532d;font-weight:800}.fail{color:#9b1c1c;font-weight:800}
    table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border-bottom:1px solid #d2dae3;padding:8px;text-align:left}th{background:#eef5f6}
  </style>
</head>
<body>
  <h1>Ethernet Packet Lab Test Case</h1>
  <div class="meta">${escapeHtml(report.name)} — ${escapeHtml(report.generatedAt)}</div>
  <div class="meta">${escapeHtml(report.sender.url)}/${escapeHtml(report.sender.interface)} → ${escapeHtml(report.receiver.url)}/${escapeHtml(report.receiver.interface)}</div>
  <div class="grid">
    <div class="box"><span>Status</span><strong class="${statusClass}">${report.ok ? 'PASS' : 'FAIL'}</strong></div>
    <div class="box"><span>Steps</span><strong>${report.summary.total}</strong></div>
    <div class="box"><span>Packets sent</span><strong>${report.summary.framesSent}</strong></div>
    <div class="box"><span>Matched</span><strong>${report.summary.matched}</strong></div>
    <div class="box"><span>Captured</span><strong>${report.summary.captured}</strong></div>
  </div>
  <table>
    <thead><tr><th>No.</th><th>Type</th><th>Name</th><th>Tx</th><th>Rx Match</th><th>Status</th><th>Info</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}

async function runTestCase(reqBody) {
  const senderUrl = normalizeBaseUrl(reqBody.senderUrl);
  const receiverUrl = normalizeBaseUrl(reqBody.receiverUrl);
  const testCase = normalizeTestCase(reqBody.testCase || {});
  if (!testCase.steps.length) throw new Error('test case has no steps');
  const loopCount = Math.max(1, Number(reqBody.loopCount || 1));
  const cyclePeriodMs = Math.max(0, Number(reqBody.cyclePeriodMs || 0));

  const [senderInfo, receiverInfo] = await Promise.all([
    remoteJson(senderUrl, '/api/interfaces'),
    remoteJson(receiverUrl, '/api/interfaces')
  ]);
  const senderIface = selectInterface(senderInfo.stdout?.interfaces || [], reqBody.senderInterface);
  const receiverIface = selectInterface(receiverInfo.stdout?.interfaces || [], reqBody.receiverInterface);
  const packetSteps = testCase.steps.filter((step) => step.kind === 'packet' && step.enabled !== false);
  const expectedFrames = packetSteps.reduce((sum, step) => sum + Math.max(1, Number(step.count || 1)), 0);
  const onePassActiveMs = testCase.steps.reduce((sum, step) => {
    if (step.kind === 'delay') return sum + Number(step.delayMs || 0);
    return sum + (Math.max(0, Number(step.intervalMs || 0)) * Math.max(1, Number(step.count || 1)));
  }, 0);
  const activeMs = Math.max(onePassActiveMs, cyclePeriodMs) * loopCount;
  const captureTimeoutSec = Number(reqBody.timeoutSec || Math.max(8, Math.ceil(activeMs / 1000) + 5));
  const captureBody = {
    interface: receiverIface.name,
    timeoutSec: captureTimeoutSec,
    timeoutMs: captureTimeoutSec * 1000 + 5000,
    maxFrames: Number(reqBody.maxFrames || expectedFrames + 100),
    srcMac: senderIface.mac
  };

  const capturePromise = remoteJson(receiverUrl, '/api/capture', { method: 'POST', body: captureBody });
  await new Promise((resolve) => setTimeout(resolve, Number(reqBody.captureLeadMs || 800)));

  const sentSteps = [];
  for (let loop = 0; loop < loopCount; loop += 1) {
    const passStarted = Date.now();
    for (const step of testCase.steps) {
      const stepName = loopCount > 1 ? `L${loop + 1}: ${step.name}` : step.name;
      if (step.kind === 'delay') {
        const delayMs = Number(step.delayMs || 0);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        sentSteps.push({ kind: 'delay', name: stepName, delayMs, ok: true, loop: loop + 1 });
        continue;
      }
      if (step.enabled === false) {
        sentSteps.push({ kind: 'packet', name: stepName, skipped: true, ok: true, framesSent: 0, expectedCount: 0, loop: loop + 1 });
        continue;
      }
      const txProfile = profileForE2E(step.profile, senderIface, receiverIface);
      txProfile.count = Math.max(1, Number(step.count || txProfile.count || 1));
      txProfile.intervalMs = Math.max(0, Number(step.intervalMs ?? txProfile.intervalMs ?? 0));
      const buildResult = await remoteJson(senderUrl, '/api/build', { method: 'POST', body: txProfile });
      const sendResult = await remoteJson(senderUrl, '/api/send', {
        method: 'POST',
        body: { ...txProfile, timeoutMs: captureTimeoutSec * 1000 + 10000 }
      });
      sentSteps.push({
        kind: 'packet',
        name: stepName,
        ok: sendResult.ok,
        expectedCount: txProfile.count,
        framesSent: sendResult.stdout?.framesSent || 0,
        protocol: decodedProtocol(sendResult.stdout?.decoded),
        sentDecoded: sendResult.stdout?.decoded,
        expectedFrameHex: ['sequence', 'random', 'benchmark'].includes(txProfile.payload?.mode)
          ? ''
          : buildResult.stdout?.frameHex,
        txProfile,
        loop: loop + 1
      });
    }
    const elapsed = Date.now() - passStarted;
    const remaining = cyclePeriodMs - elapsed;
    if (loop < loopCount - 1 && remaining > 0) {
      await new Promise((resolve) => setTimeout(resolve, remaining));
    }
  }

  const captureResult = await capturePromise;
  const frames = captureResult.stdout?.frames || [];
  const usedFrameIndexes = new Set();
  const packetResults = sentSteps.map((step) => {
    if (step.kind !== 'packet' || step.skipped) return step;
    // Pre-compute a VLAN-stripped variant of the expected hex, so receivers
    // running with rxvlan offload (which removes the 0x8100 + TCI from the
    // visible buffer) still match cleanly.
    let altHex = null;
    if (step.expectedFrameHex && step.sentDecoded?.vlan) {
      // Ethernet header is 14B (28 hex chars). VLAN tag is 4B (8 hex chars)
      // immediately after src/dst MAC. Drop bytes 12..16 (hex 24..32).
      altHex = step.expectedFrameHex.slice(0, 24) + step.expectedFrameHex.slice(32);
    }
    // Cap matched frames per step at expectedCount so a step with a
    // deterministic frameHex doesn't greedily claim identical frames belonging
    // to a later loop iteration of the same profile.
    const matched = [];
    const cap = Math.max(1, Number(step.expectedCount || 1));
    for (let frameIndex = 0; frameIndex < frames.length && matched.length < cap; frameIndex += 1) {
      if (usedFrameIndexes.has(frameIndex)) continue;
      const frame = frames[frameIndex];
      if (step.expectedFrameHex) {
        if (frame.frameHex !== step.expectedFrameHex && (!altHex || frame.frameHex !== altHex)) continue;
      } else if (!isExpectedFrame(frame, step.sentDecoded, senderIface, receiverIface)) {
        continue;
      }
      usedFrameIndexes.add(frameIndex);
      matched.push(frame);
    }
    return {
      ...step,
      ok: step.ok && matched.length >= step.expectedCount,
      matchCount: matched.length,
      sampleFrames: matched.slice(0, 5),
      sentDecoded: undefined,
      expectedFrameHex: undefined
    };
  });
  const framesSent = packetResults.reduce((sum, step) => sum + Number(step.framesSent || 0), 0);
  const matched = packetResults.reduce((sum, step) => sum + Number(step.matchCount || 0), 0);
  const failed = packetResults.filter((step) => step.kind === 'packet' && !step.ok).length;
  const report = {
    generatedAt: new Date().toISOString(),
    ok: failed === 0,
    id: testCase.id,
    name: testCase.name,
    description: testCase.description,
    sender: { url: senderUrl, interface: senderIface.name, mac: senderIface.mac, ip: firstIpv4(senderIface) },
    receiver: { url: receiverUrl, interface: receiverIface.name, mac: receiverIface.mac, ip: firstIpv4(receiverIface) },
    summary: {
      total: packetResults.length,
      failed,
      framesSent,
      matched,
      captured: frames.length,
      loopCount,
      cyclePeriodMs
    },
    steps: packetResults,
    capturedFrames: frames.slice(0, 500),
    testCase
  };
  await mkdir(reportsDir, { recursive: true });
  await writeFile(join(reportsDir, 'testcase-latest.json'), JSON.stringify(report, null, 2));
  await writeFile(join(reportsDir, 'testcase-latest.html'), testCaseReportHtml(report));
  return report;
}

async function runWireValidation(reqBody) {
  const { profiles } = await loadExampleItems();
  const orderedKeys = [
    '01_arp_request',
    '02_icmp_echo',
    '03_udp_unicast_basic',
    '04_udp_sequence',
    '05_payload_pattern_aa55',
    '06_payload_counter_256',
    '07_frame_size_64',
    '08_frame_size_128',
    '09_frame_size_256',
    '10_frame_size_512',
    '11_frame_size_1024',
    '08_frame_size_1514',
    '09_vlan10_udp_pcp0',
    '10_vlan10_udp_pcp7',
    '11_vlan20_isolation'
  ];
  const steps = [];
  for (const key of orderedKeys) {
    const profile = profiles[key];
    if (!profile) continue;
    steps.push({
      kind: 'packet',
      name: profile.name || key,
      enabled: true,
      count: Number(reqBody.count || (profile.priority <= 3 ? 3 : 2)),
      intervalMs: Number(reqBody.intervalMs ?? 100),
      profile
    });
    steps.push({ kind: 'delay', name: 'Guard 100 ms', delayMs: 100 });
  }
  return runTestCase({
    ...reqBody,
    testCase: {
      id: 'wire-standard-validation',
      name: 'Wire Standard Validation',
      description: 'On-wire ARP, ICMP, UDP, payload integrity, frame-size, VLAN, and PCP validation.',
      steps
    },
    maxFrames: Number(reqBody.maxFrames || 500)
  });
}

function sweepReportHtml(report) {
  const sizes = report.results.map((r) => r.size);
  const tx = report.results.map((r) => r.stats.throughputMbps.toFixed(2));
  const rx = report.results.map((r) => r.stats.rxThroughputMbps.toFixed(2));
  const loss = report.results.map((r) => r.stats.lossPct.toFixed(2));
  const p95 = report.results.map((r) => (r.stats.latencyAdjustedUs?.p95 ?? r.stats.latencyUs.p95 ?? 0).toFixed(2));
  const rows = report.results.map((r) => {
    const adj = r.stats.latencyAdjustedUs || {};
    const p50 = (adj.p50 ?? r.stats.latencyUs.p50 ?? 0).toFixed(2);
    const p95v = (adj.p95 ?? r.stats.latencyUs.p95 ?? 0).toFixed(2);
    return `<tr><td>${r.size}</td><td>${r.stats.txCount}</td><td>${r.stats.rxCount}</td><td>${r.stats.lossPct.toFixed(2)}%</td><td>${r.stats.throughputMbps.toFixed(2)}</td><td>${r.stats.rxThroughputMbps.toFixed(2)}</td><td>${p50}</td><td>${p95v}</td><td>${(r.stats.jitterUs.mean||0).toFixed(2)}</td></tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Frame Size Sweep</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>body{margin:24px;font:14px/1.45 system-ui;color:#17202a}.charts{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0}.chartCard{border:1px solid #d2dae3;border-radius:10px;padding:12px}canvas{max-height:280px}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{border-bottom:1px solid #e2e8f0;padding:6px;text-align:right}th:first-child,td:first-child{text-align:left}th{background:#eef5f6}</style>
</head><body>
<h1>Frame Size Sweep</h1><div>${escapeHtml(report.generatedAt)} — count=${report.config.count}, interval=${report.config.intervalMs}ms</div>
<div class="charts">
<div class="chartCard"><h3>Throughput vs frame size</h3><canvas id="tp"></canvas></div>
<div class="chartCard"><h3>Loss % vs frame size</h3><canvas id="loss"></canvas></div>
<div class="chartCard"><h3>Latency p95 (µs)</h3><canvas id="lat"></canvas></div>
<div class="chartCard"><h3>Jitter mean |Δlat| (µs)</h3><canvas id="jit"></canvas></div>
</div>
<table><thead><tr><th>Size</th><th>Tx</th><th>Rx</th><th>Loss</th><th>Tx Mbps</th><th>Rx Mbps</th><th>Lat p50µs</th><th>Lat p95µs</th><th>Jitter µs</th></tr></thead><tbody>${rows}</tbody></table>
<script>
const sizes=${JSON.stringify(sizes)};
const opts={responsive:true,animation:false,plugins:{legend:{position:'bottom'}}};
new Chart(document.getElementById('tp'),{type:'line',data:{labels:sizes,datasets:[{label:'Tx Mbps',data:${JSON.stringify(tx)}.map(Number),borderColor:'#0ea5e9'},{label:'Rx Mbps',data:${JSON.stringify(rx)}.map(Number),borderColor:'#16a34a'}]},options:opts});
new Chart(document.getElementById('loss'),{type:'bar',data:{labels:sizes,datasets:[{label:'%',data:${JSON.stringify(loss)}.map(Number),backgroundColor:'#ef4444'}]},options:opts});
new Chart(document.getElementById('lat'),{type:'line',data:{labels:sizes,datasets:[{label:'p95 µs',data:${JSON.stringify(p95)}.map(Number),borderColor:'#7c3aed'}]},options:opts});
const jit=${JSON.stringify(report.results.map((r)=>(r.stats.jitterUs.mean||0).toFixed(2)))}.map(Number);
new Chart(document.getElementById('jit'),{type:'line',data:{labels:sizes,datasets:[{label:'µs',data:jit,borderColor:'#f59e0b'}]},options:opts});
</script></body></html>`;
}

// --- Serial / TTY console support ---------------------------------------
const ttySessions = new Map(); // id -> { child, buffer, subscribers, config }
let nextTtyId = 1;
const serialAgentPath = join(root, 'tools', 'serial_agent.py');

function listTtys() {
  const out = [];
  let names;
  try { names = readdirSync('/sys/class/tty'); } catch { return out; }
  for (const name of names) {
    // ttyS* (legacy 8250) ports always exist on x86 even without hardware
    // attached, so default to USB / CDC / SoC UARTs. Add ?legacy=1 to include them.
    if (!/^(ttyUSB|ttyACM|ttyAMA|ttymxc|ttyTHS)\d+$/.test(name)) continue;
    const info = { path: `/dev/${name}`, name };
    try {
      const driver = readlinkSync(`/sys/class/tty/${name}/device/driver`).split('/').pop();
      if (driver) info.driver = driver;
    } catch {}
    try {
      const uevent = readFileSync(`/sys/class/tty/${name}/device/uevent`, 'utf8');
      const product = uevent.match(/PRODUCT=([^\n]+)/);
      if (product) info.product = product[1].trim();
    } catch {}
    // Walk up to find vendor / product strings (USB devices)
    try {
      let p = `/sys/class/tty/${name}/device`;
      for (let i = 0; i < 6; i += 1) {
        try {
          const v = readFileSync(`${p}/idVendor`, 'utf8').trim();
          const pr = readFileSync(`${p}/idProduct`, 'utf8').trim();
          info.usbId = `${v}:${pr}`;
          try { info.manufacturer = readFileSync(`${p}/manufacturer`, 'utf8').trim(); } catch {}
          try { info.usbProduct = readFileSync(`${p}/product`, 'utf8').trim(); } catch {}
          try { info.serial = readFileSync(`${p}/serial`, 'utf8').trim(); } catch {}
          break;
        } catch {}
        p = `${p}/..`;
      }
    } catch {}
    out.push(info);
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

function destroyTtySession(id) {
  const s = ttySessions.get(id);
  if (!s) return;
  clearTimeout(s.idleTimer);
  for (const sub of s.subscribers) {
    try { sub.end(); } catch {}
  }
  try { s.child.stdin.end(JSON.stringify({ type: 'close' }) + '\n'); } catch {}
  setTimeout(() => { try { s.child.kill('SIGTERM'); } catch {} }, 300).unref();
  setTimeout(() => { try { s.child.kill('SIGKILL'); } catch {} }, 1500).unref();
  ttySessions.delete(id);
}

const TTY_IDLE_TIMEOUT_MS = 60_000;

function armTtyIdleTimer(id) {
  const s = ttySessions.get(id);
  if (!s) return;
  clearTimeout(s.idleTimer);
  s.idleTimer = setTimeout(() => {
    if (!ttySessions.has(id)) return;
    const cur = ttySessions.get(id);
    if (cur.subscribers.length === 0) {
      console.log(`[tty ${id}] idle for ${TTY_IDLE_TIMEOUT_MS}ms with no subscribers, closing`);
      destroyTtySession(id);
    }
  }, TTY_IDLE_TIMEOUT_MS).unref();
}

function openTtySession(config) {
  const id = String(nextTtyId++);
  const child = spawn('python3', [serialAgentPath], {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe']
  });
  child.stdin.write(JSON.stringify(config) + '\n');
  const session = { child, buffer: '', subscribers: [], config, idleTimer: null };
  ttySessions.set(id, session);
  armTtyIdleTimer(id);
  child.stdout.on('data', (chunk) => {
    session.buffer += chunk.toString('utf8');
    let nl;
    while ((nl = session.buffer.indexOf('\n')) >= 0) {
      const line = session.buffer.slice(0, nl + 1);
      session.buffer = session.buffer.slice(nl + 1);
      for (const sub of session.subscribers) {
        try { sub.write(line); } catch {}
      }
    }
  });
  child.stderr.on('data', (chunk) => {
    const msg = JSON.stringify({ type: 'stderr', data: chunk.toString('utf8') }) + '\n';
    for (const sub of session.subscribers) { try { sub.write(msg); } catch {} }
  });
  child.on('exit', () => {
    const msg = JSON.stringify({ type: 'closed' }) + '\n';
    for (const sub of session.subscribers) { try { sub.write(msg); sub.end(); } catch {} }
    ttySessions.delete(id);
  });
  return id;
}

async function handleApi(req, res) {
  try {
    if (req.method === 'GET' && req.url === '/api/version') {
      let commit = 'dev';
      try {
        const head = readFileSync(join(root, '.git', 'HEAD'), 'utf8').trim();
        if (head.startsWith('ref:')) {
          commit = readFileSync(join(root, '.git', head.slice(5)), 'utf8').trim().slice(0, 7);
        } else {
          commit = head.slice(0, 7);
        }
      } catch {}
      return sendJson(res, 200, { ok: true, commit, node: process.version });
    }

    if (req.method === 'GET' && req.url === '/api/interfaces') {
      const result = await runAgent(['interfaces']);
      return sendJson(res, result.ok ? 200 : 500, result);
    }

    if (req.method === 'GET' && req.url === '/api/examples') {
      const { profiles, items } = await loadExampleItems();
      return sendJson(res, 200, { ok: true, profiles, items });
    }

    if (req.method === 'GET' && req.url === '/api/test-cases') {
      const items = await loadTestCases();
      return sendJson(res, 200, { ok: true, items });
    }

    if (req.method === 'GET' && req.url === '/api/test-profiles') {
      const items = await loadTestProfiles();
      return sendJson(res, 200, { ok: true, items });
    }

    if (req.method === 'POST' && req.url === '/api/test-cases') {
      const body = await readRequestJson(req);
      const testCase = await saveTestCase(body);
      return sendJson(res, 200, { ok: true, testCase });
    }

    if (req.method === 'DELETE' && req.url?.startsWith('/api/test-cases/')) {
      const id = decodeURIComponent(req.url.split('/').pop() || '');
      await unlink(testCasePath(id));
      return sendJson(res, 200, { ok: true, id: slugifyId(id) });
    }

    if (req.method === 'POST' && req.url === '/api/run-report') {
      const report = await runProfileReport();
      return sendJson(res, report.summary.fail === 0 ? 200 : 400, {
        ok: report.summary.fail === 0,
        report,
        html: '/reports/latest.html',
        json: '/reports/latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/wire-validation') {
      const body = await readRequestJson(req);
      const report = await runWireValidation(body);
      return sendJson(res, 200, {
        ok: true,
        validationOk: report.ok,
        report,
        html: '/reports/testcase-latest.html',
        json: '/reports/testcase-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/probe-node') {
      const body = await readRequestJson(req);
      const info = await remoteJson(body.url, '/api/interfaces');
      return sendJson(res, 200, { ok: true, url: normalizeBaseUrl(body.url), interfaces: info.stdout?.interfaces || [] });
    }

    if (req.method === 'POST' && req.url === '/api/benchmark') {
      const body = await readRequestJson(req);
      const report = await runBenchmark(body);
      return sendJson(res, 200, {
        ok: report.stats.rxCount > 0,
        report,
        html: '/reports/benchmark-latest.html',
        json: '/reports/benchmark-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/rfc2544') {
      const body = await readRequestJson(req);
      const report = await runRfc2544Throughput(body);
      return sendJson(res, 200, {
        ok: true,
        report,
        html: '/reports/rfc2544-latest.html',
        json: '/reports/rfc2544-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/sweep') {
      const body = await readRequestJson(req);
      const report = await runFrameSizeSweep(body);
      return sendJson(res, 200, {
        ok: true,
        report,
        html: '/reports/sweep-latest.html',
        json: '/reports/sweep-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/run-test-case') {
      const body = await readRequestJson(req);
      const report = await runTestCase(body);
      return sendJson(res, 200, {
        ok: true,
        validationOk: report.ok,
        report,
        html: '/reports/testcase-latest.html',
        json: '/reports/testcase-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/e2e-test') {
      const body = await readRequestJson(req);
      const report = await runE2ETest(body);
      return sendJson(res, report.ok ? 200 : 400, {
        ok: report.ok,
        report,
        html: '/reports/e2e-latest.html',
        json: '/reports/e2e-latest.json'
      });
    }

    if (req.method === 'POST' && req.url === '/api/build') {
      const body = await readRequestJson(req);
      const result = await runAgent(['build'], body);
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    if (req.method === 'POST' && req.url === '/api/send') {
      const body = await readRequestJson(req);
      // Sanity-clamp counts/intervals so a fat-finger '0' or negative value
      // can't spin the agent forever.
      if (typeof body.count !== 'undefined') body.count = Math.max(1, Math.min(1_000_000, Number(body.count) || 1));
      if (typeof body.intervalMs !== 'undefined') body.intervalMs = Math.max(0, Math.min(60_000, Number(body.intervalMs) || 0));
      const result = await runAgent(['send'], body, Number(body.timeoutMs || 30000));
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    if (req.method === 'POST' && req.url === '/api/capture') {
      const body = await readRequestJson(req);
      const result = await runAgent(['capture'], body, Number(body.timeoutMs || 15000) + 5000);
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    if (req.method === 'POST' && req.url === '/api/verify-prbs') {
      const body = await readRequestJson(req);
      const result = await runAgent(['verify-prbs'], body, Number(body.timeoutSec || 5) * 1000 + 5000);
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    if (req.method === 'POST' && req.url === '/api/capture-stream') {
      const body = await readRequestJson(req);
      res.writeHead(200, {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-cache',
        'x-accel-buffering': 'no'
      });
      const child = spawn('python3', [agentPath, 'capture-stream'], {
        cwd: root,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      child.stdin.end(JSON.stringify(body));
      // Backpressure-aware NDJSON forwarding.
      // If the browser can't drain fast enough, res.write() returns false and
      // we'd otherwise let the kernel buffer grow until the agent stalls. Drop
      // intermediate chunks instead of blocking; emit a 'drops' meta event so
      // the UI can flag it. Pause/resume the child stdout so backpressure also
      // throttles the python side.
      let dropped = 0;
      let lastDropEmit = 0;
      child.stdout.on('data', (chunk) => {
        if (res.writableEnded) return;
        const ok = res.write(chunk);
        if (!ok) {
          child.stdout.pause();
          res.once('drain', () => { try { child.stdout.resume(); } catch {} });
        }
      });
      // periodic drop-stats heartbeat (in case the client wants it surfaced)
      const dropTimer = setInterval(() => {
        if (res.writableEnded) return;
        const now = Date.now();
        if (dropped && now - lastDropEmit > 2000) {
          lastDropEmit = now;
          try { res.write(JSON.stringify({ type: 'streamDrops', dropped }) + '\n'); } catch {}
          dropped = 0;
        }
      }, 1000);
      child.stderr.on('data', (chunk) => {
        const txt = chunk.toString('utf8').trim();
        if (!res.writableEnded && txt) res.write(JSON.stringify({ type: 'log', stderr: txt }) + '\n');
      });
      const cleanup = () => {
        clearInterval(dropTimer);
        try { child.kill('SIGTERM'); } catch {}
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500).unref();
      };
      child.on('close', () => {
        clearInterval(dropTimer);
        if (!res.writableEnded) res.end();
      });
      req.on('close', cleanup);
      req.on('aborted', cleanup);
      return;
    }

    if (req.method === 'GET' && req.url === '/api/tty/list') {
      return sendJson(res, 200, { ok: true, ttys: listTtys() });
    }

    if (req.method === 'POST' && req.url === '/api/tty/open') {
      const body = await readRequestJson(req);
      if (!body.path) return sendJson(res, 400, { ok: false, error: 'path required' });
      const id = openTtySession({
        path: String(body.path),
        baudRate: Number(body.baudRate || 115200),
        dataBits: Number(body.dataBits || 8),
        parity: String(body.parity || 'N'),
        stopBits: Number(body.stopBits || 1),
        hwFlow: Boolean(body.hwFlow)
      });
      return sendJson(res, 200, { ok: true, sessionId: id });
    }

    if (req.method === 'GET' && req.url.startsWith('/api/tty/stream')) {
      const u = new URL(req.url, 'http://x');
      const id = u.searchParams.get('session');
      const s = ttySessions.get(id);
      if (!s) return sendJson(res, 404, { ok: false, error: 'session not found' });
      res.writeHead(200, {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-cache',
        'x-accel-buffering': 'no'
      });
      res.write(JSON.stringify({ type: 'subscribed', sessionId: id, config: s.config }) + '\n');
      s.subscribers.push(res);
      clearTimeout(s.idleTimer);   // active subscriber cancels idle close
      const cleanup = () => {
        const idx = s.subscribers.indexOf(res);
        if (idx >= 0) s.subscribers.splice(idx, 1);
        if (s.subscribers.length === 0) armTtyIdleTimer(id);
      };
      req.on('close', cleanup);
      req.on('aborted', cleanup);
      return;
    }

    if (req.method === 'POST' && req.url === '/api/tty/write') {
      const body = await readRequestJson(req);
      const s = ttySessions.get(String(body.sessionId));
      if (!s) return sendJson(res, 404, { ok: false, error: 'session not found' });
      try { s.child.stdin.write(JSON.stringify({ type: 'tx', hex: String(body.hex || '') }) + '\n'); }
      catch (err) { return sendJson(res, 500, { ok: false, error: err.message }); }
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && req.url === '/api/tty/control') {
      const body = await readRequestJson(req);
      const s = ttySessions.get(String(body.sessionId));
      if (!s) return sendJson(res, 404, { ok: false, error: 'session not found' });
      const cmd = { type: String(body.cmd) };
      if ('value' in body) cmd.value = Boolean(body.value);
      try { s.child.stdin.write(JSON.stringify(cmd) + '\n'); }
      catch (err) { return sendJson(res, 500, { ok: false, error: err.message }); }
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && req.url === '/api/tty/close') {
      const body = await readRequestJson(req);
      destroyTtySession(String(body.sessionId));
      return sendJson(res, 200, { ok: true });
    }

    return sendJson(res, 404, { ok: false, error: 'Unknown API route' });
  } catch (error) {
    return sendJson(res, 500, { ok: false, error: error.message });
  }
}

function serveStatic(req, res) {
  let requestPath;
  try {
    // Use a fixed base; req.headers.host can be empty/malformed and URL() throws on
    // exotic inputs like '//'. Fall back to a simple path strip.
    requestPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    const q = req.url.indexOf('?');
    requestPath = q >= 0 ? req.url.slice(0, q) : req.url;
  }
  if (!requestPath || requestPath[0] !== '/') requestPath = '/' + (requestPath || '');
  const clean = normalize(requestPath).replace(/^(\.\.[/\\])+/, '');
  if (clean.startsWith('/reports/')) {
    const reportPath = join(root, clean);
    if (reportPath.startsWith(reportsDir) && existsSync(reportPath) && fsStatIsFile(reportPath)) {
      const type = mimeTypes.get(extname(reportPath)) || 'text/html; charset=utf-8';
      res.writeHead(200, { 'content-type': type });
      createReadStream(reportPath).pipe(res);
      return;
    }
  }
  const relative = clean === '/' ? '/index.html' : clean;
  const filePath = join(publicDir, relative);

  if (!filePath.startsWith(publicDir) || !existsSync(filePath) || !fsStatIsFile(filePath)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  const type = mimeTypes.get(extname(filePath)) || 'application/octet-stream';
  res.writeHead(200, { 'content-type': type });
  createReadStream(filePath).pipe(res);
}

const server = createServer((req, res) => {
  try {
    if (req.url?.startsWith('/api/')) {
      handleApi(req, res);
      return;
    }
    serveStatic(req, res);
  } catch (err) {
    try {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      }
      res.end(`Server error: ${err.message}\n`);
    } catch {}
    console.error(`[handler] ${req.method} ${req.url} →`, err.message);
  }
});

// Last-line safety net: an unhandled rejection or async throw must never bring
// the lab down — log and keep serving.
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Ethernet Packet Lab listening on http://0.0.0.0:${port}`);
});
