import { createServer } from 'node:http';
import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { createReadStream, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

async function readRequestJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
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
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers: { 'content-type': 'application/json' },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const body = await response.json();
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
  if (sentDecoded?.length && decoded.length !== sentDecoded.length) return false;
  if (!sameValue(decoded.ethernet?.srcMac, senderIface.mac)) return false;
  if (sentDecoded?.ethernet?.dstMac && !sameValue(decoded.ethernet?.dstMac, sentDecoded.ethernet.dstMac)) return false;
  if (decodedProtocol(decoded) !== decodedProtocol(sentDecoded)) return false;

  if (sentDecoded?.vlan) {
    if (!decoded.vlan) return false;
    if (decoded.vlan.id !== sentDecoded.vlan.id) return false;
    if (decoded.vlan.priority !== sentDecoded.vlan.priority) return false;
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

  const captureTimeoutSec = Number(reqBody.captureTimeoutSec || Math.max(8, Math.ceil((count * intervalMs) / 1000) + 5));
  const captureBody = {
    interface: receiverIface.name,
    timeoutSec: captureTimeoutSec,
    timeoutMs: captureTimeoutSec * 1000 + 5000,
    maxFrames: count + 100,
    srcMac: senderIface.mac
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
    const matched = [];
    frames.forEach((frame, frameIndex) => {
      if (usedFrameIndexes.has(frameIndex)) return;
      if (step.expectedCount === 1 && step.expectedFrameHex) {
        if (frame.frameHex !== step.expectedFrameHex) return;
      } else if (!isExpectedFrame(frame, step.sentDecoded, senderIface, receiverIface)) {
        return;
      }
      usedFrameIndexes.add(frameIndex);
      matched.push(frame);
    });
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
  const p95 = report.results.map((r) => (r.stats.latencyUs.p95 || 0).toFixed(2));
  const rows = report.results.map((r) => `<tr><td>${r.size}</td><td>${r.stats.txCount}</td><td>${r.stats.rxCount}</td><td>${r.stats.lossPct.toFixed(2)}%</td><td>${r.stats.throughputMbps.toFixed(2)}</td><td>${r.stats.rxThroughputMbps.toFixed(2)}</td><td>${(r.stats.latencyUs.p50||0).toFixed(2)}</td><td>${(r.stats.latencyUs.p95||0).toFixed(2)}</td><td>${(r.stats.jitterUs.mean||0).toFixed(2)}</td></tr>`).join('');
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

async function handleApi(req, res) {
  try {
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
      const result = await runAgent(['send'], body, Number(body.timeoutMs || 30000));
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    if (req.method === 'POST' && req.url === '/api/capture') {
      const body = await readRequestJson(req);
      const result = await runAgent(['capture'], body, Number(body.timeoutMs || 15000) + 5000);
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
      child.stdout.on('data', (chunk) => {
        if (!res.writableEnded) res.write(chunk);
      });
      child.stderr.on('data', (chunk) => {
        const txt = chunk.toString('utf8').trim();
        if (!res.writableEnded && txt) res.write(JSON.stringify({ type: 'log', stderr: txt }) + '\n');
      });
      const cleanup = () => {
        try { child.kill('SIGTERM'); } catch {}
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500).unref();
      };
      child.on('close', () => {
        if (!res.writableEnded) res.end();
      });
      req.on('close', cleanup);
      req.on('aborted', cleanup);
      return;
    }

    return sendJson(res, 404, { ok: false, error: 'Unknown API route' });
  } catch (error) {
    return sendJson(res, 500, { ok: false, error: error.message });
  }
}

function serveStatic(req, res) {
  const requestPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  const clean = normalize(requestPath).replace(/^(\.\.[/\\])+/, '');
  if (clean.startsWith('/reports/')) {
    const reportPath = join(root, clean);
    if (reportPath.startsWith(reportsDir) && existsSync(reportPath)) {
      const type = mimeTypes.get(extname(reportPath)) || 'text/html; charset=utf-8';
      res.writeHead(200, { 'content-type': type });
      createReadStream(reportPath).pipe(res);
      return;
    }
  }
  const relative = clean === '/' ? '/index.html' : clean;
  const filePath = join(publicDir, relative);

  if (!filePath.startsWith(publicDir) || !existsSync(filePath)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  const type = mimeTypes.get(extname(filePath)) || 'application/octet-stream';
  res.writeHead(200, { 'content-type': type });
  createReadStream(filePath).pipe(res);
}

const server = createServer((req, res) => {
  if (req.url?.startsWith('/api/')) {
    handleApi(req, res);
    return;
  }
  serveStatic(req, res);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Ethernet Packet Lab listening on http://0.0.0.0:${port}`);
});
