import { createServer } from 'node:http';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createReadStream, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const publicDir = join(root, 'public');
const reportsDir = join(root, 'reports');
const agentPath = join(root, 'tools', 'packet_agent.py');
const port = Number(process.env.PORT || 8080);

const mimeTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
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

    if (req.method === 'POST' && req.url === '/api/run-report') {
      const report = await runProfileReport();
      return sendJson(res, report.summary.fail === 0 ? 200 : 400, {
        ok: report.summary.fail === 0,
        report,
        html: '/reports/latest.html',
        json: '/reports/latest.json'
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
