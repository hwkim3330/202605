import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createReadStream, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const publicDir = join(root, 'public');
const nodeModulesDir = join(root, 'node_modules');
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

async function handleApi(req, res) {
  try {
    if (req.method === 'GET' && req.url === '/api/interfaces') {
      const result = await runAgent(['interfaces']);
      return sendJson(res, result.ok ? 200 : 500, result);
    }

    if (req.method === 'GET' && req.url === '/api/examples') {
      const udp = JSON.parse(await readFile(join(root, 'examples', 'udp_profile.json'), 'utf8'));
      const arp = JSON.parse(await readFile(join(root, 'examples', 'arp_request_profile.json'), 'utf8'));
      const icmp = JSON.parse(await readFile(join(root, 'examples', 'icmp_echo_profile.json'), 'utf8'));
      return sendJson(res, 200, { ok: true, profiles: { udp, arp, icmp } });
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

    if (req.method === 'POST' && req.url === '/api/scan') {
      const body = await readRequestJson(req);
      const result = await runAgent(['scan'], body, Number(body.timeoutMs || 20000) + 5000);
      return sendJson(res, result.ok ? 200 : 400, result);
    }

    return sendJson(res, 404, { ok: false, error: 'Unknown API route' });
  } catch (error) {
    return sendJson(res, 500, { ok: false, error: error.message });
  }
}

function serveStatic(req, res) {
  const requestPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  if (requestPath === '/vendor/d3.min.js') {
    const d3Path = join(nodeModulesDir, 'd3', 'dist', 'd3.min.js');
    if (existsSync(d3Path)) {
      res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8' });
      createReadStream(d3Path).pipe(res);
      return;
    }
  }
  const clean = normalize(requestPath).replace(/^(\.\.[/\\])+/, '');
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
