#!/usr/bin/env node

// Regression checks for cross-origin / DNS-rebinding protection on the canvas
// server and symlink-safe path confinement for MCP file imports/exports.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const serverPath = join(repoRoot, 'dist', 'server.js');
const port = Number(process.env.PORT || 34000 + Math.floor(Math.random() * 2000));
const allowedExtra = 'http://localhost:8080';

function request(path, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, res => {
      res.resume();
      res.on('end', () => resolve(res));
    });
    req.on('error', reject);
    req.end();
  });
}

function wsOutcome(headers) {
  return new Promise(resolve => {
    const socket = new WebSocket(`ws://127.0.0.1:${port}`, { headers });
    socket.once('message', () => {
      socket.close();
      resolve('open');
    });
    socket.once('unexpected-response', (_req, res) => resolve(res.statusCode));
    socket.once('error', () => resolve('error'));
  });
}

async function waitForHealth(deadlineMs = 5000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    try {
      const res = await request('/health');
      if (res.statusCode === 200) return;
    } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('canvas server did not become healthy');
}

async function checkServer() {
  const child = spawn(process.execPath, [serverPath], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      LOG_LEVEL: 'error',
      EXCALIDRAW_ALLOWED_ORIGINS: allowedExtra,
      EXCALIDRAW_DATA_DIR: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await waitForHealth();
    const self = `http://127.0.0.1:${port}`;

    assert.equal((await request('/api/elements')).statusCode, 200, 'non-browser client rejected');
    assert.equal((await request('/api/elements', { headers: { Origin: self } })).statusCode, 200, 'same-origin page rejected');
    assert.equal(
      (await request('/api/elements', { headers: { Origin: `http://localhost:${port}`, Host: `localhost:${port}` } })).statusCode,
      200,
      'same-origin page via localhost rejected'
    );

    const extra = await request('/api/elements', { headers: { Origin: allowedExtra } });
    assert.equal(extra.statusCode, 200, 'EXCALIDRAW_ALLOWED_ORIGINS entry rejected');
    assert.equal(extra.headers['access-control-allow-origin'], allowedExtra, 'allowed origin got no CORS header');

    const foreign = await request('/api/elements', { headers: { Origin: 'https://evil.example' } });
    assert.equal(foreign.statusCode, 403, 'foreign origin could read the canvas');
    assert.equal(foreign.headers['access-control-allow-origin'], undefined, 'foreign origin got a CORS header');

    assert.equal(
      (await request('/api/elements/clear', { method: 'DELETE', headers: { Origin: 'https://evil.example' } })).statusCode,
      403,
      'foreign origin could clear the canvas'
    );
    assert.equal(
      (await request('/api/elements', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'DELETE' } })).statusCode,
      403,
      'foreign origin passed the CORS preflight'
    );
    assert.equal((await request('/api/elements', { headers: { Origin: 'null' } })).statusCode, 403, 'null origin accepted');

    // DNS rebinding: attacker hostname resolving to 127.0.0.1, same-origin from the browser's view.
    assert.equal(
      (await request('/api/elements', { headers: { Host: `evil.example:${port}`, Origin: `http://evil.example:${port}` } })).statusCode,
      403,
      'DNS-rebinding Host header accepted'
    );

    assert.equal(await wsOutcome({}), 'open', 'non-browser WebSocket rejected');
    assert.equal(await wsOutcome({ Origin: self }), 'open', 'same-origin WebSocket rejected');
    assert.equal(await wsOutcome({ Origin: 'https://evil.example' }), 403, 'foreign-origin WebSocket accepted');
  } finally {
    child.kill('SIGTERM');
  }
}

async function checkSanitizeFilePath() {
  const base = fs.realpathSync(fs.mkdtempSync(join(os.tmpdir(), 'excalidraw-guard-')));
  const allowed = join(base, 'project');
  const outside = join(base, 'outside');
  fs.mkdirSync(allowed);
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, join(allowed, 'escape-dir'));
  fs.symlinkSync(join(outside, 'secret.txt'), join(allowed, 'dangling.txt'));
  fs.writeFileSync(join(outside, 'existing.txt'), 'x');
  fs.symlinkSync(join(outside, 'existing.txt'), join(allowed, 'existing-link.txt'));
  fs.mkdirSync(join(allowed, 'sub'));

  process.env.EXCALIDRAW_EXPORT_DIR = allowed;
  const { sanitizeFilePath } = await import('../dist/core/normalize.js');
  try {
    assert.equal(sanitizeFilePath(join(allowed, 'out.excalidraw')), join(allowed, 'out.excalidraw'));
    assert.equal(sanitizeFilePath(join(allowed, 'sub', 'new', 'out.png')), join(allowed, 'sub', 'new', 'out.png'));
    for (const escape of [
      join(allowed, '..', 'outside', 'x'),
      join(allowed, 'escape-dir', 'x.excalidraw'),
      join(allowed, 'escape-dir', 'deep', 'x.png'),
      join(allowed, 'dangling.txt'),
      join(allowed, 'existing-link.txt'),
    ]) {
      assert.throws(() => sanitizeFilePath(escape), /Path traversal blocked/, `escape not blocked: ${escape}`);
    }
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

await checkServer();
await checkSanitizeFilePath();
console.log('request guard checks passed');
