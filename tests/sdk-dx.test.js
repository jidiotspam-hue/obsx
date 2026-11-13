'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const obsx = require('..');
const core = require('../lib/core');
const cryptoLib = require('../lib/crypto');
const server = require('../server');

let testServer = null;
let baseUrl = '';
let testProject = null;

function httpJson(method, urlStr, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const bodyStr = body !== undefined ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        agent: false,
        headers: {
          ...(bodyStr ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
          Connection: 'close',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve({ status: res.statusCode, json: raw ? JSON.parse(raw) : null });
        });
      }
    );
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function solvePoWLocal(challenge, difficulty) {
  let nonce = 0;
  while (!cryptoLib.verifyPoW(challenge, String(nonce), difficulty)) {
    nonce++;
  }
  return String(nonce);
}

function computeTsig(rk, sessionId, nonce, signals) {
  const msg = `obsx.sig.v1\n${sessionId}\n${nonce || ''}\n${cryptoLib.canon(signals)}`;
  return nodeCrypto.createHmac('sha256', Buffer.from(rk, 'base64url')).update(msg).digest('base64url');
}

function buildNaturalSignals(elapsedMs = 1900) {
  const mousePoints = [
    { x: 100, y: 120, t: 10 },
    { x: 112, y: 125, t: 26 },
    { x: 145, y: 142, t: 41 },
    { x: 162, y: 148, t: 59 },
    { x: 205, y: 175, t: 74 },
    { x: 215, y: 179, t: 94 },
    { x: 265, y: 215, t: 108 },
    { x: 274, y: 220, t: 129 },
    { x: 320, y: 260, t: 143 },
    { x: 342, y: 271, t: 164 },
  ];
  return {
    sh: 'trc_v1_live',
    screen: '1440x900',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    webdriver: false,
    headless: false,
    rt_mask: 0,
    tampered: [],
    mousePoints,
    touchPoints: [],
    keyIntervals: [112, 148, 95, 167, 134, 189, 108],
    elapsedMs,
    probe: 0,
    rum: { jitter: 0.42 },
    audio: 'ac_ok_12',
    mode: 'enforce',
  };
}

async function createGenuineSession(browserUa) {
  const sessRes = await httpJson(
    'POST',
    `${baseUrl}/api/v1/session`,
    { site: testProject.publicKey, mode: 'enforce' },
    { 'User-Agent': browserUa, 'X-Forwarded-For': '198.51.100.12' }
  );
  assert.equal(sessRes.status, 200);
  assert.equal(sessRes.json.ok, true);

  const s = sessRes.json;
  const nonce = solvePoWLocal(s.challenge, s.difficulty);
  await new Promise((r) => setTimeout(r, 8));
  const signals = buildNaturalSignals(1900);
  const tsig = computeTsig(s.rk, s.session, nonce, signals);

  const sigRes = await httpJson(
    'POST',
    `${baseUrl}/api/v1/signal`,
    { token: s.token, nonce, tsig, signals },
    { 'User-Agent': browserUa, 'X-Forwarded-For': '198.51.100.12' }
  );
  assert.equal(sigRes.status, 200);
  assert.equal(sigRes.json.ok, true);

  return { token: s.token, session: s.session, nonce, rk: s.rk };
}

test.before(async () => {
  await new Promise((resolve) => {
    testServer = server.listen(0, '127.0.0.1', () => {
      const addr = testServer.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
  testProject = await core.createProject({ name: 'SDK DX E2E Project' }, 'u_sdk_dx_test');
  await core.updateProjectSettings(testProject.pid, { minDurationMs: 1 });
});

test.after(async () => {
  if (testServer) {
    if (typeof testServer.closeAllConnections === 'function') {
      testServer.closeAllConnections();
    }
    await new Promise((resolve) => testServer.close(resolve));
  }
});

test('package: require("obsx-security") exposes SDK API cleanly without auto-listening', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.main, 'lib/index.js');
  assert.equal(pkg.types, 'index.d.ts');
  assert.equal(pkg.exports['.'], './lib/index.js');
  assert.equal(pkg.exports['./server'], './server.js');

  assert.equal(typeof obsx.verifyToken, 'function');
  assert.equal(typeof obsx.verify, 'function');
  assert.equal(typeof obsx.middleware, 'function');
  assert.equal(typeof obsx.protect, 'function');
  assert.equal(typeof obsx.verifyActionSeal, 'function');
  assert.equal(typeof obsx.core.verify, 'function');
  assert.equal(obsx.listening, undefined, 'Library entry point must not auto-create an HTTP server');
});

test('dx: server-to-server verifyToken passes clean Chrome sessions without UA false positives', async () => {
  const chromeUa =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
  const session = await createGenuineSession(chromeUa);

  const verdict = await obsx.verifyToken(session.token, {
    secretKey: testProject.secretKey,
    nonce: session.nonce,
    endpoint: `${baseUrl}/api/v1`,
  });

  assert.equal(verdict.ok, true);
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.verdict, 'accept');
  assert.equal(
    verdict.reasons.some((r) => r.code === 'tampered_builtins'),
    false,
    'Backend-to-backend verification must not penalize backend User-Agent vs browser session'
  );
});

test('dx: explicit clientUa forwarding enforces UA binding and rejects relayed sessions', async () => {
  const chromeUa =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
  const matching = await createGenuineSession(chromeUa);
  const okVerdict = await obsx.verifyToken(
    { token: matching.token, nonce: matching.nonce },
    {
      secretKey: testProject.secretKey,
      endpoint: `${baseUrl}/api/v1`,
      clientUa: chromeUa,
    }
  );
  assert.equal(okVerdict.allowed, true);
  assert.equal(okVerdict.verdict, 'accept');

  const relayed = await createGenuineSession(chromeUa);
  const mismatchVerdict = await obsx.verifyToken(
    { token: relayed.token, nonce: relayed.nonce },
    {
      secretKey: testProject.secretKey,
      endpoint: `${baseUrl}/api/v1`,
      clientUa: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
    }
  );
  assert.ok(mismatchVerdict.reasons.some((r) => r.code === 'tampered_builtins'));
});

test('dx: verifyToken strips sensitive form fields (passwords/emails) and supports sealed payloads + middleware', async () => {
  // 1. Capture outbound body on mock verify server to ensure unsealed form fields never leak
  let capturedBody = null;
  const captureServer = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      capturedBody = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, allowed: true, verdict: 'accept', risk: 0, mode: 'enforce', reasons: [] }));
    });
  });
  await new Promise((resolve) => captureServer.listen(0, '127.0.0.1', resolve));

  try {
    const captureUrl = `http://127.0.0.1:${captureServer.address().port}/api/v1`;
    const formVerdict = await obsx.verifyToken(
      {
        'obsx-token': 'tok_demo_form',
        'obsx-nonce': '42',
        email: 'user@example.com',
        password: 'super-secret-password-do-not-exfiltrate',
      },
      { secretKey: 'sk_test_capture', endpoint: captureUrl }
    );
    assert.equal(formVerdict.allowed, true);
    assert.deepEqual(capturedBody, { token: 'tok_demo_form', nonce: '42' });
  } finally {
    captureServer.closeAllConnections?.();
    await new Promise((resolve) => captureServer.close(resolve));
  }

  // 2. Sealed action payload verification end-to-end
  const chromeUa = 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36';
  const s = await createGenuineSession(chromeUa);
  const ts = Date.now();
  const payload = { amount: 250, currency: 'USD', recipient: 'acct_9' };
  const sig = cryptoLib.signActionSeal(s.rk, s.session, ts, s.nonce, payload);
  const sealedBody = {
    ...payload,
    obsx: { token: s.token, nonce: s.nonce, mode: 'enforce', ts, sig },
  };
  const sealedVerdict = await obsx.verifyToken(sealedBody, {
    secretKey: testProject.secretKey,
    endpoint: `${baseUrl}/api/v1`,
  });
  assert.equal(sealedVerdict.allowed, true);
  assert.equal(sealedVerdict.sealed, 'ok');

  // 3. Express-style middleware() passes valid request and blocks empty requests with 403
  const mw = obsx.middleware({ secretKey: testProject.secretKey, endpoint: `${baseUrl}/api/v1` });
  const mwSession = await createGenuineSession(chromeUa);
  let nextCalled = false;
  const reqOk = {
    method: 'POST',
    url: '/api/login',
    headers: { 'user-agent': chromeUa },
    ip: '198.51.100.12',
    body: { 'obsx-token': mwSession.token, 'obsx-nonce': mwSession.nonce, username: 'alice' },
  };
  const resOk = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(data) { this.jsonBody = data; return this; },
  };
  await mw(reqOk, resOk, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
  assert.equal(reqOk.obsx.allowed, true);

  let badNextCalled = false;
  const reqBad = { method: 'POST', url: '/api/login', headers: {}, body: { username: 'bot' } };
  const resBad = {
    statusCode: 200,
    headersSent: false,
    status(code) { this.statusCode = code; return this; },
    json(data) { this.jsonBody = data; return this; },
  };
  await mw(reqBad, resBad, () => { badNextCalled = true; });
  assert.equal(badNextCalled, false);
  assert.equal(resBad.statusCode, 403);
  assert.equal(resBad.jsonBody.ok, false);
});

test('dx: verifyToken fails closed on missing credentials, missing token, bad secret, and unreachable endpoint', async () => {
  const noSecret = await obsx.verifyToken('tok_123', { endpoint: `${baseUrl}/api/v1` });
  assert.equal(noSecret.ok, false);
  assert.equal(noSecret.allowed, false);
  assert.equal(noSecret.verdict, 'reject');

  const noToken = await obsx.verifyToken({}, { secretKey: testProject.secretKey });
  assert.equal(noToken.allowed, false);
  assert.equal(noToken.verdict, 'reject');

  const badProto = await obsx.verifyToken('tok_123', { secretKey: testProject.secretKey, endpoint: 'file:///etc/passwd' });
  assert.equal(badProto.allowed, false);
  assert.equal(badProto.verdict, 'reject');

  const badKey = await obsx.verifyToken('tok_123', {
    secretKey: 'sk_invalid_secret_key',
    endpoint: `${baseUrl}/api/v1`,
  });
  assert.equal(badKey.allowed, false);
  assert.equal(badKey.verdict, 'reject');

  const badLocalKey = await obsx.verifyToken('tok_123', { local: true, secretKey: 'sk_wrong_local_key' });
  assert.equal(badLocalKey.allowed, false);
  assert.equal(badLocalKey.verdict, 'reject');
});

test('dx: compiled obsx.min.js auto-resolves cross-origin script endpoints and protects declarative forms', async () => {
  const bundleCode = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'), 'utf8');
  const scriptEl = {
    src: `${baseUrl}/sdk/v2.3.0/obsx.min.js`,
    getAttribute(name) {
      if (name === 'data-site') return testProject.publicKey;
      if (name === 'data-obsx-auto') return 'false';
      return null;
    },
  };

  const listeners = {};
  const tokenInput = { type: 'hidden', name: 'obsx-token', value: '', dataset: {} };
  const nonceInput = { type: 'hidden', name: 'obsx-nonce', value: '', dataset: {} };
  const appendedInputs = [tokenInput, nonceInput];
  let nativeSubmitCount = 0;

  const mockForm = {
    dataset: {},
    getAttribute() { return null; },
    querySelector(sel) {
      if (sel === 'input[name="obsx-token"]') return appendedInputs.find((i) => i.name === 'obsx-token') || null;
      if (sel === 'input[name="obsx-nonce"]') return appendedInputs.find((i) => i.name === 'obsx-nonce') || null;
      return null;
    },
    appendChild(el) { appendedInputs.push(el); },
    addEventListener(ev, fn) { listeners[ev] = fn; },
    dispatchEvent() { return true; },
    requestSubmit() { nativeSubmitCount++; },
    submit() { nativeSubmitCount++; },
  };

  const mockDocument = {
    currentScript: scriptEl,
    readyState: 'complete',
    referrer: '',
    body: { appendChild() {} },
    querySelector(sel) {
      if (sel.includes('data-obsx-site') || sel.includes('data-site') || sel.includes('obsx.min.js')) return scriptEl;
      return null;
    },
    querySelectorAll() { return []; },
    createElement() { return { type: '', name: '', value: '', dataset: {} }; },
    addEventListener() {},
  };

  const sandbox = {
    window: null,
    document: mockDocument,
    navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36' },
    location: { origin: 'https://third-party-app.example.com', href: 'https://third-party-app.example.com/signup', search: '' },
    screen: { width: 1440, height: 900 },
    performance: { now: () => Date.now() },
    Date,
    Object,
    Function,
    TextEncoder,
    Uint8Array,
    URL,
    CustomEvent: function CustomEvent(name, init) { return { type: name, detail: init && init.detail }; },
    crypto: nodeCrypto.webcrypto,
    fetch: async (url, init = {}) => {
      const body = init.body ? JSON.parse(init.body) : undefined;
      const res = await httpJson(init.method || 'GET', url, body, init.headers || {});
      return { ok: res.status >= 200 && res.status < 300, status: res.status, json: async () => res.json };
    },
    setTimeout,
    clearTimeout,
    addEventListener() {},
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;

  vm.runInNewContext(bundleCode, sandbox);
  const sdk = sandbox.OBSX;
  assert.ok(sdk, 'OBSX global must initialize');

  try {
    // Assert cross-origin init automatically pointed at ${baseUrl}/api/v1 without explicit endpoint!
    const active = await sdk.init();
    assert.equal(active.endpoint, `${baseUrl}/api/v1`);
    assert.equal(active.siteKey, testProject.publicKey);
    assert.ok(active.token);

    sdk.protectForm(mockForm);
    let prevented = false;
    await listeners.submit({
      defaultPrevented: false,
      preventDefault() { prevented = true; },
    });

    assert.equal(prevented, true);
    assert.ok(tokenInput.value.length > 10, 'protectForm must inject attested obsx-token before submit');
    assert.ok(nonceInput.value.length > 0, 'protectForm must inject PoW obsx-nonce before submit');
    assert.equal(nativeSubmitCount, 1);
  } finally {
    sdk.reset();
  }
});

test('dx: install.md SRI hashes match built obsx.min.js and LICENSE covers lib/index.js', () => {
  const bundle = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'));
  const sha384 = 'sha384-' + nodeCrypto.createHash('sha384').update(bundle).digest('base64');
  const sha256 = 'sha256-' + nodeCrypto.createHash('sha256').update(bundle).digest('base64');

  const installMd = fs.readFileSync(path.join(ROOT, 'public/install.md'), 'utf8');
  assert.ok(installMd.includes(sha384), `public/install.md must stay synced with ${sha384}`);
  assert.ok(installMd.includes(sha256), `public/install.md must stay synced with ${sha256}`);
  assert.ok(!installMd.includes('@obsx/core'), 'public/install.md must reference obsx-security, not phantom @obsx/core');

  const licenseText = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
  assert.ok(licenseText.includes('lib/index.js'), 'LICENSE Zone 1 must cover lib/index.js');

  const leftoverSnapshots = fs.readdirSync(ROOT).filter((f) => f.startsWith('.test-snapshot-'));
  assert.deepEqual(leftoverSnapshots, [], 'Repo root must stay free of temporary test snapshot files');
});
