'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const { execFileSync } = require('child_process');
const stream = require('stream');
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
  assert.deepEqual(pkg.exports['.'], {
    types: './index.d.ts',
    default: './lib/index.js',
  });
  assert.equal(pkg.exports['./server'], './server.js');
  assert.equal(pkg.exports['./lib/*'], './lib/*');

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

  const docListeners = {};
  const winListeners = {};
  const overlayNodes = [];
  const mockDocument = {
    currentScript: scriptEl,
    readyState: 'complete',
    referrer: '',
    body: {
      appendChild(el) { overlayNodes.push(el); },
    },
    getElementById(id) {
      return overlayNodes.find((n) => n.id === id) || null;
    },
    querySelector(sel) {
      if (sel.includes('data-obsx-site') || sel.includes('data-site') || sel.includes('obsx.min.js')) return scriptEl;
      return null;
    },
    querySelectorAll() { return []; },
    createElement() { return { type: '', name: '', value: '', dataset: {}, style: {} }; },
    addEventListener(ev, fn) { docListeners[ev] = fn; },
  };

  const sandbox = {
    window: null,
    document: mockDocument,
    navigator: { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' },
    location: { origin: 'https://third-party-app.example.com', href: 'https://third-party-app.example.com/signup', search: '' },
    screen: { width: 1440, height: 900 },
    TextEncoder,
    Uint8Array,
    URL,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    CustomEvent: function CustomEvent(name, init) { return { type: name, detail: init && init.detail }; },
    crypto: nodeCrypto.webcrypto,
    fetch: async (url, init = {}) => {
      const body = init.body ? JSON.parse(init.body) : undefined;
      const res = await httpJson(init.method || 'GET', url, body, {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
        ...(init.headers || {}),
      });
      return { ok: res.status >= 200 && res.status < 300, status: res.status, json: async () => res.json };
    },
    setTimeout,
    clearTimeout,
    addEventListener(ev, fn) { winListeners[ev] = fn; },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;

  vm.createContext(sandbox);
  sandbox.performance = { now: vm.runInContext('Date.now', sandbox) };
  vm.runInContext(bundleCode, sandbox);
  const sdk = sandbox.OBSX;
  assert.ok(sdk, 'OBSX global must initialize');
  assert.equal(sdk.version, '2.3.1');

  try {
    // Assert cross-origin init automatically pointed at ${baseUrl}/api/v1 without explicit endpoint!
    const active = await sdk.init();
    assert.equal(active.endpoint, `${baseUrl}/api/v1`);
    assert.equal(active.siteKey, testProject.publicKey);
    assert.ok(active.token);

    // Feed natural human mouse cadence + varied frame deltas so tsig + biometrics verify cleanly end-to-end
    const samplePts = buildNaturalSignals().mousePoints;
    const delaysMs = [12, 23, 15, 29, 14, 24, 18, 27, 13, 21];
    for (let i = 0; i < samplePts.length; i++) {
      await new Promise((r) => setTimeout(r, delaysMs[i % delaysMs.length]));
      if (typeof winListeners.mousemove === 'function') {
        winListeners.mousemove({ clientX: samplePts[i].x, clientY: samplePts[i].y });
      }
    }

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

    // End-to-end verification of the exact form fields produced by obsx.min.js against server /api/v1/verify
    const formVerify = await obsx.verifyToken(
      { 'obsx-token': tokenInput.value, 'obsx-nonce': nonceInput.value },
      {
        secretKey: testProject.secretKey,
        endpoint: `${baseUrl}/api/v1`,
        clientUa: sandbox.navigator.userAgent,
      }
    );
    assert.equal(formVerify.allowed, true, `Form verification failed: ${JSON.stringify(formVerify.reasons)}`);
    assert.equal(formVerify.verdict, 'accept');
  } finally {
    sdk.reset();
  }
});

test('dx: security hardening blocks JSON req-spoofing, flat seal tampering, PII over-forwarding, and isolates OBSX_SECRET', async () => {
  const chromeUa = 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36';

  // 1. Type confusion attack: client sends JSON req.body with fake { method, headers, body }
  const decoy = await createGenuineSession(chromeUa);
  const attackerBody = {
    method: 'POST',
    url: '/api/transfer',
    headers: { 'user-agent': chromeUa },
    ip: '1.2.3.4',
    amount: 999999,
    body: {
      token: decoy.token,
      nonce: decoy.nonce,
    },
  };
  const decoyResult = await obsx.verifyToken(attackerBody, {
    secretKey: testProject.secretKey,
    endpoint: `${baseUrl}/api/v1`,
  });
  assert.equal(decoyResult.allowed, false, 'Parsed JSON req.body must never duck-type as HTTP req to unwrap req.body.body');

  // Real Node stream.Readable request object IS unwrapped automatically
  const realStreamReq = new stream.Readable({ read() {} });
  const realSess = await createGenuineSession(chromeUa);
  realStreamReq.headers = { 'user-agent': chromeUa };
  realStreamReq.method = 'POST';
  realStreamReq.url = '/api/transfer';
  realStreamReq.body = { token: realSess.token, nonce: realSess.nonce };
  const streamResult = await obsx.verifyToken(realStreamReq, {
    secretKey: testProject.secretKey,
    endpoint: `${baseUrl}/api/v1`,
  });
  assert.equal(streamResult.allowed, true, 'Real stream.Readable request objects must unwrap cleanly');

  // 2. Flat HMAC action seals ({ sig, ts }) work end-to-end and detect payload tampering
  const flatSess = await createGenuineSession(chromeUa);
  const flatTs = Date.now();
  const flatPayload = { action: 'withdraw', amount: 50 };
  const flatSig = cryptoLib.signActionSeal(flatSess.rk, flatSess.session, flatTs, flatSess.nonce, flatPayload);
  const flatOk = await obsx.verifyToken(
    { ...flatPayload, token: flatSess.token, nonce: flatSess.nonce, ts: flatTs, sig: flatSig },
    { secretKey: testProject.secretKey, endpoint: `${baseUrl}/api/v1` }
  );
  assert.equal(flatOk.allowed, true);
  assert.equal(flatOk.sealed, 'ok');

  const tamperedSess = await createGenuineSession(chromeUa);
  const tamperedTs = Date.now();
  const tamperedSig = cryptoLib.signActionSeal(tamperedSess.rk, tamperedSess.session, tamperedTs, tamperedSess.nonce, flatPayload);
  const tamperedRes = await obsx.verifyToken(
    { action: 'withdraw', amount: 50000, token: tamperedSess.token, nonce: tamperedSess.nonce, ts: tamperedTs, sig: tamperedSig },
    { secretKey: testProject.secretKey, endpoint: `${baseUrl}/api/v1` }
  );
  assert.equal(tamperedRes.allowed, false);
  assert.equal(tamperedRes.sealed, 'invalid');

  // 3. Truthy primitive `obsx` or non-sealed `obsx` container still strips PII locally + OBSX_SECRET is NEVER sent Bearer
  let capturedBodies = [];
  const capSrv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      capturedBodies.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, allowed: true, verdict: 'accept', risk: 0, mode: 'enforce', reasons: [] }));
    });
  });
  await new Promise((resolve) => capSrv.listen(0, '127.0.0.1', resolve));

  const prevObsxSecret = process.env.OBSX_SECRET;
  const prevObsxSecretKey = process.env.OBSX_SECRET_KEY;
  try {
    const capUrl = `http://127.0.0.1:${capSrv.address().port}/api/v1`;
    await obsx.verifyToken(
      { obsx: true, token: 'tok_safe', nonce: '7', password: 'secret-pw', email: 'pii@example.com' },
      { secretKey: 'sk_cap_123', endpoint: capUrl }
    );
    await obsx.verifyToken(
      { obsx: { token: 'tok_nested_unsealed', nonce: '8' }, password: 'secret-pw', ssn: '000' },
      { secretKey: 'sk_cap_123', endpoint: capUrl }
    );
    assert.deepEqual(capturedBodies[0], { token: 'tok_safe', nonce: '7' });
    assert.deepEqual(capturedBodies[1], { token: 'tok_nested_unsealed', nonce: '8' });

    delete process.env.OBSX_SECRET_KEY;
    process.env.OBSX_SECRET = 'master_hmac_secret_never_send_bearer';
    const beforeReqs = capturedBodies.length;
    const missingKeyRes = await obsx.verifyToken('tok_safe', { endpoint: capUrl });
    assert.equal(missingKeyRes.ok, false);
    assert.equal(missingKeyRes.allowed, false);
    assert.equal(capturedBodies.length, beforeReqs, 'OBSX_SECRET must never be sent in Authorization header');
  } finally {
    if (prevObsxSecret === undefined) delete process.env.OBSX_SECRET;
    else process.env.OBSX_SECRET = prevObsxSecret;
    if (prevObsxSecretKey === undefined) delete process.env.OBSX_SECRET_KEY;
    else process.env.OBSX_SECRET_KEY = prevObsxSecretKey;
    capSrv.closeAllConnections?.();
    await new Promise((resolve) => capSrv.close(resolve));
  }
});

test('dx: middleware review-blocking, raw HTTP responses, next() error propagation, local mode, and network resilience', async () => {
  // 1. Verdict 'review': allowed by default, rejected under blockReview: true
  const reviewSrv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, allowed: true, verdict: 'review', risk: 45, mode: 'enforce', reasons: [{ code: 'suspicious', weight: 45 }] }));
    });
  });
  await new Promise((resolve) => reviewSrv.listen(0, '127.0.0.1', resolve));

  try {
    const reviewUrl = `http://127.0.0.1:${reviewSrv.address().port}/api/v1`;
    const mwAllow = obsx.middleware({ secretKey: 'sk_r', endpoint: reviewUrl });
    const mwBlock = obsx.middleware({ secretKey: 'sk_r', endpoint: reviewUrl, blockReview: true, statusCode: 429 });

    let allowedNext = false;
    const rawRes1 = { headersSent: false, writeHead() {}, end() {} };
    await mwAllow({ method: 'POST', headers: {}, body: { token: 't' } }, rawRes1, () => { allowedNext = true; });
    assert.equal(allowedNext, true);

    let blockedNext = false;
    let writtenStatus = 0;
    let writtenBody = '';
    const rawRes2 = {
      headersSent: false,
      writeHead(code) { writtenStatus = code; this.headersSent = true; },
      end(chunk) { writtenBody = chunk; },
    };
    await mwBlock({ method: 'POST', headers: {}, body: { token: 't' } }, rawRes2, () => { blockedNext = true; });
    assert.equal(blockedNext, false);
    assert.equal(writtenStatus, 429);
    assert.equal(JSON.parse(writtenBody).verdict, 'review');

    // Downstream errors thrown from next() must propagate rather than turning into 403 obsx_verification_failed
    await assert.rejects(
      mwAllow({ method: 'POST', headers: {}, body: { token: 't' } }, rawRes1, () => {
        throw new Error('downstream_db_boom');
      }),
      /downstream_db_boom/
    );
  } finally {
    reviewSrv.closeAllConnections?.();
    await new Promise((resolve) => reviewSrv.close(resolve));
  }

  // 2. Network resilience: ECONNREFUSED, truncated/invalid JSON, timeout
  const unreachable = await obsx.verifyToken('tok_123', {
    secretKey: 'sk_t',
    endpoint: 'http://127.0.0.1:9/api/v1',
    timeoutMs: 300,
  });
  assert.equal(unreachable.ok, false);
  assert.equal(unreachable.allowed, false);

  const flakySrv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.headers['x-case'] === 'timeout') return; // intentionally hang
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{bad json');
    });
  });
  await new Promise((resolve) => flakySrv.listen(0, '127.0.0.1', resolve));
  try {
    const flakyUrl = `http://127.0.0.1:${flakySrv.address().port}/api/v1`;
    const badJsonRes = await obsx.verifyToken('tok_1', { secretKey: 'sk_1', endpoint: flakyUrl });
    assert.equal(badJsonRes.allowed, false);
    const timeoutRes = await obsx.verifyToken('tok_1', { secretKey: 'sk_1', endpoint: flakyUrl, timeoutMs: 260 });
    assert.equal(timeoutRes.allowed, false);
  } finally {
    flakySrv.closeAllConnections?.();
    await new Promise((resolve) => flakySrv.close(resolve));
  }

  // 3. Local verification success paths (by secretKey and by projectId)
  const chromeUa = 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36';
  const sLocalKey = await createGenuineSession(chromeUa);
  const localByKey = await obsx.verifyToken(
    { token: sLocalKey.token, nonce: sLocalKey.nonce },
    { local: true, secretKey: testProject.secretKey, clientUa: chromeUa }
  );
  assert.equal(localByKey.allowed, true);

  const sLocalPid = await createGenuineSession(chromeUa);
  const localByPid = await obsx.verifyToken(
    { token: sLocalPid.token, nonce: sLocalPid.nonce },
    { local: true, projectId: testProject.pid, clientUa: chromeUa }
  );
  assert.equal(localByPid.allowed, true);
});

test('dx: browser SDK DOM XSS safety, concurrent init/getAttestation queuing, and Node ESM named imports', async () => {
  const bundleCode = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'), 'utf8');
  let sessionFetchCount = 0;

  // 1. Validate XSS-hardened resolveEndpoint & showDramBlockScreen + concurrent getAttestation queuing
  const overlayNodes = [];
  const xssScript = {
    src: `${baseUrl}/sdk/v2.3.1/obsx.min.js`,
    getAttribute(name) {
      if (name === 'data-obsx-site') return testProject.publicKey;
      if (name === 'data-obsx-endpoint') return 'https://obsx.example/" onload="alert(1)/api/v1';
      if (name === 'data-obsx-auto') return 'false';
      return null;
    },
  };
  const docXss = {
    currentScript: xssScript,
    readyState: 'complete',
    referrer: '',
    body: { appendChild(el) { overlayNodes.push(el); } },
    getElementById(id) { return overlayNodes.find((n) => n.id === id) || null; },
    querySelector(sel) { return sel.includes('data-obsx-site') ? xssScript : null; },
    querySelectorAll() { return []; },
    createElement() { return { style: {}, dataset: {}, innerHTML: '' }; },
    addEventListener() {},
  };
  const sbXss = {
    window: null,
    document: docXss,
    navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
    location: { origin: 'https://app.example.com', href: 'https://app.example.com/', search: '' },
    screen: { width: 1440, height: 900 },
    performance: { now: () => 100 },
    Date,
    Object,
    Function,
    TextEncoder,
    Uint8Array,
    URL,
    crypto: nodeCrypto.webcrypto,
    fetch: async () => { throw new Error('offline'); },
    setTimeout,
    clearTimeout,
    addEventListener() {},
  };
  sbXss.window = sbXss;
  sbXss.globalThis = sbXss;
  vm.runInNewContext(bundleCode, sbXss);
  sbXss.OBSX.showDramBlockScreen('https://obsx.example/" onload="alert(1)');
  assert.equal(overlayNodes.length, 1);
  assert.ok(!overlayNodes[0].innerHTML.includes('onload="alert(1)'), 'Origin interpolation must strip path/quote breakout payloads');
  await assert.rejects(() => sbXss.OBSX.init({ site: 'pk_x', endpoint: 'javascript:alert(1)' }), /Unsupported endpoint protocol/);

  // 2. Concurrent init() deduplicates and concurrent getAttestation() calls receive distinct tokens
  const scriptOk = {
    src: `${baseUrl}/sdk/v2.3.1/obsx.min.js`,
    getAttribute(name) {
      if (name === 'data-obsx-site') return testProject.publicKey;
      if (name === 'data-obsx-auto') return 'false';
      return null;
    },
  };
  const docOk = {
    currentScript: scriptOk,
    readyState: 'complete',
    referrer: '',
    body: { appendChild() {} },
    getElementById() { return null; },
    querySelector(sel) { return sel.includes('data-obsx-site') ? scriptOk : null; },
    querySelectorAll() { return []; },
    createElement() { return { style: {}, dataset: {} }; },
    addEventListener() {},
  };
  const sbConc = {
    window: null,
    document: docOk,
    navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
    location: { origin: 'https://app.example.com', href: 'https://app.example.com/', search: '' },
    screen: { width: 1440, height: 900 },
    performance: { now: () => 250 },
    Date,
    Object,
    Function,
    TextEncoder,
    Uint8Array,
    URL,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    crypto: nodeCrypto.webcrypto,
    fetch: async (url, init = {}) => {
      if (String(url).endsWith('/session')) sessionFetchCount++;
      const body = init.body ? JSON.parse(init.body) : undefined;
      const res = await httpJson(init.method || 'GET', url, body, { 'User-Agent': 'Mozilla/5.0 Chrome/130.0.0.0', ...(init.headers || {}) });
      return { ok: res.status >= 200 && res.status < 300, status: res.status, json: async () => res.json };
    },
    setTimeout,
    clearTimeout,
    addEventListener() {},
  };
  sbConc.window = sbConc;
  sbConc.globalThis = sbConc;
  vm.runInNewContext(bundleCode, sbConc);

  try {
    const [s1, s2] = await Promise.all([sbConc.OBSX.init(), sbConc.OBSX.init()]);
    assert.equal(s1.token, s2.token, 'Concurrent init() calls must deduplicate');
    assert.equal(sessionFetchCount, 1);

    const [a1, a2] = await Promise.all([sbConc.OBSX.getAttestation(), sbConc.OBSX.getAttestation()]);
    assert.ok(a1.token && a2.token);
    assert.notEqual(a1.token, a2.token, 'Queued getAttestation() calls must each receive distinct single-use tokens');
  } finally {
    sbConc.OBSX.reset();
  }

  // 3. Native Node ESM named import verification via package exports
  const esmOut = execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import { verifyToken, verify, verifyRequest, middleware, protect, verifyActionSeal } from 'obsx-security'; import { verifyActionSeal as v2, randomInt } from 'obsx-security/crypto'; import { MemoryStore, getKv } from 'obsx-security/kv'; console.log([typeof verifyToken, typeof verify, typeof verifyRequest, typeof middleware, typeof protect, typeof verifyActionSeal, typeof v2, typeof randomInt, typeof MemoryStore, typeof getKv].join(','));",
    ],
    { cwd: ROOT, encoding: 'utf8' }
  ).trim();
  assert.equal(esmOut, 'function,function,function,function,function,function,function,function,function,function');
});

test('dx: reCAPTCHA/Turnstile compat tokens, Web Request/Headers, and grecaptcha shim work end-to-end', async () => {
  const chromeUa = 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36';
  const endpoint = `${baseUrl}/api/v1`;
  // 1. g-recaptcha-response & cf-turnstile-response packed token::nonce
  const humanA = await createGenuineSession(chromeUa);
  const recaptchaVerdict = await obsx.verifyToken(
    { 'g-recaptcha-response': `${humanA.token}::${humanA.nonce}`, email: 'secret@example.com' },
    { secretKey: testProject.secretKey, endpoint, clientUa: chromeUa }
  );
  assert.equal(recaptchaVerdict.allowed, true);
  assert.equal(recaptchaVerdict.verdict, 'accept');

  const humanB = await createGenuineSession(chromeUa);
  const turnstileVerdict = await obsx.verifyToken(
    `${humanB.token}::${humanB.nonce}`,
    { secretKey: testProject.secretKey, endpoint, clientUa: chromeUa }
  );
  assert.equal(turnstileVerdict.allowed, true);

  // 2. Web Standard Request + Headers support (Next.js App Router / Edge)
  const humanC = await createGenuineSession(chromeUa);
  const webReq = new Request('https://app.example.com/api/checkout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': chromeUa,
    },
    body: JSON.stringify({ 'cf-turnstile-response': `${humanC.token}::${humanC.nonce}` }),
  });
  const webVerdict = await obsx.verifyRequest(webReq, {
    secretKey: testProject.secretKey,
    endpoint,
  });
  assert.equal(webVerdict.allowed, true);
  assert.equal(webVerdict.verdict, 'accept');

  // 3. Browser SDK grecaptcha compatibility adapter
  const bundleCode = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'), 'utf8');
  const sb = {
    console,
    Date,
    Math,
    Object,
    Function,
    Promise,
    TextEncoder,
    Uint8Array,
    URL,
    crypto: globalThis.crypto,
    fetch: globalThis.fetch,
    setTimeout,
    clearTimeout,
    addEventListener() {},
    document: {
      readyState: 'complete',
      currentScript: { src: `${baseUrl}/obsx.min.js`, getAttribute: (k) => (k === 'data-obsx-site' ? testProject.publicKey : null) },
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener() {},
      documentElement: null,
    },
    location: { origin: baseUrl },
  };
  sb.window = sb;
  sb.globalThis = sb;
  vm.runInNewContext(bundleCode, sb);

  try {
    const compat = sb.OBSX.enableRecaptchaCompat();
    assert.equal(typeof sb.grecaptcha.execute, 'function');
    assert.equal(typeof compat.ready, 'function');
    await sb.OBSX.init({ site: testProject.publicKey, endpoint });
    const packed = await sb.grecaptcha.execute(testProject.publicKey, { action: 'submit' });
    assert.ok(packed.includes('::'), 'grecaptcha.execute() must return token::nonce compat string');
    assert.equal(sb.grecaptcha.getResponse(), packed);
  } finally {
    sb.OBSX.reset();
  }
});

test('dx: install.md SRI hashes match built obsx.min.js and LICENSE covers lib/index.js', () => {
  const bundle = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'));
  const sha384 = 'sha384-' + nodeCrypto.createHash('sha384').update(bundle).digest('base64');
  const sha256 = 'sha256-' + nodeCrypto.createHash('sha256').update(bundle).digest('base64');

  const installMd = fs.readFileSync(path.join(ROOT, 'public/install.md'), 'utf8');
  assert.ok(installMd.includes('v2.3.1'), 'public/install.md must reference v2.3.1 SDK URL');
  assert.ok(installMd.includes(sha384), `public/install.md must stay synced with ${sha384}`);
  assert.ok(installMd.includes(sha256), `public/install.md must stay synced with ${sha256}`);
  assert.ok(!installMd.includes('@obsx/core'), 'public/install.md must reference obsx-security, not phantom @obsx/core');

  const licenseText = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
  assert.ok(licenseText.includes('lib/index.js'), 'LICENSE Zone 1 must cover lib/index.js');

  const leftoverSnapshots = fs.readdirSync(ROOT).filter((f) => f.startsWith('.test-snapshot-'));
  assert.deepEqual(leftoverSnapshots, [], 'Repo root must stay free of temporary test snapshot files');
});
