'use strict';

process.env.TRUST_PROXY = 'true';
process.env.OBSX_TEST_MODE = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const mailer = require('../lib/mailer');
const botshield = require('../lib/botshield');

botshield.stopMonitors();
const initialShieldEnabled = botshield.config.enabled;

function restoreBotShield() {
  botshield.reset();
  botshield.configure({ enabled: initialShieldEnabled, mode: 'auto' });
  botshield.stopMonitors();
}

let port = 0;
let baseUrl = '';
let testServer = null;

test.before(async () => {
  await new Promise((resolve) => {
    testServer = server.listen(0, '127.0.0.1', () => {
      port = testServer.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  restoreBotShield();
  if (testServer) {
    if (typeof testServer.closeAllConnections === 'function') {
      testServer.closeAllConnections();
    }
    await new Promise((resolve) => testServer.close(resolve));
  }
});

function request(method, reqPath, options = {}) {
  return new Promise((resolve, reject) => {
    const headers = { ...(options.headers || {}), Connection: 'close' };
    let bodyData = null;

    if (options.body !== undefined) {
      bodyData = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
      headers['Content-Length'] = Buffer.byteLength(bodyData);
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers,
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: raw,
            json,
          });
        });
      }
    );

    req.on('error', reject);
    if (bodyData !== null) req.write(bodyData);
    req.end();
  });
}

function solvePow(challenge, difficulty) {
  for (let n = 0; n < 1000000; n++) {
    if (crypto.verifyPoW(challenge, String(n), difficulty)) return String(n);
  }
  throw new Error('Failed to solve PoW in test');
}

function solveBotShieldPow(challenge, bits) {
  for (let n = 0; n < 1000000; n++) {
    if (botshield.powOk(challenge, String(n), bits)) return String(n);
  }
  throw new Error('Failed to solve BotShield PoW');
}

function parseBotShieldChallenge(html) {
  const cid = /var cid = "([^"]+)"/.exec(html);
  const challenge = /challenge = "([^"]+)"/.exec(html);
  const bits = /bits = (\d+)/.exec(html);
  if (!cid || !challenge || !bits) throw new Error('BotShield challenge page malformed');
  return { cid: cid[1], challenge: challenge[1], bits: Number(bits[1]) };
}

function makeFakeRes() {
  const out = { status: 0, headers: {}, body: '' };
  return {
    out,
    writeHead(status, headers = {}) {
      out.status = status;
      Object.assign(out.headers, headers || {});
    },
    end(body = '') {
      out.body = body;
    },
  };
}

const NATURAL_CURVE = [
  { x: 10, y: 12, t: 0 },
  { x: 24, y: 29, t: 28 },
  { x: 52, y: 37, t: 62 },
  { x: 91, y: 74, t: 101 },
  { x: 138, y: 90, t: 145 },
  { x: 195, y: 126, t: 198 },
];

test('hardening: empty or short OBSX_SECRET is rejected on operator bot-protection routes', async () => {
  const prevSecret = process.env.OBSX_SECRET;
  botshield.reset();
  botshield.configure({
    enabled: true,
    mode: 'auto',
    engageRps: 10,
    baseDifficulty: 8,
    maxDifficulty: 12,
  });

  try {
    // Trigger an offender so unmasked vs masked IP check is meaningful
    const r = makeFakeRes();
    const u = new URL('/login', 'http://obsx.tech');
    botshield.evaluate(
      { method: 'GET', headers: { 'user-agent': 'python-requests/2.31', 'x-obsx-key': '' } },
      r,
      '198.51.100.77',
      u.pathname,
      10,
      u,
      { activeConnections: 1, inFlight: 1 }
    );
    assert.equal(r.out.status, 403);

    // Direct evaluate() check with empty or short OBSX_SECRET must NOT grant operator status
    process.env.OBSX_SECRET = '';
    const statsResEmpty = makeFakeRes();
    const statsUrl = new URL('/api/v1/bot-protection', 'http://obsx.tech');
    botshield.evaluate(
      { method: 'GET', headers: { 'user-agent': 'curl/8.0', 'x-obsx-key': '' } },
      statsResEmpty,
      '198.51.100.78',
      statsUrl.pathname,
      10,
      statsUrl,
      { activeConnections: 1, inFlight: 1 }
    );
    assert.equal(statsResEmpty.out.status, 200);
    const statsBodyEmpty = JSON.parse(statsResEmpty.out.body);
    assert.ok(statsBodyEmpty.topOffenders.length > 0, 'Expected at least one recorded offender');
    assert.equal(statsBodyEmpty.topOffenders[0].ip.includes('*'), true, 'Empty secret must keep offender IPs masked');

    process.env.OBSX_SECRET = 'short_key_123';
    const statsResShort = makeFakeRes();
    botshield.evaluate(
      { method: 'GET', headers: { 'user-agent': 'curl/8.0', 'x-obsx-key': 'short_key_123' } },
      statsResShort,
      '198.51.100.78',
      statsUrl.pathname,
      10,
      statsUrl,
      { activeConnections: 1, inFlight: 1 }
    );
    const statsBodyShort = JSON.parse(statsResShort.out.body);
    assert.ok(statsBodyShort.topOffenders.length > 0, 'Expected at least one recorded offender');
    assert.equal(statsBodyShort.topOffenders[0].ip.includes('*'), true, 'Short (<16) secret must keep offender IPs masked');

    // HTTP endpoint check when process.env.OBSX_SECRET is empty or too short
    for (const candidate of ['', 'short_secret']) {
      process.env.OBSX_SECRET = candidate;
      const modeRes = await request('POST', '/api/v1/bot-protection/mode', {
        headers: { 'x-obsx-key': candidate },
        body: { mode: 'off' },
      });
      assert.equal(modeRes.status, 401);
      assert.equal(modeRes.json.error, 'invalid_key');

      const getRes = await request('GET', '/api/v1/bot-protection', {
        headers: { 'x-obsx-key': candidate },
      });
      assert.equal(getRes.status, 200);
      assert.ok(getRes.json.topOffenders.length > 0, 'Expected offender entries on stats response');
      assert.equal(getRes.json.topOffenders[0].ip.includes('*'), true);
    }

    // Valid >= 16 char secret succeeds
    process.env.OBSX_SECRET = 'valid_operator_secret_key_123456';
    const okRes = await request('POST', '/api/v1/bot-protection/mode', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
      body: { mode: 'auto' },
    });
    assert.equal(okRes.status, 200);
    assert.equal(okRes.json.ok, true);
  } finally {
    if (prevSecret === undefined) delete process.env.OBSX_SECRET;
    else process.env.OBSX_SECRET = prevSecret;
    restoreBotShield();
  }
});

test('hardening: non-operator and unauthenticated callers are denied operator/system routes while allowlisted operators succeed', async () => {
  const prevSecret = process.env.OBSX_SECRET;
  const prevOps = process.env.OPERATOR_EMAILS;
  const prevAlertEmail = process.env.ALERT_EMAIL;
  const prevHttpSync = process.env.OBSX_HTTP_SYNC;
  const prevAutoRestart = process.env.OBSX_AUTO_RESTART;
  const prevAcceptLic = process.env.OBSX_ACCEPT_LICENSE;
  const prevEnforceLic = process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
  const prevLicStateFile = process.env.OBSX_LICENSE_STATE_FILE;

  const tmpLicDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-sec-lic-'));
  const licStatePath = path.join(tmpLicDir, 'license-state.json');

  process.env.OBSX_SECRET = 'valid_operator_secret_key_abcdef';
  process.env.OPERATOR_EMAILS = 'ops-admin@obsx.tech';
  process.env.ALERT_EMAIL = 'alert-recipient@example.com';
  delete process.env.OBSX_HTTP_SYNC;
  delete process.env.OBSX_AUTO_RESTART;
  delete process.env.OBSX_ACCEPT_LICENSE;
  delete process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
  process.env.OBSX_LICENSE_STATE_FILE = licStatePath;

  try {
    const regEmail = `regular_${crypto.randomId(6)}@example.com`;
    const regStart = await accounts.startEmailAuth(regEmail, '198.51.100.141');
    const regSession = await accounts.verifyEmailAuth(regEmail, regStart.devCode);
    const regCookie = `obsx_session=${regSession.sid}`;
    const regUser = await accounts.getSessionUser({ headers: { cookie: regCookie } });
    const regProj = await core.createProject({ name: 'Tenant Telemetry Scope' }, regUser.uid);

    // Neither official@obsx.tech nor ALERT_EMAIL is granted implicit operator access when omitted from OPERATOR_EMAILS
    const defaultStart = await accounts.startEmailAuth('official@obsx.tech', '198.51.100.143');
    const defaultSession = await accounts.verifyEmailAuth('official@obsx.tech', defaultStart.devCode);
    const defaultCookie = `obsx_session=${defaultSession.sid}`;

    const alertOnlyStart = await accounts.startEmailAuth('alert-recipient@example.com', '198.51.100.144');
    const alertOnlySession = await accounts.verifyEmailAuth('alert-recipient@example.com', alertOnlyStart.devCode);
    const alertOnlyCookie = `obsx_session=${alertOnlySession.sid}`;

    const opStart = await accounts.startEmailAuth('ops-admin@obsx.tech', '198.51.100.142');
    const opSession = await accounts.verifyEmailAuth('ops-admin@obsx.tech', opStart.devCode);
    const opCookie = `obsx_session=${opSession.sid}`;
    const opUser = await accounts.getSessionUser({ headers: { cookie: opCookie } });
    const opProj = await core.createProject({ name: 'Operator Telemetry Scope' }, opUser.uid);

    for (const [method, endpoint] of [
      ['GET', '/api/v1/alerts'],
      ['GET', '/api/v1/system/diff'],
      ['POST', '/api/v1/system/update'],
      ['POST', '/api/v1/system/adapt'],
      ['GET', '/api/v1/system/license'],
      ['POST', '/api/v1/system/license/accept'],
    ]) {
      const unauthed = await request(method, endpoint, {
        body: method === 'POST' ? {} : undefined,
      });
      assert.equal(unauthed.status, 401, `Expected 401 without session or key on ${method} ${endpoint}`);
      assert.equal(unauthed.json.error, 'unauthorized');

      for (const nonOpCookie of [regCookie, defaultCookie, alertOnlyCookie]) {
        const denied = await request(method, endpoint, {
          headers: { Cookie: nonOpCookie },
          body: method === 'POST' ? {} : undefined,
        });
        assert.equal(denied.status, 403, `Expected 403 for non-allowlisted user on ${method} ${endpoint}`);
        assert.equal(denied.json.error, 'operator_required');
      }
    }

    // Cross-origin or simple form-POST operator session mutations are rejected
    const evilOriginRes = await request('POST', '/api/v1/system/license/accept', {
      headers: { Cookie: opCookie, Origin: 'https://evil.example' },
      body: {},
    });
    assert.equal(evilOriginRes.status, 403);
    assert.equal(evilOriginRes.json.error, 'cross_origin_forbidden');

    const simplePostRes = await request('POST', '/api/v1/system/license/accept', {
      headers: { Cookie: opCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'foo=bar',
    });
    assert.equal(simplePostRes.status, 403);
    assert.equal(simplePostRes.json.error, 'cross_origin_forbidden');

    const opAlerts = await request('GET', '/api/v1/alerts', { headers: { Cookie: opCookie } });
    assert.equal(opAlerts.status, 200);
    assert.equal(opAlerts.json.ok, true);

    const keyAlerts = await request('GET', '/api/v1/alerts', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
    });
    assert.equal(keyAlerts.status, 200);
    assert.equal(keyAlerts.json.ok, true);

    const keyDiff = await request('GET', '/api/v1/system/diff', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
    });
    assert.equal(keyDiff.status, 200);
    if (fs.existsSync(path.join(__dirname, '..', '.git'))) {
      assert.equal(keyDiff.json.ok, true);
    } else {
      assert.equal(keyDiff.json.error, 'not_git_repo');
    }

    // Enforced acceptance before accept flips public /api/v1/system/version to safeMode: true
    process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE = 'true';
    const preAcceptVer = await request('GET', '/api/v1/system/version');
    assert.equal(preAcceptVer.status, 200);
    assert.equal(preAcceptVer.json.ok, false);
    assert.equal(preAcceptVer.json.safeMode, true);
    assert.equal(preAcceptVer.json.safeModeReason, 'license_acceptance_required');

    // Accept via key first (operator-key attribution), then via operator session (email attribution)
    const keyAcceptRes = await request('POST', '/api/v1/system/license/accept', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
      body: {},
    });
    assert.equal(keyAcceptRes.status, 200);
    assert.equal(keyAcceptRes.json.ok, true);
    assert.equal(keyAcceptRes.json.acceptedBy, 'operator-key');

    const acceptRes = await request('POST', '/api/v1/system/license/accept', {
      headers: { Cookie: opCookie },
      body: {},
    });
    assert.equal(acceptRes.status, 200);
    assert.equal(acceptRes.json.ok, true);
    assert.equal(acceptRes.json.safeMode, false);
    assert.equal(acceptRes.json.accepted, true);
    assert.equal(acceptRes.json.acceptedBy, 'ops-admin@obsx.tech');
    assert.equal(acceptRes.json.acceptedVia, 'state_file');

    const opLicRes = await request('GET', '/api/v1/system/license', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
    });
    assert.equal(opLicRes.status, 200);
    assert.equal(opLicRes.json.ok, true);
    assert.equal(opLicRes.json.accepted, true);

    // Public /api/v1/system/version must redact operator metadata and state-file internals
    const pubVer = await request('GET', '/api/v1/system/version');
    assert.equal(pubVer.status, 200);
    assert.equal(pubVer.json.ok, true);
    assert.equal(pubVer.json.safeMode, false);
    assert.ok(pubVer.json.licenseFingerprint && pubVer.json.licenseFingerprint.length === 16);
    for (const redactedKey of ['accepted', 'acceptedAt', 'acceptedBy', 'acceptedVia', 'licenseSha256', 'enforceAcceptance']) {
      assert.equal(redactedKey in pubVer.json, false, `Public version must omit ${redactedKey}`);
    }
    assert.equal(pubVer.json.autoUpdate.httpSyncEnabled, false);
    assert.equal(pubVer.json.autoUpdate.autoRestartEnabled, false);

    // Regular tenant telemetry must NEVER disclose operator advisory or acceptedBy email
    const regTele = await request('GET', `/api/v1/project/${regProj.pid}/telemetry`, {
      headers: { Cookie: regCookie },
    });
    assert.equal(regTele.status, 200);
    assert.equal(regTele.json.upstreamAdvisory, null);

    // Operator telemetry DOES receive upstreamAdvisory + licenseStatus
    const opTele = await request('GET', `/api/v1/project/${opProj.pid}/telemetry`, {
      headers: { Cookie: opCookie },
    });
    assert.equal(opTele.status, 200);
    assert.ok(opTele.json.upstreamAdvisory && opTele.json.upstreamAdvisory.licenseStatus);
    assert.equal(opTele.json.upstreamAdvisory.licenseStatus.acceptedBy, 'ops-admin@obsx.tech');
  } finally {
    fs.rmSync(tmpLicDir, { recursive: true, force: true });
    if (prevLicStateFile === undefined) delete process.env.OBSX_LICENSE_STATE_FILE;
    else process.env.OBSX_LICENSE_STATE_FILE = prevLicStateFile;
    if (prevHttpSync === undefined) delete process.env.OBSX_HTTP_SYNC;
    else process.env.OBSX_HTTP_SYNC = prevHttpSync;
    if (prevAutoRestart === undefined) delete process.env.OBSX_AUTO_RESTART;
    else process.env.OBSX_AUTO_RESTART = prevAutoRestart;
    if (prevAcceptLic === undefined) delete process.env.OBSX_ACCEPT_LICENSE;
    else process.env.OBSX_ACCEPT_LICENSE = prevAcceptLic;
    if (prevEnforceLic === undefined) delete process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
    else process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE = prevEnforceLic;
    if (prevSecret === undefined) delete process.env.OBSX_SECRET;
    else process.env.OBSX_SECRET = prevSecret;
    if (prevOps === undefined) delete process.env.OPERATOR_EMAILS;
    else process.env.OPERATOR_EMAILS = prevOps;
    if (prevAlertEmail === undefined) delete process.env.ALERT_EMAIL;
    else process.env.ALERT_EMAIL = prevAlertEmail;
  }
});

test('hardening: missing_signals applies even with gpuRenderer and enforces requireBiometrics', async () => {
  const proj = await core.createProject({ name: 'sig_hardening' }, 'u_sig_test');
  await core.updateProjectSettings(proj.pid, { minDurationMs: 0 });
  const freshProj = await core.loadProject(proj.pid);

  // 1. Bare sh only -> missing_signals
  const s1 = await core.startSession(freshProj, { ip: '198.51.100.151', action: 'test' });
  const n1 = solvePow(s1.challenge, s1.difficulty);
  await core.recordSignals({ token: s1.token, signals: { sh: 'trc_v1_live' } });
  const v1 = await core.verify(freshProj, { token: s1.token, nonce: n1 }, { ip: '198.51.100.151', ua: 'Mozilla/5.0' });
  assert.equal(v1.verdict, 'reject');
  assert.ok(v1.risk >= 65);
  assert.ok(v1.reasons.some((r) => r.code === 'missing_signals'));

  // 2. sh + gpuRenderer without interaction signals -> still missing_signals
  const s2 = await core.startSession(freshProj, { ip: '198.51.100.152', action: 'test' });
  const n2 = solvePow(s2.challenge, s2.difficulty);
  await core.recordSignals({
    token: s2.token,
    signals: { sh: 'trc_v1_live', gpuRenderer: 'standard_webgl' },
  });
  const v2 = await core.verify(freshProj, { token: s2.token, nonce: n2 }, { ip: '198.51.100.152', ua: 'Mozilla/5.0' });
  assert.equal(v2.verdict, 'reject');
  assert.ok(v2.risk >= 65);
  assert.ok(v2.reasons.some((r) => r.code === 'missing_signals'));

  // 3. requireBiometrics: true with < 4 mousePoints -> missing_signals
  const s3 = await core.startSession(freshProj, { ip: '198.51.100.153', action: 'test' });
  const n3 = solvePow(s3.challenge, s3.difficulty);
  await core.recordSignals({
    token: s3.token,
    signals: {
      sh: 'trc_v1_live',
      gpuRenderer: 'Apple M2',
      mousePoints: [{ x: 10, y: 10, t: 0 }, { x: 20, y: 20, t: 50 }],
      keyIntervals: [110, 95],
      elapsedMs: 900,
    },
  });
  const v3 = await core.verify(
    freshProj,
    { token: s3.token, nonce: n3 },
    { ip: '198.51.100.153', ua: 'Mozilla/5.0', requireBiometrics: true }
  );
  assert.equal(v3.verdict, 'reject');
  assert.ok(v3.reasons.some((r) => r.code === 'missing_signals'));
});

test('hardening: tsig + vitals + signals round-trips cleanly while forged/newline tsig rejects', async () => {
  const proj = await core.createProject({ name: 'tsig_hardening' }, 'u_tsig_test');
  await core.updateProjectSettings(proj.pid, { minDurationMs: 0 });
  const freshProj = await core.loadProject(proj.pid);

  const cleanSignals = {
    sh: 'trc_v1_live',
    gpuRenderer: 'Apple M2',
    mousePoints: NATURAL_CURVE,
    elapsedMs: 1200,
    keyIntervals: [95, 132, 88, 114],
    rum: { dns: 12, tcp: 18, ttfb: 45, domReady: 180 },
    audio: 0.00012345,
  };

  // Authentic SDK payload (includes both vitals and signals alongside tsig)
  const sOk = await core.startSession(freshProj, { ip: '198.51.100.161', action: 'test' });
  const nOk = solvePow(sOk.challenge, sOk.difficulty);
  const validTsig = crypto.hmac(
    crypto.unb64u(sOk.rk),
    `obsx.sig.v1\n${sOk.session}\n${nOk}\n${crypto.canon(cleanSignals)}`
  );
  const recOk = await core.recordSignals({
    token: sOk.token,
    nonce: nOk,
    signals: cleanSignals,
    vitals: { cls: 0.01, lcp: 420 },
    tsig: validTsig,
  });
  assert.equal(recOk.ok, true);
  const verOk = await core.verify(freshProj, { token: sOk.token, nonce: nOk }, { ip: '198.51.100.161', ua: 'Mozilla/5.0' });
  assert.equal(verOk.verdict, 'accept');
  assert.equal(verOk.risk, 0);
  assert.deepEqual(verOk.reasons, []);

  // Forged tsig even with natural curved signals -> reject with bad_signature + tampered_builtins
  const sBad = await core.startSession(freshProj, { ip: '198.51.100.162', action: 'test' });
  const nBad = solvePow(sBad.challenge, sBad.difficulty);
  await core.recordSignals({
    token: sBad.token,
    nonce: nBad,
    signals: cleanSignals,
    vitals: { cls: 0.01 },
    tsig: 'forged_tsig_value',
  });
  const verBad = await core.verify(freshProj, { token: sBad.token, nonce: nBad }, { ip: '198.51.100.162', ua: 'Mozilla/5.0' });
  assert.equal(verBad.verdict, 'reject');
  assert.equal(verBad.risk, 100);
  const badCodes = verBad.reasons.map((r) => r.code);
  assert.ok(badCodes.includes('bad_signature'));
  assert.ok(badCodes.includes('tampered_builtins'));

  // Newline delimiter injection in nonce during tsig verification
  const sNl = await core.startSession(freshProj, { ip: '198.51.100.163', action: 'test' });
  const nNl = solvePow(sNl.challenge, sNl.difficulty);
  await core.recordSignals({
    token: sNl.token,
    nonce: `${nNl}\nextra`,
    signals: cleanSignals,
    tsig: validTsig,
  });
  const verNl = await core.verify(freshProj, { token: sNl.token, nonce: nNl }, { ip: '198.51.100.163', ua: 'Mozilla/5.0' });
  assert.equal(verNl.verdict, 'reject');
  assert.equal(verNl.risk, 100);
  assert.ok(verNl.reasons.some((r) => r.code === 'bad_signature'));
});

test('hardening: BotShield challenge prevents reflected XSS and open redirects', () => {
  botshield.reset();
  botshield.configure({
    enabled: true,
    mode: 'auto',
    engageRps: 100,
    baseDifficulty: 8,
    maxDifficulty: 12,
  });

  try {
    // 1. Script breakout payload in path must be escaped inside JS string and guarded by CSP
    const xssPath = '/</script><script>alert(1)</script>';
    const resXss = makeFakeRes();
    botshield.evaluate(
      { method: 'GET', headers: { 'user-agent': 'python-requests/2.31' } },
      resXss,
      '198.51.100.171',
      xssPath,
      10,
      new URL(`http://obsx.tech${xssPath}`),
      { activeConnections: 1, inFlight: 1 }
    );
    assert.equal(resXss.out.status, 403);
    assert.ok(!resXss.out.body.includes('</script><script>alert(1)'), 'Raw </script> breakout must not appear in HTML');
    assert.ok(resXss.out.body.includes('\\u003c/script\\u003e'), 'Escaped script tag must be present');
    assert.equal(resXss.out.headers['X-Frame-Options'], 'DENY');
    assert.equal(resXss.out.headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(resXss.out.headers['Referrer-Policy'], 'no-referrer');
    assert.ok(resXss.out.headers['Content-Security-Policy'].includes("default-src 'none'"));

    // 2. Open redirect normalization via //evil.com and /\evil.com
    for (const evilPath of ['//evil.com/phish', '/\\evil.com/phish']) {
      const challengeRes = makeFakeRes();
      botshield.evaluate(
        { method: 'GET', headers: { 'user-agent': 'python-requests/2.31' } },
        challengeRes,
        '198.51.100.172',
        evilPath,
        10,
        new URL(`http://obsx.tech${evilPath}`),
        { activeConnections: 1, inFlight: 1 }
      );
      const { cid, challenge, bits } = parseBotShieldChallenge(challengeRes.out.body);
      const nonce = solveBotShieldPow(challenge, bits);

      const solvedRes = makeFakeRes();
      const verifyUrl = new URL(`http://obsx.tech/?__bs=${cid}&__bn=${nonce}`);
      botshield.evaluate(
        { method: 'GET', headers: { 'user-agent': 'python-requests/2.31' } },
        solvedRes,
        '198.51.100.172',
        evilPath,
        10,
        verifyUrl,
        { activeConnections: 1, inFlight: 1 }
      );
      assert.equal(solvedRes.out.status, 302);
      assert.equal(solvedRes.out.headers.Location, '/evil.com/phish');
      assert.ok(!solvedRes.out.headers.Location.startsWith('//'));
    }
  } finally {
    restoreBotShield();
  }
});

test('hardening: malformed URLs, bad encodings, NUL bytes, non-object JSON, invalid resource IDs, and settings bounds are rejected cleanly', async () => {
  // Invalid percent-encoding and NUL bytes
  const badPct = await request('GET', '/%ZZ');
  assert.equal(badPct.status, 400);

  const nulPath = await request('GET', '/%00');
  assert.equal(nulPath.status, 400);

  const protoRel = await request('GET', '//evil.com');
  assert.equal(protoRel.status, 404, 'Protocol-relative path must normalize internally without redirecting');
  assert.equal(protoRel.headers.location, undefined);

  const delBadId = await request('DELETE', '/api/v1/notes/%ZZ');
  assert.equal(delBadId.status, 400);
  assert.equal(delBadId.json.error, 'invalid_id');

  const projBadId = await request('GET', '/api/v1/project/bad!pid');
  assert.equal(projBadId.status, 400);
  assert.equal(projBadId.json.error, 'invalid_id');

  const projNestedBadId = await request('GET', '/api/v1/project/a/b/c');
  assert.equal(projNestedBadId.status, 400);
  assert.equal(projNestedBadId.json.error, 'invalid_id');

  // Non-object JSON payloads must return 400 cleanly
  for (const rawJson of ['null', '[]', '"str"', '123']) {
    const res = await request('POST', '/api/v1/session', { body: rawJson });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'invalid_json');
  }

  // Raw HTTP request with malformed Host header falls back to localhost cleanly
  const rawResp = await new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write('GET /api/v1/health HTTP/1.1\r\nHost: bad host:!!\r\nConnection: close\r\n\r\n');
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('error', reject);
  });
  assert.ok(rawResp.startsWith('HTTP/1.1 200 '), 'Malformed Host should fall back to localhost and return 200 OK');

  // Raw unparseable request target triggers 400 invalid_request from parseRequestUrl()
  const rawBadUrl = await new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write('GET http://[::1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('error', reject);
  });
  assert.ok(rawBadUrl.startsWith('HTTP/1.1 400 '), 'Unparseable URL should return 400 Bad Request');
  assert.ok(rawBadUrl.includes('invalid_request'));

  // HSTS header is emitted on HTTPS proxy traffic and omitted on plain HTTP
  const plainMetrics = await request('GET', '/api/v1/metrics');
  assert.equal(plainMetrics.status, 200);
  assert.equal(plainMetrics.headers['strict-transport-security'], undefined);

  const httpsMetrics = await request('GET', '/api/v1/metrics', {
    headers: { 'x-forwarded-proto': 'https' },
  });
  assert.equal(httpsMetrics.status, 200);
  assert.equal(httpsMetrics.headers['strict-transport-security'], 'max-age=31536000; includeSubDomains');

  // Both createProject and updateProjectSettings enforce schema/bounds & origin caps
  const longFirstOrigins = ['https://' + 'x'.repeat(500), ...Array.from({ length: 70 }, (_, i) => `https://origin${i}.example.com`)];
  const createdProj = await core.createProject({
    name: 'bounds_proj',
    origins: longFirstOrigins,
    settings: {
      mode: 'bogus_mode',
      powDifficulty: -4,
      sessionTtlSec: 10,
      minDurationMs: -10,
      reviewAt: 500,
    },
  }, 'u_bounds');
  assert.equal(createdProj.settings.mode, 'enforce');
  assert.equal(createdProj.settings.powDifficulty, 1);
  assert.equal(createdProj.settings.sessionTtlSec, 60);
  assert.equal(createdProj.settings.minDurationMs, 0);
  assert.equal(createdProj.settings.reviewAt, 100);
  assert.equal(createdProj.settings.origins.length, 50);
  assert.equal(createdProj.settings.origins[0].length, 200);

  const updated = await core.updateProjectSettings(createdProj.pid, {
    powDifficulty: 999,
    sessionTtlSec: -50,
    minDurationMs: 0,
    origins: longFirstOrigins,
  });
  assert.equal(updated.settings.powDifficulty, 8);
  assert.equal(updated.settings.minDurationMs, 0);
  assert.equal(updated.settings.sessionTtlSec, 60);
  assert.equal(updated.settings.origins.length, 50);
  assert.equal(updated.settings.origins[0].length, 200);
});

test('hardening: crypto.isTestRuntime ignores substring "test" and respects NODE_ENV=production', () => {
  const prevNodeEnv = process.env.NODE_ENV;
  const prevObsx = process.env.OBSX_TEST_MODE;
  const prevTm = process.env.TEST_MODE;
  const prevArgv = process.argv.slice();
  const prevExecArgv = process.execArgv.slice();

  try {
    delete process.env.NODE_ENV;
    delete process.env.OBSX_TEST_MODE;
    delete process.env.TEST_MODE;
    process.execArgv = [];
    process.argv = ['node', '/srv/obsx/latest/server.js', 'attest'];
    assert.equal(crypto.isTestRuntime(), false, 'Substring "test" in latest/attest must not activate test mode');

    process.argv = ['node', '/srv/obsx/tests/example.test.js'];
    assert.equal(crypto.isTestRuntime(), true, 'Explicit .test.js script path enables test mode when not production');

    process.env.NODE_ENV = 'production';
    process.env.OBSX_TEST_MODE = '1';
    process.env.TEST_MODE = '1';
    process.execArgv = ['--test'];
    assert.equal(crypto.isTestRuntime(), false, 'NODE_ENV=production must always disable test runtime');

    process.env.NODE_ENV = 'test';
    delete process.env.OBSX_TEST_MODE;
    delete process.env.TEST_MODE;
    process.execArgv = [];
    process.argv = ['node', '/srv/obsx/server.js'];
    assert.equal(crypto.isTestRuntime(), true);
  } finally {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevObsx === undefined) delete process.env.OBSX_TEST_MODE;
    else process.env.OBSX_TEST_MODE = prevObsx;
    if (prevTm === undefined) delete process.env.TEST_MODE;
    else process.env.TEST_MODE = prevTm;
    process.argv = prevArgv;
    process.execArgv = prevExecArgv;
  }
});

test('hardening: concurrent startEmailAuth calls enforce atomic 45s cooldown lock and subnet-first limits', async () => {
  const raceEmail = `race_${crypto.randomId(6)}@example.com`;
  const callerIp = '100.64.10.1';

  const settled = await Promise.allSettled(
    Array.from({ length: 5 }, () => accounts.startEmailAuth(raceEmail, callerIp))
  );
  const fulfilled = settled.filter((r) => r.status === 'fulfilled');
  const rejected = settled.filter((r) => r.status === 'rejected');

  assert.equal(fulfilled.length, 1, 'Exactly one concurrent OTP request should win the atomic lock');
  assert.equal(rejected.length, 4, 'All competing parallel OTP requests must fail cooldown');
  assert.ok(rejected.every((r) => /Please wait/i.test(r.reason && r.reason.message)));

  // Subnet limit (> 10) executes before acquiring victim mailbox cooldown lock
  const floodedIp = '100.64.20.1';
  for (let i = 0; i < 10; i++) {
    await accounts.startEmailAuth(`flood_${i}_${crypto.randomId(4)}@example.com`, floodedIp);
  }
  const victimEmail = `victim_${crypto.randomId(6)}@example.com`;
  await assert.rejects(() => accounts.startEmailAuth(victimEmail, floodedIp), /Too many requests/i);
  const victimFresh = await accounts.startEmailAuth(victimEmail, '100.64.30.1');
  assert.equal(victimFresh.ok, true, 'Rate-limited IP must not burn victim mailbox cooldown');
});

test('hardening: mailer formats security alerts with escaped HTML, preserved alert newlines, and safe HTTP URLs only', () => {
  const rendered = mailer.formatSecurityAlertMessage({
    title: '<script>alert(1)</script>\r\nInjectedHeader: yes',
    summary: 'Line1: <img src=x onerror=alert(2)>\nLine2: & payload',
    severity: '<b>CRITICAL</b>',
    actionUrl: 'javascript:alert(3)',
  });

  assert.ok(!rendered.subject.includes('\r') && !rendered.subject.includes('\n'));
  assert.ok(!rendered.html.includes('<script>'), 'Script tags in title must be escaped');
  assert.ok(!rendered.html.includes('<img src=x'), 'Image XSS in summary must be escaped');
  assert.ok(!rendered.html.includes('<b>CRITICAL</b>'), 'HTML tags in severity must be escaped');
  assert.ok(!rendered.html.includes('javascript:'), 'javascript: URLs must be blocked in HTML button');
  assert.ok(!rendered.text.includes('javascript:'), 'javascript: URLs must be blocked in plain text body');
  assert.ok(rendered.text.includes('Line1: <img src=x onerror=alert(2)>\nLine2: & payload'));
  assert.ok(rendered.html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(rendered.html.includes('Line1: &lt;img src=x onerror=alert(2)&gt;<br>Line2: &amp; payload'));
  assert.ok(rendered.html.includes('https://obsx.tech/dashboard.html'));

  const validHttps = mailer.formatSecurityAlertMessage({
    title: 'Valid Alert',
    summary: 'All clear',
    actionUrl: 'https://obsx.tech/dashboard.html?tab=alerts',
  });
  assert.ok(validHttps.html.includes('https://obsx.tech/dashboard.html?tab=alerts'));
});

test('hardening: recordSignals preserves invalid tsig, unions tamper flags, validates tampered shape, rejects expired/bad inputs, and resists CHALLENGE_HTML replacer tokens', async () => {
  const { getKv } = require('../lib/kv');
  const kv = getKv();
  const proj = await core.createProject({ name: 'sticky_seal_proj' }, 'u_sticky');
  await core.updateProjectSettings(proj.pid, { minDurationMs: 0 });
  const freshProj = await core.loadProject(proj.pid);

  const cleanSignals = {
    sh: 'trc_v1_live',
    gpuRenderer: 'Apple M2',
    mousePoints: NATURAL_CURVE,
    elapsedMs: 1200,
    keyIntervals: [95, 132, 88, 114],
    rum: { dns: 12, tcp: 18, ttfb: 45, domReady: 180 },
    audio: 0.00012345,
  };

  // 1. Expired token and malformed signal arrays/objects rejected at recordSignals()
  const expiredTok = await crypto.signToken({ p: freshProj.pid, s: 's_exp', e: Date.now() - 1000 }, kv);
  assert.deepEqual(await core.recordSignals({ token: expiredTok, signals: cleanSignals }), { ok: false, error: 'expired' });

  const sBadInput = await core.startSession(freshProj, { ip: '198.51.100.181', action: 'test' });
  assert.deepEqual(await core.recordSignals({ token: sBadInput.token, signals: ['not', 'obj'] }), { ok: false, error: 'bad_signals' });
  assert.deepEqual(await core.recordSignals({ token: sBadInput.token, vitals: 'not_obj' }), { ok: false, error: 'bad_signals' });

  // 2. Sticky tsig='invalid' cannot be cleared by a subsequent valid tsig beacon
  const sSticky = await core.startSession(freshProj, { ip: '198.51.100.182', action: 'test' });
  const nSticky = solvePow(sSticky.challenge, sSticky.difficulty);
  await core.recordSignals({
    token: sSticky.token,
    nonce: nSticky,
    signals: cleanSignals,
    tsig: 'bad_first_tsig',
  });
  const validFollowupTsig = crypto.hmac(
    crypto.unb64u(sSticky.rk),
    `obsx.sig.v1\n${sSticky.session}\n${nSticky}\n${crypto.canon(cleanSignals)}`
  );
  await core.recordSignals({
    token: sSticky.token,
    nonce: nSticky,
    signals: cleanSignals,
    tsig: validFollowupTsig,
  });
  const stickyVerdict = await core.verify(freshProj, { token: sSticky.token, nonce: nSticky }, { ip: '198.51.100.182', ua: 'Mozilla/5.0' });
  assert.equal(stickyVerdict.verdict, 'reject');
  assert.ok(stickyVerdict.reasons.some((r) => r.code === 'bad_signature'));

  // 3. Monotonic preservation of tampered/webdriver flags and non-throwing malformed tampered types
  const sMono = await core.startSession(freshProj, { ip: '198.51.100.183', action: 'test' });
  const nMono = solvePow(sMono.challenge, sMono.difficulty);
  await core.recordSignals({
    token: sMono.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: NATURAL_CURVE,
      keyIntervals: [100, 120, 95],
      elapsedMs: 1200,
      webdriver: true,
      tampered: ['env_custom_flag', 123, null],
    },
  });
  await core.recordSignals({
    token: sMono.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: NATURAL_CURVE,
      keyIntervals: [100, 120, 95],
      elapsedMs: 1300,
      webdriver: false,
      tampered: { length: 1 },
    },
  });
  const monoVerdict = await core.verify(freshProj, { token: sMono.token, nonce: nMono }, { ip: '198.51.100.183', ua: 'Mozilla/5.0' });
  assert.ok(monoVerdict.reasons.some((r) => r.code === 'automation_webdriver'));
  assert.ok(monoVerdict.reasons.some((r) => r.code === 'automation_headless'));

  // 3b. Single-beacon malformed non-array tampered triggers delete merged.tampered cleanly without TypeError
  const sMalformed = await core.startSession(freshProj, { ip: '198.51.100.186', action: 'test' });
  const nMalformed = solvePow(sMalformed.challenge, sMalformed.difficulty);
  await core.recordSignals({
    token: sMalformed.token,
    signals: {
      ...cleanSignals,
      tampered: { length: 1 },
    },
  });
  const malformedVerdict = await core.verify(freshProj, { token: sMalformed.token, nonce: nMalformed }, { ip: '198.51.100.186', ua: 'Mozilla/5.0' });
  assert.equal(malformedVerdict.verdict, 'accept');

  // 4. Benign wrapped: and unrecognized gpu: entries with zero interaction still trigger missing_signals
  const sWrapped = await core.startSession(freshProj, { ip: '198.51.100.184', action: 'test' });
  const nWrapped = solvePow(sWrapped.challenge, sWrapped.difficulty);
  await core.recordSignals({
    token: sWrapped.token,
    signals: { sh: 'trc_v1_live', tampered: ['wrapped:console'] },
  });
  const wrappedVerdict = await core.verify(freshProj, { token: sWrapped.token, nonce: nWrapped }, { ip: '198.51.100.184', ua: 'Mozilla/5.0' });
  assert.equal(wrappedVerdict.verdict, 'reject');
  assert.ok(wrappedVerdict.reasons.some((r) => r.code === 'missing_signals'));

  const sGpuFake = await core.startSession(freshProj, { ip: '198.51.100.187', action: 'test' });
  const nGpuFake = solvePow(sGpuFake.challenge, sGpuFake.difficulty);
  await core.recordSignals({
    token: sGpuFake.token,
    signals: { sh: 'trc_v1_live', tampered: ['gpu:fake'] },
  });
  const gpuFakeVerdict = await core.verify(freshProj, { token: sGpuFake.token, nonce: nGpuFake }, { ip: '198.51.100.187', ua: 'Mozilla/5.0' });
  assert.equal(gpuFakeVerdict.verdict, 'reject');
  assert.ok(gpuFakeVerdict.reasons.some((r) => r.code === 'tampered_builtins'));
  assert.ok(gpuFakeVerdict.reasons.some((r) => r.code === 'missing_signals'));

  // 5. CHALLENGE_HTML ignores $' / placeholder tokens in UA & pathname
  botshield.reset();
  botshield.configure({ enabled: true, mode: 'auto', engageRps: 100, baseDifficulty: 8, maxDifficulty: 12 });
  try {
    const trkRes = makeFakeRes();
    const trkPath = "/__TARGET__/ok/$'/</script>";
    botshield.evaluate(
      { method: 'GET', headers: { 'user-agent': "bot$'__TARGET____BITS__" } },
      trkRes,
      '198.51.100.185',
      trkPath,
      10,
      new URL(`http://obsx.tech${trkPath}`),
      { activeConnections: 1, inFlight: 1 }
    );
    assert.equal(trkRes.out.status, 403);
    assert.equal((trkRes.out.body.match(/<\/script>/g) || []).length, 1, 'Only the legitimate closing script tag should exist');
    assert.ok(trkRes.out.body.includes("bot$'__TARGET____BITS__\""), 'Single-pass replacement must preserve placeholder literals in challenge');
    assert.ok(
      trkRes.out.body.includes('target = "/__TARGET__/ok/$\'/\\u003c/script\\u003e"'),
      'Single-pass replacement must render escaped target JS assignment intact'
    );
  } finally {
    restoreBotShield();
  }
});

test('hardening: telemetry privacy, scrub on verify, KV eviction, MIME checks, ring fail-closed, data export/erasure & Safe Mode 503', async () => {
  const kvMod = require('../lib/kv');
  const updater = require('../lib/updater');
  const obsxSdk = require('../lib/index');
  const nodeCrypto = require('node:crypto');
  const kv = kvMod.getKv();

  // 1. No synthetic recentEvents in fresh core load & /api/v1/telemetry/live filters strictly to DEMO pid + redacts topReasons
  const isolatedCoreRes = require('node:child_process').execFileSync(
    process.execPath,
    ['-e', "const c=require('./lib/core'); c.getLiveTelemetry().then(t=>console.log(JSON.stringify(t.recentEvents))).catch(e=>{console.error(e);process.exit(1);});"],
    { cwd: path.join(__dirname, '..'), encoding: 'utf8' }
  ).trim();
  assert.deepEqual(JSON.parse(isolatedCoreRes), [], 'Fresh core module must contain zero pre-seeded fake telemetry events');

  const privProj = await core.createProject({ name: 'private_telemetry_proj' }, 'u_priv_telemetry');
  await core.updateProjectSettings(privProj.pid, { minDurationMs: 0 });
  const privSession = await core.startSession(privProj, { ip: '198.51.100.190', action: 'private_checkout' });
  const privNonce = solvePow(privSession.challenge, privSession.difficulty);
  await core.recordSignals({
    token: privSession.token,
    nonce: privNonce,
    signals: {
      sh: 'trc_v1_live',
      gpuRenderer: 'NVIDIA RTX',
      mousePoints: [
        { x: 10, y: 10, t: 0 },
        { x: 34, y: 29, t: 21 },
        { x: 67, y: 41, t: 48 },
        { x: 92, y: 78, t: 74 },
        { x: 129, y: 95, t: 106 },
      ],
      keyIntervals: [92, 118, 86],
      elapsedMs: 1100,
    },
  });
  // Before verify: tr:s:<session> exists
  assert.ok(await kv.get(`tr:s:${privSession.session}`));
  const privVerdict = await core.verify(privProj, { token: privSession.token, nonce: privNonce }, { ip: '198.51.100.190', ua: 'Mozilla/5.0' });
  assert.equal(privVerdict.verdict, 'accept');
  // 2. Immediately scrubbed on verify() completion
  assert.equal(await kv.get(`tr:s:${privSession.session}`), null, 'tr:s:<session> behavioral telemetry must be scrubbed after verify()');

  const pubLive = await request('GET', '/api/v1/telemetry/live');
  assert.equal(pubLive.status, 200);
  assert.deepEqual(pubLive.json.stats && pubLive.json.stats.topReasons, {}, 'Unauthenticated /api/v1/telemetry/live must redact topReasons');
  assert.ok(!JSON.stringify(pubLive.json.recentEvents || []).includes('private_checkout'), 'Non-demo project events must never leak on public /api/v1/telemetry/live');

  const pubMetrics = await request('GET', '/api/v1/metrics');
  assert.equal(pubMetrics.status, 200);
  assert.deepEqual(pubMetrics.json.metrics && pubMetrics.json.metrics.topReasons, {}, 'Unauthenticated /api/v1/metrics must return redacted topReasons');

  // 3. MemoryStore priority-tiered eviction protects tr:used:* and credentials against tr:rl:* floods
  const tinyStore = new kvMod.MemoryStore(6);
  await tinyStore.set('tr:used:tok_critical', '1', 'EX', 300);
  await tinyStore.set('cred:important', '{"ok":true}');
  for (let i = 0; i < 8; i++) {
    await tinyStore.set(`tr:rl:198.51.100.${i}`, '5', 'EX', 60);
    await tinyStore.set(`tr:s:unverified_${i}`, '{}', 'EX', 300);
  }
  assert.equal(await tinyStore.get('tr:used:tok_critical'), '1', 'tr:used:* lock must survive rate-limit & unverified session floods');
  assert.equal(await tinyStore.get('cred:important'), '{"ok":true}', 'Credentials must survive volatile floods');

  // 4. lib/index.js WHATWG Headers support for clientUa resolution
  let seenServerToServerHeader = '';
  let capturedUa = '';
  const mockApiServer = http.createServer((req, res) => {
    seenServerToServerHeader = req.headers['content-type'] || '';
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      capturedUa = req.headers['x-obsx-client-ua'] || '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, allowed: true, verdict: 'accept', risk: 0, reasons: [] }));
    });
  });
  await new Promise((resolve) => mockApiServer.listen(0, '127.0.0.1', resolve));
  try {
    const apiEndpoint = `http://127.0.0.1:${mockApiServer.address().port}/api/v1`;
    const webReq = new Request('https://example.com/submit', {
      method: 'POST',
      headers: new Headers({ 'user-agent': 'Mozilla/5.0 WHATWG-Headers-Check/1.0' }),
    });
    const r = await obsxSdk.verifyToken({ token: 'tok_x', nonce: '1' }, {
      secretKey: 'sk_test_whatwg',
      endpoint: apiEndpoint,
      req: webReq,
    });
    assert.equal(r.allowed, true);
    assert.ok(seenServerToServerHeader.includes('application/json'));
    assert.equal(capturedUa, 'Mozilla/5.0 WHATWG-Headers-Check/1.0');
  } finally {
    mockApiServer.closeAllConnections?.();
    await new Promise((resolve) => mockApiServer.close(resolve));
  }

  // 5. CSRF guard blocks simple text/plain requests (403) and strict MIME check rejects non-JSON mutations with 415
  const csrfMimeRes = await request('POST', '/api/v1/notes', {
    headers: { 'Content-Type': 'text/plain' },
    body: '{"title":"x","content":"y"}',
  });
  assert.equal(csrfMimeRes.status, 403);
  assert.equal(csrfMimeRes.json.error, 'cross_origin_forbidden');

  const badMimeRes = await request('POST', '/api/v1/notes', {
    headers: { 'Content-Type': 'text/plain', 'X-Requested-With': 'fetch' },
    body: '{"title":"x","content":"y"}',
  });
  assert.equal(badMimeRes.status, 415);
  assert.equal(badMimeRes.json.error, 'unsupported_media_type');

  // 6. fetchHttpsBuffer rejects prematurely closed truncated HTTP responses
  const truncServer = net.createServer((sock) => {
    sock.once('data', () => {
      sock.write('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: text/plain\r\n\r\npartial_only');
      sock.destroy();
    });
  });
  await new Promise((resolve) => truncServer.listen(0, '127.0.0.1', resolve));
  try {
    const truncPort = truncServer.address().port;
    await assert.rejects(
      () => updater.fetchHttpsBuffer(`http://127.0.0.1:${truncPort}/truncated.js`, {
        allowedHosts: ['127.0.0.1'],
        allowInsecureLocal: true,
        allowIpLiteral: true,
      }),
      /Incomplete|truncated|aborted|closed|socket/i
    );
  } finally {
    await new Promise((resolve) => truncServer.close(resolve));
  }

  // 7. syncHybridCloudRing fails closed without verification key and validates HMAC(syncSecret, payloadStr)
  const unverifiedRing = await updater.syncHybridCloudRing({
    env: { OBSX_CLOUD_KEY: 'ck_test', OBSX_CLOUD_URL: 'https://obsx.tech' },
    fetchText: async () => JSON.stringify({ ok: true, activeSubnets: [{ subnet: '203.0.113.0/24', rejections: 5 }] }),
  });
  assert.equal(unverifiedRing.synced, false);
  assert.equal(unverifiedRing.reason, 'ring_verification_key_required');

  const ringSecret = 'ring-sync-secret-123456';
  const ringPayloadObj = { ts: Date.now(), activeSubnets: [{ subnet: '203.0.113.0/24', rejections: 7, remainingSeconds: 120 }] };
  const badSigRing = await updater.syncHybridCloudRing({
    env: { OBSX_CLOUD_KEY: 'ck_test', OBSX_CLOUD_URL: 'https://obsx.tech', OBSX_CLOUD_SYNC_SECRET: ringSecret },
    fetchText: async () => JSON.stringify({ ok: true, ...ringPayloadObj, sig: 'deadbeef' }),
  });
  assert.equal(badSigRing.synced, false);
  assert.equal(badSigRing.reason, 'invalid_ring_signature');

  const goodSig = crypto.hmac(ringSecret, crypto.canon(ringPayloadObj));
  const okRing = await updater.syncHybridCloudRing({
    env: { OBSX_CLOUD_KEY: 'ck_test', OBSX_CLOUD_URL: 'https://obsx.tech', OBSX_CLOUD_SYNC_SECRET: ringSecret },
    fetchText: async () => JSON.stringify({ ok: true, ...ringPayloadObj, sig: goodSig }),
  });
  assert.equal(okRing.synced, true);
  assert.equal(okRing.count, 1);

  // 8. GDPR/CCPA GET /api/v1/me/export & DELETE /api/v1/me cascading deletion
  const gdprEmail = 'gdpr-user@example.com';
  const startAuth = await accounts.startEmailAuth(gdprEmail, '198.51.100.191');
  const verifiedAuth = await accounts.verifyEmailAuth(gdprEmail, startAuth.devCode, false, { termsAccepted: true, termsVersion: '2026-11-14' });
  const gdprCookie = `obsx_session=${verifiedAuth.sid}`;
  const gdprProj = await core.createProject({ name: 'GDPR Cascade Project' }, verifiedAuth.uid);
  const createNoteRes = await request('POST', '/api/v1/notes', {
    headers: { Cookie: gdprCookie, 'X-Forwarded-For': '198.51.100.191' },
    body: { title: 'My Personal Note', content: 'Erase me completely', protectionMode: 'advisory' },
  });
  assert.equal(createNoteRes.status, 201);

  const exportRes = await request('GET', '/api/v1/me/export', { headers: { Cookie: gdprCookie } });
  assert.equal(exportRes.status, 200);
  assert.equal(exportRes.json.ok, true);
  assert.equal(exportRes.json.data.account.email, gdprEmail);
  assert.ok(exportRes.json.data.projects.some((p) => p.pid === gdprProj.pid));
  assert.ok(exportRes.json.data.notes.some((n) => n.title === 'My Personal Note'));

  const deleteMeRes = await request('DELETE', '/api/v1/me', { headers: { Cookie: gdprCookie } });
  assert.equal(deleteMeRes.status, 200);
  assert.equal(deleteMeRes.json.ok, true);

  const meAfterDelete = await request('GET', '/api/v1/me', { headers: { Cookie: gdprCookie } });
  assert.equal(meAfterDelete.status, 200);
  assert.equal(meAfterDelete.json.user, null, 'Deleted user session must be invalidated');
  assert.equal(await core.loadProject(gdprProj.pid), null, 'Deleted user projects must be cascaded out');

  // 9. OBSX_ENFORCE_LICENSE_ACCEPTANCE=true Safe Mode blocks /api/v1/session with 503 license_safe_mode
  const tmpLicenseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-lic-enforce-'));
  const prevEnforce = process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
  const prevStateFile = process.env.OBSX_LICENSE_STATE_FILE;
  const prevAcceptEnv = process.env.OBSX_ACCEPT_LICENSE;
  try {
    delete process.env.OBSX_ACCEPT_LICENSE;
    process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE = 'true';
    process.env.OBSX_LICENSE_STATE_FILE = path.join(tmpLicenseDir, 'missing-state.json');

    const safeSessionRes = await request('POST', '/api/v1/session', {
      body: { site: 'pk_obsx_sandbox' },
    });
    assert.equal(safeSessionRes.status, 503);
    assert.equal(safeSessionRes.json.error, 'license_safe_mode');
  } finally {
    if (prevEnforce === undefined) delete process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
    else process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE = prevEnforce;
    if (prevStateFile === undefined) delete process.env.OBSX_LICENSE_STATE_FILE;
    else process.env.OBSX_LICENSE_STATE_FILE = prevStateFile;
    if (prevAcceptEnv === undefined) delete process.env.OBSX_ACCEPT_LICENSE;
    else process.env.OBSX_ACCEPT_LICENSE = prevAcceptEnv;
    fs.rmSync(tmpLicenseDir, { recursive: true, force: true });
  }
});

test('hardening: seal monotonicity, blank score rejection, semver prerelease order, mailer fail-closed, cookie conflicts, and missing Content-Type', async () => {
  const telemetryMod = require('../lib/telemetry');
  const kvMod = require('../lib/kv');
  const updater = require('../lib/updater');
  const nodeCrypto = require('node:crypto');
  const kv = kvMod.getKv();

  // 1. evaluatePointerDynamics marks instant jump (>50px/ms) invalid directly
  const instantEval = telemetryMod.evaluatePointerDynamics([
    { x: 0, y: 0, t: 0 },
    { x: 500, y: 500, t: 1 },
    { x: 520, y: 510, t: 40 },
    { x: 530, y: 525, t: 85 },
  ]);
  assert.equal(instantEval.isInstant, true);
  assert.equal(instantEval.valid, false);

  const proj = await core.createProject({ name: 'inverse_hardening_proj' }, 'u_inverse_test');
  await core.updateProjectSettings(proj.pid, { minDurationMs: 0 });
  const freshProj = await core.loadProject(proj.pid);

  // 2. Empty / whitespace score coerces to NaN -> hard score_exceeded rejection
  const sBlankScore = await core.startSession(freshProj, { ip: '198.51.100.201', action: 'checkout' });
  const nBlankScore = solvePow(sBlankScore.challenge, sBlankScore.difficulty);
  const blankSignals = {
    sh: 'trc_v1_live',
    hrp: 'hrp_1a2b3c4d',
    mousePoints: NATURAL_CURVE,
    keyIntervals: [95, 118, 102, 129],
    elapsedMs: 1300,
    audio: 0.00012345,
  };
  await core.recordSignals({
    token: sBlankScore.token,
    nonce: nBlankScore,
    signals: blankSignals,
    tsig: crypto.hmac(
      crypto.unb64u(sBlankScore.rk),
      `obsx.sig.v1\n${sBlankScore.session}\n${nBlankScore}\n${crypto.canon(blankSignals)}`
    ),
  });
  const blankScoreVerdict = await core.verify(
    freshProj,
    { token: sBlankScore.token, nonce: nBlankScore, score: '   ' },
    { ip: '198.51.100.201', ua: 'Mozilla/5.0' }
  );
  assert.equal(blankScoreVerdict.verdict, 'reject');
  assert.ok(blankScoreVerdict.reasons.some((r) => r.code === 'score_exceeded'));

  // 3. tampered:bad_hrp adds synthetic_environment weight (>= rejectAt) and is rejected
  const sBadHrp = await core.startSession(freshProj, { ip: '198.51.100.202', action: 'login' });
  const nBadHrp = solvePow(sBadHrp.challenge, sBadHrp.difficulty);
  const badHrpSignals = {
    sh: 'trc_v1_live',
    hrp: 'forged_hrp_value',
    mousePoints: NATURAL_CURVE,
    keyIntervals: [95, 118, 102, 129],
    elapsedMs: 1300,
    audio: 0.00012345,
  };
  await core.recordSignals(
    {
      token: sBadHrp.token,
      nonce: nBadHrp,
      signals: badHrpSignals,
      tsig: crypto.hmac(
        crypto.unb64u(sBadHrp.rk),
        `obsx.sig.v1\n${sBadHrp.session}\n${nBadHrp}\n${crypto.canon(badHrpSignals)}`
      ),
    },
    { fromHttp: true, ip: '198.51.100.202', ua: 'Mozilla/5.0' }
  );
  const badHrpVerdict = await core.verify(
    freshProj,
    { token: sBadHrp.token, nonce: nBadHrp },
    { fromHttp: true, ip: '198.51.100.202', ua: 'Mozilla/5.0' }
  );
  assert.equal(badHrpVerdict.allowed, false);
  assert.equal(badHrpVerdict.verdict, 'reject');
  assert.ok(badHrpVerdict.reasons.some((r) => r.code === 'synthetic_environment'));

  // 4. missing_http stays sticky if signal #1 over HTTP omits tsig and signal #2 provides valid tsig
  const sMissingHttp = await core.startSession(freshProj, { ip: '198.51.100.203', action: 'login' });
  const nMissingHttp = solvePow(sMissingHttp.challenge, sMissingHttp.difficulty);
  await core.recordSignals(
    {
      token: sMissingHttp.token,
      nonce: nMissingHttp,
      signals: blankSignals,
    },
    { fromHttp: true, ip: '198.51.100.203', ua: 'Mozilla/5.0' }
  );
  await core.recordSignals(
    {
      token: sMissingHttp.token,
      nonce: nMissingHttp,
      signals: blankSignals,
      tsig: crypto.hmac(
        crypto.unb64u(sMissingHttp.rk),
        `obsx.sig.v1\n${sMissingHttp.session}\n${nMissingHttp}\n${crypto.canon(blankSignals)}`
      ),
    },
    { fromHttp: true, ip: '198.51.100.203', ua: 'Mozilla/5.0' }
  );
  const stickyMissingVerdict = await core.verify(
    freshProj,
    { token: sMissingHttp.token, nonce: nMissingHttp },
    { fromHttp: true, ip: '198.51.100.203', ua: 'Mozilla/5.0' }
  );
  assert.equal(stickyMissingVerdict.verdict, 'reject');
  assert.ok(stickyMissingVerdict.reasons.some((r) => r.code === 'missing_telemetry_seal'));

  // 4b. Signal #1 with valid tsig followed by Signal #2 over HTTP without tsig still flags missing_telemetry_seal
  const sDowngradeHttp = await core.startSession(freshProj, { ip: '198.51.100.208', action: 'login' });
  const nDowngradeHttp = solvePow(sDowngradeHttp.challenge, sDowngradeHttp.difficulty);
  await core.recordSignals(
    {
      token: sDowngradeHttp.token,
      nonce: nDowngradeHttp,
      signals: blankSignals,
      tsig: crypto.hmac(
        crypto.unb64u(sDowngradeHttp.rk),
        `obsx.sig.v1\n${sDowngradeHttp.session}\n${nDowngradeHttp}\n${crypto.canon(blankSignals)}`
      ),
    },
    { fromHttp: true, ip: '198.51.100.208', ua: 'Mozilla/5.0' }
  );
  await core.recordSignals(
    {
      token: sDowngradeHttp.token,
      nonce: nDowngradeHttp,
      signals: blankSignals,
    },
    { fromHttp: true, ip: '198.51.100.208', ua: 'Mozilla/5.0' }
  );
  const downgradeMissingVerdict = await core.verify(
    freshProj,
    { token: sDowngradeHttp.token, nonce: nDowngradeHttp },
    { fromHttp: true, ip: '198.51.100.208', ua: 'Mozilla/5.0' }
  );
  assert.equal(downgradeMissingVerdict.verdict, 'reject');
  assert.ok(downgradeMissingVerdict.reasons.some((r) => r.code === 'missing_telemetry_seal'));

  // 5. Future clock-skew > 60s reports stale_signature
  const sFutureSkew = await core.startSession(freshProj, { ip: '198.51.100.204', action: 'login' });
  const nFutureSkew = solvePow(sFutureSkew.challenge, sFutureSkew.difficulty);
  await core.recordSignals({
    token: sFutureSkew.token,
    nonce: nFutureSkew,
    signals: blankSignals,
    tsig: crypto.hmac(
      crypto.unb64u(sFutureSkew.rk),
      `obsx.sig.v1\n${sFutureSkew.session}\n${nFutureSkew}\n${crypto.canon(blankSignals)}`
    ),
  });
  const futureTs = Date.now() + 120000;
  const futureAction = { token: sFutureSkew.token, nonce: nFutureSkew, action: 'transfer', amount: 10 };
  const futureSig = crypto.signActionSeal(sFutureSkew.rk, sFutureSkew.session, futureTs, nFutureSkew, { action: 'transfer', amount: 10 });
  const futureVerdict = await core.verify(
    freshProj,
    { ...futureAction, seal: { ts: futureTs, sig: futureSig } },
    { ip: '198.51.100.204', ua: 'Mozilla/5.0' }
  );
  assert.equal(futureVerdict.verdict, 'reject');
  assert.ok(futureVerdict.reasons.some((r) => r.code === 'stale_signature'));

  // 6. Conflicting or malformed duplicate __Host-obsx_session fails closed
  const victimEmail = `dup_cookie_${crypto.randomId(4).toLowerCase()}@example.com`;
  const victimOtp = await accounts.startEmailAuth(victimEmail, '198.51.100.205');
  const victimSession = await accounts.verifyEmailAuth(victimEmail, victimOtp.devCode, true);
  assert.equal(
    await accounts.getSessionUser({
      headers: { cookie: `__Host-obsx_session=x; __Host-obsx_session=${victimSession.sid}` },
    }),
    null
  );
  assert.equal(
    (
      await accounts.getSessionUser({
        headers: { cookie: `obsx_session=attacker_noise_1234; obsx_session=more_noise; __Host-obsx_session=${victimSession.sid}` },
      })
    )?.email,
    victimEmail
  );

  // 7. 25th distinct /24 subnet is NOT locked out globally by earlier probes on victim mailbox
  const multiIpEmail = `fresh_subnet_${crypto.randomId(4)}@example.com`;
  for (let i = 1; i <= 24; i++) {
    await accounts.startEmailAuth(multiIpEmail, `100.65.${i}.10`);
  }
  const fresh25 = await accounts.startEmailAuth(multiIpEmail, '100.66.1.10');
  assert.equal(fresh25.ok, true);

  // 8. Production unconfigured SMTP fails closed for alerts & does not persist OTP hash
  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
  };
  try {
    process.env.NODE_ENV = 'production';
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;
    const prodAlert = await mailer.sendSecurityAlert('op@obsx.tech', {
      title: 'Prod Alert Fail Closed',
      summary: 'Should not succeed without SMTP in production',
      severity: 'HIGH',
    });
    assert.equal(prodAlert.ok, false);
    assert.equal(prodAlert.error, 'smtp_unconfigured');

    const failEmail = `no_persist_${crypto.randomId(4)}@example.com`;
    await assert.rejects(
      () => accounts.startEmailAuth(failEmail, '100.67.1.10'),
      /smtp_unconfigured/i
    );
    const leakedOtp = await kv.hgetall(`tr:ec:${crypto.sha256(failEmail)}`);
    assert.deepEqual(leakedOtp, {});
  } finally {
    if (savedEnv.NODE_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedEnv.NODE_ENV;
    if (savedEnv.SMTP_HOST !== undefined) process.env.SMTP_HOST = savedEnv.SMTP_HOST;
    if (savedEnv.SMTP_USER !== undefined) process.env.SMTP_USER = savedEnv.SMTP_USER;
    if (savedEnv.SMTP_PASS !== undefined) process.env.SMTP_PASS = savedEnv.SMTP_PASS;
  }

  // 9. Updater blocks prerelease downgrade (2.3.1 -> 2.3.1-alpha.1) and numeric prerelease downgrade
  const tmpPreDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-semver-pre-'));
  try {
    const keyPair = nodeCrypto.generateKeyPairSync('ed25519');
    const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });
    fs.writeFileSync(path.join(tmpPreDir, 'package.json'), JSON.stringify({ name: 'obsx-security', version: '2.3.1-alpha.10' }));
    const downPkgBuf = Buffer.from(JSON.stringify({ name: 'obsx-security', version: '2.3.1-alpha.2' }));
    const commitSha = 'a'.repeat(40);
    const manifestBuf = Buffer.from(
      JSON.stringify({
        commit: commitSha,
        files: { 'package.json': nodeCrypto.createHash('sha256').update(downPkgBuf).digest('hex') },
      })
    );
    const manifestSig = nodeCrypto.sign(null, manifestBuf, keyPair.privateKey);
    const preRes = await updater.checkAndApplyUpstreamUpdate({
      rootDir: tmpPreDir,
      force: true,
      silent: true,
      env: { OBSX_HTTP_SYNC: 'true', OBSX_UPDATE_PUBLIC_KEY: pubPem },
      assetFiles: ['package.json'],
      manifestBuffer: manifestBuf,
      manifestSigBuffer: manifestSig,
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return Buffer.from(JSON.stringify({ sha: commitSha }));
        return downPkgBuf;
      },
    });
    assert.equal(preRes.updated, false);
    assert.match(preRes.status, /version_downgrade_rejected/);

    // Also block 2.3.1 -> 2.3.1-alpha.1 prerelease downgrade
    fs.writeFileSync(path.join(tmpPreDir, 'package.json'), JSON.stringify({ name: 'obsx-security', version: '2.3.1' }));
    const downAlphaBuf = Buffer.from(JSON.stringify({ name: 'obsx-security', version: '2.3.1-alpha.1' }));
    const alphaManifestBuf = Buffer.from(
      JSON.stringify({
        commit: commitSha,
        files: { 'package.json': nodeCrypto.createHash('sha256').update(downAlphaBuf).digest('hex') },
      })
    );
    const alphaManifestSig = nodeCrypto.sign(null, alphaManifestBuf, keyPair.privateKey);
    const alphaRes = await updater.checkAndApplyUpstreamUpdate({
      rootDir: tmpPreDir,
      force: true,
      silent: true,
      env: { OBSX_HTTP_SYNC: 'true', OBSX_UPDATE_PUBLIC_KEY: pubPem },
      assetFiles: ['package.json'],
      manifestBuffer: alphaManifestBuf,
      manifestSigBuffer: alphaManifestSig,
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return Buffer.from(JSON.stringify({ sha: commitSha }));
        return downAlphaBuf;
      },
    });
    assert.equal(alphaRes.updated, false);
    assert.match(alphaRes.status, /version_downgrade_rejected/);
  } finally {
    fs.rmSync(tmpPreDir, { recursive: true, force: true });
  }

  // 10. POST with missing Content-Type and non-empty body rejects with 403 cross_origin_forbidden (and 415 with X-Requested-With)
  const postNoCt = (extraHeaders = {}) =>
    new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: Number(new URL(baseUrl).port),
          path: '/api/v1/notes',
          method: 'POST',
          headers: {
            Host: new URL(baseUrl).host,
            Origin: baseUrl,
            'Content-Length': 15,
            ...extraHeaders,
          },
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
        }
      );
      req.on('error', reject);
      req.write('{"title":"x"}  ');
      req.end();
    });
  const noCtCsrf = await postNoCt();
  assert.equal(noCtCsrf.status, 403);
  assert.equal(noCtCsrf.json.error, 'cross_origin_forbidden');

  const noCtMime = await postNoCt({ 'X-Requested-With': 'fetch' });
  assert.equal(noCtMime.status, 415);
  assert.equal(noCtMime.json.error, 'unsupported_media_type');
});

test('core, telemetry, mailer, updater, kv, and botshield handle review regressions cleanly', async () => {
  const { execFileSync } = require('child_process');
  const telemetryMod = require('../lib/telemetry');
  const updaterMod = require('../lib/updater');
  const { MemoryStore } = require('../lib/kv');

  // 1. project settings.origins normalizes trailing slashes & mixed case; mobile touchPoints satisfy human interaction
  const originProj = await core.createProject({
    name: 'Normalized Origin & Touch Project',
    origins: [
      'HTTPS://Shop.Example.COM/checkout/',
      'https://shop.example.com',
      'javascript:alert(1)',
    ],
    settings: { minDurationMs: 0 },
  });
  assert.deepEqual(originProj.settings.origins, ['https://shop.example.com']);
  const loadedOriginProj = await core.loadProject(originProj.pid);

  const mobileUa = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)';
  const touchSess = await core.startSession(loadedOriginProj, { ip: '198.51.100.201', action: 'checkout' });
  const touchNonce = solvePow(touchSess.challenge, touchSess.difficulty);
  const touchSignals = {
    sh: 'trc_v1_live',
    gpuRenderer: 'Apple GPU',
    mousePoints: [],
    touchPoints: [
      { x: 110, y: 240, t: 15 },
      { x: 115, y: 248, t: 48 },
      { x: 121, y: 256, t: 84 },
    ],
    dwellTimeMs: 420,
    elapsedMs: 1100,
    keyIntervals: [118, 142, 99],
    rum: { dns: 10, tcp: 14, ttfb: 38, domReady: 165 },
    audio: 0.00023456,
  };
  const touchTsig = crypto.hmac(
    crypto.unb64u(touchSess.rk),
    `obsx.sig.v1\n${touchSess.session}\n${touchNonce}\n${crypto.canon(touchSignals)}`
  );
  const recTouch = await core.recordSignals({
    token: touchSess.token,
    nonce: touchNonce,
    signals: touchSignals,
    tsig: touchTsig,
  });
  assert.equal(recTouch.ok, true);
  const acceptOriginVerdict = await core.verify(
    loadedOriginProj,
    { token: touchSess.token, nonce: touchNonce },
    { ip: '198.51.100.201', ua: mobileUa, origin: 'https://shop.example.com/cart' }
  );
  assert.equal(acceptOriginVerdict.verdict, 'accept');
  assert.equal(acceptOriginVerdict.risk, 0);

  const touchSessWrongOrigin = await core.startSession(loadedOriginProj, { ip: '198.51.100.202', action: 'checkout' });
  const touchNonceWrong = solvePow(touchSessWrongOrigin.challenge, touchSessWrongOrigin.difficulty);
  const recWrong = await core.recordSignals({
    token: touchSessWrongOrigin.token,
    nonce: touchNonceWrong,
    signals: touchSignals,
    tsig: crypto.hmac(
      crypto.unb64u(touchSessWrongOrigin.rk),
      `obsx.sig.v1\n${touchSessWrongOrigin.session}\n${touchNonceWrong}\n${crypto.canon(touchSignals)}`
    ),
  });
  assert.equal(recWrong.ok, true);
  const badOriginVerdict = await core.verify(
    loadedOriginProj,
    { token: touchSessWrongOrigin.token, nonce: touchNonceWrong },
    { ip: '198.51.100.202', ua: mobileUa, origin: 'https://evil.example.com' }
  );
  assert.ok(badOriginVerdict.reasons.some((r) => r.code === 'origin_mismatch'));

  // 2. telemetry.evaluatePointerDynamics rejects null/''/false coercion and sets isInstant: false for < 3 points
  const twoPtEval = telemetryMod.evaluatePointerDynamics([
    { x: 10, y: 10, t: 0 },
    { x: 20, y: 20, t: 25 },
  ]);
  assert.equal(twoPtEval.isInstant, false);
  const nonFiniteEval = telemetryMod.evaluatePointerDynamics([
    { x: null, y: '', t: false },
    { x: '  ', y: false, t: null },
    { x: 10, y: 12, t: 10 },
    { x: 20, y: 24, t: 30 },
  ]);
  assert.equal(nonFiniteEval.isInstant, false);
  assert.equal(nonFiniteEval.isLinear, false);

  // 3. mailer non-production unconfigured console OTP fallback & caught SMTP alert error
  const prevNodeEnv = process.env.NODE_ENV;
  const prevTestMode = process.env.OBSX_TEST_MODE;
  const prevForceSmtp = process.env.FORCE_SMTP;
  const prevSmtpHost = process.env.SMTP_HOST;
  const prevSmtpPort = process.env.SMTP_PORT;
  const prevSmtpUser = process.env.SMTP_USER;
  const prevSmtpPass = process.env.SMTP_PASS;
  const prevSmtpFrom = process.env.SMTP_FROM;
  const prevSmtpSecure = process.env.SMTP_SECURE;
  const origConsoleLog = console.log;
  const origConsoleWarn = console.warn;
  const origConsoleError = console.error;
  const closedSrv = net.createServer();
  await new Promise((resolve) => closedSrv.listen(0, '127.0.0.1', resolve));
  const deadSmtpPort = closedSrv.address().port;
  await new Promise((resolve) => closedSrv.close(resolve));

  try {
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_PASS;
    const childEnv = { PATH: process.env.PATH || '', NODE_ENV: 'development' };
    const devFallbackOut = execFileSync(
      process.execPath,
      [
        '-e',
        'const m = require("./lib/mailer"); m.sendVerificationCode("dev-otp@example.com", "654321").then((r) => { console.log("__RESULT__=" + JSON.stringify(r)); });',
      ],
      { cwd: path.resolve(__dirname, '..'), env: childEnv, encoding: 'utf8' }
    );
    const devResultLine = devFallbackOut.split('\n').find((l) => l.startsWith('__RESULT__='));
    assert.ok(devResultLine, 'Dev fallback child process must emit __RESULT__');
    const devFallbackRes = JSON.parse(devResultLine.slice('__RESULT__='.length));
    assert.equal(devFallbackRes.ok, true);
    assert.equal(devFallbackRes.devMode, true);
    assert.equal(devFallbackRes.code, undefined, 'Non-test dev fallback must not return code field in response');
    assert.ok(devFallbackOut.includes('654321'), 'Dev fallback must print OTP code box to console');

    process.env.OBSX_TEST_MODE = '1';
    process.env.FORCE_SMTP = 'true';
    process.env.SMTP_HOST = '127.0.0.1';
    process.env.SMTP_PORT = String(deadSmtpPort);
    process.env.SMTP_USER = 'ops@example.com';
    process.env.SMTP_PASS = 'secret-pass';
    process.env.SMTP_FROM = 'ops@example.com';
    process.env.SMTP_SECURE = 'false';
    console.log = () => {};
    console.warn = () => {};
    console.error = () => {};
    const failedAlert = await mailer.sendSecurityAlert('security@example.com', {
      title: 'SMTP Failure Isolation Test',
      summary: 'Verify sendSecurityAlert catches transport exceptions',
    });
    assert.equal(failedAlert.ok, false);
    assert.equal(failedAlert.devMode, false);
    assert.ok(typeof failedAlert.error === 'string' && failedAlert.error.length > 0);
  } finally {
    console.log = origConsoleLog;
    console.warn = origConsoleWarn;
    console.error = origConsoleError;
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevTestMode === undefined) delete process.env.OBSX_TEST_MODE;
    else process.env.OBSX_TEST_MODE = prevTestMode;
    if (prevForceSmtp === undefined) delete process.env.FORCE_SMTP;
    else process.env.FORCE_SMTP = prevForceSmtp;
    if (prevSmtpHost === undefined) delete process.env.SMTP_HOST;
    else process.env.SMTP_HOST = prevSmtpHost;
    if (prevSmtpPort === undefined) delete process.env.SMTP_PORT;
    else process.env.SMTP_PORT = prevSmtpPort;
    if (prevSmtpUser === undefined) delete process.env.SMTP_USER;
    else process.env.SMTP_USER = prevSmtpUser;
    if (prevSmtpPass === undefined) delete process.env.SMTP_PASS;
    else process.env.SMTP_PASS = prevSmtpPass;
    if (prevSmtpFrom === undefined) delete process.env.SMTP_FROM;
    else process.env.SMTP_FROM = prevSmtpFrom;
    if (prevSmtpSecure === undefined) delete process.env.SMTP_SECURE;
    else process.env.SMTP_SECURE = prevSmtpSecure;
  }

  // 4. updater.getSystemVersionInfo respects custom env & getOperatorDriftAdvisory tracks configured branch
  const tmpGitBase = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-branch-drift-'));
  try {
    const bareDir = path.join(tmpGitBase, 'remote.git');
    const cloneDir = path.join(tmpGitBase, 'clone');
    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: 'OBSX Test',
      GIT_AUTHOR_EMAIL: 'test@obsx.tech',
      GIT_COMMITTER_NAME: 'OBSX Test',
      GIT_COMMITTER_EMAIL: 'test@obsx.tech',
    };
    execFileSync('git', ['init', '--bare', bareDir], { stdio: 'ignore' });
    execFileSync('git', ['clone', bareDir, cloneDir], { stdio: 'ignore' });
    execFileSync('git', ['-C', cloneDir, 'checkout', '-b', 'release/v2.4'], { stdio: 'ignore' });
    fs.writeFileSync(path.join(cloneDir, 'package.json'), JSON.stringify({ name: 'obsx-security', version: '2.4.0' }));
    fs.writeFileSync(path.join(cloneDir, 'LICENSE'), 'Copyright\n');
    execFileSync('git', ['-C', cloneDir, 'add', '.'], { stdio: 'ignore' });
    execFileSync('git', ['-C', cloneDir, 'commit', '-m', 'init'], { env: gitEnv, stdio: 'ignore' });
    execFileSync('git', ['-C', cloneDir, 'push', '-u', 'origin', 'release/v2.4'], { stdio: 'ignore' });

    const clone2Dir = path.join(tmpGitBase, 'clone2');
    execFileSync('git', ['clone', '-b', 'release/v2.4', bareDir, clone2Dir], { stdio: 'ignore' });
    fs.writeFileSync(path.join(clone2Dir, 'VERSION'), '2.4.1\n');
    execFileSync('git', ['-C', clone2Dir, 'add', '.'], { stdio: 'ignore' });
    execFileSync('git', ['-C', clone2Dir, 'commit', '-m', 'upstream'], { env: gitEnv, stdio: 'ignore' });
    execFileSync('git', ['-C', clone2Dir, 'push', 'origin', 'release/v2.4'], { stdio: 'ignore' });
    execFileSync('git', ['-C', cloneDir, 'fetch', 'origin'], { stdio: 'ignore' });

    const verInfo = updaterMod.getSystemVersionInfo({
      rootDir: cloneDir,
      env: { OBSX_UPSTREAM_REPO: 'custom-org/obsx-mirror', OBSX_AUTO_UPDATE: 'true' },
    });
    assert.equal(verInfo.upstream, 'custom-org/obsx-mirror');
    assert.equal(verInfo.autoUpdate.enabled, true);

    const branchAdvisory = updaterMod.getOperatorDriftAdvisory({
      rootDir: cloneDir,
      branch: 'release/v2.4',
      fresh: true,
    });
    assert.ok(branchAdvisory.commitsBehind >= 1);
    assert.ok(branchAdvisory.upstreamCommits.length >= 1);
    assert.match(branchAdvisory.adaptationCommand, /git fetch origin release\/v2\.4 .*pull --rebase origin release\/v2\.4/);
  } finally {
    fs.rmSync(tmpGitBase, { recursive: true, force: true });
  }

  // 5. MemoryStore._evictIfFull pass-local counters preserve tr:used:* / tr:ec:* and Pass 5 evicts oldest tr:auth:* before replay locks
  const boundedMem = new MemoryStore(5, null);
  try {
    await boundedMem.set('tr:used:tok_keep', '1', 'EX', 300);
    await boundedMem.set('tr:ec:mail_keep', '123456', 'EX', 300);
    await boundedMem.set('tr:rl:volatile_1', '5', 'EX', 300);
    await boundedMem.set('tr:rl:volatile_2', '5', 'EX', 300);
    await boundedMem.set('tr:s:sess_unverified', { ok: 1 }, 'EX', 300);
    await boundedMem.set('tr:rl:trigger_evict', '1', 'EX', 300);
    assert.equal(await boundedMem.get('tr:used:tok_keep'), '1');
    assert.equal(await boundedMem.get('tr:ec:mail_keep'), '123456');

    const authMem = new MemoryStore(4, null);
    try {
      await authMem.set('tr:used:critical', '1', 'EX', 300);
      await authMem.set('tr:auth:oldest', 'a', 'EX', 300);
      await authMem.set('tr:auth:second', 'b', 'EX', 300);
      await authMem.set('tr:auth:third', 'c', 'EX', 300);
      await authMem.set('tr:auth:newest', 'd', 'EX', 300);
      assert.equal(await authMem.get('tr:used:critical'), '1');
      assert.equal(await authMem.get('tr:auth:oldest'), null);
      assert.equal(await authMem.get('tr:auth:newest'), 'd');
    } finally {
      authMem.close();
    }
  } finally {
    boundedMem.close();
  }

  // 6. botshield: short OBSX_OPERATOR_KEY falls back to OBSX_SECRET, maskSubnet masks CIDR, and Secure flag follows reqIsHttps
  const prevOpKey = process.env.OBSX_OPERATOR_KEY;
  const prevSecret = process.env.OBSX_SECRET;
  const origWarn = console.warn;
  console.warn = () => {};
  try {
    restoreBotShield();
    botshield.configure({
      enabled: true,
      mode: 'always',
      calmBudget: 1,
      ipBudget: 1,
      subnetQuarantinePerMin: 2,
      quarantineMs: 5000,
    });
    process.env.OBSX_OPERATOR_KEY = 'short';
    process.env.OBSX_SECRET = 'obsx_secret_min_16_chars_fallback';

    for (let i = 0; i < 5; i++) {
      botshield.evaluate(
        {
          method: 'POST',
          headers: {
            host: 'example.com',
            'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36',
            accept: 'application/json',
          },
        },
        makeFakeRes(),
        '198.51.100.88',
        '/api/v1/verify',
        1,
        new URL('http://example.com/api/v1/verify')
      );
    }

    const statsMaskedReq = makeFakeRes();
    botshield.evaluate(
      { method: 'GET', headers: { host: 'example.com', 'x-obsx-operator-key': 'short' } },
      statsMaskedReq,
      '203.0.113.89',
      '/api/v1/bot-protection',
      1,
      new URL('http://example.com/api/v1/bot-protection')
    );
    const maskedStats = JSON.parse(statsMaskedReq.out.body);
    assert.ok(maskedStats.quarantinedSubnets.some((s) => s.subnet === '198.51.*.*/24'));

    const statsDetailedReq = makeFakeRes();
    botshield.evaluate(
      { method: 'GET', headers: { host: 'example.com', 'x-obsx-operator-key': process.env.OBSX_SECRET } },
      statsDetailedReq,
      '203.0.113.90',
      '/api/v1/bot-protection',
      1,
      new URL('http://example.com/api/v1/bot-protection')
    );
    const detailedStats = JSON.parse(statsDetailedReq.out.body);
    assert.ok(detailedStats.quarantinedSubnets.some((s) => s.subnet === '198.51.100.0/24'));

    // Challenge solve cookie omits ; Secure when capacity.isHttps=false even with spoofed X-Forwarded-Proto
    const chalRes = makeFakeRes();
    botshield.evaluate(
      {
        method: 'GET',
        headers: {
          host: 'example.com',
          'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36',
          accept: 'text/html',
        },
      },
      chalRes,
      '203.0.113.91',
      '/',
      1,
      new URL('http://example.com/'),
      { isHttps: false, proxyTrustEnabled: false }
    );
    const parsedChal = parseBotShieldChallenge(chalRes.out.body);
    const solvedNonce = solveBotShieldPow(parsedChal.challenge, parsedChal.bits);

    const solveHttpRes = makeFakeRes();
    botshield.evaluate(
      {
        method: 'GET',
        headers: {
          host: 'example.com',
          'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36',
          'x-forwarded-proto': 'https',
        },
      },
      solveHttpRes,
      '203.0.113.91',
      '/',
      1,
      new URL(`http://example.com/?__bs=${parsedChal.cid}&__bn=${solvedNonce}`),
      { isHttps: false, proxyTrustEnabled: false }
    );
    const httpCookie = String(solveHttpRes.out.headers['Set-Cookie'] || '');
    assert.ok(httpCookie.includes('obsx_bs='));
    assert.ok(!httpCookie.includes('; Secure'));

    const chalRes2 = makeFakeRes();
    botshield.evaluate(
      {
        method: 'GET',
        headers: {
          host: 'example.com',
          'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36',
          accept: 'text/html',
        },
      },
      chalRes2,
      '203.0.113.92',
      '/',
      1,
      new URL('https://example.com/'),
      { isHttps: true, proxyTrustEnabled: false }
    );
    const parsedChal2 = parseBotShieldChallenge(chalRes2.out.body);
    const solvedNonce2 = solveBotShieldPow(parsedChal2.challenge, parsedChal2.bits);
    const solveHttpsRes = makeFakeRes();
    botshield.evaluate(
      {
        method: 'GET',
        headers: {
          host: 'example.com',
          'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36',
        },
      },
      solveHttpsRes,
      '203.0.113.92',
      '/',
      1,
      new URL(`https://example.com/?__bs=${parsedChal2.cid}&__bn=${solvedNonce2}`),
      { isHttps: true, proxyTrustEnabled: false }
    );
    const httpsCookie = String(solveHttpsRes.out.headers['Set-Cookie'] || '');
    assert.ok(httpsCookie.includes('obsx_bs='));
    assert.ok(httpsCookie.includes('; Secure'));
  } finally {
    console.warn = origWarn;
    if (prevOpKey === undefined) delete process.env.OBSX_OPERATOR_KEY;
    else process.env.OBSX_OPERATOR_KEY = prevOpKey;
    if (prevSecret === undefined) delete process.env.OBSX_SECRET;
    else process.env.OBSX_SECRET = prevSecret;
    restoreBotShield();
  }
});

test('accounts handle SMTP rollback, cross-subnet grace verification, multi-session delete, and termsVersion', async () => {
  // 1. startEmailAuth rolls back cooldown on SMTP failure so immediate retry succeeds
  const origSendVerification = mailer.sendVerificationCode;
  mailer.sendVerificationCode = async () => ({ ok: false, error: 'smtp_down' });
  try {
    await assert.rejects(
      () => accounts.startEmailAuth('rollback-retry@obsx.tech', '198.51.100.210'),
      (err) => err && err.status === 503 && err.message === 'smtp_down'
    );
  } finally {
    mailer.sendVerificationCode = origSendVerification;
  }
  const immediateRetry = await accounts.startEmailAuth('rollback-retry@obsx.tech', '198.51.100.210');
  assert.equal(immediateRetry.ok, true);
  assert.ok(/^\d{6}$/.test(immediateRetry.devCode));

  // 2. Cross-subnet OTP grace window accepts initial active code once with shared 5-attempt cap
  const graceEmail = 'cross-subnet-grace@obsx.tech';
  const g1 = await accounts.startEmailAuth(graceEmail, '198.51.100.220');
  const g2 = await accounts.startEmailAuth(graceEmail, '203.0.113.221');
  assert.notEqual(g1.devCode, g2.devCode);
  // First wrong attempt increments shared failure budget
  await assert.rejects(() => accounts.verifyEmailAuth(graceEmail, '000000', false));
  // Original code from g1 succeeds via grace window once
  const graceVerified = await accounts.verifyEmailAuth(graceEmail, g1.devCode, false, { termsAccepted: true });
  assert.ok(graceVerified.uid && graceVerified.sid);
  assert.equal(graceVerified.email, graceEmail);
  // Replay of g1 must fail because grace entry is deleted upon consumption
  await assert.rejects(() => accounts.verifyEmailAuth(graceEmail, g1.devCode, false));

  // 3. HTTP /api/v1/auth/email forwards termsVersion & DELETE /api/v1/me revokes sessions across devices
  const multiEmail = 'multi-session-revoke@obsx.tech';
  const sA = await request('POST', '/api/v1/auth/email', {
    headers: { 'X-Forwarded-For': '198.51.100.230' },
    body: { action: 'start', email: multiEmail },
  });
  assert.equal(sA.status, 200);
  const vA = await request('POST', '/api/v1/auth/email', {
    headers: { 'X-Forwarded-For': '198.51.100.230' },
    body: { action: 'verify', email: multiEmail, code: sA.json.devCode, termsAccepted: true, termsVersion: '2026-11-14-rev2' },
  });
  assert.equal(vA.status, 200);
  const cookieA = String(vA.headers['set-cookie']).split(';')[0];

  const sB = await request('POST', '/api/v1/auth/email', {
    headers: { 'X-Forwarded-For': '203.0.113.231' },
    body: { action: 'start', email: multiEmail },
  });
  assert.equal(sB.status, 200);
  const vB = await request('POST', '/api/v1/auth/email', {
    headers: { 'X-Forwarded-For': '203.0.113.231' },
    body: { action: 'verify', email: multiEmail, code: sB.json.devCode },
  });
  assert.equal(vB.status, 200);
  const cookieB = String(vB.headers['set-cookie']).split(';')[0];

  const exportTermsRes = await request('GET', '/api/v1/me/export', { headers: { Cookie: cookieA } });
  assert.equal(exportTermsRes.status, 200);
  assert.equal(exportTermsRes.json.data.account.termsVersion, '2026-11-14-rev2');

  const delAccountRes = await request('DELETE', '/api/v1/me', { headers: { Cookie: cookieA } });
  assert.equal(delAccountRes.status, 200);
  assert.equal(delAccountRes.json.deleted, true);

  const deviceBProjects = await request('GET', '/api/v1/projects', { headers: { Cookie: cookieB } });
  assert.equal(deviceBProjects.status, 401, 'Deleting account must immediately invalidate all device sessions');
});

