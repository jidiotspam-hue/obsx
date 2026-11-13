'use strict';

process.env.TRUST_PROXY = 'true';
process.env.OBSX_TEST_MODE = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
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
  const licStatePath = path.join(__dirname, '..', '.obsx-license-state.json');
  const hadLicState = fs.existsSync(licStatePath);
  const prevLicState = hadLicState ? fs.readFileSync(licStatePath, 'utf8') : null;
  process.env.OBSX_SECRET = 'valid_operator_secret_key_abcdef';
  process.env.OPERATOR_EMAILS = 'ops-admin@obsx.tech';
  process.env.ALERT_EMAIL = 'alert-recipient@example.com';

  try {
    const regEmail = `regular_${crypto.randomId(6)}@example.com`;
    const regStart = await accounts.startEmailAuth(regEmail, '198.51.100.141');
    const regSession = await accounts.verifyEmailAuth(regEmail, regStart.devCode);
    const regCookie = `obsx_session=${regSession.sid}`;

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
    assert.equal(keyDiff.json.ok, true);

    const acceptRes = await request('POST', '/api/v1/system/license/accept', {
      headers: { Cookie: opCookie },
      body: {},
    });
    assert.equal(acceptRes.status, 200);
    assert.equal(acceptRes.json.ok, true);
    assert.equal(acceptRes.json.accepted, true);
    assert.equal(acceptRes.json.acceptedBy, 'ops-admin@obsx.tech');

    const opLicRes = await request('GET', '/api/v1/system/license', {
      headers: { 'x-obsx-key': process.env.OBSX_SECRET },
    });
    assert.equal(opLicRes.status, 200);
    assert.equal(opLicRes.json.ok, true);
    assert.equal(opLicRes.json.accepted, true);

    const pubVer = await request('GET', '/api/v1/system/version');
    assert.equal(pubVer.status, 200);
    assert.equal(pubVer.json.safeMode, false);
    assert.ok(pubVer.json.licenseFingerprint && pubVer.json.licenseFingerprint.length === 16);
    assert.equal('acceptedBy' in pubVer.json, false);
    assert.equal(pubVer.json.license, undefined);
    assert.equal(pubVer.json.autoUpdate.httpSyncEnabled, false);
    assert.equal(pubVer.json.autoUpdate.autoRestartEnabled, false);
  } finally {
    if (hadLicState) fs.writeFileSync(licStatePath, prevLicState, 'utf8');
    else if (fs.existsSync(licStatePath)) fs.unlinkSync(licStatePath);
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
