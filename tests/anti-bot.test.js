'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');

test('anti-bot: empty signals {} must be rejected with missing_telemetry', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Record EMPTY signals (The flaw that defeated legacy advisory scripts)
  await core.recordSignals({ token: s.token, signals: {} });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    score: 100,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(v.risk >= 65, 'Risk must be at or above reject threshold');
  assert.ok(
    v.reasons.some((r) => r.code === 'missing_telemetry'),
    'Must explicitly flag missing_telemetry'
  );
});

test('anti-bot: missing or invalid proof-of-work is hard rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Provide signals but invalid PoW nonce
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [{ x: 10, y: 20, t: 100 }, { x: 30, y: 55, t: 200 }, { x: 90, y: 110, t: 300 }],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: 'bad_nonce_12345',
    score: 50,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(
    v.reasons.some((r) => r.code === 'invalid_pow'),
    'Must reject invalid PoW'
  );
});

test('anti-bot: valid session with PoW and natural entropy is accepted with risk 0', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Solve PoW
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Supply natural signals
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
        { x: 80, y: 125, t: 340 },
        { x: 120, y: 170, t: 420 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 100,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'accept');
  assert.equal(v.risk, 0);
  assert.equal(v.reasons.length, 0);
});

test('anti-bot: web proxy virtualization (Ultraviolet / Scramjet / Bare-mux) is rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Solve PoW
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Supply signals flagged with proxy virtualization
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: ['proxy_artifact:__uv', 'proxy_virtualization:location_getter_trap'],
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
        { x: 80, y: 125, t: 340 },
        { x: 120, y: 170, t: 420 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 100,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(v.risk >= 65, 'Risk must trigger reject');
  assert.ok(
    v.reasons.some((r) => r.code === 'proxy_virtualization'),
    'Must specifically flag proxy_virtualization'
  );
});

test('anti-bot: real user monitoring (RUM) metrics with PoW is accepted with risk 0', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Solve PoW
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Supply disguised Web Vitals payload
  await core.recordSignals({
    token: s.token,
    vitals: {
      fp: 'trc_v1_live',
      cls: 0.002,
      fid: 12,
      d_vec: '10,20,100;25,40,180;45,80,260;80,125,340;120,170,420',
      c_var: '120,135,110,140',
      rt_mask: 0,
      hp: 0,
      age: 2000,
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 100,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'accept');
  assert.equal(v.risk, 0);
});

test('anti-bot: unauthorized probe interface is hard rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Supply payload with probe violation flag
  await core.recordSignals({
    token: s.token,
    vitals: {
      fp: 'trc_v1_live',
      d_vec: '10,20,100;25,40,180;45,80,260',
      rt_mask: 8, // Probe flag
      hp: 1,
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'probe_violation'));
});

test('anti-bot: automated scanner probe signature (wd/hl/au) is flagged and rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Supply scanner-style bot probe fields
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      wd: false,
      hl: false,
      au: [],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'bot_signature_probe'));
});
