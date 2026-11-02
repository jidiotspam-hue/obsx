'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');

test('anti-proxy: incoming request with Bare-mux and Wisp headers is rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.22' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  // Simulate server verifying request that passed through a web proxy / Bare server
  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 100,
  }, {
    proxyHeaders: ['bare_mux_protocol', 'wisp_tunnel'],
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(v.risk >= 65);
  assert.ok(
    v.reasons.some((r) => r.code === 'proxy_virtualization'),
    'Must explicitly flag proxy_virtualization'
  );
  assert.ok(
    v.reasons.find((r) => r.code === 'proxy_virtualization').detail.includes('bare_mux_protocol')
  );
});

test('anti-proxy: Ultraviolet service worker controller signature is caught and rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.22' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: ['proxy_virtualization:sw_controller:/uv/sw.js'],
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 50,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.ok(
    v.reasons.some((r) => r.code === 'proxy_virtualization')
  );
});

test('anti-proxy: clean residential traffic with natural entropy passes cleanly', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.22' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: [],
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
    score: 50,
  }, {
    proxyHeaders: [],
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'accept');
  assert.equal(v.risk, 0);
  assert.equal(v.reasons.length, 0);
});

test('anti-proxy: sovereign gateway header is hard rejected with risk 100', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.33', proxyHeaders: ['sovereign_gateway'] });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  }, {
    proxyHeaders: ['sovereign_gateway'],
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.equal(v.risk, 100);
  assert.ok(v.reasons.some((r) => r.code === 'proxy_virtualization'));
  assert.ok(v.reasons.find((r) => r.code === 'proxy_virtualization').detail.includes('sovereign_gateway'));
});

test('anti-proxy: sovereign client hook and wrapped RTCPeerConnection are detected and rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.44' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: [
        'proxy_artifact:__sovereignHookActive',
        'proxy_virtualization:wrapped_RTCPeerConnection',
        'proxy_virtualization:dom_hud_injected',
      ],
      mousePoints: [
        { x: 10, y: 20, t: 100 },
        { x: 25, y: 40, t: 180 },
        { x: 45, y: 80, t: 260 },
      ],
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
  assert.equal(v.risk, 100);
  assert.ok(v.reasons.some((r) => r.code === 'proxy_virtualization'));
});

test('anti-bot: synthetic trajectory with degenerate jerk is detected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.55' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Generate mathematically smooth curve with constant acceleration (zero jerk variation)
  const syntheticPoints = [];
  for (let i = 0; i < 10; i++) {
    const t = 100 + i * 50;
    const x = Math.round(5 * i * i); // quadratic curve with constant 2nd derivative -> 0 jerk
    const y = Math.round(3 * i * i);
    syntheticPoints.push({ x, y, t });
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: syntheticPoints,
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  });

  Date.now = realNow;

  assert.ok(v.reasons.some((r) => r.code === 'synthetic_cadence'));
  assert.ok(v.reasons.find((r) => r.code === 'synthetic_cadence').detail.includes('tremor'));
});
