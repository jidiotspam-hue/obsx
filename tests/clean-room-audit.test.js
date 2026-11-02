'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');

test('clean-room: benign APM monitoring wraps (fetch/setTimeout) are classified as wrapped_runtime with low risk', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Solve PoW
  let nonce = 0;
  while (!require('../lib/crypto').verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Simulate client where Sentry or Datadog wrapped fetch
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: ['wrapped:fetch', 'wrapped:setTimeout'],
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 150 },
        { x: 45, y: 70, t: 200 },
        { x: 68, y: 110, t: 250 },
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

  // Benign APM wraps should only carry weight 5, keeping risk well below reject threshold (65)
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.risk, 5);
  assert.ok(
    v.reasons.some((r) => r.code === 'wrapped_runtime'),
    'Must classify benign APM hooks as wrapped_runtime'
  );
  assert.ok(
    !v.reasons.some((r) => r.code === 'tampered_builtins'),
    'Must NOT flag benign APM as hostile tampered_builtins'
  );
});

test('clean-room: hostile clock tampering (performance.now) is flagged as tampered_builtins with high risk', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Hostile cheat script hooked performance.now
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: ['tampered:performance.now'],
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 150 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, {
    token: s.token,
    score: 100,
  });

  Date.now = realNow;

  assert.ok(v.risk >= 60, 'Risk must be high for clock tampering');
  assert.ok(
    v.reasons.some((r) => r.code === 'tampered_builtins'),
    'Must flag hostile clock hooks as tampered_builtins'
  );
});
