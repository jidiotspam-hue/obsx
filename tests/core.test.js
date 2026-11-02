'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');

async function getSolvedSession(project) {
  const s = await core.startSession(project, { ip: '127.0.0.1' });
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [{ x: 10, y: 15, t: 10 }, { x: 30, y: 50, t: 80 }, { x: 60, y: 95, t: 160 }],
    },
  });
  return { ...s, nonce: String(nonce) };
}

test('core: replaying a spent session token is strictly rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await getSolvedSession(p);

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  // First verification passes
  const v1 = await core.verify(p, { token: s.token, nonce: s.nonce, score: 10 });
  assert.equal(v1.verdict, 'accept');

  // Second verification with identical token must fail
  const v2 = await core.verify(p, { token: s.token, nonce: s.nonce, score: 10 });
  assert.equal(v2.verdict, 'reject');
  assert.ok(v2.reasons.some((r) => r.code === 'token_reused'));

  Date.now = realNow;
});

test('core: scores exceeding maximum limit are rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid); // maxScore is 1000
  const s = await getSolvedSession(p);

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const v = await core.verify(p, { token: s.token, nonce: s.nonce, score: 99999 });
  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'score_exceeded'));

  Date.now = realNow;
});

test('core: actions completed faster than minDurationMs are rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid); // minDurationMs is 1200
  const s = await getSolvedSession(p);

  // No wait time (0ms elapsed)
  const v = await core.verify(p, { token: s.token, nonce: s.nonce, score: 10 });
  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'too_fast'));
});
