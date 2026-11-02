'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const mailer = require('../lib/mailer');
const { getKv } = require('../lib/kv');

test('passive-mode: project defaults to enforce mode and can be updated to passive mode', async () => {
  const p = await core.createProject({ name: 'Passive Test Project' });
  assert.equal(p.settings.mode, 'enforce');

  const updated = await core.updateProjectSettings(p.pid, { mode: 'passive' });
  assert.equal(updated.settings.mode, 'passive');

  const reloaded = await core.loadProject(p.pid);
  assert.equal(reloaded.settings.mode, 'passive');
});

test('passive-mode: session handshake with mode: passive issues difficulty <= 2', async () => {
  const p = await core.createProject({
    name: 'Passive Handshake Project',
    settings: { powDifficulty: 4, mode: 'passive' },
  });

  const session = await core.startSession(p, { ip: '198.51.100.55' });
  assert.equal(session.mode, 'passive');
  assert.ok(session.difficulty <= 2, `Difficulty should be capped at 2 in passive mode (was ${session.difficulty})`);
});

test('passive-mode: hostile bot request is allowed with verdict observe and shadowVerdict reject', async () => {
  const p = await core.createProject({
    name: 'Shadow Rejection Test',
    settings: { mode: 'passive' },
  });

  const s = await core.startSession(p, { ip: '198.51.100.99' });

  // Solve PoW
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Do NOT record any signals (missing_telemetry violation) -> would be Risk 100 Hard Reject
  const verdict = await core.verify(p, {
    token: s.token,
    nonce,
    action: 'Simulated Bot Check',
  }, { ip: '198.51.100.99' });

  assert.equal(verdict.ok, true);
  assert.equal(verdict.verdict, 'observe');
  assert.equal(verdict.allowed, true, 'Passive mode must never block requests');
  assert.equal(verdict.shadowVerdict, 'reject', 'Cryptographic reality must be shadow rejected');
  assert.equal(verdict.risk, 100);
  assert.ok(verdict.reasons.some((r) => r.code === 'missing_telemetry'));
});

test('passive-mode: switching back to enforce mode immediately hard-blocks the same attack signature', async () => {
  const p = await core.createProject({
    name: 'Enforce Switch Test',
    settings: { mode: 'passive' },
  });

  // Switch to enforce
  await core.updateProjectSettings(p.pid, { mode: 'enforce' });

  const s = await core.startSession(p, { ip: '198.51.100.100' });
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Submit missing telemetry in enforce mode
  const verdict = await core.verify(p, {
    token: s.token,
    nonce,
  }, { ip: '198.51.100.100' });

  assert.equal(verdict.verdict, 'reject');
  assert.equal(verdict.allowed, false, 'Enforce mode must block hostile requests');
  assert.equal(verdict.risk, 100);
});

test('passive-mode: live metrics record observe and shadowReject counters', async () => {
  const p = await core.createProject({
    name: 'Metrics Audit Test',
    settings: { mode: 'passive' },
  });

  const s = await core.startSession(p, { ip: '127.0.0.1' });
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.verify(p, {
    token: s.token,
    nonce,
  }, { ip: '127.0.0.1' });

  const metrics = await core.getLiveMetrics();
  assert.ok(metrics.breakdown.observe >= 1);
  assert.ok(metrics.breakdown.shadowReject >= 1);
});
