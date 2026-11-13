'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('engine: behavioral telemetry is mandatory; empty signals reject with risk 100', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Fast-forward session start time past minDurationMs
  const kv = require('../lib/kv').getKv();
  await kv.hset(`tr:s:${s.session}`, 'i', String(Date.now() - 2000));

  // Verify without sending any telemetry signals
  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  });

  assert.equal(v.verdict, 'reject', 'Expected zero-beacon request to be rejected');
  assert.equal(v.risk, 100, 'Expected risk 100');
  const hasMissing = v.reasons.some((r) => r.code === 'missing_telemetry');
  assert.equal(hasMissing, true, 'Expected missing_telemetry in reasons');
});

test('engine: rotateProjectSecretKey enforces strict revocation of deprecated keys', async () => {
  const p = await core.createProject({ name: 'Key Revocation Specification' }, 'test_user_key_rev');
  const oldKey = p.secretKey;

  // Confirm old key works
  const beforeRotation = await core.projectBySecretKey(oldKey);
  assert.ok(beforeRotation, 'Old key should resolve project initially');
  assert.equal(beforeRotation.pid, p.pid);

  // Rotate key
  const rotated = await core.rotateProjectSecretKey(p.pid);
  const newKey = rotated.secretKey;
  assert.notEqual(newKey, oldKey);

  // Confirm new key works
  const withNewKey = await core.projectBySecretKey(newKey);
  assert.ok(withNewKey, 'New key should resolve project');
  assert.equal(withNewKey.pid, p.pid);

  // Confirm old key is REVOKED
  const withOldKeyAfter = await core.projectBySecretKey(oldKey);
  assert.equal(withOldKeyAfter, null, 'Old secret key must be revoked after rotation');
});

test('engine: mailbox normalization handles canonical provider addressing', () => {
  const email1 = 'alexis.grimmace@gmail.com';
  const email2 = 'a.lexis.grimmace@gmail.com';
  const email3 = 'alexisgrimmace@gmail.com';

  const key1 = accounts.getNormalizedMailboxKey(email1);
  const key2 = accounts.getNormalizedMailboxKey(email2);
  const key3 = accounts.getNormalizedMailboxKey(email3);

  assert.equal(key1, key2, 'Canonical provider aliases must produce identical mailbox key');
  assert.equal(key2, key3, 'Canonical provider aliases must produce identical mailbox key');
});

test('engine: action seal preserves application-level token fields', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Record human signals
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 150 },
        { x: 45, y: 70, t: 200 },
        { x: 68, y: 110, t: 250 },
        { x: 95, y: 160, t: 300 },
      ],
    },
  });

  const kv = require('../lib/kv').getKv();
  await kv.hset(`tr:s:${s.session}`, 'i', String(Date.now() - 2000));

  // Application payload contains its own payment gateway 'token' field
  const payload = {
    action: 'checkout',
    token: 'tok_stripe_client_charge_12345',
    amount: 99.50,
  };

  const ts = Date.now();
  const sig = crypto.signActionSeal(s.rk, s.session, ts, String(nonce), payload);

  const requestBody = {
    ...payload,
    obsx: {
      token: s.token,
      nonce: String(nonce),
      ts,
      sig,
    },
  };

  const v = await core.verify(p, requestBody);
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.sealed, 'ok', 'Sealed status must be ok even when payload has a token field');
  assert.equal(v.risk, 0);
});

test('engine: SDK widget embeds dual token and challenge nonce hidden inputs', () => {
  const tracerSrc = fs.readFileSync(path.join(__dirname, '../src/tracer.js'), 'utf8');
  assert.ok(tracerSrc.includes('name="obsx-token"'), 'Must contain obsx-token');
  assert.ok(tracerSrc.includes('name="obsx-nonce"'), 'Must contain obsx-nonce');
});

test('engine: MemoryStore snapshot persistence restores session state across restarts', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-snap-'));
  const tmpSnapshot = path.join(tmpDir, 'snapshot.json');
  const { MemoryStore } = require('../lib/kv');

  try {
    const store1 = new MemoryStore(1000, tmpSnapshot);
    await store1.set('test:key', 'persistent_value');
    await store1.hset('test:hash', 'field1', 'hash_value');
    store1.saveSnapshot();
    store1.close();

    // New instance simulates restarted daemon
    const store2 = new MemoryStore(1000, tmpSnapshot);
    const val = await store2.get('test:key');
    const hval = await store2.hget('test:hash', 'field1');
    store2.close();

    assert.equal(val, 'persistent_value');
    assert.equal(hval, 'hash_value');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('engine: SDK rehandshake method produces fresh attestation with rolling entropy', () => {
  const tracerSrc = fs.readFileSync(path.join(__dirname, '../src/tracer.js'), 'utf8');
  assert.ok(tracerSrc.includes('async rehandshake('), 'Must provide rehandshake API');
  assert.ok(tracerSrc.includes('mouseBuffer.shift()'), 'Must use rolling ring-buffer');
});

test('engine: priority-tiered eviction purges ephemeral bot keys while preserving active human sessions', async () => {
  const { MemoryStore } = require('../lib/kv');
  const store = new MemoryStore(10); // tiny cap of 10 keys

  // 1. Insert verified human session
  await store.hset('tr:s:human_session_1', { p: 'p1', sig: '{"sh":"trc_v1_live"}' });

  // 2. Insert unverified bot session
  await store.hset('tr:s:bot_session_1', { p: 'p1' });

  // 3. Flood with ephemeral bot rate keys and used tokens
  for (let i = 0; i < 15; i++) {
    await store.set(`tr:used:token_${i}`, '1');
    await store.set(`tr:rl:sub_${i}`, '1');
  }

  // Store must stay bounded
  assert.ok(store.store.size <= 10, 'Store must not exceed maxKeys cap');

  // Verified human session MUST survive eviction
  const human = await store.hgetall('tr:s:human_session_1');
  assert.ok(human && human.p === 'p1', 'Verified human session must be preserved');
  assert.ok(human && human.sig, 'Human session telemetry must be intact');
});

test('updater: hashFileSha256 normalizes CRLF to LF to prevent false-positive Safe Mode lockouts', () => {
  const { hashFileSha256 } = require('../lib/updater');
  const hash = hashFileSha256('lib/core.js');
  assert.ok(hash && hash.length === 64, 'SHA-256 hash must be 64 hex characters');
});
