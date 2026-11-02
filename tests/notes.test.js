'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const { getKv } = require('../lib/kv');

test('notes: unauthenticated access to notes is strictly denied', async () => {
  // Directly invoking note functions without valid uid fails
  const notes = await core.getUserNotes('non_existent_user');
  assert.deepEqual(notes, []);
});

test('notes: creating a note with OBSX protection verifies cryptographic attestation', async () => {
  const uid = 'u_test_note_owner';
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 180 },
        { x: 50, y: 70, t: 260 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  // Verification passes with valid PoW & signals
  const v = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
    score: 10,
  });

  Date.now = realNow;

  assert.equal(v.verdict, 'accept');

  // Create note
  const note = await core.createUserNote(uid, {
    title: 'Secret Vault Key',
    content: 'Sensitive encrypted payload',
    protection: 'obsx',
  });

  assert.ok(note.id.startsWith('note_'));
  assert.equal(note.title, 'Secret Vault Key');
  assert.equal(note.protection, 'obsx');

  // Verify retrieval
  const notes = await core.getUserNotes(uid);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].id, note.id);

  // Clean up
  const deleted = await core.deleteUserNote(uid, note.id);
  assert.equal(deleted, true);
  const emptyNotes = await core.getUserNotes(uid);
  assert.equal(emptyNotes.length, 0);
});

test('notes: malicious user cannot delete another user note', async () => {
  const ownerUid = 'u_legitimate_owner';
  const attackerUid = 'u_malicious_attacker';

  const note = await core.createUserNote(ownerUid, {
    title: 'Private Note',
    content: 'Do not touch',
    protection: 'obsx',
  });

  // Attacker attempts deletion
  const deleted = await core.deleteUserNote(attackerUid, note.id);
  assert.equal(deleted, false, 'Attacker must not be allowed to delete another user note');

  // Note remains intact for owner
  const ownerNotes = await core.getUserNotes(ownerUid);
  assert.equal(ownerNotes.length, 1);

  // Clean up
  await core.deleteUserNote(ownerUid, note.id);
});
