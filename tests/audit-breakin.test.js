'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const { getKv } = require('../lib/kv');

test('break-in audit: concurrent replay attack under race conditions is strictly rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '198.51.100.77' });

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

  // Fire 15 concurrent verify requests with the exact same token simultaneously
  const results = await Promise.all(
    Array.from({ length: 15 }).map(() =>
      core.verify(p, {
        token: s.token,
        nonce: String(nonce),
        score: 10,
      })
    )
  );

  Date.now = realNow;

  // Exactly 1 request may succeed; all other 14 must be rejected with token_reused
  const accepted = results.filter((r) => r.verdict === 'accept');
  const rejected = results.filter((r) => r.verdict === 'reject' && r.reasons.some((x) => x.code === 'token_reused'));

  assert.equal(accepted.length, 1, 'Only one atomic redemption can succeed');
  assert.equal(rejected.length, 14, 'All concurrent replays must be rejected');
});

test('break-in audit: PoW validation rejects difficulty 0 or negative bypass attempts', () => {
  // If difficulty is 0 or negative, verifyPoW must reject and not return true for empty prefix
  assert.equal(crypto.verifyPoW('any_challenge', '123', 0), false);
  assert.equal(crypto.verifyPoW('any_challenge', '123', -1), false);
  assert.equal(crypto.verifyPoW('any_challenge', '123', 'invalid'), false);
});

test('break-in audit: email auth enforces per-email cooldown against inbox bombing', async () => {
  const victimEmail = 'inbox_target@example.com';
  const ip1 = '198.51.100.10';
  const ip2 = '198.51.100.20';

  // First request succeeds
  const res1 = await accounts.startEmailAuth(victimEmail, ip1);
  assert.equal(res1.ok, true);

  // Immediate second request from a different IP must hit the email cooldown ceiling
  await assert.rejects(
    async () => {
      await accounts.startEmailAuth(victimEmail, ip2);
    },
    (err) => {
      return err.message.includes('cooldown') || err.message.includes('wait') || err.status === 429;
    }
  );
});

test('break-in audit: rate limiting normalizes IPv6 addresses to /64 subnets', async () => {
  const kv = getKv();
  const baseEmail = 'ipv6_user_';

  // 11 requests from rotating interface IDs within the same /64 subnet
  let blockedCount = 0;
  for (let i = 1; i <= 12; i++) {
    const ip = `2001:0db8:85a3:0000:0000:8a2e:0370:${i.toString(16).padStart(4, '0')}`;
    try {
      await accounts.startEmailAuth(`${baseEmail}${i}@example.com`, ip);
    } catch (err) {
      if (err.status === 429) blockedCount++;
    }
  }

  assert.ok(blockedCount >= 2, 'Subnet-based rate limiter must block after 10 requests from same /64 subnet');
});
