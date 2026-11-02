'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('../lib/crypto');
const core = require('../lib/core');
const { getKv } = require('../lib/kv');
const server = require('../server');
const http = require('http');

test('canon: deeply nested objects (> 32 levels) throw CANON_TOO_DEEP and fail closed', () => {
  // Build a 35-level deep object
  let deepObj = { level: 35 };
  for (let i = 34; i >= 0; i--) {
    deepObj = { child: deepObj, depth: i };
  }

  assert.throws(
    () => {
      crypto.canon(deepObj);
    },
    (err) => err.code === 'CANON_TOO_DEEP',
    'Must throw CANON_TOO_DEEP when recursion exceeds CANON_MAX_DEPTH'
  );

  // verifyActionSeal must fail closed (return false) instead of crashing server
  const isValid = crypto.verifyActionSeal(
    crypto.randomId(32),
    'sess_123',
    Date.now(),
    'nonce_1',
    deepObj,
    'fake_sig'
  );
  assert.equal(isValid, false, 'verifyActionSeal must fail closed on deeply nested payload');
});

test('canon: circular object references throw CANON_CIRCULAR and fail closed', () => {
  const circularObj = { name: 'exploit_probe' };
  circularObj.loop = circularObj;

  assert.throws(
    () => {
      crypto.canon(circularObj);
    },
    (err) => err.code === 'CANON_CIRCULAR',
    'Must throw CANON_CIRCULAR when cyclic graph is detected'
  );

  const isValid = crypto.verifyActionSeal(
    crypto.randomId(32),
    'sess_123',
    Date.now(),
    'nonce_1',
    circularObj,
    'fake_sig'
  );
  assert.equal(isValid, false, 'verifyActionSeal must fail closed on circular payload');
});

test('subnet: IPv4 and IPv6 normalizes to standard /24 and /48 CIDR buckets', () => {
  assert.equal(core.getSubnetKey('198.51.100.45'), 'subnet:v4:198.51.100.0/24');
  assert.equal(core.getSubnetKey('::ffff:203.0.113.19'), 'subnet:v4:203.0.113.0/24');
  assert.equal(core.getSubnetKey('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), 'subnet:v6:2001:0db8:85a3/48');
  assert.equal(core.getSubnetKey('127.0.0.1'), 'subnet:loopback');
  assert.equal(core.getSubnetKey('::1'), 'subnet:loopback');
});

test('enterprise: bursts of session requests from the same /24 subnet escalate PoW difficulty', async () => {
  const project = await core.loadProject(core.DEMO.pid);
  const targetSubnetIpBase = '198.51.200.';

  // Issue 8 initial sessions from the same /24 subnet
  for (let i = 1; i <= 8; i++) {
    await core.startSession(project, { ip: `${targetSubnetIpBase}${i}` });
  }

  // 9th request should see difficulty escalate to 3
  const s9 = await core.startSession(project, { ip: `${targetSubnetIpBase}9` });
  assert.equal(s9.difficulty >= 3, true, 'Subnet velocity must escalate PoW difficulty to >= 3');

  // Push past 16 requests from the same subnet
  for (let i = 10; i <= 16; i++) {
    await core.startSession(project, { ip: `${targetSubnetIpBase}${i}` });
  }

  const s17 = await core.startSession(project, { ip: `${targetSubnetIpBase}17` });
  assert.equal(s17.difficulty >= 4, true, 'Aggressive subnet burst must escalate difficulty to >= 4');
});

test('cdn: /sdk/v2.3.0/obsx.min.js delivers immutable cache headers and valid script', async () => {
  let tempServer = null;
  let port = null;

  if (!server.listening) {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
    tempServer = server;
  } else {
    port = server.address().port;
  }

  try {
    const res = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${port}/sdk/v2.3.0/obsx.min.js`, (r) => {
        let data = '';
        r.on('data', (c) => (data += c));
        r.on('end', () => resolve({ statusCode: r.statusCode, headers: r.headers, body: data }));
        r.on('error', reject);
      });
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['access-control-allow-origin'], '*');
    assert.equal(res.headers['cache-control'], 'public, max-age=31536000, immutable');
    assert.equal(res.body.includes('obsx.seal.v1'), true);
  } finally {
    if (tempServer) {
      await new Promise((resolve) => tempServer.close(resolve));
    }
  }
});
