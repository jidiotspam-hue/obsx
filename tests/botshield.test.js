'use strict';

/*
 * Unit tests for the origin shield (lib/botshield.js).
 *
 * The shield is the only thing standing between a flood and a 905 MB Raspberry
 * Pi, so every rule here is exercised against a fake request/response pair: no
 * server, no network, no Cloudflare.
 *
 *   OBSX_TEST_MODE=1 node --test tests/botshield.test.js
 */

const test = require('node:test');
const assert = require('node:assert');
const botshield = require('../lib/botshield');

process.env.OBSX_TEST_MODE = '1';
botshield.stopMonitors();

const BROWSER = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';
const BOT = 'python-requests/2.31';

function fakeRes() {
  const out = { status: 0, headers: {}, body: '' };
  return {
    out,
    writeHead(status, headers = {}) {
      out.status = status;
      Object.assign(out.headers, headers || {});
    },
    end(body = '') { out.body = body; },
  };
}

function makeReq(ua, cookie = '', extra = null, method = 'GET') {
  const headers = { 'user-agent': ua, cookie };
  // Real browsers negotiate content and language. The shield uses that as
  // evidence that the user agent string is not just copied from Chrome.
  if (extra === null) {
    headers.accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
    headers['accept-language'] = 'en-US,en;q=0.9';
  } else {
    Object.assign(headers, extra);
  }
  return { headers, method };
}

/** One request through the shield. Returns the outcome plus what the shield said. */
function hit(ip, pathname, ua, capacity, cookie = '', method = 'GET') {
  const res = fakeRes();
  const url = new URL(pathname, 'http://obsx.tech');
  const outcome = botshield.evaluate(makeReq(ua, cookie, null, method), res, ip, url.pathname,
    capacity && capacity.reqRate !== undefined ? capacity.reqRate : 10, url, capacity);
  return { handled: outcome.handled, verified: outcome.verified,
    status: res.out.status, body: res.out.body, headers: res.out.headers };
}

// Every test starts from the same known configuration; otherwise a threshold set
// in one test leaks into the next and the failures stop meaning anything.
const DEFAULTS = {
  enabled: true, mode: 'auto', engageRps: 120, disengageRps: 40, calmMs: 45000,
  baseDifficulty: 8, maxDifficulty: 12, verifyTtlMs: 900000, challengeTtlMs: 120000,
  maxAttempts: 6, quarantineMs: 300000, ipBudget: 60, crawlerBudget: 240,
  maxConnsPerIp: 120, maxConcurrentPerIp: 25, fanoutIpsPerMin: 400,
  verifiedBudget: 600, calmBudget: 400, statusBudget: 40, subnetBudget: 900,
  subnetQuarantinePerMin: 2400, uaFleetBudget: 1500, hardConnCeiling: 600,
  fanoutSubnetsPerMin: 120, maxPathLen: 256, escapeMaxAttempts: 12,
  maxActiveConnections: 300, maxInFlight: 100, maxServedRps: 150,
  maxBodyBytes: 512 * 1024,
  maxWorkLatencyMs: 250, maxRssMb: 620, maxEventLagMs: 200, maxMapSize: 20000,
  quarantineEscape: true,
};

function fresh(overrides) {
  botshield.reset();
  botshield.configure(Object.assign({}, DEFAULTS, overrides || {}));
  return botshield.config;
}

/** Brute-force the nonce the browser would find (test difficulty is kept low). */
function solve(challenge, bits) {
  for (let n = 0; n < 1000000; n++) {
    if (botshield.powOk(challenge, String(n), bits)) return String(n);
  }
  throw new Error('no nonce found');
}

function parseChallenge(html) {
  const cid = /var cid = "([^"]+)"/.exec(html);
  const challenge = /challenge = "([^"]+)"/.exec(html);
  const bits = /bits = (\d+)/.exec(html);
  if (!cid || !challenge || !bits) throw new Error('challenge page malformed');
  return { cid: cid[1], challenge: challenge[1], bits: Number(bits[1]) };
}

test('PoW: a solved nonce verifies, a forged one does not', () => {
  const challenge = 'abc123:1.2.3.4:chrome';
  const nonce = solve(challenge, 12);
  assert.ok(botshield.powOk(challenge, nonce, 12), 'valid nonce must verify');
  assert.ok(!botshield.powOk(challenge, nonce + '1', 12), 'tampered nonce must fail');
  assert.ok(!botshield.powOk(challenge, '', 12), 'empty nonce must fail');
  assert.ok(botshield.fnv1a('hello') === botshield.fnv1a('hello'), 'hash is deterministic');
});

test('disabled shield passes everything through to the application', () => {
  fresh({ mode: 'off' });
  const r = hit('203.0.113.5', '/', BOT, { activeConnections: 5, inFlight: 1 });
  assert.equal(r.handled, false, 'a disabled shield must not answer');
  assert.equal(r.status, 0, 'nothing was written to the response');
});

test('calm traffic: a real browser is served, a scripted client is challenged', () => {
  fresh();
  const human = hit('198.51.100.7', '/', BROWSER, { activeConnections: 4, inFlight: 1 });
  assert.equal(human.handled, false, 'browser must reach the application untouched');

  const bot = hit('198.51.100.8', '/', BOT, { activeConnections: 4, inFlight: 1 });
  assert.equal(bot.handled, true);
  assert.equal(bot.status, 403);
  assert.match(bot.headers['X-OBSX-BotShield'], /challenge/);
  assert.match(bot.body, /proof-of-work/, 'challenge page must explain itself');
});

test('challenge round trip: solve once, get a cookie, then pass for 15 minutes', () => {
  fresh();
  const ip = '198.51.100.9';
  const cap = { activeConnections: 4, inFlight: 1 };
  const page = hit(ip, '/', BOT, cap);
  const { cid, challenge, bits } = parseChallenge(page.body);

  const nonce = solve(challenge, bits);
  const answer = hit(ip, `/?__bs=${cid}&__bn=${nonce}`, BOT, cap);
  assert.equal(answer.status, 302, 'a correct answer redirects to the page');
  const cookie = /obsx_bs=([^;]+)/.exec(answer.headers['Set-Cookie']);
  assert.ok(cookie, 'verification must set obsx_bs');
  assert.match(answer.headers['Set-Cookie'], /HttpOnly/, 'cookie must be HttpOnly');

  const followUp = hit(ip, '/', BROWSER, cap, `obsx_bs=${cookie[1]}`);
  assert.equal(followUp.handled, false, 'verified client reaches the application');

  const forged = hit(ip, `/?__bs=${cid}&__bn=999999`, BOT, cap);
  assert.equal(forged.status, 403, 'the same challenge cannot be reused');
});

test('difficulty is frozen into the challenge, so a ramp cannot break a real user', () => {
  fresh({ baseDifficulty: 8, maxDifficulty: 22 });
  const ip = '198.51.100.10';
  const page = hit(ip, '/', BOT, { activeConnections: 4, inFlight: 1, reqRate: 10 });
  const { cid, challenge, bits } = parseChallenge(page.body);
  // Traffic spikes to 2000 req/s between the challenge and the answer.
  const nonce = solve(challenge, bits);
  const answer = hit(ip, `/?__bs=${cid}&__bn=${nonce}`, BOT, { activeConnections: 4, inFlight: 1, reqRate: 2000 });
  assert.equal(answer.status, 302, 'answer must still be accepted at the issued difficulty');
  assert.ok(bits < botshield.currentDifficulty(2000), 'difficulty should have ramped for new challenges');
});

test('adaptive difficulty: pressure makes the work harder, calm makes it cheap', () => {
  fresh({ baseDifficulty: 16, maxDifficulty: 22 });
  assert.equal(botshield.currentDifficulty(10), 16, 'calm origin uses the base cost');
  const engaged = hit('198.51.100.11', '/', BOT, { activeConnections: 4, inFlight: 1, reqRate: 900 });
  assert.equal(engaged.status, 403);
  const bits = Number(/bits = (\d+)/.exec(engaged.body)[1]);
  assert.ok(bits > 16, 'engaged origin raises the difficulty');
  assert.ok(bits <= 22, 'difficulty is capped so real browsers are never locked out');
});

test('engagement is automatic: it fires under load and stands down when calm', () => {
  fresh({ engageRps: 120, disengageRps: 40, calmMs: 0 });
  hit('198.51.100.12', '/', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 300 });
  assert.equal(botshield.stats().engaged, true, '120+ req/s engages the shield');

  const asset = hit('198.51.100.12', '/assets/app.js', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 300 });
  assert.equal(asset.status, 403, 'unverified asset requests are refused while engaged');
  assert.match(asset.headers['X-OBSX-BotShield'], /under_attack/);

  hit('198.51.100.12', '/', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 20 });
  assert.equal(botshield.stats().engaged, false, 'the shield stands down once traffic settles');
});

test('per-IP budget: a polite visitor is never rate limited, a hammer is', () => {
  fresh({ calmBudget: 20, ipBudget: 20 });
  const ip = '198.51.100.13';
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  let served = 0;
  let limited = 0;
  for (let i = 0; i < 25; i++) {
    const r = hit(ip, '/dashboard.html', BROWSER, cap);
    if (r.handled) { limited++; assert.equal(r.status, 429); }
    else served++;
  }
  assert.equal(served, 20, 'exactly the budget is served');
  assert.equal(limited, 5, 'the rest is refused with 429');
  assert.ok(botshield.stats().counters.byTier.budget >= 5);
});

test('repeat offenders are quarantined, and quarantine is cheaper than a challenge', () => {
  fresh({ maxAttempts: 3, ipBudget: 100000 });
  const ip = '198.51.100.14';
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  for (let i = 0; i < 3; i++) hit(ip, '/', BOT, cap);
  const r = hit(ip, '/', BOT, cap);
  assert.equal(r.status, 403);
  assert.equal(r.headers['X-OBSX-BotShield'], 'quarantine', 'the offender is now refused by a Map hit');
  assert.ok(botshield.stats(true).quarantinedIps.some((q) => q.ip === ip));
  assert.ok(r.body.length < 120, 'quarantine response must be tiny');
});

test('status endpoints are never challenged, but they are budgeted', () => {
  fresh({ statusBudget: 5 });
  const ip = '198.51.100.15';
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 1000 };
  for (let i = 0; i < 5; i++) {
    const r = hit(ip, '/api/v1/health', 'curl/8.0', cap);
    assert.equal(r.handled, false, 'health must stay readable during an attack');
  }
  const over = hit(ip, '/api/v1/health', 'curl/8.0', cap);
  assert.equal(over.status, 429, 'the status path cannot become the flood path');
  assert.equal(over.headers['X-OBSX-BotShield'], 'status_budget');
});

test('fleet detection: a botnet of polite IPs is caught by its subnet', () => {
  fresh({ subnetBudget: 100, ipBudget: 100000, uaFleetBudget: 100000 });
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  let refused = 0;
  for (let i = 1; i <= 30; i++) {
    for (let j = 0; j < 5; j++) {
      const r = hit(`203.0.113.${i}`, '/', BROWSER, cap);
      if (r.headers['X-OBSX-BotShield'] === 'subnet') refused++;
    }
  }
  assert.ok(refused > 0, 'the /24 as a whole is stopped even though no single IP broke a rule');
  assert.ok(botshield.stats().stateSizes.subnetWindows > 0);
});

test('fleet detection: rotating IPs sharing one user agent are caught as one class', () => {
  fresh({ uaFleetBudget: 200, subnetBudget: 100000, ipBudget: 100000 });
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  let refused = 0;
  for (let i = 1; i <= 60; i++) {
    for (let j = 0; j < 5; j++) {
      const r = hit(`203.0.113.${i}`, '/', 'HeadlessChrome/120.0.0.0', cap);
      if (r.headers['X-OBSX-BotShield'] === 'fleet') refused++;
    }
  }
  assert.ok(refused > 0, 'one user agent making 300 requests is a fleet, not a visitor');
});

test('capacity: connection ceiling and in-flight saturation shed with 503', () => {
  fresh();
  const r1 = hit('198.51.100.16', '/', BROWSER, { activeConnections: 700, inFlight: 30 });
  assert.equal(r1.status, 503);
  assert.equal(r1.headers['X-OBSX-BotShield'], 'shed:connection_ceiling');
  assert.equal(r1.headers['Retry-After'], '5');

  const r2 = hit('198.51.100.16', '/', BROWSER, { activeConnections: 10, inFlight: 150 });
  assert.equal(r2.status, 503);
  assert.equal(r2.headers['X-OBSX-BotShield'], 'shed:saturation');
});

test('memory guard: the shield refuses before the Pi runs out of RAM', () => {
  fresh({ maxRssMb: 1 }); // real RSS is always above this, so the guard must fire
  const r = hit('198.51.100.17', '/', BROWSER, { activeConnections: 5, inFlight: 1 });
  assert.equal(r.status, 503, 'a process at its memory limit stops doing work');
  assert.ok(botshield.stats().health.rssMb > 0, 'the shield actually measures its own memory');
  fresh({ maxRssMb: 9999 });
});

test('verified visitors get headroom, so a real surge is not punished', () => {
  fresh({ maxServedRps: 10, verifiedBudget: 100000, ipBudget: 1, calmBudget: 1 });
  const ip = '198.51.100.18';
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  const page = hit(ip, '/', BOT, cap);
  const { cid, challenge, bits } = parseChallenge(page.body);
  const nonce = solve(challenge, bits);
  const cookie = /obsx_bs=([^;]+)/.exec(hit(ip, `/?__bs=${cid}&__bn=${nonce}`, BOT, cap).headers['Set-Cookie'])[1];

  let served = 0;
  for (let i = 0; i < 25; i++) {
    if (!hit(ip, '/dashboard.html', BROWSER, cap, `obsx_bs=${cookie}`).handled) served++;
  }
  assert.ok(served > 10, 'verified clients pass the 1x cap that stops unverified ones');
});

test('state is bounded: a spoofed-IP flood cannot grow the shield forever', () => {
  fresh({ maxMapSize: 100, ipBudget: 1000000 });
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  for (let i = 0; i < 5000; i++) hit(`203.0.${Math.floor(i / 256)}.${i % 256}`, '/', BROWSER, cap);
  const sizes = botshield.stats().stateSizes;
  assert.ok(sizes.ipWindows <= 100, `ip windows must be capped (${sizes.ipWindows})`);
  assert.ok(sizes.offenders <= 100, `offender list must be capped (${sizes.offenders})`);
  assert.ok(sizes.verified <= 100);
  assert.ok(sizes.pending <= 100);
});

test('counters add up: every request is accounted for exactly once', () => {
  fresh({ calmBudget: 5000, ipBudget: 5000 });
  const cap = { activeConnections: 5, inFlight: 1, reqRate: 10 };
  const before = { ...botshield.stats().counters };
  for (let i = 1; i <= 50; i++) hit(`198.51.100.${i}`, '/', i % 2 ? BROWSER : BOT, cap);
  const after = botshield.stats().counters;
  assert.equal(after.requests - before.requests, 50);
  assert.equal(after.challenged + after.passed + after.blocked + after.shed, 50);
});

test('subnet math: IPv4 uses /24 and IPv6 uses /64', () => {
  assert.equal(botshield.subnetOf('203.0.113.45'), '203.0.113.0/24');
  assert.equal(botshield.subnetOf('2605:8880:4c00:1f2:1234:5678:9abc:def0'), '2605:8880:4c00:1f2::/64');
  assert.notEqual(botshield.uaClass('Chrome/121.0'), botshield.uaClass('Firefox/121.0'));
  assert.equal(botshield.uaClass('Chrome/121.0.1'), botshield.uaClass('Chrome/122.0.2'));
});

/* ------------------------------------------------------ search engines */

test('search engines are served, never challenged, but still budgeted', () => {
  fresh({ crawlerBudget: 5 });
  const googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
  let served = 0, refused = 0;
  for (let i = 0; i < 8; i++) {
    const r = hit('203.0.113.50', '/', googlebot, { activeConnections: 5, inFlight: 1 });
    if (r.handled) refused++; else served++;
  }
  assert.equal(served, 5, 'a search engine gets its budget without a challenge');
  assert.equal(refused, 3, 'the surplus is rate limited, not challenged');
  assert.equal(botshield.stats().counters.challenged, 0, 'Googlebot must never get a JS challenge');
});

test('a browser user agent with no browser headers is treated as a bot', () => {
  fresh();
  const spoof = { headers: { 'user-agent': BROWSER } };   // no Accept, no Accept-Language
  const res = fakeRes();
  const url = new URL('/', 'http://obsx.tech');
  const outcome = botshield.evaluate(spoof, res, '198.51.100.70', url.pathname, 10, url,
    { activeConnections: 3, inFlight: 1 });
  assert.equal(outcome.handled, true, 'a copied Chrome string is not proof of a browser');
  assert.equal(res.out.status, 403);
  assert.equal(res.out.headers['X-OBSX-BotShield'], 'challenge');
  assert.equal(botshield.stats().counters.byTier.spoofed, 1);
});

/* ------------------------------------------------------ quarantine */

test('a subnet quarantine is not undone by one solved challenge', () => {
  fresh({ subnetBudget: 20, subnetQuarantinePerMin: 20, quarantineMs: 300000 });
  // Get a real challenge for one address before the subnet trips.
  const first = hit('203.0.113.1', '/', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 300 });
  const m = parseChallenge(first.body);
  assert.ok(m, 'the shield issued a challenge');

  // Hammer the /24 from twenty different addresses: the fleet rule quarantines it.
  for (let i = 2; i <= 22; i++) {
    hit('203.0.113.' + i, '/', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 300 });
  }
  assert.ok(botshield.stats().quarantinedSubnets.length > 0, 'the subnet was quarantined');

  // The one address that did the work gets through, the range stays closed.
  const url = new URL('/?__bs=' + m.cid + '&__bn=' + solve(m.challenge, m.bits), 'http://obsx.tech');
  const res = fakeRes();
  const solved = botshield.evaluate(makeReq(BROWSER), res, '203.0.113.1', url.pathname, 10, url,
    { activeConnections: 5, inFlight: 1 });
  assert.equal(solved.handled, true);
  assert.equal(res.out.status, 302, 'the verified address is released');

  const neighbour = hit('203.0.113.2', '/', BROWSER, { activeConnections: 5, inFlight: 1, reqRate: 300 });
  assert.equal(neighbour.status, 403);
  assert.equal(neighbour.headers['X-OBSX-BotShield'], 'subnet_quarantine',
    'a solved challenge does not open the whole /24');
});

test('repeat quarantine escalates: the second offence costs more than the first', () => {
  fresh({ maxAttempts: 1, quarantineMs: 1000 });
  const ip = '198.51.100.90';
  hit(ip, '/', BOT, { activeConnections: 5, inFlight: 1 });      // challenge
  hit(ip, '/', BOT, { activeConnections: 5, inFlight: 1 });      // quarantine, strike 1
  const first = botshield.stats().quarantinedIps[0];
  assert.ok(first && first.secondsLeft > 0, 'the address was quarantined');
  assert.ok(first.secondsLeft <= 1000, 'the first strike is the base duration');

  // Let it expire, then offend again.
  const t0 = Date.now();
  while (Date.now() - t0 < 1100) { /* spin: the test clock is short */ }
  hit(ip, '/', BOT, { activeConnections: 5, inFlight: 1 });      // challenge again
  hit(ip, '/', BOT, { activeConnections: 5, inFlight: 1 });      // quarantine, strike 2
  const second = botshield.stats().quarantinedIps[0];
  assert.ok(second.secondsLeft > first.secondsLeft, 'the second strike lasts longer than the first');
  assert.equal(botshield.stats().counters.quarantined, 2);
});

/* ------------------------------------------------------ hygiene */

test('expired state is swept, so the shield does not become the leak', () => {
  fresh({ quarantineMs: 1000, challengeTtlMs: 1000, maxAttempts: 1 });
  hit('198.51.100.99', '/', BOT, { activeConnections: 5, inFlight: 1 });
  hit('198.51.100.99', '/', BOT, { activeConnections: 5, inFlight: 1 });
  assert.equal(botshield.stats().stateSizes.quarantined, 1);
  const t0 = Date.now();
  while (Date.now() - t0 < 1100) { /* let the quarantine expire */ }
  botshield.pruneState();
  assert.equal(botshield.stats().stateSizes.quarantined, 0, 'expired entries are removed');
  assert.equal(botshield.stats().stateSizes.pending, 0, 'unanswered challenges are removed');
});

test('served traffic is counted separately from refused traffic', () => {
  fresh();
  for (let i = 0; i < 10; i++) {
    hit('198.51.100.80', '/', BROWSER, { activeConnections: 4, inFlight: 1 });
    hit('198.51.100.81', '/', BOT, { activeConnections: 4, inFlight: 1 });
  }
  const c = botshield.stats().counters;
  assert.equal(c.requests, 20);
  assert.equal(c.servedRequests, 10, 'only traffic that reached the application counts as served');
  assert.equal(c.blocked + c.challenged, 10);
});

/* ------------------------------------------- concurrency and fan-out */

test('one address cannot hold the origin open with unlimited parallel requests', () => {
  fresh({ maxConcurrentPerIp: 5 });
  const ip = '198.51.100.70';
  for (let i = 0; i < 5; i++) {
    const r = hit(ip, '/', BROWSER, { activeConnections: 20, inFlight: 5 });
    assert.equal(r.handled, false, 'the first five parallel requests are served');
  }
  const sixth = hit(ip, '/', BROWSER, { activeConnections: 20, inFlight: 6 });
  assert.equal(sixth.status, 429, 'the sixth concurrent request is refused');
  assert.equal(sixth.headers['X-OBSX-BotShield'], 'concurrent');

  // Drain them and the address is served again: the cap is about parallelism,
  // not a punishment.
  for (let i = 0; i < 5; i++) botshield.noteWorkLatency(1, ip);
  const after = hit(ip, '/', BROWSER, { activeConnections: 20, inFlight: 1 });
  assert.equal(after.handled, false, 'the address is served once its requests finish');
});

test('a botnet of many polite addresses is detected by fan-out, not by rate', () => {
  // engageRps is deliberately unreachable, so only fan-out can engage the shield.
  fresh({ engageRps: 100000, disengageRps: 0, ipBudget: 500, calmBudget: 100000, uaFleetBudget: 100000, subnetBudget: 100000, subnetQuarantinePerMin: 100000, fanoutIpsPerMin: 300, maxServedRps: 100000 });
  for (let i = 0; i < 400; i++) {
    hit('203.0.113.' + (i % 250) + '', '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
    hit('198.51.100.' + (i % 250), '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
    hit('192.0.2.' + (i % 250), '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
  }
  assert.ok(botshield.stats().engaged, 'fan-out alone engaged the shield');
  assert.ok(botshield.stats().counters.distinctIps >= 300, 'distinct addresses were counted');
  const r = hit('198.51.100.123', '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
  assert.equal(r.status, 403, 'while engaged, an unproven client is challenged (got ' + r.status + ')');
});

test('state stays bounded under a spoofed-IP flood', () => {
  fresh({ maxMapSize: 1000 });
  for (let i = 0; i < 60000; i++) {
    hit('203.' + (i % 250) + '.' + ((i * 13) % 250) + '.' + ((i * 7) % 250), '/', BOT,
      { activeConnections: 10, inFlight: 1, reqRate: 400 });
  }
  const sizes = botshield.stats().stateSizes;
  assert.ok(sizes.verified <= 1000, 'verified map is capped');
  assert.ok(sizes.pending <= 1000, 'pending challenges are capped');
  assert.ok(sizes.ipWindows <= 1000, 'per-IP windows are capped');
  assert.ok(sizes.subnetWindows <= 1000, 'subnet windows are capped');
  assert.ok(sizes.uaWindows <= 1000, 'ua windows are capped');
  assert.ok(sizes.quarantined <= 1000, 'the quarantine map is capped');
});

test('the shield reports what it is holding, so an operator can see it working', () => {
  fresh();
  hit('198.51.100.11', '/', BROWSER, { activeConnections: 3, inFlight: 1 });
  const st = botshield.stats();
  assert.ok(st.thresholds.maxConcurrentPerAddress > 0);
  assert.ok(st.thresholds.fanoutAddressesPerMinute > 0);
  assert.ok(st.thresholds.crawlerBudgetPerMinute > 0);
  assert.equal(typeof st.stateSizes.concurrentAddresses, 'number');
});

test('the public stats mask addresses, the operator key uncovers them', () => {
  fresh({ maxAttempts: 1, quarantineMs: 600000 });
  hit('203.0.113.77', '/', BOT, { activeConnections: 5, inFlight: 1 });
  hit('203.0.113.77', '/', BOT, { activeConnections: 5, inFlight: 1 });   // quarantined
  const anon = botshield.stats(false);
  const operator = botshield.stats(true);
  assert.equal(anon.quarantinedIps[0].ip, '203.0.*.*', 'the host part is not public');
  assert.equal(operator.quarantinedIps[0].ip, '203.0.113.77', 'the operator sees the full address');
  assert.equal(anon.topOffenders[0].ip, '203.0.*.*');
});

test('capacity telemetry: the shield reports the sockets and rate the server measured', () => {
  fresh();
  hit('198.51.100.21', '/', BROWSER, { activeConnections: 42, inFlight: 7, reqRate: 180 });
  const h = botshield.stats().health;
  assert.equal(h.activeConnections, 42, 'open sockets reach the health block');
  assert.equal(h.inFlight, 7, 'requests being worked reach the health block');
  assert.equal(h.requestsPerMinute, 10800, 'req/s is reported per minute');

  // The numbers must survive a standing-down shield: the dashboard reads them
  // continuously, not only while the shield is engaged.
  fresh({ mode: 'off' });
  hit('198.51.100.21', '/', BROWSER, { activeConnections: 3, inFlight: 0, reqRate: 5 });
  const off = botshield.stats().health;
  assert.equal(off.activeConnections, 3, 'capacity is still recorded when the shield is off');
  assert.equal(off.requestsPerMinute, 300);
});

test('connection posture: idle sockets are reclaimed fast while engaged, generously when calm', () => {
  fresh();
  assert.equal(botshield.isEngaged(), false, 'calm traffic does not engage the shield');
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 5000, idleTimeoutMs: 20000, headersTimeoutMs: 10000, requestTimeoutMs: 30000 });

  fresh({ engageRps: 50 });
  hit('198.51.100.31', '/', BROWSER, { activeConnections: 300, inFlight: 40, reqRate: 200 });
  assert.equal(botshield.isEngaged(), true, 'load engages the shield');
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 2000, idleTimeoutMs: 8000, headersTimeoutMs: 6000, requestTimeoutMs: 15000 },
    'an engaged origin churns idle sockets instead of holding them open');

  fresh({ mode: 'off' });
  assert.equal(botshield.isEngaged(), false, 'off mode can never be engaged');
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 5000, idleTimeoutMs: 20000, headersTimeoutMs: 10000, requestTimeoutMs: 30000 },
    'a disabled shield keeps the generous timeouts');
});

test('the server applies the shield connection posture and caps requests per socket', () => {
  const httpServer = require('../server');
  assert.equal(httpServer.maxRequestsPerSocket, 100, 'a keep-alive socket is not an endless pipeline');

  fresh();
  httpServer.applyConnectionPosture();
  assert.equal(httpServer.keepAliveTimeout, 5000, 'calm origin keeps its keep-alive window');

  fresh({ engageRps: 50, mode: 'always' });
  hit('198.51.100.41', '/', BROWSER, { activeConnections: 500, inFlight: 60, reqRate: 400 });
  httpServer.applyConnectionPosture();
  assert.equal(httpServer.keepAliveTimeout, 2000, 'an engaged origin tightens keep-alive');
  assert.equal(httpServer.headersTimeout, 6000, 'an engaged origin gives a half-sent header less room');
  assert.equal(httpServer.requestTimeout, 15000, 'an engaged origin stops waiting for slow bodies');

  fresh({ mode: 'off' });
  httpServer.applyConnectionPosture();
  assert.equal(httpServer.keepAliveTimeout, 5000, 'the posture is restored when the shield stands down');
  assert.equal(httpServer.requestTimeout, 30000, 'a calm origin is patient again');
});

test('a quarantined address is refused if it scripts, challenged if it looks like a browser', () => {
  fresh({ engageRps: 100, maxAttempts: 2, quarantineMs: 60000, maxDifficulty: 10, ipBudget: 10 });
  const ip = '203.0.113.9';
  const cap = { reqRate: 400, activeConnections: 60, inFlight: 4 };

  hit(ip, '/', BOT, cap);
  hit(ip, '/', BOT, cap);
  hit(ip, '/', BOT, cap);                       // third attempt burns the budget
  assert.ok(botshield.stats(false).counters.quarantined >= 1, 'the address must be quarantined');

  const scripted = hit(ip, '/', BOT, cap);
  assert.equal(scripted.headers['X-OBSX-BotShield'], 'quarantine', 'a scripted client stays refused');

  const browser = hit(ip, '/', BROWSER, cap);
  assert.equal(browser.status, 403, 'the browser is not served yet');
  assert.equal(browser.headers['X-OBSX-BotShield'], 'challenge', 'but it is offered a way back in');

  const { cid, challenge, bits } = parseChallenge(browser.body);
  assert.equal(bits, 10, 'the escape puzzle is the hardest one, not the calm one');
  const nonce = solve(challenge, bits);
  const answered = hit(ip, `/?__bs=${cid}&__bn=${nonce}`, BROWSER, cap);
  assert.equal(answered.status, 302, 'doing the work clears the quarantine');
  const cookie = (answered.headers['Set-Cookie'] || '').split(';')[0];
  assert.match(cookie, /obsx_bs=/, 'verification must hand back a cookie');
  const served = hit(ip, '/', BROWSER, cap, cookie);
  assert.equal(served.handled, false, 'the verified client is served again');
  assert.equal(botshield.stats(false).counters.solved, 1, 'the solve is counted');
});

test('quarantine escape can be switched off for a hardened node', () => {
  fresh({ engageRps: 100, maxAttempts: 2, quarantineMs: 60000, quarantineEscape: false });
  const ip = '203.0.113.10';
  const cap = { reqRate: 400, activeConnections: 60, inFlight: 4 };
  hit(ip, '/', BOT, cap); hit(ip, '/', BOT, cap); hit(ip, '/', BOT, cap);
  const browser = hit(ip, '/', BROWSER, cap);
  assert.equal(browser.headers['X-OBSX-BotShield'], 'quarantine', 'with the escape disabled, everyone is refused');
});

test('a swarm of quiet addresses is caught by fan-out counting, not by per-IP budgets', () => {
  fresh({ engageRps: 5000, fanoutIpsPerMin: 200, baseDifficulty: 8, maxDifficulty: 12,
    ipBudget: 5000, subnetBudget: 100000, uaFleetBudget: 100000 });
  const cap = { reqRate: 60, activeConnections: 40, inFlight: 2 };
  for (let i = 0; i < 250; i++) hit(`198.51.100.${i + 1}`, '/', BOT, cap);
  const st = botshield.stats(false);
  assert.ok(st.engaged, 'fan-out alone must engage the shield even at 60 req/s');
  assert.ok(st.counters.fanoutDetected >= 1, 'the swarm is recorded as an attack');
  assert.equal(st.difficultyBits, 12, 'a swarm gets the hardest puzzle immediately');
  assert.ok(st.counters.distinctIps >= 200, 'distinct addresses are counted per window');
});

/* ---------------- fan-out by range, path guards, answer budget ------------ */

test('a fleet that rotates /24s is caught by subnet fan-out, not by per-IP rules', () => {
  fresh({ engageRps: 100000, disengageRps: 0, fanoutIpsPerMin: 100000, fanoutSubnetsPerMin: 120,
    ipBudget: 5000, subnetBudget: 100000, uaFleetBudget: 100000, subnetQuarantinePerMin: 100000,
    baseDifficulty: 8, maxDifficulty: 12 });
  const cap = { reqRate: 30, activeConnections: 20, inFlight: 1 };
  for (let i = 0; i < 150; i++) hit(`203.0.${i}.100.1`, '/', BOT, cap);
  const st = botshield.stats(false);
  assert.ok(st.engaged, 'rotating ranges engage the shield even at 30 req/s');
  assert.ok(st.attack.distinctSubnets >= 120, 'the ranges are counted as a fleet');
  assert.equal(st.difficultyBits, 12, 'a range-rotating fleet gets the hardest puzzle');
});

test('an absurdly long request path is refused before any application work', () => {
  fresh({ engageRps: 100000 });
  const long = '/' + 'a'.repeat(400);
  const r = hit('203.0.113.150', long, BROWSER, { reqRate: 5 });
  assert.equal(r.status, 400, 'path-fuzz requests are closed with 400, not rendered');
  assert.ok(botshield.stats(false).counters.byTier.path >= 1);
  const normal = hit('203.0.113.150', '/' + 'a'.repeat(200), BROWSER, { reqRate: 5 });
  assert.equal(normal.status, 0, 'a normal-length path is allowed through');
});

test('unsupported HTTP methods are refused by the shield', () => {
  fresh({ engageRps: 100000 });
  const r = hit('203.0.113.151', '/', BROWSER, { reqRate: 5 }, '', 'TRACE');
  assert.equal(r.status, 405);
  assert.ok(botshield.stats(false).counters.byTier.method >= 1);
});

test('guessing challenge answers is charged to the attempt budget and ends in quarantine', () => {
  fresh({ engageRps: 100000, disengageRps: 0, maxAttempts: 3, quarantineMs: 60000,
    baseDifficulty: 4, maxDifficulty: 6, ipBudget: 10000, uaFleetBudget: 100000,
    subnetBudget: 100000, subnetQuarantinePerMin: 100000 });
  const ip = '203.0.113.200';
  const cap = { reqRate: 10, activeConnections: 10, inFlight: 1 };
  const first = hit(ip, '/', BOT, cap);
  const m = /var cid = "([^"]+)", challenge = "([^"]+)", bits = (\d+)/.exec(first.body);
  assert.ok(m, 'a challenge page is served first');
  const cid = m[1];
  // Pick nonces that are provably wrong for this challenge: a small integer can
  // luckily satisfy a six-bit puzzle, which would make the test flaky.
  const guesses = [];
  for (let i = 0; i < 500 && guesses.length < 6; i++) {
    if (!botshield.powOk(m[2], String(i), Number(m[3]))) guesses.push(i);
  }
  for (const i of guesses) {
    const bad = hit(ip, '/?__bs=' + cid + '&__bn=' + i, BOT, cap);
    assert.ok(bad.status === 403, 'a wrong answer is refused (got ' + bad.status + ': ' + bad.body.slice(0, 60) + ')');
  }
  const st = botshield.stats(false);
  assert.ok(st.counters.quarantined >= 1, 'answer guessing gets the address quarantined');
});

test('the quarantine escape hatch is capped so it cannot be abused', () => {
  fresh({ engageRps: 100000, disengageRps: 0, maxAttempts: 2, escapeMaxAttempts: 5,
    quarantineMs: 120000, baseDifficulty: 4, maxDifficulty: 6,
    ipBudget: 10000, uaFleetBudget: 100000, subnetBudget: 100000, subnetQuarantinePerMin: 100000 });
  const ip = '203.0.113.201';
  const cap = { reqRate: 10, activeConnections: 10, inFlight: 1 };
  for (let i = 0; i < 3; i++) hit(ip, '/', BOT, cap);   // scripted client -> quarantined
  const b1 = hit(ip, '/', BROWSER, cap);
  const b2 = hit(ip, '/', BROWSER, cap);
  const b3 = hit(ip, '/', BROWSER, cap);
  assert.ok(b1.body.includes('proof-of-work'), 'a quarantined browser is offered the hardest puzzle');
  assert.ok(b2.body.includes('proof-of-work'), 'it may try again');
  assert.ok(b3.body.includes('bot_blocked'), 'the escape hatch closes after enough tries');
});

test('deep saturation tells clients to back off for thirty seconds, not five', () => {
  fresh({ engageRps: 100, disengageRps: 0, maxInFlight: 10, hardConnCeiling: 600, maxActiveConnections: 300 });
  const light = hit('203.0.113.202', '/', BROWSER, { reqRate: 200, activeConnections: 100, inFlight: 12 });
  assert.equal(light.status, 503);
  assert.equal(light.headers['Retry-After'], '5');
  const deep = hit('203.0.113.203', '/', BROWSER, { reqRate: 200, activeConnections: 1300, inFlight: 60 });
  assert.equal(deep.status, 503);
  assert.equal(deep.headers['Retry-After'], '30', 'a drowning origin asks for a real pause');
});

test('per-address in-flight counts are released when the request finishes', () => {
  fresh({ engageRps: 100000, disengageRps: 0, maxConcurrentPerIp: 3, ipBudget: 10000,
    calmBudget: 10000, uaFleetBudget: 100000, subnetBudget: 100000, subnetQuarantinePerMin: 100000 });
  const ip = '203.0.113.204';
  const cap = { reqRate: 10, activeConnections: 10, inFlight: 1 };
  for (let i = 0; i < 3; i++) {
    const r = hit(ip, '/', BROWSER, cap);
    assert.equal(r.handled, false, 'the first three requests are served');
  }
  const fourth = hit(ip, '/', BROWSER, cap);
  assert.equal(fourth.status, 429, 'the fourth parallel request from one address is refused');
  for (let i = 0; i < 3; i++) botshield.noteWorkLatency(5, ip);
  const fifth = hit(ip, '/', BROWSER, cap);
  assert.equal(fifth.handled, false, 'the address is free again once its requests are done');
});

test('the stats expose an attack signature an operator can read', () => {
  fresh({ engageRps: 120, disengageRps: 0 });
  hit('203.0.113.205', '/', BROWSER, { reqRate: 400, activeConnections: 50, inFlight: 5 });
  const st = botshield.stats(false);
  assert.equal(st.attack.peakReqRate, 400);
  assert.ok(st.attack.engagedSeconds >= 0);
  assert.ok(typeof st.attack.refusedRatio === 'number');
  assert.ok(!Object.values(st.topOffenders).some((o) => o.ip.split('.').length === 4 && !o.ip.includes('*')),
    'anonymous stats never publish a full offender address');
});

test('a path-fuzz flood closes unseen paths without routing them', () => {
  fresh({ engageRps: 4000, fanoutPathsPerMin: 50, maxAttempts: 200 });
  for (let i = 0; i < 60; i++) hit('203.0.113.' + (i % 250), '/p' + i, 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.strictEqual(botshield.stats().attack.pathFuzz, true, 'the flood was recognised');
  const fuzz = hit('198.51.100.9', '/never-seen-61', 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.strictEqual(fuzz.status, 404, 'a brand new path is closed without routing');
  assert.ok(fuzz.body.includes('not_found'));
  assert.ok(botshield.stats().counters.byTier.pathFuzz > 0);
  // a path already seen keeps going through the normal tiers
  const repeat = hit('198.51.100.9', '/p1', 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.notStrictEqual(repeat.status, 404);
});

test('a puzzle that real browsers take too long to solve is eased back to base', () => {
  const slowBrowser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
  const cap = { reqRate: 900, activeConnections: 40, inFlight: 2 };
  fresh({ engageRps: 120, baseDifficulty: 12, maxDifficulty: 16, maxSolveMs: 3000,
    ipBudget: 10000, calmBudget: 10000, maxAttempts: 50 });
  for (let i = 0; i < 3; i++) hit('203.0.113.7', '/', slowBrowser, cap);
  assert.ok(botshield.stats().difficultyBits > 12, 'difficulty ramps with pressure');
  const page = hit('203.0.113.7', '/', slowBrowser, cap);
  assert.equal(page.status, 403, 'the client is challenged (got ' + page.status + ')');
  const ch = parseChallenge(page.body);
  const answer = hit('203.0.113.7', `/?__bs=${ch.cid}&__bn=${solve(ch.challenge, ch.bits)}&__ms=9000`, slowBrowser, cap);
  assert.ok(answer.headers['Set-Cookie'], 'the slow browser is still let through');
  assert.strictEqual(botshield.stats().difficultyBits, 12, 'difficulty drops back to base for real, struggling users');
});

test('a reported solve time out of range is ignored', () => {
  fresh({ engageRps: 120, baseDifficulty: 12, maxDifficulty: 22 });
  const cap = { reqRate: 400, activeConnections: 20, inFlight: 1 };
  const page = hit('198.51.100.30', '/', BOT, cap);
  const ch = parseChallenge(page.body);
  const answer = hit('198.51.100.30', `/?__bs=${ch.cid}&__bn=${solve(ch.challenge, ch.bits)}&__ms=999999999`, BOT, cap);
  assert.strictEqual(botshield.stats().attack.browserSolveMs, 0, 'an absurd reported time is not trusted (got ' + botshield.stats().attack.browserSolveMs + ', status ' + answer.status + ')');
});

test('the path guard stands down when the flood stops', () => {
  fresh({ engageRps: 4000, fanoutPathsPerMin: 50, maxAttempts: 200 });
  for (let i = 0; i < 60; i++) hit('203.0.113.1', '/q' + i, 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.strictEqual(botshield.stats().attack.pathFuzz, true, 'the flood was recognised');
  botshield.reset();
  hit('203.0.113.1', '/q1', 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  const normal = hit('203.0.113.1', '/brand-new-page', 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.notStrictEqual(normal.status, 404, 'a new page is not closed after the flood is over (got ' + normal.status + ')');
  assert.strictEqual(botshield.stats().attack.pathFuzz, false);
});

test('an oversized request body is refused before any parsing', () => {
  fresh({ engageRps: 5000, maxBodyBytes: 1000 });
  const res = fakeRes();
  const url = new URL('/api/v1/session', 'http://obsx.tech');
  const outcome = botshield.evaluate(
    { headers: { 'user-agent': BROWSER, 'content-length': '2000000' }, method: 'POST' },
    res, '203.0.113.50', url.pathname, 5000, url, { reqRate: 5000, activeConnections: 10, inFlight: 1 });
  assert.strictEqual(outcome.handled, true, 'the shield answered, the application never ran');
  assert.strictEqual(res.out.status, 413, 'a 2 MB body is refused (got ' + res.out.status + ')');
  assert.ok(res.out.body.includes('payload_too_large'));
  assert.strictEqual(botshield.stats().counters.byTier.body, 1);
  // a body within the limit is not caught by this rule; it is still judged by
  // the normal tiers (challenge/budget), never by the size gate.
  const res2 = fakeRes();
  const url2 = new URL('/api/v1/session', 'http://obsx.tech');
  botshield.evaluate(
    { headers: { 'user-agent': BROWSER, 'content-length': '900' }, method: 'POST' },
    res2, '203.0.113.51', url2.pathname, 5000, url2, { reqRate: 5000, activeConnections: 10, inFlight: 1 });
  assert.notStrictEqual(res2.out.status, 413, 'a 900-byte POST is not refused for size (got ' + res2.out.status + ')');
});

test('the shield serves its own telemetry while under attack', () => {
  fresh({ engageRps: 400, ipBudget: 30, maxAttempts: 6, statusBudget: 40 });
  for (let i = 0; i < 40; i++) hit('203.0.113.60', '/', BOT, { reqRate: 500, activeConnections: 20, inFlight: 2 });
  const out = hit('203.0.113.60', '/api/v1/bot-protection', BOT, { reqRate: 500, activeConnections: 20, inFlight: 2 });
  assert.strictEqual(out.status, 200, 'telemetry is readable even with the shield at maximum defence (got ' + out.status + ')');
  assert.strictEqual(out.handled, true, 'answered inside the shield, not by the application layer');
  const json = JSON.parse(out.body);
  assert.strictEqual(json.ok, true);
  assert.ok(json.attack.distinctAddresses >= 0, 'attack signature present');
  assert.ok(json.topOffenders.length > 0, 'the offenders are visible to the operator');
  assert.ok(json.topOffenders[0].ip.includes('*'), 'anonymous view masks addresses (got ' + json.topOffenders[0].ip + ')');
  assert.ok(out.headers['X-OBSX-BotShield'] === 'telemetry');
});

test('the telemetry endpoint is budgeted like any other status path', () => {
  fresh({ engageRps: 400, statusBudget: 3 });
  const cap = { reqRate: 500, activeConnections: 20, inFlight: 1 };
  const first = hit('203.0.113.70', '/api/v1/bot-protection', BOT, cap);
  const second = hit('203.0.113.70', '/api/v1/bot-protection', BOT, cap);
  const third = hit('203.0.113.70', '/api/v1/bot-protection', BOT, cap);
  const fourth = hit('203.0.113.70', '/api/v1/bot-protection', BOT, cap);
  assert.strictEqual(first.status, 200);
  assert.strictEqual(second.status, 200);
  assert.strictEqual(third.status, 200);
  assert.strictEqual(fourth.status, 429, 'the monitoring endpoint cannot itself become the flood path');
});

test('the telemetry walk does not copy the whole offender table', () => {
  fresh({ engageRps: 120, maxAttempts: 3, quarantineMs: 300000 });
  for (let i = 0; i < 60; i++) hit('203.0.113.' + (i + 1), '/', BOT, { reqRate: 300, activeConnections: 10, inFlight: 1 });
  const st = botshield.stats(false);
  assert.ok(st.stateSizes.offenders > st.topOffenders.length, 'top offenders are a slice, not the whole map');
  assert.ok(st.quarantinedIps.length <= 20, 'the quarantined list is capped');
  assert.ok(st.topOffenders.length === 10);
});

test('the shield stands down on its own when the origin goes quiet', () => {
  fresh({ engageRps: 100, disengageRps: 40, calmMs: 45000, ipBudget: 10000, maxAttempts: 20 });
  const cap = { reqRate: 500, activeConnections: 30, inFlight: 2 };
  for (let i = 0; i < 20; i++) hit('203.0.113.80', '/', BOT, cap);
  assert.strictEqual(botshield.isEngaged(), true, 'the flood engaged the shield');
  // a shield that has only just gone quiet is still defending
  assert.strictEqual(botshield.checkIdle(Date.now() - 1000), false);
  assert.strictEqual(botshield.isEngaged(), true);
  // sixty seconds of silence, no requests at all: the heartbeat releases it
  botshield.checkIdle(Date.now() + 46000);
  assert.strictEqual(botshield.isEngaged(), false, 'engagement cannot outlive the flood');
  const page = hit('203.0.113.81', '/', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36', { reqRate: 12, activeConnections: 3, inFlight: 1 });
  assert.notStrictEqual(page.status, 403, 'the next real visitor is not challenged (got ' + page.status + ')');
});

test('an idle check releases the path guard so new pages are not 404 forever', () => {
  fresh({ engageRps: 4000, fanoutPathsPerMin: 50, maxAttempts: 200 });
  for (let i = 0; i < 60; i++) hit('203.0.113.90', '/z' + i, 'curl/8.0.1', { reqRate: 4000, activeConnections: 20, inFlight: 1 });
  assert.strictEqual(botshield.stats().attack.pathFuzz, true, 'the flood closed unseen paths');
  botshield.checkIdle(Date.now() + 61000);
  const st = botshield.stats();
  assert.strictEqual(st.attack.pathFuzz, false, 'a quiet origin releases the guard without a single request');
  assert.strictEqual(st.attack.distinctPaths, 0);
  assert.strictEqual(st.attack.fanout, false);
});

test('a socket refused at the TCP level is still counted by the shield', () => {
  fresh({ engageRps: 100 });
  for (let i = 0; i < 7; i++) botshield.noteSocketShed('203.0.113.' + (i % 3), 'hard_conn_ceiling');
  const st = botshield.stats(false);
  assert.strictEqual(st.counters.shed, 7, 'socket-level refusals show up in the shed counter');
  assert.strictEqual(st.counters.byTier.capacity, 7);
  assert.ok(st.topOffenders[0].hits >= 2, 'the worst socket offender is visible without scanning the whole table');
});

test('a trickle of ordinary traffic is enough to stand the shield down', () => {
  fresh({ engageRps: 100, disengageRps: 40, calmMs: 45000, ipBudget: 100000, calmBudget: 100000, maxServedRps: 100000, maxAttempts: 50 });
  const storm = { reqRate: 600, activeConnections: 60, inFlight: 3 };
  for (let i = 0; i < 30; i++) hit('203.0.113.95', '/', BOT, storm);
  assert.strictEqual(botshield.isEngaged(), true, 'the storm engaged the shield');
  // a normal site: a few requests a second, never silent, never alarming
  let now = Date.now();
  for (let i = 0; i < 40; i++) hit('198.51.100.' + (i % 250), '/', BROWSER, { reqRate: 20, activeConnections: 5, inFlight: 1 });
  botshield.checkIdle(now + 30000);
  assert.strictEqual(botshield.isEngaged(), true, 'thirty seconds of calm is not yet a stand-down');
  botshield.checkIdle(now + 90000);
  assert.strictEqual(botshield.isEngaged(), false, 'a minute of ordinary traffic releases the shield');
  assert.ok(botshield.stats().attack.engagedSeconds >= 0);
});
