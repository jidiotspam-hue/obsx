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

function makeReq(ua, cookie = '', extra = null) {
  const headers = { 'user-agent': ua, cookie };
  // Real browsers negotiate content and language. The shield uses that as
  // evidence that the user agent string is not just copied from Chrome.
  if (extra === null) {
    headers.accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
    headers['accept-language'] = 'en-US,en;q=0.9';
  } else {
    Object.assign(headers, extra);
  }
  return { headers };
}

/** One request through the shield. Returns the outcome plus what the shield said. */
function hit(ip, pathname, ua, capacity, cookie = '') {
  const res = fakeRes();
  const url = new URL(pathname, 'http://obsx.tech');
  const outcome = botshield.evaluate(makeReq(ua, cookie), res, ip, url.pathname,
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
  maxActiveConnections: 300, maxInFlight: 100, maxServedRps: 150,
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
  fresh({ engageRps: 100000, disengageRps: 0, ipBudget: 500, calmBudget: 100000, uaFleetBudget: 100000, subnetBudget: 100000, subnetQuarantinePerMin: 100000, fanoutIpsPerMin: 300 });
  for (let i = 0; i < 400; i++) {
    hit('203.0.113.' + (i % 250) + '', '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
    hit('198.51.100.' + (i % 250), '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
    hit('192.0.2.' + (i % 250), '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
  }
  assert.ok(botshield.stats().engaged, 'fan-out alone engaged the shield');
  assert.ok(botshield.stats().counters.distinctIps >= 300, 'distinct addresses were counted');
  const r = hit('198.51.100.123', '/', BROWSER, { activeConnections: 40, inFlight: 2, reqRate: 5 });
  assert.equal(r.status, 403, 'while engaged, an unproven client is challenged');
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
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 5000, idleTimeoutMs: 20000 });

  fresh({ engageRps: 50 });
  hit('198.51.100.31', '/', BROWSER, { activeConnections: 300, inFlight: 40, reqRate: 200 });
  assert.equal(botshield.isEngaged(), true, 'load engages the shield');
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 2000, idleTimeoutMs: 8000 },
    'an engaged origin churns idle sockets instead of holding them open');

  fresh({ mode: 'off' });
  assert.equal(botshield.isEngaged(), false, 'off mode can never be engaged');
  assert.deepEqual(botshield.connectionPosture(), { keepAliveTimeoutMs: 5000, idleTimeoutMs: 20000 },
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

  fresh({ mode: 'off' });
  httpServer.applyConnectionPosture();
  assert.equal(httpServer.keepAliveTimeout, 5000, 'the posture is restored when the shield stands down');
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
