'use strict';

/*
 * OBSX Bot Protection — the origin shield.
 *
 * A flood is a capacity problem, so the shield has to cost less to run than the
 * attack costs to send. Every rule here is O(1): a Map lookup, a 32-bit hash, a
 * string slice. The expensive Security Gate (PoW + HMAC + telemetry scoring)
 * only ever sees traffic the shield has already cleared.
 *
 * Tiers, cheapest first:
 *   0. self-monitoring     — the shield watches its own RSS, event-loop lag,
 *                           in-flight count and served rate, and refuses before
 *                           the origin starts dying.
 *   1. connection ceiling  — sockets refused before parsing (server.js)
 *   2. quarantine          — repeat offenders refused from a Map hit
 *   3. proof of work       — a browser proves it is a browser, once per 15 min
 *   4. budgets             — per-IP, per-subnet and per-user-agent-class
 *   5. capacity shed       — 503 + Retry-After when the origin is saturated
 *
 * The shield engages automatically when traffic climbs and stands down when it
 * settles, so a normal visitor never sees a challenge.
 *
 * Why subnets and user-agent classes matter: a modern botnet does not hammer
 * from one address. It rotates across thousands of IPs, each sending a handful
 * of requests, so a per-IP rule never trips. The subnet (/24 or /64) and UA-class
 * budgets catch the fleet even when every individual address looks polite.
 */

const crypto = require('./crypto');

function envInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
}

const CFG = {
  // Unit tests must opt in: a shield that silently engages during unrelated
  // request tests makes those tests fail for reasons they do not understand.
  // The suite must not be gated by the shield it is not testing: in test mode
  // the shield starts off and a test turns it on when it wants it. Production
  // keeps the .env value.
  enabled: process.env.OBSX_TEST_MODE === '1'
    ? process.env.OBSX_BOT_PROTECTION === 'force'
    : (process.env.OBSX_BOT_PROTECTION || 'true') !== 'false',
  mode: (process.env.OBSX_BOT_MODE || 'auto').toLowerCase(),   // auto | always | off

  engageRps: envInt('OBSX_SHIELD_RPS', 120),
  disengageRps: envInt('OBSX_SHIELD_OFF_RPS', 40),
  calmMs: envInt('OBSX_SHIELD_CALM_MS', 45000),

  baseDifficulty: Math.min(24, Math.max(8, envInt('OBSX_BOT_DIFFICULTY', 16))),
  maxDifficulty: Math.min(24, envInt('OBSX_BOT_MAX_DIFFICULTY', 22)),

  verifyTtlMs: envInt('OBSX_BOT_TTL', 900000),           // 15 minutes of free passage
  challengeTtlMs: envInt('OBSX_BOT_CHALLENGE_TTL', 120000),
  maxAttempts: envInt('OBSX_BOT_MAX_ATTEMPTS', 6),       // unsolved -> quarantine
  quarantineMs: envInt('OBSX_BOT_QUARANTINE_MS', 300000),
  quarantineEscape: envInt('OBSX_QUARANTINE_ESCAPE', 1) !== 0,  // quarantined browsers may work out of it

  ipBudget: envInt('OBSX_IP_BUDGET', 60),                // unverified req/min
  crawlerBudget: envInt('OBSX_CRAWLER_BUDGET', 240),     // search-engine req/min
  maxConnsPerIp: envInt('OBSX_MAX_CONNS_PER_IP', 120),   // sockets one address may hold
  verifiedBudget: envInt('OBSX_VERIFIED_BUDGET', 600),   // verified req/min
  calmBudget: envInt('OBSX_CALM_BUDGET', 400),           // idle, shield not engaged
  statusBudget: envInt('OBSX_STATUS_BUDGET', 40),        // health/status req/min
  subnetBudget: envInt('OBSX_SUBNET_BUDGET', 900),       // req/min per /24 or /64
  subnetQuarantinePerMin: envInt('OBSX_SUBNET_QUARANTINE', 2400),
  uaFleetBudget: envInt('OBSX_UA_FLEET_BUDGET', 1500),   // req/min per UA class
  maxConcurrentPerIp: envInt('OBSX_MAX_CONCURRENT_PER_IP', 25),  // requests in flight from one address
  fanoutIpsPerMin: envInt('OBSX_FANOUT_IPS', 400),       // distinct addresses/min that counts as a botnet
  fanoutSubnetsPerMin: envInt('OBSX_FANOUT_SUBNETS', 120), // distinct /24s/min: rotating botnets change range, not just address
  maxPathLen: envInt('OBSX_MAX_PATH_LEN', 256),           // path-fuzz floods defeat caches and blow up maps
  fanoutPathsPerMin: envInt('OBSX_FANOUT_PATHS', 800),    // distinct paths/min: a path-fuzz flood defeats every cache
  maxSolveMs: envInt('OBSX_BOT_MAX_SOLVE_MS', 3000),      // if real browsers need longer than this, make the puzzle easier
  escapeMaxAttempts: envInt('OBSX_QUARANTINE_ESCAPE_ATTEMPTS', 12),

  hardConnCeiling: envInt('OBSX_HARD_CONN_CEILING', 600),
  maxActiveConnections: envInt('OBSX_MAX_CONNS', 300),
  maxInFlight: envInt('OBSX_MAX_INFLIGHT', 100),
  maxServedRps: envInt('OBSX_MAX_SERVED_RPS', 150),
  maxWorkLatencyMs: envInt('OBSX_MAX_WORK_LATENCY', 250),
  maxRssMb: envInt('OBSX_MAX_RSS_MB', 620),
  maxEventLagMs: envInt('OBSX_MAX_EVENT_LAG_MS', 200),

  maxMapSize: envInt('OBSX_SHIELD_MAP_SIZE', 20000),
  maxBodyBytes: envInt('OBSX_MAX_BODY_BYTES', 512 * 1024),   // request bodies above this are refused before routing
};

// Known search engines: they are not the threat, and blocking them costs the
// site its index. They get a generous budget but never a JavaScript challenge.
const CRAWLER_UA_RE = /(googlebot|bingbot|duckduckbot|baiduspider|yandexbot|applebot|petalbot|seznambot)/i;

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);

const SCRIPTED_UA_RE = /(python-requests|python-urllib|aiohttp|httpx|curl\/|wget|go-http-client|okhttp|java\/|scrapy|node-fetch|headlesschrome|phantomjs|selenium|puppeteer|httpclient|libcurl|lua-requests|deno\/|\bperl\b|nikbot|masscan|zmap)/i;

/* ------------------------------------------------------------------ state */

const verified = new Map();        // token -> { expires, ip }
const pending = new Map();         // cid -> { challenge, bits, expires }
const blocked = new Map();         // ip -> until
const blockedSubnets = new Map();  // subnet -> until
const attempts = new Map();        // ip -> { count, reset }
const usage = new Map();           // ip -> { count, ips, windowStart }
const subnetUsage = new Map();     // subnet -> { count, ips, windowStart }
const uaUsage = new Map();         // uaHash -> { count, ips, windowStart }
const offenders = new Map();       // ip -> { ip, hits, first, last, reason }
const strikes = new Map();         // ip -> number of quarantines (escalating)
const inflightByIp = new Map();    // ip -> requests of this address currently being worked
const seenWindow = new Set();        // distinct addresses in the current 60 s window (fan-out detection)
const seenSubnets = new Set();       // distinct /24s or /64s in the same window: a fleet that rotates ranges
const pathUsage = new Map();         // path -> requests in the current minute (path-fuzz detection)

const counters = {
  requests: 0,
  challenged: 0,
  solved: 0,
  passed: 0,
  servedRequests: 0,
  blocked: 0,
  quarantined: 0,
  quarantinedSubnets: 0,
  shed: 0,
  distinctIps: 0,        // distinct addresses seen in the last minute
  distinctSubnets: 0,    // distinct subnets seen in the last minute
  distinctPaths: 0,      // distinct paths seen in the last minute
  fanoutDetected: 0,
  peakReqRate: 0,        // highest sustained req/s the shield has seen
  lastRequest: 0,
  byTier: {
    capacity: 0,        // refused: the origin is saturated
    quarantine: 0,      // refused: in quarantine
    ua: 0,              // challenged: scripted/headless client
    under_attack: 0,    // refused: asset/API hit while the shield is engaged
    fleet: 0,           // refused: user-agent class behaving like a botnet
    subnet: 0,          // refused: the whole subnet is hammering
    budget: 0,          // refused: per-IP budget exhausted
    crawler: 0,         // refused: search engine over its budget
    spoofed: 0,        // challenged: browser user agent, no browser headers
    concurrent: 0,     // refused: one address holding too many requests open
    fanout: 0,         // engaged: many distinct addresses, each polite
    path: 0,           // refused: absurdly long request path
    pathFuzz: 0,       // refused: a new unique path during a path-fuzz flood
    method: 0,         // refused: unsupported HTTP method
    body: 0,           // refused: request body larger than the API accepts
  },
};

const state = { engaged: false, engagedSince: 0, calmSince: 0, engagements: 0, distinctWindowStart: Date.now(), fanout: false, lastRequestAt: 0, minuteWindowStart: Date.now(), minuteWindowCount: 0 };

// Self-monitoring, sampled on heartbeats, never inside the request path.
const health = {
  rssMb: 0,
  eventLagMs: 0,
  lagStreak: 0,
  servedRate: 0,
  servedWindowStart: Date.now(),
  servedWindowCount: 0,
  workLatencyEma: 0,
  requestRate: 0,
  solveTimeEma: 0,      // how long real browsers report spending on the puzzle
  activeConnections: 0,   // last reported by server.js through evaluate()
  inFlight: 0,
  requestsPerMinute: 0,
};

let lastTick = Date.now();
let lastRssSample = 0;
let lagTimer = null;
let rssTimer = null;

// Cheap, lazy RSS sample: at most one per two seconds, taken on the request
// path rather than on a timer, so the memory guard works even when the
// heartbeats are disabled (tests).
function sampleMemory() {
  const now = Date.now();
  if (now - lastRssSample < 2000) return;
  lastRssSample = now;
  health.rssMb = Math.round((process.memoryUsage().rss || 0) / 1048576);
}

let idleTick = 0;

function startMonitors() {
  if (lagTimer) return;
  lastTick = Date.now();
  // Event-loop lag: if a 100 ms heartbeat lands late, the loop is backed up and
  // the next request will be slow no matter what it is.
  lagTimer = setInterval(() => {
    const now = Date.now();
    const lag = now - lastTick - 100;
    lastTick = now;
    if (lag > CFG.maxEventLagMs / 2) {
      health.lagStreak++;
      health.eventLagMs = Math.min(5000, lag);
    } else {
      health.lagStreak = 0;
      health.eventLagMs = Math.max(0, health.eventLagMs - 50);
    }
    if (now - health.servedWindowStart >= 1000) {
      health.servedRate = Math.round(health.servedWindowCount * 1000 / (now - health.servedWindowStart));
      health.servedWindowStart = now;
      health.servedWindowCount = 0;
    }
    idleTick++;
    if (idleTick >= 50) { idleTick = 0; checkIdle(now); }   // once a second
  }, 100);
  rssTimer = setInterval(sampleMemory, 2000);
}

function stopMonitors() {
  if (lagTimer) { clearInterval(lagTimer); lagTimer = null; }
  if (rssTimer) { clearInterval(rssTimer); rssTimer = null; }
}

if (process.env.OBSX_TEST_MODE !== '1') startMonitors();

/* ----------------------------------------------------------- primitives */

/** 32-bit FNV-1a: cheap in a browser loop, trivial to verify on the origin. */
function fnv1a(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function powOk(challenge, nonce, bits) {
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 32) return false;
  return (fnv1a(challenge + nonce) >>> (32 - bits)) === 0;
}

/**
 * Insert with a hard cap. A Map that grows unbounded under a spoofed-IP flood is
 * itself a DoS: 100k fake IPs at ~200 bytes each is 20 MB of state we never read.
 * Insertion order is oldest-first, so dropping the head is an acceptable LRU.
 */
function boundedSet(map, key, value) {
  if (map.size >= CFG.maxMapSize && !map.has(key)) map.delete(map.keys().next().value);
  map.set(key, value);
}

function subnetOf(ip) {
  if (ip.indexOf(':') >= 0) return ip.split(':').slice(0, 4).join(':') + '::/64';
  const p = ip.split('.');
  return p.length >= 4 ? p.slice(0, 3).join('.') + '.0/24' : ip;
}

/** Collapse a UA to a class so 40k Chrome-121 bots share one bucket. */
function uaClass(ua) {
  if (!ua) return 'none';
  return ua.toLowerCase().replace(/\d+/g, '').slice(0, 48);
}

function windowFor(map, key, windowMs) {
  const now = Date.now();
  let w = map.get(key);
  if (!w || now - w.windowStart >= windowMs) {
    w = { count: 0, ips: new Set(), windowStart: now };
    boundedSet(map, key, w);
  }
  return w;
}

/* ----------------------------------------------------------- socket posture */

/**
 * Is the shield working right now? `off` mode never engages, so the origin keeps
 * its generous keep-alive even if the flag was set earlier.
 */
function isEngaged() {
  return CFG.enabled && CFG.mode !== 'off' && state.engaged;
}

/**
 * How long the origin is willing to keep a socket idle. Calm: be generous, a real
 * browser reuses its connection. Engaged: a flood socket is worth less than the
 * file descriptor it burns, so half-open connections churn instead of sitting
 * open for twenty seconds. server.js applies this in its connection handler.
 */
function connectionPosture() {
  return isEngaged()
    ? { keepAliveTimeoutMs: 2000, idleTimeoutMs: 8000, headersTimeoutMs: 6000, requestTimeoutMs: 15000 }
    : { keepAliveTimeoutMs: 5000, idleTimeoutMs: 20000, headersTimeoutMs: 10000, requestTimeoutMs: 30000 };
}

/* ------------------------------------------------------- mode / engagement */

/** Difficulty rises with pressure: a calm origin is cheap, a shone one is not. */
/**
 * Difficulty is a moving target. Under fan-out it is the hardest puzzle we have.
 * Otherwise it ramps with rate - but if real browsers report spending longer than
 * maxSolveMs on it we fall back to the base. A challenge that locks out actual
 * visitors is not protection, it is an outage.
 */
function currentDifficulty(reqRate) {
  if (!state.engaged) return CFG.baseDifficulty;
  // A swarm of distinct addresses is a botnet even when every address is quiet,
  // so it gets the hardest puzzle immediately instead of the ramp.
  if (state.fanout) return CFG.maxDifficulty;
  if (health.solveTimeEma > CFG.maxSolveMs) return CFG.baseDifficulty;
  const ramp = Math.min(
    CFG.maxDifficulty - CFG.baseDifficulty,
    1 + Math.floor((reqRate || 0) / 250)
  );
  return Math.min(CFG.maxDifficulty, CFG.baseDifficulty + Math.max(1, ramp));
}

/**
 * A botnet is many addresses each sending a little. Per-IP budgets are useless
 * against it, so we count distinct addresses per minute: 400 different IPs in a
 * minute against a Raspberry Pi is an attack whatever each one is doing.
 */
function noteAddress(ip, subnet, now) {
  if (!seenWindow.has(ip) && seenWindow.size < CFG.maxMapSize) {
    seenWindow.add(ip);
    counters.distinctIps++;
  }
  if (!seenSubnets.has(subnet) && seenSubnets.size < CFG.maxMapSize) {
    seenSubnets.add(subnet);
    counters.distinctSubnets++;
  }
  if (!state.fanout && (counters.distinctIps >= CFG.fanoutIpsPerMin || counters.distinctSubnets >= CFG.fanoutSubnetsPerMin)) {
    state.fanout = true;
    counters.fanoutDetected++;
    console.log(`[OBSX BotShield] fan-out: ${counters.distinctIps} addresses across ${counters.distinctSubnets} subnets in one minute - botnet pattern, hardest puzzle`);
  }
  return true;
}


// Stand-down cannot depend on a request arriving: after a flood the heartbeat
// is the only thing still running, and a shield that stays engaged forever
// challenges the next real visitor for no reason.
function rollDistinctWindow(now) {
  if (now - state.distinctWindowStart < 60000) return;
  // A path guard that never clears turns every new page on the site into a 404.
  if (counters.distinctPaths < CFG.fanoutPathsPerMin) state.pathFuzz = false;
  state.distinctWindowStart = now;
  counters.distinctIps = 0;
  counters.distinctPaths = 0;
  counters.distinctSubnets = 0;
  state.fanout = false;
  pathUsage.clear();
  seenWindow.clear();
  seenSubnets.clear();
}

function checkIdle(now = Date.now()) {
  if (!CFG.enabled || CFG.mode === 'always') return false;
  if (!state.minuteWindowStart) { state.minuteWindowStart = now; state.minuteWindowCount = 0; }
  if (now - state.minuteWindowStart >= 60000) {
    state.minuteWindowStart = now;
    state.minuteWindowCount = 0;
  }
  const secs = Math.max(1, (now - state.minuteWindowStart) / 1000);
  const rate = state.minuteWindowCount / secs;
  health.quietRate = Math.round(rate);
  rollDistinctWindow(now);

  if (!state.engaged) return true;
  if (rate > CFG.disengageRps) { state.calmSince = 0; return false; }
  if (!state.calmSince) state.calmSince = now;
  if (now - state.calmSince >= CFG.calmMs) {
    state.engaged = false;
    state.calmSince = 0;
    console.log(`[OBSX BotShield] stood down: ${Math.round(rate)} req/s for ${Math.round(CFG.calmMs / 1000)}s`);
  }
  return state.engaged === false;
}

function noteSocketShed(ip, reason) {
  counters.shed++;
  counters.byTier.capacity++;
  noteOffender(ip, 'shed_' + reason);
}

function checkIdle(now = Date.now()) {
  if (!CFG.enabled || CFG.mode === 'always') return false;
  if (!state.lastRequestAt) return false;
  const quietFor = now - state.lastRequestAt;
  if (state.engaged && quietFor >= CFG.calmMs) {
    state.engaged = false;
    state.calmSince = 0;
    console.log(`[OBSX BotShield] stood down: no traffic for ${Math.round(quietFor / 1000)}s`);
  }
  if (quietFor >= 60000) {
    // A path guard that never clears turns every new page on the site into a 404.
    state.pathFuzz = false;
    state.fanout = false;
    counters.distinctPaths = 0;
    counters.distinctIps = 0;
    counters.distinctSubnets = 0;
    pathUsage.clear();
    seenWindow.clear();
    seenSubnets.clear();
    state.distinctWindowStart = now;
  }
  return state.engaged === false;
}

function updateMode(reqRate) {
  const now = Date.now();
  if (!CFG.enabled || CFG.mode === 'off') { state.engaged = false; return; }
  if (CFG.mode === 'always') { state.engaged = true; return; }

  if (reqRate > counters.peakReqRate) counters.peakReqRate = reqRate;

  // Three independent reasons to engage: raw rate, a fleet of distinct addresses,
  // or the origin's own work latency climbing - the Pi saying it is hurting before
  // the request count does.
  const pressure = reqRate >= CFG.engageRps
    || counters.distinctIps >= CFG.fanoutIpsPerMin
    || counters.distinctSubnets >= CFG.fanoutSubnetsPerMin
    || counters.distinctPaths >= CFG.fanoutPathsPerMin
    || (health.workLatencyEma >= CFG.maxWorkLatencyMs && counters.requests > 200);

  if (pressure) {
    if (!state.engaged) {
      state.engaged = true;
      state.engagedSince = now;
      state.engagements++;
      console.log(`[OBSX BotShield] engaged at ${reqRate} req/s (${counters.distinctIps} addresses across ${counters.distinctSubnets} subnets in the last minute)`);
    }
    if (counters.distinctPaths >= CFG.fanoutPathsPerMin && !state.pathFuzz) {
      state.pathFuzz = true;
      console.log(`[OBSX BotShield] path fuzz: ${counters.distinctPaths} unique paths in one minute - unseen paths closed without routing`);
    }
    state.calmSince = 0;
    return;
  }
  if (state.engaged) {
    if (reqRate <= CFG.disengageRps) {
      if (!state.calmSince) state.calmSince = now;
      if (now - state.calmSince >= CFG.calmMs) {
        state.engaged = false;
        state.calmSince = 0;
        console.log(`[OBSX BotShield] stood down at ${reqRate} req/s after ${Math.round((now - state.engagedSince) / 1000)}s engaged`);
      }
    } else {
      state.calmSince = 0;
    }
  }
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/**
 * A user agent string is a claim, not evidence. A real browser also sends an
 * Accept header and a language; a scripted client that copies a Chrome string
 * usually sends neither.
 */
function looksLikeBrowser(req, ua) {
  if (!ua) return false;
  if (SCRIPTED_UA_RE.test(ua)) return false;
  const h = req.headers || {};
  const accept = String(h.accept || '');
  return !!h['sec-fetch-mode'] || !!h['accept-language'] || /text\/html|\*\/\*/.test(accept);
}

function isHtmlPath(p) {
  if (p.startsWith('/api/')) return false;
  return p === '/' || p.endsWith('.html') || !/\.[a-z0-9]+$/i.test(p);
}

// Read-only status endpoints and the admin control surface are never worth
// challenging: refusing them hides the telemetry that tells us an attack is
// starting. They do get their own tight budget so they cannot become the flood
// path instead of /, which is how the November attack worked.
function isStatusPath(p) {
  return p === '/api/v1/health' || p.startsWith('/api/v1/bot-protection');
}

/* ------------------------------------------------------- responses */

/* Per-address in-flight tracking. Each entry carries its own timestamp so a
 * handler that dies without reporting back cannot keep an address permanently
 * marked "concurrent". */
function inflightOf(ip) {
  const v = inflightByIp.get(ip);
  return v ? v.n : 0;
}

function inflightInc(ip) {
  const now = Date.now();
  const v = inflightByIp.get(ip);
  if (v) { v.n++; v.at = now; }
  else boundedSet(inflightByIp, ip, { n: 1, at: now });
}

function inflightDec(ip) {
  const v = inflightByIp.get(ip);
  if (!v) return;
  v.n--;
  v.at = Date.now();
  if (v.n <= 0) inflightByIp.delete(ip);
}

function noteOffender(ip, reason) {
  const now = Date.now();
  let e = offenders.get(ip);
  if (!e) { e = { ip, hits: 0, first: now, reason }; boundedSet(offenders, ip, e); }
  e.hits++;
  e.last = now;
  e.reason = reason;
}

// Refusals are deliberately tiny and keep the connection open: reusing one
// socket costs the origin far less than accepting a new one per request.
function markServed(ip) {
  counters.passed++;
  counters.servedRequests++;
  health.servedWindowCount++;
  inflightInc(ip);
}

function refuse(res, reason, ip) {
  counters.blocked++;
  counters.byTier[reason] = (counters.byTier[reason] || 0) + 1;
  noteOffender(ip, reason);
  res.writeHead(403, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Retry-After': '120',
    'X-OBSX-BotShield': reason,
  });
  res.end('{"ok":false,"error":"bot_blocked","reason":"' + reason + '"}');
}

function shed(res, reason, ip, inFlight = 0, activeConnections = 0) {
  // Back off harder the deeper into saturation we are: a client told to retry in
  // five seconds during a 6,000-socket storm just sends the request again.
  const deep = health.rssMb > CFG.maxRssMb
    || health.lagStreak >= 3
    || health.eventLagMs > CFG.maxEventLagMs
    || inFlight > CFG.maxInFlight * 3
    || activeConnections > CFG.hardConnCeiling * 2;
  const seconds = deep ? 30 : 5;
  counters.shed++;
  counters.byTier.capacity++;
  noteOffender(ip, 'shed_' + reason);
  res.writeHead(503, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Retry-After': String(seconds),
    'Connection': 'close',
    'X-OBSX-BotShield': 'shed:' + reason,
  });
  res.end('{"ok":false,"error":"origin_overloaded","retry_after":' + seconds + '}');
}

/**
 * Expired entries are swept rather than left to rot. A spoofed-IP flood creates
 * thousands of keys a second; without a sweep the shield itself becomes the
 * memory problem it is supposed to solve.
 */
function pruneState() {
  const now = Date.now();
  for (const [k, v] of blocked) if (v <= now) blocked.delete(k);
  for (const [k, v] of blockedSubnets) if (v <= now) blockedSubnets.delete(k);
  for (const [k, v] of pending) if (v.expires <= now) pending.delete(k);
  for (const [k, w] of usage) if (now - w.windowStart > 180000) usage.delete(k);
  for (const [k, w] of subnetUsage) if (now - w.windowStart > 180000) subnetUsage.delete(k);
  for (const [k, w] of uaUsage) if (now - w.windowStart > 180000) uaUsage.delete(k);
  for (const [k, o] of offenders) if (now - o.last > 600000) offenders.delete(k);
  for (const [k, n] of strikes) if (n === 0) strikes.delete(k);
  for (const [k, v] of inflightByIp) if (v.n <= 0 || now - v.at > 60000) inflightByIp.delete(k);
  // seenWindow is bounded and rolled every minute, so it needs no sweep.
}

/**
 * Attempt budget: N unanswered or wrong puzzle answers inside a minute sends the
 * address to quarantine. Shared by challenge issuance and failed answers so a
 * client cannot brute-force the answer endpoint for free.
 */
function noteAttempt(ip, now, cap) {
  let a = attempts.get(ip);
  if (!a || now >= a.reset) { a = { count: 0, reset: now + 60000 }; boundedSet(attempts, ip, a); }
  a.count++;
  if (a.count > cap && now < a.reset) {
    quarantineIp(ip, 'challenge_failed');
    return true;
  }
  return false;
}

function quarantineSubnet(subnet, reason) {
  if (blockedSubnets.has(subnet)) return;
  boundedSet(blockedSubnets, subnet, Date.now() + CFG.quarantineMs);
  counters.quarantinedSubnets++;
  console.log(`[OBSX BotShield] subnet ${subnet} quarantined (${reason})`);
}

function quarantineIp(ip, reason) {
  const now = Date.now();
  // Escalate: a second offence in the hour costs 10 minutes, a third 15, up to
  // a 30-minute ceiling. A rotating bot learns nothing, so this costs it
  // nothing; a persistent attacker pays more each time.
  const n = (strikes.get(ip) || 0) + 1;
  boundedSet(strikes, ip, n);
  const duration = Math.min(1800000, CFG.quarantineMs * n);
  boundedSet(blocked, ip, now + duration);
  counters.quarantined++;
  noteOffender(ip, reason);
  const subnet = subnetOf(ip);
  const w = subnetUsage.get(subnet);
  if (w && w.count >= CFG.subnetQuarantinePerMin && !blockedSubnets.has(subnet)) {
    boundedSet(blockedSubnets, subnet, now + CFG.quarantineMs);
    console.log(`[OBSX BotShield] subnet ${subnet} quarantined (${reason})`);
  }
  console.log(`[OBSX BotShield] quarantined ${ip} (${reason}) for ${duration / 1000}s (strike ${n})`);
}

const CHALLENGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBSX Bot Protection</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#0c1017;color:#e6edf3;margin:0;padding:40px 24px}
  .box{max-width:520px;margin:0 auto;border:1px solid #232c38;border-radius:10px;padding:28px;background:#111823}
  h1{font-size:18px;margin:0 0 8px}p{font-size:13.5px;color:#8b98a6;line-height:1.5;margin:0 0 14px}
  code{font-family:ui-monospace,monospace;font-size:12px;color:#7dd3fc}
  .bar{height:6px;border-radius:3px;background:#1d2631;overflow:hidden}
  .bar i{display:block;height:100%;width:0;background:#38bdf8;transition:width .3s}
</style>
</head>
<body>
  <div class="box">
    <h1>OBSX Bot Protection</h1>
    <p>This node is under elevated traffic. One quick check and you are through &mdash; it runs in your browser and takes well under a second.</p>
    <div class="bar"><i id="prog"></i></div>
    <p style="margin-top:12px"><code id="status">Solving proof-of-work (&#968;<span id="bits"></span> hashes)...</code></p>
  </div>
<script>
(function () {
  var cid = __CID__, challenge = __CHALLENGE__, bits = __BITS__, target = __TARGET__;
  var t0 = Date.now();
  function fnv(s) {
    var h = 2166136261 >>> 0;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return h >>> 0;
  }
  var shift = 32 - bits, n = 0;
  while (((fnv(challenge + n) >>> shift) !== 0)) n++;
  document.getElementById('prog').style.width = '100%';
  document.getElementById('status').textContent =
    'Verified in ' + (Date.now() - t0) + ' ms (' + n + ' hashes). Redirecting...';
  var sep = target.indexOf('?') >= 0 ? '&' : '?';
  setTimeout(function () { location.href = target + sep + '__bs=' + cid + '&__bn=' + n; }, 150);
})();
</script>
</body>
</html>`;

function issueChallenge(res, ip, ua, pathname, reqRate, options = {}) {
  const now = Date.now();
  const cid = crypto.randomId(12);
  const challenge = `${cid}:${ip}:${ua.slice(0, 32)}`;
  const bits = options.forceBits || currentDifficulty(reqRate);
  // Difficulty is frozen into the challenge: if the ramp moved between the
  // challenge and the answer, a real user would be rejected for no reason.
  boundedSet(pending, cid, { challenge, bits, expires: now + CFG.challengeTtlMs });

  // An escape challenge does not count toward the attempt budget: the address is
  // already quarantined, and refusing it again would lock out a real user who is
  // simply sharing a network with the flood.
  // The escape hatch is capped: a quarantined address may try the hardest puzzle
  // a limited number of times, then it is refused like any other offender.
  const cap = options.escape ? CFG.escapeMaxAttempts : CFG.maxAttempts;
  if (noteAttempt(ip, now, cap)) {
    refuse(res, 'quarantine', ip);
    return;
  }

  counters.challenged++;
  noteOffender(ip, 'challenge_issued');
  const html = CHALLENGE_HTML
    .replace('__CID__', JSON.stringify(cid))
    .replace('__CHALLENGE__', JSON.stringify(challenge))
    .replace('__BITS__', String(bits))
    .replace('__TARGET__', JSON.stringify(pathname));

  res.writeHead(403, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, must-revalidate',
    'X-OBSX-BotShield': 'challenge',
  });
  res.end(html);
}

/* -------------------------------------------------------- main entry */

/**
 * Returns { handled, verified }. handled === true means the shield already
 * answered and the request must not reach the application.
 *
 * capacity: { activeConnections, inFlight, reqRate } measured by the server.
 */
function evaluate(req, res, ip, pathname, reqRate, url, capacity) {
  counters.requests++;
  counters.lastRequest = Date.now();
  state.lastRequestAt = counters.lastRequest;
  if (counters.requests % 2000 === 0) pruneState();

  // Record the capacity the server last measured, before the enabled check: the
  // dashboard and the load tests read health.activeConnections / inFlight /
  // requestsPerMinute continuously, and a standing-down shield still has to say
  // what the origin is holding.
  health.activeConnections = (capacity && capacity.activeConnections) || 0;
  health.inFlight = (capacity && capacity.inFlight) || 0;
  health.requestsPerMinute = Math.round((reqRate || 0) * 60);
  health.requestRate = reqRate || 0;

  if (!CFG.enabled || CFG.mode === 'off') return { handled: false, verified: true };

  const now = Date.now();
  state.minuteWindowCount++;
  rollDistinctWindow(now);
  const activeConnections = capacity && capacity.activeConnections ? capacity.activeConnections : 0;
  const inFlight = capacity && capacity.inFlight ? capacity.inFlight : 0;

  sampleMemory();
  // Roll the served-rate window here so the capacity decision never depends on
  // a timer having fired.
  if (now - health.servedWindowStart >= 1000) {
    health.servedRate = Math.round(health.servedWindowCount * 1000 / (now - health.servedWindowStart));
    health.servedWindowStart = now;
    health.servedWindowCount = 0;
  }

  updateMode(reqRate);
  const ua = String(req.headers['user-agent'] || '');

  // Path-fuzz floods hammer thousands of unique, absurdly long paths to defeat
  // caches and inflate per-path maps. Refusing them costs a string comparison.
  if (pathname.length > CFG.maxPathLen) {
    counters.blocked++;
    counters.byTier.path++;
    noteOffender(ip, 'path_too_long');
    res.writeHead(400, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end('{"ok":false,"error":"path_too_long"}');
    return { handled: true, verified: false };
  }

  const pw = windowFor(pathUsage, pathname, 60000);
  if (pw.count === 0) counters.distinctPaths++;
  pw.count++;

  const method = String(req.method || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    counters.blocked++;
    counters.byTier.method++;
    noteOffender(ip, 'method');
    res.writeHead(405, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end('{"ok":false,"error":"method_not_allowed"}');
    return { handled: true, verified: false };
  }

  // A body is application work. While the origin is being flooded, bodies
  // bigger than the API will ever accept are refused here, before any parsing.
  const declaredLen = Number(req.headers['content-length'] || 0);
  if (declaredLen > CFG.maxBodyBytes) {
    counters.blocked++;
    counters.byTier.body++;
    noteOffender(ip, 'body_too_large');
    res.writeHead(413, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end('{"ok":false,"error":"payload_too_large"}');
    return { handled: true, verified: false };
  }
  const subnet = subnetOf(ip);
  const crawler = CRAWLER_UA_RE.test(ua);

  // 1a. One address should not hold the origin open with hundreds of parallel
  //     requests. Through a tunnel every socket looks like the tunnel, so this
  //     has to be measured per client address, not per socket.
  if (inflightOf(ip) >= CFG.maxConcurrentPerIp) {
    counters.blocked++;
    counters.byTier.concurrent++;
    noteOffender(ip, 'concurrent');
    res.writeHead(429, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Retry-After': '10',
      'X-OBSX-BotShield': 'concurrent',
    });
    res.end('{"ok":false,"error":"too_many_parallel_requests"}');
    return { handled: true, verified: false };
  }

  // 1. Connection ceiling: the socket handler refuses the open, this catches
  //    keep-alive reuse while the origin is already drowning.
  if (activeConnections > CFG.hardConnCeiling) {
    shed(res, 'connection_ceiling', ip, inFlight, activeConnections);
    return { handled: true, verified: false };
  }

  // 2. Status endpoints: cheap, budgeted, never challenged.
  if (isStatusPath(pathname)) {
    const w = windowFor(usage, ip, 60000);
    w.count++;
    if (w.count > CFG.statusBudget) {
      counters.blocked++;
      counters.byTier.budget++;
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Retry-After': '30',
        'X-OBSX-BotShield': 'status_budget',
      });
      res.end('{"ok":false,"error":"status_rate_limited"}');
      return { handled: true, verified: false };
    }
    // The shield answers its own telemetry call in microseconds. During a flood
    // the application layer is the part that gets slow, and an operator who
    // cannot see the counters cannot act.
    if (pathname === '/api/v1/bot-protection') {
      const detailed = sameSecret(String(req.headers['x-obsx-key'] || ''),
        String(process.env.OBSX_SECRET || ''));
      counters.passed++;
      counters.servedRequests++;
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-OBSX-BotShield': 'telemetry',
      });
      res.end(JSON.stringify(stats(detailed)));
      return { handled: true, verified: true };
    }
    return { handled: false, verified: true };
  }

  // 3. Already cleared the proof of work: a Map hit, no crypto.
  const cookies = parseCookies(req);
  const token = cookies.obsx_bs;
  let isVerified = false;
  if (token) {
    const v = verified.get(token);
    if (v && v.expires > now && v.ip === ip) isVerified = true;
  }

  // 4. Answering a challenge. Runs before quarantine on purpose: a quarantined
  //    address can buy its way back by doing the work, so a real user on a noisy
  //    shared network is not locked out for five minutes.
  const cid = url.searchParams.get('__bs');
  const nonce = url.searchParams.get('__bn');
  if (cid && nonce) {
    const p = pending.get(cid);
    if (!p || p.expires <= now || !powOk(p.challenge, nonce, p.bits)) {
      counters.blocked++;
      counters.byTier.budget++;
      noteOffender(ip, 'bad_challenge_answer');
      // Wrong answers are charged to the attempt budget too: without this the
      // answer endpoint is a free oracle for guessing nonces.
      if (noteAttempt(ip, now, CFG.maxAttempts)) {
        refuse(res, 'quarantine', ip);
        return { handled: true, verified: false };
      }
      res.writeHead(403, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end('{"ok":false,"error":"challenge_failed"}');
      return { handled: true, verified: false };
    }
    pending.delete(cid);
    // The page reports how long the browser actually spent. It is telemetry, not
    // proof, and is capped, so a bot cannot use it to soften the puzzle.
    const reported = Number(url && url.searchParams ? url.searchParams.get('__ms') : '');
    if (Number.isFinite(reported) && reported >= 0 && reported <= 60000) {
      health.solveTimeEma = health.solveTimeEma ? Math.round(health.solveTimeEma * 0.8 + reported * 0.2) : reported;
    }
    const t = crypto.randomId(24);
    boundedSet(verified, t, { expires: now + CFG.verifyTtlMs, ip });
    blocked.delete(ip);
    attempts.delete(ip);
    // One solved challenge does not clear a subnet quarantine: that verdict is
    // about the range, not this one address.
    counters.solved++;
    res.writeHead(302, {
      Location: pathname,
      'Set-Cookie': `obsx_bs=${t}; Path=/; Max-Age=${Math.floor(CFG.verifyTtlMs / 1000)}; HttpOnly; SameSite=Lax`,
      'Cache-Control': 'no-store',
      'X-OBSX-BotShield': 'verified',
    });
    res.end();
    return { handled: true, verified: true };
  }

  // 5. Quarantine: per IP, and per subnet when a whole range is hammering.
  const until = blocked.get(ip);
  if (until && now < until) {
    // Quarantine is not a life sentence. A client that presents the header
    // fingerprint of a real browser is offered the hardest puzzle instead of a
    // flat 403, so a person behind the same NAT as an attacker can work their
    // way back in, while a scripted bot is refused outright.
    if (CFG.quarantineEscape && looksLikeBrowser(req, ua)) {
      issueChallenge(res, ip, ua, pathname, reqRate, { escape: true, forceBits: CFG.maxDifficulty });
      return { handled: true, verified: false };
    }
    refuse(res, 'quarantine', ip);
    return { handled: true, verified: false };
  }
  const subnetUntil = blockedSubnets.get(subnet);
  if (subnetUntil && now < subnetUntil) {
    refuse(res, 'subnet_quarantine', ip);
    return { handled: true, verified: false };
  }

  // 6. Capacity: refuse before doing any real work. Hard limits shed everyone;
  //    the served-rate limit gives verified visitors 2x headroom so a genuine
  //    surge is not punished while a JS-capable botnet stays bounded.
  if (inFlight > CFG.maxInFlight ||
    activeConnections > CFG.maxActiveConnections ||
    health.workLatencyEma > CFG.maxWorkLatencyMs ||
    health.rssMb > CFG.maxRssMb ||
    health.lagStreak >= 3) {
    shed(res, 'saturation', ip, inFlight, activeConnections);
    return { handled: true, verified: false };
  }
  const servedCap = isVerified ? CFG.maxServedRps * 2 : CFG.maxServedRps;
  if (health.servedRate > servedCap) {
    shed(res, 'served_rate', ip, inFlight, activeConnections);
    return { handled: true, verified: false };
  }

  // 7. Fleet detection: catch the botnet even when every IP is polite.
  noteAddress(ip, subnet, now);
  const uaKey = fnv1a(uaClass(ua));
  const uw = windowFor(uaUsage, uaKey, 60000);
  uw.count++;
  if (uw.ips.size < 200) uw.ips.add(ip);

  const sw = windowFor(subnetUsage, subnet, 60000);
  sw.count++;
  if (sw.ips.size < 200) sw.ips.add(ip);
  // A range that pushes thousands of requests a minute is a fleet, whatever
  // each address looks like. Quarantine the whole range, not just the loudest IP.
  if (sw.count > CFG.subnetQuarantinePerMin && sw.ips.size > 10) {
    quarantineSubnet(subnet, 'subnet_flood');
  }

  const iw = windowFor(usage, ip, 60000);
  iw.count++;

  // 7a. A path-fuzz flood sends thousands of unique paths per minute. No cache
  //     can help, and every per-path structure in the origin grows. Once the
  //     pattern is recognised, unseen paths are answered with a 404 that does no
  //     work instead of being routed.
  if (state.pathFuzz && pw.count === 1) {
    counters.blocked++;
    counters.byTier.pathFuzz++;
    noteOffender(ip, 'path_fuzz');
    res.writeHead(404, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end('{"ok":false,"error":"not_found"}');
    return { handled: true, verified: false };
  }

  // 7a. Search engines: never challenged, but budgeted, and still shed when the
  //     origin is saturated. Indexing is not a licence to flood.
  if (crawler) {
    const cw = windowFor(uaUsage, 'crawler', 60000);
    cw.count++;
    if (cw.count > CFG.crawlerBudget || iw.count > CFG.crawlerBudget) {
      counters.blocked++;
      counters.byTier.crawler++;
      noteOffender(ip, 'crawler_budget');
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Retry-After': '60',
        'X-OBSX-BotShield': 'crawler_budget',
      });
      res.end('{"ok":false,"error":"rate_limited","retry_after":60}');
      return { handled: true, verified: false };
    }
    markServed(ip);
    return { handled: false, verified: true };
  }

  // A client that already proved it is a browser is served; only its budgets
  // can stop it.
  if (isVerified) {
    if (iw.count > CFG.verifiedBudget) {
      counters.blocked++;
      counters.byTier.budget++;
      noteOffender(ip, 'verified_budget');
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Retry-After': '60',
        'X-OBSX-BotShield': 'verified_budget',
      });
      res.end('{"ok":false,"error":"rate_limited","retry_after":60}');
      return { handled: true, verified: true };
    }
    markServed(ip);
    return { handled: false, verified: true };
  }

  if (uw.count > CFG.uaFleetBudget && uw.ips.size > 25) {
    refuse(res, 'fleet', ip);
    return { handled: true, verified: false };
  }
  if (sw.count > CFG.subnetBudget && sw.ips.size > 5) {
    refuse(res, 'subnet', ip);
    return { handled: true, verified: false };
  }

  // 8. Per-IP budget.
  const budget = state.engaged ? CFG.ipBudget : CFG.calmBudget;
  if (iw.count > budget) {
    counters.blocked++;
    counters.byTier.budget++;
    noteOffender(ip, 'budget');
    if (iw.count > budget * 3) quarantineIp(ip, 'budget_overrun');
    res.writeHead(429, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Retry-After': '60',
      'X-OBSX-BotShield': 'budget',
    });
    res.end('{"ok":false,"error":"rate_limited","retry_after":60}');
    return { handled: true, verified: false };
  }

  // 9. Classification. A user agent is a claim; the header set is the evidence.
  const scripted = !ua || SCRIPTED_UA_RE.test(ua) || !looksLikeBrowser(req, ua);

  if (state.engaged) {
    if (isHtmlPath(pathname)) {
      counters.byTier.ua++;
      issueChallenge(res, ip, ua, pathname, reqRate);
      return { handled: true, verified: false };
    }
    refuse(res, 'under_attack', ip);
    return { handled: true, verified: false };
  }

  if (scripted && isHtmlPath(pathname)) {
    counters.byTier[SCRIPTED_UA_RE.test(ua) ? 'ua' : 'spoofed']++;
    issueChallenge(res, ip, ua, pathname, reqRate);
    return { handled: true, verified: false };
  }

  markServed(ip);
  return { handled: false, verified: false };
}

function noteWorkLatency(ms, ip) {
  if (ip) inflightDec(ip);
  const v = Math.min(ms, 5000);
  health.workLatencyEma = health.workLatencyEma ? health.workLatencyEma * 0.85 + v * 0.15 : v;
}

/**
 * The counters are public so an operator can watch the shield from a dashboard.
 * The addresses are not: a flood from a shared or residential network is not a
 * public record, so unless the operator key is supplied the last octets are
 * clipped and only the range is shown.
 */
function maskIp(ip) {
  const s = String(ip || '');
  if (s.includes(':')) return s.split(':').slice(0, 4).join(':') + ':***';
  const parts = s.split('.');
  return parts.length === 4 ? parts[0] + '.' + parts[1] + '.*.*' : s;
}

function sameSecret(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Walk a Map and stop at the first N still-active entries: no copy of the whole
// table, no sort, so the telemetry stays cheap while the maps are huge.
function collectActive(map, limit, now, detailed, shape) {
  const out = [];
  for (const [key, until] of map) {
    if (until > now) { out.push(shape(key, until)); if (out.length >= limit) break; }
  }
  return out;
}

// Top offenders without sorting a 20,000-entry map on every dashboard refresh:
// one pass, keep the eleven biggest.
function topOffenders(limit) {
  const top = [];
  for (const o of offenders.values()) {
    if (top.length < limit) {
      top.push(o);
      top.sort((a, b) => b.hits - a.hits);
    } else if (o.hits > top[limit - 1].hits) {
      top[limit - 1] = o;
      top.sort((a, b) => b.hits - a.hits);
    }
  }
  return top;
}

function stats(detailed) {
  const now = Date.now();
  const out = {
    ok: true,
    feature: 'bot_protection',
    edition: 'origin-shield',
    enabled: CFG.enabled,
    mode: CFG.mode,
    engaged: state.engaged,
    engagedForSeconds: state.engaged ? Math.round((now - state.engagedSince) / 1000) : 0,
    engagements: state.engagements,
    // Difficulty follows the pressure on the origin, not just the traffic we
    // manage to serve: during a flood almost everything is refused, so serving
    // rate alone would keep the puzzle at its easiest.
    difficultyBits: currentDifficulty(Math.max(health.servedRate, health.requestRate)),
    thresholds: {
      engageRps: CFG.engageRps,
      disengageRps: CFG.disengageRps,
      baseDifficulty: CFG.baseDifficulty,
      maxDifficulty: CFG.maxDifficulty,
      unverifiedBudgetPerMinute: CFG.ipBudget,
      verifiedBudgetPerMinute: CFG.verifiedBudget,
      subnetBudgetPerMinute: CFG.subnetBudget,
      fleetBudgetPerMinute: CFG.uaFleetBudget,
      quarantineSeconds: CFG.quarantineMs / 1000,
      hardConnectionCeiling: CFG.hardConnCeiling,
      maxConcurrentPerAddress: CFG.maxConcurrentPerIp,
      fanoutAddressesPerMinute: CFG.fanoutIpsPerMin,
      fanoutSubnetsPerMinute: CFG.fanoutSubnetsPerMin,
      fanoutPathsPerMinute: CFG.fanoutPathsPerMin,
      maxPathLength: CFG.maxPathLen,
      quarantineEscapeAttempts: CFG.escapeMaxAttempts,
      crawlerBudgetPerMinute: CFG.crawlerBudget,
    },
    counters,
    attack: {
      fanout: state.fanout,
      pathFuzz: state.pathFuzz,
      distinctAddresses: counters.distinctIps,
      distinctSubnets: counters.distinctSubnets,
      distinctPaths: counters.distinctPaths,
      peakReqRate: counters.peakReqRate,
      browserSolveMs: health.solveTimeEma,
      refusedRatio: counters.requests ? Math.round((counters.blocked + counters.shed) / counters.requests * 1000) / 1000 : 0,
      engagedSeconds: state.engaged ? Math.round((now - state.engagedSince) / 1000) : 0,
    },
    health: {
      rssMb: health.rssMb,
      eventLagMs: health.eventLagMs,
      servedRate: health.servedRate,
      workLatencyMs: Math.round(health.workLatencyEma),
      // Capacity as last reported by the server (see evaluate).
      activeConnections: health.activeConnections || 0,
      inFlight: health.inFlight || 0,
      requestsPerMinute: health.requestsPerMinute || 0,
    },
    verifiedClients: verified.size,
    pendingChallenges: pending.size,
    stateSizes: {
      verified: verified.size,
      pending: pending.size,
      quarantined: blocked.size,
      quarantinedSubnets: blockedSubnets.size,
      ipWindows: usage.size,
      subnetWindows: subnetUsage.size,
      uaWindows: uaUsage.size,
      offenders: offenders.size,
      concurrentAddresses: inflightByIp.size,
      addressesSeenThisMinute: counters.distinctIps,
      cap: CFG.maxMapSize,
    },
    quarantinedIps: collectActive(blocked, 20, now, detailed, (ip, until) => ({
      ip: detailed ? ip : maskIp(ip), secondsLeft: Math.round((until - now) / 1000) })),
    quarantinedSubnets: collectActive(blockedSubnets, 10, now, true, (sub, until) => ({
      subnet: sub, secondsLeft: Math.round((until - now) / 1000) })),
    topOffenders: topOffenders(10).map((o) => ({ ip: detailed ? o.ip : maskIp(o.ip), hits: o.hits, reason: o.reason })),
  };
  return out;
}

function setMode(mode) {
  const m = String(mode || '').toLowerCase();
  if (m !== 'auto' && m !== 'always' && m !== 'off') return false;
  CFG.mode = m;
  CFG.enabled = m !== 'off';
  if (m === 'off') state.engaged = false;
  console.log(`[OBSX BotShield] mode set to ${m}`);
  return true;
}

function configure(overrides) {
  Object.assign(CFG, overrides || {});
  return CFG;
}

function reset() {
  verified.clear();
  strikes.clear();
  pending.clear();
  blocked.clear();
  blockedSubnets.clear();
  attempts.clear();
  usage.clear();
  subnetUsage.clear();
  uaUsage.clear();
  offenders.clear();
  inflightByIp.clear();
  seenWindow.clear();
  seenSubnets.clear();
  pathUsage.clear();
  state.distinctWindowStart = Date.now();
  state.fanout = false;
  state.pathFuzz = false;
  state.engaged = false;
  state.engagedSince = 0;
  state.calmSince = 0;
  for (const k of Object.keys(counters.byTier)) counters.byTier[k] = 0;
  counters.requests = counters.challenged = counters.solved = counters.passed = counters.blocked = 0;
  counters.quarantined = counters.quarantinedSubnets = counters.shed = 0;
  counters.servedRequests = 0;
  counters.distinctIps = 0;
  counters.distinctSubnets = 0;
  counters.distinctPaths = 0;
  counters.fanoutDetected = 0;
  counters.peakReqRate = 0;
  health.servedRate = 0;
  health.requestRate = 0;
  health.solveTimeEma = 0;
  health.workLatencyEma = 0;
  health.servedWindowCount = 0;
  health.workLatencyEma = 0;
  health.lagStreak = 0;
}

module.exports = {
  evaluate,
  pruneState,
  stats,
  checkIdle,
  noteSocketShed,
  setMode,
  isEngaged,
  connectionPosture,
  configure,
  reset,
  startMonitors,
  stopMonitors,
  noteWorkLatency,
  config: CFG,
  fnv1a,
  powOk,
  subnetOf,
  uaClass,
  currentDifficulty,
};
