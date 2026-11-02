'use strict';

const crypto = require('./crypto');
const { getKv } = require('./kv');
const telemetry = require('./telemetry');
const mailer = require('./mailer');

const KNOWN_BUILDS = new Set(['trc_v1_live', 'trc_v1_debug']);

const DEFAULTS = {
  mode: 'enforce',
  reviewAt: 35,
  rejectAt: 65,
  maxScore: null,
  maxScorePerSec: null,
  minDurationMs: 1200,
  powDifficulty: 3,
  origins: [],
  sessionTtlSec: 3600,
  adaptiveCircuitBreaker: false,
  blockOpenAiScrapers: true,
};

const DEMO = {
  pid: 'sandbox',
  publicKey: 'pk_obsx_sandbox',
  legacyPublicKey: 'pk_tracer_sandbox',
  name: 'OBSX Sandbox Demo',
  settings: {
    maxScore: 1000,
    maxScorePerSec: 100,
    minDurationMs: 1200,
    powDifficulty: 2,
    sessionTtlSec: 1800,
    origins: [],
    adaptiveCircuitBreaker: true,
    blockOpenAiScrapers: true,
  },
};

function isOpenAiScraperUa(ua, referer = '', urlQuery = '') {
  const uaStr = typeof ua === 'string' ? ua : '';
  const refStr = typeof referer === 'string' ? referer : '';
  const qStr = typeof urlQuery === 'string' ? urlQuery : '';
  if (/GPTBot|ChatGPT-User|OAI-SearchBot|ChatGPT-Browser|OpenAI-Crawler|OpenAI\/|ChatGPT\/|operator\.chatgpt\.com/i.test(uaStr)) {
    return true;
  }
  if (/chatgpt\.com|chat\.openai\.com/i.test(refStr) || /utm_source=chatgpt/i.test(qStr)) {
    return true;
  }
  return false;
}

const WEIGHTS = {
  probe_violation: 100,
  automation_cdp: 100,
  bad_signature: 100,
  stale_signature: 100,
  bot_signature_probe: 80,
  software_rasterizer_anomaly: 80,
  proxy_virtualization: 75,
  unattested_sdk: 75,
  invalid_pow: 70,
  automation_webdriver: 70,
  automation_headless: 70,
  synthetic_touch: 65,
  tampered_builtins: 60,
  missing_telemetry: 100,
  unattested_execution: 100,
  synthetic_cadence: 45,
  linear_pointer: 40,
  idle_long_session: 35,
  speed_anomaly: 30,
  wrapped_runtime: 5,
};

const REASONS = {
  probe_violation: 'Unauthorized client manipulation or debug interface invocation.',
  automation_cdp: 'Active Chrome DevTools Protocol (CDP) or browser instrumentation detected.',
  bad_signature: 'Cryptographic action payload seal mismatch (wire tampering detected).',
  stale_signature: 'Cryptographic action payload seal timestamp expired or excessive clock skew.',
  bot_signature_probe: 'Payload matches known automated scanner signature or dummy bot probe.',
  software_rasterizer_anomaly: 'Client environment is running on a software-emulated GPU rasterizer (SwiftShader/llvmpipe).',
  proxy_virtualization: 'Client environment running inside web proxy unblocker (Ultraviolet, Scramjet, Rammerhead, Bare-mux, or Sovereign Gateway).',
  invalid_token: 'Session token was forged, malformed, or missing.',
  token_reused: 'Session token was already redeemed (replay attack rejected).',
  expired: 'Session token expired before the request was completed.',
  too_fast: 'Action completed faster than humanly achievable.',
  score_exceeded: 'Value exceeded project threshold ceiling.',
  score_velocity_exceeded: 'Value accumulated faster than permitted rate.',
  unattested_sdk: 'Client SDK hash missing or does not match official build.',
  invalid_pow: 'Cryptographic proof-of-work challenge failed or missing.',
  missing_telemetry: 'No client behavioral signals were provided.',
  unattested_execution: 'Client lacks genuine hardware rasterization rendering pipeline or runtime attestation.',
  automation_webdriver: 'Active automation framework detected (navigator.webdriver).',
  automation_headless: 'Headless browser environment indicators present.',
  synthetic_touch: 'Touch pressure and contact area dynamics lack biological human variance.',
  tampered_builtins: 'Native JavaScript functions or prototypes were hijacked.',
  wrapped_runtime: 'Standard application performance monitoring (APM) wrapper detected.',
  synthetic_cadence: 'Keystroke timing variance indicates scripted automated dispatch.',
  linear_pointer: 'Pointer trajectory lacks natural human micro-curvature.',
  idle_long_session: 'Extended session duration with zero physical interaction.',
  speed_anomaly: 'System clock or animation loop running at abnormal multipliers.',
  openai_scraper_blocked: 'get your own ram',
  circuit_breaker_isolated: 'Attack vector or hostile subnet isolated by Sentinel.',
};

const HARD_REASONS = new Set([
  'probe_violation',
  'automation_cdp',
  'bad_signature',
  'stale_signature',
  'invalid_token',
  'token_reused',
  'expired',
  'score_exceeded',
  'score_velocity_exceeded',
  'invalid_pow',
  'proxy_virtualization',
  'missing_telemetry',
  'unattested_execution',
  'openai_scraper_blocked',
  'circuit_breaker_isolated',
]);

async function loadProject(pid) {
  if (pid === DEMO.pid) return DEMO;
  const kv = getKv();
  const raw = await kv.hgetall(`tr:p:${pid}`);
  if (!raw || !raw.publicKey) return null;
  return {
    pid,
    name: raw.name,
    publicKey: raw.publicKey,
    owner: raw.owner || null,
    created: Number(raw.created) || Date.now(),
    settings: raw.settings ? JSON.parse(raw.settings) : { ...DEFAULTS },
  };
}

async function projectByPublicKey(pk) {
  if (pk === DEMO.publicKey || pk === DEMO.legacyPublicKey || pk === 'pk_obsx_sandbox' || pk === 'pk_tracer_sandbox') return DEMO;
  const kv = getKv();
  const pid = await kv.get(`tr:pk:${pk}`);
  if (!pid) return null;
  return loadProject(pid);
}

async function projectBySecretKey(sk) {
  const kv = getKv();
  const pid = await kv.get(`tr:sk:${crypto.sha256(sk)}`);
  if (!pid) return null;
  return loadProject(pid);
}

async function createProject(opts, ownerUid) {
  const kv = getKv();
  const pid = `p_${crypto.randomId(8)}`;
  const publicKey = `pk_${crypto.randomId(12)}`;
  const secretKey = `sk_${crypto.randomId(24)}`;
  const skHash = crypto.sha256(secretKey);

  const settings = {
    ...DEFAULTS,
    ...(opts.settings || {}),
    name: opts.name ? String(opts.name).slice(0, 60) : 'My Project',
    origins: Array.isArray(opts.origins) ? opts.origins : [],
  };

  const projectRecord = {
    pid,
    name: settings.name,
    publicKey,
    owner: ownerUid || 'anonymous',
    created: String(Date.now()),
    settings: JSON.stringify(settings),
    secretKeyHash: skHash,
  };

  await kv.hset(`tr:p:${pid}`, projectRecord);
  await kv.set(`tr:pk:${publicKey}`, pid);
  await kv.set(`tr:sk:${skHash}`, pid);

  if (ownerUid) {
    await kv.hset(`tr:u:${ownerUid}:projects`, pid, String(Date.now()));
  }

  return {
    pid,
    publicKey,
    secretKey,
    name: settings.name,
    settings,
  };
}

/**
 * Normalizes client IP address to a subnet grouping key:
 * - IPv4: /24 subnet (e.g. "subnet:v4:198.51.100.0/24")
 * - IPv6: /48 subnet (e.g. "subnet:v6:2001:db8:1234::/48")
 */
function getSubnetKey(ip) {
  if (!ip || typeof ip !== 'string') return 'subnet:unknown';
  const clean = ip.trim().replace(/^::ffff:/, '');
  if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') {
    return 'subnet:loopback';
  }
  if (clean.includes('.')) {
    const parts = clean.split('.');
    if (parts.length === 4) {
      return `subnet:v4:${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  } else if (clean.includes(':')) {
    const hextets = clean.split(':').filter(Boolean);
    const prefix = hextets.slice(0, 3).join(':');
    return `subnet:v6:${prefix || '::'}/48`;
  }
  return `subnet:other:${clean}`;
}

async function startSession(project, ctx = {}) {
  const kv = getKv();
  const freshProject = project && project.pid ? (await loadProject(project.pid)) || project : project;
  const s = freshProject.settings || DEFAULTS;
  const now = Date.now();
  const sid = crypto.randomId(16);
  const exp = now + (s.sessionTtlSec || 3600) * 1000;
  const isPassive = s.mode === 'passive';
  const effectiveMode = isPassive ? 'passive' : 'enforce';

  // Subnet-level velocity tracking (neutralizes distributed proxy-pool attacks)
  const subnetKey = getSubnetKey(ctx.ip);
  let subnetVolume = 0;
  let globalRingThreat = 0;
  if (subnetKey !== 'subnet:loopback') {
    try {
      const windowMin = Math.floor(now / 60000);
      const rateKey = `rate:${subnetKey}:${windowMin}`;
      subnetVolume = (await kv.incr(rateKey, 120)) || 1;
      const memRing = globalThreatRingMemory.get(subnetKey);
      if (memRing && now < memRing.expiresAt) {
        globalRingThreat = memRing.count;
      } else {
        const ringVal = await kv.get(`tr:sentinel:ring:${subnetKey}`);
        if (ringVal) globalRingThreat = Number(ringVal) || 1;
      }
    } catch {
      // Graceful fallback if kv is unavailable
    }
  }

  // Generate dynamic micro-PoW challenge with adaptive difficulty escalation
  let targetDifficulty = isPassive ? Math.min(s.powDifficulty || 2, 2) : (s.powDifficulty || 2);
  if (!isPassive && ctx.proxyHeaders && ctx.proxyHeaders.length > 0) {
    targetDifficulty = Math.max(3, targetDifficulty + 1);
  }
  // Pre-emptive escalation if subnet is flagged in the Global Sentinel Threat Ring
  if (!isPassive && globalRingThreat >= 3) {
    targetDifficulty = Math.max(targetDifficulty, 4);
  }
  // If subnet is aggressively spawning sessions (> 15/min from same /24 or /48)
  if (!isPassive && subnetVolume > 15) {
    targetDifficulty = Math.max(targetDifficulty, 4);
  } else if (!isPassive && subnetVolume > 8) {
    targetDifficulty = Math.max(targetDifficulty, 3);
  }
  const pow = crypto.createPoWChallenge(sid, targetDifficulty);

  const ipHash = await crypto.fingerprint('ip', ctx.ip || '0.0.0.0', kv);
  const uaHash = await crypto.fingerprint('ua', ctx.ua || '', kv);

  const token = await crypto.signToken({
    v: 1,
    p: project.pid,
    s: sid,
    i: now,
    e: exp,
    ch: pow.challenge,
    diff: pow.difficulty,
    ih: ipHash,
    uh: uaHash,
  }, kv);

  const rk = crypto.randomId(32);

  // Store active session descriptor
  const sessionRecord = {
    p: project.pid,
    i: String(now),
    ch: pow.challenge,
    diff: String(pow.difficulty),
    ih: ipHash,
    uh: uaHash,
    rk,
    b: '0',
    mode: effectiveMode,
  };
  if (ctx.proxyHeaders && ctx.proxyHeaders.length > 0) {
    sessionRecord.proxyTainted = JSON.stringify(ctx.proxyHeaders);
  }
  await kv.hset(`tr:s:${sid}`, sessionRecord);
  // Unverified sessions begin with a 60s handshake TTL (extended upon authentic signal arrival)
  await kv.expire(`tr:s:${sid}`, 60);

  return {
    token,
    session: sid,
    challenge: pow.challenge,
    difficulty: pow.difficulty,
    expiresAt: exp,
    rk,
    mode: effectiveMode,
    blockOpenAiScrapers: s.blockOpenAiScrapers !== false,
  };
}

async function recordSignals(body, ctx = {}) {
  const kv = getKv();
  const t = await crypto.verifyToken(body.token, kv);
  if (!t || !t.s) return { ok: false, error: 'invalid_token' };

  const sess = await kv.hgetall(`tr:s:${t.s}`);
  if (!sess || !sess.p) return { ok: false, error: 'session_expired' };

  let rawSignals = body.signals;

  // Unpack disguised Web Vitals telemetry if present
  if (body.vitals && typeof body.vitals === 'object') {
    const v = body.vitals;
    const points = [];
    if (typeof v.d_vec === 'string' && v.d_vec.length > 0) {
      for (const segment of v.d_vec.split(';')) {
        const [x, y, pt] = segment.split(',').map(Number);
        if (Number.isFinite(x) && Number.isFinite(y) && Number.isFinite(pt)) {
          points.push({ x, y, t: pt });
        }
      }
    }
    const intervals = typeof v.c_var === 'string' ? v.c_var.split(',').map(Number).filter(Number.isFinite) : [];
    const mask = Number(v.rt_mask) || 0;
    const tampered = [];
    if (mask & 1) tampered.push('native_hook_trap');
    if (mask & 2) tampered.push('proxy_virtualization');
    if (mask & 4) tampered.push('webdriver_detected');
    if (mask & 8 || (v.hp && Number(v.hp) > 0)) tampered.push('probe_violation');

    rawSignals = {
      sh: v.fp || 'unattested',
      mousePoints: points,
      keyIntervals: intervals,
      tampered,
      probe: (mask & 8) || (v.hp && Number(v.hp) > 0) ? 1 : 0,
      webdriver: !!(mask & 4),
      headless: !!(mask & 16),
      elapsedMs: Number(v.age) || 0,
    };
  }

  if (!rawSignals || typeof rawSignals !== 'object') {
    return { ok: false, error: 'bad_signals' };
  }

  // Detect automated probe signatures (e.g. dummy scanner tests feeding wd/hl/au)
  if ('wd' in rawSignals || 'hl' in rawSignals || 'au' in rawSignals || 'tp' in rawSignals) {
    rawSignals.botProbe = true;
  }

  // Verify Challenge-Bound Telemetry HMAC Seal (tsig) when supplied
  let tsigStatus = sess.tsig || '0';
  if (typeof body.tsig === 'string' && sess.rk) {
    try {
      const msg = `obsx.sig.v1\n${t.s}\n${body.nonce || ''}\n${canon.canonJson(rawSignals)}`;
      const expected = crypto.hmacSign(crypto.fromB64u(sess.rk), msg);
      if (crypto.safeEqual(body.tsig, expected)) {
        tsigStatus = '1';
      } else {
        rawSignals.tampered = Array.isArray(rawSignals.tampered) ? rawSignals.tampered : [];
        rawSignals.tampered.push('tampered:telemetry_seal_mismatch');
      }
    } catch {
      rawSignals.tampered = Array.isArray(rawSignals.tampered) ? rawSignals.tampered : [];
      rawSignals.tampered.push('tampered:telemetry_seal_invalid');
    }
  }

  // Record signals
  const existing = sess.sig ? JSON.parse(sess.sig) : {};
  const merged = { ...existing, ...rawSignals };

  const updateFields = {
    sig: JSON.stringify(merged),
    b: String((Number(sess.b) || 0) + 1),
    lastSignal: String(Date.now()),
    tsig: tsigStatus,
  };
  if (ctx.proxyHeaders && ctx.proxyHeaders.length > 0) {
    const existingProxies = sess.proxyTainted ? JSON.parse(sess.proxyTainted) : [];
    updateFields.proxyTainted = JSON.stringify(Array.from(new Set([...existingProxies, ...ctx.proxyHeaders])));
  }

  await kv.hset(`tr:s:${t.s}`, updateFields);

  // Extend session TTL to full project duration now that authentic signals have arrived
  const project = await loadProject(t.p);
  const fullTtl = (project && project.settings && project.settings.sessionTtlSec) || 3600;
  await kv.expire(`tr:s:${t.s}`, fullTtl + 300);

  return { ok: true };
}

async function verify(project, body, ctx = {}) {
  const kv = getKv();
  const now = Date.now();
  const freshProject = project && project.pid ? (await loadProject(project.pid)) || project : project;
  const s = freshProject.settings || DEFAULTS;
  const reasons = [];

  const hard = (code, detail) => reasons.push({ code, weight: 100, detail });

  // Mode is strictly governed by server-side project settings (never client request body)
  const effectiveMode = s.mode === 'passive' ? 'passive' : 'enforce';

  // Pre-verification ingress inspections (evaluated regardless of token presence)
  const ingressProxies = (ctx && Array.isArray(ctx.proxyHeaders)) ? ctx.proxyHeaders : [];
  if (ingressProxies.length > 0) {
    hard('proxy_virtualization', 'Request carries web proxy tunnel headers: ' + ingressProxies.join(', '));
  }
  const ingressUa = (ctx && ctx.ua) || (ctx && ctx.headers && ctx.headers['user-agent']) || '';
  const blockOpenAi = s.blockOpenAiScrapers !== false && process.env.BLOCK_OPENAI_SCRAPERS !== 'false';
  if (blockOpenAi && isOpenAiScraperUa(ingressUa)) {
    hard('openai_scraper_blocked', 'get your own ram');
    return computeVerdict(
      reasons,
      s,
      { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'OpenAI Scraper Blocked', mode: effectiveMode, project },
      { sealed: 'none', customMessage: 'get your own ram' }
    );
  }
  if (/headlesschrome|playwright|puppeteer|selenium|webdriver/i.test(ingressUa)) {
    hard('automation_cdp', 'Instrumented automation framework user-agent: ' + ingressUa);
  }

  // 1. Resolve token and nonce from sealed container first (preventing payload key collision)
  const reqToken =
    (body.obsx && body.obsx.token) ||
    (body.seal && body.seal.token) ||
    (body.advisory && body.advisory.token) ||
    body.token;

  const reqNonce =
    body.obsx && body.obsx.nonce !== undefined
      ? body.obsx.nonce
      : body.seal && body.seal.nonce !== undefined
      ? body.seal.nonce
      : body.advisory && body.advisory.nonce !== undefined
      ? body.advisory.nonce
      : body.nonce !== undefined
      ? body.nonce
      : undefined;

  let sealedStatus = 'none';

  // Verify token cryptographic integrity
  const t = await crypto.verifyToken(reqToken, kv);
  if (!t) {
    hard('invalid_token');
    return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
  }

  if (t.p !== project.pid) {
    hard('invalid_token', 'Project mismatch');
    return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
  }

  if (now > t.e) {
    hard('expired');
    return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
  }

  // 2. Atomic single-use check (Prevent replay attacks)
  const ttl = Math.ceil((t.e - now) / 1000) + 300;
  const claimed = await kv.set(`tr:used:${t.s}`, '1', 'NX', 'EX', ttl);
  if (!claimed || claimed !== 'OK') {
    hard('token_reused');
    return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
  }

  // 3. Load active session state
  const sess = await kv.hgetall(`tr:s:${t.s}`);
  if (!sess || !sess.p) {
    hard('expired', 'Session record purged');
    return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
  }

  // 3b. Verify Session-to-Verify Client Binding (User-Agent & IP Fingerprint Corroboration)
  if (ctx.ua && sess.uh) {
    const emptyUaHash = await crypto.fingerprint('ua', '', kv);
    if (sess.uh !== emptyUaHash) {
      const currentUaHash = await crypto.fingerprint('ua', ctx.ua, kv);
      if (currentUaHash !== sess.uh) {
        reasons.push({
          code: 'tampered_builtins',
          weight: 45,
          detail: 'Session relayed across mismatched User-Agent environments between startSession and verify',
        });
      }
    }
  }

  // 4. Elapsed time check
  const started = Number(sess.i) || t.i;
  const elapsed = Math.max(0, now - started);
  if (s.minDurationMs && elapsed < s.minDurationMs) {
    const sig = sess.sig ? JSON.parse(sess.sig) : null;
    const hasHumanSignals = sig && Array.isArray(sig.mousePoints) && sig.mousePoints.length >= 3;
    if (hasHumanSignals && elapsed >= 200) {
      // Fast human with autofill/password manager: apply soft risk without hard-blocking genuine users
      reasons.push({ code: 'too_fast', weight: 25, detail: `${elapsed}ms < min ${s.minDurationMs}ms (Autofill tolerance)` });
    } else {
      hard('too_fast', `${elapsed}ms < min ${s.minDurationMs}ms`);
    }
  }

  // 5. Hard score limits
  const hasScore = body.score !== undefined && body.score !== null;
  const score = hasScore ? Number(body.score) : null;
  if (hasScore && s.maxScore !== null && score > s.maxScore) {
    hard('score_exceeded', `${score} > max ${s.maxScore}`);
  }
  if (hasScore && s.maxScorePerSec !== null && elapsed > 500) {
    const rate = score / (elapsed / 1000);
    if (rate > s.maxScorePerSec) {
      hard('score_velocity_exceeded', `${rate.toFixed(1)}/s > max ${s.maxScorePerSec}/s`);
    }
  }

  // 6. Cryptographic Proof of Work (PoW) Verification
  const requiredDiff = Number(sess.diff) || 0;
  if (requiredDiff > 0) {
    if (!reqNonce || !crypto.verifyPoW(sess.ch, String(reqNonce), requiredDiff)) {
      hard('invalid_pow', 'Failed micro-PoW challenge');
    }
  }

  // 6a. Global Sentinel Fleet Ring Subnet Quarantine Check
  if (ctx.ip) {
    const sKey = getSubnetKey(ctx.ip);
    if (sKey !== 'subnet:loopback' && sKey !== 'subnet:unknown') {
      const ringCount = Number(await kv.get(`tr:sentinel:ring:${sKey}`)) || 0;
      if (ringCount >= 10) {
        hard('circuit_breaker_isolated', `Global Sentinel Fleet Ring quarantined hostile subnet (${sKey})`);
      }
    }
  }

  // 6b. Cryptographic Action Seal Verification (Wire Tampering Defense)
  const seal = body.obsx || body.seal || body.advisory || (body.sig && body.ts ? { sig: body.sig, ts: body.ts } : null);
  if (seal && seal.sig && sess.rk) {
    const sealTs = Number(seal.ts);
    if (!sealTs || Math.abs(now - sealTs) > 300000) {
      hard('stale_signature', 'Action seal timestamp expired or excessive clock skew');
      sealedStatus = 'stale';
    } else {
      // Reconstruct action payload without seal containers and attestation metadata
      const unsealed = { ...body };
      delete unsealed.obsx;
      delete unsealed.seal;
      delete unsealed.advisory;
      delete unsealed.sig;
      delete unsealed.ts;

      // If root token matches the session attestation token, strip it
      if (unsealed.token !== undefined && unsealed.token === reqToken) {
        delete unsealed.token;
      }
      // If root nonce matches the PoW challenge nonce, strip it
      if (unsealed.nonce !== undefined && String(unsealed.nonce) === String(reqNonce)) {
        delete unsealed.nonce;
      }
      if (unsealed.mode !== undefined) {
        delete unsealed.mode;
      }

      const isValidSeal = crypto.verifyActionSeal(sess.rk, t.s, sealTs, reqNonce || '', unsealed, seal.sig);
      if (!isValidSeal) {
        hard('bad_signature', 'Action payload tampered on the wire or invalid signature');
        sealedStatus = 'invalid';
      } else {
        sealedStatus = 'ok';
      }
    }
  } else if (s.requireSignedRequests) {
    hard('bad_signature', 'Signed action seal required for this project');
    sealedStatus = 'missing';
  }

  // 7. Proxy Tunnel & Virtualization Inspection (Evaluated unconditionally)
  const sessionProxies = sess.proxyTainted ? JSON.parse(sess.proxyTainted) : [];
  const currentProxies = (ctx && Array.isArray(ctx.proxyHeaders)) ? ctx.proxyHeaders : [];
  const allProxyHeaders = Array.from(new Set([...sessionProxies, ...currentProxies]));
  if (allProxyHeaders.length > 0) {
    hard('proxy_virtualization', 'Request carries web proxy tunnel headers: ' + allProxyHeaders.join(', '));
  }

  // 8. Client SDK Hash & Signal Completeness
  const sig = sess.sig ? JSON.parse(sess.sig) : null;
  if (!sig || Object.keys(sig).length === 0) {
    hard('missing_telemetry', 'No client behavioral signals were provided');
  } else {
    // Check SDK Build Integrity
    if (!sig.sh || !KNOWN_BUILDS.has(sig.sh)) {
      reasons.push({ code: 'unattested_sdk', weight: WEIGHTS.unattested_sdk });
    }

    // Instrumentation probe detection (Immediate hard rejection)
    if ((sig.probe && sig.probe > 0) || (sig.honeypot && sig.honeypot > 0)) {
      hard('probe_violation', 'Unauthorized client instrumentation detected');
    }

    // Bot signature probes
    if (sig.botProbe) {
      reasons.push({ code: 'bot_signature_probe', weight: WEIGHTS.bot_signature_probe, detail: 'Detected generic crawler probe signature' });
    }

    // Tamper & Client Proxy detection
    if (sig.tampered && sig.tampered.length > 0) {
      const proxyFlags = sig.tampered.filter((t) => t.startsWith('proxy_') || t.includes('location_getter'));
      if (proxyFlags.length > 0) {
        hard('proxy_virtualization', 'Client environment tampered by web proxy: ' + proxyFlags.join(', '));
      }

      const cdpFlags = sig.tampered.filter((t) => t.startsWith('automation_cdp') || t.startsWith('automation_framework'));
      if (cdpFlags.length > 0) {
        hard('automation_cdp', 'Instrumented automation framework detected: ' + cdpFlags.join(', '));
      }

      const gpuFlags = sig.tampered.filter((t) => t.startsWith('gpu:software_rasterizer'));
      if (gpuFlags.length > 0) {
        reasons.push({
          code: 'software_rasterizer_anomaly',
          weight: WEIGHTS.software_rasterizer_anomaly,
          detail: gpuFlags.join(', '),
        });
      }

      const wrappedFlags = sig.tampered.filter((t) => t.startsWith('wrapped:') || t.startsWith('wrapped_builtin:'));
      if (wrappedFlags.length > 0) {
        reasons.push({
          code: 'wrapped_runtime',
          weight: WEIGHTS.wrapped_runtime,
          detail: 'Benign APM / monitoring hooks: ' + wrappedFlags.join(', '),
        });
      }

      const otherTampered = sig.tampered.filter(
        (t) =>
          !t.startsWith('proxy_') &&
          !t.includes('location_getter') &&
          !t.startsWith('env_') &&
          !t.startsWith('automation_cdp') &&
          !t.startsWith('automation_framework') &&
          !t.startsWith('gpu:') &&
          !t.startsWith('wrapped:') &&
          !t.startsWith('wrapped_builtin:')
      );
      if (otherTampered.length > 0) {
        reasons.push({
          code: 'tampered_builtins',
          weight: WEIGHTS.tampered_builtins,
          detail: otherTampered.join(', '),
        });
      }
      const envAnomalies = sig.tampered.filter((t) => t.startsWith('env_'));
      if (envAnomalies.length > 0) {
        reasons.push({
          code: 'automation_headless',
          weight: WEIGHTS.automation_headless,
          detail: envAnomalies.join(', '),
        });
      }
    }

    // Automation flags
    if (sig.webdriver) {
      reasons.push({ code: 'automation_webdriver', weight: WEIGHTS.automation_webdriver });
    }
    if (sig.headless) {
      reasons.push({ code: 'automation_headless', weight: WEIGHTS.automation_headless });
    }

    // Ephemeral GPU Renderer Evaluation
    if (typeof sig.gpuRenderer === 'string' && sig.gpuRenderer !== 'unknown' && sig.gpuRenderer !== 'standard_webgl') {
      const gpuEval = telemetry.evaluateGpuRenderer(sig.gpuRenderer, ctx.ua);
      if (gpuEval.isSoftwareRasterizer) {
        reasons.push({
          code: 'software_rasterizer_anomaly',
          weight: WEIGHTS.software_rasterizer_anomaly,
          detail: `Software rasterizer emulator: ${sig.gpuRenderer}`,
        });
      }
    }

    // Mobile Touch Biometrics Evaluation
    if (Array.isArray(sig.touchPoints) && sig.touchPoints.length > 0) {
      const touchDynamics = telemetry.evaluateTouchDynamics(sig.touchPoints);
      if (touchDynamics.isSyntheticTouch) {
        reasons.push({
          code: 'synthetic_touch',
          weight: WEIGHTS.synthetic_touch,
          detail: 'Touch contact mechanics lack natural human pressure variation',
        });
      }
    }

    // Biometric Entropy & Kinematic Tremor Evaluation
    const hasPointer = Array.isArray(sig.mousePoints) && sig.mousePoints.length > 0;
    const hasTouch = Array.isArray(sig.touchPoints) && sig.touchPoints.length > 0;
    const hasKeys = Array.isArray(sig.keyIntervals) && sig.keyIntervals.length > 0;
    const hasEnvTamper = Array.isArray(sig.tampered) && sig.tampered.length > 0;

    if (!hasPointer && !hasTouch && !hasKeys && !hasEnvTamper && !sig.webdriver && !sig.headless && !sig.gpuRenderer) {
      reasons.push({
        code: 'missing_signals',
        weight: WEIGHTS.missing_signals,
        detail: 'Zero physical interaction or environment telemetry recorded',
      });
    } else if (ctx.requireBiometrics && (!Array.isArray(sig.mousePoints) || sig.mousePoints.length < 4) && !hasTouch) {
      reasons.push({
        code: 'missing_signals',
        weight: WEIGHTS.missing_signals,
        detail: 'Protected interactive action requires continuous pointer or touch kinematics (>= 4 samples)',
      });
    }

    if (
      ctx.requireBiometrics &&
      (!ctx.ua || /^(curl|python|node|undici|go-http-client|wget|postman|insomnia|axios|httpie)/i.test(String(ctx.ua).trim()))
    ) {
      reasons.push({
        code: 'automation_headless',
        weight: WEIGHTS.automation_headless,
        detail: 'Non-browser CLI or script HTTP User-Agent signature',
      });
    }

    if (Array.isArray(sig.mousePoints)) {
      const dynamics = telemetry.evaluatePointerDynamics(sig.mousePoints);
      if (dynamics.isLinear) {
        reasons.push({ code: 'linear_pointer', weight: WEIGHTS.linear_pointer });
      }
      if (dynamics.isSyntheticJerk) {
        reasons.push({ code: 'synthetic_cadence', weight: WEIGHTS.synthetic_cadence, detail: 'Pointer kinematics lacks natural physiological tremor' });
      }
    }

    if (Array.isArray(sig.keyIntervals)) {
      const cadence = telemetry.evaluateKeystrokeCadence(sig.keyIntervals);
      if (cadence.isSyntheticCadence) {
        reasons.push({ code: 'synthetic_cadence', weight: WEIGHTS.synthetic_cadence });
      }
    }
  }

  return computeVerdict(reasons, s, { pid: project.pid, clientIp: ctx.ip, action: ctx.action || 'API Request Attestation', mode: effectiveMode, project }, { sealed: sealedStatus });
}

// Rolling live telemetry events feed
const recentEvents = [
  {
    id: 'ev_live_init1',
    timestamp: Date.now() - 42000,
    action: 'Session Handshake',
    verdict: 'accept',
    risk: 0,
    reasons: [],
    maskedIp: '2600:4040:2753:****',
    latencyMs: 1,
    engine: 'OBSX',
  },
  {
    id: 'ev_live_init2',
    timestamp: Date.now() - 118000,
    action: 'Vault Exploit Probe',
    verdict: 'reject',
    risk: 100,
    reasons: ['Missing client telemetry ({})', 'Zero micro-PoW puzzle nonce'],
    maskedIp: '198.51.100.***',
    latencyMs: 1,
    engine: 'OBSX',
  },
  {
    id: 'ev_live_init3',
    timestamp: Date.now() - 245000,
    action: 'Proxy Relay Scan',
    verdict: 'reject',
    risk: 100,
    reasons: ['Web proxy unblocker virtualization (Bare-mux / UV)', 'Location getter trap'],
    maskedIp: '185.220.101.***',
    latencyMs: 2,
    engine: 'OBSX',
  },
  {
    id: 'ev_live_init4',
    timestamp: Date.now() - 410000,
    action: 'Synthetic Spline Bot',
    verdict: 'reject',
    risk: 85,
    reasons: ['Degenerate kinematic jerk entropy (d³x/dt³)', 'Synthetic neuromuscular cadence'],
    maskedIp: '104.244.42.***',
    latencyMs: 1,
    engine: 'OBSX',
  },
  {
    id: 'ev_live_init5',
    timestamp: Date.now() - 620000,
    action: 'Operator Session Auth',
    verdict: 'accept',
    risk: 0,
    reasons: [],
    maskedIp: '10.10.42.***',
    latencyMs: 1,
    engine: 'OBSX',
  },
];

// Rolling per-project isolated telemetry events feed (pid -> Array of events)
const projectRecentEvents = new Map();
// Global Sentinel Fleet Ring in-memory fast lookup (subnetKey -> { count, expiresAt })
const globalThreatRingMemory = new Map();

function getProjectRecentEvents(pid) {
  if (!pid) return [];
  if (!projectRecentEvents.has(pid)) {
    projectRecentEvents.set(pid, []);
  }
  return projectRecentEvents.get(pid);
}

function recordProjectEvent(pid, ev) {
  if (!pid) return;
  const list = getProjectRecentEvents(pid);
  list.unshift(ev);
  if (list.length > 50) list.pop();
}

function maskIp(ip) {
  if (!ip || typeof ip !== 'string') return '127.0.0.1';
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return `${parts.slice(0, 3).join(':')}:****`;
  }
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.***.***`;
  }
  return ip.slice(0, 7) + '***';
}

function recordLiveEvent({ action, verdict, shadowVerdict, risk, reasons, clientIp, latencyMs, engine = 'OBSX', mode = 'enforce', pid }) {
  const ev = {
    id: 'ev_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    timestamp: Date.now(),
    action: action || 'Request Attestation',
    verdict,
    shadowVerdict,
    risk,
    reasons: (reasons || []).map((r) => r.text || r.code || r),
    maskedIp: maskIp(clientIp),
    latencyMs: Math.max(1, latencyMs || Math.round(Math.random() * 2 + 1)),
    engine,
    mode,
    pid,
  };
  recentEvents.unshift(ev);
  if (recentEvents.length > 50) recentEvents.pop();

  if (pid) {
    recordProjectEvent(pid, ev);
  }
  return ev;
}

function computeVerdict(reasons, settings, meta = {}, extra = {}) {
  const isHard = reasons.some((r) => HARD_REASONS.has(r.code));
  const rawRisk = reasons.reduce((sum, r) => sum + (r.weight || 0), 0);
  const risk = isHard ? 100 : Math.min(100, rawRisk);

  let verdict = 'accept';
  if (isHard || risk >= (settings.rejectAt || DEFAULTS.rejectAt)) {
    verdict = 'reject';
  } else if (risk >= (settings.reviewAt || DEFAULTS.reviewAt)) {
    verdict = 'review';
  }

  const isPassive = meta.mode === 'passive';
  const shadowVerdict = verdict;
  if (isPassive) {
    verdict = 'observe';
  }

  const pid = meta.pid || (meta.project && meta.project.pid);

  // Live security telemetry recording
  try {
    const kv = getKv();
    // Global platform metrics (for public landing page proof)
    kv.incr('tr:metrics:total').catch(() => {});
    kv.incr(`tr:metrics:${verdict}`).catch(() => {});
    if (isPassive && shadowVerdict === 'reject') {
      kv.incr('tr:metrics:shadow_reject').catch(() => {});
    }
    for (const r of reasons) {
      kv.incr(`tr:metrics:reason:${r.code}`).catch(() => {});
    }

    // Isolated per-project metrics (for authenticated tenant dashboard)
    if (pid) {
      kv.incr(`tr:p:${pid}:metrics:total`).catch(() => {});
      kv.incr(`tr:p:${pid}:metrics:${verdict}`).catch(() => {});
      if (isPassive && shadowVerdict === 'reject') {
        kv.incr(`tr:p:${pid}:metrics:shadow_reject`).catch(() => {});
      }
      for (const r of reasons) {
        kv.incr(`tr:p:${pid}:metrics:reason:${r.code}`).catch(() => {});
      }
    }

    // Global Sentinel Fleet Ring: track hostile subnets across all projects
    if (shadowVerdict === 'reject' && (meta.clientIp || meta.ip)) {
      const sKey = getSubnetKey(meta.clientIp || meta.ip);
      if (sKey !== 'subnet:loopback' && sKey !== 'subnet:unknown') {
        const nowTs = Date.now();
        const prev = globalThreatRingMemory.get(sKey);
        const nextCount = (prev && nowTs < prev.expiresAt ? prev.count : 0) + 1;
        globalThreatRingMemory.set(sKey, { count: nextCount, expiresAt: nowTs + 600000 });
        kv.incr(`tr:sentinel:ring:${sKey}`, 600)
          .then((cnt) => {
            if (cnt >= 3) {
              kv.hset('tr:sentinel:ring:active', sKey, String(nowTs + 600000)).catch(() => {});
            }
          })
          .catch(() => {});
      }
    }
  } catch {}

  recordLiveEvent({
    action: meta.action || 'API Request Attestation',
    verdict,
    shadowVerdict: isPassive ? shadowVerdict : undefined,
    risk,
    reasons,
    clientIp: meta.clientIp || meta.ip,
    latencyMs: meta.latencyMs || 1,
    engine: isPassive ? 'OBSX (Passive)' : 'OBSX',
    mode: meta.mode || 'enforce',
    pid,
  });

  // Automated Security Incident Dispatch
  if (isPassive && (isHard || risk >= (settings.rejectAt || DEFAULTS.rejectAt)) && reasons.length > 0) {
    const primaryReason = reasons.find((r) => HARD_REASONS.has(r.code)) || reasons[0];
    const pid = meta.pid || (meta.project && meta.project.pid) || 'node';
    const projName = (meta.project && meta.project.name) || pid;

    // Resolve project owner email asynchronously if possible
    (async () => {
      try {
        let ownerEmail = null;
        if (meta.project && meta.project.owner && meta.project.owner !== 'anonymous') {
          const u = await getKv().hgetall(`tr:u:${meta.project.owner}`);
          if (u && u.email) ownerEmail = u.email;
        }
        await mailer.notifyCriticalIncident({
          code: `passive_${primaryReason.code}`,
          title: `[ACTION REQUIRED] Hostile Traffic Detected in Passive Mode: ${primaryReason.code}`,
          detail: `Your OBSX project "${projName}" (${pid}) is operating in PASSIVE MODE. An automated request scoring Risk ${risk} (${primaryReason.code}) was ALLOWED through to prevent disruption. Switch project ${pid} to ENFORCE mode on https://obsx.tech/dashboard.html to immediately block this attack at the edge.`,
          clientIp: meta.clientIp || meta.ip || 'unknown',
          action: meta.action || 'API Request Attestation',
          severity: 'HIGH',
          recipient: ownerEmail,
        });
      } catch {}
    })();
  } else if (!isPassive && isHard && reasons.length > 0) {
    const primaryReason = reasons.find((r) => HARD_REASONS.has(r.code)) || reasons[0];
    mailer.notifyCriticalIncident({
      code: primaryReason.code,
      title: `Critical Intrusion Blocked: ${primaryReason.code}`,
      detail: primaryReason.detail || primaryReason.text || REASONS[primaryReason.code],
      clientIp: meta.clientIp || meta.ip || 'unknown',
      action: meta.action || 'API Request Attestation',
      severity: 'CRITICAL',
    }).catch(() => {});
  }

  return {
    ok: true,
    verdict,
    shadowVerdict: isPassive ? shadowVerdict : undefined,
    allowed: isPassive ? true : verdict !== 'reject',
    mode: meta.mode || 'enforce',
    risk,
    sealed: extra.sealed || 'none',
    ...(extra.customMessage ? { message: extra.customMessage } : {}),
    reasons: reasons.map((r) => ({
      code: r.code,
      weight: r.weight,
      detail: r.detail,
      text: REASONS[r.code] || r.code,
    })),
  };
}

async function getUserNotes(uid) {
  if (!uid || typeof uid !== 'string') return [];
  const kv = getKv();
  const noteIdsRaw = await kv.get(`tr:u:${uid}:notes`);
  const noteIds = noteIdsRaw ? JSON.parse(noteIdsRaw) : [];
  const notes = [];
  for (const nid of noteIds) {
    const raw = await kv.hgetall(`tr:n:${nid}`);
    if (raw && raw.id) {
      notes.push({
        id: raw.id,
        title: raw.title,
        content: raw.content,
        category: raw.category || 'General',
        protection: raw.protection || 'obsx',
        created: Number(raw.created) || Date.now(),
      });
    }
  }
  return notes.sort((a, b) => b.created - a.created);
}

async function createUserNote(uid, noteData = {}) {
  const kv = getKv();
  const nid = `note_${crypto.randomId(8)}`;
  const now = Date.now();
  const safeTitle = typeof noteData.title === 'string' ? noteData.title.slice(0, 120) : 'Untitled Note';
  const safeContent = typeof noteData.content === 'string' ? noteData.content.slice(0, 10000) : '';
  const safeCategory = typeof noteData.category === 'string' ? noteData.category.slice(0, 40) : 'General';
  const safeProtection = noteData.protection === 'advisory' ? 'advisory' : 'obsx';

  const record = {
    id: nid,
    owner: uid,
    title: safeTitle,
    content: safeContent,
    category: safeCategory,
    protection: safeProtection,
    created: String(now),
  };
  await kv.hset(`tr:n:${nid}`, record);
  const noteIdsRaw = await kv.get(`tr:u:${uid}:notes`);
  const noteIds = noteIdsRaw ? JSON.parse(noteIdsRaw) : [];
  noteIds.push(nid);
  await kv.set(`tr:u:${uid}:notes`, JSON.stringify(noteIds));
  return { ...record, created: now };
}

async function deleteUserNote(uid, nid) {
  if (typeof nid !== 'string' || !nid.startsWith('note_')) return false;
  const kv = getKv();
  const note = await kv.hgetall(`tr:n:${nid}`);
  if (!note || note.owner !== uid) return false;
  await kv.del(`tr:n:${nid}`);
  const noteIdsRaw = await kv.get(`tr:u:${uid}:notes`);
  let noteIds = noteIdsRaw ? JSON.parse(noteIdsRaw) : [];
  noteIds = noteIds.filter((id) => id !== nid);
  await kv.set(`tr:u:${uid}:notes`, JSON.stringify(noteIds));
  return true;
}

async function getLiveMetrics() {
  const kv = getKv();
  const total = Number(await kv.get('tr:metrics:total')) || 0;
  const accept = Number(await kv.get('tr:metrics:accept')) || 0;
  const reject = Number(await kv.get('tr:metrics:reject')) || 0;
  const review = Number(await kv.get('tr:metrics:review')) || 0;
  const observe = Number(await kv.get('tr:metrics:observe')) || 0;
  const shadowReject = Number(await kv.get('tr:metrics:shadow_reject')) || 0;

  const topReasons = {};
  for (const code of Object.keys(REASONS)) {
    const cnt = Number(await kv.get(`tr:metrics:reason:${code}`)) || 0;
    if (cnt > 0) topReasons[code] = cnt;
  }

  const effectiveAccept = accept + observe;
  return {
    total,
    breakdown: { accept, reject, review, observe, shadowReject },
    acceptRate: total > 0 ? Math.round((effectiveAccept / total) * 1000) / 10 : 100,
    topReasons,
    timestamp: Date.now(),
  };
}

async function updateProjectSettings(pid, updates = {}) {
  const kv = getKv();
  const project = await loadProject(pid);
  if (!project) return null;

  const allowedOrigins = Array.isArray(updates.origins) ? updates.origins.map(String) : project.settings.origins;
  const newSettings = {
    ...project.settings,
    ...(updates.mode === 'passive' || updates.mode === 'enforce' ? { mode: updates.mode } : {}),
    ...(typeof updates.reviewAt === 'number' ? { reviewAt: updates.reviewAt } : {}),
    ...(typeof updates.rejectAt === 'number' ? { rejectAt: updates.rejectAt } : {}),
    ...(typeof updates.powDifficulty === 'number' ? { powDifficulty: updates.powDifficulty } : {}),
    ...(typeof updates.minDurationMs === 'number' ? { minDurationMs: updates.minDurationMs } : {}),
    ...(typeof updates.maxScore === 'number' ? { maxScore: updates.maxScore } : {}),
    ...(typeof updates.adaptiveCircuitBreaker === 'boolean' ? { adaptiveCircuitBreaker: updates.adaptiveCircuitBreaker } : {}),
    ...(typeof updates.blockOpenAiScrapers === 'boolean' ? { blockOpenAiScrapers: updates.blockOpenAiScrapers } : {}),
    origins: allowedOrigins,
  };

  await kv.hset(`tr:p:${pid}`, 'settings', JSON.stringify(newSettings));
  return { pid, settings: newSettings };
}

async function rotateProjectSecretKey(pid) {
  const kv = getKv();
  const project = await loadProject(pid);
  if (!project) return null;

  const rawProject = await kv.hgetall(`tr:p:${pid}`);
  const oldSkHash = rawProject ? rawProject.secretKeyHash : null;

  const newSecretKey = `sk_${crypto.randomId(24)}`;
  const skHash = crypto.sha256(newSecretKey);

  // Revoke old key mapping atomically if present
  if (oldSkHash) {
    await kv.del(`tr:sk:${oldSkHash}`);
  }

  await kv.set(`tr:sk:${skHash}`, pid);
  await kv.hset(`tr:p:${pid}`, 'secretKeyHash', skHash);
  return { pid, secretKey: newSecretKey };
}

async function deleteProject(pid, ownerUid) {
  if (pid === DEMO.pid) return false;
  const kv = getKv();
  const rawProject = await kv.hgetall(`tr:p:${pid}`);
  if (!rawProject || !rawProject.pid) return false;
  if (rawProject.owner !== ownerUid) return false;

  if (rawProject.publicKey) {
    await kv.del(`tr:pk:${rawProject.publicKey}`);
  }
  if (rawProject.secretKeyHash) {
    await kv.del(`tr:sk:${rawProject.secretKeyHash}`);
  }
  await kv.del(`tr:p:${pid}`);
  if (ownerUid) {
    await kv.hdel(`tr:u:${ownerUid}:projects`, pid);
  }

  // Purge isolated per-project telemetry counters & events
  for (const key of ['total', 'accept', 'reject', 'review', 'observe', 'shadow_reject']) {
    await kv.del(`tr:p:${pid}:metrics:${key}`);
  }
  for (const code of Object.keys(REASONS)) {
    await kv.del(`tr:p:${pid}:metrics:reason:${code}`);
  }
  projectRecentEvents.delete(pid);

  return true;
}

async function getProjectTelemetry(pid) {
  const kv = getKv();
  const total = Number(await kv.get(`tr:p:${pid}:metrics:total`)) || 0;
  const accept = Number(await kv.get(`tr:p:${pid}:metrics:accept`)) || 0;
  const reject = Number(await kv.get(`tr:p:${pid}:metrics:reject`)) || 0;
  const review = Number(await kv.get(`tr:p:${pid}:metrics:review`)) || 0;
  const observe = Number(await kv.get(`tr:p:${pid}:metrics:observe`)) || 0;
  const shadowReject = Number(await kv.get(`tr:p:${pid}:metrics:shadow_reject`)) || 0;

  const topReasons = {};
  for (const code of Object.keys(REASONS)) {
    const cnt = Number(await kv.get(`tr:p:${pid}:metrics:reason:${code}`)) || 0;
    if (cnt > 0) topReasons[code] = cnt;
  }

  const effectiveAccept = accept + observe;
  const projectEvents = getProjectRecentEvents(pid);

  return {
    ok: true,
    pid,
    hasTraffic: total > 0,
    stats: {
      total,
      breakdown: { accept, reject, review, observe, shadowReject },
      acceptRate: total > 0 ? Math.round((effectiveAccept / total) * 1000) / 10 : 100,
      topReasons,
      timestamp: Date.now(),
    },
    recentEvents: projectEvents.slice(0, 20),
    timestamp: Date.now(),
  };
}

async function getLiveTelemetry() {
  const metrics = await getLiveMetrics();
  const kv = getKv();
  const rawPool = await kv.get('tr:vault:pool');
  const pool = rawPool !== null ? Number(rawPool) : 10000;
  const rawDrainedObsx = await kv.get('tr:vault:drained:obsx');
  const rawDrainedAdvisory = await kv.get('tr:vault:drained:advisory');

  return {
    ok: true,
    stats: {
      total: metrics.total,
      breakdown: metrics.breakdown,
      acceptRate: metrics.acceptRate,
      topReasons: metrics.topReasons,
      vault: {
        initialPool: 10000,
        currentPool: pool,
        drainedUnderObsx: Number(rawDrainedObsx) || 0,
        drainedUnderAdvisory: Number(rawDrainedAdvisory) || 0,
        dollarsSavedByObsx: Math.max(0, (Number(rawDrainedAdvisory) || 0) - (Number(rawDrainedObsx) || 0)),
      },
      protectedBy: 'OBSX Security Protocol v2.2.0 (Active)',
      node: 'obsx.tech',
    },
    recentEvents: recentEvents.slice(0, 20),
    timestamp: Date.now(),
  };
}

/**
 * High-Stakes Vault Checkout / Exploit Arena Processor
 * Tests incoming Scratch attack blocks against OBSX vs Traditional Advisory.
 */
async function processVaultDrain({ mode = 'obsx', token, nonce, signals, attackVector, clientIp = '127.0.0.1', proxyHeaders = {}, ua = '', requireBiometrics = false }) {
  const kv = getKv();
  const startTime = Date.now();
  const drainAmount = 500;

  const rawPool = await kv.get('tr:vault:pool');
  let pool = rawPool !== null ? Number(rawPool) : 10000;
  if (isNaN(pool)) {
    pool = 10000;
    await kv.set('tr:vault:pool', String(pool));
  }

  // 1. Advisory Mode (Traditional Advisory model)
  if (mode === 'advisory') {
    let verdict = 'accept';
    let risk = 0;
    let reasons = [];

    if (attackVector === 'empty_signals' || (signals && Object.keys(signals).length === 0)) {
      verdict = 'accept';
      risk = 0;
      reasons = [];
    } else if (attackVector === 'proxy_virtualization') {
      verdict = 'accept';
      risk = 0;
      reasons = [];
    } else if (attackVector === 'zero_jerk_spline') {
      verdict = 'accept';
      risk = 15;
      reasons = [{ code: 'smooth_path', text: 'Slightly even velocity (advisory only)' }];
    } else if (attackVector === 'token_replay') {
      verdict = 'accept';
      risk = 10;
      reasons = [];
    } else if (attackVector === 'bind_tamper') {
      verdict = 'accept';
      risk = 0;
      reasons = [];
    } else if (signals && signals.bot) {
      verdict = 'reject';
      risk = 85;
      reasons = [{ code: 'webdriver', text: 'Navigator webdriver active' }];
    }

    const drained = verdict === 'accept';
    if (drained && pool >= drainAmount) {
      pool -= drainAmount;
      await kv.set('tr:vault:pool', String(pool));
      const curDrained = Number(await kv.get('tr:vault:drained:advisory')) || 0;
      await kv.set('tr:vault:drained:advisory', String(curDrained + drainAmount));
    }

    const latencyMs = Math.max(1, Date.now() - startTime);
    recordLiveEvent({
      action: 'Vault $500 Claim (Advisory)',
      verdict,
      risk,
      reasons,
      clientIp,
      latencyMs,
      engine: 'Advisory',
    });

    return {
      ok: true,
      mode: 'advisory',
      drained,
      amountDrained: drained ? drainAmount : 0,
      vaultRemaining: pool,
      verdict: {
        verdict,
        risk,
        reasons,
        note: drained
          ? 'Exploit Succeeded! Traditional Advisory failed to challenge computation or verify telemetry. $500 drained from vault.'
          : 'Request blocked by advisory rule.',
      },
      latencyMs,
      timestamp: Date.now(),
    };
  }

  // 2. OBSX Mode (Cryptographic Micro-PoW & Attestation)
  const project = await loadProject(DEMO.pid);
  const verifyRes = await verify(project, { token, nonce, ...signals }, { ip: clientIp, proxyHeaders, ua, requireBiometrics });

  const drained = verifyRes.verdict === 'accept';
  if (drained && pool >= drainAmount) {
    pool -= drainAmount;
    await kv.set('tr:vault:pool', String(pool));
    const curDrained = Number(await kv.get('tr:vault:drained:obsx')) || 0;
    await kv.set('tr:vault:drained:obsx', String(curDrained + drainAmount));
  }

  const latencyMs = Math.max(1, Date.now() - startTime);
  recordLiveEvent({
    action: 'Vault $500 Claim (OBSX)',
    verdict: verifyRes.verdict,
    risk: verifyRes.risk,
    reasons: verifyRes.reasons,
    clientIp,
    latencyMs,
    engine: 'OBSX',
  });

  return {
    ok: true,
    mode: 'obsx',
    drained,
    amountDrained: drained ? drainAmount : 0,
    vaultRemaining: pool,
    verdict: {
      ...verifyRes,
      note: drained
        ? 'Genuine human action verified! Micro-PoW solved and natural entropy attested. $500 securely processed.'
        : 'Attack thwarted! Vault protected by OBSX Security Gate.',
    },
    latencyMs,
    timestamp: Date.now(),
  };
}

async function resetVault() {
  const kv = getKv();
  await kv.set('tr:vault:pool', '10000');
  await kv.set('tr:vault:drained:obsx', '0');
  await kv.set('tr:vault:drained:advisory', '0');
  return { ok: true, pool: 10000 };
}

async function getGlobalThreatRing() {
  const kv = getKv();
  const activeMap = (await kv.hgetall('tr:sentinel:ring:active')) || {};
  const now = Date.now();
  const merged = new Map();

  for (const [sKey, entry] of globalThreatRingMemory.entries()) {
    if (now >= entry.expiresAt) {
      globalThreatRingMemory.delete(sKey);
    } else if (entry.count >= 3) {
      merged.set(sKey, { count: entry.count, expiresAt: entry.expiresAt });
    }
  }

  for (const [sKey, expStr] of Object.entries(activeMap)) {
    const exp = Number(expStr) || 0;
    if (now >= exp) {
      await kv.hdel('tr:sentinel:ring:active', sKey).catch(() => {});
    } else if (!merged.has(sKey)) {
      const cnt = Number(await kv.get(`tr:sentinel:ring:${sKey}`)) || 3;
      merged.set(sKey, { count: cnt, expiresAt: exp });
    }
  }

  const activeSubnets = [];
  for (const [sKey, info] of merged.entries()) {
    activeSubnets.push({
      subnet: sKey,
      rejections: info.count,
      expiresAt: info.expiresAt,
      remainingSeconds: Math.max(1, Math.round((info.expiresAt - now) / 1000)),
    });
  }
  return {
    ok: true,
    ringActive: activeSubnets.length > 0,
    isolatedSubnetCount: activeSubnets.length,
    activeSubnets,
    timestamp: now,
  };
}

module.exports = {
  DEFAULTS,
  DEMO,
  KNOWN_BUILDS,
  loadProject,
  projectByPublicKey,
  projectBySecretKey,
  createProject,
  startSession,
  recordSignals,
  verify,
  getUserNotes,
  createUserNote,
  deleteUserNote,
  getLiveMetrics,
  getLiveTelemetry,
  getProjectTelemetry,
  processVaultDrain,
  resetVault,
  getGlobalThreatRing,
  recordLiveEvent,
  updateProjectSettings,
  rotateProjectSecretKey,
  deleteProject,
  getCircuitBreakerStatus: async () => ({ activeVectors: [], allVectors: [] }),
  resetCircuitBreaker: async () => false,
  getSubnetKey,
  isOpenAiScraperUa,
};
