'use strict';

/**
 * OBSX Security — Multi-Tenant Account & Project Administration
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 (ELv2) — See LICENSE file.
 * Free for self-hosted and internal use; commercial SaaS hosting and snippet extraction prohibited.
 */

const crypto = require('./crypto');
const { getKv } = require('./kv');
const mailer = require('./mailer');

const SESSION_COOKIE = 'obsx_session';
const HOST_SESSION_COOKIE = '__Host-obsx_session';

function cleanEmail(v) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  // NFKC normalization reduces compatibility characters to canonical forms
  const e = String(v).normalize('NFKC').trim().toLowerCase();
  if (e.length > 254) return null;
  // Strict ASCII format prevents IDN homoglyphs (e.g. Cyrillic 'а' vs Latin 'a')
  const validFormat = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  return validFormat.test(e) ? e : null;
}

function getNormalizedMailboxKey(email) {
  if (!email || !email.includes('@')) return crypto.sha256(email || '');
  const [localPart, domain] = email.split('@');
  // Strip sub-addressing (+tag) to neutralize mailbox flooding
  let baseLocal = localPart.split('+')[0];
  const lowerDomain = (domain || '').toLowerCase().trim();
  // Strip dots for Gmail and Google Workspace domains (dot-insensitive MTAs)
  if (lowerDomain === 'gmail.com' || lowerDomain === 'googlemail.com') {
    baseLocal = baseLocal.replace(/\./g, '');
  }
  return crypto.sha256(`${baseLocal}@${lowerDomain}`);
}

function extractSessionId(cookies) {
  if (!cookies) return null;
  // Strict RFC 6265bis precedence: __Host- cookie MUST take priority over plain cookie
  // Defeats cookie-tossing attacks from compromised subdomains
  const hostMatch = cookies.match(/__Host-obsx_session=([A-Za-z0-9_-]+)/);
  if (hostMatch) return hostMatch[1];
  const plainMatch = cookies.match(/(?:^|;\s*)obsx_session=([A-Za-z0-9_-]+)/);
  if (plainMatch) return plainMatch[1];
  return null;
}

function getSubnetKey(ip) {
  const cleanIp = String(ip || '').trim().toLowerCase();
  if (cleanIp.includes(':')) {
    // IPv6: Group by /48 subscriber allocation (first 3 hextets) to defeat /64 subnet hopping
    const parts = cleanIp.split(':').filter(Boolean);
    const prefix = parts.slice(0, 3).join(':');
    return `ipv6:${prefix}`;
  }
  // IPv4: Group by /24 subnet (first 3 octets)
  const parts = cleanIp.split('.');
  if (parts.length === 4) {
    return `ipv4:${parts.slice(0, 3).join('.')}`;
  }
  return `ip:${cleanIp}`;
}

/**
 * Initiates an email sign-in code flow.
 * Rate limiting is strictly applied to caller IP subnet to prevent global email lockout denial of service.
 * Per-email cooldown (45s) prevents malicious inbox bombing.
 */
async function startEmailAuth(email, clientIp) {
  const kv = getKv();
  const cleaned = cleanEmail(email);
  if (!cleaned) throw new Error('invalid_email');

  const mailboxHash = getNormalizedMailboxKey(cleaned);
  const emailHash = crypto.sha256(cleaned);

  // 1. Subnet-based rate limiting (/24 for IPv4, /48 for IPv6) before per-email lock
  const subnet = getSubnetKey(clientIp);
  const ipKey = `tr:rl:sub:${crypto.sha256(subnet).slice(0, 16)}`;
  const attempts = await kv.incr(ipKey, 600); // 10 minutes window
  if (attempts > 10) {
    const err = new Error('Too many requests from this network. Please wait a few minutes.');
    err.status = 429;
    throw err;
  }

  // 2. Atomic per-mailbox cooldown to prevent parallel inbox bombing (45s) across aliases or +tags
  const cdKey = `tr:cd:email:${mailboxHash}`;
  const acquired = await kv.set(cdKey, '1', 'NX', 'EX', 45);
  if (acquired !== 'OK') {
    const err = new Error('Please wait 45 seconds before requesting another code.');
    err.status = 429;
    throw err;
  }

  // 3. Per-mailbox hourly ceiling (Max 6 codes/hour across aliases or +tags)
  const hourlyKey = `tr:cnt:email:${mailboxHash}`;
  const emailHourlyAttempts = await kv.incr(hourlyKey, 3600);
  if (emailHourlyAttempts > 6) {
    const err = new Error('Too many verification codes requested for this email. Please try again later.');
    err.status = 429;
    throw err;
  }

  // Generate secure 6-digit code using CSPRNG
  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = crypto.sha256(`code:${cleaned}:${code}`);

  // Store code with 10-minute TTL and max 5 attempts counter
  const emailKey = `tr:ec:${emailHash}`;
  await kv.hset(emailKey, {
    h: codeHash,
    n: '0',
  });
  await kv.expire(emailKey, 600);

  // Dispatch email via configured mailer (SMTP / iCloud custom domain or dev logger)
  const dispatch = await mailer.sendVerificationCode(cleaned, code);
  const isTestEnv = crypto.isTestRuntime();

  return {
    ok: true,
    message: 'A verification code has been dispatched to your email address.',
    devMode: Boolean(dispatch.devMode && isTestEnv),
    ...(dispatch.devMode && isTestEnv ? { devCode: code } : {}),
  };
}

async function verifyEmailAuth(email, code, isHttps = false) {
  const kv = getKv();
  const cleaned = cleanEmail(email);
  const strCode = String(code !== undefined && code !== null ? code : '').trim();
  if (!cleaned || !/^\d{6}$/.test(strCode)) throw new Error('Invalid code. Must be a 6-digit numeric code.');

  const emailKey = `tr:ec:${crypto.sha256(cleaned)}`;
  const stored = await kv.hgetall(emailKey);
  if (!stored || !stored.h) {
    throw new Error('Code expired or invalid. Please request a new code.');
  }

  // Atomic counter increment to eliminate concurrent check-then-act race windows
  const tries = await kv.hincrby(emailKey, 'n', 1);
  if (tries > 5) {
    await kv.del(emailKey);
    throw new Error('Too many incorrect attempts. Please request a new code.');
  }

  const candidateHash = crypto.sha256(`code:${cleaned}:${strCode}`);
  if (!crypto.safeEqual(candidateHash, stored.h)) {
    throw new Error('Invalid code.');
  }

  // Successful verification -> purge active code
  await kv.del(emailKey);

  // Resolve or create user account
  const uKey = `tr:ue:${crypto.sha256(cleaned)}`;
  let uid = await kv.get(uKey);
  if (!uid) {
    uid = `u_${crypto.randomId(12)}`;
    await kv.set(uKey, uid);
    await kv.hset(`tr:u:${uid}`, {
      email: cleaned,
      created: String(Date.now()),
    });
  }

  // Create session
  const sid = crypto.randomId(32);
  const sidHash = crypto.sha256(sid);
  await kv.set(`tr:auth:${sidHash}`, uid, 'EX', 7 * 86400);

  const cookieName = isHttps ? HOST_SESSION_COOKIE : SESSION_COOKIE;
  const secureFlag = isHttps ? '; Secure' : '';
  const sessionCookie = `${cookieName}=${sid}; Path=/; HttpOnly; SameSite=Lax${secureFlag}; Max-Age=604800`;

  return {
    uid,
    email: cleaned,
    sessionCookie,
    sid,
  };
}

async function getSessionUser(req) {
  const kv = getKv();
  const cookies = (req && req.headers ? req.headers.cookie : '') || '';
  const sid = extractSessionId(cookies);
  if (!sid) return null;
  const sidHash = crypto.sha256(sid);
  const uid = await kv.get(`tr:auth:${sidHash}`);
  if (!uid) return null;
  const user = await kv.hgetall(`tr:u:${uid}`);
  if (!user || !user.email) return null;

  // Retrieve user projects
  const projMap = (await kv.hgetall(`tr:u:${uid}:projects`)) || {};
  const projects = [];
  for (const pid of Object.keys(projMap)) {
    const p = await kv.hgetall(`tr:p:${pid}`);
    if (p && p.pid) {
      projects.push({
        pid: p.pid,
        name: p.name,
        publicKey: p.publicKey,
        created: Number(p.created) || Date.now(),
        settings: p.settings ? (typeof p.settings === 'string' ? JSON.parse(p.settings) : p.settings) : {},
      });
    }
  }

  return {
    uid,
    email: user.email,
    created: Number(user.created) || Date.now(),
    projects,
  };
}

async function deleteUserSession(req) {
  const kv = getKv();
  const cookies = (req && req.headers ? req.headers.cookie : '') || '';
  const sid = extractSessionId(cookies);
  if (sid) {
    const sidHash = crypto.sha256(sid);
    await kv.del(`tr:auth:${sidHash}`);
  }
  return {
    sessionCookie: [
      `${HOST_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`,
      `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    ],
  };
}

async function sendUserSecurityAlert(uid, alertDetails) {
  const kv = getKv();
  const user = await kv.hgetall(`tr:u:${uid}`);
  if (!user || !user.email) throw new Error('User not found');
  return mailer.sendSecurityAlert(user.email, alertDetails);
}

module.exports = {
  startEmailAuth,
  verifyEmailAuth,
  getSessionUser,
  deleteUserSession,
  sendUserSecurityAlert,
  cleanEmail,
  getNormalizedMailboxKey,
  SESSION_COOKIE,
  HOST_SESSION_COOKIE,
};
