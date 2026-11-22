'use strict';

/**
 * OBSX Security — Multi-Tenant Account & Project Administration
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the OBSX Source-Available License v1.0 (Zone 2) — See LICENSE file.
 * Free for self-hosted internal use; commercial SaaS hosting and competing extraction prohibited.
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

function extractSessionId(cookies, requireHostPrefix = false) {
  if (!cookies || typeof cookies !== 'string') return null;
  // Parse semicolon-separated pairs and fail closed if conflicting/malformed duplicate session cookies appear
  let hostSid = null;
  let hostConflict = false;
  let plainSid = null;
  let plainConflict = false;
  for (const part of cookies.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx <= 0) continue;
    const name = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    const validFormat = /^[A-Za-z0-9_-]{16,128}$/.test(val);
    if (name === '__Host-obsx_session') {
      if (!validFormat || (hostSid && hostSid !== val)) {
        hostConflict = true;
        hostSid = null;
      } else if (!hostConflict) {
        hostSid = val;
      }
    } else if (name === 'obsx_session') {
      if (!validFormat || (plainSid && plainSid !== val)) {
        plainConflict = true;
        plainSid = null;
      } else if (!plainConflict) {
        plainSid = val;
      }
    }
  }
  if (hostConflict) return null;
  if (hostSid) return hostSid;
  if (requireHostPrefix) return null;
  if (plainConflict) return null;
  return plainSid || null;
}

function getSubnetKey(ip) {
  return crypto.getSubnetKey(ip);
}

/**
 * Initiates an email sign-in code flow.
 * Rate limiting is applied per caller subnet and (mailbox, subnet) pair so external callers
 * cannot trigger a 1-hour global mailbox lockout for legitimate users.
 */
async function startEmailAuth(email, clientIp) {
  const kv = getKv();
  const cleaned = cleanEmail(email);
  if (!cleaned) throw new Error('invalid_email');

  const mailboxHash = getNormalizedMailboxKey(cleaned);
  const emailHash = crypto.sha256(cleaned);

  // 1. Subnet-based rate limiting (/24 for IPv4, /48 for IPv6) before per-email lock
  const subnet = getSubnetKey(clientIp);
  const subHash = crypto.sha256(subnet).slice(0, 16);
  const ipKey = `tr:rl:sub:${subHash}`;
  const attempts = await kv.incr(ipKey, 600); // 10 minutes window
  if (attempts > 10) {
    const err = new Error('Too many requests from this network. Please wait a few minutes.');
    err.status = 429;
    throw err;
  }

  // 2. Check hourly ceiling per (mailbox, subnet) pair BEFORE acquiring 45s cooldown lock
  const pairHourlyKey = `tr:cnt:em:${mailboxHash}:${subHash}`;
  const pairExisting = Number((await kv.get(pairHourlyKey)) || 0);
  if (pairExisting >= 6) {
    const err = new Error('Too many verification codes requested for this email. Please try again later.');
    err.status = 429;
    throw err;
  }

  // 2b. Cross-subnet safety valve per mailbox (high enough not to lock out a
  //     legitimate user after small multi-subnet probes, while capping distributed
  //     mailbox bombing and SMTP quota burn).
  const globalMailboxLimit = Math.max(6, Number(process.env.OBSX_OTP_GLOBAL_MAILBOX_LIMIT || 30));
  const globalMailboxKey = `tr:cnt:em:global:${mailboxHash}`;
  const globalMailboxExisting = Number((await kv.get(globalMailboxKey)) || 0);
  if (globalMailboxExisting >= globalMailboxLimit) {
    const err = new Error('Too many verification codes requested for this email. Please try again later.');
    err.status = 429;
    throw err;
  }

  // 3. Atomic (mailbox, subnet) cooldown to prevent parallel inbox bombing across aliases or +tags
  const cdKey = `tr:cd:email:${mailboxHash}:${subHash}`;
  const acquired = await kv.set(cdKey, '1', 'NX', 'EX', 45);
  if (acquired !== 'OK') {
    const err = new Error('Please wait 45 seconds before requesting another code.');
    err.status = 429;
    throw err;
  }

  // Generate secure 6-digit code using CSPRNG
  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = crypto.sha256(`code:${cleaned}:${code}`);

  // Dispatch email via configured mailer BEFORE consuming hourly quota or storing active OTP hash in KV
  let dispatch;
  try {
    dispatch = await mailer.sendVerificationCode(cleaned, code);
  } catch (err) {
    await kv.del(cdKey);
    throw err;
  }
  if (!dispatch || dispatch.ok === false) {
    await kv.del(cdKey);
    const err = new Error((dispatch && dispatch.error) || 'Failed to dispatch verification email.');
    err.status = 503;
    throw err;
  }

  await kv.incr(pairHourlyKey, 3600);
  await kv.incr(globalMailboxKey, 3600);

  // Preserve only the most recently replaced live OTP in a 300s grace slot so rotating subnets
  // cannot churn an in-flight user code, while carrying forward cumulative attempts so resends
  // never reset the brute-force counter.
  const emailKey = `tr:ec:${emailHash}`;
  const graceKey = `tr:ec:grace:${emailHash}`;
  const prevOtp = await kv.hgetall(emailKey);
  const prevTries = Math.max(0, Number((prevOtp && prevOtp.n) || 0));
  let carriedTries = 0;
  if (prevOtp && prevOtp.h && prevTries < 5) {
    carriedTries = prevTries;
    await kv.set(
      graceKey,
      JSON.stringify({ h: prevOtp.h, n: prevTries, exp: Date.now() + 300 * 1000 }),
      'EX',
      300
    );
  } else {
    await kv.del(graceKey);
  }
  // Store new active code with 10-minute TTL and cumulative attempts counter
  await kv.hset(emailKey, {
    h: codeHash,
    n: String(carriedTries),
  });
  await kv.expire(emailKey, 600);
  const isTestEnv = crypto.isTestRuntime();

  return {
    ok: true,
    message: 'A verification code has been dispatched to your email address.',
    devMode: Boolean(dispatch.devMode && isTestEnv),
    ...(dispatch.devMode && isTestEnv ? { devCode: code } : {}),
  };
}

async function verifyEmailAuth(email, code, isHttps = false, opts = {}) {
  const kv = getKv();
  if (opts && opts.clientIp) {
    const verifySubHash = crypto.sha256(getSubnetKey(opts.clientIp)).slice(0, 16);
    const verifyLimit = Math.max(10, Number(process.env.OBSX_VERIFY_SUBNET_LIMIT || 30));
    const verifyAttempts = await kv.incr(`tr:rl:verify:sub:${verifySubHash}`, 600);
    if (verifyAttempts > verifyLimit) {
      const err = new Error('Too many verification attempts from this network. Please wait a few minutes.');
      err.status = 429;
      throw err;
    }
  }
  const cleaned = cleanEmail(email);
  const strCode = String(code !== undefined && code !== null ? code : '').trim();
  if (!cleaned || !/^\d{6}$/.test(strCode)) throw new Error('Invalid code. Must be a 6-digit numeric code.');

  const emailHash = crypto.sha256(cleaned);
  const emailKey = `tr:ec:${emailHash}`;
  const graceKey = `tr:ec:grace:${emailHash}`;
  const stored = await kv.hgetall(emailKey);
  if (!stored || !stored.h) {
    throw new Error('Code expired or invalid. Please request a new code.');
  }

  // Atomic counter increment to eliminate concurrent check-then-act race windows
  const tries = await kv.hincrby(emailKey, 'n', 1);
  if (tries > 5) {
    await kv.del(emailKey, graceKey);
    throw new Error('Too many incorrect attempts. Please request a new code.');
  }

  const candidateHash = crypto.sha256(`code:${cleaned}:${strCode}`);
  let matchedHash = crypto.safeEqual(candidateHash, stored.h) ? stored.h : null;
  if (!matchedHash) {
    const graceRaw = await kv.get(graceKey);
    if (graceRaw) {
      try {
        const parsedGrace = JSON.parse(graceRaw);
        const graceTries = Number((parsedGrace && parsedGrace.n) || 0);
        if (parsedGrace && typeof parsedGrace.h === 'string' && graceTries < 5) {
          if (crypto.safeEqual(candidateHash, parsedGrace.h)) {
            matchedHash = parsedGrace.h;
          } else {
            const nextGraceTries = graceTries + 1;
            const remMs = Number(parsedGrace.exp) ? Number(parsedGrace.exp) - Date.now() : 300 * 1000;
            if (nextGraceTries >= 5 || remMs <= 0) {
              await kv.del(graceKey);
            } else {
              await kv.set(
                graceKey,
                JSON.stringify({ h: parsedGrace.h, n: nextGraceTries, exp: parsedGrace.exp || (Date.now() + remMs) }),
                'EX',
                Math.max(1, Math.ceil(remMs / 1000))
              );
            }
          }
        } else {
          await kv.del(graceKey);
        }
      } catch {
        await kv.del(graceKey);
      }
    }
  }
  if (!matchedHash) {
    throw new Error('Invalid code.');
  }

  // Atomic single-use OTP claim prevents parallel double-spend of the same 6-digit code
  const claimKey = `tr:ec:used:${emailHash}:${matchedHash.slice(0, 16)}`;
  const claimed = await kv.set(claimKey, '1', 'NX', 'EX', 600);
  if (claimed !== 'OK') {
    throw new Error('Code expired or invalid. Please request a new code.');
  }

  // Successful verification -> purge active code and grace slot
  await kv.del(emailKey, graceKey);

  // Resolve or atomically create user account
  const termsVersion =
    opts && typeof opts.termsVersion === 'string' && opts.termsVersion.trim()
      ? opts.termsVersion.trim().slice(0, 64)
      : 'v2.3.0-dual';
  const acceptMeta =
    opts && opts.termsAccepted === true
      ? { termsAcceptedAt: String(Date.now()), termsVersion }
      : {};
  const uKey = `tr:ue:${emailHash}`;
  let uid = await kv.get(uKey);
  if (!uid) {
    const candidateUid = `u_${crypto.randomId(12)}`;
    await kv.hset(`tr:u:${candidateUid}`, {
      email: cleaned,
      created: String(Date.now()),
      ...acceptMeta,
    });
    const won = await kv.set(uKey, candidateUid, 'NX');
    if (won === 'OK') {
      uid = candidateUid;
    } else {
      await kv.del(`tr:u:${candidateUid}`);
      uid = await kv.get(uKey);
    }
  } else if (acceptMeta.termsAcceptedAt) {
    await kv.hset(`tr:u:${uid}`, acceptMeta);
  }

  // Create session & index by user for eager cross-device revocation on account deletion
  const SESSION_TTL_SEC = 7 * 86400;
  const SESSION_TTL_MS = SESSION_TTL_SEC * 1000;
  const sid = crypto.randomId(32);
  const sidHash = crypto.sha256(sid);
  const nowTs = Date.now();
  await kv.set(`tr:auth:${sidHash}`, uid, 'EX', SESSION_TTL_SEC);
  const sessIdxKey = `tr:u:${uid}:sessions`;
  const existingSess = await kv.hgetall(sessIdxKey);
  if (existingSess && typeof existingSess === 'object') {
    const expiredSids = Object.entries(existingSess)
      .filter(([, ts]) => !Number.isFinite(Number(ts)) || Number(ts) <= 0 || Number(ts) + SESSION_TTL_MS <= nowTs)
      .map(([k]) => k);
    if (expiredSids.length > 0) {
      await kv.hdel(sessIdxKey, ...expiredSids);
    }
  }
  await kv.hset(sessIdxKey, { [sidHash]: String(nowTs) });
  await kv.expire(sessIdxKey, SESSION_TTL_SEC);

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

async function hydrateUserProjects(kv, uid) {
  const projMap = (await kv.hgetall(`tr:u:${uid}:projects`)) || {};
  const projects = [];
  for (const pid of Object.keys(projMap)) {
    const p = await kv.hgetall(`tr:p:${pid}`);
    if (p && p.pid) {
      let parsedSettings = {};
      if (p.settings) {
        try {
          parsedSettings = typeof p.settings === 'string' ? JSON.parse(p.settings) : p.settings;
        } catch (_) {
          parsedSettings = {};
        }
      }
      projects.push({
        pid: p.pid,
        name: p.name,
        publicKey: p.publicKey,
        created: Number(p.created) || Date.now(),
        settings: parsedSettings,
      });
    }
  }
  return projects;
}

async function getSessionUser(req, isHttps = false) {
  const kv = getKv();
  const cookies = (req && req.headers ? req.headers.cookie : '') || '';
  const sid = extractSessionId(cookies, Boolean(isHttps));
  if (!sid) return null;
  const sidHash = crypto.sha256(sid);
  const uid = await kv.get(`tr:auth:${sidHash}`);
  if (!uid) return null;
  const user = await kv.hgetall(`tr:u:${uid}`);
  if (!user || !user.email) return null;

  const projects = await hydrateUserProjects(kv, uid);

  return {
    uid,
    email: user.email,
    created: Number(user.created) || Date.now(),
    projects,
  };
}

async function deleteUserSession(req, isHttps = false) {
  const kv = getKv();
  const cookies = (req && req.headers ? req.headers.cookie : '') || '';
  const sid = extractSessionId(cookies, Boolean(isHttps));
  if (sid) {
    const sidHash = crypto.sha256(sid);
    const uid = await kv.get(`tr:auth:${sidHash}`);
    await kv.del(`tr:auth:${sidHash}`);
    if (uid) {
      await kv.hdel(`tr:u:${uid}:sessions`, sidHash);
    }
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

async function exportUserData(uid) {
  if (!uid || typeof uid !== 'string') return null;
  const kv = getKv();
  const user = await kv.hgetall(`tr:u:${uid}`);
  if (!user || !user.email) return null;
  const core = require('./core');
  const projects = await hydrateUserProjects(kv, uid);
  const notes = await core.getUserNotes(uid);
  return {
    exportedAt: new Date().toISOString(),
    account: {
      uid,
      email: user.email,
      created: Number(user.created) || Date.now(),
      termsAcceptedAt: user.termsAcceptedAt ? Number(user.termsAcceptedAt) : null,
      termsVersion: user.termsVersion || null,
    },
    projects,
    notes,
  };
}

async function deleteUserAccount(uid, req = null, isHttps = false) {
  if (!uid || typeof uid !== 'string') return { ok: false };
  const kv = getKv();
  const user = await kv.hgetall(`tr:u:${uid}`);
  if (!user || !user.email) return { ok: false };
  const core = require('./core');
  const emailHash = crypto.sha256(user.email);

  const projMap = (await kv.hgetall(`tr:u:${uid}:projects`)) || {};
  for (const pid of Object.keys(projMap)) {
    await core.deleteProject(pid, uid);
  }
  await kv.del(`tr:u:${uid}:projects`);
  const sessMap = (await kv.hgetall(`tr:u:${uid}:sessions`)) || {};
  const sessionAuthKeys = Object.keys(sessMap).map((sidHash) => `tr:auth:${sidHash}`);
  if (sessionAuthKeys.length > 0) {
    await kv.del(...sessionAuthKeys);
  }
  await kv.del(`tr:u:${uid}:sessions`);
  await core.purgeUserNotes(uid);
  await kv.del(`tr:ue:${emailHash}`);
  await kv.del(`tr:ec:${emailHash}`, `tr:ec:grace:${emailHash}`);
  await kv.del(`tr:u:${uid}`);
  const cleared = await deleteUserSession(req || {}, Boolean(isHttps));
  return { ok: true, sessionCookie: cleared.sessionCookie };
}

module.exports = {
  startEmailAuth,
  verifyEmailAuth,
  getSessionUser,
  deleteUserSession,
  sendUserSecurityAlert,
  exportUserData,
  deleteUserAccount,
  cleanEmail,
  getNormalizedMailboxKey,
  SESSION_COOKIE,
  HOST_SESSION_COOKIE,
};
