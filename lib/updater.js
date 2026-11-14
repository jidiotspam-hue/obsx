'use strict';

/**
 * OBSX Self-Healing Upstream Auto-Updater & License Integrity Verifier
 *
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 + OBSX Zone 2 Terms — See LICENSE file.
 *
 * Ensures that any local or self-hosted OBSX node stays synchronized with
 * the official upstream repository (https://github.com/jidiotspam-hue/obsx)
 * and exposes cryptographic code-tree and LICENSE attestation so modified or
 * stale local forks are immediately identifiable.
 */

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const {
  canon,
  hmac,
  safeEqual,
  parseCanonicalIp,
  getSubnetKey: getCanonicalSubnetKey,
} = require('./crypto');

const ROOT_DIR = path.resolve(__dirname, '..');
const LICENSE_STATE_FILE = path.join(ROOT_DIR, '.obsx-license-state.json');
const UPSTREAM_REPO = process.env.OBSX_UPSTREAM_REPO || 'jidiotspam-hue/obsx';
const UPSTREAM_BRANCH = process.env.OBSX_UPSTREAM_BRANCH || 'main';
const DEFAULT_INTERVAL_MS = Number(process.env.OBSX_UPDATE_INTERVAL_MS) || 5 * 60 * 1000;

const VALID_UPSTREAM_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const VALID_UPSTREAM_BRANCH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$/;
const ALLOWED_GITHUB_HOSTS = new Set([
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com',
  'codeload.github.com',
]);
const MAX_FETCH_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const MAX_CLOUD_RING_SUBNETS = 500;
const MAX_CLOUD_RING_TTL_SEC = 3600;

const CORE_WATCH_FILES = [
  'LICENSE',
  'lib/core.js',
  'lib/telemetry.js',
  'lib/crypto.js',
  'lib/accounts.js',
  'lib/botshield.js',
  'lib/kv.js',
  'lib/mailer.js',
  'lib/updater.js',
  'server.js',
];

const CRITICAL_INTEGRITY_FILES = [
  'LICENSE',
  'lib/core.js',
  'lib/botshield.js',
  'lib/updater.js',
];

const SYNC_ASSET_FILES = [
  ...CORE_WATCH_FILES,
  'package.json',
  'lib/index.js',
  'src/tracer.js',
  'public/dashboard.js',
  'public/index.html',
  'public/dram-dark.jpg',
  'public/dram-light.jpg',
  'public/dram-stick.svg',
];
const SYNC_ASSET_SET = new Set(SYNC_ASSET_FILES);

const BINARY_EXT_RE = /\.(jpg|jpeg|png|gif|ico|webp|woff2?|eot|ttf|bin)$/i;
const FULL_SHA_RE = /^[0-9a-f]{40}$/i;
const HEX_SHA256_RE = /^[0-9a-f]{64}$/i;
const GIT_CACHE_TTL_MS = 15000;

let lastCheckTime = null;
let lastUpdateStatus = 'initialized';
let upstreamCommitCache = null;
let updateTimer = null;
let updateInProgress = false;

const fileHashCache = new Map();
const pkgVersionCache = new Map();
const licenseStateCache = new Map();
const gitInfoCache = new Map();
const gitDriftCache = new Map();

function invalidateGitCaches(rootDir) {
  fileHashCache.clear();
  gitInfoCache.delete(rootDir);
  const prefix = `${rootDir}:`;
  for (const key of gitDriftCache.keys()) {
    if (key === rootDir || key.startsWith(prefix)) {
      gitDriftCache.delete(key);
    }
  }
}

function readTopStashOid(runSync, rootDir) {
  try {
    return runSync('git', ['rev-parse', '--verify', 'stash@{0}'], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    })
      .toString()
      .trim();
  } catch (_) {
    return null;
  }
}

function hasGitCommit(runSync, rootDir, oid) {
  if (!oid) return false;
  try {
    runSync('git', ['cat-file', '-e', `${oid}^{commit}`], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    });
    return true;
  } catch (_) {
    return false;
  }
}

function restoreStashedEdits(runSync, rootDir, stashOid) {
  try {
    runSync('git', ['stash', 'apply', stashOid], { cwd: rootDir, timeout: 10000 });
  } catch (_) {
    const curStashOid = readTopStashOid(runSync, rootDir);
    const stashPreserved = curStashOid === stashOid || hasGitCommit(runSync, rootDir, stashOid);
    if (stashPreserved) {
      try {
        runSync('git', ['reset', '--hard', 'HEAD'], { cwd: rootDir, timeout: 5000 });
      } catch (_) {}
    }
    return { restored: false, stashPreserved };
  }

  // Drop only when stash@{0} is still ours; drop errors must never discard restored edits.
  if (readTopStashOid(runSync, rootDir) === stashOid) {
    try {
      runSync('git', ['stash', 'drop', 'stash@{0}'], { cwd: rootDir, timeout: 5000 });
    } catch (_) {}
  }
  return { restored: true, stashPreserved: false };
}

function isReadableRegularFile(fullPath) {
  try {
    const st = fs.statSync(fullPath);
    if (!st.isFile()) return false;
    fs.accessSync(fullPath, fs.constants.R_OK);
    return true;
  } catch (_) {
    return false;
  }
}

function hashBufferForAsset(relPath, buf) {
  if (BINARY_EXT_RE.test(relPath)) {
    return crypto.createHash('sha256').update(buf).digest('hex');
  }
  const normalized = buf.toString('utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(normalized, 'utf8')).digest('hex');
}

function hashFileSha256(relPath, rootDir = ROOT_DIR) {
  const full = path.join(rootDir, relPath);
  try {
    const st = fs.statSync(full);
    if (!st.isFile()) {
      fileHashCache.delete(full);
      return null;
    }
    const cached = fileHashCache.get(full);
    if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
      return cached.hash;
    }
    const buf = fs.readFileSync(full);
    // Normalize CRLF -> LF on text assets to prevent false-positive drift across checkouts
    const hash = hashBufferForAsset(relPath, buf);
    fileHashCache.set(full, { mtimeMs: st.mtimeMs, size: st.size, hash });
    return hash;
  } catch (_) {
    fileHashCache.delete(full);
    return null;
  }
}

function computeTreeFingerprint(rootDir = ROOT_DIR) {
  const h = crypto.createHash('sha256');
  for (const rel of CORE_WATCH_FILES) {
    const fileHash = hashFileSha256(rel, rootDir) || 'missing';
    h.update(`${rel}:${fileHash}\n`);
  }
  return h.digest('hex').slice(0, 16);
}

function getPkgVersion(rootDir = ROOT_DIR) {
  const pkgPath = path.join(rootDir, 'package.json');
  try {
    const st = fs.statSync(pkgPath);
    const cached = pkgVersionCache.get(pkgPath);
    if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
      return cached.version;
    }
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    if (pkg && typeof pkg.version === 'string' && pkg.version) {
      pkgVersionCache.set(pkgPath, { mtimeMs: st.mtimeMs, size: st.size, version: pkg.version });
      return pkg.version;
    }
  } catch (_) {
    pkgVersionCache.delete(pkgPath);
  }
  return '2.2.1';
}

function readLicenseState(statePath = LICENSE_STATE_FILE) {
  try {
    const st = fs.statSync(statePath);
    if (!st.isFile()) {
      licenseStateCache.delete(statePath);
      return { corrupt: true };
    }
    const cached = licenseStateCache.get(statePath);
    if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size) {
      return cached.value;
    }
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    const valid = Boolean(
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      typeof parsed.acceptedHash === 'string' &&
      HEX_SHA256_RE.test(parsed.acceptedHash)
    );
    const value = valid ? parsed : { corrupt: true };
    licenseStateCache.set(statePath, { mtimeMs: st.mtimeMs, size: st.size, value });
    return value;
  } catch (err) {
    licenseStateCache.delete(statePath);
    if (err && err.code === 'ENOENT') return null;
    return { corrupt: true };
  }
}

function getLicenseStatus(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const env = opts.env || process.env;
  const statePath = opts.statePath || env.OBSX_LICENSE_STATE_FILE || path.join(rootDir, '.obsx-license-state.json');

  const licenseSha256 = hashFileSha256('LICENSE', rootDir);
  const missingCriticalFiles = CRITICAL_INTEGRITY_FILES.filter((rel) => {
    if (rel === 'LICENSE') return !licenseSha256;
    return !isReadableRegularFile(path.join(rootDir, rel));
  });
  const saved = readLicenseState(statePath);

  const acceptedViaEnv = env.OBSX_ACCEPT_LICENSE === 'true';
  const enforceAcceptance = env.OBSX_ENFORCE_LICENSE_ACCEPTANCE === 'true';
  const savedHash = saved && !saved.corrupt ? saved.acceptedHash.toLowerCase() : null;
  const matchesCurrentLicense = Boolean(licenseSha256 && savedHash && savedHash === licenseSha256);
  const accepted = Boolean(licenseSha256 && (acceptedViaEnv || matchesCurrentLicense));
  const licenseChanged = Boolean(licenseSha256 && savedHash && savedHash !== licenseSha256);

  let safeMode = false;
  let safeModeReason = null;
  if (missingCriticalFiles.length > 0) {
    safeMode = true;
    safeModeReason = !licenseSha256 ? 'missing_license_file' : 'missing_critical_files';
  } else if (saved && saved.corrupt && enforceAcceptance) {
    safeMode = true;
    safeModeReason = 'corrupt_license_state';
  } else if (enforceAcceptance && !accepted) {
    safeMode = true;
    safeModeReason = licenseChanged ? 'license_terms_updated' : 'license_acceptance_required';
  }

  return {
    ok: !safeMode,
    termsPath: 'LICENSE',
    licenseSha256,
    safeMode,
    safeModeReason,
    missingCriticalFiles,
    accepted,
    acceptedAt: matchesCurrentLicense ? (saved.acceptedAt || null) : null,
    acceptedBy: matchesCurrentLicense ? (saved.acceptedBy || null) : null,
    acceptedVia: accepted ? (acceptedViaEnv ? 'env' : 'state_file') : null,
    licenseChanged,
    enforceAcceptance,
    policy: {
      termsVersion: 'v2.2.0-dual',
      grandfatherCutoff: '2026-11-15',
      zones: {
        zone1: 'MIT',
        zone2: 'Elastic-2.0 + OBSX Zone 2 Terms',
      },
    },
  };
}

function acceptLicenseTerms(metadata = {}, options = {}) {
  const meta = metadata && typeof metadata === 'object' ? metadata : {};
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const env = opts.env || process.env;
  const statePath = opts.statePath || env.OBSX_LICENSE_STATE_FILE || path.join(rootDir, '.obsx-license-state.json');

  const licenseSha256 = hashFileSha256('LICENSE', rootDir);
  if (!licenseSha256) {
    return { ok: false, error: 'missing_license_file' };
  }
  const acceptedBy = typeof meta.acceptedBy === 'string' && meta.acceptedBy.trim()
    ? meta.acceptedBy.trim().slice(0, 120)
    : 'operator';
  const payload = {
    acceptedHash: licenseSha256,
    acceptedAt: new Date().toISOString(),
    termsVersion: 'v2.2.0-dual',
    acceptedBy,
  };
  const tmpPath = `${statePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.mkdirSync(path.dirname(statePath), { recursive: true });
    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, statePath);
    licenseStateCache.delete(statePath);
  } catch (_) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch (_) {}
    return { ok: false, error: 'license_state_write_failed', statusCode: 500 };
  }
  const status = getLicenseStatus({ rootDir, statePath, env });
  return { ...status, ok: true, saved: true };
}

function getGitInfo(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const fresh = Boolean(opts.fresh);
  const runSync = opts.execFileSync || execFileSync;
  const useCache = !fresh && !opts.execFileSync;

  const cached = useCache ? gitInfoCache.get(rootDir) : null;
  if (cached && Date.now() - cached.at < GIT_CACHE_TTL_MS) {
    return cached.value;
  }

  let value;
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));
  try {
    const commit = runSync('git', ['rev-parse', 'HEAD'], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();
    const statusOut = runSync('git', ['status', '--porcelain', '--untracked-files=no'], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();
    value = {
      isGitRepo: true,
      commit,
      shortCommit: commit.slice(0, 7),
      dirty: statusOut.length > 0 && !hasSentinel,
      edition: hasSentinel ? 'enterprise-sentinel' : statusOut.length > 0 ? 'modified-local' : 'official',
    };
  } catch (_) {
    value = {
      isGitRepo: false,
      commit: 'standalone',
      shortCommit: 'local',
      dirty: false,
      edition: hasSentinel ? 'enterprise-sentinel' : 'standalone',
    };
  }
  if (useCache) {
    gitInfoCache.set(rootDir, { at: Date.now(), value });
  }
  return value;
}

function getSystemVersionInfo(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const env = opts.env || process.env;
  const pkgVersion = getPkgVersion(rootDir);
  const git = getGitInfo({ rootDir, fresh: Boolean(opts.fresh) });
  const treeHash = computeTreeFingerprint(rootDir);
  const sdkHash = (hashFileSha256('public/obsx.min.js', rootDir) || '').slice(0, 16);
  const licenseStatus = getLicenseStatus({ rootDir, statePath: opts.statePath, env });

  return {
    ok: !licenseStatus.safeMode,
    product: 'OBSX Security Gate',
    version: pkgVersion,
    edition: git.edition,
    commit: git.commit,
    shortCommit: git.shortCommit,
    dirtyWorkingTree: git.dirty,
    safeMode: licenseStatus.safeMode,
    safeModeReason: licenseStatus.safeModeReason,
    engineFingerprint: treeHash,
    sdkFingerprint: sdkHash,
    licenseFingerprint: licenseStatus.licenseSha256 ? licenseStatus.licenseSha256.slice(0, 16) : null,
    licensePolicy: licenseStatus.policy,
    upstream: resolveUpstreamTarget({ env }).ok ? resolveUpstreamTarget({ env }).repo : 'jidiotspam-hue/obsx',
    autoUpdate: {
      enabled: env.OBSX_AUTO_UPDATE === 'true',
      httpSyncEnabled: env.OBSX_HTTP_SYNC === 'true',
      autoRestartEnabled: env.OBSX_AUTO_RESTART === 'true',
      unverifiedAllowed: env.OBSX_ALLOW_UNVERIFIED_UPDATES === 'true',
      lastCheckTime,
      status: lastUpdateStatus,
      latestUpstreamCommit: upstreamCommitCache,
    },
    timestamp: Date.now(),
  };
}

function isValidUpstreamRepo(repo) {
  if (typeof repo !== 'string' || !VALID_UPSTREAM_REPO_RE.test(repo)) return false;
  const parts = repo.split('/');
  if (parts.length !== 2) return false;
  return !parts.some((seg) => !seg || seg === '.' || seg === '..' || seg.includes('..'));
}

function isValidUpstreamBranch(branch) {
  if (typeof branch !== 'string' || !VALID_UPSTREAM_BRANCH_RE.test(branch)) return false;
  if (
    branch.startsWith('-') ||
    branch.startsWith('.') ||
    branch.startsWith('/') ||
    branch.endsWith('/') ||
    branch.endsWith('.') ||
    branch.endsWith('.lock') ||
    branch.includes('..') ||
    branch.includes('//') ||
    branch.includes('@{') ||
    branch.includes('\\') ||
    /[\s\x00-\x1f\x7f]/.test(branch)
  ) {
    return false;
  }
  return true;
}

function resolveUpstreamTarget(opts = {}, env = process.env) {
  const repo = String(opts.repo !== undefined ? opts.repo : (env.OBSX_UPSTREAM_REPO || UPSTREAM_REPO || 'jidiotspam-hue/obsx')).trim();
  const branch = String(opts.branch !== undefined ? opts.branch : (env.OBSX_UPSTREAM_BRANCH || UPSTREAM_BRANCH || 'main')).trim();
  if (!isValidUpstreamRepo(repo) || !isValidUpstreamBranch(branch)) {
    return { ok: false, error: 'invalid_upstream_config' };
  }
  return { ok: true, repo, branch };
}

function validateRemoteUrl(rawUrl, opts = {}) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch (_) {
    throw new Error('Invalid remote URL');
  }
  if (u.username || u.password) {
    throw new Error('Embedded URL credentials are not allowed');
  }
  const allowInsecureLocal =
    opts.allowInsecureLocal === true &&
    u.protocol === 'http:' &&
    (u.hostname === '127.0.0.1' || u.hostname === '::1');
  if (u.protocol !== 'https:' && !allowInsecureLocal) {
    throw new Error(`Disallowed URL scheme: ${u.protocol}`);
  }
  const host = u.hostname.toLowerCase();
  const allowedHosts = opts.allowedHosts instanceof Set
    ? opts.allowedHosts
    : Array.isArray(opts.allowedHosts)
      ? new Set(opts.allowedHosts.map((h) => String(h).toLowerCase()))
      : ALLOWED_GITHUB_HOSTS;
  if (!allowedHosts.has(host)) {
    throw new Error(`Disallowed upstream host: ${host}`);
  }
  if (net.isIP(host) !== 0 && !opts.allowIpLiteral) {
    throw new Error('Direct IP literals are disallowed');
  }
  return u;
}

function fetchHttpsBuffer(url, depthOrOpts = 0, maybeOpts = {}) {
  const depth = typeof depthOrOpts === 'number' ? depthOrOpts : 0;
  const opts = typeof depthOrOpts === 'object' && depthOrOpts !== null
    ? depthOrOpts
    : (maybeOpts && typeof maybeOpts === 'object' ? maybeOpts : {});

  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = validateRemoteUrl(url, opts);
    } catch (err) {
      return reject(err);
    }
    const maxBytes = Number(opts.maxBytes) > 0 ? Number(opts.maxBytes) : MAX_FETCH_BYTES;
    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : 8000;
    const customHeaders = opts.headers && typeof opts.headers === 'object' ? opts.headers : {};
    const headers = {
      'User-Agent': `OBSX-AutoUpdater/${getPkgVersion()}`,
      Accept: 'application/vnd.github.v3+json, application/json, text/plain, */*',
    };
    for (const [k, v] of Object.entries(customHeaders)) {
      if (/^[A-Za-z0-9-]+$/.test(k) && typeof v === 'string' && !/[\r\n\0]/.test(v)) {
        headers[k] = v;
      }
    }

    const transport = parsedUrl.protocol === 'http:' ? http : https;
    const req = transport.get(
      parsedUrl,
      { headers, timeout: timeoutMs },
      (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (depth >= MAX_REDIRECTS) {
            return reject(new Error('Too many HTTP redirects'));
          }
          let nextUrl;
          try {
            nextUrl = new URL(res.headers.location, parsedUrl).toString();
            validateRemoteUrl(nextUrl, opts);
          } catch (err) {
            return reject(err);
          }
          return fetchHttpsBuffer(nextUrl, depth + 1, opts).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${parsedUrl.hostname}`));
        }
        const declaredLen = Number(res.headers['content-length']);
        if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
          res.resume();
          return reject(new Error('Response exceeds max size limit'));
        }
        const chunks = [];
        let totalBytes = 0;
        let overflowed = false;
        res.on('data', (c) => {
          if (overflowed) return;
          totalBytes += c.length;
          if (totalBytes > maxBytes) {
            overflowed = true;
            req.destroy(new Error('Response exceeds max size limit'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          if (!overflowed) resolve(Buffer.concat(chunks));
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });
  });
}

function fetchHttpsText(url, opts) {
  return fetchHttpsBuffer(url, opts).then((buf) => buf.toString('utf8'));
}

function assertSafeAssetPath(rootDir, relPath, allowCustomRelPath = false) {
  if (
    typeof relPath !== 'string' ||
    !relPath ||
    relPath.includes('\0') ||
    relPath.includes('\\') ||
    path.isAbsolute(relPath)
  ) {
    throw new Error(`Invalid asset path: ${String(relPath)}`);
  }
  const normalized = path.posix.normalize(relPath);
  const parts = normalized.split('/');
  if (
    normalized === '.' ||
    normalized.startsWith('../') ||
    parts.some((p) => !p || p === '.' || p === '..' || p === '.git')
  ) {
    throw new Error(`Unsafe asset path traversal: ${relPath}`);
  }
  if (!allowCustomRelPath && !SYNC_ASSET_SET.has(normalized)) {
    throw new Error(`Disallowed asset target: ${normalized}`);
  }
  const rootReal = fs.realpathSync(rootDir);
  let cur = rootDir;
  let deepestExisting = rootReal;
  for (let i = 0; i < parts.length; i++) {
    cur = path.join(cur, parts[i]);
    try {
      const lst = fs.lstatSync(cur);
      if (lst.isSymbolicLink()) {
        throw new Error(`Symlink rejected in update path: ${normalized}`);
      }
      if (i < parts.length - 1) {
        if (!lst.isDirectory()) {
          throw new Error(`Non-directory parent in update path: ${normalized}`);
        }
        deepestExisting = fs.realpathSync(cur);
      } else if (!lst.isFile()) {
        throw new Error(`Non-regular target file: ${normalized}`);
      }
    } catch (err) {
      if (err && err.code === 'ENOENT') continue;
      throw err;
    }
  }
  if (deepestExisting !== rootReal && !deepestExisting.startsWith(rootReal + path.sep)) {
    throw new Error(`Update path escapes repository root: ${normalized}`);
  }
  return path.join(rootDir, ...parts);
}

function parseSemverTuple(raw) {
  if (typeof raw !== 'string') return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(raw.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareSemverTuples(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

function decodeSignatureBuffer(sigRaw) {
  if (Buffer.isBuffer(sigRaw)) {
    if (sigRaw.length === 64) return sigRaw;
    const asText = sigRaw.toString('utf8').trim();
    if (/^[A-Za-z0-9+/=]{80,128}$/.test(asText)) {
      return Buffer.from(asText, 'base64');
    }
    return sigRaw;
  }
  if (typeof sigRaw === 'string') {
    const trimmed = sigRaw.trim();
    return Buffer.from(trimmed, 'base64');
  }
  return Buffer.alloc(0);
}

function verifyEd25519Manifest(manifestBuf, sigBuf, publicKeyPem, expectedCommit) {
  if (!publicKeyPem || !Buffer.isBuffer(manifestBuf) || manifestBuf.length === 0) {
    return { ok: false, reason: 'missing_manifest_or_key' };
  }
  try {
    const sig = decodeSignatureBuffer(sigBuf);
    const verified = crypto.verify(null, manifestBuf, publicKeyPem, sig);
    if (!verified) return { ok: false, reason: 'invalid_manifest_signature' };
    const parsed = JSON.parse(manifestBuf.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, reason: 'invalid_manifest_format' };
    }
    if (expectedCommit && parsed.commit !== expectedCommit) {
      return { ok: false, reason: 'manifest_commit_mismatch' };
    }
    if (!parsed.files || typeof parsed.files !== 'object' || Array.isArray(parsed.files)) {
      return { ok: false, reason: 'invalid_manifest_files' };
    }
    return { ok: true, manifest: parsed };
  } catch (_) {
    return { ok: false, reason: 'manifest_verification_failed' };
  }
}

function verifyGitCommitTrust(runSync, rootDir, remoteHead, env) {
  if (!FULL_SHA_RE.test(remoteHead || '')) return false;
  try {
    runSync('git', ['verify-commit', remoteHead], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
  } catch (_) {
    return false;
  }
  const trustedRaw = String(env.OBSX_UPDATE_TRUSTED_SIGNERS || '').trim();
  if (!trustedRaw) return true;
  const trusted = new Set(
    trustedRaw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
  if (trusted.size === 0) return true;
  try {
    const out = runSync('git', ['log', '-1', '--format=%GK%n%GS%n%G?', remoteHead], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    })
      .toString()
      .split('\n');
    const keyId = (out[0] || '').trim().toLowerCase();
    const signer = (out[1] || '').trim().toLowerCase();
    const status = (out[2] || '').trim().toUpperCase();
    if (status !== 'G' && status !== 'U') return false;
    return trusted.has(keyId) || trusted.has(signer);
  } catch (_) {
    return false;
  }
}

function stageAndApplyAssetWrites(rootDir, stagedEntries, env) {
  const pkgUpdate = stagedEntries.find((e) => e.rel === 'package.json');
  if (pkgUpdate && env.OBSX_ALLOW_DOWNGRADE !== 'true') {
    const localVer = parseSemverTuple(getPkgVersion(rootDir));
    try {
      const remotePkg = JSON.parse(pkgUpdate.buf.toString('utf8'));
      const remoteVer = parseSemverTuple(remotePkg && remotePkg.version);
      if (localVer && remoteVer && compareSemverTuples(remoteVer, localVer) < 0) {
        throw new Error('version_downgrade_rejected');
      }
    } catch (err) {
      if (err && err.message === 'version_downgrade_rejected') throw err;
    }
  }

  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-stage-'));
  const backups = [];
  const applied = [];
  try {
    for (let i = 0; i < stagedEntries.length; i++) {
      const entry = stagedEntries[i];
      const stageFile = path.join(stageDir, `asset-${i}.bin`);
      fs.writeFileSync(stageFile, entry.buf);
      entry.stageFile = stageFile;
    }
    for (const entry of stagedEntries) {
      const destPath = assertSafeAssetPath(rootDir, entry.rel, entry.allowCustom);
      const existed = fs.existsSync(destPath);
      const prevBuf = existed ? fs.readFileSync(destPath) : null;
      backups.push({ destPath, existed, prevBuf });
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      const tmpDest = `${destPath}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tmpDest, entry.buf);
      fs.renameSync(tmpDest, destPath);
      applied.push(destPath);
      fileHashCache.delete(destPath);
    }
  } catch (err) {
    for (let i = backups.length - 1; i >= 0; i--) {
      const b = backups[i];
      try {
        if (b.existed && b.prevBuf !== null) {
          fs.writeFileSync(b.destPath, b.prevBuf);
        } else if (!b.existed && fs.existsSync(b.destPath)) {
          fs.unlinkSync(b.destPath);
        }
        fileHashCache.delete(b.destPath);
      } catch (_) {}
    }
    throw err;
  } finally {
    try {
      fs.rmSync(stageDir, { recursive: true, force: true });
    } catch (_) {}
  }
  return applied.length;
}

async function checkAndApplyUpstreamUpdate(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const { force = false, silent = false } = opts;
  const env = opts.env || process.env;
  const rootDir = opts.rootDir || ROOT_DIR;
  const fetchBuf = opts.fetchBuffer || fetchHttpsBuffer;
  const runSync = opts.execFileSync || execFileSync;
  const restartFn = opts.triggerRestart || (() => triggerHotRestartIfConfigured({ env, rootDir }));

  if (!force && (env.NODE_ENV === 'test' || env.OBSX_AUTO_UPDATE !== 'true')) {
    return { updated: false, status: 'disabled' };
  }

  const target = resolveUpstreamTarget(opts, env);
  if (!target.ok) {
    lastUpdateStatus = 'invalid_upstream_config';
    return { updated: false, status: lastUpdateStatus };
  }

  if (updateInProgress) {
    return { updated: false, status: 'update_in_progress' };
  }
  updateInProgress = true;
  lastCheckTime = Date.now();
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));

  try {
    // Query latest commit on upstream branch via GitHub API
    const apiBuf = await fetchBuf(`https://api.github.com/repos/${target.repo}/commits/${target.branch}`);
    const parsed = JSON.parse(Buffer.isBuffer(apiBuf) ? apiBuf.toString('utf8') : String(apiBuf));
    const remoteSha = parsed && parsed.sha ? String(parsed.sha).trim() : null;
    if (remoteSha && FULL_SHA_RE.test(remoteSha)) upstreamCommitCache = remoteSha.slice(0, 7);

    const git = getGitInfo({ rootDir, fresh: true, execFileSync: runSync });

    // Strategy A: Git repository fast-forward sync (when not running custom Sentinel overlay)
    if (git.isGitRepo && !hasSentinel) {
      runSync('git', ['fetch', '--quiet', 'origin', `refs/heads/${target.branch}:refs/remotes/origin/${target.branch}`], {
        cwd: rootDir,
        stdio: 'ignore',
        timeout: 15000,
      });

      const remoteHead = runSync('git', ['rev-parse', '--verify', `refs/remotes/origin/${target.branch}`], {
        cwd: rootDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
      })
        .toString()
        .trim();

      const allowUnverified = env.OBSX_ALLOW_UNVERIFIED_UPDATES === 'true';
      if (!allowUnverified && !verifyGitCommitTrust(runSync, rootDir, remoteHead, env)) {
        lastUpdateStatus = 'signature_verification_required';
        return {
          updated: false,
          status: lastUpdateStatus,
          remoteCommit: remoteHead.slice(0, 7),
        };
      }

      const enforceOfficial = env.OBSX_ENFORCE_OFFICIAL === 'true';
      if (git.dirty && !enforceOfficial) {
        lastUpdateStatus = remoteHead !== git.commit
          ? `paused_dirty_tree_behind_${remoteHead.slice(0, 7)}`
          : 'paused_dirty_tree';
        return {
          updated: false,
          status: lastUpdateStatus,
          advisory: getOperatorDriftAdvisory({ rootDir, branch: target.branch, statePath: opts.statePath, env, execFileSync: runSync }),
        };
      }

      if ((remoteHead && remoteHead !== git.commit) || (enforceOfficial && git.dirty)) {
        if (!silent) {
          console.log(`[OBSX Auto-Updater] Applying verified update (${git.shortCommit} -> ${remoteHead.slice(0, 7)}).`);
        }
        if (enforceOfficial) {
          runSync('git', ['reset', '--hard', `refs/remotes/origin/${target.branch}`], { cwd: rootDir, timeout: 10000 });
        } else {
          runSync('git', ['merge', '--ff-only', `refs/remotes/origin/${target.branch}`], { cwd: rootDir, timeout: 15000 });
        }
        invalidateGitCaches(rootDir);
        assertSafeAssetPath(rootDir, 'scripts/build.js', true);
        const buildScript = path.join(rootDir, 'scripts/build.js');
        if (fs.existsSync(buildScript)) {
          runSync(process.execPath, [buildScript], { cwd: rootDir, timeout: 10000 });
        }
        lastUpdateStatus = `updated_to_${remoteHead.slice(0, 7)}`;
        restartFn();
        return { updated: true, from: git.shortCommit, to: remoteHead.slice(0, 7) };
      }

      lastUpdateStatus = 'up_to_date';
      return { updated: false, status: 'up_to_date', commit: git.shortCommit };
    }

    // Strategy B: Standalone / ZIP / Non-Git local directory HTTP sync (strictly opt-in + signed)
    if (!git.isGitRepo && !hasSentinel && remoteSha && FULL_SHA_RE.test(remoteSha)) {
      if (env.OBSX_HTTP_SYNC !== 'true') {
        lastUpdateStatus = `http_sync_opt_in_required_${remoteSha.slice(0, 7)}`;
        return { updated: false, status: lastUpdateStatus, latestCommit: remoteSha.slice(0, 7) };
      }

      const allowUnverified = env.OBSX_ALLOW_UNVERIFIED_UPDATES === 'true';
      const pubKeyPem = String(env.OBSX_UPDATE_PUBLIC_KEY || '').trim();
      let verifiedManifest = null;
      if (!allowUnverified) {
        if (!pubKeyPem) {
          lastUpdateStatus = 'signature_verification_required';
          return { updated: false, status: lastUpdateStatus, latestCommit: remoteSha.slice(0, 7) };
        }
        const manifestRaw = opts.manifestBuffer
          || await fetchBuf(`https://raw.githubusercontent.com/${target.repo}/${remoteSha}/obsx-release-manifest.json`);
        const sigRaw = opts.manifestSigBuffer
          || await fetchBuf(`https://raw.githubusercontent.com/${target.repo}/${remoteSha}/obsx-release-manifest.sig`);
        const sigCheck = verifyEd25519Manifest(manifestRaw, sigRaw, pubKeyPem, remoteSha);
        if (!sigCheck.ok) {
          lastUpdateStatus = sigCheck.reason;
          return { updated: false, status: lastUpdateStatus, latestCommit: remoteSha.slice(0, 7) };
        }
        verifiedManifest = sigCheck.manifest;
      }

      const hasCustomAssetList = Array.isArray(opts.assetFiles);
      const assetFiles = hasCustomAssetList ? opts.assetFiles : SYNC_ASSET_FILES;
      const stagedEntries = [];
      for (const rel of assetFiles) {
        assertSafeAssetPath(rootDir, rel, hasCustomAssetList);
        const rawUrl = `https://raw.githubusercontent.com/${target.repo}/${remoteSha}/${rel}`;
        const remoteBuf = await fetchBuf(rawUrl);
        if (!remoteBuf || remoteBuf.length === 0) continue;
        if (verifiedManifest) {
          const expectedDigest = String(verifiedManifest.files[rel] || '').toLowerCase();
          const actualDigest = crypto.createHash('sha256').update(remoteBuf).digest('hex');
          if (!HEX_SHA256_RE.test(expectedDigest) || expectedDigest !== actualDigest) {
            throw new Error(`manifest_digest_mismatch:${rel}`);
          }
        }
        const remoteHash = hashBufferForAsset(rel, remoteBuf);
        const localHash = hashFileSha256(rel, rootDir);
        if (remoteHash !== localHash) {
          stagedEntries.push({ rel, buf: remoteBuf, allowCustom: hasCustomAssetList });
        }
      }

      if (stagedEntries.length > 0) {
        const updatedFiles = stageAndApplyAssetWrites(rootDir, stagedEntries, env);
        invalidateGitCaches(rootDir);
        const buildScript = path.join(rootDir, 'scripts/build.js');
        if (fs.existsSync(buildScript)) {
          assertSafeAssetPath(rootDir, 'scripts/build.js', true);
          runSync(process.execPath, [buildScript], { cwd: rootDir, timeout: 10000 });
        }
        lastUpdateStatus = `http_synced_${remoteSha.slice(0, 7)}`;
        restartFn();
        return { updated: true, filesUpdated: updatedFiles, to: remoteSha.slice(0, 7) };
      }
    }

    lastUpdateStatus = 'up_to_date';
    return { updated: false, status: 'up_to_date' };
  } catch (err) {
    lastUpdateStatus = `check_deferred: ${err.message}`;
    return { updated: false, status: lastUpdateStatus };
  } finally {
    updateInProgress = false;
  }
}

function triggerHotRestartIfConfigured(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const env = opts.env || process.env;
  const rootDir = opts.rootDir || ROOT_DIR;
  const spawnFn = opts.spawn || spawn;
  const killFn = opts.kill || process.kill;
  if (env.OBSX_AUTO_RESTART !== 'true' || (!opts.allowInTest && env.NODE_ENV === 'test')) return false;
  console.log('[OBSX Auto-Updater] Respawning server worker with updated security engine...');
  try {
    const child = spawnFn(process.execPath, process.argv.slice(1), {
      cwd: rootDir,
      env,
      detached: true,
      stdio: 'inherit',
    });
    if (child && typeof child.unref === 'function') child.unref();
    killFn(process.pid, 'SIGTERM');
    return true;
  } catch (err) {
    console.error('[OBSX Auto-Updater] Hot-restart failed:', err.message);
    return false;
  }
}

function startAutoUpdater() {
  if (process.env.NODE_ENV === 'test' || process.env.OBSX_AUTO_UPDATE !== 'true') return;
  if (updateTimer) return;

  setTimeout(() => {
    checkAndApplyUpstreamUpdate({ silent: false }).catch(() => {});
    syncHybridCloudRing().catch(() => {});
  }, 5000).unref();

  updateTimer = setInterval(() => {
    checkAndApplyUpstreamUpdate({ silent: true }).catch(() => {});
    syncHybridCloudRing().catch(() => {});
  }, DEFAULT_INTERVAL_MS);
  updateTimer.unref();
}

function getUpstreamCodeDiff() {
  const git = getGitInfo();
  if (!git.isGitRepo) {
    return { ok: false, error: 'not_git_repo', upstreamDiff: '', localDiff: '' };
  }
  const target = resolveUpstreamTarget();
  if (!target.ok) {
    return { ok: false, error: 'invalid_upstream_config', upstreamDiff: '', localDiff: '' };
  }
  let upstreamDiff = '';
  let localDiff = '';
  try {
    upstreamDiff = execFileSync('git', ['diff', `HEAD..refs/remotes/origin/${target.branch}`], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    })
      .toString()
      .slice(0, 32768);
  } catch (_) {}
  try {
    localDiff = execFileSync('git', ['diff', 'HEAD'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    })
      .toString()
      .slice(0, 32768);
  } catch (_) {}
  return {
    ok: true,
    localCommit: git.shortCommit,
    upstreamDiff: upstreamDiff || 'No upstream diff relative to HEAD.',
    localDiff: localDiff || 'No uncommitted local modifications.',
  };
}

function autoAdaptDirtyNode(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const runSync = opts.execFileSync || execFileSync;
  const target = resolveUpstreamTarget({ branch: opts.branch }, opts.env || process.env);
  if (!target.ok) {
    return { ok: false, error: 'invalid_upstream_config' };
  }
  if (updateInProgress) {
    return { ok: false, error: 'update_in_progress' };
  }
  const branch = target.branch;

  const git = getGitInfo({ rootDir, fresh: true, execFileSync: opts.execFileSync });
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));
  if (!git.isGitRepo || hasSentinel) {
    return { ok: false, error: 'unsupported_edition', message: 'Auto-adapt applies to standard Git local nodes.' };
  }
  updateInProgress = true;
  try {
    runSync('git', ['fetch', '--quiet', 'origin', `refs/heads/${branch}:refs/remotes/origin/${branch}`], { cwd: rootDir, timeout: 15000 });
    const hadDirty = git.dirty;
    let stashOid = null;
    if (hadDirty) {
      runSync('git', ['stash', 'push', '-m', 'obsx-operator-auto-adapt'], { cwd: rootDir, timeout: 10000 });
      stashOid = readTopStashOid(runSync, rootDir);
    }
    try {
      runSync('git', ['rebase', `refs/remotes/origin/${branch}`], { cwd: rootDir, timeout: 15000 });
    } catch (rebaseErr) {
      let abortedRebase = false;
      try {
        runSync('git', ['rebase', '--abort'], { cwd: rootDir, stdio: 'ignore', timeout: 5000 });
        abortedRebase = true;
      } catch (_) {}
      if (hadDirty && stashOid) {
        restoreStashedEdits(runSync, rootDir, stashOid);
      }
      invalidateGitCaches(rootDir);
      if (abortedRebase) {
        return { ok: false, conflict: true, message: 'Rebase encountered overlapping lines; restored working tree safely.' };
      }
      return { ok: false, conflict: false, error: rebaseErr.message };
    }

    if (hadDirty && stashOid) {
      const restoreResult = restoreStashedEdits(runSync, rootDir, stashOid);
      if (!restoreResult.restored) {
        invalidateGitCaches(rootDir);
        return {
          ok: false,
          conflict: true,
          message: restoreResult.stashPreserved
            ? 'Your local edits overlap directly with upstream changes; stashed safely in git stash list.'
            : 'Conflict occurred while reapplying local edits; inspect git status before retrying.',
        };
      }
    }

    invalidateGitCaches(rootDir);
    const buildScript = path.join(rootDir, 'scripts/build.js');
    if (fs.existsSync(buildScript)) {
      assertSafeAssetPath(rootDir, 'scripts/build.js', true);
      runSync(process.execPath, [buildScript], { cwd: rootDir, timeout: 10000 });
    }
    const updatedGit = getGitInfo({ rootDir, fresh: true, execFileSync: opts.execFileSync });
    lastUpdateStatus = `adapted_to_${updatedGit.shortCommit}`;
    return {
      ok: true,
      adapted: true,
      commit: updatedGit.shortCommit,
      dirtyWorkingTree: updatedGit.dirty,
    };
  } catch (err) {
    invalidateGitCaches(rootDir);
    return { ok: false, error: err.message };
  } finally {
    updateInProgress = false;
  }
}

const CANONICAL_RING_V4_RE = /^subnet:v4:((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\.0\/24$/;
const CANONICAL_RING_V6_RE = /^subnet:v6:([0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4})\/48$/;

function isPrivateOrReservedV4Prefix(a, b) {
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

function normalizeCloudRingSubnetKey(rawSubnet) {
  if (typeof rawSubnet !== 'string' || rawSubnet.length > 64) return null;
  const trimmed = rawSubnet.trim().toLowerCase();
  const v4 = CANONICAL_RING_V4_RE.exec(trimmed);
  if (v4) {
    const octets = v4[1].split('.').map(Number);
    if (isPrivateOrReservedV4Prefix(octets[0], octets[1])) return null;
    return `subnet:v4:${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }
  const v6 = CANONICAL_RING_V6_RE.exec(trimmed);
  if (v6) {
    return trimmed;
  }
  const cidrMatch = /^([0-9a-f:.]+)\/(24|48|64)$/.exec(trimmed);
  if (cidrMatch) {
    const parsed = parseCanonicalIp(cidrMatch[1]);
    if (!parsed || parsed.isLoopback) return null;
    if (parsed.family === 4 && isPrivateOrReservedV4Prefix(parsed.octets[0], parsed.octets[1])) {
      return null;
    }
    const key = getCanonicalSubnetKey(parsed.ip);
    return key.startsWith('subnet:v4:') || key.startsWith('subnet:v6:') ? key : null;
  }
  return null;
}

async function syncHybridCloudRing(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const env = opts.env || process.env;
  const cloudKey = String(env.OBSX_CLOUD_KEY || '').trim();
  if (!cloudKey) return { synced: false, reason: 'no_cloud_key' };
  const cloudUrl = String(env.OBSX_CLOUD_URL || 'https://obsx.tech').trim().replace(/\/+$/, '');
  const fetchText = opts.fetchText || fetchHttpsText;

  let parsedUrl;
  try {
    const allowInsecureLocal = env.OBSX_ALLOW_INSECURE_CLOUD_URL === 'true';
    parsedUrl = validateRemoteUrl(cloudUrl, {
      allowedHosts: new Set([new URL(cloudUrl).hostname.toLowerCase()]),
      allowInsecureLocal,
      allowIpLiteral: allowInsecureLocal,
    });
  } catch (_) {
    return { synced: false, reason: 'invalid_cloud_url' };
  }

  try {
    const allowInsecureLocal = env.OBSX_ALLOW_INSECURE_CLOUD_URL === 'true';
    const raw = await fetchText(`${cloudUrl}/api/v1/sentinel/ring`, {
      headers: { 'X-OBSX-Cloud-Key': cloudKey },
      allowedHosts: [parsedUrl.hostname],
      allowInsecureLocal,
      allowIpLiteral: allowInsecureLocal,
    });
    const data = JSON.parse(raw);
    if (!data || !data.ok || !Array.isArray(data.activeSubnets)) {
      return { synced: false };
    }

    const syncSecret = String(env.OBSX_CLOUD_SYNC_SECRET || '').trim();
    const cloudPubKey = String(env.OBSX_CLOUD_PUBLIC_KEY || '').trim();
    if (syncSecret || cloudPubKey) {
      const ts = Number(data.ts);
      if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 300000 || typeof data.sig !== 'string') {
        return { synced: false, reason: 'invalid_ring_signature' };
      }
      const payloadStr = canon({ ts, activeSubnets: data.activeSubnets });
      if (cloudPubKey) {
        const sigOk = crypto.verify(null, Buffer.from(payloadStr, 'utf8'), cloudPubKey, decodeSignatureBuffer(data.sig));
        if (!sigOk) return { synced: false, reason: 'invalid_ring_signature' };
      } else {
        const expected = hmac(payloadStr, syncSecret);
        if (!safeEqual(data.sig, expected)) return { synced: false, reason: 'invalid_ring_signature' };
      }
    }

    const { getKv } = require('./kv');
    const kv = opts.kv || getKv();
    let count = 0;
    for (const item of data.activeSubnets.slice(0, MAX_CLOUD_RING_SUBNETS)) {
      if (!item || typeof item !== 'object') continue;
      const subnetKey = normalizeCloudRingSubnetKey(item.subnet);
      if (!subnetKey) continue;
      const rem = Number(item.remainingSeconds);
      const ttl = Math.min(MAX_CLOUD_RING_TTL_SEC, Math.max(60, Number.isFinite(rem) ? Math.floor(rem) : 300));
      const rejRaw = Number(item.rejections);
      const rej = Math.min(1000, Math.max(1, Number.isFinite(rejRaw) ? Math.floor(rejRaw) : 5));
      await kv.set(`tr:sentinel:ring:${subnetKey}`, String(rej), 'EX', ttl);
      await kv.hset('tr:sentinel:ring:active', subnetKey, String(Date.now() + ttl * 1000));
      count++;
    }
    return { synced: true, count };
  } catch (_) {}
  return { synced: false };
}

function getOperatorDriftAdvisory(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const env = opts.env || process.env;
  const target = resolveUpstreamTarget({ branch: opts.branch }, env);
  const branch = target.ok ? target.branch : 'main';
  const runSync = opts.execFileSync || execFileSync;
  const fresh = Boolean(opts.fresh);
  const useCache = !fresh && !opts.execFileSync;

  const git = getGitInfo({ rootDir, fresh, execFileSync: opts.execFileSync });
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));
  const licenseStatus = getLicenseStatus({ rootDir, statePath: opts.statePath, env });

  if (!git.isGitRepo || hasSentinel) {
    return {
      showReminder: Boolean(licenseStatus.safeMode || licenseStatus.licenseChanged),
      isGitRepo: git.isGitRepo,
      edition: git.edition,
      dirtyWorkingTree: false,
      commitsBehind: 0,
      locallyModifiedFiles: [],
      upstreamCommits: [],
      upstreamChangedFiles: [],
      overlappingFiles: [],
      licenseStatus,
    };
  }

  const driftKey = `${rootDir}:${branch}`;
  const cachedDrift = useCache ? gitDriftCache.get(driftKey) : null;
  let driftSnapshot = cachedDrift && Date.now() - cachedDrift.at < GIT_CACHE_TTL_MS ? cachedDrift.value : null;

  if (!driftSnapshot) {
    let locallyModifiedFiles = [];
    let localDiffStat = '';
    let commitsBehind = 0;
    let upstreamCommits = [];
    let upstreamChangedFiles = [];

    try {
      const porcelain = runSync('git', ['status', '--porcelain', '--untracked-files=no'], {
        cwd: rootDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 3000,
      })
        .toString()
        .trim();
      if (porcelain) {
        locallyModifiedFiles = porcelain
          .split('\n')
          .map((line) => line.trim().replace(/^[A-Z?]+\s+/, ''))
          .filter(Boolean);
      }

      localDiffStat = runSync('git', ['diff', '--stat', 'HEAD'], {
        cwd: rootDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 3000,
      })
        .toString()
        .trim();

      const behindRaw = runSync('git', ['rev-list', '--count', `HEAD..origin/${branch}`], {
        cwd: rootDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 3000,
      })
        .toString()
        .trim();
      commitsBehind = Number(behindRaw) || 0;

      if (commitsBehind > 0) {
        const logRaw = runSync('git', ['log', '--oneline', '-n', '5', `HEAD..origin/${branch}`], {
          cwd: rootDir,
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 3000,
        })
          .toString()
          .trim();
        upstreamCommits = logRaw ? logRaw.split('\n').map((s) => s.trim()) : [];

        const nameOnlyRaw = runSync('git', ['diff', '--name-only', `HEAD..origin/${branch}`], {
          cwd: rootDir,
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 3000,
        })
          .toString()
          .trim();
        upstreamChangedFiles = nameOnlyRaw ? nameOnlyRaw.split('\n').map((s) => s.trim()).filter(Boolean) : [];
      }
    } catch (_) {}

    driftSnapshot = {
      locallyModifiedFiles,
      localDiffStat,
      commitsBehind,
      upstreamCommits,
      upstreamChangedFiles,
    };
    if (useCache) {
      gitDriftCache.set(driftKey, { at: Date.now(), value: driftSnapshot });
    }
  }

  const {
    locallyModifiedFiles,
    localDiffStat,
    commitsBehind,
    upstreamCommits,
    upstreamChangedFiles,
  } = driftSnapshot;

  const overlappingFiles = locallyModifiedFiles.filter((f) => upstreamChangedFiles.includes(f));
  const showReminder = Boolean(git.dirty || commitsBehind > 0 || licenseStatus.safeMode || licenseStatus.licenseChanged);

  return {
    showReminder,
    isGitRepo: true,
    edition: git.edition,
    localCommit: git.shortCommit,
    latestUpstreamCommit: upstreamCommitCache || git.shortCommit,
    dirtyWorkingTree: git.dirty,
    locallyModifiedFiles,
    localDiffStat,
    commitsBehind,
    upstreamCommits,
    upstreamChangedFiles,
    overlappingFiles,
    licenseStatus,
    adaptationCommand: 'git fetch origin main && git stash && git pull --rebase origin main && git stash pop',
  };
}

module.exports = {
  getSystemVersionInfo,
  getOperatorDriftAdvisory,
  getUpstreamCodeDiff,
  autoAdaptDirtyNode,
  syncHybridCloudRing,
  checkAndApplyUpstreamUpdate,
  startAutoUpdater,
  hashFileSha256,
  hashBufferForAsset,
  computeTreeFingerprint,
  getLicenseStatus,
  acceptLicenseTerms,
  triggerHotRestartIfConfigured,
};
