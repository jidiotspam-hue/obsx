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
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const LICENSE_STATE_FILE = path.join(ROOT_DIR, '.obsx-license-state.json');
const UPSTREAM_REPO = process.env.OBSX_UPSTREAM_REPO || 'jidiotspam-hue/obsx';
const UPSTREAM_BRANCH = process.env.OBSX_UPSTREAM_BRANCH || 'main';
const DEFAULT_INTERVAL_MS = Number(process.env.OBSX_UPDATE_INTERVAL_MS) || 5 * 60 * 1000;

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
  'src/tracer.js',
  'public/dashboard.js',
  'public/index.html',
  'public/dram-dark.jpg',
  'public/dram-light.jpg',
  'public/dram-stick.svg',
];

const BINARY_EXT_RE = /\.(jpg|jpeg|png|gif|ico|webp|woff2?|eot|ttf|bin)$/i;
const FULL_SHA_RE = /^[0-9a-f]{40}$/i;
const HEX_SHA256_RE = /^[0-9a-f]{64}$/i;
const GIT_CACHE_TTL_MS = 15000;

let lastCheckTime = null;
let lastUpdateStatus = 'initialized';
let upstreamCommitCache = null;
let updateTimer = null;

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
    upstream: UPSTREAM_REPO,
    autoUpdate: {
      enabled: env.OBSX_AUTO_UPDATE !== 'false',
      httpSyncEnabled: env.OBSX_HTTP_SYNC === 'true',
      autoRestartEnabled: env.OBSX_AUTO_RESTART === 'true',
      lastCheckTime,
      status: lastUpdateStatus,
      latestUpstreamCommit: upstreamCommitCache,
    },
    timestamp: Date.now(),
  };
}

function fetchHttpsBuffer(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': `OBSX-AutoUpdater/${getPkgVersion()}`,
          Accept: 'application/vnd.github.v3+json, text/plain, */*',
        },
        timeout: 8000,
      },
      (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return fetchHttpsBuffer(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });
  });
}

function fetchHttpsText(url) {
  return fetchHttpsBuffer(url).then((buf) => buf.toString('utf8'));
}

async function checkAndApplyUpstreamUpdate(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const { force = false, silent = false } = opts;
  const env = opts.env || process.env;
  const rootDir = opts.rootDir || ROOT_DIR;
  const fetchBuf = opts.fetchBuffer || fetchHttpsBuffer;
  const runSync = opts.execFileSync || execFileSync;
  const restartFn = opts.triggerRestart || (() => triggerHotRestartIfConfigured({ env, rootDir }));

  if (!force && (env.NODE_ENV === 'test' || env.OBSX_AUTO_UPDATE === 'false')) {
    return { updated: false, status: 'disabled' };
  }

  lastCheckTime = Date.now();
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));

  try {
    // Query latest commit on upstream main via GitHub API
    const apiBuf = await fetchBuf(`https://api.github.com/repos/${UPSTREAM_REPO}/commits/${UPSTREAM_BRANCH}`);
    const parsed = JSON.parse(Buffer.isBuffer(apiBuf) ? apiBuf.toString('utf8') : String(apiBuf));
    const remoteSha = parsed && parsed.sha ? String(parsed.sha).trim() : null;
    if (remoteSha) upstreamCommitCache = remoteSha.slice(0, 7);

    const git = getGitInfo({ rootDir, fresh: true, execFileSync: runSync });

    // Strategy A: Git repository fast-forward sync (when not running custom Sentinel overlay)
    if (git.isGitRepo && !hasSentinel) {
      runSync('git', ['fetch', 'origin', UPSTREAM_BRANCH, '--quiet'], {
        cwd: rootDir,
        stdio: 'ignore',
        timeout: 15000,
      });

      const remoteHead = runSync('git', ['rev-parse', `origin/${UPSTREAM_BRANCH}`], {
        cwd: rootDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
      })
        .toString()
        .trim();

      if (git.dirty && env.OBSX_ENFORCE_OFFICIAL !== 'true') {
        lastUpdateStatus = remoteHead !== git.commit
          ? `paused_dirty_tree_behind_${remoteHead.slice(0, 7)}`
          : 'paused_dirty_tree';
        return {
          updated: false,
          status: lastUpdateStatus,
          advisory: getOperatorDriftAdvisory({ rootDir, statePath: opts.statePath, env, execFileSync: runSync }),
        };
      }

      if (remoteHead && remoteHead !== git.commit) {
        if (!silent) {
          console.log(`[OBSX Auto-Updater] New official commit detected (${git.shortCommit} -> ${remoteHead.slice(0, 7)}). Updating...`);
        }
        // Reset any accidental local drift if OBSX_ENFORCE_OFFICIAL=true, otherwise pull --ff-only
        if (env.OBSX_ENFORCE_OFFICIAL === 'true') {
          runSync('git', ['reset', '--hard', `origin/${UPSTREAM_BRANCH}`], { cwd: rootDir, timeout: 10000 });
        } else {
          runSync('git', ['pull', '--ff-only', 'origin', UPSTREAM_BRANCH], { cwd: rootDir, timeout: 15000 });
        }
        invalidateGitCaches(rootDir);
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

    // Strategy B: Standalone / ZIP / Non-Git local directory HTTP sync (strictly opt-in)
    if (!git.isGitRepo && !hasSentinel && remoteSha && FULL_SHA_RE.test(remoteSha)) {
      if (env.OBSX_HTTP_SYNC !== 'true') {
        lastUpdateStatus = `http_sync_opt_in_required_${remoteSha.slice(0, 7)}`;
        return { updated: false, status: lastUpdateStatus, latestCommit: remoteSha.slice(0, 7) };
      }
      let updatedFiles = 0;
      const assetFiles = Array.isArray(opts.assetFiles) ? opts.assetFiles : SYNC_ASSET_FILES;
      for (const rel of assetFiles) {
        const rawUrl = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${remoteSha}/${rel}`;
        const remoteBuf = await fetchBuf(rawUrl);
        if (!remoteBuf || remoteBuf.length === 0) continue;
        const remoteHash = hashBufferForAsset(rel, remoteBuf);
        const localHash = hashFileSha256(rel, rootDir);
        if (remoteHash !== localHash) {
          const destPath = path.join(rootDir, rel);
          fs.mkdirSync(path.dirname(destPath), { recursive: true });
          fs.writeFileSync(destPath, remoteBuf);
          fileHashCache.delete(destPath);
          updatedFiles++;
        }
      }
      if (updatedFiles > 0) {
        invalidateGitCaches(rootDir);
        const buildScript = path.join(rootDir, 'scripts/build.js');
        if (fs.existsSync(buildScript)) {
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
  if (process.env.NODE_ENV === 'test' || process.env.OBSX_AUTO_UPDATE === 'false') return;
  if (updateTimer) return;

  // Initial non-blocking check 5 seconds after boot
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
  let upstreamDiff = '';
  let localDiff = '';
  try {
    upstreamDiff = execFileSync('git', ['diff', `HEAD..origin/${UPSTREAM_BRANCH}`], {
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
  const branch = opts.branch || UPSTREAM_BRANCH;
  const runSync = opts.execFileSync || execFileSync;

  const git = getGitInfo({ rootDir, fresh: true, execFileSync: opts.execFileSync });
  const hasSentinel = fs.existsSync(path.join(rootDir, 'lib/sentinel.js'));
  if (!git.isGitRepo || hasSentinel) {
    return { ok: false, error: 'unsupported_edition', message: 'Auto-adapt applies to standard Git local nodes.' };
  }
  try {
    runSync('git', ['fetch', 'origin', branch, '--quiet'], { cwd: rootDir, timeout: 15000 });
    const hadDirty = git.dirty;
    let stashOid = null;
    if (hadDirty) {
      runSync('git', ['stash', 'push', '-m', 'obsx-operator-auto-adapt'], { cwd: rootDir, timeout: 10000 });
      stashOid = readTopStashOid(runSync, rootDir);
    }
    try {
      runSync('git', ['rebase', `origin/${branch}`], { cwd: rootDir, timeout: 15000 });
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
  }
}

async function syncHybridCloudRing() {
  const cloudKey = process.env.OBSX_CLOUD_KEY || '';
  if (!cloudKey) return { synced: false, reason: 'no_cloud_key' };
  const cloudUrl = (process.env.OBSX_CLOUD_URL || 'https://obsx.tech').replace(/\/+$/, '');
  try {
    const raw = await fetchHttpsText(`${cloudUrl}/api/v1/sentinel/ring`);
    const data = JSON.parse(raw);
    if (data && data.ok && Array.isArray(data.activeSubnets)) {
      const { getKv } = require('./kv');
      const kv = getKv();
      for (const item of data.activeSubnets) {
        if (item && item.subnet) {
          const ttl = Math.max(60, Number(item.remainingSeconds) || 300);
          await kv.set(`tr:sentinel:ring:${item.subnet}`, String(item.rejections || 5), 'EX', ttl);
          await kv.hset('tr:sentinel:ring:active', item.subnet, String(Date.now() + ttl * 1000));
        }
      }
      return { synced: true, count: data.activeSubnets.length };
    }
  } catch (_) {}
  return { synced: false };
}

function getOperatorDriftAdvisory(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const rootDir = opts.rootDir || ROOT_DIR;
  const branch = opts.branch || UPSTREAM_BRANCH;
  const env = opts.env || process.env;
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
