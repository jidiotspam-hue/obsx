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

let lastCheckTime = null;
let lastUpdateStatus = 'initialized';
let upstreamCommitCache = null;
let updateTimer = null;

function hashFileSha256(relPath, rootDir = ROOT_DIR) {
  try {
    const full = path.join(rootDir, relPath);
    if (!fs.existsSync(full)) return null;
    const buf = fs.readFileSync(full);
    // For text assets and source code, normalize CRLF to LF to prevent false-positive
    // tree fingerprint mismatches and Safe Mode triggers across Windows/macOS checkouts
    if (BINARY_EXT_RE.test(relPath)) {
      return crypto.createHash('sha256').update(buf).digest('hex');
    }
    const normalized = buf.toString('utf8').replace(/\r\n/g, '\n');
    return crypto.createHash('sha256').update(Buffer.from(normalized, 'utf8')).digest('hex');
  } catch (_) {
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
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
    if (pkg && typeof pkg.version === 'string' && pkg.version) return pkg.version;
  } catch (_) {}
  return '2.2.0';
}

function readLicenseState(statePath = LICENSE_STATE_FILE) {
  try {
    if (!fs.existsSync(statePath)) return null;
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { corrupt: true };
    return parsed;
  } catch (_) {
    return { corrupt: true };
  }
}

function getLicenseStatus(options = {}) {
  const rootDir = options.rootDir || ROOT_DIR;
  const statePath = options.statePath || path.join(rootDir, '.obsx-license-state.json');
  const env = options.env || process.env;

  const licenseSha256 = hashFileSha256('LICENSE', rootDir);
  const missingCriticalFiles = CRITICAL_INTEGRITY_FILES.filter((rel) => !hashFileSha256(rel, rootDir));
  const saved = readLicenseState(statePath);

  const acceptedViaEnv = env.OBSX_ACCEPT_LICENSE === 'true';
  const enforceAcceptance = env.OBSX_ENFORCE_LICENSE_ACCEPTANCE === 'true';
  const hasSavedAcceptance = Boolean(
    saved && !saved.corrupt && typeof saved.acceptedHash === 'string' && /^[0-9a-f]{64}$/i.test(saved.acceptedHash)
  );
  const savedHash = hasSavedAcceptance ? saved.acceptedHash.toLowerCase() : null;
  const accepted = Boolean(licenseSha256 && (acceptedViaEnv || (savedHash && savedHash === licenseSha256)));
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
    acceptedAt: hasSavedAcceptance ? (saved.acceptedAt || null) : null,
    acceptedBy: hasSavedAcceptance ? (saved.acceptedBy || null) : null,
    acceptedVia: acceptedViaEnv ? 'env' : (accepted ? 'state_file' : null),
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
  const rootDir = options.rootDir || ROOT_DIR;
  const statePath = options.statePath || path.join(rootDir, '.obsx-license-state.json');
  const licenseSha256 = hashFileSha256('LICENSE', rootDir);
  if (!licenseSha256) {
    return { ok: false, error: 'missing_license_file' };
  }
  const acceptedBy = typeof metadata.acceptedBy === 'string' && metadata.acceptedBy.trim()
    ? metadata.acceptedBy.trim().slice(0, 120)
    : 'operator';
  const payload = {
    acceptedHash: licenseSha256,
    acceptedAt: new Date().toISOString(),
    termsVersion: 'v2.2.0-dual',
    acceptedBy,
  };
  try {
    fs.writeFileSync(statePath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
  } catch (err) {
    return { ok: false, error: 'license_state_write_failed', message: err.message };
  }
  return getLicenseStatus({ rootDir, statePath, env: options.env });
}

function getGitInfo() {
  try {
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();
    const statusOut = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();
    const hasSentinel = fs.existsSync(path.join(ROOT_DIR, 'lib/sentinel.js'));
    return {
      isGitRepo: true,
      commit,
      shortCommit: commit.slice(0, 7),
      dirty: statusOut.length > 0 && !hasSentinel,
      edition: hasSentinel ? 'enterprise-sentinel' : statusOut.length > 0 ? 'modified-local' : 'official',
    };
  } catch (_) {
    const hasSentinel = fs.existsSync(path.join(ROOT_DIR, 'lib/sentinel.js'));
    return {
      isGitRepo: false,
      commit: 'standalone',
      shortCommit: 'local',
      dirty: false,
      edition: hasSentinel ? 'enterprise-sentinel' : 'standalone',
    };
  }
}

function getSystemVersionInfo() {
  const pkgVersion = getPkgVersion();
  const git = getGitInfo();
  const treeHash = computeTreeFingerprint();
  const sdkHash = (hashFileSha256('public/obsx.min.js') || '').slice(0, 16);
  const licenseStatus = getLicenseStatus();

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
      enabled: process.env.OBSX_AUTO_UPDATE !== 'false',
      httpSyncEnabled: process.env.OBSX_HTTP_SYNC === 'true',
      autoRestartEnabled: process.env.OBSX_AUTO_RESTART === 'true',
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
          'User-Agent': 'OBSX-AutoUpdater/2.3',
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
  const { force = false, silent = false } = options;
  if (!force && (process.env.NODE_ENV === 'test' || process.env.OBSX_AUTO_UPDATE === 'false')) {
    return { updated: false, status: 'disabled' };
  }

  lastCheckTime = Date.now();
  const hasSentinel = fs.existsSync(path.join(ROOT_DIR, 'lib/sentinel.js'));

  try {
    // Query latest commit on upstream main via GitHub API
    const apiData = await fetchHttpsText(`https://api.github.com/repos/${UPSTREAM_REPO}/commits/${UPSTREAM_BRANCH}`);
    const parsed = JSON.parse(apiData);
    const remoteSha = parsed && parsed.sha ? String(parsed.sha).trim() : null;
    if (remoteSha) upstreamCommitCache = remoteSha.slice(0, 7);

    const git = getGitInfo();

    // Strategy A: Git repository fast-forward sync (when not running custom Sentinel overlay)
    if (git.isGitRepo && !hasSentinel) {
      execFileSync('git', ['fetch', 'origin', UPSTREAM_BRANCH, '--quiet'], {
        cwd: ROOT_DIR,
        stdio: 'ignore',
        timeout: 15000,
      });

      const remoteHead = execFileSync('git', ['rev-parse', `origin/${UPSTREAM_BRANCH}`], {
        cwd: ROOT_DIR,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
      })
        .toString()
        .trim();

      if (git.dirty && process.env.OBSX_ENFORCE_OFFICIAL !== 'true') {
        lastUpdateStatus = remoteHead !== git.commit
          ? `paused_dirty_tree_behind_${remoteHead.slice(0, 7)}`
          : 'paused_dirty_tree';
        return {
          updated: false,
          status: lastUpdateStatus,
          advisory: getOperatorDriftAdvisory(),
        };
      }

      if (remoteHead && remoteHead !== git.commit) {
        if (!silent) {
          console.log(`[OBSX Auto-Updater] New official commit detected (${git.shortCommit} -> ${remoteHead.slice(0, 7)}). Updating...`);
        }
        // Reset any accidental local drift if OBSX_ENFORCE_OFFICIAL=true, otherwise pull --ff-only
        if (process.env.OBSX_ENFORCE_OFFICIAL === 'true') {
          execFileSync('git', ['reset', '--hard', `origin/${UPSTREAM_BRANCH}`], { cwd: ROOT_DIR, timeout: 10000 });
        } else {
          execFileSync('git', ['pull', '--ff-only', 'origin', UPSTREAM_BRANCH], { cwd: ROOT_DIR, timeout: 15000 });
        }
        execFileSync(process.execPath, [path.join(ROOT_DIR, 'scripts/build.js')], { cwd: ROOT_DIR, timeout: 10000 });
        lastUpdateStatus = `updated_to_${remoteHead.slice(0, 7)}`;
        triggerHotRestartIfConfigured();
        return { updated: true, from: git.shortCommit, to: remoteHead.slice(0, 7) };
      }

      lastUpdateStatus = 'up_to_date';
      return { updated: false, status: 'up_to_date', commit: git.shortCommit };
    }

    // Strategy B: Standalone / ZIP / Non-Git local directory HTTP sync (strictly opt-in)
    if (!git.isGitRepo && !hasSentinel && remoteSha && FULL_SHA_RE.test(remoteSha)) {
      if (process.env.OBSX_HTTP_SYNC !== 'true') {
        lastUpdateStatus = `http_sync_opt_in_required_${remoteSha.slice(0, 7)}`;
        return { updated: false, status: lastUpdateStatus, latestCommit: remoteSha.slice(0, 7) };
      }
      let updatedFiles = 0;
      for (const rel of SYNC_ASSET_FILES) {
        const rawUrl = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${remoteSha}/${rel}`;
        const remoteBuf = await fetchHttpsBuffer(rawUrl);
        if (!remoteBuf || remoteBuf.length === 0) continue;
        const remoteHash = crypto.createHash('sha256').update(remoteBuf).digest('hex');
        const localHash = hashFileSha256(rel);
        if (remoteHash !== localHash) {
          fs.writeFileSync(path.join(ROOT_DIR, rel), remoteBuf);
          updatedFiles++;
        }
      }
      if (updatedFiles > 0) {
        execFileSync(process.execPath, [path.join(ROOT_DIR, 'scripts/build.js')], { cwd: ROOT_DIR, timeout: 10000 });
        lastUpdateStatus = `http_synced_${remoteSha.slice(0, 7)}`;
        triggerHotRestartIfConfigured();
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

function triggerHotRestartIfConfigured() {
  if (process.env.OBSX_AUTO_RESTART !== 'true' || process.env.NODE_ENV === 'test') return;
  console.log('[OBSX Auto-Updater] Respawning server worker with updated security engine...');
  try {
    const child = spawn(process.execPath, process.argv.slice(1), {
      cwd: ROOT_DIR,
      env: process.env,
      detached: true,
      stdio: 'inherit',
    });
    child.unref();
    process.kill(process.pid, 'SIGTERM');
  } catch (err) {
    console.error('[OBSX Auto-Updater] Hot-restart failed:', err.message);
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

function autoAdaptDirtyNode() {
  const git = getGitInfo();
  const hasSentinel = fs.existsSync(path.join(ROOT_DIR, 'lib/sentinel.js'));
  if (!git.isGitRepo || hasSentinel) {
    return { ok: false, error: 'unsupported_edition', message: 'Auto-adapt applies to standard Git local nodes.' };
  }
  try {
    execFileSync('git', ['fetch', 'origin', UPSTREAM_BRANCH, '--quiet'], { cwd: ROOT_DIR, timeout: 15000 });
    const hadDirty = git.dirty;
    if (hadDirty) {
      execFileSync('git', ['stash', 'push', '-m', 'obsx-operator-auto-adapt'], { cwd: ROOT_DIR, timeout: 10000 });
    }
    try {
      execFileSync('git', ['pull', '--rebase', 'origin', UPSTREAM_BRANCH], { cwd: ROOT_DIR, timeout: 15000 });
    } catch (rebaseErr) {
      try {
        execFileSync('git', ['rebase', '--abort'], { cwd: ROOT_DIR, timeout: 5000 });
      } catch (_) {}
      if (hadDirty) {
        try {
          execFileSync('git', ['stash', 'pop'], { cwd: ROOT_DIR, timeout: 5000 });
        } catch (_) {}
      }
      return { ok: false, conflict: true, message: 'Rebase encountered overlapping lines; restored working tree safely.' };
    }

    if (hadDirty) {
      try {
        execFileSync('git', ['stash', 'pop'], { cwd: ROOT_DIR, timeout: 10000 });
      } catch (popErr) {
        // Restore merge index safely while keeping user modifications preserved in git stash
        execFileSync('git', ['reset', '--merge', 'HEAD'], { cwd: ROOT_DIR, timeout: 5000 });
        return {
          ok: false,
          conflict: true,
          message: 'Your local edits overlap directly with upstream changes; stashed safely in git stash list.',
        };
      }
    }

    execFileSync(process.execPath, [path.join(ROOT_DIR, 'scripts/build.js')], { cwd: ROOT_DIR, timeout: 10000 });
    const updatedGit = getGitInfo();
    lastUpdateStatus = `adapted_to_${updatedGit.shortCommit}`;
    return {
      ok: true,
      adapted: true,
      commit: updatedGit.shortCommit,
      dirtyWorkingTree: updatedGit.dirty,
    };
  } catch (err) {
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

function getOperatorDriftAdvisory() {
  const git = getGitInfo();
  const hasSentinel = fs.existsSync(path.join(ROOT_DIR, 'lib/sentinel.js'));
  if (!git.isGitRepo || hasSentinel) {
    return {
      showReminder: false,
      edition: git.edition,
    };
  }

  let locallyModifiedFiles = [];
  let localDiffStat = '';
  let commitsBehind = 0;
  let upstreamCommits = [];
  let upstreamChangedFiles = [];

  try {
    const porcelain = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
      cwd: ROOT_DIR,
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

    localDiffStat = execFileSync('git', ['diff', '--stat', 'HEAD'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();

    const behindRaw = execFileSync('git', ['rev-list', '--count', `HEAD..origin/${UPSTREAM_BRANCH}`], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    })
      .toString()
      .trim();
    commitsBehind = Number(behindRaw) || 0;

    if (commitsBehind > 0) {
      const logRaw = execFileSync('git', ['log', '--oneline', '-n', '5', `HEAD..origin/${UPSTREAM_BRANCH}`], {
        cwd: ROOT_DIR,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 3000,
      })
        .toString()
        .trim();
      upstreamCommits = logRaw ? logRaw.split('\n').map((s) => s.trim()) : [];

      const nameOnlyRaw = execFileSync('git', ['diff', '--name-only', `HEAD..origin/${UPSTREAM_BRANCH}`], {
        cwd: ROOT_DIR,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 3000,
      })
        .toString()
        .trim();
      upstreamChangedFiles = nameOnlyRaw ? nameOnlyRaw.split('\n').map((s) => s.trim()).filter(Boolean) : [];
    }
  } catch (_) {}

  const licenseStatus = getLicenseStatus();
  const overlappingFiles = locallyModifiedFiles.filter((f) => upstreamChangedFiles.includes(f));
  const showReminder = Boolean(git.dirty || commitsBehind > 0 || licenseStatus.safeMode || licenseStatus.licenseChanged);

  return {
    showReminder,
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
  computeTreeFingerprint,
  getLicenseStatus,
  acceptLicenseTerms,
};
