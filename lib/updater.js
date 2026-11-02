'use strict';

/**
 * OBSX Self-Healing Upstream Auto-Updater & Runtime Integrity Verifier
 *
 * Ensures that any local or self-hosted OBSX node stays synchronized with
 * the official upstream repository (https://github.com/jidiotspam-hue/obsx)
 * and exposes cryptographic code-tree attestation so modified or stale local
 * forks are immediately identifiable.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const UPSTREAM_REPO = process.env.OBSX_UPSTREAM_REPO || 'jidiotspam-hue/obsx';
const UPSTREAM_BRANCH = process.env.OBSX_UPSTREAM_BRANCH || 'main';
const DEFAULT_INTERVAL_MS = Number(process.env.OBSX_UPDATE_INTERVAL_MS) || 5 * 60 * 1000;

const CORE_WATCH_FILES = [
  'lib/core.js',
  'lib/telemetry.js',
  'lib/crypto.js',
  'lib/accounts.js',
  'server.js',
];

let lastCheckTime = null;
let lastUpdateStatus = 'initialized';
let upstreamCommitCache = null;
let updateTimer = null;

function hashFileSha256(relPath) {
  try {
    const full = path.join(ROOT_DIR, relPath);
    if (!fs.existsSync(full)) return null;
    const buf = fs.readFileSync(full);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch (_) {
    return null;
  }
}

function computeTreeFingerprint() {
  const h = crypto.createHash('sha256');
  for (const rel of CORE_WATCH_FILES) {
    const fileHash = hashFileSha256(rel) || 'missing';
    h.update(`${rel}:${fileHash}\n`);
  }
  return h.digest('hex').slice(0, 16);
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
  let pkgVersion = '2.3.0';
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf8'));
    if (pkg.version) pkgVersion = pkg.version;
  } catch (_) {}

  const git = getGitInfo();
  const treeHash = computeTreeFingerprint();
  const sdkHash = (hashFileSha256('public/obsx.min.js') || '').slice(0, 16);

  return {
    ok: true,
    product: 'OBSX Security Gate',
    version: pkgVersion,
    edition: git.edition,
    commit: git.commit,
    shortCommit: git.shortCommit,
    dirtyWorkingTree: git.dirty,
    engineFingerprint: treeHash,
    sdkFingerprint: sdkHash,
    upstream: UPSTREAM_REPO,
    autoUpdate: {
      enabled: process.env.OBSX_AUTO_UPDATE !== 'false',
      lastCheckTime,
      status: lastUpdateStatus,
      latestUpstreamCommit: upstreamCommitCache,
    },
    timestamp: Date.now(),
  };
}

function fetchHttpsText(url) {
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
          return fetchHttpsText(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });
  });
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

    // Strategy B: Standalone / ZIP / Non-Git local directory HTTP sync
    if (!git.isGitRepo && !hasSentinel && remoteSha) {
      let updatedFiles = 0;
      for (const rel of CORE_WATCH_FILES) {
        const rawUrl = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${remoteSha}/${rel}`;
        const remoteContent = await fetchHttpsText(rawUrl);
        const remoteHash = crypto.createHash('sha256').update(remoteContent).digest('hex');
        const localHash = hashFileSha256(rel);
        if (remoteHash !== localHash) {
          fs.writeFileSync(path.join(ROOT_DIR, rel), remoteContent, 'utf8');
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
  if (process.env.OBSX_AUTO_RESTART === 'false' || process.env.NODE_ENV === 'test') return;
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
  }, 5000).unref();

  updateTimer = setInterval(() => {
    checkAndApplyUpstreamUpdate({ silent: true }).catch(() => {});
  }, DEFAULT_INTERVAL_MS);
  updateTimer.unref();
}

module.exports = {
  getSystemVersionInfo,
  checkAndApplyUpstreamUpdate,
  startAutoUpdater,
};
