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

const SYNC_ASSET_FILES = [
  ...CORE_WATCH_FILES,
  'src/tracer.js',
  'public/dashboard.js',
  'public/index.html',
  'public/dram-dark.jpg',
  'public/dram-light.jpg',
  'public/dram-stick.svg',
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
    // For text assets and source code, normalize CRLF to LF to prevent false-positive
    // tree fingerprint mismatches and Safe Mode triggers across Windows/macOS checkouts
    const isBinary = /\.(jpg|jpeg|png|gif|ico|webp|woff2?|eot|ttf|bin)$/i.test(relPath);
    if (isBinary) {
      return crypto.createHash('sha256').update(buf).digest('hex');
    }
    const normalized = buf.toString('utf8').replace(/\r\n/g, '\n');
    return crypto.createHash('sha256').update(Buffer.from(normalized, 'utf8')).digest('hex');
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

    // Strategy B: Standalone / ZIP / Non-Git local directory HTTP sync
    if (!git.isGitRepo && !hasSentinel && remoteSha) {
      let updatedFiles = 0;
      for (const rel of SYNC_ASSET_FILES) {
        const rawUrl = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${remoteSha}/${rel}`;
        const remoteBuf = await fetchHttpsBuffer(rawUrl);
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
        // Restore clean state and re-apply without conflict markers if needed
        execFileSync('git', ['reset', '--hard', 'HEAD'], { cwd: ROOT_DIR, timeout: 5000 });
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

  const overlappingFiles = locallyModifiedFiles.filter((f) => upstreamChangedFiles.includes(f));
  const showReminder = Boolean(git.dirty || commitsBehind > 0);

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
};
