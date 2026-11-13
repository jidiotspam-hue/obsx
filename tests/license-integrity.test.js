'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const updater = require('../lib/updater');

const ROOT = path.resolve(__dirname, '..');

function writeTreeFiles(baseDir, overrides = {}) {
  const files = {
    LICENSE: 'Dual License v1\n',
    'lib/core.js': 'module.exports = {};\n',
    'lib/botshield.js': 'module.exports = {};\n',
    'lib/updater.js': 'module.exports = {};\n',
    ...overrides,
  };
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(baseDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    if (content === null) {
      if (fs.existsSync(full)) fs.unlinkSync(full);
    } else {
      fs.writeFileSync(full, content, 'utf8');
    }
  }
}

test('license: repository LICENSE, package.json, README, and HTML pages stay aligned', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const licenseText = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
  const readmeText = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const baselineText = fs.readFileSync(path.join(ROOT, 'README.baseline.md'), 'utf8');
  const archText = fs.readFileSync(path.join(ROOT, 'docs/ARCHITECTURE.md'), 'utf8');
  const releaseNotes = fs.readFileSync(path.join(ROOT, 'docs/RELEASE_NOTES.md'), 'utf8');
  const termsHtml = fs.readFileSync(path.join(ROOT, 'public/terms.html'), 'utf8');
  const sdkMin = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'), 'utf8');

  assert.equal(pkg.license, 'SEE LICENSE IN LICENSE');
  assert.ok(!licenseText.includes('UNIVERSAL & RETROACTIVE APPLICABILITY'));
  assert.ok(licenseText.includes('PROSPECTIVE APPLICABILITY & PRIOR RELEASES'));
  assert.ok(!readmeText.includes('Universal & Retroactive Applicability'));
  assert.ok(!baselineText.includes('Universal & Retroactive Applicability'));
  assert.ok(!archText.includes('Open source under the MIT License'));
  assert.ok(releaseNotes.includes(pkg.version));
  assert.ok(sdkMin.includes('MIT License'), 'Built client SDK must retain MIT attribution banner');

  const zone1Start = licenseText.indexOf('1. **ZONE 1:');
  const zone2Start = licenseText.indexOf('2. **ZONE 2:');
  const propStart = licenseText.indexOf('## PROPRIETARY & CLOSED-SOURCE NOTICE');
  assert.ok(zone1Start >= 0 && zone2Start > zone1Start && propStart > zone2Start);
  const zone1Section = licenseText.slice(zone1Start, zone2Start);
  const zone2Section = licenseText.slice(zone2Start, propStart);

  for (const z1 of [
    'lib/core.js',
    'lib/crypto.js',
    'lib/kv.js',
    'lib/config.js',
    'index.d.ts',
    'scripts/',
    'docs/',
    '.github/',
    'package.json',
    '.gitignore',
    'README.baseline.md',
  ]) {
    assert.ok(zone1Section.includes(z1), `LICENSE Zone 1 must include ${z1}`);
  }

  for (const z2 of [
    'server.js',
    'lib/accounts.js',
    'lib/mailer.js',
    'lib/botshield.js',
    'lib/updater.js',
    'tools/flood.js',
    'public/dashboard.html',
  ]) {
    assert.ok(zone2Section.includes(z2), `LICENSE Zone 2 must include ${z2}`);
  }

  for (const htmlFile of [
    'public/index.html',
    'public/dashboard.html',
    'public/docs.html',
    'public/notes.html',
    'public/privacy.html',
    'public/terms.html',
  ]) {
    const html = fs.readFileSync(path.join(ROOT, htmlFile), 'utf8');
    assert.ok(!html.includes('Open source under the MIT License.'), `${htmlFile} must reflect dual licensing`);
    assert.ok(!html.includes('MIT Open-Source License · Acceptable Use Policy'), `${htmlFile} hero pill must reflect dual licensing`);
    assert.ok(!html.includes('Zero External Dependencies · MIT\n'), `${htmlFile} hero pill must not claim MIT-only node runtime`);
    assert.ok(html.includes('ELv2 + OBSX Zone 2 Terms (Operator)'), `${htmlFile} footer must reference ELv2 + OBSX Zone 2 Terms`);
  }

  assert.ok(termsHtml.includes('Elastic License 2.0 + Additional OBSX Zone 2 Terms'));
});

test('updater: tree fingerprint includes LICENSE/shield/updater and normalizes CRLF', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-fp-'));
  try {
    writeTreeFiles(tmpDir, { LICENSE: 'line1\nline2\n' });
    const fpLf = updater.computeTreeFingerprint(tmpDir);

    writeTreeFiles(tmpDir, { LICENSE: 'line1\r\nline2\r\n' });
    const fpCrlf = updater.computeTreeFingerprint(tmpDir);
    assert.equal(fpCrlf, fpLf, 'CRLF normalization must preserve fingerprint across platforms');

    writeTreeFiles(tmpDir, { LICENSE: 'line1\nchanged-line2\n' });
    const fpLicChanged = updater.computeTreeFingerprint(tmpDir);
    assert.notEqual(fpLicChanged, fpLf, 'LICENSE changes must alter engine tree fingerprint');

    writeTreeFiles(tmpDir, { LICENSE: 'line1\nline2\n', 'lib/botshield.js': 'module.exports = { changed: true };\n' });
    const fpShieldChanged = updater.computeTreeFingerprint(tmpDir);
    assert.notEqual(fpShieldChanged, fpLf, 'BotShield changes must alter engine tree fingerprint');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('updater: getLicenseStatus and acceptLicenseTerms detect missing files, drift, corrupt state, and env acceptance safely', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-lic-'));
  try {
    writeTreeFiles(tmpDir);

    // 1. Healthy baseline without enforcement
    const baseline = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(baseline.ok, true);
    assert.equal(baseline.safeMode, false);
    assert.equal(baseline.accepted, false);
    assert.equal(baseline.licenseChanged, false);

    // 2. Enforced acceptance requires operator or env opt-in
    const unaccepted = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(unaccepted.safeMode, true);
    assert.equal(unaccepted.safeModeReason, 'license_acceptance_required');

    // 3. Env acceptance clears requirement cleanly
    const envAccepted = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true', OBSX_ACCEPT_LICENSE: 'true' },
    });
    assert.equal(envAccepted.safeMode, false);
    assert.equal(envAccepted.accepted, true);
    assert.equal(envAccepted.acceptedVia, 'env');

    // 4. Operator acceptance persists hash cleanly
    const recorded = updater.acceptLicenseTerms(
      { acceptedBy: 'ops@obsx.tech' },
      { rootDir: tmpDir, env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' } }
    );
    assert.equal(recorded.ok, true);
    assert.equal(recorded.safeMode, false);
    assert.equal(recorded.accepted, true);
    assert.equal(recorded.acceptedBy, 'ops@obsx.tech');
    assert.equal(recorded.acceptedVia, 'state_file');

    // 5. Drifted LICENSE triggers license_terms_updated and hides stale acceptedBy under env override
    fs.writeFileSync(path.join(tmpDir, 'LICENSE'), 'Updated Dual License v2\n', 'utf8');
    const drifted = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(drifted.licenseChanged, true);
    assert.equal(drifted.safeMode, true);
    assert.equal(drifted.safeModeReason, 'license_terms_updated');

    const envDrifted = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ACCEPT_LICENSE: 'true', OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(envDrifted.accepted, true);
    assert.equal(envDrifted.acceptedVia, 'env');
    assert.equal(envDrifted.acceptedBy, null, 'Env override must not attribute acceptance to stale state-file operator');

    // 6. Malformed or non-JSON state file triggers Safe Mode and recovers cleanly on acceptLicenseTerms
    fs.writeFileSync(path.join(tmpDir, '.obsx-license-state.json'), '{"acceptedHash":"bad"}', 'utf8');
    const malformed = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(malformed.safeMode, true);
    assert.equal(malformed.safeModeReason, 'corrupt_license_state');

    fs.writeFileSync(path.join(tmpDir, '.obsx-license-state.json'), '{not-json', 'utf8');
    const corrupt = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(corrupt.safeMode, true);
    assert.equal(corrupt.safeModeReason, 'corrupt_license_state');

    const recovered = updater.acceptLicenseTerms({ acceptedBy: 'ops@obsx.tech' }, { rootDir: tmpDir, env: {} });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.safeMode, false);

    // 7. Missing non-LICENSE critical file triggers missing_critical_files even when LICENSE is accepted
    fs.unlinkSync(path.join(tmpDir, 'lib/botshield.js'));
    const missingShield = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(missingShield.safeMode, true);
    assert.equal(missingShield.safeModeReason, 'missing_critical_files');
    assert.ok(missingShield.missingCriticalFiles.includes('lib/botshield.js'));

    const acceptWithMissingShield = updater.acceptLicenseTerms({ acceptedBy: 'ops@obsx.tech' }, { rootDir: tmpDir, env: {} });
    assert.equal(acceptWithMissingShield.ok, true);
    assert.equal(acceptWithMissingShield.saved, true);
    assert.equal(acceptWithMissingShield.safeMode, true);
    assert.equal(acceptWithMissingShield.safeModeReason, 'missing_critical_files');

    // 8. Missing LICENSE triggers missing_license_file (even with OBSX_ACCEPT_LICENSE=true) and blocks accept
    fs.unlinkSync(path.join(tmpDir, 'LICENSE'));
    const missingLic = updater.getLicenseStatus({ rootDir: tmpDir, env: { OBSX_ACCEPT_LICENSE: 'true' } });
    assert.equal(missingLic.safeMode, true);
    assert.equal(missingLic.safeModeReason, 'missing_license_file');
    assert.equal(missingLic.accepted, false);
    assert.equal(missingLic.acceptedVia, null);
    assert.ok(missingLic.missingCriticalFiles.includes('LICENSE'));

    const missingAccept = updater.acceptLicenseTerms({}, { rootDir: tmpDir, env: {} });
    assert.equal(missingAccept.ok, false);
    assert.equal(missingAccept.error, 'missing_license_file');

    // 9. Nested OBSX_LICENSE_STATE_FILE creates parent directories; unwritable state path returns 500 without leaking raw host errors
    writeTreeFiles(tmpDir);
    const nestedStatePath = path.join(tmpDir, 'nested', 'state-dir', '.obsx-license-state.json');
    const nestedOk = updater.acceptLicenseTerms({ acceptedBy: 'ops' }, { rootDir: tmpDir, statePath: nestedStatePath, env: {} });
    assert.equal(nestedOk.ok, true);
    assert.equal(nestedOk.accepted, true);
    assert.ok(fs.existsSync(nestedStatePath));

    const badStatePath = path.join(tmpDir, 'LICENSE', '.obsx-license-state.json');
    const writeFail = updater.acceptLicenseTerms({ acceptedBy: 'ops' }, { rootDir: tmpDir, statePath: badStatePath, env: {} });
    assert.equal(writeFail.ok, false);
    assert.equal(writeFail.error, 'license_state_write_failed');
    assert.equal(writeFail.statusCode, 500);
    assert.equal(writeFail.message, undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('updater: drift advisory covers non-git Safe Mode and Strategy B / restart remain strictly opt-in', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-stratb-'));
  try {
    writeTreeFiles(tmpDir, { LICENSE: 'line1\nline2\n', 'lib/core.js': 'module.exports = { v: 1 };\n' });

    // Non-git standalone directory in Safe Mode must still surface licenseStatus and showReminder
    const advisory = updater.getOperatorDriftAdvisory({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(advisory.isGitRepo, false);
    assert.equal(advisory.showReminder, true);
    assert.ok(advisory.licenseStatus);
    assert.equal(advisory.licenseStatus.safeMode, true);

    const validSha = '0123456789abcdef0123456789abcdef01234567';
    const commitPayload = Buffer.from(JSON.stringify({ sha: validSha }));

    // 1. Without OBSX_HTTP_SYNC=true, Strategy B refuses to overwrite files even with force: true
    let fetchedRawCount = 0;
    const optInBlocked = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: {},
      assetFiles: ['LICENSE', 'lib/core.js'],
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return commitPayload;
        fetchedRawCount++;
        return Buffer.from('should-not-write');
      },
    });
    assert.equal(optInBlocked.updated, false);
    assert.equal(optInBlocked.status, `http_sync_opt_in_required_${validSha.slice(0, 7)}`);
    assert.equal(fetchedRawCount, 0);

    // 2. Invalid commit SHA never triggers raw sync
    const invalidShaRes = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_HTTP_SYNC: 'true' },
      assetFiles: ['LICENSE'],
      fetchBuffer: async () => Buffer.from(JSON.stringify({ sha: '../evil-ref' })),
    });
    assert.equal(invalidShaRes.updated, false);
    assert.equal(invalidShaRes.status, 'up_to_date');

    // 3. With OBSX_HTTP_SYNC=true: CRLF match skips write, empty buffer skips write, valid change writes & rebuilds
    let restarted = false;
    const syncRes = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_HTTP_SYNC: 'true' },
      assetFiles: ['LICENSE', 'lib/core.js', 'lib/updater.js'],
      triggerRestart: () => { restarted = true; },
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return commitPayload;
        if (url.endsWith('/LICENSE')) return Buffer.from('line1\r\nline2\r\n'); // identical after CRLF normalization
        if (url.endsWith('/lib/core.js')) return Buffer.alloc(0); // empty buffer must be ignored
        if (url.endsWith('/lib/updater.js')) return Buffer.from('module.exports = { updated: true };\n');
        return Buffer.alloc(0);
      },
    });
    assert.equal(syncRes.updated, true);
    assert.equal(syncRes.filesUpdated, 1, 'Only lib/updater.js should be overwritten; CRLF and empty buffers skipped');
    assert.equal(restarted, true);
    assert.equal(fs.readFileSync(path.join(tmpDir, 'LICENSE'), 'utf8'), 'line1\nline2\n');
    assert.equal(fs.readFileSync(path.join(tmpDir, 'lib/core.js'), 'utf8'), 'module.exports = { v: 1 };\n');
    assert.equal(fs.readFileSync(path.join(tmpDir, 'lib/updater.js'), 'utf8'), 'module.exports = { updated: true };\n');

    // 4. triggerHotRestartIfConfigured stays opt-in unless OBSX_AUTO_RESTART === 'true'
    let spawnCount = 0;
    let killSignal = null;
    assert.equal(
      updater.triggerHotRestartIfConfigured({
        allowInTest: true,
        env: { NODE_ENV: 'production' },
        spawn: () => { spawnCount++; return { unref() {} }; },
        kill: (_pid, sig) => { killSignal = sig; },
      }),
      false
    );
    assert.equal(spawnCount, 0);

    assert.equal(
      updater.triggerHotRestartIfConfigured({
        allowInTest: true,
        env: { NODE_ENV: 'production', OBSX_AUTO_RESTART: 'true' },
        spawn: () => { spawnCount++; return { unref() {} }; },
        kill: (_pid, sig) => { killSignal = sig; },
      }),
      true
    );
    assert.equal(spawnCount, 1);
    assert.equal(killSignal, 'SIGTERM');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('updater: autoAdaptDirtyNode preserves conflicting edits in stash and keeps working tree clean', () => {
  const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-git-'));
  const bareRepo = path.join(baseDir, 'upstream.git');
  const seedDir = path.join(baseDir, 'seed');
  const cloneDir = path.join(baseDir, 'node');
  try {
    execFileSync('git', ['init', '--bare', '-b', 'main', bareRepo]);
    execFileSync('git', ['clone', bareRepo, seedDir]);
    execFileSync('git', ['config', 'user.email', 'test@obsx.tech'], { cwd: seedDir });
    execFileSync('git', ['config', 'user.name', 'OBSX Test'], { cwd: seedDir });

    fs.writeFileSync(path.join(seedDir, 'conflict.txt'), 'line1\noriginal\n', 'utf8');
    fs.writeFileSync(path.join(seedDir, 'clean.txt'), 'base\n', 'utf8');
    execFileSync('git', ['add', '.'], { cwd: seedDir });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: seedDir });
    execFileSync('git', ['push', '-u', 'origin', 'main'], { cwd: seedDir });

    execFileSync('git', ['clone', bareRepo, cloneDir]);
    execFileSync('git', ['config', 'user.email', 'test@obsx.tech'], { cwd: cloneDir });
    execFileSync('git', ['config', 'user.name', 'OBSX Test'], { cwd: cloneDir });

    // Upstream modifies conflict.txt
    fs.writeFileSync(path.join(seedDir, 'conflict.txt'), 'line1\nupstream-change\n', 'utf8');
    execFileSync('git', ['add', 'conflict.txt'], { cwd: seedDir });
    execFileSync('git', ['commit', '-m', 'upstream change'], { cwd: seedDir });
    execFileSync('git', ['push', 'origin', 'main'], { cwd: seedDir });

    // Local node modifies BOTH conflict.txt (overlapping) and clean.txt (non-overlapping)
    fs.writeFileSync(path.join(cloneDir, 'conflict.txt'), 'line1\nlocal-custom\n', 'utf8');
    fs.writeFileSync(path.join(cloneDir, 'clean.txt'), 'base\nlocal-clean-edit\n', 'utf8');

    execFileSync('git', ['fetch', 'origin', 'main', '--quiet'], { cwd: cloneDir });
    const upstreamHead = execFileSync('git', ['rev-parse', 'origin/main'], { cwd: cloneDir }).toString().trim();

    // Pre-warm gitInfoCache and gitDriftCache before conflict attempt
    const preAdvisory = updater.getOperatorDriftAdvisory({ rootDir: cloneDir, branch: 'main' });
    assert.equal(preAdvisory.dirtyWorkingTree, true);
    assert.equal(preAdvisory.commitsBehind, 1);

    const adaptRes = updater.autoAdaptDirtyNode({ rootDir: cloneDir, branch: 'main' });
    assert.equal(adaptRes.ok, false);
    assert.equal(adaptRes.conflict, true);

    const statusAfter = execFileSync('git', ['status', '--porcelain'], { cwd: cloneDir }).toString().trim();
    assert.equal(statusAfter, '', 'Conflict rollback must leave working tree cleanly at HEAD');

    // Conflict rollback must immediately invalidate gitInfoCache and gitDriftCache
    const postAdvisory = updater.getOperatorDriftAdvisory({ rootDir: cloneDir, branch: 'main' });
    assert.equal(postAdvisory.dirtyWorkingTree, false);
    assert.equal(postAdvisory.commitsBehind, 0);
    assert.equal(postAdvisory.edition, 'official');
    assert.equal(postAdvisory.localCommit, upstreamHead.slice(0, 7));

    const stashList = execFileSync('git', ['stash', 'list'], { cwd: cloneDir }).toString();
    assert.ok(stashList.includes('obsx-operator-auto-adapt'), 'User edits must remain safely in stash');

    const stashedConflict = execFileSync('git', ['show', 'stash@{0}:conflict.txt'], { cwd: cloneDir }).toString();
    const stashedClean = execFileSync('git', ['show', 'stash@{0}:clean.txt'], { cwd: cloneDir }).toString();
    assert.ok(stashedConflict.includes('local-custom'));
    assert.ok(stashedClean.includes('local-clean-edit'));

    // Non-fatal stash drop error must NOT discard cleanly applied local edits
    execFileSync('git', ['stash', 'drop', 'stash@{0}'], { cwd: cloneDir });
    fs.writeFileSync(path.join(cloneDir, 'clean.txt'), 'base\nnon-conflicting-edit\n', 'utf8');
    const adaptDropErrRes = updater.autoAdaptDirtyNode({
      rootDir: cloneDir,
      branch: 'main',
      execFileSync: (cmd, args, opts) => {
        if (cmd === 'git' && args[0] === 'stash' && args[1] === 'drop') {
          throw new Error('simulated stash drop permission warning');
        }
        return execFileSync(cmd, args, opts);
      },
    });
    assert.equal(adaptDropErrRes.ok, true);
    assert.equal(adaptDropErrRes.adapted, true);
    assert.ok(fs.readFileSync(path.join(cloneDir, 'clean.txt'), 'utf8').includes('non-conflicting-edit'));

    // gitDriftCache serves warm advisory snapshots without spawning git, and honors { fresh: true }
    const warmCached = updater.getOperatorDriftAdvisory({ rootDir: cloneDir, branch: 'main' });
    assert.deepEqual(warmCached.locallyModifiedFiles, ['clean.txt']);
    fs.writeFileSync(path.join(cloneDir, 'conflict.txt'), 'line1\nlocal-second-edit\n', 'utf8');
    const cachedHit = updater.getOperatorDriftAdvisory({ rootDir: cloneDir, branch: 'main' });
    assert.deepEqual(cachedHit.locallyModifiedFiles, ['clean.txt'], 'Expected TTL cache hit to avoid spawning git');
    const freshHit = updater.getOperatorDriftAdvisory({ rootDir: cloneDir, branch: 'main', fresh: true });
    assert.ok(freshHit.locallyModifiedFiles.includes('conflict.txt'));
    assert.ok(freshHit.locallyModifiedFiles.includes('clean.txt'));
  } finally {
    fs.rmSync(baseDir, { recursive: true, force: true });
  }
});
