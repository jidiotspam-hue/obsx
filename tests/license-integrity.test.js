'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const updater = require('../lib/updater');

const ROOT = path.resolve(__dirname, '..');

function writeTreeFiles(baseDir, overrides = {}) {
  const files = {
    LICENSE: 'Dual License v1\n',
    'lib/core.js': 'module.exports = {};\n',
    'lib/botshield.js': 'module.exports = {};\n',
    'lib/updater.js': 'module.exports = {};\n',
    'lib/crypto.js': 'module.exports = {};\n',
    'lib/accounts.js': 'module.exports = {};\n',
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
  const baselineText = fs.readFileSync(path.join(ROOT, 'docs', 'README.baseline.md'), 'utf8');
  const archText = fs.readFileSync(path.join(ROOT, 'docs/ARCHITECTURE.md'), 'utf8');
  const releaseNotes = fs.readFileSync(path.join(ROOT, 'docs/RELEASE_NOTES.md'), 'utf8');
  const termsHtml = fs.readFileSync(path.join(ROOT, 'public/terms.html'), 'utf8');
  const sdkMin = fs.readFileSync(path.join(ROOT, 'public/obsx.min.js'), 'utf8');

  assert.equal(pkg.license, 'MIT AND LicenseRef-OBSX-Zone-2-1.0');
  assert.ok(!licenseText.includes('UNIVERSAL & RETROACTIVE APPLICABILITY'));
  assert.ok(licenseText.includes('Prospective Applicability'));
  assert.ok(!licenseText.includes('Elastic License 2.0'));
  assert.ok(!readmeText.includes('Universal & Retroactive Applicability'));
  assert.ok(!baselineText.includes('Universal & Retroactive Applicability'));
  assert.ok(!archText.includes('Open source under the MIT License'));
  assert.ok(releaseNotes.includes(pkg.version));
  assert.ok(sdkMin.includes('MIT License'), 'Built client SDK must retain MIT attribution banner');

  const zone1Start = licenseText.indexOf('- **Zone 1 (`MIT`)**');
  const zone2Start = licenseText.indexOf('- **Zone 2 (`LicenseRef-OBSX-Zone-2-1.0`');
  const propStart = licenseText.indexOf('- **Closed-Source / Proprietary Modules');
  assert.ok(zone1Start >= 0 && zone2Start > zone1Start && propStart > zone2Start);
  const zone1Section = licenseText.slice(zone1Start, propStart);
  const zone2PartStart = licenseText.indexOf('## PART 2: OBSX SOURCE-AVAILABLE LICENSE v1.0');
  const zone2Section = licenseText.slice(zone2PartStart);

  for (const z1 of [
    'lib/core.js',
    'lib/crypto.js',
    'lib/kv.js',
    'lib/config.js',
    'index.d.ts',
    'scripts/',
    'docs/',
    'package.json',
    '.gitignore',
    'docs/README.baseline.md',
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
    '.github/',
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
    assert.ok(!html.includes('ELv2 + OBSX Zone 2 Terms'), `${htmlFile} must not claim ELv2`);
    assert.ok(html.includes('OBSX Source-Available License v1.0 (Zone 2)'), `${htmlFile} footer must reference OBSX Source-Available License v1.0 (Zone 2)`);
  }

  assert.ok(termsHtml.includes('OBSX Source-Available License v1.0'));

  // Verify npm pack Zone 1 allowlist excludes all Zone 2 and closed-source modules
  const packOut = execFileSync('npm', ['pack', '--json', '--dry-run'], { cwd: ROOT, encoding: 'utf8' });
  const packInfo = JSON.parse(packOut);
  const packedPaths = (packInfo[0] && packInfo[0].files || []).map((f) => f.path);
  assert.ok(packedPaths.includes('lib/core.js'), 'npm pack must include Zone 1 lib/core.js');
  assert.ok(packedPaths.includes('lib/index.js'), 'npm pack must include Zone 1 lib/index.js');
  for (const forbidden of ['server.js', 'lib/botshield.js', 'lib/sentinel.js', 'lib/updater.js', 'lib/accounts.js', 'lib/mailer.js', 'tools/flood.js', 'public/veritas.min.js', 'README.baseline.md', 'docs/README.baseline.md']) {
    assert.ok(!packedPaths.includes(forbidden), `npm pack must exclude Zone 2 / proprietary file: ${forbidden}`);
  }
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

    // 3a. Unsigned Strategy B fails closed unless Ed25519 manifest or OBSX_ALLOW_UNVERIFIED_UPDATES=true is set
    const unsignedBlocked = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_HTTP_SYNC: 'true' },
      assetFiles: ['LICENSE', 'lib/updater.js'],
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return commitPayload;
        return Buffer.from('unsigned-payload');
      },
    });
    assert.equal(unsignedBlocked.updated, false);
    assert.equal(unsignedBlocked.status, 'signature_verification_required');

    // 3b. Valid Ed25519 signed manifest updates files atomically
    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const updatedCorePayload = Buffer.from('module.exports = { signed: true };\n');
    const manifestObj = {
      commit: validSha,
      files: {
        'lib/core.js': nodeCrypto.createHash('sha256').update(updatedCorePayload).digest('hex'),
      },
    };
    const manifestBuf = Buffer.from(JSON.stringify(manifestObj));
    const sigBuf = nodeCrypto.sign(null, manifestBuf, privateKey);
    const signedSyncRes = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_HTTP_SYNC: 'true', OBSX_UPDATE_PUBLIC_KEY: pubPem },
      assetFiles: ['lib/core.js'],
      triggerRestart: () => {},
      fetchBuffer: async (url) => {
        if (url.includes('/commits/')) return commitPayload;
        if (url.endsWith('/obsx-release-manifest.json')) return manifestBuf;
        if (url.endsWith('/obsx-release-manifest.sig')) return sigBuf;
        if (url.endsWith('/lib/core.js')) return updatedCorePayload;
        return Buffer.alloc(0);
      },
    });
    assert.equal(signedSyncRes.updated, true);
    assert.equal(fs.readFileSync(path.join(tmpDir, 'lib/core.js'), 'utf8'), 'module.exports = { signed: true };\n');

    // Reset lib/core.js before break-glass CRLF/empty-buffer test
    fs.writeFileSync(path.join(tmpDir, 'lib/core.js'), 'module.exports = { v: 1 };\n');

    // 3c. With OBSX_HTTP_SYNC=true + break-glass opt-in: CRLF match skips write, empty buffer skips write, valid change writes & rebuilds
    let restarted = false;
    const syncRes = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_HTTP_SYNC: 'true', OBSX_ALLOW_UNVERIFIED_UPDATES: 'true' },
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

    // 3d. Rejects branch flag injection & validates hybrid ring entries strictly
    const badBranchRes = await updater.checkAndApplyUpstreamUpdate({
      force: true,
      rootDir: tmpDir,
      env: { OBSX_UPSTREAM_BRANCH: '--upload-pack=touch /tmp/pwn' },
    });
    assert.equal(badBranchRes.updated, false);
    assert.equal(badBranchRes.status, 'invalid_upstream_config');

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

test('hardening: normalizeCloudRingSubnetKey rejects unspecified :: and full fe80::/10 link-local ranges', () => {
  assert.equal(updater.normalizeCloudRingSubnetKey('subnet:v6:0000:0000:0000/48'), null);
  assert.equal(updater.normalizeCloudRingSubnetKey('::/48'), null);
  assert.equal(updater.normalizeCloudRingSubnetKey('subnet:v6:fe85:0000:0000/48'), null);
  assert.equal(updater.normalizeCloudRingSubnetKey('subnet:v6:febf:1234:5678/48'), null);
  assert.equal(updater.normalizeCloudRingSubnetKey('subnet:v6:2001:0db8:85a3/48'), 'subnet:v6:2001:0db8:85a3/48');
});

test('hardening: empty/whitespace LICENSE & critical files trigger Safe Mode and OBSX_ENFORCE_INTEGRITY pins tree fingerprint', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-lic-empty-'));
  try {
    writeTreeFiles(tmpDir);

    // 1. Accepted baseline works under both OBSX_ENFORCE_LICENSE_ACCEPTANCE and OBSX_ENFORCE_INTEGRITY
    const strictEnv = {
      OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true',
      OBSX_ENFORCE_INTEGRITY: 'true',
    };
    const beforeAccept = updater.getLicenseStatus({ rootDir: tmpDir, env: strictEnv });
    assert.equal(beforeAccept.safeMode, true);
    assert.equal(beforeAccept.safeModeReason, 'license_acceptance_required');
    assert.equal(beforeAccept.enforceIntegrity, true);

    const accepted = updater.acceptLicenseTerms({ acceptedBy: 'ops@obsx.tech' }, { rootDir: tmpDir, env: strictEnv });
    assert.equal(accepted.ok, true);
    assert.equal(accepted.safeMode, false);
    assert.equal(accepted.treeChanged, false);
    assert.match(accepted.treeFingerprint, /^[0-9a-f]{16}$/);

    // 2. Modifying lib/core.js without touching LICENSE triggers critical_integrity_changed under OBSX_ENFORCE_INTEGRITY
    fs.writeFileSync(path.join(tmpDir, 'lib/core.js'), 'module.exports = { tampered: true };\n', 'utf8');
    const tampered = updater.getLicenseStatus({ rootDir: tmpDir, env: strictEnv });
    assert.equal(tampered.safeMode, true);
    assert.equal(tampered.safeModeReason, 'critical_integrity_changed');
    assert.equal(tampered.treeChanged, true);
    assert.equal(tampered.licenseChanged, false);

    // Non-strict mode still notes treeChanged while keeping runtime operational unless files are missing/empty
    const relaxedDrift = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(relaxedDrift.safeMode, false);
    assert.equal(relaxedDrift.treeChanged, true);

    // Operator re-acceptance re-pins acceptedTreeFingerprint and exits Safe Mode
    const treeAdv = updater.getOperatorDriftAdvisory({ rootDir: tmpDir, env: {} });
    assert.equal(treeAdv.showReminder, true);
    assert.ok(typeof treeAdv.version === 'string' && treeAdv.version.length > 0);
    assert.equal(typeof treeAdv.localCommit, 'string');
    assert.equal(treeAdv.licenseStatus.treeChanged, true);

    const reaccepted = updater.acceptLicenseTerms({ acceptedBy: 'ops@obsx.tech' }, { rootDir: tmpDir, env: strictEnv });
    assert.equal(reaccepted.ok, true);
    assert.equal(reaccepted.safeMode, false);
    assert.equal(reaccepted.treeChanged, false);

    // 3. Empty/whitespace lib/crypto.js and lib/accounts.js trigger missing_critical_files even with empty env
    fs.writeFileSync(path.join(tmpDir, 'lib/crypto.js'), '   \n\t  ', 'utf8');
    const emptyCrypto = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(emptyCrypto.safeMode, true);
    assert.equal(emptyCrypto.safeModeReason, 'missing_critical_files');
    assert.ok(emptyCrypto.missingCriticalFiles.includes('lib/crypto.js'));

    writeTreeFiles(tmpDir);
    fs.writeFileSync(path.join(tmpDir, 'lib/accounts.js'), '', 'utf8');
    const emptyAccounts = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(emptyAccounts.safeMode, true);
    assert.equal(emptyAccounts.safeModeReason, 'missing_critical_files');
    assert.ok(emptyAccounts.missingCriticalFiles.includes('lib/accounts.js'));

    // 4. Empty/whitespace LICENSE triggers missing_license_file (even with OBSX_ACCEPT_LICENSE=true) and blocks acceptLicenseTerms
    writeTreeFiles(tmpDir);
    fs.writeFileSync(path.join(tmpDir, 'LICENSE'), ' \n\r\t ', 'utf8');
    const emptyLic = updater.getLicenseStatus({ rootDir: tmpDir, env: { OBSX_ACCEPT_LICENSE: 'true' } });
    assert.equal(emptyLic.safeMode, true);
    assert.equal(emptyLic.safeModeReason, 'missing_license_file');
    assert.equal(emptyLic.licenseSha256, null);
    assert.equal(emptyLic.accepted, false);
    assert.ok(emptyLic.missingCriticalFiles.includes('LICENSE'));

    const emptyLicAccept = updater.acceptLicenseTerms({ acceptedBy: 'ops@obsx.tech' }, { rootDir: tmpDir, env: {} });
    assert.equal(emptyLicAccept.ok, false);
    assert.equal(emptyLicAccept.error, 'missing_license_file');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('hardening: config.loadEnv ignores OBSX_ACCEPT_LICENSE, OBSX_ENFORCE_LICENSE_ACCEPTANCE, and OBSX_ENFORCE_INTEGRITY in .env', () => {
  const config = require('../lib/config');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-cfg-deny-'));
  const prevAccept = process.env.OBSX_ACCEPT_LICENSE;
  const prevEnforceLic = process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
  const prevEnforceInt = process.env.OBSX_ENFORCE_INTEGRITY;
  try {
    delete process.env.OBSX_ACCEPT_LICENSE;
    delete process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
    delete process.env.OBSX_ENFORCE_INTEGRITY;

    for (const k of ['OBSX_ACCEPT_LICENSE', 'OBSX_ENFORCE_LICENSE_ACCEPTANCE', 'OBSX_ENFORCE_INTEGRITY']) {
      assert.ok(config.ENV_FILE_DENYLIST_KEYS.has(k), `Expected ${k} in ENV_FILE_DENYLIST_KEYS`);
    }

    const fakeEnv = path.join(tmpDir, '.env');
    fs.writeFileSync(
      fakeEnv,
      'OBSX_ACCEPT_LICENSE=true\nOBSX_ENFORCE_LICENSE_ACCEPTANCE=true\nOBSX_ENFORCE_INTEGRITY=true\n',
      'utf8'
    );
    config.loadEnv(fakeEnv);

    assert.equal('OBSX_ACCEPT_LICENSE' in process.env, false);
    assert.equal('OBSX_ENFORCE_LICENSE_ACCEPTANCE' in process.env, false);
    assert.equal('OBSX_ENFORCE_INTEGRITY' in process.env, false);
  } finally {
    if (prevAccept === undefined) delete process.env.OBSX_ACCEPT_LICENSE;
    else process.env.OBSX_ACCEPT_LICENSE = prevAccept;
    if (prevEnforceLic === undefined) delete process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE;
    else process.env.OBSX_ENFORCE_LICENSE_ACCEPTANCE = prevEnforceLic;
    if (prevEnforceInt === undefined) delete process.env.OBSX_ENFORCE_INTEGRITY;
    else process.env.OBSX_ENFORCE_INTEGRITY = prevEnforceInt;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
