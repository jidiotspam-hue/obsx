'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

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
  const termsHtml = fs.readFileSync(path.join(ROOT, 'public/terms.html'), 'utf8');

  assert.equal(pkg.license, 'SEE LICENSE IN LICENSE');
  assert.ok(!licenseText.includes('UNIVERSAL & RETROACTIVE APPLICABILITY'));
  assert.ok(licenseText.includes('PROSPECTIVE APPLICABILITY & PRIOR RELEASES'));
  assert.ok(!readmeText.includes('Universal & Retroactive Applicability'));

  for (const mapped of [
    'lib/kv.js',
    'lib/config.js',
    'index.d.ts',
    'scripts/',
    'lib/updater.js',
    'lib/botshield.js',
    'server.js',
    'tools/flood.js',
  ]) {
    assert.ok(licenseText.includes(mapped), `LICENSE must assign ${mapped} to a zone`);
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

    writeTreeFiles(tmpDir, { LICENSE: 'line1\nchanged\n' });
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

    // 5. Drifted LICENSE triggers license_terms_updated under enforcement
    fs.writeFileSync(path.join(tmpDir, 'LICENSE'), 'Updated Dual License v2\n', 'utf8');
    const drifted = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(drifted.licenseChanged, true);
    assert.equal(drifted.safeMode, true);
    assert.equal(drifted.safeModeReason, 'license_terms_updated');

    // 6. Corrupt state file triggers Safe Mode when enforced
    fs.writeFileSync(path.join(tmpDir, '.obsx-license-state.json'), '{not-json', 'utf8');
    const corrupt = updater.getLicenseStatus({
      rootDir: tmpDir,
      env: { OBSX_ENFORCE_LICENSE_ACCEPTANCE: 'true' },
    });
    assert.equal(corrupt.safeMode, true);
    assert.equal(corrupt.safeModeReason, 'corrupt_license_state');

    // 7. Missing LICENSE always triggers missing_license_file Safe Mode and blocks accept
    fs.unlinkSync(path.join(tmpDir, 'LICENSE'));
    const missingLic = updater.getLicenseStatus({ rootDir: tmpDir, env: {} });
    assert.equal(missingLic.safeMode, true);
    assert.equal(missingLic.safeModeReason, 'missing_license_file');
    assert.ok(missingLic.missingCriticalFiles.includes('LICENSE'));

    const missingAccept = updater.acceptLicenseTerms({}, { rootDir: tmpDir, env: {} });
    assert.equal(missingAccept.ok, false);
    assert.equal(missingAccept.error, 'missing_license_file');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
