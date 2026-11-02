'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mailer = require('../lib/mailer');

test('mailer: dev mode fallback works gracefully when SMTP credentials are unset', async () => {
  const res = await mailer.sendVerificationCode('dev_test@example.com', '654321');
  assert.equal(res.ok, true);
  assert.equal(res.devMode, true);
  assert.equal(res.code, '654321');
});

test('mailer: security alert formats cleanly without throwing', async () => {
  const res = await mailer.sendSecurityAlert('dev_test@example.com', {
    title: 'Node Status OK',
    summary: 'Cloudflare tunnel connection verified across 4 regions.',
    severity: 'LOW',
  });
  assert.equal(res.ok, true);
});

test('mailer: critical incident auto-notifier enforces anti-spam cooldown throttle', async () => {
  const first = await mailer.notifyCriticalIncident({
    code: 'honeypot_test_probe',
    title: 'Honeypot Triggered',
    detail: 'Unauthorized probe on /__VERITAS_DEBUG__',
    clientIp: '198.51.100.42',
    action: 'POST /api/v1/verify',
    severity: 'CRITICAL',
  });
  assert.equal(first.ok, true);
  assert.equal(first.throttled, false);

  // Immediate subsequent call with identical code must be throttled
  const second = await mailer.notifyCriticalIncident({
    code: 'honeypot_test_probe',
    title: 'Duplicate Probe',
    detail: 'Automated replay',
    clientIp: '198.51.100.42',
  });
  assert.equal(second.ok, true);
  assert.equal(second.throttled, true);

  const alerts = mailer.getRecentAlerts();
  assert.ok(alerts.length >= 2);
  assert.equal(alerts[0].code, 'honeypot_test_probe');
});
