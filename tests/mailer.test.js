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

test('mailer: critical incident auto-notifier fails closed without recipient and enforces cooldown', async () => {
  const savedAlert = process.env.ALERT_EMAIL;
  const savedOp = process.env.OPERATOR_EMAIL;
  const savedOps = process.env.OPERATOR_EMAILS;
  delete process.env.ALERT_EMAIL;
  delete process.env.OPERATOR_EMAIL;
  delete process.env.OPERATOR_EMAILS;
  try {
    const unconfigured = await mailer.notifyCriticalIncident({
      code: 'unconfigured_probe',
      title: 'Unconfigured Recipient Probe',
      detail: 'Should fail closed when no recipient is configured',
      clientIp: '198.51.100.42',
    });
    assert.equal(unconfigured.ok, false);
    assert.equal(unconfigured.skipped, true);
    assert.equal(unconfigured.reason, 'no_recipient_configured');
  } finally {
    if (savedAlert !== undefined) process.env.ALERT_EMAIL = savedAlert;
    if (savedOp !== undefined) process.env.OPERATOR_EMAIL = savedOp;
    if (savedOps !== undefined) process.env.OPERATOR_EMAILS = savedOps;
  }

  const first = await mailer.notifyCriticalIncident({
    code: 'honeypot_test_probe',
    title: 'Honeypot Triggered',
    detail: 'Unauthorized probe on /__OBSX_DEBUG__',
    clientIp: '198.51.100.42',
    action: 'POST /api/v1/verify',
    severity: 'CRITICAL',
    recipient: 'operator@example.com',
  });
  assert.equal(first.ok, true);
  assert.equal(first.throttled, false);

  // Immediate subsequent call with identical code must be throttled
  const second = await mailer.notifyCriticalIncident({
    code: 'honeypot_test_probe',
    title: 'Duplicate Probe',
    detail: 'Automated replay',
    clientIp: '198.51.100.42',
    recipient: 'operator@example.com',
  });
  assert.equal(second.ok, true);
  assert.equal(second.throttled, true);

  const alerts = mailer.getRecentAlerts();
  assert.ok(alerts.length >= 2);
  assert.equal(alerts[0].code, 'honeypot_test_probe');
});
