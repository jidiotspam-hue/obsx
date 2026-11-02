'use strict';

/**
 * OBSX Security Mailer & Notification Dispatcher
 * Zero-dependency, hardened SMTP client supporting STARTTLS and implicit TLS.
 * Formats responsive, security-first notifications and verification codes.
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 (ELv2) — See LICENSE file.
 */

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const noCrlf = (s) => String(s || '').replace(/[\r\n]+/g, ' ').trim();
const addr = (s) => (/<([^<>\s]+)>/.exec(s) || [null, String(s).trim()])[1];
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const b64Chunk = (s) => b64(s).replace(/.{76}/g, '$&\r\n');

function getConfig() {
  const isTest =
    (process.env.NODE_ENV === 'test' ||
      Boolean(process.env.TEST_MODE) ||
      process.execArgv.includes('--test') ||
      process.argv.some((a) => a.includes('test'))) &&
    process.env.FORCE_SMTP !== 'true';

  if (isTest) {
    return {
      host: null,
      port: 587,
      user: null,
      pass: null,
      from: 'OBSX Security <official@obsx.tech>',
      isConfigured: false,
    };
  }

  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const from = process.env.SMTP_FROM || 'OBSX Security <official@obsx.tech>';

  const isConfigured = Boolean(host && user && pass);
  return { host, port, user, pass, from, isConfigured };
}

function parseReplies(sock) {
  let buf = '';
  let waiting = null;
  let ended = null;
  const queue = [];

  const onData = (chunk) => {
    buf += chunk.toString('utf8');
    let m;
    while ((m = /^(\d{3})([ -])(.*)\r?\n/m.exec(buf)) && m.index === 0) {
      buf = buf.slice(m[0].length);
      queue.lines = queue.lines || [];
      queue.lines.push(m[3]);
      if (m[2] === ' ') {
        const reply = { code: Number(m[1]), lines: queue.lines };
        queue.lines = null;
        if (waiting) {
          const w = waiting;
          waiting = null;
          w.resolve(reply);
        } else {
          queue.push(reply);
        }
      }
    }
  };

  const onEnd = (err) => {
    ended = err || new Error('smtp_closed');
    if (waiting) {
      const w = waiting;
      waiting = null;
      w.reject(ended);
    }
  };

  sock.on('data', onData);
  sock.on('error', onEnd);
  sock.on('close', () => onEnd());

  return {
    next() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (ended) return Promise.reject(ended);
      return new Promise((resolve, reject) => { waiting = { resolve, reject }; });
    },
    detach() {
      sock.removeListener('data', onData);
    },
  };
}

function buildMime(msg, from) {
  const boundary = 'obsx-' + crypto.randomBytes(8).toString('hex');
  const safeTo = noCrlf(msg.to);
  const safeSubject = noCrlf(msg.subject);
  const safeFrom = noCrlf(from);
  const fromDomain = addr(safeFrom).split('@')[1] || 'obsx.tech';

  return [
    `From: ${safeFrom}`,
    `To: ${safeTo}`,
    `Subject: =?UTF-8?B?${b64(safeSubject)}?=`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomBytes(12).toString('hex')}@${fromDomain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64Chunk(msg.text),
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64Chunk(msg.html || msg.text),
    `--${boundary}--`,
    '',
  ].join('\r\n');
}

async function sendSmtp(msg) {
  const cfg = getConfig();
  if (!cfg.isConfigured) {
    throw new Error('smtp_not_configured');
  }

  const implicitTls = cfg.port === 465;
  const timeoutMs = 12000;
  const safeRecipient = addr(noCrlf(msg.to));
  const safeSender = addr(noCrlf(cfg.from));

  let sock = implicitTls
    ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host })
    : net.connect({ host: cfg.host, port: cfg.port });

  const timer = setTimeout(() => sock.destroy(new Error('smtp_timeout')), timeoutMs);
  let replies = parseReplies(sock);

  const write = (line) => sock.write(line + '\r\n');
  const expect = async (validCodes, stage) => {
    const res = await replies.next();
    if (!validCodes.includes(res.code)) {
      throw new Error(`smtp_${stage}_error_${res.code}: ${res.lines.join(' ')}`);
    }
    return res;
  };

  try {
    await expect([220], 'greeting');
    write('EHLO obsx.tech');
    let ehlo = await expect([250], 'ehlo');

    if (!implicitTls) {
      if (ehlo.lines.some((l) => /^STARTTLS\b/i.test(l))) {
        write('STARTTLS');
        await expect([220], 'starttls');
        replies.detach();
        sock = tls.connect({ socket: sock, servername: cfg.host });
        replies = parseReplies(sock);
        await new Promise((resolve, reject) => {
          sock.once('secureConnect', resolve);
          sock.once('error', reject);
        });
        write('EHLO obsx.tech');
        ehlo = await expect([250], 'ehlo');
      } else {
        throw new Error('smtp_requires_starttls');
      }
    }

    // Authenticate (AUTH PLAIN)
    const authPayload = b64(`\0${cfg.user}\0${cfg.pass}`);
    write('AUTH PLAIN ' + authPayload);
    await expect([235], 'auth');

    write(`MAIL FROM:<${safeSender}>`);
    await expect([250], 'mail_from');

    write(`RCPT TO:<${safeRecipient}>`);
    await expect([250, 251], 'rcpt');

    write('DATA');
    await expect([354], 'data');

    const mime = buildMime(msg, cfg.from);
    sock.write(mime.replace(/\r\n\./g, '\r\n..') + '\r\n.\r\n');
    await expect([250], 'sent');

    write('QUIT');
    await replies.next().catch(() => {});
    return { ok: true, delivered: true };
  } finally {
    clearTimeout(timer);
    sock.end();
  }
}

/**
 * Dispatch verification code to recipient.
 * Falls back cleanly to secure console output in development / unconfigured environments.
 */
async function sendVerificationCode(to, code) {
  const cfg = getConfig();
  const textBody = `Your OBSX Security verification code is: ${code}\r\n\r\nThis code is valid for 10 minutes. If you did not request this sign-in code, you can safely ignore this email.\r\n\r\n— OBSX Security Systems (https://obsx.tech)`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 32px 16px; margin: 0; }
    .card { max-width: 500px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 36px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 20px; color: #ffffff; letter-spacing: -0.5px; margin-bottom: 24px; }
    .brand-dot { width: 10px; height: 10px; background: #10b981; border-radius: 50%; box-shadow: 0 0 10px #10b981; display: inline-block; }
    h1 { font-size: 22px; color: #f8fafc; margin-top: 0; margin-bottom: 12px; }
    p { font-size: 14.5px; line-height: 1.6; color: #94a3b8; margin-bottom: 24px; }
    .code-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 18px; text-align: center; margin: 28px 0; }
    .code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #34d399; }
    .footer { font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 20px; margin-top: 28px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <span class="brand-dot"></span> OBSX SECURITY
    </div>
    <h1>Verify Your Sign-In</h1>
    <p>Use the 6-digit one-time code below to access your OBSX developer account and telemetry dashboard.</p>
    <div class="code-box">
      <div class="code">${code}</div>
    </div>
    <p style="font-size: 13px; color: #64748b; margin-bottom: 0;">⏱️ This code expires in 10 minutes. If you did not request this, no action is required.</p>
    <div class="footer">
      OBSX Client Integrity & Anti-Automation Node<br>
      Automated dispatch from <a href="https://obsx.tech" style="color: #38bdf8; text-decoration: none;">obsx.tech</a>
    </div>
  </div>
</body>
</html>
  `.trim();

  if (!cfg.isConfigured) {
    if (process.env.NODE_ENV !== 'test') {
      console.log('\n┌────────────────────────────────────────────────────────┐');
      console.log(`│ [OBSX Mailer] Verification Code for ${to.padEnd(25)} │`);
      console.log(`│ Code: ${code.padEnd(49)}│`);
      console.log('│ Note: Set SMTP_USER & SMTP_PASS in .env for delivery   │');
      console.log('└────────────────────────────────────────────────────────┘\n');
    }
    return { ok: true, devMode: true, code };
  }

  try {
    return await sendSmtp({
      to,
      subject: `Your OBSX Verification Code: ${code}`,
      text: textBody,
      html: htmlBody,
    });
  } catch (err) {
    console.error('[OBSX Mailer Error]', err.message);
    // In production, log error but return structured status
    return { ok: false, error: err.message, devMode: false };
  }
}

/**
 * Send security alert or system update broadcast.
 */
async function sendSecurityAlert(to, { title, summary, actionUrl, severity = 'INFO' }) {
  const cfg = getConfig();
  const textBody = `[OBSX SECURITY ALERT - ${severity}]\r\n${title}\r\n\r\n${summary}\r\n\r\nReview your security dashboard: ${actionUrl || 'https://obsx.tech/dashboard.html'}\r\n\r\n— OBSX Security Systems`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 32px 16px; margin: 0; }
    .card { max-width: 520px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; }
    .brand { font-weight: 700; font-size: 18px; color: #ffffff; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
    .brand-dot { width: 10px; height: 10px; background: #38bdf8; border-radius: 50%; display: inline-block; }
    .tag { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; background: #0369a1; color: #e0f2fe; margin-bottom: 16px; }
    h1 { font-size: 20px; color: #f8fafc; margin-top: 0; }
    p { font-size: 14.5px; line-height: 1.6; color: #94a3b8; }
    .btn { display: inline-block; background: #10b981; color: #ffffff; text-decoration: none; font-weight: 600; font-size: 14px; padding: 10px 20px; border-radius: 6px; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand"><span class="brand-dot"></span> OBSX SECURITY ADVISORY</div>
    <div class="tag">${severity}</div>
    <h1>${noCrlf(title)}</h1>
    <p>${noCrlf(summary)}</p>
    <a href="${actionUrl || 'https://obsx.tech/dashboard.html'}" class="btn">View Security Dashboard</a>
  </div>
</body>
</html>
  `.trim();

  if (!cfg.isConfigured) {
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[OBSX Mailer] Security alert simulated for ${to}: "${title}"`);
    }
    return { ok: true, devMode: true };
  }

  return await sendSmtp({
    to,
    subject: `[OBSX Security] ${title}`,
    text: textBody,
    html: htmlBody,
  });
}

// In-memory alert cooldown circuit breaker (prevents DDoS on operator inbox)
const alertCooldowns = new Map();
const recentAlerts = [];
const COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes per threat code

/**
 * Automatically triggers when high-risk or probe violation attacks hit the node.
 * Strictly throttled to prevent inbox flooding.
 */
async function notifyCriticalIncident({
  code = 'generic_threat',
  title = 'Critical Intrusion Thwarted',
  detail = '',
  clientIp = 'unknown',
  action = 'API Endpoint',
  severity = 'CRITICAL',
  recipient = null,
}) {
  const targetEmail = recipient || process.env.ALERT_EMAIL || process.env.OPERATOR_EMAIL || 'official@obsx.tech';
  const now = Date.now();
  const lastSent = alertCooldowns.get(code) || 0;

  const alertEntry = {
    id: 'alt_' + now.toString(36) + Math.random().toString(36).slice(2, 5),
    timestamp: now,
    code,
    title,
    detail,
    clientIp,
    action,
    severity,
    recipient: targetEmail,
    throttled: false,
  };

  if (now - lastSent < COOLDOWN_MS) {
    alertEntry.throttled = true;
    recentAlerts.unshift(alertEntry);
    if (recentAlerts.length > 30) recentAlerts.pop();
    return { ok: true, throttled: true, alert: alertEntry };
  }

  alertCooldowns.set(code, now);
  recentAlerts.unshift(alertEntry);
  if (recentAlerts.length > 30) recentAlerts.pop();

  const summary = `Attack Vector: ${code.toUpperCase()}\nEndpoint: ${action}\nClient IP: ${clientIp}\nDetail: ${detail || 'Hard security invariant breach detected by OBSX gate.'}\nTime: ${new Date(now).toUTCString()}`;

  const dispatch = await sendSecurityAlert(targetEmail, {
    title: `[${severity}] ${title} (${code})`,
    summary,
    actionUrl: 'https://obsx.tech/dashboard.html',
    severity,
  });

  return { ok: true, throttled: false, dispatch, alert: alertEntry };
}

function getRecentAlerts() {
  return [...recentAlerts];
}

module.exports = {
  getConfig,
  sendVerificationCode,
  sendSecurityAlert,
  notifyCriticalIncident,
  getRecentAlerts,
};
