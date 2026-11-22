'use strict';

/**
 * Lightweight Zero-Dependency Environment Loader (.env) (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 */

const fs = require('fs');
const path = require('path');

// Keys that decide how strict the gate is and how persistent the store is. They
// belong to the deployment, not to a unit-test run.
const POSTURE_KEYS = new Set([
  'NODE_ENV',
  'STRICT_GATE',
  'OBSX_PERSIST_KV',
  'KV_SNAPSHOT_PATH',
  'OBSX_AUTO_UPDATE',
  'OBSX_AUTO_RESTART',
  'TRUST_PROXY',
  'TRUSTED_PROXY_CIDRS',
]);

// Supply-chain and runtime test switches must come from process environment, never mutable .env files.
const ENV_FILE_DENYLIST_KEYS = new Set([
  'OBSX_TEST_MODE',
  'TEST_MODE',
  'OBSX_UPSTREAM_REPO',
  'OBSX_UPSTREAM_BRANCH',
  'OBSX_HTTP_SYNC',
  'OBSX_ALLOW_UNVERIFIED_UPDATES',
  'OBSX_UPDATE_PUBLIC_KEY',
  'OBSX_UPDATE_TRUSTED_SIGNERS',
  'OBSX_CLOUD_URL',
  'OBSX_CLOUD_PUBLIC_KEY',
  'OBSX_CLOUD_SYNC_SECRET',
  'OBSX_ENFORCE_OFFICIAL',
  'OBSX_ALLOW_DOWNGRADE',
  'OBSX_OPERATOR_EMAILS',
  'OBSX_OPERATOR_EMAIL',
  'OPERATOR_EMAILS',
  'OPERATOR_EMAIL',
  'OBSX_ALLOW_INSECURE_CLOUD_URL',
  'OBSX_ALLOW_UNVERIFIED_CLOUD_RING',
  'OBSX_ACCEPT_LICENSE',
  'OBSX_ENFORCE_LICENSE_ACCEPTANCE',
  'OBSX_ENFORCE_INTEGRITY',
  'OBSX_LICENSE_STATE_FILE',
  'TRUST_CLOUDFLARE',
]);

function loadEnv(envPath = path.join(__dirname, '../.env')) {
  if (!fs.existsSync(envPath)) return;

  try {
    const content = fs.readFileSync(envPath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const eqIdx = trimmed.indexOf('=');
      if (eqIdx <= 0) continue;

      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();

      // Strip enclosing quotes (and ignore inline comments outside quotes)
      if ((val.startsWith('"') || val.startsWith("'")) && val.length >= 2) {
        const q = val[0];
        let endIdx = -1;
        for (let i = 1; i < val.length; i++) {
          if (q === '"' && val[i] === '\\' && i + 1 < val.length) {
            i++;
            continue;
          }
          if (val[i] === q) {
            endIdx = i;
            break;
          }
        }
        if (endIdx !== -1 && /^\s*(#.*)?$/.test(val.slice(endIdx + 1))) {
          val = val.slice(1, endIdx);
        }
      } else {
        const inlineCommentIdx = val.search(/(?:^|\s)#/);
        if (inlineCommentIdx !== -1) {
          val = val.slice(0, inlineCommentIdx).trim();
        }
      }

      // A test run must not inherit the host's production posture. On edge nodes
      // a local .env may set NODE_ENV=production and STRICT_GATE=true, which
      // silently flips the gate to strict mode during unit tests.
      if (ENV_FILE_DENYLIST_KEYS.has(key)) continue;
      if (process.env.OBSX_TEST_MODE === '1' && POSTURE_KEYS.has(key)) continue;

      if (!(key in process.env)) {
        process.env[key] = val;
      }
    }
  } catch (err) {
    console.warn('[OBSX Config] Failed reading .env:', err.message);
  }
}

loadEnv();

module.exports = {
  loadEnv,
  ENV_FILE_DENYLIST_KEYS,
};
