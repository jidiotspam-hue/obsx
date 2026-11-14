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
  'OPERATOR_EMAILS',
]);

// Supply-chain and runtime test switches must come from process environment, never mutable .env files.
const ENV_FILE_DENYLIST_KEYS = new Set([
  'OBSX_TEST_MODE',
  'TEST_MODE',
  'OBSX_UPSTREAM_REPO',
  'OBSX_UPSTREAM_BRANCH',
  'OBSX_HTTP_SYNC',
  'OBSX_ALLOW_UNVERIFIED_UPDATES',
]);

function loadEnv() {
  const envPath = path.join(__dirname, '../.env');
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

      // A test run must not inherit the box's production posture. On the Pi the
      // .env sitting next to the tests says NODE_ENV=production and
      // STRICT_GATE=true, which silently puts the Security Gate into strict mode
      // for tests that send no attestation token (403 instead of 200) and points
      // the KV store at the live snapshot file. Under OBSX_TEST_MODE=1 those keys
      // are ignored; the real server (no OBSX_TEST_MODE) still reads every key,
      // so production keeps its full configuration.
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
};
