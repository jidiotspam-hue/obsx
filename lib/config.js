'use strict';

/**
 * Lightweight Zero-Dependency Environment Loader (.env)
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

      // Strip enclosing quotes if present
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }

      // A test run must not inherit the box's production posture. On the Pi the
      // .env sitting next to the tests says NODE_ENV=production and
      // STRICT_GATE=true, which silently puts the Security Gate into strict mode
      // for tests that send no attestation token (403 instead of 200) and points
      // the KV store at the live snapshot file. Under OBSX_TEST_MODE=1 those keys
      // are ignored; the real server (no OBSX_TEST_MODE) still reads every key,
      // so production keeps its full configuration.
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
