'use strict';

/**
 * Lightweight Zero-Dependency Environment Loader (.env)
 */

const fs = require('fs');
const path = require('path');

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
