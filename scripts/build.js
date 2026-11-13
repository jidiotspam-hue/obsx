'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

const srcPath = path.join(__dirname, '../src/tracer.js');
const outDir = path.join(__dirname, '../public');

if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

const source = fs.readFileSync(srcPath, 'utf8');

// Safe minification: strip multi-line comments and pure single-line comment lines,
// then prepend Zone 1 MIT attribution header so distributed bundles retain required notices.
const MIT_BANNER = '/*! OBSX Security Client SDK | Copyright (c) 2026 Alexis Grimmace | MIT License */\n';
const minifiedBody = source
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '')
  .replace(/^\s+|\s+$/gm, '')
  .replace(/\n\s*\n/g, '\n');
const minified = MIT_BANNER + minifiedBody;

// Strict syntax verification before deployment
try {
  new vm.Script(minified);
} catch (syntaxErr) {
  console.error('[OBSX Build ERROR] Minified bundle has syntax errors:', syntaxErr.message);
  process.exit(1);
}

const obsxPath = path.join(outDir, 'obsx.min.js');
const veritasPath = path.join(outDir, 'veritas.min.js');
const tracerPath = path.join(outDir, 'tracer.min.js');

fs.writeFileSync(obsxPath, minified, 'utf8');
fs.writeFileSync(veritasPath, minified, 'utf8');
fs.writeFileSync(tracerPath, minified, 'utf8');

const hash = crypto.createHash('sha256').update(minified).digest('hex');
console.log(`[OBSX Build] Built obsx.min.js, veritas.min.js, tracer.min.js (${minified.length} bytes)`);
console.log(`[OBSX Build] SHA-256: ${hash}`);
