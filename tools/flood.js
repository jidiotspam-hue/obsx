#!/usr/bin/env node
'use strict';

/*
 * OBSX origin-shield soak test. (Zone 2)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 + OBSX Zone 2 Terms — See LICENSE file.
 *
 * Zero dependencies, pure Node. It opens N keep-alive connections and pushes
 * requests through them for a fixed time, then prints a status histogram and
 * latency percentiles. Point it at the origin (http://127.0.0.1:3000) to test
 * the shield without Cloudflare in front, or at the site to test the whole path.
 *
 *   node tools/flood.js --url http://127.0.0.1:3000 --duration 60 --conns 200
 *   node tools/flood.js --url https://obsx.tech --duration 120 --conns 800 --bots
 *
 * Use it to prove the shield works, not to attack other people's servers.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

function arg(name, fallback) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const TARGET = arg('url', 'http://127.0.0.1:3000/');
const DURATION = parseInt(arg('duration', '30'), 10);
const CONNS = parseInt(arg('conns', '100'), 10);
const PATHS = arg('paths', '/,/api/v1/bot-protection,/dashboard.html').split(',');
const BOTS = arg('bots', '0') !== '0';
const STATS = arg('stats', '/api/v1/bot-protection');

const BOT_UA = 'Mozilla/5.0 (compatible; LoadTest/1.0; +https://obsx.tech)';
const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';

const url = new URL(TARGET);
const lib = url.protocol === 'https:' ? https : http;
const agent = new lib.Agent({ keepAlive: true, maxSockets: CONNS });

const status = new Map();
const tiers = new Map();
const latencies = [];
let requests = 0;
let errors = 0;
let stop = false;

function record(ms, res, body) {
  requests++;
  latencies.push(ms);
  status.set(res.statusCode, (status.get(res.statusCode) || 0) + 1);
  const tier = res.headers['x-obsx-botshield'];
  if (tier) tiers.set(tier, (tiers.get(tier) || 0) + 1);
  if (res.statusCode >= 500 && body) {
    try {
      const parsed = JSON.parse(body);
      if (parsed.error) tiers.set('server:' + parsed.error, (tiers.get('server:' + parsed.error) || 0) + 1);
    } catch (err) { /* non-JSON body */ }
  }
}

function worker(id) {
  return new Promise((resolve) => {
    let i = 0;
    const send = () => {
      if (stop) return resolve();
      const path = PATHS[i++ % PATHS.length];
      const started = Date.now();
      const req = lib.request(url, {
        agent,
        method: 'GET',
        path,
        headers: {
          'user-agent': BOTS ? BOT_UA : BROWSER_UA,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.9',
        },
        timeout: 15000,
      }, (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          record(Date.now() - started, res, body);
          setImmediate(send);
        });
      });
      req.on('error', () => { errors++; setImmediate(send); });
      req.on('timeout', () => { req.destroy(); errors++; setImmediate(send); });
      req.end();
    };
    // Stagger the start so 800 sockets do not all open in the same millisecond.
    setTimeout(send, id * 5);
  });
}

function snapshot() {
  return new Promise((resolve) => {
    const statsUrl = new URL(STATS, url);
    const lib2 = statsUrl.protocol === 'https:' ? https : http;
    const req = lib2.request(statsUrl, { method: 'GET', timeout: 5000, headers: { 'user-agent': BROWSER_UA } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch (err) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function percentile(list, p) {
  if (!list.length) return 0;
  const sorted = list.slice().sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

(async function main() {
  const before = await snapshot();
  console.log(`target: ${TARGET}  connections: ${CONNS}  duration: ${DURATION}s  traffic: ${BOTS ? 'scripted bot' : 'browser-like'}`);

  const started = Date.now();
  setTimeout(() => { stop = true; }, DURATION * 1000);
  const progress = setInterval(() => {
    const secs = (Date.now() - started) / 1000;
    console.log(`  ${secs.toFixed(0)}s  ${requests} requests  ${(requests / secs).toFixed(0)} req/s`);
  }, 10000);

  await Promise.all(Array.from({ length: CONNS }, (_, i) => worker(i)));
  clearInterval(progress);

  const secs = (Date.now() - started) / 1000;
  const after = await snapshot();

  const histogram = [...status.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([code, count]) => `${code}: ${count} (${((count / requests) * 100).toFixed(1)}%)`)
    .join('\n  ');
  const tierLines = [...tiers.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([tier, count]) => `${tier}: ${count}`)
    .join('\n  ');

  console.log('\n=== result ===');
  console.log(`requests: ${requests} over ${secs.toFixed(1)}s (${(requests / secs).toFixed(1)} req/s), transport errors: ${errors}`);
  console.log('status histogram:\n  ' + histogram);
  if (tierLines) console.log('shield tiers:\n  ' + tierLines);
  console.log(`latency ms  p50 ${percentile(latencies, 0.5)}  p95 ${percentile(latencies, 0.95)}  p99 ${percentile(latencies, 0.99)}  max ${percentile(latencies, 1)}`);
  if (after && after.counters) {
    const d = before ? after.counters.requests - before.counters.requests : after.counters.requests;
    console.log(`origin shield saw ${d} requests this run: ${after.counters.blocked} refused, ${after.counters.challenged} challenged, ${after.counters.servedRequests} served, ${after.counters.shed} shed`);
    console.log(`origin state: engaged=${after.engaged}, difficulty=${after.difficultyBits}, rss=${(after.health && after.health.rssMb) || 0} MB, quarantined=${after.counters.quarantined}`);
  }
  agent.destroy();
}());
