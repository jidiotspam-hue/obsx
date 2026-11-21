'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const { isTestRuntime } = require('./crypto');

/**
 * Universal Key-Value Storage Engine for OBSX (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 * Supports bounded in-memory state with TTL cleanup for zero-dependency execution
 * and optional permission-hardened atomic JSON snapshots (0o600) for single-node restarts.
 */

const LOW_MEM_THRESHOLD_BYTES = 1600 * 1024 * 1024;

function defaultKvMaxKeys(totalMemBytes = os.totalmem()) {
  const envVal = Number(process.env.OBSX_KV_MAX_KEYS);
  if (Number.isFinite(envVal) && envVal > 0) return Math.floor(envVal);
  return totalMemBytes <= LOW_MEM_THRESHOLD_BYTES ? 25000 : 100000;
}

const SNAPSHOT_SENSITIVE_PREFIXES = [
  'tracer:secret',
  'tr:otp:',
  'tr:ec:',
  'tr:auth:',
  'tr:guest:',
];

// High-churn ephemeral rate-limit / counter prefixes should never dirty or
// persist into .kv-snapshot.json, preventing unnecessary disk write wear.
const SNAPSHOT_VOLATILE_PREFIXES = [
  'tr:rl:',
  'tr:cnt:',
  'tr:cd:',
  'tr:cb:cnt:',
  'rate:',
];

function isSensitiveSnapshotKey(key) {
  return SNAPSHOT_SENSITIVE_PREFIXES.some((prefix) =>
    prefix.endsWith(':') ? key.startsWith(prefix) : key === prefix
  );
}

function isVolatileSnapshotKey(key) {
  return SNAPSHOT_VOLATILE_PREFIXES.some((prefix) => key.startsWith(prefix));
}

function shouldSkipSnapshotKey(key) {
  return isSensitiveSnapshotKey(key) || isVolatileSnapshotKey(key);
}

class MemoryStore {
  constructor(maxKeys = defaultKvMaxKeys(), snapshotPath = (isTestRuntime() ? null : (process.env.KV_SNAPSHOT_PATH || (process.env.OBSX_PERSIST_KV === 'true' || process.env.NODE_ENV === 'production' ? path.join(__dirname, '../.kv-snapshot.json') : null)))) {
    this.store = new Map();
    this.ttls = new Map();
    this.maxKeys = maxKeys;
    this.snapshotPath = snapshotPath;
    this._dirty = false;
    this._snapshotInFlight = false;
    this._loadSnapshot();
    this.interval = setInterval(() => this.cleanup(), 1000);
    if (this.interval.unref) this.interval.unref();
    if (this.snapshotPath) {
      const snapMs = Math.max(3000, Number(process.env.OBSX_KV_SNAPSHOT_MS) || 30000);
      this._snapshotInterval = setInterval(() => {
        this._saveSnapshotAsync();
      }, snapMs);
      if (this._snapshotInterval.unref) this._snapshotInterval.unref();
      if (typeof process !== 'undefined' && process.on) {
        process.on('exit', () => {
          if (this._dirty) this.saveSnapshot();
        });
      }
    }
  }

  _loadSnapshot() {
    if (!this.snapshotPath || !fs.existsSync(this.snapshotPath)) return;
    try {
      const st = fs.lstatSync(this.snapshotPath);
      if (st.isSymbolicLink() || !st.isFile()) return;
      const data = JSON.parse(fs.readFileSync(this.snapshotPath, 'utf8'));
      const now = Date.now();
      if (data && typeof data === 'object' && Array.isArray(data.items)) {
        for (const item of data.items) {
          if (!item || typeof item !== 'object') continue;
          if (typeof item.key !== 'string' || !item.key || item.key.length > 512) continue;
          if (
            shouldSkipSnapshotKey(item.key) ||
            item.key === '__proto__' ||
            item.key === 'constructor' ||
            item.key === 'prototype'
          ) {
            continue;
          }
          let exp = null;
          if (item.exp !== null && item.exp !== undefined) {
            if (typeof item.exp !== 'number' || !Number.isFinite(item.exp) || item.exp <= 0) continue;
            if (now >= item.exp) continue;
            exp = item.exp;
          }
          if (item.type === 'hash' && item.value && typeof item.value === 'object' && !Array.isArray(item.value)) {
            const map = new Map();
            for (const [hk, hv] of Object.entries(item.value)) {
              if (hk === '__proto__' || hk === 'constructor' || hk === 'prototype') continue;
              if (item.key.startsWith('tr:s:') && (hk === 'sig' || hk === 'rk')) continue;
              map.set(hk, hv);
            }
            this.store.set(item.key, map);
          } else if (item.type === 'val') {
            this.store.set(item.key, item.value);
          } else {
            continue;
          }
          if (exp) this.ttls.set(item.key, exp);
        }
      }
    } catch (_) {}
  }

  _markDirty(key) {
    if (!key || !shouldSkipSnapshotKey(key)) this._dirty = true;
  }

  _buildSnapshotPayload() {
    const items = [];
    const now = Date.now();
    for (const [key, val] of this.store.entries()) {
      if (shouldSkipSnapshotKey(key)) continue;
      const exp = this.ttls.get(key) || null;
      if (exp && now >= exp) continue;
      if (val instanceof Map) {
        const obj = {};
        for (const [k, v] of val.entries()) {
          if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
          if (key.startsWith('tr:s:') && (k === 'sig' || k === 'rk')) continue;
          obj[k] = v;
        }
        items.push({ key, type: 'hash', value: obj, exp });
      } else {
        items.push({ key, type: 'val', value: val, exp });
      }
    }
    return JSON.stringify({ version: 1, items });
  }

  saveSnapshot() {
    if (!this.snapshotPath) return;
    let tmp = null;
    try {
      try {
        if (fs.lstatSync(this.snapshotPath).isSymbolicLink()) return;
      } catch (_) {}
      const payload = this._buildSnapshotPayload();
      const rand = nodeCrypto.randomBytes(8).toString('hex');
      tmp = `${this.snapshotPath}.tmp.${process.pid}.${rand}`;
      fs.writeFileSync(tmp, payload, { encoding: 'utf8', mode: 0o600 });
      try {
        fs.chmodSync(tmp, 0o600);
      } catch (_) {}
      fs.renameSync(tmp, this.snapshotPath);
      tmp = null;
      this._dirty = false;
      try {
        fs.chmodSync(this.snapshotPath, 0o600);
      } catch (_) {}
    } catch (_) {
      if (tmp) {
        try { fs.unlinkSync(tmp); } catch (_) {}
      }
    }
  }

  async _saveSnapshotAsync() {
    if (!this.snapshotPath || !this._dirty || this._snapshotInFlight) return;
    this._snapshotInFlight = true;
    let tmp = null;
    try {
      try {
        const st = await fs.promises.lstat(this.snapshotPath);
        if (st.isSymbolicLink()) return;
      } catch (_) {}
      const payload = this._buildSnapshotPayload();
      const rand = nodeCrypto.randomBytes(8).toString('hex');
      tmp = `${this.snapshotPath}.tmp.${process.pid}.${rand}`;
      await fs.promises.writeFile(tmp, payload, { encoding: 'utf8', mode: 0o600 });
      try {
        await fs.promises.chmod(tmp, 0o600);
      } catch (_) {}
      await fs.promises.rename(tmp, this.snapshotPath);
      tmp = null;
      this._dirty = false;
      try {
        await fs.promises.chmod(this.snapshotPath, 0o600);
      } catch (_) {}
    } catch (_) {
      if (tmp) {
        try { await fs.promises.unlink(tmp); } catch (_) {}
      }
    } finally {
      this._snapshotInFlight = false;
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [key, exp] of this.ttls.entries()) {
      if (now >= exp) {
        this.store.delete(key);
        this.ttls.delete(key);
      }
    }
  }

  _isExpired(key) {
    if (this.ttls.has(key) && Date.now() >= this.ttls.get(key)) {
      this.store.delete(key);
      this.ttls.delete(key);
      return true;
    }
    return false;
  }

  _evictIfFull() {
    if (this.store.size < this.maxKeys) return;
    const now = Date.now();

    // Pass 1: Active TTL purge of any expired keys first
    let expiredCount = 0;
    for (const [key, exp] of this.ttls.entries()) {
      if (now >= exp) {
        this.store.delete(key);
        this.ttls.delete(key);
        expiredCount++;
        if (expiredCount >= 500) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 2: Evict volatile rate-limit / counter / cooldown keys FIRST
    // Single-use replay locks (tr:used:*, tr:ec:*) are NEVER evicted in Pass 2
    let volatileCount = 0;
    for (const key of this.store.keys()) {
      if (
        key.startsWith('tr:rl:') ||
        key.startsWith('tr:cnt:') ||
        key.startsWith('tr:cd:') ||
        key.startsWith('tr:cb:cnt:') ||
        key.startsWith('rate:')
      ) {
        this.store.delete(key);
        this.ttls.delete(key);
        volatileCount++;
        if (volatileCount >= 200) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 3: Evict unverified / telemetry-less sessions (tr:s:* where no signals recorded)
    let unverifiedCount = 0;
    for (const [key, val] of this.store.entries()) {
      if (key.startsWith('tr:s:')) {
        const hasSignals = val instanceof Map ? val.has('sig') : Boolean(val && typeof val === 'object' && val.sig);
        if (!hasSignals) {
          this.store.delete(key);
          this.ttls.delete(key);
          unverifiedCount++;
          if (unverifiedCount >= 200) break;
        }
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 4: Evict oldest non-critical entries while protecting credentials, verified sessions, and vault state
    let fallbackCount = 0;
    for (const [key, val] of this.store.entries()) {
      const isVerifiedSession =
        key.startsWith('tr:s:') &&
        (val instanceof Map ? val.has('sig') : Boolean(val && typeof val === 'object' && val.sig));
      if (
        key !== 'tracer:secret' &&
        !isVerifiedSession &&
        !key.startsWith('tr:used:') &&
        !key.startsWith('tr:ec:') &&
        !key.startsWith('tr:p:') &&
        !key.startsWith('tr:pk:') &&
        !key.startsWith('tr:sk:') &&
        !key.startsWith('tr:u:') &&
        !key.startsWith('tr:ue:') &&
        !key.startsWith('tr:auth:') &&
        !key.startsWith('tr:vault:')
      ) {
        this.store.delete(key);
        this.ttls.delete(key);
        fallbackCount++;
        if (fallbackCount >= 100) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 5 (session ceiling enforcement): evict oldest dashboard sessions before touching OTP/replay locks
    for (const key of this.store.keys()) {
      if (key.startsWith('tr:auth:')) {
        this.store.delete(key);
        this.ttls.delete(key);
        if (this.store.size < this.maxKeys) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 6 (last-resort cap enforcement): evict oldest OTP/replay locks only when memory ceiling still demands it
    for (const key of this.store.keys()) {
      if (key.startsWith('tr:ec:') || key.startsWith('tr:used:')) {
        this.store.delete(key);
        this.ttls.delete(key);
        if (this.store.size < this.maxKeys) break;
      }
    }
  }

  async get(key) {
    if (this._isExpired(key)) return null;
    const val = this.store.get(key);
    return val !== undefined ? val : null;
  }

  async set(key, value, ...opts) {
    const flags = opts.map((s) => String(s).toUpperCase());
    if (flags.includes('NX')) {
      if (this.store.has(key) && !this._isExpired(key)) {
        return null;
      }
    }
    this._evictIfFull();
    this.store.set(key, value);
    this.ttls.delete(key);
    const exIdx = flags.indexOf('EX');
    if (exIdx >= 0 && opts[exIdx + 1]) {
      this.ttls.set(key, Date.now() + Number(opts[exIdx + 1]) * 1000);
    }
    this._markDirty(key);
    return 'OK';
  }

  async del(...keys) {
    let count = 0;
    for (const key of keys) {
      if (this.store.delete(key)) {
        count++;
        this._markDirty(key);
      }
      this.ttls.delete(key);
    }
    return count;
  }

  async incr(key, ttlSec = null) {
    // Perform check + increment synchronously before returning to prevent lost concurrent updates
    const raw = this._isExpired(key) ? undefined : this.store.get(key);
    const cur = Number(raw) || 0;
    const next = cur + 1;
    this._evictIfFull();
    this.store.set(key, String(next));
    if (cur === 0 && ttlSec) {
      this.ttls.set(key, Date.now() + ttlSec * 1000);
    }
    this._markDirty(key);
    return next;
  }

  async hset(key, ...fields) {
    if (this._isExpired(key)) {
      this.store.delete(key);
    }
    let map = this.store.get(key);
    if (!(map instanceof Map)) {
      this._evictIfFull();
      map = new Map();
      this.store.set(key, map);
    }
    if (fields.length === 1 && typeof fields[0] === 'object' && fields[0] !== null) {
      for (const [k, v] of Object.entries(fields[0])) {
        map.set(k, String(v));
      }
    } else {
      for (let i = 0; i < fields.length; i += 2) {
        map.set(String(fields[i]), String(fields[i + 1]));
      }
    }
    this._markDirty(key);
    return 'OK';
  }

  async hincrby(key, field, amount = 1) {
    if (this._isExpired(key)) {
      this.store.delete(key);
    }
    let map = this.store.get(key);
    if (!(map instanceof Map)) {
      this._evictIfFull();
      map = new Map();
      this.store.set(key, map);
    }
    const cur = Number(map.get(field)) || 0;
    const next = cur + amount;
    map.set(field, String(next));
    this._markDirty(key);
    return next;
  }

  async hget(key, field) {
    if (this._isExpired(key)) return null;
    const map = this.store.get(key);
    if (!(map instanceof Map)) return null;
    const v = map.get(field);
    return v !== undefined ? v : null;
  }

  async hgetall(key) {
    if (this._isExpired(key)) return {};
    const map = this.store.get(key);
    if (!(map instanceof Map)) return {};
    const obj = {};
    for (const [k, v] of map.entries()) {
      obj[k] = v;
    }
    return obj;
  }

  async hdel(key, ...fields) {
    if (this._isExpired(key)) return 0;
    const map = this.store.get(key);
    if (!(map instanceof Map)) return 0;
    let count = 0;
    for (const f of fields) {
      if (map.delete(String(f))) count++;
    }
    if (count > 0) this._markDirty(key);
    return count;
  }

  async expire(key, seconds) {
    if (this._isExpired(key) || !this.store.has(key)) return 0;
    this.ttls.set(key, Date.now() + seconds * 1000);
    this._markDirty(key);
    return 1;
  }

  close() {
    if (this.interval) {
      clearInterval(this.interval);
    }
    if (this._snapshotInterval) {
      clearInterval(this._snapshotInterval);
    }
    if (this.snapshotPath && this._dirty) {
      this.saveSnapshot();
    }
  }
}

// Global active store instance
let instance = null;
function getKv() {
  if (instance) return instance;
  instance = new MemoryStore();
  return instance;
}

module.exports = {
  getKv,
  MemoryStore,
  defaultKvMaxKeys,
};
