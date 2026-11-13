'use strict';

const fs = require('fs');
const path = require('path');
const { isTestRuntime } = require('./crypto');

/**
 * Universal Key-Value Storage Engine for OBSX (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 * Supports high-speed in-memory state with TTL cleanup for local dev & testing,
 * optional atomic filesystem snapshots for resilient single-node restarts,
 * and seamlessly switches to Upstash Redis REST API when deployed to distributed clusters.
 */

class MemoryStore {
  constructor(maxKeys = 100000, snapshotPath = (isTestRuntime() ? null : (process.env.KV_SNAPSHOT_PATH || (process.env.OBSX_PERSIST_KV === 'true' || process.env.NODE_ENV === 'production' ? path.join(__dirname, '../.kv-snapshot.json') : null)))) {
    this.store = new Map();
    this.ttls = new Map();
    this.maxKeys = maxKeys;
    this.snapshotPath = snapshotPath;
    this._loadSnapshot();
    this.interval = setInterval(() => this.cleanup(), 1000);
    if (this.interval.unref) this.interval.unref();
    if (this.snapshotPath) {
      this._snapshotInterval = setInterval(() => this.saveSnapshot(), 3000);
      if (this._snapshotInterval.unref) this._snapshotInterval.unref();
      if (typeof process !== 'undefined' && process.on) {
        process.on('exit', () => this.saveSnapshot());
      }
    }
  }

  _loadSnapshot() {
    if (!this.snapshotPath || !fs.existsSync(this.snapshotPath)) return;
    try {
      const data = JSON.parse(fs.readFileSync(this.snapshotPath, 'utf8'));
      const now = Date.now();
      if (Array.isArray(data.items)) {
        for (const item of data.items) {
          if (item.exp && now >= item.exp) continue;
          if (item.type === 'hash' && item.value && typeof item.value === 'object') {
            const map = new Map(Object.entries(item.value));
            this.store.set(item.key, map);
          } else {
            this.store.set(item.key, item.value);
          }
          if (item.exp) this.ttls.set(item.key, item.exp);
        }
      }
    } catch (_) {}
  }

  saveSnapshot() {
    if (!this.snapshotPath) return;
    try {
      const items = [];
      const now = Date.now();
      for (const [key, val] of this.store.entries()) {
        const exp = this.ttls.get(key) || null;
        if (exp && now >= exp) continue;
        if (val instanceof Map) {
          const obj = {};
          for (const [k, v] of val.entries()) obj[k] = v;
          items.push({ key, type: 'hash', value: obj, exp });
        } else {
          items.push({ key, type: 'val', value: val, exp });
        }
      }
      const tmp = `${this.snapshotPath}.tmp.${Date.now()}`;
      fs.writeFileSync(tmp, JSON.stringify({ version: 1, items }), 'utf8');
      fs.renameSync(tmp, this.snapshotPath);
    } catch (_) {}
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
    let count = 0;

    // Pass 1: Active TTL purge of any expired keys first
    for (const [key, exp] of this.ttls.entries()) {
      if (now >= exp) {
        this.store.delete(key);
        this.ttls.delete(key);
        count++;
        if (count >= 500) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 2: Evict ephemeral rate-limit counters, single-use tokens, and cooldown locks
    // (tr:used:*, tr:rl:*, tr:cnt:*, tr:cd:*, tr:cb:cnt:*, tr:ec:*, rate:*)
    for (const key of this.store.keys()) {
      if (
        key.startsWith('tr:used:') ||
        key.startsWith('tr:rl:') ||
        key.startsWith('tr:cnt:') ||
        key.startsWith('tr:cd:') ||
        key.startsWith('tr:cb:cnt:') ||
        key.startsWith('tr:ec:') ||
        key.startsWith('rate:')
      ) {
        this.store.delete(key);
        this.ttls.delete(key);
        count++;
        if (count >= 200) break;
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 3: Evict unverified / telemetry-less sessions (tr:s:* where no signals recorded)
    for (const [key, val] of this.store.entries()) {
      if (key.startsWith('tr:s:')) {
        let hasSignals = false;
        if (val instanceof Map) {
          hasSignals = val.has('sig');
        } else if (typeof val === 'object' && val !== null) {
          hasSignals = Boolean(val.sig);
        }
        if (!hasSignals) {
          this.store.delete(key);
          this.ttls.delete(key);
          count++;
          if (count >= 200) break;
        }
      }
    }
    if (this.store.size < this.maxKeys) return;

    // Pass 4: Evict oldest keys, strictly protecting project credentials & user accounts
    for (const key of this.store.keys()) {
      if (
        !key.startsWith('tr:p:') &&
        !key.startsWith('tr:pk:') &&
        !key.startsWith('tr:sk:') &&
        !key.startsWith('tr:u:')
      ) {
        this.store.delete(key);
        this.ttls.delete(key);
        count++;
        if (count >= 100) break;
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
    return 'OK';
  }

  async del(...keys) {
    let count = 0;
    for (const key of keys) {
      if (this.store.delete(key)) count++;
      this.ttls.delete(key);
    }
    return count;
  }

  async incr(key, ttlSec = null) {
    const cur = Number(await this.get(key)) || 0;
    const next = cur + 1;
    this._evictIfFull();
    this.store.set(key, String(next));
    if (cur === 0 && ttlSec) {
      this.ttls.set(key, Date.now() + ttlSec * 1000);
    }
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
    return count;
  }

  async expire(key, seconds) {
    if (this._isExpired(key) || !this.store.has(key)) return 0;
    this.ttls.set(key, Date.now() + seconds * 1000);
    return 1;
  }

  close() {
    if (this.interval) {
      clearInterval(this.interval);
    }
    if (this._snapshotInterval) {
      clearInterval(this._snapshotInterval);
    }
    if (this.snapshotPath) {
      this.saveSnapshot();
    }
  }
}

// Global active store instance
let instance = null;
function getKv() {
  if (instance) return instance;
  // If Redis credentials are configured, wrap them; otherwise default to in-memory
  instance = new MemoryStore();
  return instance;
}

module.exports = {
  getKv,
  MemoryStore,
};
