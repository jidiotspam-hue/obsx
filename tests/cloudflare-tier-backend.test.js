'use strict';

process.env.NODE_ENV = 'test';
process.env.TRUST_PROXY = 'true';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const { getKv, MemoryStore } = require('../lib/kv');

let port = 0;
let baseUrl = '';
let testServer = null;

test.before(async () => {
  await new Promise((resolve) => {
    testServer = server.listen(0, '127.0.0.1', () => {
      port = testServer.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (testServer) {
    if (typeof testServer.closeAllConnections === 'function') {
      testServer.closeAllConnections();
    }
    await new Promise((resolve) => testServer.close(resolve));
  }
});

// Helper for HTTP requests
function request(method, path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers = { ...(options.headers || {}) };
    let bodyData = null;

    if (options.body) {
      bodyData = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
      headers['Content-Length'] = Buffer.byteLength(bodyData);
    }

    const req = http.request(
      url,
      {
        method,
        headers,
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch {
            // not json
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: raw,
            json,
          });
        });
      }
    );

    req.on('error', reject);
    if (bodyData) req.write(bodyData);
    req.end();
  });
}

// 1. CORS Preflight & API Headers
test('cloudflare-tier: CORS OPTIONS preflight returns 204 with full headers', async () => {
  const res = await request('OPTIONS', '/api/v1/session');
  assert.equal(res.status, 204);
  assert.equal(res.headers['access-control-allow-origin'], '*');
  assert.ok(res.headers['access-control-allow-methods'].includes('POST'));
  assert.ok(res.headers['access-control-allow-headers'].includes('Content-Type'));
});

// 2. HTTP 405 Method Not Allowed Handling
test('cloudflare-tier: wrong HTTP verbs return 405 Method Not Allowed with Allow header', async () => {
  // Session accepts only POST and OPTIONS
  const resSession = await request('GET', '/api/v1/session');
  assert.equal(resSession.status, 405);
  assert.equal(resSession.json.error, 'method_not_allowed');
  assert.ok(resSession.headers['allow'].includes('POST'));

  // Signal accepts only POST and OPTIONS
  const resSignal = await request('GET', '/api/v1/signal');
  assert.equal(resSignal.status, 405);
  assert.ok(resSignal.headers['allow'].includes('POST'));

  // Me endpoint accepts only GET
  const resMe = await request('POST', '/api/v1/me', { body: {} });
  assert.equal(resMe.status, 405);
  assert.ok(resMe.headers['allow'].includes('GET'));

  // Static files only accept GET and HEAD
  const resStatic = await request('POST', '/index.html', { body: {} });
  assert.equal(resStatic.status, 405);
  assert.ok(resStatic.headers['allow'].includes('GET'));
});

// 3. Static File Serving with ETags and 304 Caching
test('cloudflare-tier: static assets serve with ETag, Cache-Control, and support 304 Not Modified', async () => {
  const res1 = await request('GET', '/index.html');
  assert.equal(res1.status, 200);
  assert.ok(res1.headers['etag'], 'ETag header must be present');
  assert.ok(res1.headers['cache-control'], 'Cache-Control header must be present');
  assert.ok(res1.body.includes('OBSX'), 'Must serve HTML body');

  const etag = res1.headers['etag'];

  // Conditional request with matching If-None-Match -> 304
  const res304 = await request('GET', '/index.html', {
    headers: { 'if-none-match': etag },
  });
  assert.equal(res304.status, 304);
  assert.equal(res304.body, '', '304 responses must carry zero content');

  // HEAD method -> 200 with headers, zero body
  const resHead = await request('HEAD', '/index.html');
  assert.equal(resHead.status, 200);
  assert.equal(resHead.body, '', 'HEAD request must have zero body');
  assert.equal(resHead.headers['etag'], etag);
});

// 4. Directory Traversal Defense
test('cloudflare-tier: directory traversal attempts are strictly blocked', async () => {
  const res1 = await request('GET', '/../../package.json');
  assert.ok(res1.status === 403 || res1.status === 404, 'Must not serve root files');
  assert.ok(!res1.body.includes('"name": "obsx-security"'));

  const res2 = await request('GET', '/%2e%2e%2f%2e%2e%2fpackage.json');
  assert.ok(res2.status === 403 || res2.status === 404);
  assert.ok(!res2.body.includes('"name": "obsx-security"'));
});

// 5. Payload Body Size Limitation (512KB Cap)
test('cloudflare-tier: payloads exceeding 512KB cap are rejected with 413 Payload Too Large', async () => {
  const largeBuffer = 'x'.repeat(600 * 1024);
  const res = await request('POST', '/api/v1/notes', { body: { large: largeBuffer } });
  assert.equal(res.status, 413);
  assert.equal(res.json.error, 'payload_too_large');
});

// 6. Cookie Security (RFC 6265bis __Host- vs standard)
test('cloudflare-tier: cookies set __Host- with Secure on HTTPS, standard on HTTP', async () => {
  const email1 = 'auth_cookie_test1@example.com';
  const email2 = 'auth_cookie_test2@example.com';
  const start1 = await accounts.startEmailAuth(email1, '127.0.0.1');
  assert.ok(start1.ok);

  // Verification over HTTP
  const httpAuth = await accounts.verifyEmailAuth(email1, start1.devCode, false);
  assert.ok(httpAuth.sessionCookie.startsWith('obsx_session='));
  assert.ok(!httpAuth.sessionCookie.includes('Secure'));

  // Verification over HTTPS
  const start2 = await accounts.startEmailAuth(email2, '127.0.0.1');
  const httpsAuth = await accounts.verifyEmailAuth(email2, start2.devCode, true);
  assert.ok(httpsAuth.sessionCookie.startsWith('__Host-obsx_session='));
  assert.ok(httpsAuth.sessionCookie.includes('; Secure'));
});

// 7. KV Store TTL Accuracy & Atomic Invalidation
test('cloudflare-tier: KV MemoryStore hget and hgetall honor TTL expiration immediately', async () => {
  const store = new MemoryStore(100);
  await store.hset('test_session', { user: 'alex', role: 'admin' });
  await store.expire('test_session', 1); // 1 second TTL

  // Immediately accessible
  const val1 = await store.hget('test_session', 'user');
  assert.equal(val1, 'alex');

  // Fast-forward or sleep past TTL
  await new Promise((r) => setTimeout(r, 1100));

  // Must return null/empty immediately even before cleanup interval
  const val2 = await store.hget('test_session', 'user');
  const all = await store.hgetall('test_session');
  assert.equal(val2, null, 'Expired hget must return null');
  assert.deepEqual(all, {}, 'Expired hgetall must return empty object');

  store.close();
});

// 8. End-to-End User Sign-in, Projects, and Note Creation Flow
test('cloudflare-tier: full E2E auth lifecycle with project and notes management', async () => {
  const userEmail = 'e2e_full_user@obsx.tech';

  // Step 1: Start Email Auth
  const startRes = await request('POST', '/api/v1/auth/email', {
    body: { action: 'start', email: userEmail },
  });
  assert.equal(startRes.status, 200);
  assert.ok(startRes.json.ok);
  const code = startRes.json.devCode;

  // Step 2: Verify Code -> get session cookie
  const verifyRes = await request('POST', '/api/v1/auth/email', {
    body: { action: 'verify', email: userEmail, code },
  });
  assert.equal(verifyRes.status, 200);
  assert.ok(verifyRes.json.ok);

  const rawCookieHeader = verifyRes.headers['set-cookie'];
  assert.ok(rawCookieHeader, 'Set-Cookie must be returned');
  const cookieVal = Array.isArray(rawCookieHeader) ? rawCookieHeader[0].split(';')[0] : rawCookieHeader.split(';')[0];

  // Step 3: Call /api/v1/me with cookie
  const meRes = await request('GET', '/api/v1/me', {
    headers: { Cookie: cookieVal },
  });
  assert.equal(meRes.status, 200);
  assert.equal(meRes.json.user.email, userEmail);

  // Step 4: Create a project under authenticated user
  const projRes = await request('POST', '/api/v1/project', {
    headers: { Cookie: cookieVal },
    body: { name: 'E2E Production Project' },
  });
  assert.equal(projRes.status, 201);
  assert.ok(projRes.json.project.publicKey.startsWith('pk_'));

  // Step 5: List projects
  const listProjRes = await request('GET', '/api/v1/projects', {
    headers: { Cookie: cookieVal },
  });
  assert.equal(listProjRes.status, 200);
  assert.ok(listProjRes.json.projects.length >= 1);

  // Step 6: Create note under authenticated user
  const noteRes = await request('POST', '/api/v1/notes', {
    headers: { Cookie: cookieVal },
    body: {
      title: 'Authenticated User Secret',
      content: 'Cloudflare tier security validated',
      protectionMode: 'advisory',
    },
  });
  assert.equal(noteRes.status, 201);
  assert.equal(noteRes.json.note.title, 'Authenticated User Secret');

  // Step 7: Read notes
  const notesListRes = await request('GET', '/api/v1/notes', {
    headers: { Cookie: cookieVal },
  });
  assert.equal(notesListRes.status, 200);
  assert.equal(notesListRes.json.isGuest, false);
  assert.ok(notesListRes.json.notes.some((n) => n.title === 'Authenticated User Secret'));

  // Step 8: Logout
  const logoutRes = await request('POST', '/api/v1/auth/logout', {
    headers: { Cookie: cookieVal },
  });
  assert.equal(logoutRes.status, 200);

  // Step 9: Re-check /api/v1/me after logout -> user is null
  const meAfterLogout = await request('GET', '/api/v1/me', {
    headers: { Cookie: cookieVal },
  });
  assert.equal(meAfterLogout.status, 200);
  assert.equal(meAfterLogout.json.user, null);
});

// 9. Guest Sandbox Partitioning & Note Deletion Safety
test('cloudflare-tier: guest sandbox partitions notes safely and prevents unauthorized deletion', async () => {
  // Guest 1 creates a note
  const g1Res = await request('POST', '/api/v1/notes', {
    headers: { 'X-Forwarded-For': '203.0.113.195' },
    body: {
      title: 'Guest Note One',
      content: 'Isolated in guest sandbox',
      protectionMode: 'advisory',
    },
  });
  assert.equal(g1Res.status, 201);
  const noteId = g1Res.json.note.id;

  // Guest 2 from different IP cannot see Guest 1's note
  const g2List = await request('GET', '/api/v1/notes', {
    headers: { 'X-Forwarded-For': '198.51.100.44' },
  });
  assert.equal(g2List.status, 200);
  assert.ok(!g2List.json.notes.some((n) => n.id === noteId));

  // Guest 2 cannot delete Guest 1's note
  const g2Delete = await request('DELETE', `/api/v1/notes/${noteId}`, {
    headers: { 'X-Forwarded-For': '198.51.100.44' },
  });
  assert.equal(g2Delete.status, 200);
  assert.equal(g2Delete.json.ok, false);

  // Guest 1 can successfully delete their own note
  const g1Delete = await request('DELETE', `/api/v1/notes/${noteId}`, {
    headers: { 'X-Forwarded-For': '203.0.113.195' },
  });
  assert.equal(g1Delete.status, 200);
  assert.equal(g1Delete.json.ok, true);
});