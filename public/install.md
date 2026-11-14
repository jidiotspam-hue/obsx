# OBSX Security SDK Installation Guide

Deploy OBSX client-side anti-bot attestation and cryptographic action sealing to any web application.

---

## 1. Quick Integration (Production CDN)

Add the OBSX SDK script to the `<head>` of your HTML document before any application forms or sensitive actions:

```html
<!-- OBSX Security SDK v2.3.1 (Cryptographically Pinned with SRI) -->
<script
  src="https://obsx.tech/sdk/v2.3.1/obsx.min.js"
  data-obsx-site="pk_YOUR_SITE_KEY"
  integrity="sha384-zjDlyXRfz2+UkWMPjUhvyBA8wEWqxEj/OBYXdqwhAYdleL/vk5dqd6KQEPY3e+3i"
  crossorigin="anonymous"
  defer>
</script>
```

### Alternative Floating Tag
If you prefer automatic patch upgrades (both `data-obsx-site` and `data-site` are accepted):
```html
<script
  src="https://obsx.tech/sdk/latest/obsx.min.js"
  data-obsx-site="pk_YOUR_SITE_KEY"
  crossorigin="anonymous"
  defer>
</script>
```

### Zero-JS HTML Form Protection
Add `data-obsx-protect` to any `<form>` and OBSX automatically binds hidden `obsx-token` and `obsx-nonce` inputs on submission:
```html
<form action="/api/transfers" method="POST" data-obsx-protect>
  <input type="text" name="recipient" required />
  <button type="submit">Send</button>
</form>
```

---

## 2. Cryptographic Action Sealing (`OBSX.seal`)

Prevent parameter tampering and API replay on sensitive actions (fund transfers, credential submission, vote casting):

```javascript
// Sign and submit a sensitive action payload
const order = {
  recipient: "user_89124",
  amount: 250.00,
  currency: "USD"
};

// Cryptographically seal action using the hardware-bound ephemeral session key
const sealedPayload = await window.OBSX.seal(order);

const response = await fetch('/api/transfers', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(sealedPayload)
});
```

The resulting payload is formatted with key canonicalization, cycle rejection, recursion depth ceilings (`depth <= 32`), and a micro-PoW bound HMAC signature:
```json
{
  "recipient": "user_89124",
  "amount": 250.00,
  "currency": "USD",
  "obsx": {
    "token": "tok_...",
    "mode": "enforce",
    "ts": 1793498421000,
    "nonce": "104",
    "sig": "HMAC_SHA256_BASE64URL"
  }
}
```

---

## 3. Server-Side Verification (Node.js / Express)

Verify attestation and action integrity (including `OBSX.seal()` HMAC envelopes and `<form data-obsx-protect>` submissions) in your backend controller using `obsx-security`:

```javascript
const { middleware, verifyToken } = require('obsx-security');

// Option 1: One-line Express middleware
app.post('/api/transfers', middleware({ secretKey: process.env.OBSX_SECRET_KEY }), async (req, res) => {
  await processTransfer(req.body.recipient, req.body.amount, req.body.currency);
  res.json({ ok: true, risk: req.obsx.risk });
});

// Option 2: Direct verification helper (for any Node.js framework)
app.post('/api/manual-transfer', async (req, res) => {
  const result = await verifyToken(req.body, {
    secretKey: process.env.OBSX_SECRET_KEY,
    clientUa: req.headers['user-agent']
  });

  if (!result.allowed) {
    return res.status(403).json({ error: 'gate_rejected', reasons: result.reasons });
  }

  await processTransfer(req.body.recipient, req.body.amount, req.body.currency);
  res.json({ ok: true });
});

// Option 3: Web Standard Request (Next.js App Router / Edge / Deno / Bun)
import { verifyRequest } from 'obsx-security';

export async function POST(request) {
  const result = await verifyRequest(request, { secretKey: process.env.OBSX_SECRET_KEY });
  if (!result.allowed) {
    return Response.json({ ok: false, reasons: result.reasons }, { status: 403 });
  }
  return Response.json({ ok: true, risk: result.risk });
}
```

### Migrating from Google reCAPTCHA / Turnstile (60-Second Drop-In)
Add `data-obsx-compat="recaptcha"` to keep existing `grecaptcha.ready()`, `grecaptcha.execute()`, `.g-recaptcha` containers, and `g-recaptcha-response` / `cf-turnstile-response` server fields working with zero image puzzles:
```html
<script
  src="https://obsx.tech/obsx.min.js"
  data-obsx-site="pk_YOUR_SITE_KEY"
  data-obsx-compat="recaptcha"
  defer>
</script>
```

---

## 4. Subresource Integrity (SRI) Checksums

| Asset | Version | Algorithm | Hash |
| :--- | :--- | :--- | :--- |
| `obsx.min.js` | `v2.3.1` | **SHA-384** | `sha384-zjDlyXRfz2+UkWMPjUhvyBA8wEWqxEj/OBYXdqwhAYdleL/vk5dqd6KQEPY3e+3i` |
| `obsx.min.js` | `v2.3.1` | **SHA-256** | `sha256-4RTLhRChl8GMOVS/iFOEz5lhdQu04KeQKNxwSwDIjKM=` |
| `tracer.min.js` | `v2.3.1` | **SHA-384** | `sha384-zjDlyXRfz2+UkWMPjUhvyBA8wEWqxEj/OBYXdqwhAYdleL/vk5dqd6KQEPY3e+3i` |
| `veritas.min.js` | `v2.3.1` | **SHA-384** | `sha384-zjDlyXRfz2+UkWMPjUhvyBA8wEWqxEj/OBYXdqwhAYdleL/vk5dqd6KQEPY3e+3i` |
