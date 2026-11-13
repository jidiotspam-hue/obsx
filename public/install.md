# OBSX Security SDK Installation Guide

Deploy OBSX client-side anti-bot attestation and cryptographic action sealing to any web application.

---

## 1. Quick Integration (Production CDN)

Add the OBSX SDK script to the `<head>` of your HTML document before any application forms or sensitive actions:

```html
<!-- OBSX Security SDK v2.3.0 (Cryptographically Pinned with SRI) -->
<script
  src="https://obsx.tech/sdk/v2.3.0/obsx.min.js"
  data-obsx-site="pk_YOUR_SITE_KEY"
  integrity="sha384-IImxd5YYp6MZGcDMsV7SMLRyETzGv0Zs2eDIFYrlcFrm+N7hQGHajS48u5sc5OWp"
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
```

---

## 4. Subresource Integrity (SRI) Checksums

| Asset | Version | Algorithm | Hash |
| :--- | :--- | :--- | :--- |
| `obsx.min.js` | `v2.3.0` | **SHA-384** | `sha384-IImxd5YYp6MZGcDMsV7SMLRyETzGv0Zs2eDIFYrlcFrm+N7hQGHajS48u5sc5OWp` |
| `obsx.min.js` | `v2.3.0` | **SHA-256** | `sha256-uKzNn83sKhNHtj1pY4Kcy0+rFuItLsONNvMM7f4SPaY=` |
| `tracer.min.js` | `v2.3.0` | **SHA-384** | `sha384-IImxd5YYp6MZGcDMsV7SMLRyETzGv0Zs2eDIFYrlcFrm+N7hQGHajS48u5sc5OWp` |
| `veritas.min.js` | `v2.3.0` | **SHA-384** | `sha384-IImxd5YYp6MZGcDMsV7SMLRyETzGv0Zs2eDIFYrlcFrm+N7hQGHajS48u5sc5OWp` |
