# OBSX Security SDK Installation Guide

Deploy OBSX client-side anti-bot attestation and cryptographic action sealing to any web application.

---

## 1. Quick Integration (Production CDN)

Add the OBSX SDK script to the `<head>` of your HTML document before any application forms or sensitive actions:

```html
<!-- OBSX Security SDK v2.3.0 (Cryptographically Pinned with SRI) -->
<script 
  src="https://obsx.tech/sdk/v2.3.0/obsx.min.js" 
  data-site="YOUR_OBSX_PUBLIC_KEY" 
  integrity="sha384-4ws7XPo5a1nGiKBuK8CzXDPstp4BbmQWIgPh6pqrkjejylK62rglQH2fvUK81APv" 
  crossorigin="anonymous" 
  defer>
</script>
```

### Alternative Floating Tag
If you prefer automatic patch upgrades:
```html
<script 
  src="https://obsx.tech/sdk/latest/obsx.min.js" 
  data-site="YOUR_OBSX_PUBLIC_KEY" 
  crossorigin="anonymous" 
  defer>
</script>
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
    "session": "sess_...",
    "ts": 1793498421000,
    "nonce": "104",
    "sig": "HMAC_SHA256_BASE64URL"
  }
}
```

---

## 3. Server-Side Verification (Node.js / Express)

Verify attestation and action integrity in your backend controller using `@obsx/core`:

```javascript
const { verifyActionSeal, verify } = require('@obsx/core');

app.post('/api/transfers', async (req, res) => {
  const { recipient, amount, currency, obsx } = req.body;
  
  // 1. Verify cryptographic seal authenticity
  const isAuthentic = verifyActionSeal(
    sessionRecord.rk,
    obsx.session,
    obsx.ts,
    obsx.nonce,
    { recipient, amount, currency },
    obsx.sig
  );

  if (!isAuthentic) {
    return res.status(403).json({ error: 'tampered_or_invalid_signature' });
  }

  // 2. Execute business logic safely
  await processTransfer(recipient, amount, currency);
  res.json({ ok: true });
});
```

---

## 4. Subresource Integrity (SRI) Checksums

| Asset | Version | Algorithm | Hash |
| :--- | :--- | :--- | :--- |
| `obsx.min.js` | `v2.3.0` | **SHA-384** | `sha384-4ws7XPo5a1nGiKBuK8CzXDPstp4BbmQWIgPh6pqrkjejylK62rglQH2fvUK81APv` |
| `obsx.min.js` | `v2.3.0` | **SHA-256** | `sha256-NyQBbFxdBN0z0puBVl+39mUzTm5gJaXSk3D+YW/REyU=` |
| `tracer.min.js` | `v2.3.0` | **SHA-384** | `sha384-4ws7XPo5a1nGiKBuK8CzXDPstp4BbmQWIgPh6pqrkjejylK62rglQH2fvUK81APv` |
| `veritas.min.js` | `v2.3.0` | **SHA-384** | `sha384-4ws7XPo5a1nGiKBuK8CzXDPstp4BbmQWIgPh6pqrkjejylK62rglQH2fvUK81APv` |
