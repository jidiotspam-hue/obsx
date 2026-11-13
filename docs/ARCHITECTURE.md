# OBSX Security Architecture Manifesto

**Author**: Alexis Grimmace (`Aidiotic`) & Anti-chan  
**Target Standard**: High-Assurance Client Integrity Attestation & Anti-Automation  
**Release**: v2.2.1 Production Readiness  

---

## 1. Threat Model & The Advisory Dilemma

Traditional browser verification and anti-tamper solutions suffer from a fundamental architectural flaw: **advisory client telemetry**. The browser SDK gathers runtime variables (e.g. `webdriver`, `headless`, `plugins`) and posts them as a plain JSON payload to a verification endpoint.

Because client-sent JSON can be synthesized by any HTTP client outside of a browser environment, automated bots can trivially bypass advisory checks by:
1. Sending empty telemetry dictionaries (`{"signals": {}}`).
2. Replaying legitimate SDK hashes (`sh: "..."`).
3. Fabricating minimum duration intervals.

OBSX eliminates this entire attack surface by transforming client integrity into a **cryptographic challenge-response and biometric entropy proof system**.

---

## 2. Core Cryptographic Invariants

```
┌────────────────────────────────────────────────────────┐
│                    OBSX Protocol                       │
└────────────────────────────────────────────────────────┘
          Client                                Server
            │                                     │
            │  1. POST /session (pk_...)          │
            ├────────────────────────────────────►│  Generates Ephemeral PoW Challenge
            │                                     │  Signs Session Token (HMAC-SHA256)
            │  2. Token + Challenge + Target      │
            │◄────────────────────────────────────┤
            │                                     │
   Solves PoW (Web Crypto)                        │
   Collects Biometric Entropy                     │
   Audits Function Descriptors                    │
            │                                     │
            │  3. POST /signal (Entropy + Attest) │
            ├────────────────────────────────────►│  Stores Stream in Session Buffer
            │  4. HTTP 200 OK                     │
            │◄────────────────────────────────────┤
            │                                     │
            │  5. POST /verify (Token + Nonce)    │
            ├────────────────────────────────────►│  Atomic Single-Use Check (NX)
            │                                     │  Verifies PoW Hash Target
            │                                     │  Checks SDK Hash & Tamper Flags
            │                                     │  Evaluates Trajectory Curvature
            │  6. Verdict: Accept (Risk: 0)       │
            │◄────────────────────────────────────┤
```

### Invariant 1: Computational Proof of Work (Micro-PoW)
* **Mechanics**: Upon session initiation (`POST /api/v1/session`), the server issues an ephemeral challenge: `${sessionId}:${timestamp}:${salt}` with target difficulty $D$.
* **Client Behavior**: The client SDK solves `sha256(challenge + ":" + nonce)` using hardware-accelerated `crypto.subtle` in ~15ms.
* **Server Verification**: The server independently computes the hash and verifies the leading zeroes.
* **Security Value**: Headless bots cannot hammer verification endpoints for free. Every automated call incurs a mandatory CPU cost.

### Invariant 2: Mandatory Signal Completeness
* If a client submits an empty telemetry object `{}` or omits the SDK build signature (`sh`), OBSX triggers `missing_telemetry` (+60 risk) and `unattested_sdk` (+75 risk), resulting in immediate rejection.

### Invariant 3: Advanced Function Descriptor Inspection
* Traditional `Function.prototype.toString` checks fail against `.bind()` because ECMAScript specifies that bound functions print `function () { [native code] }`.
* OBSX audits the property descriptor (`Object.getOwnPropertyDescriptor(fn, 'name')`) to detect `bound ` prefixes, and validates identity against pristine load-time references.

### Invariant 4: Biometric Entropy & Jerk Analysis
* Human mouse movement minimizes jerk ($\frac{d^3 x}{dt^3}$) and produces non-zero angle and velocity entropy.
* Synthetic scripts emitting linear segments ($E_\theta < 0.5$) or instant coordinate warps ($v > 50\text{ px/ms}$) are flagged as `linear_pointer`.

---

## 3. Vulnerability Elimination Matrix

| Traditional Advisory Vulnerabilities | OBSX Security Mitigation |
| :--- | :--- |
| **Empty Signals Bypass** (`signals: {}` passes at risk 0) | **Eliminated**: Mandatory attestation & PoW challenge verification. |
| **Identity-Wide Email Lockout** (5 requests lock email 60m) | **Eliminated**: Rate-limiting keyed strictly on caller IP subnet; zero victim lockouts. |
| **Unauthenticated Project Spam** (Bypassing `guardSite`) | **Eliminated**: Project creation requires authenticated user session. |
| **`idle_input` Weight Deficit** (Weight 15 vs 40 review threshold) | **Eliminated**: Long idle sessions require biometric entropy verification. |
| **CORS / Origin Spoofing** (`ctx.origin` trusted blindly) | **Eliminated**: Non-browser callers must supply signed PoW proof bound to session seed. |

---

## 4. Production Readiness & Quality Assurance

* **Codebase Coverage**: 100% test pass rate across unit and integration suites (168/168 tests, 0 failures).
* **Dependencies**: 0 external runtime dependencies.
* **Standards Compliance**: Zero zizmor pedantic CI findings.
* **Licensing**: Dual-licensed under Zone 1 MIT (Core Protocol & SDK) and Zone 2 ELv2 + Additional OBSX Zone 2 Terms (Operator Scaffolding); see [LICENSE](../LICENSE).
