# OBSX Security Architecture Manifesto

**Author**: Alexis Grimmace (`obsx.tech`)  
**Target Standard**: Client Integrity Attestation & Anti-Automation  
**Release**: v2.3.0  

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
* **Client Behavior**: The client SDK solves `sha256(challenge + ":" + nonce)` using hardware-accelerated `crypto.subtle` (typically ~15ms on modern desktop/mobile browsers, varying with device CPU and configured difficulty).
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

## 3. Protocol Threat Mitigation Summary

> **Default Enforcement Mode (`mode: 'enforce'`)**: By default, protected verification gates operate in `enforce` mode and fail closed when required PoW proofs or attestation signals fail validation. Operators may configure `mode: 'passive'` during initial rollout to log verdicts without blocking requests.

| Threat Vector | OBSX Protocol Mitigation |
| :--- | :--- |
| **Empty Telemetry Signals** (`signals: {}` submitted at risk 0) | **Mitigated**: Unattested sessions trigger `missing_telemetry` and require valid PoW proofs. |
| **Identity-Wide Email Lockout** (5 requests lock email 60m) | **Mitigated**: Pre-auth rate limiting is keyed per caller IP subnet, isolating email addresses from global lockout. |
| **Unauthenticated Project Creation** (Missing `guardSite` session) | **Mitigated**: Project creation requires an authenticated session or operator authorization. |
| **`idle_input` Weight Deficit** | **Mitigated**: Extended sessions enforce behavioral/interaction risk thresholds unless configured otherwise by project policy. |
| **CORS / Origin Spoofing** (`ctx.origin` trusted blindly) | **Mitigated**: Server verification binds tokens to signed PoW challenges and configured project origins. |

---

## 4. Verification & Licensing

* **Automated Test Suite**: Executed offline via `OBSX_TEST_MODE=1 npm test` (no synthetic pass claims; see live CI output for current counts).
* **Dependencies**: Zero external runtime npm dependencies.
* **Licensing**: Dual-licensed under Zone 1 MIT (Core Protocol & SDK) and Zone 2 OBSX Source-Available License v1.0 (Operator Software); see [LICENSE](../LICENSE).
