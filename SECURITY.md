# Security Policy

## Reporting Security Issues

We take the security of the **OBSX Security Protocol** very seriously. We appreciate the efforts of security researchers and engineers who discover vulnerabilities and work with us to disclose them responsibly.

If you believe you have discovered a vulnerability, cryptographic defect, or security flaw in OBSX Core or any related client module:

1. **Do NOT open a public GitHub issue.** Public issues disclose vulnerabilities before patches can be deployed to live nodes.
2. **Submit via GitHub Security Advisories**: Navigate to the [Security Advisory Submission](https://github.com/jidiotspam-hue/obsx/security/advisories/new) page on GitHub.
3. **Email the Security Team**: Alternatively, send an encrypted report directly to:
   - **`security@obsx.tech`** or **`official@obsx.tech`**

### What to Include in Your Report

Please include the following information in your advisory:
- Description of the vulnerability and attack vector.
- Affected components (e.g. `lib/core.js`, `lib/crypto.js`, client SDK, dashboard).
- Step-by-step reproduction instructions or a minimal proof-of-concept (PoC).
- Any potential impact on self-hosted nodes or client attestation pipelines.

---

## Response Times & SLA

When you submit a vulnerability report:
- **Initial Acknowledgment**: Within **24 hours**.
- **Triage & Reproduction**: Within **48 hours**.
- **Fix & Patch Deployment**: Critical issues impacting token verification or cryptographic invariants are prioritized for immediate resolution on live nodes (`obsx.tech`) and released via hotfix tags.

---

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `v2.2.x` | YES | Active stable branch |
| `v2.1.x` | Security fixes only | Maintenance |
| `< v2.0.0` | NO | Deprecated legacy releases |

---

## Scope & Bounties

- **In Scope**:
  - Cryptographic token forging or HMAC signature bypass in `lib/crypto.js`.
  - Replay attacks or state race conditions in `lib/kv.js` and `lib/core.js`.
  - Client-side bypasses that convincingly spoof natural human kinematic tremor without triggering `degenerate_jerk` or `synthetic_cadence`.
  - Unauthorized privilege escalation or cross-tenant data bleed in `server.js` and `lib/accounts.js`.
- **Out of Scope**:
  - Denial of Service (DoS) attacks requiring massive volumetric bandwidth floods.
  - Social engineering against operators or maintainers.
  - Vulnerabilities in third-party mailer SMTP relays outside OBSX's code.
