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

---

## Bot Protection: the origin shield

`obsx.tech` runs a layer-7 flood gate inside the node itself (`lib/botshield.js`),
so a flood is absorbed by the origin's own capacity accounting rather than by a
third-party rule set. Cloudflare absorbs bandwidth; this decides *who* gets
through.

Tiers, cheapest first — every rule is O(1) and runs before any application work:

| Tier | What it does | Cost to the origin |
| :--- | :--- | :--- |
| Connection ceiling | Sockets refused before parsing; per-address socket cap | a write and a destroy |
| Quarantine | Repeat offenders refused from a map hit, escalating 5 → 30 min | one lookup |
| Proof of work | A browser solves a 16–22 bit proof-of-work once, gets an HttpOnly cookie | ~2 ms, once per 15 min |
| Budgets | Per IP, per /24 or /64, and per user-agent class | a map increment |
| Capacity shed | 503 + `Retry-After` when connections, in-flight work, latency, or RSS are saturated | a small JSON |
| Fan-out detection | Engagement triggers on *distinct addresses* and *distinct /24s* per minute, not just rate | a set lookup |
| Path and method guard | Paths longer than 256 characters and unsupported methods are closed before routing | a length check |
| Path-fuzz close | Once a minute shows 800+ distinct paths, every *new* path is answered 404 without routing; it stands down after one calm minute | a map increment |
| Body gate | Request bodies above 512 KB are refused (413) before anything is parsed | a header read |
| Self-monitoring | `GET /api/v1/bot-protection` is answered by the shield itself, ~10 ms even while the origin is saturated | a JSON snapshot |
| Socket posture | Keep-alive, header and request timeouts tighten while engaged (2 s / 6 s / 15 s) and relax when calm | nothing, it is Node's own timing |

The shield engages automatically when the origin sees sustained pressure
(default 120 req/s), when 400 distinct addresses or 120 distinct /24s appear in
a minute, or when its own work latency reaches the saturation threshold — and
stands down when traffic settles (40 req/s for 45 seconds), so ordinary visitors
never see a challenge. Search engines are identified separately: they are
budgeted, never JavaScript-challenged.

A user agent string is treated as a claim, not evidence: a browser-looking agent
with no `Accept` or `Accept-Language` header is challenged as spoofed. Quarantine
is not a life sentence — an address with real browser headers is offered the
hardest puzzle instead of a flat 403, capped at twelve attempts, so a person
sharing a network with an attacker can work their way back in while a scripted
client cannot. Wrong puzzle answers are charged to the same attempt budget, so
the answer endpoint is not a free oracle.

**Public endpoints.** `GET /api/v1/bot-protection` (answered by the shield, not the application, so it stays readable during a flood) returns counters, thresholds and state sizes;
offender addresses are masked (`203.0.*.*`) unless the operator key is
supplied, so the public endpoint cannot be used to fingerprint visitors.
`POST /api/v1/bot-protection/mode` (`auto` | `always` | `off`) requires the `x-obsx-key`
header matching a configured `OBSX_SECRET` of at least 16 characters; unset or shorter secrets fail closed with 401.
Dashboard operator endpoints (`/api/v1/alerts`, `/api/v1/system/update`, `/api/v1/system/diff`, `/api/v1/system/adapt`) additionally accept an authenticated session whose email is explicitly allowlisted via `OPERATOR_EMAILS`, `OBSX_OPERATOR_EMAILS`, or `OPERATOR_EMAIL` (fail-closed when unset).

**Why this matters.** A botnet does not hammer from one address; it rotates across
thousands of IPs, each sending a few requests. Per-IP rules alone never trip, so
the shield also budgets the subnet and the user-agent class the fleet shares.

Run the tests: `OBSX_TEST_MODE=1 node --test tests/botshield.test.js` — 57 tests for the shield, 153 for the whole repo (`npm test`), no network and no server needed.
