# Security Policy

## Reporting Security Issues

We take the security of the **OBSX Security Protocol** very seriously. We appreciate the efforts of security researchers and engineers who discover vulnerabilities and work with us to disclose them responsibly.

If you believe you have discovered a vulnerability, cryptographic defect, or security flaw in OBSX Core or any related client module:

1. **Do NOT open a public GitHub issue.** Public issues disclose vulnerabilities before patches can be deployed to live nodes.
2. **Submit via GitHub Security Advisories**: Navigate to the [Security Advisory Submission](https://github.com/jidiotspam-hue/obsx/security/advisories/new) page on GitHub.
3. **Email Security Contact**: Alternatively, send an encrypted report directly to:
   - **`security@obsx.tech`**

### What to Include in Your Report

Please include the following information in your advisory:
- Description of the vulnerability and attack vector.
- Affected components (e.g. `lib/core.js`, `lib/crypto.js`, client SDK, dashboard).
- Step-by-step reproduction instructions or a minimal proof-of-concept (PoC).
- Any potential impact on self-hosted nodes or client attestation pipelines.

---

## Response Targets

We handle vulnerability reports on a **best-effort basis** as an individually maintained project (non-binding targets, not a contractual SLA):
- **Initial Acknowledgment**: Best-effort target within **3 business days**.
- **Triage & Reproduction**: Best-effort assessment as maintainer capacity permits.
- **Fix & Patch Deployment**: Confirmed issues affecting cryptographic invariants or boundary isolation are prioritized for hotfix releases.

---

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `v2.3.x` | YES | Active stable branch |
| `v2.2.x` | Security fixes only | Maintenance |
| `< v2.2.0` | NO | Legacy releases |

---

## Research Scope & Safe Harbor

- **In Scope (Public Code & Scoped `obsx.tech` Sandbox Only)**:
  - Cryptographic token forging or HMAC signature bypass in `lib/crypto.js`.
  - Replay attacks or state race conditions in `lib/kv.js` and `lib/core.js`.
  - Attestation validation flaws or cross-tenant isolation bugs in `server.js` and `lib/accounts.js`.
- **Safe Harbor Conditions**: Good-faith, low-rate testing strictly scoped to the public `obsx.tech` sandbox (`pk_obsx_sandbox`) or your own local self-hosted instance is permitted when you do not access other users' data, degrade availability, or run automated flood tools against `obsx.tech`.
- **Out of Scope**:
  - Volumetric Denial of Service (DoS/DDoS) or running `tools/flood.js` against `obsx.tech` without prior written authorization.
  - Social engineering or phishing against operators or maintainers.
  - Third-party mail relays outside OBSX's code.

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
Dashboard operator endpoints (`/api/v1/alerts`, `/api/v1/system/update`, `/api/v1/system/diff`, `/api/v1/system/adapt`, `/api/v1/system/license`, `/api/v1/system/license/accept`) additionally accept an authenticated session whose email is explicitly allowlisted via `OPERATOR_EMAILS`, `OBSX_OPERATOR_EMAILS`, or `OPERATOR_EMAIL` (fail-closed when unset).

**Why this matters.** A botnet does not hammer from one address; it rotates across
thousands of IPs, each sending a few requests. Per-IP rules alone never trip, so
the shield also budgets the subnet and the user-agent class the fleet shares.

Run the tests locally with no network required: `OBSX_TEST_MODE=1 npm test` (or `OBSX_TEST_MODE=1 node --test tests/botshield.test.js` for origin shield tests).
