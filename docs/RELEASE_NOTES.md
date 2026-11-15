# OBSX Security Protocol — Release Notes

## Version 2.3.0 (Developer Experience SDK, Zero-JS Forms & Backend Middleware)

### Migration Notice — Package Entry Point (`lib/index.js`)
- **`main` & Package Root Export Changed**: Importing `require('obsx-security')` or `import { verifyToken, middleware } from 'obsx-security'` now loads `lib/index.js` (Zone 1 MIT SDK) without auto-starting an HTTP listener.
- **Self-Hosted Daemon Imports**: Self-hosted deployments run `npm start` directly from a source checkout (Zone 2 `server.js` is excluded from the Zone 1-only npm package).

### Highlights
- **Drop-In Node.js Verification (`lib/index.js`)**: Added `verifyToken()`, `middleware()`, `protect()`, and conditional TypeScript `exports` (`./`, `./core`, `./crypto`, `./telemetry`, `./kv`, `./config`). Unsealed form submissions strip PII locally (`token`/`nonce` only), while `OBSX.seal()` nested & flat HMAC action seals are preserved for cryptographic signature verification.
- **Zero-JS Browser Integration (`src/tracer.js` `v2.3.0`)**: Added `autoMountSdk()`, `<form data-obsx-protect>`, `.obsx-widget`, `OBSX.getAttestation()`, cross-origin endpoint auto-discovery from `<script src>`, and `data-obsx-site` / `data-site` support.
- **Backend Header Forwarding (`server.js`)**: Added `X-OBSX-Client-UA` support on `POST /api/v1/verify` (`serverToServer: true`) so Node/Python backends do not trigger false User-Agent mismatches against browser sessions.
- **Verification**: Executed via `npm run build && OBSX_TEST_MODE=1 npm test` (0 failures).

---

## Version 2.2.1 (Dual-License Alignment & Updater Safe Mode)

### Licensing, Integrity & Upgrade Notes
- **Prospective Dual-License & Complete File Mapping**: Clarified `LICENSE` prospective applicability (`v2.2.0+`), preserved MIT terms for prior releases, explicitly assigned Zone 1 (`MIT`) and Zone 2 (`OBSX Source-Available License v1.0`), set `package.json` `"license": "MIT AND LicenseRef-OBSX-Zone-2-1.0"`, and preserved MIT attribution headers inside built SDK bundles.
- **License Integrity Verification & Safe Mode**: Expanded `CORE_WATCH_FILES` (`LICENSE`, `lib/botshield.js`, `lib/kv.js`, `lib/mailer.js`, `lib/updater.js`) with `stat`-validated hash caching, added `GET /api/v1/system/license` and `POST /api/v1/system/license/accept` (operator-gated with same-origin CSRF enforcement on cookie sessions), and surfaced Safe Mode / `licensePolicy` on public `/api/v1/system/version` (`ok: !licenseStatus.safeMode`) while redacting operator metadata.
- **Migration Notice — Opt-In Updater Flags**:
  - `OBSX_AUTO_RESTART` now defaults to `false` (previously enabled unless set to `'false'`). Set `OBSX_AUTO_RESTART=true` in `.env` if you want automated worker respawns after pulls.
  - `OBSX_HTTP_SYNC` now defaults to `false` for non-Git Strategy B HTTP raw-file sync (returning `http_sync_opt_in_required_<sha>` unless opted in via `OBSX_HTTP_SYNC=true`).
  - Conflict rollback in `autoAdaptDirtyNode()` preserves stashed user changes cleanly via `git stash apply` + `git reset --hard HEAD`.
- **Verification**: Verified via `npm run build && OBSX_TEST_MODE=1 npm test` at release time.

---

## Version 2.2.0 (Production Release)

### Core Enhancements
- **Sovereign Unblocker Gateway Attestation**: Comprehensive Web IDL descriptor auditing detecting proxy virtualization shims (Bare-Mux, Wisp, and Sovereign Gateway relays).
- **Hardware Telemetry Pipeline**: GPU rendering pipeline verification and 3rd-derivative kinematic jerk entropy ($d^3x/dt^3$) evaluation for biological human tremor attestation.
- **Mandatory Attestation**: Enforced strict telemetry validation; unverified empty payloads (`{}`) reject automatically with Risk 100.
- **Dual-Token Architecture**: Ephemeral PoW challenge nonces combined with HMAC-SHA256 wire seals (`obsx.seal.v1`).
- **Atomic Secret Key Revocation**: Instant invalidation of deprecated rotated keys with zero leakage window.
- **Priority-Tiered Memory Eviction**: 100k key cap with LRU pruning preventing memory exhaustion under concurrent volumetric load.

### Verification
- **Test Suite**: 81 / 81 tests passing locally and across edge environments.
- **Zero Dependencies**: 100% native standard library (`crypto`, `http`, `fs`).
