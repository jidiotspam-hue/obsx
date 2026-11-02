# OBSX Security Protocol — Release Notes

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
