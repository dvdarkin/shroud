# Changelog

## 0.2.0 — 2026-04-08

Detection quality and release readiness.

- Fix: verb_quantity pattern no longer consumes the verb ("bought 100" → "bought [QTY]", not "[QTY]")
- Fix: price pattern split into structural ($) and contextual (bare) — "at 512 MB" no longer detected as price
- Fix: arithmetic patterns no longer triggered by distant `$` in context window
- Fix: comma-separated numbers ("15,000 USDC") detected as full amount, not bare "000"
- Fix: date components excluded — "17 JUL" and timestamp parts (10:36:54) no longer detected as quantities
- Fix: token ID widened from 2 bytes to 4 bytes (8 hex chars) for collision safety at vault scale
- Refactor: financial layers renamed from L1/L2/L3 to `magnitudes`/`markets`/`directional`
- Refactor: PatternLibrary split into 5 domain-specific partial classes with contributor docs
- Refactor: service-specific patterns (Etherscan) removed from core — use Shroud.Private for extensions
- Feat: `--verbose` and `--debug` flags on `scan` command for detection transparency
- Feat: private pattern extensions via conditional Shroud.Private project
- Preset `trading` renamed to `financial`
- 81 tests (51 unit, 30 integration) including vault round-trip with SHA-256 hash verification

## 0.1.0 — 2026-04-08

Initial release.

- 5 detection domains: on-chain, credentials, secrets, financial, identity
- 70+ detection patterns across 15+ blockchain ecosystems and 30+ credential services
- Context-aware confidence scoring with 120-character window analysis
- Deterministic HMAC-SHA256 token generation for cross-file correlation
- AES-256-GCM vault encryption with PBKDF2-SHA512 key derivation (600k iterations)
- Three presets: `paranoid`, `financial`, `dev`
- CLI commands: `scan`, `mask`, `vault`, `reveal`, `init`
- Zero runtime dependencies
