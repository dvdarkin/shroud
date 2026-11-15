# Changelog

## 0.3.0 - 2026-11-15

A second implementation, and the leaks it turned up. See SECURITY.md: files masked with 0.2.0 or earlier should be rescanned.

- Feat: TypeScript implementation in `ts/` (`@logmark/shroud`): the library and CLI with zero runtime dependencies, identical detection results, masked output and vault format; vaults are interchangeable with the C# build in both directions
- Feat: conformance corpus in `conformance/` (106 inputs x 13 configs, mask goldens, token vectors, 6 vaults) generated from the C# build and checked against the TypeScript port; CI on Windows and Linux
- Feat: format specification in `docs/format.md`
- Security: front matter is excluded only when the file starts with `---`; text between two horizontal rules was never scanned
- Security: `file:`/`path:`/`source_file:`/`attachment:` exclude a line only as a real metadata key (at a line start or after a space, tab or `(`), only up to the end of that line, and never the next line; `profile: ...` and similar hid text
- Security: a token id collision between two different values fails the vault build (`TokenCollisionException`); the second value used to be lost and `reveal` restored the wrong text
- Security: `manifest.json` stores only the source directory name, not the path as given
- Fix: detection no longer depends on the process culture (under tr-TR, uppercase `VALIDATOR`, `LOGIN`, `API_KEY`, `POSITION`, `FILE:` did not match); vault file order is ordinal
- Fix: separator-only text such as a lone `,` is no longer detected as an amount
- Fix: `shroud.json` keys are matched case-insensitively (`"onchain"` used to be ignored silently)
- Fix: manifest `service` is the pattern of the token's own entity type
- Fix: `mask -o <file>` with several inputs is refused; it used to overwrite the same file for each input
- Fix: `init --preset <unknown>` fails and writes nothing; it used to save the paranoid preset
- Fix: `scan --verbose` shows the real base confidence and the winning pattern's scoring
- 208 C# tests (159 unit, 49 integration), 241 TypeScript tests

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
