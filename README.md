# Shroud

Sensitive data detection and masking for text files. Scans markdown files for sensitive patterns across five detection domains, replaces matches with deterministic tokens, and stores originals in an AES-256-GCM encrypted vault.

Zero runtime dependencies. Source-auditable. Built on .NET 8.

## Quick Start

```bash
git clone https://github.com/dvdarkin/shroud.git
cd shroud
dotnet build src

# 1. Scan a file to see what would be detected
dotnet run --project src/Shroud.Cli -- scan my-notes.md --verbose

# 2. Review the output. Adjust shroud.json if needed.
# 3. When satisfied, vault a directory
dotnet run --project src/Shroud.Cli -- vault ./notes
```

## Verify Before You Trust

Shroud works for the author's use cases. **Your data is different.**

Before vaulting a directory, run `scan` on representative files and verify the detections match your expectations. The `--verbose` flag shows why each span was flagged (structural match vs. context-boosted, which context words were found, confidence breakdown). The `--debug` flag adds exclusion zones, overlap resolutions, and context window boundaries.

**Vault mode is recursive** — it processes all `.md` files in the target directory and all subdirectories. Run `scan` first on individual files to calibrate.

Recommended workflow:
1. `shroud init` — pick a preset, or edit `shroud.json` directly
2. `shroud scan sample.md --verbose` — review detections on a representative file
3. Adjust threshold or toggle domains in `shroud.json`
4. Repeat until detections match your expectations
5. `shroud vault ./directory` — create the vault

## Detection Domains

| Domain | Covers | Examples |
|--------|--------|----------|
| **On-Chain** | Crypto addresses (15+ chains), transaction hashes, ENS names, validator indices, block numbers, explorer URLs | `0x1234...`, `bc1q...`, `validator #548231` |
| **Credentials** | Service-specific API keys and tokens (30+ services) | `ghp_...`, `sk-ant-...`, `AKIA...` |
| **Secrets** | PEM private keys, JWTs, database connection strings, password assignments | `-----BEGIN PRIVATE KEY-----`, `eyJ...` |
| **Financial** | Currency amounts, market pairs, credit cards (Luhn-validated), arithmetic chains | `$12,500`, `EUR/USD`, `4111-1111-...` |
| **Identity** | SSNs, IBANs, IP addresses, MAC addresses, email addresses | `123-45-6789`, `AA:BB:CC:DD:EE:FF` |

## Presets

| Preset | Domains | Financial Layer | Threshold |
|--------|---------|----------------|-----------|
| `paranoid` (default) | All | `directional` (amounts + markets + direction words) | 0.50 |
| `financial` | All | `markets` (amounts + market pairs) | 0.70 |
| `dev` | All except Financial | — | 0.70 |

## Commands

```
shroud <directory>                              Vault (default command)
shroud vault <directory> [-o output]            Vault with explicit command
shroud reveal <vault-dir> [-o output]           Decrypt and restore
shroud scan <file.md> [--verbose] [--debug]     Detection report
shroud mask <file.md> [-o output.md]            Replace spans with tokens
shroud init [--preset financial|dev|paranoid]    Create shroud.json
```

## Diagnostic Output

### `--verbose` (verify detections)

Shows whether each match is structural or contextual, which context words were found, and the confidence breakdown:

```
Financial   Amount        currency_amount   0.85  $12,500
            structural match (base: 0.85)

OnChain     CryptoAddr    solana_address    0.85  7xKXtg...
            contextual match (base: 0.30 + context: +0.55)
            context words: "solana", "phantom" (within 120 chars)
```

### `--debug` (contributor diagnostics)

Everything in `--verbose`, plus exclusion zones, overlap resolutions, Luhn rejections, and context window char boundaries.

## Known Limitations

**Structural vs. contextual detection.** Patterns with unique prefixes (EVM `0x` addresses, API keys with service-specific prefixes) are detected with high confidence (0.85-0.95). Patterns without unique structure (generic hex strings, shorthand amounts like "12.5k", addresses in Base58 without prefixes) rely on a 120-character context window to boost confidence. This is inherently heuristic.

**Specific weak spots:**
- **Solana/Polkadot addresses** (0.30 base confidence) — Base58 without a unique prefix. Requires context words like "solana" or "polkadot" nearby. False positives possible with other Base58-like strings.
- **Shorthand amounts** ("12.5k", "500m") — Ambiguous with data sizes (megabytes, kilobytes). Detected only when financial context words appear within 120 characters.
- **Context word substring matching** — "sol" matches inside "solution", "dot" inside "polkadot". Context scoring uses substring matching, not whole-word matching.
- **Market pairs with dashes** — "CI-CD" matches the `[A-Z]{2,6}-[A-Z]{2,6}` pattern at 0.40 base confidence. Requires trading context words to reach threshold.
- **Arithmetic expressions** — Numbers in math ("10 / 2") can be flagged if currency codes appear within 120 characters.
- **Seed phrase detection** — Placeholder only (first 10 BIP-39 words at 0.10 confidence).
- **Markdown files only** — Other file formats are not scanned.

## Trust Model

Three-tier trust architecture:
- **Tier 0 (Public):** Read masked files, view manifest metadata, correlate tokens across files
- **Tier 1 (Operator):** Can mask files (requires key file), cannot unmask
- **Tier 2 (Owner):** Can reveal original data (requires vault password)

Masking increases safety (allowed). Revealing decreases safety (password-gated).

See [docs/trust-architecture.md](docs/trust-architecture.md) for details.

## Configuration

`shroud.json` controls which domains are active, the confidence threshold, and the financial detection layer:

```json
{
  "domains": {
    "onChain": { "enabled": true },
    "financial": { "enabled": true, "layer": "markets" },
    "identity": { "enabled": true },
    "credentials": { "enabled": true },
    "secrets": { "enabled": true }
  },
  "threshold": 0.70,
  "preset": "financial"
}
```

## Vault Output

```
<dir>.shroud/
  public/          Masked copies with [TYPE:XXXXXXXX] tokens
  vault.shroud     Encrypted token registry (AES-256-GCM, PBKDF2-SHA512 600k iterations)
  manifest.json    Public metadata for agents (no secret values)
```

### Token Collision Safety

Token IDs are HMAC-SHA256 truncated to 4 bytes (2^32 = ~4.3 billion possible values). By the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem), the probability of any two distinct sensitive values producing the same token ID is:

| Unique values in vault | Collision probability |
|------------------------|---------------------|
| 1,000 | ~0.01% |
| 10,000 | ~1.2% |
| 50,000 | ~25% |

For realistic workloads (hundreds of files, thousands of unique sensitive values), collision risk is negligible. Same value always produces the same token (deterministic via HMAC), so repeated occurrences of the same address or key are not collisions — they correctly map to the same token.

## Two Ways to Use Shroud

**CLI tool** — `dotnet tool install --global Shroud.Cli`. Scan files, mask in place, or vault entire directories from the command line. Best for batch processing and CI pipelines.

**Library** — reference the `Shroud` NuGet package directly. Call `SensitivityScanner.Scan()` to detect spans, `SpanMasker.Mask()` to tokenize them, and `VaultEncryption` to encrypt/decrypt vault data. This lets applications shroud data on the fly — for example, showing original values in a UI while persisting only masked content to disk, or scanning user input before it reaches storage. The library has zero dependencies beyond .NET 8, making it safe to embed in any application without dependency conflicts.

```csharp
var scanner = new SensitivityScanner(config);
var result = scanner.Scan(userInput);

var masker = new SpanMasker(key);
var masked = masker.Mask(userInput, result);
// masked.MaskedText is safe to persist
// masked.Tokens maps token IDs back to original values (keep in memory or encrypt)
```

## Building

```bash
dotnet build src
dotnet test src
dotnet run --project src/Shroud.Cli -- help
```

## License

Apache-2.0
