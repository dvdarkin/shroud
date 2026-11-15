# Shroud

Sensitive data detection and masking for text files. Scans markdown files for sensitive patterns across five detection domains, replaces matches with deterministic tokens, and stores originals in an AES-256-GCM encrypted vault.

Zero runtime dependencies. Source-auditable. Two implementations that behave identically: C# (.NET 8, `src/`) and TypeScript (Node 20 or later, `ts/`). Vaults written by one are read by the other.

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

The same commands with the TypeScript build:

```bash
cd ts && npm ci && npm run build && cd ..
node ts/dist/src/cli.js scan my-notes.md --verbose
node ts/dist/src/cli.js vault ./notes
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

`mask -o` takes exactly one input file; with several inputs (after glob expansion) it refuses and writes nothing. Without `-o` each file is masked in place. `init` with an unknown preset name fails and writes nothing.

## Diagnostic Output

### `--verbose` (verify detections)

Shows whether each match is structural or contextual, which context words were found, and the confidence breakdown:

```
Financial   Amount        currency_amount   0.85  $12,500
            structural match (base: 0.85)

OnChain     CryptoAddr    solana_address    0.85  7xKXtg...
            contextual match (base: 0.30 + context: +0.55)
            context words: "solana", "phantom" (within 120 chars)

Financial   CreditCard    visa              0.95  4111 1111 1111 1111
            structural match (base: 0.80 + context: +0.15)
            context words: "card" (within 120 chars)
```

A structural pattern (base >= 0.80) that also has context words shows the same breakdown, because nearby words can still raise its confidence. When two patterns of the same type match the same span, the scoring shown is the winning pattern's.

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
- **Excluded regions** - YAML front matter is not scanned, but only when the file starts with a `---` line (it ends at the next `---` line); `---` pairs later in a document are horizontal rules and are scanned. Text from a `source_file:`, `file:`, `path:` or `attachment:` key to the end of its line is not scanned when the key starts a line or follows a space, a tab or `(`; a key glued to anything else (`profile:`, `classpath:`, `my-file:`, `|file:`, a combining mark) is ordinary text and is scanned.

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

Property names are matched case-insensitively at every level (`"onchain"` configures `onChain`).

## Vault Output

```
<dir>.shroud/
  public/          Masked copies with [TYPE:XXXXXXXX] tokens
  vault.shroud     Encrypted token registry (AES-256-GCM, PBKDF2-SHA512 600k iterations)
  manifest.json    Public metadata for agents (no secret values)
```

`manifest.json` records the source only as its directory name (`my-notes`), never the absolute path.

### Token Collision Safety

Token IDs are HMAC-SHA256 truncated to 4 bytes (2^32 = ~4.3 billion possible values). By the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem), the probability of any two distinct sensitive values producing the same token ID is:

| Unique values in vault | Collision probability |
|------------------------|---------------------|
| 1,000 | ~0.01% |
| 10,000 | ~1.2% |
| 50,000 | ~25% |

For realistic workloads (hundreds of files, thousands of unique sensitive values), collision risk is negligible. Same value always produces the same token (deterministic via HMAC), so repeated occurrences of the same address or key are not collisions — they correctly map to the same token.

If two different values do produce the same token ID, `VaultBuilder.Build` throws `TokenCollisionException` (naming the token ID, never the values) instead of silently dropping one, and `shroud vault` prints a one-line error, exits non-zero and writes nothing. Each run uses a fresh masking key, so running again resolves it.

## Two Ways to Use Shroud

Packages: `LogMark.Shroud` (library) and `LogMark.Shroud.Cli` (.NET tool, command `shroud`) on NuGet, `@logmark/shroud` on npm. The package called `Shroud` on NuGet is an unrelated project; do not install it expecting this one. Building from source (Quick Start) gives the same result.

**CLI tool** — `dotnet tool install --global LogMark.Shroud.Cli`, or `npm install -g @logmark/shroud`, or from source with `dotnet run --project src/Shroud.Cli -- <command>`. Scan files, mask in place, or vault entire directories from the command line. Best for batch processing and CI pipelines.

**Library** — `dotnet add package LogMark.Shroud`, or a project reference to `src/Shroud/Shroud.csproj` if you build from source. Call `SensitivityScanner.Scan()` to detect spans, `SpanMasker.Mask()` to tokenize them, and `VaultEncryption` to encrypt/decrypt vault data. This lets applications shroud data on the fly — for example, showing original values in a UI while persisting only masked content to disk, or scanning user input before it reaches storage. The library has zero dependencies beyond .NET 8, making it safe to embed in any application without dependency conflicts.

```csharp
var scanner = new SensitivityScanner(config);
var result = scanner.Scan(userInput);

var masker = new SpanMasker(key);
var masked = masker.Mask(userInput, result);
// masked.MaskedText is safe to persist
// masked.Tokens maps token IDs back to original values (keep in memory or encrypt)
```

**TypeScript library** - `npm install @logmark/shroud`, built from `ts/`. The same API in camelCase, with no runtime dependencies beyond Node itself:

```ts
import { SensitivityScanner, SpanMasker, loadConfig } from '@logmark/shroud';

const scanner = new SensitivityScanner(loadConfig('shroud.json'));
const result = scanner.scan(userInput);
const masked = new SpanMasker(key).mask(userInput, result);
// masked.maskedText is safe to persist
```

## Two Implementations, One Corpus

The C# and TypeScript implementations are held to the same behaviour by `conformance/`: 106 input files across 13 configurations, with the expected scan results, masked output, token derivation vectors and six encrypted vaults, all generated from the C# build. The TypeScript port has to reproduce every expected file and read every vault. CI runs this on Windows and Linux, and fails if the committed corpus no longer matches what the C# source generates.

- Detection results are identical span for span, including confidence values.
- Masked text and token ids are identical for the same key.
- A vault written by either implementation is revealed by the other.

The on-disk format (vault container, key derivation, token derivation, manifest, `shroud.json`) is specified in [docs/format.md](docs/format.md). A change in behaviour lands in both implementations together; see [CONTRIBUTING.md](CONTRIBUTING.md).

Known differences are limited to the command-line host: the TypeScript CLI always writes UTF-8, does not open a directory given with a trailing dot or space on Windows, and is about three times slower than .NET on bulk scans. [ts/README.md](ts/README.md) lists them in full.

## Building

```bash
# C#
dotnet build src
dotnet test src
dotnet run --project src/Shroud.Cli -- help

# TypeScript
cd ts && npm ci && npm test && cd ..

# The TypeScript port against the corpus generated from the C# build
node conformance/run-ts.mjs
```

## License

Apache-2.0
