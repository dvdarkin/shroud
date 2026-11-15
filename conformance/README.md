# Shroud conformance corpus ("golden oracle")

Language-neutral test data generated from the C# implementation (`src/Shroud`, library public API only).
A second implementation (for example the TypeScript port) is conformant when, for every input and config
in this directory, it reproduces the files under `expected/` and can read the vaults under `vaults/`.

Nothing here depends on, or is checked against, any other implementation. `src/Shroud.Private` is ignored.

## Layout

```
conformance/
  inputs/            101 markdown inputs (exact bytes matter: CRLF, BOM, empty file, non-ASCII)
  configs/           13 shroud.json variants
  expected/
    index.json                       input list with byte length, UTF-16 length, SHA-256; config list; mask key
    patterns.json                    the full pattern library in evaluation order (regex source, confidences, context words)
    config/<config>.json             effective config + which patterns it enables (indexes into patterns.json)
    scan/<config>/<input>.json       scan result per (config, input)          13 x 101 = 1313 files
    mask/<input>.md                  masked text, default config, fixed key  101 files
    mask/<input>.tokens.json         token list for the same run             101 files
    tokens/derivation-vectors.json   HMAC token derivation vectors, abbreviation table
  vaults/            6 vaults written by the C# VaultBuilder (see vaults/README.md)
  Generator/         the C# console project that produces everything under expected/ and vaults/
  .gitattributes     `* -text`: never normalise line endings in this tree
```

`<input>` is the input file name without `.md`, `<config>` the config file name without `.json`.

## Regenerating

```
dotnet run --project conformance/Generator              # rewrites conformance/expected/, verifies the vaults
dotnet run --project conformance/Generator -- --vaults  # additionally REWRITES the vault fixtures (new random bytes)
dotnet run --project conformance/Generator -- --out DIR # write expected/ elsewhere (used for determinism checks)
dotnet run --project conformance/Generator -- --culture tr-TR --out DIR   # experiment: non-invariant culture
```

The generator references `src/Shroud/Shroud.csproj` directly (project reference) and lives outside `src/`, so
`dotnet build src` / `dotnet test src` never see it. It pins `CultureInfo.InvariantCulture` before any `Regex` is
built (see "Culture dependence" below). Without `--vaults` the existing vault fixtures are only verified (wrong
passphrase rejected, right passphrase decrypts, reveal equals source, recorded file hashes match, `manifest.json`
`source` is `input`, every manifest `service` is a pattern of the token's own type). Scan, mask,
config, pattern and token outputs are byte-identical across runs; vault bytes are not (random salt, nonce and
masking key), which is why vault regeneration is opt-in.

Output conventions: UTF-8 without BOM, LF newlines, 2-space indent, insertion-ordered keys, non-ASCII written raw,
only JSON-mandatory escapes. Offsets are UTF-16 code units (C# `string` indexes), counted on the text as decoded by
C# `File.ReadAllText` (see "Input decoding").

## Inputs

Each file is small and focused; names are `NNN-topic.md`.

| Range | Content |
|---|---|
| 001-012 | On-chain: EVM (full, truncated, bracketed, corrupted), Bitcoin family, other chains, ENS/validators/pools, correlation identifiers with and without context, key=value log lines, explorer URLs, BIP32 keys, 64-hex values |
| 020-024 | Credentials: every service pattern, near-miss lengths, context-only shapes (Cloudflare, Heroku, Twilio, NuGet) |
| 030-032 | Secrets: PEM headers, JWT, database URIs, SQL connection strings, password and login assignments, YAML/JSON snippets |
| 040-055 | Financial: currency symbols and codes, shorthand, market pairs, quantities, prices, arithmetic chains, table cells, credit cards (Luhn valid and invalid matrix), date and time formats next to trading words, years that are really amounts, wei-precision decimals |
| 060-063 | Identity: SSN (including excluded ranges), IBAN, IPv4, MAC, email, UNC and file URI paths |
| 070-079 | False-positive fixtures (devops log, academic text, legal text, crypto tech doc, spreadsheet export, markdown formatting, multilingual text, meeting notes, strategy text, code discussion, substring context words) |
| 080-085 | Mixed fixtures taken from the C# integration tests |
| 090-091 | Fenced, indented and inline code (the scanner does NOT exclude code) |
| 100-101 | Overlapping candidate spans |
| 110-115 | Context window: a context word exactly at the 120-character edge, one character outside, before and after the match, case and multiple words |
| 120-129 | Non-ASCII: accented Latin, Cyrillic, CJK, emoji (surrogate pairs), fullwidth digits, Arabic-Indic digits, case-folding oddities, letters adjacent to word-bounded patterns, combining marks and special spaces, uppercase ASCII `I` (Turkish culture trap) |
| 130-133 | YAML front matter (LF, CRLF, edge cases), `file:`/`path:`/`attachment:` metadata lines. The prose inside 132 and 133 predates the front matter and metadata-key fixes (for example "excluded because profile: contains file:"); the bytes are kept stable and the goldens show the current behaviour |
| 134-139 | LF, CRLF, mixed and lone-CR line endings, no trailing newline, UTF-8 BOM, tabs and blank lines |
| 140-145 | Empty file (0 bytes), whitespace only, no-match line, 30k-character line, long digit/hex runs, 40 dense matches |
| 150-155 | Front matter only at offset 0: real front matter followed by a horizontal-rule pair with secrets between (LF 150, CRLF 151), rules with a secret and trailing spaces/tab and no front matter (152), a `---` block preceded by a blank line (153), empty front matter followed by more text and a lone rule (154), unterminated front matter at offset 0 (155) |
| 156 | Whole-word metadata keys: `profile:`, `classpath:`, `my-file:`, `my_path:`, `Docfile:`, `file2path:` and a `file:` URI glued to a word are scanned; genuine `file:`, `FILE:`, `source_file:`, `path:`, `Attachment:`, `- file:`, `(path:` lines stay excluded |
| 157 | Separator-only text (`,`, `,,,,`, `$,`, `EUR ,`, `at ,`) in every financial shape that used to match it, plus the same shapes with real numbers |
| 158 | A metadata key at the end of its line (`file:`, `path:   `) does not hide the following line; a key with a value on the same line stays excluded |

Strings from the existing C# fixtures (`FalsePositiveFixtures`, `ScannerFixtures`, unit tests) are reused; fixture
files are marked `-fixture` where they are verbatim copies. All values are obviously fake (`0x1111...`, `AAAA...`,
`example.com`, documentation-style card numbers, `123-45-6789`).

Coverage: every one of the 22 entity types that have patterns and every one of the 5 domains is detected at least
once; all 104 patterns are exercised (`file_uri_network_path` only in 156, see "Quirks").

## Configs

| File | What |
|---|---|
| `default.json` | `ShroudConfig.Default()` = the `paranoid` preset (what the CLI uses when no `shroud.json` exists) |
| `paranoid.json`, `financial.json`, `dev.json` | the three presets the CLI offers (`init --preset`), equal to `ShroudConfig.ForPreset(...)` (self-checked by the generator) |
| `threshold-090.json`, `threshold-030.json` | paranoid domains, threshold 0.90 and 0.30 |
| `layer-magnitudes.json` | financial layer `magnitudes` |
| `no-onchain.json`, `no-identity.json`, `no-credentials-secrets.json` | a domain switched off |
| `quirk-empty-object.json`, `quirk-preset-name-only.json` | how the C# loader treats incomplete files (see "Quirks") |
| `case-insensitive-keys.json` | property names in mixed case at both levels (`Domains`, `onchain`, `FINANCIAL`/`Enabled`, `identity`/`ENABLED`, `THRESHOLD`): all honoured, so on-chain, financial and identity are off and the threshold is 0.90 (replaces the former `quirk-lowercase-keys.json`, where `onchain` was ignored) |

The mask goldens and vault fixtures use `default` (vaults also use `dev` and `financial`).

## JSON schema of the expected files

### `expected/scan/<config>/<input>.json`

```
{
  "input": "NNN-name.md",
  "config": "<config>",
  "inputBytes": int,              raw file size
  "inputSha256": "hex",           SHA-256 of the raw file bytes (corpus integrity check)
  "inputUtf16Length": int,        length of the decoded text the offsets refer to
  "threshold": number,            ScanResult.Threshold (= config threshold)
  "thresholdString": "0.5",       invariant-culture round-trip string of the same double
  "counts": { "allDetected": int, "aboveThreshold": int, "belowThreshold": int },
  "allDetected": [                ScanResult.AllDetected, in C# order (ascending Start)
    {
      "index": int,               position in allDetected
      "start": int,               UTF-16 offset, inclusive
      "end": int,                 UTF-16 offset, exclusive
      "length": int,              end - start
      "matchedText": string,      exactly text[start, end)
      "entityType": string,       C# enum name, e.g. "CryptoAddr"
      "domain": string,           C# enum name: OnChain | Financial | Identity | Credentials | Secrets
      "service": string,          pattern id, e.g. "evm_address"
      "typeAbbreviation": string, token prefix, e.g. "ADDR"
      "confidence": number,       final confidence (JSON number == confidenceString text)
      "confidenceString": string, double.ToString("R", InvariantCulture), shortest round-trip
      "aboveThreshold": bool      confidence >= threshold
    }
  ]
}
```

`AboveThreshold` is `allDetected` filtered by `aboveThreshold == true`, `BelowThreshold` the rest, both in the same
order. Confidence values are IEEE doubles produced by `base + boost + 0.05*min(n-1,3) + 0.10 + 0.10`, capped at 1.0,
evaluated left to right, so values such as `0.8999999999999999` and `0.30000000000000004` are expected; compare with
the string field or exact double equality.

### `expected/mask/<input>.md` and `<input>.tokens.json`

`.md` is the masked text (default config, key below), UTF-8 without BOM, no newline normalisation. `.tokens.json`:

```
{ "input", "config": "default",
  "maskKeyHex": "000102...1f",
  "maskedUtf16Length": int, "maskedSha256": "hex of the UTF-8 bytes of the .md file",
  "tokenCount": int,
  "tokensInReplacementOrder": [   SpanMasker.Mask().Tokens: spans sorted by Start DESCENDING (right-to-left)
    { "tokenId": "ADDR:f116adc4",   TypeAbbreviation + ":" + 8 lowercase hex
      "start": int, "end": int,     offsets in the ORIGINAL text
      "originalValue": string, "entityType": string, "domain": string } ] }
```

The masking key for every mask golden is the 32 bytes `00 01 02 ... 1f` (hex above). Duplicate values appear once
per occurrence.

### `expected/tokens/derivation-vectors.json`

`vectors[]`: `{keyLabel, keyHex, text, textUtf8Hex (null for the 5000-character text), textUtf16Length, entityType, tokenId}`
for 4 keys (32 bytes, 9 bytes, 100 bytes, empty) x 12 texts (ASCII, empty, accented, Cyrillic, CJK, emoji, CRLF, tab, 5000 chars).
`typeAbbreviations[]`: `{entityType, typeAbbreviation, tokenIdForTextSampleWithFixedKey}` for all 24 enum values.

### `expected/patterns.json`

`{contextWindowChars, additionalContextWordBoost, maxAdditionalContextWords, assetNameBoost, currencySignalBoost, knownAssets[], patternCount, patterns[]}`;
each pattern: `{index, service, entityType, domain, regex (the .NET pattern source), regexOptionsDotNet, regexOptionsDotNetValue, baseConfidence(+String), contextWords[], contextBoost(+String), isStructural}`.
The array order is the evaluation order (matters for overlap ties). `regexOptionsDotNet` is the .NET flag set
(`Compiled`; the in-pattern `(?i)` is part of `regex`; `large_number` also has `IgnoreCase`).

### `expected/config/<config>.json`

`{config, sourceFile, threshold(+String), preset, keyFile, domains{onChain,financial,identity,credentials,secrets: {enabled, layer}}, patternCount, patternIndexes[], patternServices[]}`.
This is the config as the C# loader sees it (not as the file reads), and the ordered subset of patterns it enables.
`layer` is only meaningful for `financial`.

### `expected/index.json`

`{inputs[{name, bytes, utf16Length, sha256}], configs[], maskKeyHex}`.

## Observed behaviour a second implementation must reproduce

This is a description of what the C# source does, not a design opinion.

### Pipeline (`SensitivityScanner.Scan`)

1. Exclusion zones on the full text:
   - front matter `\A---[ \t]*\r?\n(?:[^\n]*\n)*?---[ \t]*\r?$` (multiline): only when the text starts with a `---`
     line at offset 0 (after BOM stripping), up to and including the next `---` line (LF or CRLF; trailing spaces/tabs
     allowed; an empty block `---\n---` ends at its own closing line). At most one zone; later `---` pairs are
     horizontal rules. Unterminated front matter produces no zone. Inputs 130-132, 150-155.
   - file-path metadata `(?<![\p{L}\p{Nd}_\-])(?:source_file|file|path|attachment):[ \t]*.+$` (multiline, ignore-case):
     the key must not be preceded by a Unicode letter, decimal digit, `_` or `-` (start of line, space, `(`, `- ` are
     fine). The value must be on the same line as the key: a key with nothing after it excludes nothing, so the
     next line is scanned. Inputs 133, 156, 158.
   - nine date/time regexes (private in C#; ISO date with optional time, year-month, clock time, MM/DD/YYYY,
     DD/MM/YYYY, month-name dates, ISO week, 12-hour clock, bare year 19xx/20xx). Copy them from
     `SensitivityScanner.cs`; the effects are visible in inputs 052/053.
2. For each pattern in order, for each regex match: drop it when it lies FULLY inside one zone. Then drop it when the
   pattern is Financial with entity type Amount, Quantity or Price and the matched text contains no decimal digit
   (`char.IsDigit`, i.e. Unicode Nd, the same class as .NET `\d`). This post-filter (inputs 041, 157) removes
   separator-only matches such as `,` from `[\d,]+` patterns; the regexes in `patterns.json` are unchanged. A dropped
   match is not scored and takes no part in overlap resolution.
3. Score: if the pattern has no context words the confidence is the base. Otherwise take the window
   `[max(0, start-120), min(len, end+120))`; every context word found in the window (ordinal ignore-case
   SUBSTRING) is collected; found > 0 adds `contextBoost`; found > 1 adds `0.05 * min(found-1, 3)`; for
   Financial-domain patterns add 0.10 if any known asset name is a substring of the window, then 0.10 if any
   currency signal (`usd aud eur gbp jpy cad chf nzd sgd hkd krw cny inr brl usdt usdc dai $ fee fees commission rate`)
   is; cap at 1.0.
4. Credit-card spans failing Luhn (ASCII-digit sum, 13..19 digits, separators ignored) are dropped.
5. Overlap resolution: sort by length DESC then confidence DESC (stable, input order = pattern order then match
   order); keep a span unless it overlaps an already accepted span in a way that dominates it (contained, shorter,
   or equal length with accepted confidence >=); an accepted span fully contained in a new winner is removed.
   Result sorted by Start (stable).
6. Split at `confidence >= threshold`.

### Masking

Spans with `AboveThreshold` are replaced right to left: `[` + `ABBR:` + first 4 bytes of
`HMAC-SHA256(key, UTF8(matchedText))` as lowercase hex + `]`. The replaced range is exactly `[start, end)` of the
span, so matched text that includes leading whitespace or a leading `at ` (e.g. `asset_quantity`, `price_dollar`)
takes that text with it (`Bought[QTY:815ea90f]`). Token ids do not depend on the pattern, only on type
abbreviation and matched text.

### Input decoding

C# reads with `File.ReadAllText`: UTF-8 by default, a BOM is detected and stripped (UTF-16/32 BOMs also switch the
encoding), invalid bytes become U+FFFD, newlines are untouched. Input 138 starts with a UTF-8 BOM: its offsets are
relative to the text after the BOM (`inputBytes` is 3 more than the UTF-8 length of the text).

### Vault container format

`vault.shroud` (`VaultEncryption`): `salt(16) | nonce(12) | tag(16) | ciphertext(N)`, N = plaintext length, all
concatenated, no header, no version byte.
- Key: PBKDF2-HMAC-SHA512, password = UTF-8 bytes of the passphrase (no Unicode normalisation), salt = the 16
  bytes, 600000 iterations, 32-byte output.
- Cipher: AES-256-GCM, 12-byte nonce, 16-byte tag, no associated data. Note the tag sits BEFORE the ciphertext
  (WebCrypto expects it appended after the ciphertext; Node `createDecipheriv` takes it separately).
- Any failure (wrong passphrase, tampering, input shorter than 44 bytes) is reported as "null"/wrong password; there
  is no other error classification. A 44-byte file decrypts to the empty string.
- Plaintext: UTF-8 JSON, camelCase, indented, nulls omitted, produced by `System.Text.Json` with its default
  encoder (so `"` is `"`, `+` is `+`, non-ASCII is `\uXXXX`; the indent newline is the OS newline, CRLF on
  Windows): `{"version": 1, "created": "<ISO-8601 UTC, 7 fractional digits>", "tokens": {"ADDR:abcd1234": "<original value>", ...}, "fileHashes": {"<relative path>": "sha256:<hex>", ...}}`.
  `fileHashes` hashes the UTF-8 bytes of the MASKED file content. The CLI never verifies them.
- `manifest.json` (public): `{created, source, fileCount, tokenCount, tokens: {tokenId: {service (pattern id), domain (lowercase enum name), files[], occurrences}}, summary: {domain: occurrences}}`.
  `source` is only the final directory name of the source: the path passed to `Build` is resolved to a full path
  (so `.` and relative paths work), a trailing separator is trimmed, and the last segment is kept (a filesystem root
  has no name and is kept as is). `service` is the pattern id of the first above-threshold span, in the file where the
  token first appears, whose matched text AND entity type equal the token's (vault `v6` shows the same text as an
  Amount and as a Quantity, each with its own service).
- Token id collisions: when a token id already registered maps to a DIFFERENT original value, `Build` throws
  `TokenCollisionException` (property `TokenId`; the message names the token id only, never a value) before anything
  is written; the same value seen again is just another occurrence.
- `public/<relative path>`: masked copies, same relative layout, UTF-8 without BOM, newlines preserved; files with
  no above-threshold span are re-written as read (so a BOM is dropped).
- Reveal (CLI): for each `public/**/*.md`, `ReadAllText`, then for each `(tokenId, value)` of `tokens` in file
  order `content = content.Replace("[" + tokenId + "]", value)` (ordinal, sequential), `WriteAllText`.
- The vault masking key is 32 fresh random bytes per `VaultBuilder` instance and is not exposed by the public API,
  so the token ids inside a vault fixture cannot be recomputed by another implementation. Verify vaults by decrypting
  and restoring, not by recomputing tokens. (Token derivation is verified separately by `tokens/derivation-vectors.json`
  and the mask goldens.) The CLI `mask` command uses a key file (`config.keyFile` or `.shroud/vault.key`, 32 random
  raw bytes, any length accepted).

## Hard-to-match behaviours (for the port)

- **Unicode regex classes.** .NET `\d`, `\w`, `\b`, `\s` are Unicode-aware: fullwidth, Arabic-Indic, Devanagari and
  Extended Arabic-Indic digits match `\d` (inputs 124, 125 produce amounts, SSNs, quantities from them); a Cyrillic
  or accented letter next to a word-bounded pattern suppresses it (121, 127). JavaScript `\d`/`\b` are ASCII-only
  even with the `u` flag, and JS `\s` includes U+FEFF.
- **`.` and `$`.** .NET `.` excludes only `\n`; JS `.` also excludes `\r`, ` `, ` `. .NET multiline `$` matches
  only before `\n`; JS multiline `$` also matches before `\r`. Inputs 131, 135, 136, 128 exercise this.
- **Ignore-case.** .NET `IgnoreCase` without `CultureInvariant` uses the current culture (see below) and its own
  equivalence table; U+017F (long s) and U+212A (Kelvin) do NOT match `s`/`k` here (input 126), while JS `/iu`
  folds them.
- **Offsets** are UTF-16 code units; emoji are 2 units (123).
- **Floating point.** Confidence arithmetic accumulates in a fixed order (see schema).
- **Lookbehind** with variable length is used (`arithmetic_result`, `arithmetic_equals_right`, `table_cell_number`).
- **Culture dependence.** Under a Turkish culture the `(?i)` patterns stop matching uppercase ASCII `I`
  (`VALIDATOR`, `LOGIN`, `API_KEY`, `POSITION`, `FILE:`); only inputs 129 and 156 (its `FILE:` line) differ between
  the invariant run and a `tr-TR` run (`--culture tr-TR`), so the goldens are the invariant-culture behaviour. `VaultBuilder` also orders
  files with a culture-sensitive `OrderBy`, which changes only the order of JSON keys and of the file list, not content.
- **Path separators.** `VaultBuilder` stores `Path.GetRelativePath` results unchanged, so `manifest.json` `files` and
  `fileHashes` keys use `\` when written on Windows and `/` elsewhere. The committed vaults were written on Windows.
- **Timestamps and paths.** `created` is `DateTime.UtcNow`. `manifest.json` `source` is the source directory name
  only; the generator passes the ABSOLUTE path of each vault's `input/` and checks that `source` is `input`.
- **Unicode lookbehind.** The file-path key lookbehind uses `\p{L}` and `\p{Nd}`; JavaScript needs the `u` flag for
  those, and `\d`/`\w` must not be used in their place.

## Quirks recorded (not fixed; see report)

1. `PatternLibrary.IsWithinFinancialLayer`: credit-card patterns fall into the default arm and require layer
   `directional`; the `financial` preset (`markets`) and `magnitudes` never detect cards (compare `scan/default` and
   `scan/financial` for 050/051).
2. `file_uri_network_path` fires only when `file:` is glued to a preceding letter, digit, `_` or `-` (156,
   `see-file:///...`); an ordinary `file:///...` URI starts with a whole-word `file:` key and lies fully inside the
   file-path exclusion zone (062).
3. `ShroudConfig.Load` silently ignores unknown property names; `preset` is informational only (`{"preset": "dev"}`
   loads as threshold 0.70, all domains on); `{}` is not equivalent to `Default()` (threshold 0.70, financial
   `markets`). CLI `init` defaults to the `financial` preset while no config means `paranoid`.
4. `LuhnValidator` uses `char.IsDigit` and `c - '0'`, which is wrong for non-ASCII digits (latent: the card regexes only admit `[0-9]`).
5. `bip39` (0.10) can only be reported below the default thresholds; `EntityType.PhoneNumber` and `EntityType.AssetName` have no pattern.
6. `arithmetic_sum_operand` (`[\d,]{4,}\.?\d*(?=\s*[+\-])`) has no leading boundary, so the digit run inside a hex value
   such as `0x1111...1111` followed by a newline and `---` matches when on-chain detection is off (`scan/no-onchain/132`).

## Fixed (formerly listed as quirks or likely bugs)

- Front matter was recognised between ANY two `---` lines, so horizontal rules hid secrets: now only at offset 0.
- The file-path key matched inside longer words (`profile:`, `Docfile:`, `classpath:`): now whole words only.
- `ShroudConfig.Load` was case-sensitive on property names (`"onchain"` was ignored): now case-insensitive at every level.
- Separator-only text (a lone `,`, `$,`) could be an Amount, Quantity or Price: now a financial number needs a digit.
- `VaultBuilder` silently merged two different values that collided on a token id: now `TokenCollisionException`.
- `GetServiceId` ignored the entity type: now text and type must both match.
- `manifest.json` `source` stored the path as given (possibly absolute): now the directory name only.
- CLI: `mask a.md b.md -o out.md` overwrote one output with every input: now refused with exit 1 before writing.
  `init --preset <unknown>` saved the paranoid preset: now exit 1, the error lists the valid presets, nothing written.
  `scan --verbose` printed structural patterns with context words as "structural match (base: X)" and could show a
  losing same-type pattern's scoring: now the real breakdown and the winner's own scoring.
