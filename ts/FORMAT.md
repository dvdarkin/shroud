# Shroud on-disk formats (v1)

This is the first written specification of the files Shroud reads and writes. It was
derived from the C# 0.2.0 sources (`src/Shroud/Vault/VaultEncryption.cs`,
`VaultBuilder.cs`, `Masking/SpanMasker.cs`, `Models/ShroudConfig.cs`,
`Shroud.Cli/Program.cs`) and checked against the running .NET 8 build. Both
implementations (C# `Shroud` 0.2.0 and `@logmark/shroud` 0.2.0) produce and accept
exactly this format; vaults are interchangeable in both directions.

Keywords MUST/SHOULD describe what an independent implementation needs to do to
interoperate. "Observed" marks behaviour of the C# build that is reproduced rather
than designed.

## 1. Vault output directory

`shroud vault <dir>` writes:

```
<out>/
  public/            masked copy of every *.md file under <dir>, same relative paths
  manifest.json      token metadata, no secret values (Tier 0)
  vault.shroud       encrypted token registry (Tier 2)
```

- `<out>` defaults to `<dir>` with trailing `/` and `\` characters removed, plus
  `.shroud` (so `notes/` gives `notes.shroud`; observed: `.` gives `..shroud`).
- Input files: every file matching `*.md` in `<dir>` and all subdirectories (Win32
  wildcard matching, case-insensitive on Windows, case-sensitive elsewhere), processed
  in culture-sensitive order of their full path strings (.NET `OrderBy` with the
  current culture; the TS port uses `Intl.Collator()` with the default locale, which
  agreed with .NET on every sample tested).
- All text files are written as UTF-8 without a byte order mark.

## 2. `vault.shroud` container

A flat byte string with no magic number, version byte or length field:

| Offset | Length | Content |
|-------:|-------:|---------|
| 0      | 16     | PBKDF2 salt (random) |
| 16     | 12     | AES-GCM nonce (random) |
| 28     | 16     | AES-GCM authentication tag |
| 44     | N      | AES-GCM ciphertext, N = plaintext length |

Total length is `44 + N`. Note the tag comes **before** the ciphertext, unlike the
`ciphertext || tag` layout produced by WebCrypto and many libraries.

A reader MUST reject (treat as "wrong password") any blob shorter than 44 bytes and any
blob whose tag does not verify. No partial plaintext is ever returned.

### 2.1 Key derivation

```
key = PBKDF2(PRF = HMAC-SHA-512,
             password = UTF-8 bytes of the password string,
             salt = bytes 0..16 of the blob,
             iterations = 600000,
             dkLen = 32)
```

- The password is encoded as UTF-8 with no Unicode normalization; a lone UTF-16
  surrogate (only possible programmatically) is encoded as `EF BF BD`.
- The empty password is valid for the library; the CLI refuses it ("Password required.").

### 2.2 Encryption

AES-256-GCM, 96-bit nonce, 128-bit tag, **no additional authenticated data**. Salt and
nonce are fresh random values for every write, so encrypting the same payload twice
gives different blobs.

### 2.3 Plaintext

The plaintext is the UTF-8 encoding (no BOM) of the vault payload JSON (section 3).
Decoders replace invalid UTF-8 with U+FFFD and do not strip a BOM.

## 3. Vault payload (decrypted JSON)

```json
{
  "version": 1,
  "created": "2026-11-15T01:52:55.5864138Z",
  "tokens": {
    "ADDR:6c8d0f1a": "0x1111111111111111111111111111111111111111",
    "QTY:01b2c3d4": "0.5 ETH"
  },
  "fileHashes": {
    "a.md": "sha256:<64 lower-case hex>",
    "sub\\b.md": "sha256:<64 lower-case hex>"
  }
}
```

| Property | Type | Meaning |
|----------|------|---------|
| `version` | integer | Always `1`. Not checked by either reader. |
| `created` | string | UTC timestamp, .NET round-trip format `yyyy-MM-ddTHH:mm:ss.fffffffZ` (7 fraction digits; the TS build has millisecond resolution and writes `.fff0000Z`). Same value as the manifest. |
| `tokens` | object | Token id (section 5) to original matched text. |
| `fileHashes` | object | Relative path to `sha256:` + lower-case hex SHA-256 of the UTF-8 bytes of that file in `public/`. |

Ordering (writers SHOULD reproduce it; readers MUST NOT depend on it, except that
reveal applies tokens in document order, section 6):

- `tokens`: first-seen order. Files are visited in the order of section 1; within a
  file, tokens are registered right to left (descending span start).
- `fileHashes`: file processing order.
- Relative paths use the platform directory separator of the writer (`\` on
  Windows, `/` elsewhere), so a vault written on Windows has `sub\b.md` keys.
  `fileHashes` is informational: neither build verifies it on reveal.

Serialization (System.Text.Json, `WriteIndented = true`, camelCase names, null
properties omitted):

- Two-space indentation, `"name": value`, empty containers as `{}` / `[]`.
- New lines are the writer platform's `Environment.NewLine`: CRLF on Windows, LF
  elsewhere. Readers MUST accept both.
- String escaping (JavaScriptEncoder.Default): printable ASCII is written as is,
  except `"` `&` `'` `+` `<` `>` and backtick, which are written as `\u0022` `\u0026`
  `\u0027` `\u002B` `\u003C` `\u003E` `\u0060`; `\b \t \n \f \r` use short escapes;
  backslash is `\\`; all other control characters, DEL and every non-ASCII UTF-16
  code unit are written as `\uXXXX` with upper-case hex (a surrogate pair as two
  escapes, a lone surrogate as `\uFFFD`). Readers MUST use a complete JSON parser.
- Numbers use the .NET shortest round-trip form (`0.7`, `1E-07`, `1E+17`).

Reader rules (C# reveal, reproduced by the TS reader): property names are matched
case-sensitively; unknown properties are ignored; a JSON `null` document is reported
as "Corrupt vault file."; malformed JSON or a wrong-typed property aborts the program.

## 4. `manifest.json`

```json
{
  "created": "2026-11-15T01:52:55.5864138Z",
  "source": "notes",
  "fileCount": 6,
  "tokenCount": 122,
  "tokens": {
    "ADDR:6c8d0f1a": {
      "service": "evm_address",
      "domain": "onchain",
      "files": [
        "trading.md"
      ],
      "occurrences": 3
    }
  },
  "summary": {
    "financial": 78,
    "onchain": 32
  }
}
```

| Property | Meaning |
|----------|---------|
| `created` | Same value as the vault payload. |
| `source` | The source directory exactly as given on the command line. |
| `fileCount` | Number of `.md` files written to `public/` (clean files included). |
| `tokenCount` | Number of distinct token ids. |
| `tokens.<id>.service` | Pattern identifier (for example `evm_address`) of the first above-threshold span **in the same file** whose matched text equals the token's value (observed; may name a pattern of a different entity type that matched the same text). |
| `tokens.<id>.domain` | Lower-cased domain: `onchain`, `financial`, `identity`, `credentials`, `secrets`. |
| `tokens.<id>.files` | Distinct relative paths (platform separator) in first-seen order. |
| `tokens.<id>.occurrences` | Total number of replaced spans. |
| `summary` | Domain to total occurrences, in first-seen domain order. |

Same serialization rules as section 3. The manifest never contains original values.

## 5. Tokens

A masked span is replaced by `[` + token id + `]`. A token id is

```
<ABBR> ":" <first 4 bytes of HMAC-SHA-256(key, UTF-8(matchedText)), as 8 lower-case hex digits>
```

| Entity type | ABBR | Entity type | ABBR | Entity type | ABBR |
|---|---|---|---|---|---|
| CryptoAddr | ADDR | PrivateKey | PRIVKEY | CreditCard | CC |
| TxHash | TX | Jwt | JWT | Ssn | SSN |
| ValidatorKey | VKEY | ConnectionString | CONNSTR | Iban | IBAN |
| EnsName | ENS | PasswordInContext | PASSWD | IpAddress | IP |
| SeedPhrase | SEED | Quantity | QTY | MacAddress | MAC |
| ApiKey | KEY | Amount | AMT | Email | EMAIL |
| AccessToken | TOKEN | Price | PRICE | PhoneNumber | PHONE |
| WebhookSecret | WHSEC | MarketPair | MKT | AssetName | ASSET |

The HMAC key depends on the command:

- `shroud vault`: 32 fresh random bytes per run, never stored. Tokens therefore
  correlate across files of one vault but not across vault runs, and never match
  `mask` tokens.
- `shroud mask`: the raw bytes of the key file (section 7), any length.

The matched text is UTF-8 encoded without normalization (a lone surrogate becomes
`EF BF BD`). The same value and type always give the same id under one key.

Collisions (observed): ids are 32-bit; if two different values of the same type
collide in one vault, the registry keeps the first value and silently counts the
second as another occurrence, so reveal restores the first value in both places.

## 6. Reveal

`shroud reveal <vaultDir>`:

1. Decrypt `<vaultDir>/vault.shroud` (section 2) and parse it (section 3).
2. Output directory: `-o` if given, else `<vaultDir>` with **every** `.shroud`
   substring replaced by `.revealed` (observed: a directory name without `.shroud`
   reveals into the vault directory itself).
3. For every `*.md` file under `<vaultDir>/public/` (recursive), read it as text and,
   for each `(id, value)` in `tokens` document order, replace every occurrence of
   `[id]` with `value` (ordinal, non-overlapping, left to right; a JSON `null` value
   replaces with the empty string). Replacements are sequential, so a value that
   itself contains `[other-id]` text is expanded by a later token.
4. Write each result to the same relative path under the output directory.

Round-trip guarantees and limits: the revealed bytes equal the original bytes when the
source was UTF-8 without a BOM. A source BOM is dropped, UTF-16/UTF-32 sources come back
as UTF-8, and invalid UTF-8 comes back as U+FFFD (all observed in both builds). Text in
the source that already looks like `[ID:xxxxxxxx]` for an id in the vault is replaced too.

## 7. Key file (`mask`)

`shroud mask` reads the HMAC key from `keyFile` in `shroud.json`, default
`.shroud/vault.key` relative to the working directory. When the file does not exist it
is created with 32 random bytes (creating the directory if needed) and a warning is
printed to stderr. The file is raw bytes; any length (including zero) is accepted.

## 8. `shroud.json`

```json
{
  "domains": {
    "onChain": { "enabled": true, "layer": "markets" },
    "financial": { "enabled": true, "layer": "markets" },
    "identity": { "enabled": true, "layer": "markets" },
    "credentials": { "enabled": true, "layer": "markets" },
    "secrets": { "enabled": true, "layer": "markets" }
  },
  "threshold": 0.7,
  "preset": "financial"
}
```

- Reading: camelCase names matched case-sensitively; unknown properties ignored; a
  missing property keeps the default of a freshly constructed object (all domains
  enabled, `layer` `"markets"`, `threshold` 0.70, no preset); a JSON `null` document
  gives those defaults; `enabled` must be a boolean and `threshold` a number (anything
  else aborts); `layer`, `keyFile`, `preset` and the domain objects may be `null`.
  Note that `{}` therefore means "markets at 0.70", while having no `shroud.json` at
  all means the paranoid preset (directional at 0.50).
- `layer` (financial only): `"magnitudes"` (amounts, prices, quantities),
  `"markets"` (adds market pairs and asset names) or `"directional"` (adds everything
  else in the financial domain, currently credit cards). Any other value, including
  null, behaves like `"magnitudes"`.
- Writing (`shroud init`): the section 3 serialization rules, property order
  `domains, threshold, keyFile, preset`, null properties omitted.

## 9. Verification

- `test/fixtures/dotnet-vectors.json` holds a vault, manifest, masked files, small
  blobs, token ids and `shroud.json` files produced by the C# build itself;
  `test/unit/dotnet-interop.test.ts` decrypts, re-serializes and re-derives them
  byte for byte.
- `tools/differential.mjs` diffs the TS and C# scanners match by match.
- The CLI cross-checks (C# vault revealed by TS and the reverse) are described in the
  port report.
