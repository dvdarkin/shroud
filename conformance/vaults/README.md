# Vault interop fixtures

Five vaults written by the C# `VaultBuilder` (`Build` + `WriteOutput`) from the small source directories in each
`<name>/input/`. They test "C# wrote it, another implementation must read it". Format description:
`../README.md`, section "Vault container format".

Layout of each `<name>/`:

```
input/                       source markdown files (what was vaulted)
vault/vault.shroud           encrypted registry (salt16 | nonce12 | tag16 | ciphertext)
vault/manifest.json          public metadata
vault/public/                masked copies
vault-data.decrypted.json    the plaintext inside vault.shroud, verbatim (UTF-8; CRLF indentation, written on Windows)
restored/                    expected plaintext after "reveal" (what the CLI reveal algorithm yields; equals input/)
meta.json                    passphrase (also as UTF-8 hex), config, file list, token count
```

| Vault | Passphrase | Config | Tokens | Notes |
|---|---|---|---|---|
| `v1-basic-mixed-nested` | `correct horse battery staple (test only)` | `default` (paranoid) | 13 | 5 files incl. nested `notes/deep/`, a clean file, one address repeated across files (occurrences 3) |
| `v2-unicode-passphrase-crlf` | `pässwörd-тест-密码-😀` (UTF-8 hex `70c3a4737377c3b672642dd182d0b5d181d1822de5af86e7a0812df09f9880`, precomposed ä/ö) | `default` | 6 | CRLF file, CJK, Cyrillic, emoji, file without trailing newline |
| `v3-dev-preset-credentials` | `simple-test-passphrase-3` | `dev` | 7 | credentials, secrets, identity; financial amounts deliberately left visible; nested `sub/` |
| `v4-clean-only-no-tokens` | `empty-vault-passphrase` | `default` | 0 | nothing detected: `vault.shroud` holds an encrypted registry with an empty token map (the CLI would refuse to write this; the library does) |
| `v5-large-many-tokens` | `large-vault-passphrase-5` | `financial` | 1600 | one 400-line file, 4 unique tokens per line, ~73 KB vault |

Passphrases are used as UTF-8 bytes exactly as written, with no normalisation and no trailing newline.

## What a reader must do

1. Read `vault/vault.shroud`, decrypt with the passphrase (PBKDF2-HMAC-SHA512, 600000 iterations, AES-256-GCM), parse the JSON.
2. Compare the decrypted text with `vault-data.decrypted.json` (identical bytes), or at least its parsed `tokens` and
   `fileHashes` (`created` is a timestamp).
3. For every file in `vault/public/` replace each `[<tokenId>]` by the matching original value and compare with
   `restored/<same relative path>` (byte-equal; `restored/` equals `input/`).
4. Optionally check `fileHashes`: `sha256:` + hex of the UTF-8 bytes of the masked file content.
5. A wrong passphrase must be rejected.

## Things that differ per generation or per platform

- Salt, nonce, the masking key (hence every token id) and `created` are random or time-based: regenerating with
  `dotnet run --project conformance/Generator -- --vaults` produces a different, equally valid set.
- Relative paths inside `manifest.json` (`files`) and inside the decrypted JSON (`fileHashes` keys) use the OS
  separator of the generating machine. These fixtures were generated on Windows, so nested files appear as
  `notes\\deep\\keys.md` in JSON (a single backslash in the decoded string). `public/` and `restored/` on disk use
  ordinary directories.
- `manifest.json` `source` is `input` (the generator passes a relative path; the CLI would store whatever path the
  user typed).
- The C# key order inside `tokens` / `fileHashes` follows culture-sensitive file ordering and token creation order;
  readers must not depend on it.
- Each token id embeds the masking key, so a different implementation cannot reproduce these ids; it can only
  verify restore.
