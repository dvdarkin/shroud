# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Shroud, please report it through [GitHub Security Advisories](https://github.com/dvdarkin/shroud/security/advisories/new). Do not open a public issue.

You should receive an initial response within 72 hours. Once confirmed, fixes will be prioritized and released as soon as practical.

## Scope

Shroud is a detection and masking tool — vulnerabilities in the encryption (AES-256-GCM, PBKDF2-SHA512), token generation (HMAC-SHA256), or pattern logic that could leak sensitive data are all in scope.

## Advisories

### 0.3.0 and earlier: plaintext written into the vault or source directory (fixed in 0.4.0)

Three command-line cases put files where they did not belong. Detection and the vault format were not affected.

- `reveal` built its default output by replacing every `.shroud` in the vault path. For a vault directory without that suffix (`shroud vault notes -o out`, then `shroud reveal out`) the revealed plaintext was written inside the vault directory, next to `public/`, where anything that syncs or shares the vault would pick it up.
- `shroud vault .` wrote its output to `./..shroud`, inside the source directory.
- `shroud vault X/public -o X` overwrote the source files with their masked copies.

If you used `reveal` on a vault directory not named `*.shroud`, look in that directory for anything besides `manifest.json`, `public/` and `vault.shroud`, delete it, and check whether it was synced, committed or backed up. 0.4.0 writes revealed files to `<name>.revealed` beside the vault, refuses an output inside the vault or source, and refuses a source inside the output.

### 0.2.0 and earlier: text hidden from the scanner (fixed in 0.3.0)

Versions up to 0.2.0 skipped detection in places where they should not have, so sensitive values there were left unmasked:

- Everything between any two `---` lines was treated as YAML front matter, including text between two markdown horizontal rules.
- A line containing `file:`, `path:`, `source_file:` or `attachment:` inside a longer word (`profile:`, `classpath:`, `my-file:`) was skipped from that point to the end of the line.
- A line ending in one of those keys with nothing after it caused the whole next line to be skipped.
- In files with lone-CR line endings, such a key caused everything up to the next line feed to be skipped.

If you masked or vaulted files with 0.2.0 or earlier, run `shroud scan` on the sources again with 0.3.0 and re-create the masked copies. Vaults themselves are not affected: the encryption and the vault format are unchanged, and 0.3.0 reads vaults written by earlier versions.

Also fixed in 0.3.0: two different values that produced the same token id were stored as one, so `reveal` restored the first value in both places (the build now fails instead); and `manifest.json`, a public file, could contain the absolute local path of the source directory.
