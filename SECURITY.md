# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Shroud, please report it through [GitHub Security Advisories](https://github.com/dvdarkin/shroud/security/advisories/new). Do not open a public issue.

You should receive an initial response within 72 hours. Once confirmed, fixes will be prioritized and released as soon as practical.

## Scope

Shroud is a detection and masking tool — vulnerabilities in the encryption (AES-256-GCM, PBKDF2-SHA512), token generation (HMAC-SHA256), or pattern logic that could leak sensitive data are all in scope.

## Advisories

### 0.2.0 and earlier: text hidden from the scanner (fixed in 0.3.0)

Versions up to 0.2.0 skipped detection in places where they should not have, so sensitive values there were left unmasked:

- Everything between any two `---` lines was treated as YAML front matter, including text between two markdown horizontal rules.
- A line containing `file:`, `path:`, `source_file:` or `attachment:` inside a longer word (`profile:`, `classpath:`, `my-file:`) was skipped from that point to the end of the line.
- A line ending in one of those keys with nothing after it caused the whole next line to be skipped.
- In files with lone-CR line endings, such a key caused everything up to the next line feed to be skipped.

If you masked or vaulted files with 0.2.0 or earlier, run `shroud scan` on the sources again with 0.3.0 and re-create the masked copies. Vaults themselves are not affected: the encryption and the vault format are unchanged, and 0.3.0 reads vaults written by earlier versions.

Also fixed in 0.3.0: two different values that produced the same token id were stored as one, so `reveal` restored the first value in both places (the build now fails instead); and `manifest.json`, a public file, could contain the absolute local path of the source directory.
