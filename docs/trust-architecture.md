# Shroud Trust Architecture

**Date:** 2026-04-05
**Status:** Foundational design

---

## The Problem

Sensitive data has multiple consumers with different trust levels. A trading journal read by its author, by a local agent, by a cloud LLM, and by a backup service should expose different things to each. Today most tools treat access as binary: you can read it or you can't. Shroud introduces graduated trust.

## Trust Tiers

Three tiers, defined by what operations are permitted. The boundary between tiers is enforced by key access, not by configuration.

### Tier 0: Public (read-only, tokenized)

**Who:** Any agent, any tool, any sync service, any reader of vault files.

**Can do:**
- Read masked files (tokens visible, values hidden)
- Read `manifest.json`: which tokens exist, their type and domain, which files they appear in (no original values)
- Reason about entry structure ("this entry has 3 on-chain artifacts and 2 financial spans")
- Correlate tokens across entries ("ADDR:6335a1c0 appears in 5 entries")

**Cannot do:**
- See original values behind tokens
- Run `shroud scan` on the originals: its report prints the matched values, so it belongs to whoever may read the source files
- Unmask anything

**Trust assumption:** Zero. This tier assumes the reader may be compromised, monitored, or cloud-hosted. The masked file is designed to be safe for this audience. A blockchain analyst who reads a Tier 0 file learns nothing.

**Implementation:** Masked markdown files on disk. No special tooling needed -- any file reader sees the tokenized version. This is the default state of all vault content after masking.

### Tier 1: Operator (can mask, cannot unmask)

**Who:** Trusted local tooling, CI pipelines, LogMark's VaultWriter, automation scripts.

**Can do:**
- Everything in Tier 0
- Run `shroud mask` to tokenize sensitive spans in files
- Run `shroud init` to create/modify configuration
- Access detection patterns and confidence scores
- Batch-process files

**Cannot do:**
- Unmask tokens (resolve back to original values)
- Learn anything from the masking key that the source files do not already show (the key derives token ids; it decrypts nothing)

**Trust assumption:** The operator is running locally and is not adversarial, but may be compromised via supply chain, plugin injection, or prompt injection. Allowing masking is safe because masking is a one-way operation that increases safety. An operator that masks your files is helping you. An operator that unmasks is a risk.

**Implementation:** `shroud mask` reads a key file (`.shroud/vault.key` by default, an ordinary file readable by whoever runs the command) and uses it as the HMAC key for token ids. `mask` stores no mapping from token to value: its output cannot be reversed by anyone, with or without the key. `shroud vault` is the operation that keeps the originals, encrypted under the owner's password, and it uses a fresh random masking key on every run.

**Why masking uses a key:** Deterministic tokens (same value = same token) need a keyed hash. With an unkeyed hash, anyone could confirm a guessed value by hashing it. The key therefore protects token ids against guessing; it is not an unmasking key. An operator necessarily sees the values it masks, so Tier 1 is about what the operator can do to already-masked data (nothing), not about hiding the source from it.

### Tier 2: Owner (full access)

**Who:** The human who holds the key/password.

**Can do:**
- Everything in Tier 0 and Tier 1
- Run `shroud reveal` to resolve tokens back to original values
- Change the password (reveal, then vault again with a new one)
- Decide which tools get the masked copies and which get the source

**Cannot do:** Nothing restricted.

**Trust assumption:** This is you. You know the vault password.

**Implementation:** `shroud reveal` needs the vault password. `vault.shroud` is AES-256-GCM encrypted under a key derived from it with PBKDF2-SHA512 (600,000 iterations); there is no other way in, and no recovery if the password is lost. LogMark, which embeds this library, manages keys its own way (DPAPI in its standard mode, Argon2id in its paranoid mode); that is LogMark's design and not part of standalone Shroud.

## The Trust Boundary

```
                    MASKING BOUNDARY
                         |
    Tier 0 (Public)      |     Tier 1 (Operator)         Tier 2 (Owner)
                         |                                     |
    Read masked files    |     Detect + tokenize              |  Reveal original values
    Correlate tokens     |     Config management              |  Password change
    Read manifest.json   |     Batch processing               |
                         |                                     |
                         |              REVEAL BOUNDARY -------+
                         |
```

The critical insight: **the trust boundary sits between mask and reveal, not between read and write.** Masking is a safety-increasing operation. Revealing is a safety-decreasing operation. The permission model follows the direction of risk.

## Agent Integration

Agents are Tier 0 consumers by default. They read masked files and receive structured metadata about what was detected, without seeing the values.

### The manifest, for agents

`shroud vault` writes `manifest.json` next to the masked copies:

```json
{
  "source": "journal",
  "fileCount": 6,
  "tokenCount": 2,
  "tokens": {
    "ADDR:6335a1c0": {
      "service": "evm_address",
      "domain": "onchain",
      "files": ["trades.md", "notes.md"],
      "occurrences": 12
    },
    "QTY:3ba80f2e": {
      "service": "verb_quantity",
      "domain": "financial",
      "files": ["trades.md"],
      "occurrences": 1
    }
  },
  "summary": { "onchain": 12, "financial": 1 }
}
```

An agent reading this, together with the masked files, knows that one EVM address recurs across two files and that a quantity sits next to it in `trades.md`: probably a transaction record. It can reason about the sensitivity profile, suggest route changes, flag unusual patterns, all without seeing a single real value. [format.md](format.md) section 4 specifies the file.

Token ids are stable within one vault run. A new `shroud vault` run uses a new masking key, so ids change between runs; correlation over time needs the same vault output, not a re-vault.

### What Agents Can Reason About (Tier 0)

- **Token correlation:** "ADDR:6335a1c0 appears in 12 entries across 3 months -- this is a frequently used address"
- **Domain distribution:** "This route is 80% on-chain artifacts -- suggest escalating to sealed"
- **Anomaly detection:** "This entry in +work has financial tokens -- unusual for a work route"
- **Temporal patterns:** "Financial activity clusters on Mondays and Fridays"

### What Agents Cannot Do

- Reconstruct the original address from ADDR:6335a1c0
- Determine the magnitude of QTY:3ba80f2e
- Distinguish between a $500 and $500,000 position
- Link an on-chain token to a real blockchain address

## Composition with LogMark

Shroud is the engine. LogMark adds the car:

| Layer | Shroud (standalone) | LogMark (integrated) |
|-------|-------------------|---------------------|
| Detection | PatternLibrary, ContextScorer | Same engine via library reference |
| Masking | CLI `mask` command | VaultWriter automatic integration |
| Configuration | shroud.json | Route-level sensitivity cascade + config.md |
| Key management | Vault password (PBKDF2-SHA512); a key file only for `mask` token ids | DPAPI (standard) or Argon2id (paranoid) |
| Reveal | CLI `reveal` command | `/fill` command with layered domain control |
| Agent access | Masked copies and `manifest.json` (no secret values) | MCP tools with Tier 0 enforcement |
| Trust UI | N/A | Setup wizard, smart detection prompts, feed suggestions |

LogMark can reference Shroud as:
1. **A prebuilt `Shroud.dll`** shipped with LogMark (what LogMark does today)
2. **A user-built `Shroud.dll`** dropped in place of the shipped one, for users who compile from source for maximum trust
3. **NuGet package** `LogMark.Shroud` (versioned; the bare `Shroud` ID on NuGet belongs to an unrelated project)

Option 2 is the trust play. A user who doesn't trust precompiled binaries can clone Shroud, audit the code, build it, and replace LogMark's copy with their local build. The zero-dependency design makes this audit tractable -- there's nothing hidden behind abstractions or transitive dependencies.

## Design Principles

1. **Masking increases safety. Revealing decreases safety.** Permission boundaries follow this.

2. **Tier 0 is the default.** Everything starts masked. Revealing is opt-in, gated, and auditable.

3. **Agents are Tier 0.** An agent that reads your vault through MCP sees tokens, not values. This is structural, not configurable -- there's no setting to "let the agent see everything."

4. **Key possession defines trust.** Not configuration, not permissions, not role assignments. If you have the key, you're Tier 2. If you don't, you can't reveal. This is cryptographic enforcement, not policy enforcement.

5. **Zero trust in the library itself.** Shroud has zero external dependencies. Every line of code is auditable. No network calls, no telemetry, no logging of sensitive values, no ambient authority. The library is a pure function: text in, safe text out.

6. **Trust is earned through transparency.** Open source, two independent implementations checked against one corpus, minimal surface area. The README leads with "audit this" not "trust us."

## Implementations

The tiers above are a property of the file format and the keys, not of one program. Shroud has two implementations, C# and TypeScript, that produce and accept the same files: a vault masked by one is revealed by the other, with the same password. They are held together by the conformance corpus in `conformance/` and the format specification in [format.md](format.md).

Auditing the trust boundary therefore means reading either implementation, or neither: the specification states what a vault contains and how the keys are derived, and the corpus contains vaults with their passwords that any third implementation can test itself against.

---

**Version:** 1.1
