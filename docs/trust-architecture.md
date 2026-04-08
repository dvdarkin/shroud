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
- Run `shroud scan` to get a detection report (span positions, types, confidence -- no original values)
- Reason about entry structure ("this entry has 3 on-chain artifacts and 2 financial spans")
- Correlate tokens across entries ("ADDR:6335 appears in 5 entries")

**Cannot do:**
- See original values behind tokens
- Access the key file
- Run mask or unmask operations

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
- Read the key file contents
- Export or transmit the key

**Trust assumption:** The operator is running locally and is not adversarial, but may be compromised via supply chain, plugin injection, or prompt injection. Allowing masking is safe because masking is a one-way operation that increases safety. An operator that masks your files is helping you. An operator that unmasks is a risk.

**Implementation:** The `shroud mask` command uses the key file to generate deterministic HMAC tokens but does not expose the key or original values to the caller. The key is read, used, and discarded within the process. The operator sees the token IDs, never the mapped values.

**Why masking requires the key:** Deterministic tokens (same value = same token) require HMAC with a secret. Without the key, masking would produce random tokens that can't correlate across entries. The key is used for tokenization but doesn't grant unmask access -- unmasking requires a separate resolution step.

### Tier 2: Owner (full access)

**Who:** The human who holds the key/password.

**Can do:**
- Everything in Tier 0 and Tier 1
- Run `shroud reveal` to resolve tokens back to original values
- Rotate keys
- Export/backup the key
- Configure trust settings
- Grant Tier 1 access to specific tools

**Cannot do:** Nothing restricted.

**Trust assumption:** This is you. You have the key because you generated it or received it at setup. In standard mode, your OS session is the trust boundary. In paranoid mode, your memory is.

**Implementation:** The `reveal` command requires either:
- Standard mode: DPAPI-unwrapped key + password gate
- Paranoid mode: User-provided secret (Argon2id key derivation)
- Standalone Shroud: Direct key file access

## The Trust Boundary

```
                    MASKING BOUNDARY
                         |
    Tier 0 (Public)      |     Tier 1 (Operator)         Tier 2 (Owner)
                         |                                     |
    Read masked files    |     Detect + tokenize              |  Reveal original values
    Correlate tokens     |     Config management              |  Key rotation
    Scan (report only)   |     Batch processing               |  Key export/backup
                         |                                     |
                         |              REVEAL BOUNDARY -------+
                         |
```

The critical insight: **the trust boundary sits between mask and reveal, not between read and write.** Masking is a safety-increasing operation. Revealing is a safety-decreasing operation. The permission model follows the direction of risk.

## Agent Integration

Agents are Tier 0 consumers by default. They read masked files and receive structured metadata about what was detected, without seeing the values.

### Scan Output for Agents

```
shroud scan journal.md --json
```

```json
{
  "file": "journal.md",
  "summary": {
    "onchain": 3,
    "financial": 5,
    "identity": 0
  },
  "spans": [
    {
      "token": "ADDR:6335",
      "type": "CryptoAddrEth",
      "domain": "onchain",
      "line": 3,
      "confidence": 0.95
    },
    {
      "token": "QTY:3ba8",
      "type": "Quantity",
      "domain": "financial",
      "line": 3,
      "confidence": 0.75
    }
  ]
}
```

An agent reading this knows: "line 3 has an ETH address and a quantity next to each other -- this is probably a transaction record." It can reason about the entry's sensitivity profile, suggest route changes, flag unusual patterns -- all without seeing a single real value.

### What Agents Can Reason About (Tier 0)

- **Token correlation:** "ADDR:6335 appears in 12 entries across 3 months -- this is a frequently used address"
- **Domain distribution:** "This route is 80% on-chain artifacts -- suggest escalating to sealed"
- **Anomaly detection:** "This entry in +work has financial tokens -- unusual for a work route"
- **Temporal patterns:** "Financial activity clusters on Mondays and Fridays"

### What Agents Cannot Do

- Reconstruct the original address from ADDR:6335
- Determine the magnitude of QTY:3ba8
- Distinguish between a $500 and $500,000 position
- Link an on-chain token to a real blockchain address

## Composition with LogMark

Shroud is the engine. LogMark adds the car:

| Layer | Shroud (standalone) | LogMark (integrated) |
|-------|-------------------|---------------------|
| Detection | PatternLibrary, ContextScorer | Same engine via library reference |
| Masking | CLI `mask` command | VaultWriter automatic integration |
| Configuration | shroud.json | Route-level sensitivity cascade + config.md |
| Key management | Key file on disk | DPAPI (standard) or Argon2id (paranoid) |
| Reveal | CLI `reveal` command | `/fill` command with layered domain control |
| Agent access | `--json` output | MCP tools with Tier 0 enforcement |
| Trust UI | N/A | Setup wizard, smart detection prompts, feed suggestions |

LogMark can reference Shroud as:
1. **NuGet package** (standard distribution, versioned, signed)
2. **Local project reference** (for users who compile from source for maximum trust)

Option 2 is the trust play. A user who doesn't trust precompiled binaries can clone Shroud, audit the code, build it, and point LogMark at their local build. The zero-dependency design makes this audit tractable -- there's nothing hidden behind abstractions or transitive dependencies.

## Design Principles

1. **Masking increases safety. Revealing decreases safety.** Permission boundaries follow this.

2. **Tier 0 is the default.** Everything starts masked. Revealing is opt-in, gated, and auditable.

3. **Agents are Tier 0.** An agent that reads your vault through MCP sees tokens, not values. This is structural, not configurable -- there's no setting to "let the agent see everything."

4. **Key possession defines trust.** Not configuration, not permissions, not role assignments. If you have the key, you're Tier 2. If you don't, you can't reveal. This is cryptographic enforcement, not policy enforcement.

5. **Zero trust in the library itself.** Shroud has zero external dependencies. Every line of code is auditable. No network calls, no telemetry, no logging of sensitive values, no ambient authority. The library is a pure function: text in, safe text out.

6. **Trust is earned through transparency.** Open source, reproducible builds, minimal surface area. The README leads with "audit this" not "trust us."

---

**Version:** 1.0
