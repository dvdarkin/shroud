// ============================================================================
// PatternLibrary.OnChain.cs -- On-Chain Domain Patterns
// ============================================================================
//
// Covers: EVM addresses (full, truncated, corrupted, bracketed), Bitcoin
// (legacy, SegWit, Taproot), Bitcoin Cash, Litecoin, Solana, Cardano, Cosmos,
// Ripple/XRP, Tron, Dogecoin, Monero, Polkadot, Tezos, Avalanche, transaction
// hashes, ENS names, seed phrases, correlation identifiers (block numbers,
// validator indices, nonces, NFT IDs, LP positions, gas/gwei, slots, epochs,
// key=value log identifiers, Cardano pool IDs, Cosmos valoper), and block
// explorer URLs.
//
// Confidence calibration:
//   High (>= 0.90) -- Structurally unique patterns (EVM 0x+40hex, bc1q, ENS).
//   Medium (0.70)   -- Patterns that rarely false-positive but can overlap
//                       with non-crypto data (corrupted addresses).
//   Low   (<= 0.35) -- Ambiguous patterns requiring context words to promote
//                       (Solana base58, Polkadot SS58, bare hex64 tx hashes).
//
// To add a new pattern:
//   1. Pick the correct EntityType and SensitivityDomain.OnChain.
//   2. Choose a base confidence from the tiers above.
//   3. If the pattern is ambiguous, add context words and a context boost.
//   4. Give the pattern a unique Service string for diagnostics.
//   5. Add integration tests covering match and non-match cases.
// ============================================================================

using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

public static partial class PatternLibrary
{
    internal static IReadOnlyList<SensitivityPattern> GetOnChainPatterns() =>
    [
        // ================================================================
        // ON-CHAIN DOMAIN (atomic -- each match independently compromising)
        // ================================================================

        // --- EVM (Ethereum, Arbitrum, Optimism, Base, Polygon -- same format) ---
        // Full address: 0x + 40 hex
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"0x[a-fA-F0-9]{40}\b", Opts),
            0.95, [], 0, "evm_address"),
        // Truncated address: 0x1234abcd...5678ef90 or 0x1234...5678 or 0x0118…8110
        // Supports ... (three dots), .. (two dots), and … (unicode ellipsis U+2026)
        // Also tolerates OCR/copy-paste corruption (non-hex chars mixed in)
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"0x[a-fA-F0-9]{3,10}(?:\.{2,3}|\u2026)[a-fA-F0-9]{3,10}", Opts),
            0.90, [], 0, "evm_address_truncated"),
        // Corrupted addresses: 0x + hex-ish chars with occasional non-hex (OCR, copy errors)
        // e.g. 0x0549ddh7f61865fc...cb13e78360y0c0557y6
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"0x[a-zA-Z0-9]{8,}(?:\.{2,3}|\u2026)[a-zA-Z0-9]{8,}", Opts),
            0.70, [], 0, "evm_address_corrupted"),
        // Bracketed truncated: [0x0118…8110] or [0x1234...5678]
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\[0x[a-fA-F0-9]{3,10}(?:\.{2,3}|\u2026)[a-fA-F0-9]{3,10}\]", Opts),
            0.90, [], 0, "evm_address_bracketed"),

        // --- Bitcoin ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Opts),
            0.85, [], 0, "btc_legacy"),
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bbc1q[a-z0-9]{38,58}\b", Opts),
            0.90, [], 0, "btc_segwit"),
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bbc1p[a-z0-9]{58}\b", Opts),
            0.90, [], 0, "btc_taproot"),

        // --- Bitcoin Cash ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bbitcoincash:[qp][a-z0-9]{41}\b", Opts),
            0.90, [], 0, "bch_cashaddr"),

        // --- Litecoin ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b", Opts),
            0.80, ["litecoin", "ltc"], 0.10, "ltc_legacy"),
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bltc1[a-z0-9]{39,59}\b", Opts),
            0.90, [], 0, "ltc_segwit"),

        // --- Solana (no unique prefix, needs context) ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", Opts),
            0.30, ["solana", "sol", "phantom", "solscan", "raydium", "jupiter", "jup", "marinade", "orca", "program"], 0.55, "sol_address"),

        // --- Cardano ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\baddr1[a-z0-9]{58,100}\b", Opts),
            0.90, [], 0, "ada_shelley"),

        // --- Cosmos ecosystem (cosmos1, osmo1, etc.) ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b(?:cosmos|osmo|juno|atom|evmos|sei)1[a-z0-9]{38,58}\b", Opts),
            0.90, [], 0, "cosmos_bech32"),

        // --- Ripple/XRP ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", Opts),
            0.75, ["xrp", "ripple", "xrpl"], 0.15, "xrp_address"),

        // --- Tron ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", Opts),
            0.85, [], 0, "tron_address"),

        // --- Dogecoin ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\bD[5-9A-HJ-NP-Za-km-z][a-km-zA-HJ-NP-Z1-9]{32}\b", Opts),
            0.80, ["doge", "dogecoin"], 0.10, "doge_address"),

        // --- Monero ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", Opts),
            0.90, [], 0, "xmr_address"),

        // --- Polkadot/Substrate (starts with 1, needs context to distinguish from BTC) ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b1[a-km-zA-HJ-NP-Z1-9]{46,47}\b", Opts),
            0.30, ["polkadot", "dot", "substrate", "kusama", "parachain"], 0.55, "dot_ss58"),

        // --- Tezos ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\btz[1-3][1-9A-HJ-NP-Za-km-z]{33}\b", Opts),
            0.90, [], 0, "tez_address"),

        // --- Avalanche (C-chain uses EVM format, X/P-chain uses avax prefix) ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\b(?:X|P)-avax1[a-z0-9]{38,58}\b", Opts),
            0.90, [], 0, "avax_bech32"),

        // --- Transaction hashes ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"0x[a-fA-F0-9]{64}\b", Opts),
            0.95, [], 0, "evm_tx"),
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"\b[a-fA-F0-9]{64}\b", Opts),
            0.35, ["tx", "txid", "transaction", "hash", "confirmed", "mempool", "block"], 0.55, "hex64_tx"),

        // --- ENS names ---
        new(EntityType.EnsName, SensitivityDomain.OnChain,
            new Regex(@"\b[a-z0-9]([a-z0-9-]*[a-z0-9])?\.eth\b", Opts),
            0.90, [], 0, "ens"),

        // --- Seed phrases (placeholder -- real BIP-39 detection is separate) ---
        new(EntityType.SeedPhrase, SensitivityDomain.OnChain,
            new Regex(@"\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b", Opts),
            0.10, [], 0, "bip39"),

        // ================================================================
        // ON-CHAIN CORRELATION IDENTIFIERS
        // Secondary identifiers that people forget to redact. Equally
        // identifying as addresses when combined with minimal context.
        // All context-dependent (bare numbers are not sensitive alone).
        // ================================================================

        // --- Block numbers (narrows to ~12-second window on ETH) ---
        // Explicit: "block #12345678" or "block 12345678"
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\b(?:block|blk)\s*#?\s*(\d{6,9})\b", Opts),
            0.30, ["etherscan", "transaction", "tx", "confirmed", "mined"], 0.55, "block_number"),
        // Markdown links to explorer paths: [1326681](https://.../block/1326681)
        // Catches block, tx, token, address links where link text is a number or truncated hash
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"\[[^\]]*\]\([^\)]*?/(?:block|tx|transaction)/[^\)]+\)", Opts),
            0.90, [], 0, "explorer_link_block_tx"),
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"\[[^\]]*\]\([^\)]*?/(?:address|token|account|validator)/[^\)]+\)", Opts),
            0.90, [], 0, "explorer_link_addr_token"),

        // --- Validator indices (CRITICAL -- maps to deposit tx -> funding wallet) ---
        new(EntityType.ValidatorKey, SensitivityDomain.OnChain,
            new Regex(@"(?i)\bvalidator\s*#?\s*(\d{1,7})\b", Opts),
            0.85, [], 0, "eth_validator_index"),

        // --- Nonce values (sequential counter, narrows to specific account + tx) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\bnonce\s*:?\s*(\d{1,6})\b", Opts),
            0.30, ["transaction", "tx", "wallet", "account", "pending"], 0.55, "tx_nonce"),

        // --- NFT token IDs (unique pointer to wallet -- CRITICAL for PFP collections) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\b(?:token\s*(?:id|#)|nft\s*#)\s*:?\s*(\d{1,10})\b", Opts),
            0.80, [], 0, "nft_token_id"),

        // --- LP position IDs (Uniswap v3 -- each position is a unique NFT) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\bposition\s*#?\s*(\d{1,7})\b", Opts),
            0.30, ["uniswap", "uni", "lp", "liquidity", "pool", "v3", "concentrated"], 0.55, "lp_position_id"),

        // --- Gas/Gwei values (behavioral fingerprint for wallet software / MEV bots) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\b(\d{1,4}(?:\.\d{1,9})?)\s*[Gg]wei\b", Opts),
            0.30, ["gas", "fee", "priority", "tip", "base"], 0.50, "gas_gwei"),

        // --- Slot numbers (PoS -- reveals which validator proposed) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\bslot\s*#?\s*(\d{6,10})\b", Opts),
            0.30, ["beacon", "validator", "proposer", "attestation", "epoch"], 0.55, "beacon_slot"),

        // --- Epoch numbers (coarse window, dangerous for slashing events) ---
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)\bepoch\s*#?\s*(\d{2,7})\b", Opts),
            0.25, ["validator", "staking", "slashed", "reward", "beacon", "attestation"], 0.55, "beacon_epoch"),

        // --- Key=value crypto identifiers (log output, API responses, config) ---
        // The key name itself signals the value type, no context window needed
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)(?:payloadHash|txHash|transactionHash|blockHash|parentHash|stateRoot|receiptsRoot|builderPubKey|proposerPubKey|feeRecipient|withdrawalAddress|depositRoot|randaoReveal|graffiti|extraData|logsBloom|mixHash)\s*[=:]\s*0x[a-fA-F0-9]+", Opts),
            0.90, [], 0, "kv_hash"),
        new(EntityType.TxHash, SensitivityDomain.OnChain,
            new Regex(@"(?i)(?:slot|slotNumber|blockNumber|blockNum|blockHeight|nonce|epoch|validatorIndex|gasUsed|gasLimit|gasPrice|baseFee|priorityFee|blobGasUsed|excessBlobGas|timestamp|logIndex|txIndex|transactionIndex)\s*[=:]\s*\d+", Opts),
            0.85, [], 0, "kv_block_identifier"),

        // --- Cardano pool IDs ---
        new(EntityType.ValidatorKey, SensitivityDomain.OnChain,
            new Regex(@"\bpool1[a-z0-9]{50,56}\b", Opts),
            0.90, [], 0, "ada_pool_id"),

        // --- Cosmos validator operator addresses ---
        new(EntityType.ValidatorKey, SensitivityDomain.OnChain,
            new Regex(@"\b(?:cosmos|osmo)valoper1[a-z0-9]{38,58}\b", Opts),
            0.90, [], 0, "cosmos_valoper"),

        // --- Block explorer URLs (known explorers) ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"https?://(?:etherscan\.io|bscscan\.com|polygonscan\.com|arbiscan\.io|optimistic\.etherscan\.io|basescan\.org|solscan\.io|explorer\.solana\.com|cardanoscan\.io|tronscan\.org|starkscan\.co|voyager\.online|snowtrace\.io|celoscan\.io|ftmscan\.com|moonscan\.io|gnosisscan\.io|lineascan\.build|scrollscan\.com|nearblocks\.io|explorer\.near\.org|mintscan\.io|atomscan\.com|subscan\.io|blockscout\.com)/[^\s\)\]]+", Opts),
            0.90, [], 0, "block_explorer_url"),
        // --- Generic explorer URL pattern: any URL with /block/, /tx/, /address/, /token/ path ---
        new(EntityType.CryptoAddr, SensitivityDomain.OnChain,
            new Regex(@"https?://[^\s\)\]]+/(?:block|tx|transaction|address|token|validator|account)/[^\s\)\]]+", Opts),
            0.85, [], 0, "generic_explorer_url")
    ];
}
