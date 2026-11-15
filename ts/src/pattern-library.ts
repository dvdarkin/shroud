/**
 * Central registry of all sensitivity patterns.
 *
 * Every pattern source below is the verbatim .NET pattern from the C# build (C#
 * verbatim-string `""` written as `"`), compiled with `dotnetRegex`, which translates
 * it into a JS RegExp with .NET 8 matching semantics. Keeping the sources identical
 * makes the two builds diffable line by line; do not "simplify" a pattern into JS
 * syntax here.
 *
 * Order matters: the scanner evaluates patterns in this order and the order feeds
 * diagnostics output. It is OnChain, Credentials, Secrets, Financial, Identity, the
 * same as PatternLibrary.GetAll() in C#.
 */
import type { ShroudConfig } from './config.js';
import { dotnetRegex } from './internal/dotnet-regex.js';
import type { EntityType, SensitivityDomain, SensitivityPattern } from './models.js';

// Confidence tier constants - use these when adding new patterns.
export const HIGH_CONFIDENCE = 0.9;
export const MEDIUM_CONFIDENCE = 0.7;
export const LOW_CONFIDENCE = 0.35;

function pattern(
  entityType: EntityType,
  domain: SensitivityDomain,
  source: string,
  baseConfidence: number,
  contextWords: readonly string[],
  contextBoost: number,
  service: string,
  options: { ignoreCase?: boolean } = {},
): SensitivityPattern {
  return {
    entityType,
    domain,
    regex: dotnetRegex(source, options),
    baseConfidence,
    contextWords,
    contextBoost,
    service,
  };
}

const raw = String.raw;

// ---------------------------------------------------------------------------
// Context arrays shared across domains (primarily Financial)
// ---------------------------------------------------------------------------

const KNOWN_ASSET_LIST = [
  'BTC', 'ETH', 'SOL', 'AVAX', 'MATIC', 'DOT', 'ADA', 'LINK',
  'UNI', 'AAVE', 'CRV', 'MKR', 'SNX', 'COMP', 'SUSHI', 'YFI',
  'DOGE', 'SHIB', 'PEPE', 'WIF', 'BONK',
  'BNB', 'XRP', 'LTC', 'ATOM', 'NEAR', 'APT', 'SUI', 'ARB', 'OP',
  'FTM', 'INJ', 'TIA', 'JUP', 'RNDR', 'FET', 'TAO',
  'USDT', 'USDC', 'DAI', 'FRAX',
  'WETH', 'WBTC', 'stETH', 'rETH', 'cbETH',
  'Bitcoin', 'Ethereum', 'Solana',
  // DeFi protocols and bridges (context boosters)
  'Uniswap', 'Aave', 'Compound', 'Curve', 'Lido', 'Convex',
  'Starkgate', 'Starknet', 'zkSync', 'Orbiter', 'Hop',
  'LayerZero', 'Wormhole', 'Across', 'Stargate',
  'Raydium', 'Orca', 'Marinade', 'Jupiter',
  'Osmosis', 'Astroport',
];

const asciiFold = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/**
 * Known asset and protocol names, deduplicated case-insensitively in insertion order
 * (the C# HashSet uses StringComparer.OrdinalIgnoreCase, so "Aave" collapses into
 * "AAVE").
 */
export const KNOWN_ASSETS: readonly string[] = KNOWN_ASSET_LIST.filter(
  (name, i) => KNOWN_ASSET_LIST.findIndex((other) => asciiFold(other) === asciiFold(name)) === i,
);

const KNOWN_ASSET_KEYS = new Set(KNOWN_ASSETS.map(asciiFold));

/** Case-insensitive (ordinal) membership test for KNOWN_ASSETS. */
export function isKnownAsset(name: string): boolean {
  return KNOWN_ASSET_KEYS.has(asciiFold(name));
}

export const TRADING_CONTEXT: readonly string[] = [
  'bought', 'sold', 'buy', 'sell', 'long', 'short',
  'position', 'portfolio', 'balance', 'worth', 'allocated',
  'staked', 'swapped', 'transferred', 'deposited', 'withdrew',
  'liquidated', 'margin', 'leverage', 'PnL', 'profit', 'loss',
  'bridge', 'bridged', 'minted', 'burned', 'claimed', 'harvested',
  'airdrop', 'vesting', 'locked', 'unlocked', 'pending',
];

export const PRICE_CONTEXT: readonly string[] = [
  'at', 'for', 'price', 'cost', 'entry', 'exit',
  'filled', 'limit', 'market', 'bid', 'ask', 'spot',
];

export const AMOUNT_CONTEXT: readonly string[] = [
  'bought', 'sold', 'position', 'portfolio', 'balance',
  'worth', 'allocated', 'total', 'value', 'holding',
];

// ---------------------------------------------------------------------------
// ON-CHAIN DOMAIN (atomic - each match independently compromising)
// ---------------------------------------------------------------------------

export function getOnChainPatterns(): SensitivityPattern[] {
  return [
    // --- EVM (Ethereum, Arbitrum, Optimism, Base, Polygon - same format) ---
    pattern('CryptoAddr', 'OnChain', raw`0x[a-fA-F0-9]{40}\b`, 0.95, [], 0, 'evm_address'),
    // Truncated address: 0x1234abcd...5678ef90, 0x1234...5678, 0x0118…8110
    pattern('CryptoAddr', 'OnChain', raw`0x[a-fA-F0-9]{3,10}(?:\.{2,3}|\u2026)[a-fA-F0-9]{3,10}`, 0.9, [], 0, 'evm_address_truncated'),
    // Corrupted addresses (OCR, copy errors)
    pattern('CryptoAddr', 'OnChain', raw`0x[a-zA-Z0-9]{8,}(?:\.{2,3}|\u2026)[a-zA-Z0-9]{8,}`, 0.7, [], 0, 'evm_address_corrupted'),
    // Bracketed truncated: [0x0118…8110]
    pattern('CryptoAddr', 'OnChain', raw`\[0x[a-fA-F0-9]{3,10}(?:\.{2,3}|\u2026)[a-fA-F0-9]{3,10}\]`, 0.9, [], 0, 'evm_address_bracketed'),

    // --- Bitcoin ---
    pattern('CryptoAddr', 'OnChain', raw`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`, 0.85, [], 0, 'btc_legacy'),
    pattern('CryptoAddr', 'OnChain', raw`\bbc1q[a-z0-9]{38,58}\b`, 0.9, [], 0, 'btc_segwit'),
    pattern('CryptoAddr', 'OnChain', raw`\bbc1p[a-z0-9]{58}\b`, 0.9, [], 0, 'btc_taproot'),

    // --- Bitcoin Cash ---
    pattern('CryptoAddr', 'OnChain', raw`\bbitcoincash:[qp][a-z0-9]{41}\b`, 0.9, [], 0, 'bch_cashaddr'),

    // --- Litecoin ---
    pattern('CryptoAddr', 'OnChain', raw`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`, 0.8, ['litecoin', 'ltc'], 0.1, 'ltc_legacy'),
    pattern('CryptoAddr', 'OnChain', raw`\bltc1[a-z0-9]{39,59}\b`, 0.9, [], 0, 'ltc_segwit'),

    // --- Solana (no unique prefix, needs context) ---
    pattern('CryptoAddr', 'OnChain', raw`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`, 0.3,
      ['solana', 'sol', 'phantom', 'solscan', 'raydium', 'jupiter', 'jup', 'marinade', 'orca', 'program'], 0.55, 'sol_address'),

    // --- Cardano ---
    pattern('CryptoAddr', 'OnChain', raw`\baddr1[a-z0-9]{58,100}\b`, 0.9, [], 0, 'ada_shelley'),

    // --- Cosmos ecosystem ---
    pattern('CryptoAddr', 'OnChain', raw`\b(?:cosmos|osmo|juno|atom|evmos|sei)1[a-z0-9]{38,58}\b`, 0.9, [], 0, 'cosmos_bech32'),

    // --- Ripple/XRP ---
    pattern('CryptoAddr', 'OnChain', raw`\br[1-9A-HJ-NP-Za-km-z]{24,34}\b`, 0.75, ['xrp', 'ripple', 'xrpl'], 0.15, 'xrp_address'),

    // --- Tron ---
    pattern('CryptoAddr', 'OnChain', raw`\bT[1-9A-HJ-NP-Za-km-z]{33}\b`, 0.85, [], 0, 'tron_address'),

    // --- Dogecoin ---
    pattern('CryptoAddr', 'OnChain', raw`\bD[5-9A-HJ-NP-Za-km-z][a-km-zA-HJ-NP-Z1-9]{32}\b`, 0.8, ['doge', 'dogecoin'], 0.1, 'doge_address'),

    // --- Monero ---
    pattern('CryptoAddr', 'OnChain', raw`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`, 0.9, [], 0, 'xmr_address'),

    // --- Polkadot/Substrate (starts with 1, needs context to distinguish from BTC) ---
    pattern('CryptoAddr', 'OnChain', raw`\b1[a-km-zA-HJ-NP-Z1-9]{46,47}\b`, 0.3, ['polkadot', 'dot', 'substrate', 'kusama', 'parachain'], 0.55, 'dot_ss58'),

    // --- Tezos ---
    pattern('CryptoAddr', 'OnChain', raw`\btz[1-3][1-9A-HJ-NP-Za-km-z]{33}\b`, 0.9, [], 0, 'tez_address'),

    // --- Avalanche (X/P-chain) ---
    pattern('CryptoAddr', 'OnChain', raw`\b(?:X|P)-avax1[a-z0-9]{38,58}\b`, 0.9, [], 0, 'avax_bech32'),

    // --- Transaction hashes ---
    pattern('TxHash', 'OnChain', raw`0x[a-fA-F0-9]{64}\b`, 0.95, [], 0, 'evm_tx'),
    pattern('TxHash', 'OnChain', raw`\b[a-fA-F0-9]{64}\b`, 0.35, ['tx', 'txid', 'transaction', 'hash', 'confirmed', 'mempool', 'block'], 0.55, 'hex64_tx'),

    // --- ENS names ---
    pattern('EnsName', 'OnChain', raw`\b[a-z0-9]([a-z0-9-]*[a-z0-9])?\.eth\b`, 0.9, [], 0, 'ens'),

    // --- Seed phrases (placeholder - real BIP-39 detection is separate) ---
    pattern('SeedPhrase', 'OnChain', raw`\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b`, 0.1, [], 0, 'bip39'),

    // ---- On-chain correlation identifiers ----

    // Block numbers: "block #12345678" or "block 12345678"
    pattern('TxHash', 'OnChain', raw`(?i)\b(?:block|blk)\s*#?\s*(\d{6,9})\b`, 0.3, ['etherscan', 'transaction', 'tx', 'confirmed', 'mined'], 0.55, 'block_number'),
    // Markdown links to explorer paths: [1326681](https://.../block/1326681)
    pattern('TxHash', 'OnChain', raw`\[[^\]]*\]\([^\)]*?/(?:block|tx|transaction)/[^\)]+\)`, 0.9, [], 0, 'explorer_link_block_tx'),
    pattern('CryptoAddr', 'OnChain', raw`\[[^\]]*\]\([^\)]*?/(?:address|token|account|validator)/[^\)]+\)`, 0.9, [], 0, 'explorer_link_addr_token'),

    // Validator indices (maps to deposit tx -> funding wallet)
    pattern('ValidatorKey', 'OnChain', raw`(?i)\bvalidator\s*#?\s*(\d{1,7})\b`, 0.85, [], 0, 'eth_validator_index'),

    // Nonce values
    pattern('TxHash', 'OnChain', raw`(?i)\bnonce\s*:?\s*(\d{1,6})\b`, 0.3, ['transaction', 'tx', 'wallet', 'account', 'pending'], 0.55, 'tx_nonce'),

    // NFT token IDs
    pattern('TxHash', 'OnChain', raw`(?i)\b(?:token\s*(?:id|#)|nft\s*#)\s*:?\s*(\d{1,10})\b`, 0.8, [], 0, 'nft_token_id'),

    // LP position IDs (Uniswap v3)
    pattern('TxHash', 'OnChain', raw`(?i)\bposition\s*#?\s*(\d{1,7})\b`, 0.3, ['uniswap', 'uni', 'lp', 'liquidity', 'pool', 'v3', 'concentrated'], 0.55, 'lp_position_id'),

    // Gas/Gwei values
    pattern('TxHash', 'OnChain', raw`(?i)\b(\d{1,4}(?:\.\d{1,9})?)\s*[Gg]wei\b`, 0.3, ['gas', 'fee', 'priority', 'tip', 'base'], 0.5, 'gas_gwei'),

    // Slot numbers (PoS)
    pattern('TxHash', 'OnChain', raw`(?i)\bslot\s*#?\s*(\d{6,10})\b`, 0.3, ['beacon', 'validator', 'proposer', 'attestation', 'epoch'], 0.55, 'beacon_slot'),

    // Epoch numbers
    pattern('TxHash', 'OnChain', raw`(?i)\bepoch\s*#?\s*(\d{2,7})\b`, 0.25, ['validator', 'staking', 'slashed', 'reward', 'beacon', 'attestation'], 0.55, 'beacon_epoch'),

    // Key=value crypto identifiers (log output, API responses, config)
    pattern('TxHash', 'OnChain',
      raw`(?i)(?:payloadHash|txHash|transactionHash|blockHash|parentHash|stateRoot|receiptsRoot|builderPubKey|proposerPubKey|feeRecipient|withdrawalAddress|depositRoot|randaoReveal|graffiti|extraData|logsBloom|mixHash)\s*[=:]\s*0x[a-fA-F0-9]+`,
      0.9, [], 0, 'kv_hash'),
    pattern('TxHash', 'OnChain',
      raw`(?i)(?:slot|slotNumber|blockNumber|blockNum|blockHeight|nonce|epoch|validatorIndex|gasUsed|gasLimit|gasPrice|baseFee|priorityFee|blobGasUsed|excessBlobGas|timestamp|logIndex|txIndex|transactionIndex)\s*[=:]\s*\d+`,
      0.85, [], 0, 'kv_block_identifier'),

    // Cardano pool IDs
    pattern('ValidatorKey', 'OnChain', raw`\bpool1[a-z0-9]{50,56}\b`, 0.9, [], 0, 'ada_pool_id'),

    // Cosmos validator operator addresses
    pattern('ValidatorKey', 'OnChain', raw`\b(?:cosmos|osmo)valoper1[a-z0-9]{38,58}\b`, 0.9, [], 0, 'cosmos_valoper'),

    // Block explorer URLs (known explorers)
    pattern('CryptoAddr', 'OnChain',
      raw`https?://(?:etherscan\.io|bscscan\.com|polygonscan\.com|arbiscan\.io|optimistic\.etherscan\.io|basescan\.org|solscan\.io|explorer\.solana\.com|cardanoscan\.io|tronscan\.org|starkscan\.co|voyager\.online|snowtrace\.io|celoscan\.io|ftmscan\.com|moonscan\.io|gnosisscan\.io|lineascan\.build|scrollscan\.com|nearblocks\.io|explorer\.near\.org|mintscan\.io|atomscan\.com|subscan\.io|blockscout\.com)/[^\s\)\]]+`,
      0.9, [], 0, 'block_explorer_url'),
    // Generic explorer URL: any URL with /block/, /tx/, /address/, /token/ path
    pattern('CryptoAddr', 'OnChain', raw`https?://[^\s\)\]]+/(?:block|tx|transaction|address|token|validator|account)/[^\s\)\]]+`, 0.85, [], 0, 'generic_explorer_url'),
  ];
}

// ---------------------------------------------------------------------------
// CREDENTIALS DOMAIN (service-specific keys and tokens; patterns from Gitleaks, MIT)
// ---------------------------------------------------------------------------

export function getCredentialPatterns(): SensitivityPattern[] {
  return [
    // --- AWS ---
    pattern('ApiKey', 'Credentials', raw`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`, 0.95, [], 0, 'aws_access_key'),

    // --- GitHub (5 token types) ---
    pattern('AccessToken', 'Credentials', raw`\bghp_[0-9a-zA-Z]{36}\b`, 0.95, [], 0, 'github_pat'),
    pattern('AccessToken', 'Credentials', raw`\bgho_[0-9a-zA-Z]{36}\b`, 0.95, [], 0, 'github_oauth'),
    pattern('AccessToken', 'Credentials', raw`\bghu_[0-9a-zA-Z]{36}\b`, 0.95, [], 0, 'github_user'),
    pattern('AccessToken', 'Credentials', raw`\bghs_[0-9a-zA-Z]{36}\b`, 0.95, [], 0, 'github_app'),
    pattern('AccessToken', 'Credentials', raw`\bgithub_pat_\w{82}\b`, 0.95, [], 0, 'github_fine_grained'),

    // --- GitLab ---
    pattern('AccessToken', 'Credentials', raw`\bglpat-[A-Za-z0-9\-_]{20}\b`, 0.95, [], 0, 'gitlab_pat'),

    // --- Slack ---
    pattern('AccessToken', 'Credentials', raw`\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b`, 0.95, [], 0, 'slack_bot'),
    pattern('AccessToken', 'Credentials', raw`\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b`, 0.95, [], 0, 'slack_user'),
    pattern('AccessToken', 'Credentials', raw`\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b`, 0.95, [], 0, 'slack_app'),

    // --- Google ---
    pattern('ApiKey', 'Credentials', raw`\bAIza[0-9A-Za-z\-_]{35}\b`, 0.95, [], 0, 'google_api_key'),

    // --- OpenAI ---
    pattern('ApiKey', 'Credentials', raw`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`, 0.95, [], 0, 'openai_key'),

    // --- Anthropic ---
    pattern('ApiKey', 'Credentials', raw`\bsk-ant-api03-[a-zA-Z0-9_\-]{90,}\b`, 0.95, [], 0, 'anthropic_key'),

    // --- Stripe ---
    pattern('ApiKey', 'Credentials', raw`\b[sr]k_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b`, 0.95, [], 0, 'stripe_key'),
    pattern('WebhookSecret', 'Credentials', raw`\bwhsec_[A-Za-z0-9]{24,}\b`, 0.95, [], 0, 'stripe_webhook'),

    // --- SendGrid ---
    pattern('ApiKey', 'Credentials', raw`\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b`, 0.95, [], 0, 'sendgrid_key'),

    // --- Twilio ---
    pattern('ApiKey', 'Credentials', raw`\bSK[a-f0-9]{32}\b`, 0.9, ['twilio'], 0.05, 'twilio_key'),

    // --- Telegram Bot ---
    pattern('AccessToken', 'Credentials', raw`\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b`, 0.9, [], 0, 'telegram_bot'),

    // --- Discord Bot ---
    pattern('AccessToken', 'Credentials', raw`\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b`, 0.9, [], 0, 'discord_bot'),

    // --- Shopify ---
    pattern('AccessToken', 'Credentials', raw`\bshpat_[0-9a-fA-F]{32}\b`, 0.95, [], 0, 'shopify_access'),

    // --- npm ---
    pattern('AccessToken', 'Credentials', raw`\bnpm_[A-Za-z0-9]{36}\b`, 0.95, [], 0, 'npm_token'),

    // --- PyPI ---
    pattern('AccessToken', 'Credentials', raw`\bpypi-[A-Za-z0-9]{36,}\b`, 0.95, [], 0, 'pypi_token'),

    // --- NuGet ---
    pattern('ApiKey', 'Credentials', raw`\boy2[a-z0-9]{43}\b`, 0.9, ['nuget'], 0.05, 'nuget_key'),

    // --- Cloudflare ---
    pattern('ApiKey', 'Credentials', raw`\b[A-Za-z0-9_-]{37}\b`, 0.2, ['cloudflare', 'cf_api', 'x-auth-key'], 0.7, 'cloudflare_key'),

    // --- Heroku ---
    pattern('ApiKey', 'Credentials', raw`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`, 0.2, ['heroku', 'HEROKU_API_KEY'], 0.7, 'heroku_key'),

    // --- xprv / xpub (BIP32 extended keys; domain is OnChain) ---
    pattern('ApiKey', 'OnChain', raw`\b[xt](?:prv|pub)[a-zA-Z0-9]{100,}\b`, 0.95, [], 0, 'bip32_extended_key'),
  ];
}

// ---------------------------------------------------------------------------
// SECRETS DOMAIN (structural secrets, not service-specific)
// ---------------------------------------------------------------------------

export function getSecretPatterns(): SensitivityPattern[] {
  return [
    // --- PEM private keys ---
    pattern('PrivateKey', 'Secrets', raw`-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?:\sBLOCK)?-----`, 0.95, [], 0, 'pem_private_key'),

    // --- JWT tokens (always start with eyJ, base64 of {") ---
    pattern('Jwt', 'Secrets', raw`\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b`, 0.9, [], 0, 'jwt'),

    // --- Connection strings with passwords ---
    pattern('ConnectionString', 'Secrets', raw`(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:]+:[^@\s]+@[^\s]+`, 0.9, [], 0, 'database_uri'),
    pattern('ConnectionString', 'Secrets', raw`(?i)(?:Server|Data\sSource)=[^;]+;.*?(?:Password|Pwd)=[^;\s]+`, 0.9, [], 0, 'sql_connection_string'),

    // --- Generic password/secret in context ---
    pattern('PasswordInContext', 'Secrets', raw`(?i)(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*['"][^'"]{4,}['"]`, 0.85, [], 0, 'password_assignment'),
    pattern('PasswordInContext', 'Secrets', raw`(?i)(?:login|username|user)\s*[=:]\s*['"][^'"]{2,}['"]`, 0.7, [], 0, 'login_assignment'),
  ];
}

// ---------------------------------------------------------------------------
// FINANCIAL DOMAIN (compositional - layered by sensitivity)
// ---------------------------------------------------------------------------

const ARITHMETIC_CONTEXT = ['usd', 'aud', 'eur', 'gbp', 'jpy', 'cad', 'chf', 'nzd',
  'bought', 'sold', 'profit', 'loss', 'fee', 'withdrawal', 'deposit'];

export function getFinancialPatterns(): SensitivityPattern[] {
  return [
    // --- Market pairs (multiple separator conventions) ---
    pattern('MarketPair', 'Financial', raw`\b[A-Z]{2,6}/[A-Z]{2,6}\b`, 0.6, ['long', 'short', 'position', 'pair', 'chart', 'trade'], 0.25, 'pair_slash'),
    pattern('MarketPair', 'Financial', raw`\b[A-Z]{2,6}-[A-Z]{2,6}\b`, 0.4, ['long', 'short', 'position', 'pair', 'chart', 'trade', 'coinbase'], 0.35, 'pair_dash'),

    // --- Currency symbol amounts: $1,234.56, $12.5k, $1.2M, $500 ($, GBP, EUR, JPY symbols) ---
    pattern('Amount', 'Financial', raw`[\$\u00A3\u20AC\u00A5][\d,]+(?:\.\d+)?[kKmMbB]?`, 0.75, AMOUNT_CONTEXT, 0.15, 'symbol_amount'),
    // Symbol after number: 1,234 USD, 12.5k USD
    pattern('Amount', 'Financial', raw`\b[\d,]+\.?\d*[kKmMbB]?\s*(?:USD|US\$)\b`, 0.8, [], 0, 'usd_code_amount'),

    // --- Non-USD fiat: code before number (AUD 1,576.12, EUR 500, GBP 12.5k) ---
    pattern('Amount', 'Financial',
      raw`\b(?:AUD|EUR|GBP|JPY|CAD|CHF|NZD|SGD|HKD|KRW|CNY|INR|BRL|SEK|NOK|DKK|PLN|CZK|THB|MYR|IDR|PHP|TWD|ZAR|MXN)\s+[\d,]+\.?\d*[kKmMbB]?`,
      0.85, [], 0, 'fiat_currency_amount'),
    // --- Non-USD fiat: code after number (1,576.12 AUD, 12.5k EUR) ---
    pattern('Amount', 'Financial',
      raw`\b[\d,]+\.?\d*[kKmMbB]?\s+(?:AUD|EUR|GBP|JPY|CAD|CHF|NZD|SGD|HKD|KRW|CNY|INR|BRL|SEK|NOK|DKK|PLN|CZK|THB|MYR|IDR|PHP|TWD|ZAR|MXN)\b`,
      0.85, [], 0, 'fiat_amount_trailing'),

    // --- Shorthand multipliers near financial context: 12.5k, 1.2M, 500k ---
    pattern('Amount', 'Financial', raw`\b\d+(?:\.\d+)?[kKmMbB]\b`, 0.25,
      ['worth', 'position', 'portfolio', 'balance', 'value', 'profit', 'loss',
        'revenue', 'cost', 'budget', 'salary', 'total', 'deposit', 'withdrawal',
        '$', 'USD', 'AUD', 'EUR', 'GBP'], 0.5, 'shorthand_amount'),

    // --- Napkin math / arithmetic chains (only with strong currency context) ---
    pattern('Amount', 'Financial', raw`[\d,]+\.?\d*(?=\s*[/\*])`, 0.15, ARITHMETIC_CONTEXT, 0.55, 'arithmetic_operand'),
    pattern('Amount', 'Financial', raw`[\d,]+\.?\d*(?=\s*=(?!=))`, 0.15, ARITHMETIC_CONTEXT, 0.55, 'arithmetic_equals_left'),
    pattern('Amount', 'Financial', raw`(?<=[/\*]\s?)[\d,]+\.?\d*`, 0.15, ARITHMETIC_CONTEXT, 0.55, 'arithmetic_result'),
    pattern('Amount', 'Financial', raw`(?<=(?<!=)=\s?)[\d,]+\.?\d*`, 0.15, ARITHMETIC_CONTEXT, 0.55, 'arithmetic_equals_right'),
    // + and - only with comma-formatted numbers AND currency context
    pattern('Amount', 'Financial', raw`[\d,]{4,}\.?\d*(?=\s*[+\-])`, 0.15, ARITHMETIC_CONTEXT, 0.55, 'arithmetic_sum_operand'),

    // --- Numbers preceded by trading verbs (lookbehind keeps the verb out of the span) ---
    pattern('Quantity', 'Financial',
      raw`(?i)(?<=(?:bought|sold|buy|sell|staked|swapped|transferred|deposited|withdrew|allocated|spent|received|sent|wired)\s)\d+(?:[.,]\d+)?[kKmMbB]?`,
      0.8, [], 0, 'verb_quantity'),

    // --- Comma-formatted numbers: 1,234 or 11,234 or 1,234.56 ---
    pattern('Quantity', 'Financial', raw`\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b`, 0.3, TRADING_CONTEXT, 0.45, 'comma_number'),

    // --- Large bare numbers near financial context (excludes years, "17 JUL", "10:36") ---
    pattern('Quantity', 'Financial',
      raw`(?<![\#\-/:])\b(?!(?:19|20)\d{2}\b)(?:\d{1,3}(?:,\d{3})+|\d{3,})(?:\.\d+)?\b(?![\-/:]|\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\b)`,
      0.2, TRADING_CONTEXT, 0.45, 'large_number', { ignoreCase: true }),

    // --- Numbers adjacent to asset names (case-insensitive) ---
    pattern('Quantity', 'Financial',
      raw`(?i)[+\-]?\s*\d+(?:[.,]\d+)?\.{0,4}\s+(?:BTC|ETH|SOL|AVAX|MATIC|DOT|ADA|LINK|UNI|AAVE|BNB|XRP|LTC|ATOM|NEAR|APT|SUI|ARB|OP|USDT|USDC|WETH|WBTC|stETH)\b`,
      0.75, [], 0, 'asset_quantity'),

    // --- High-precision decimals (10+ decimal digits = wei/gwei precision) ---
    pattern('Quantity', 'Financial', raw`\b\d+\.\d{10,}\b`, 0.8, [], 0, 'wei_precision_quantity'),

    // --- Bare numbers in table cells near financial context ---
    pattern('Quantity', 'Financial', raw`\b\d{1,}(?:,\d{3})*\.\d{2,}\b`, 0.15,
      ['quantity', 'price', 'value', 'balance', 'asset', 'contract', 'token', 'ETH', 'BTC', 'USDT', 'USDC', 'stETH'], 0.55, 'table_quantity'),

    // --- Bare integer/decimal inside a markdown table cell ("| 30 |", "| 0.5 |") ---
    pattern('Quantity', 'Financial', raw`(?<=\|\s*)\d+(?:[.,]\d+)?(?=\s*\|)`, 0.2,
      ['price', 'amount', 'total', 'executed', 'iceberg', 'qty', 'quantity',
        'balance', 'filled', 'order', 'trigger', 'limit', 'buy', 'sell'],
      0.55, 'table_cell_number'),

    // --- Price patterns (exclude "at 10:43" and IP-like "at 192.168") ---
    // Price with explicit $ symbol: structural
    pattern('Price', 'Financial', raw`\b(?:at|@)\s+\$[\d,]+\.?\d*\b(?![\.:]\d+\.\d+)(?!:\d{2})`, 0.75, PRICE_CONTEXT, 0.15, 'price_dollar'),
    // Price without $ symbol: requires strong financial context
    pattern('Price', 'Financial', raw`\b(?:at|@)\s+[\d,]+\.?\d*\b(?![\.:]\d+\.\d+)(?!:\d{2})(?!\s*[MGTmgt][Bb]?\b)`, 0.25, PRICE_CONTEXT, 0.45, 'price_bare'),

    // --- Credit card numbers (Luhn-validated in post-processing) ---
    pattern('CreditCard', 'Financial', raw`\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b`, 0.8, ['card', 'credit', 'visa', 'payment', 'cc', 'cvv'], 0.15, 'visa'),
    pattern('CreditCard', 'Financial', raw`\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b`, 0.8, ['card', 'credit', 'mastercard', 'payment', 'cc', 'cvv'], 0.15, 'mastercard'),
    pattern('CreditCard', 'Financial', raw`\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b`, 0.8, ['card', 'credit', 'amex', 'american express', 'payment', 'cc'], 0.15, 'amex'),
  ];
}

// ---------------------------------------------------------------------------
// IDENTITY DOMAIN
// ---------------------------------------------------------------------------

export function getIdentityPatterns(): SensitivityPattern[] {
  return [
    pattern('Ssn', 'Identity', raw`\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`, 0.7, ['ssn', 'social', 'security'], 0.2, 'us_ssn'),

    pattern('Iban', 'Identity', raw`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`, 0.6, ['iban', 'bank', 'transfer', 'wire', 'account'], 0.25, 'iban'),

    pattern('IpAddress', 'Identity', raw`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, 0.5,
      ['server', 'host', 'node', 'rpc', 'endpoint', 'ssh', 'vpn',
        'TCP', 'UDP', 'port', 'api', 'gateway', 'router', 'NAS',
        'docker', 'container', 'network', 'lan', 'dhcp', 'dns',
        'ipfs', 'mqtt', 'proxy', 'firewall', 'homelab'], 0.3, 'ipv4'),

    // --- UNC paths / network shares with IPs: \\192.168.10.2\share ---
    pattern('IpAddress', 'Identity', raw`\\\\(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\\[^\s\)\]]+`, 0.9, [], 0, 'unc_network_path'),
    // file:// URIs with IPs
    pattern('IpAddress', 'Identity', raw`file:///\\\\(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\\[^\s\)\]]+`, 0.9, [], 0, 'file_uri_network_path'),

    // --- MAC addresses ---
    pattern('MacAddress', 'Identity', raw`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b`, 0.85, [], 0, 'mac_colon'),
    pattern('MacAddress', 'Identity', raw`\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b`, 0.85, [], 0, 'mac_dash'),

    pattern('Email', 'Identity', raw`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`, 0.7, ['email', 'contact', 'mailto', 'send'], 0.15, 'email'),
  ];
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/** Every registered pattern across all domains, in C# GetAll() order. */
export function getAllPatterns(): SensitivityPattern[] {
  return [
    ...getOnChainPatterns(),
    ...getCredentialPatterns(),
    ...getSecretPatterns(),
    ...getFinancialPatterns(),
    ...getIdentityPatterns(),
  ];
}

function isWithinFinancialLayer(type: EntityType, layer: string | null): boolean {
  switch (type) {
    case 'Quantity':
    case 'Amount':
    case 'Price':
      return true;
    case 'MarketPair':
    case 'AssetName':
      return layer === 'markets' || layer === 'directional';
    default:
      return layer === 'directional';
  }
}

/**
 * The patterns enabled by a config. A null domain toggle throws, like the
 * NullReferenceException the C# build raises for the same config.
 */
export function getPatternsForConfig(config: ShroudConfig): SensitivityPattern[] {
  const domains = config.domains!;
  return getAllPatterns().filter((p) => {
    switch (p.domain) {
      case 'OnChain':
        return domains.onChain!.enabled;
      case 'Financial':
        return domains.financial!.enabled && isWithinFinancialLayer(p.entityType, domains.financial!.layer);
      case 'Identity':
        return domains.identity!.enabled;
      case 'Credentials':
        return domains.credentials!.enabled;
      case 'Secrets':
        return domains.secrets!.enabled;
    }
  });
}
