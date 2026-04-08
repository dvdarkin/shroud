// ============================================================================
// PatternLibrary.Financial.cs -- Financial Domain Patterns
// ============================================================================
//
// Covers: Market pairs (slash and dash separators), currency-symbol amounts
// ($, GBP, EUR, JPY), USD code amounts, non-USD fiat amounts (code before
// and after number), shorthand multipliers (12.5k, 1.2M), arithmetic chains
// (napkin math), verb-preceded quantities, comma-
// formatted numbers, large bare numbers, asset-adjacent quantities, high-
// precision (wei) decimals, table-cell quantities, price patterns (with and
// without $), and credit card numbers (Visa, Mastercard, Amex).
//
// Confidence calibration:
//   High (>= 0.90) -- Not typically used here; financial data is compositional.
//   Medium (0.70-0.85) -- Amounts with explicit currency symbols or fiat codes,
//                          verb-preceded quantities, credit cards.
//   Low   (<= 0.35) -- Bare numbers, arithmetic, and shorthand that only fire
//                       with strong currency/trading context words.
//
// Context arrays TradingContext, PriceContext, and AmountContext are defined
// in the main PatternLibrary.cs and referenced here.
//
// To add a new pattern:
//   1. Use EntityType.Amount for monetary values, EntityType.Quantity for
//      counts, EntityType.Price for price-at points, EntityType.MarketPair
//      for trading pairs, EntityType.CreditCard for card numbers.
//   2. Domain is SensitivityDomain.Financial.
//   3. Low-confidence patterns MUST have context words to avoid false positives.
//   4. Give the pattern a unique Service string for diagnostics.
//   5. Add integration tests covering match and non-match cases.
// ============================================================================

using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

public static partial class PatternLibrary
{
    internal static IReadOnlyList<SensitivityPattern> GetFinancialPatterns() =>
    [
        // ================================================================
        // FINANCIAL DOMAIN (compositional -- layered by sensitivity)
        // ================================================================

        // --- Market pairs (multiple separator conventions) ---
        new(EntityType.MarketPair, SensitivityDomain.Financial,
            new Regex(@"\b[A-Z]{2,6}/[A-Z]{2,6}\b", Opts),
            0.60, ["long", "short", "position", "pair", "chart", "trade"], 0.25, "pair_slash"),
        new(EntityType.MarketPair, SensitivityDomain.Financial,
            new Regex(@"\b[A-Z]{2,6}-[A-Z]{2,6}\b", Opts),
            0.40, ["long", "short", "position", "pair", "chart", "trade", "coinbase"], 0.35, "pair_dash"),

        // --- Currency symbol amounts: $1,234.56, $12.5k, $1.2M, $500 ---
        // Supports $, GBP, EUR, JPY symbols. Decimal only when followed by digits.
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"[\$\u00A3\u20AC\u00A5][\d,]+(?:\.\d+)?[kKmMbB]?", Opts),
            0.75, AmountContext, 0.15, "symbol_amount"),
        // Symbol after number: 1,234 USD, 12.5k USD
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"\b[\d,]+\.?\d*[kKmMbB]?\s*(?:USD|US\$)\b", Opts),
            0.80, [], 0, "usd_code_amount"),

        // --- Non-USD fiat: code before number ---
        // AUD 1,576.12, EUR 500, GBP 12.5k
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"\b(?:AUD|EUR|GBP|JPY|CAD|CHF|NZD|SGD|HKD|KRW|CNY|INR|BRL|SEK|NOK|DKK|PLN|CZK|THB|MYR|IDR|PHP|TWD|ZAR|MXN)\s+[\d,]+\.?\d*[kKmMbB]?", Opts),
            0.85, [], 0, "fiat_currency_amount"),
        // --- Non-USD fiat: code after number ---
        // 1,576.12 AUD, 12.5k EUR, 35,479.69 AUD
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"\b[\d,]+\.?\d*[kKmMbB]?\s+(?:AUD|EUR|GBP|JPY|CAD|CHF|NZD|SGD|HKD|KRW|CNY|INR|BRL|SEK|NOK|DKK|PLN|CZK|THB|MYR|IDR|PHP|TWD|ZAR|MXN)\b", Opts),
            0.85, [], 0, "fiat_amount_trailing"),

        // --- Shorthand multipliers near financial context: 12.5k, 1.2M, 500k ---
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"\b\d+(?:\.\d+)?[kKmMbB]\b", Opts),
            0.25, ["worth", "position", "portfolio", "balance", "value", "profit", "loss",
                    "revenue", "cost", "budget", "salary", "total", "deposit", "withdrawal",
                    "$", "USD", "AUD", "EUR", "GBP"], 0.50, "shorthand_amount"),

        // --- Napkin math / OneNote arithmetic chains ---
        // Numbers in arithmetic expressions only fire with STRONG currency context.
        // Generic words like "total" or "sum" are too ambiguous (recipes, physics, etc).
        // Requires actual currency signals: $, USD, AUD, EUR, GBP, or financial verbs.
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"[\d,]+\.?\d*(?=\s*[/\*])", Opts),
            0.15, ["usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd",
                    "bought", "sold", "profit", "loss", "fee", "withdrawal", "deposit"], 0.55, "arithmetic_operand"),
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"[\d,]+\.?\d*(?=\s*=(?!=))", Opts),
            0.15, ["usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd",
                    "bought", "sold", "profit", "loss", "fee", "withdrawal", "deposit"], 0.55, "arithmetic_equals_left"),
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"(?<=[/\*]\s?)[\d,]+\.?\d*", Opts),
            0.15, ["usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd",
                    "bought", "sold", "profit", "loss", "fee", "withdrawal", "deposit"], 0.55, "arithmetic_result"),
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"(?<=(?<!=)=\s?)[\d,]+\.?\d*", Opts),
            0.15, ["usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd",
                    "bought", "sold", "profit", "loss", "fee", "withdrawal", "deposit"], 0.55, "arithmetic_equals_right"),
        // + and - only with comma-formatted numbers AND currency context
        new(EntityType.Amount, SensitivityDomain.Financial,
            new Regex(@"[\d,]{4,}\.?\d*(?=\s*[+\-])", Opts),
            0.15, ["usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd",
                    "bought", "sold", "profit", "loss", "fee", "withdrawal", "deposit"], 0.55, "arithmetic_sum_operand"),

        // --- Numbers preceded by trading verbs: "bought 743", "sold 10", "staked 500" ---
        // Uses lookbehind so only the number is captured — the verb stays in the output.
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"(?i)(?<=(?:bought|sold|buy|sell|staked|swapped|transferred|deposited|withdrew|allocated|spent|received|sent|wired)\s)\d+(?:[.,]\d+)?[kKmMbB]?", Opts),
            0.80, [], 0, "verb_quantity"),

        // --- Comma-formatted numbers: 1,234 or 11,234 or 1,234.56 ---
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b", Opts),
            0.30, TradingContext, 0.45, "comma_number"),

        // --- Large bare numbers near financial context ---
        // Requires 3+ digits (bare) or comma-formatted (1,234). Excludes 4-digit years
        // (19xx/20xx), day-of-month before month names (17 JUL), and time components (10:36).
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"(?<![\#\-/:])\b(?!(?:19|20)\d{2}\b)(?:\d{1,3}(?:,\d{3})+|\d{3,})(?:\.\d+)?\b(?![\-/:]|\s+(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\b)", Opts | RegexOptions.IgnoreCase),
            0.20, TradingContext, 0.45, "large_number"),

        // --- Numbers adjacent to asset names (case-insensitive for casual writing) ---
        // Handles: "0.5 eth", "1234 USDC", "+ 1234 USDC", "1234.... USDC" (with trailing dots)
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"(?i)[+\-]?\s*\d+(?:[.,]\d+)?\.{0,4}\s+(?:BTC|ETH|SOL|AVAX|MATIC|DOT|ADA|LINK|UNI|AAVE|BNB|XRP|LTC|ATOM|NEAR|APT|SUI|ARB|OP|USDT|USDC|WETH|WBTC|stETH)\b", Opts),
            0.75, [], 0, "asset_quantity"),

        // --- High-precision decimals (10+ decimal digits = wei/gwei precision) ---
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"\b\d+\.\d{10,}\b", Opts),
            0.80, [], 0, "wei_precision_quantity"),

        // --- Bare numbers in table cells near financial context ---
        new(EntityType.Quantity, SensitivityDomain.Financial,
            new Regex(@"\b\d{1,}(?:,\d{3})*\.\d{2,}\b", Opts),
            0.15, ["quantity", "price", "value", "balance", "asset", "contract", "token", "ETH", "BTC", "USDT", "USDC", "stETH"], 0.55, "table_quantity"),

        // --- Price patterns ---
        // Excludes time formats: "at 10:43" and IP-like: "at 192.168"
        // Price with explicit $ symbol: structural
        new(EntityType.Price, SensitivityDomain.Financial,
            new Regex(@"\b(?:at|@)\s+\$[\d,]+\.?\d*\b(?![\.:]\d+\.\d+)(?!:\d{2})", Opts),
            0.75, PriceContext, 0.15, "price_dollar"),
        // Price without $ symbol: requires strong financial context
        new(EntityType.Price, SensitivityDomain.Financial,
            new Regex(@"\b(?:at|@)\s+[\d,]+\.?\d*\b(?![\.:]\d+\.\d+)(?!:\d{2})(?!\s*[MGTmgt][Bb]?\b)", Opts),
            0.25, PriceContext, 0.45, "price_bare"),

        // --- Credit card numbers (Luhn-validated in post-processing) ---
        // Visa
        new(EntityType.CreditCard, SensitivityDomain.Financial,
            new Regex(@"\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b", Opts),
            0.80, ["card", "credit", "visa", "payment", "cc", "cvv"], 0.15, "visa"),
        // Mastercard
        new(EntityType.CreditCard, SensitivityDomain.Financial,
            new Regex(@"\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b", Opts),
            0.80, ["card", "credit", "mastercard", "payment", "cc", "cvv"], 0.15, "mastercard"),
        // Amex
        new(EntityType.CreditCard, SensitivityDomain.Financial,
            new Regex(@"\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b", Opts),
            0.80, ["card", "credit", "amex", "american express", "payment", "cc"], 0.15, "amex")
    ];
}
