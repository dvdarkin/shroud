using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

/// <summary>
/// Central registry of all sensitivity patterns, split into domain-specific
/// partial classes for maintainability.  Each domain file returns its own
/// pattern list; <see cref="GetAll"/> aggregates them.
/// </summary>
public static partial class PatternLibrary
{
    // -----------------------------------------------------------------
    // Confidence tier constants -- use these when adding new patterns
    // to keep calibration consistent across domains.
    // -----------------------------------------------------------------
    internal const double HighConfidence = 0.90;
    internal const double MediumConfidence = 0.70;
    internal const double LowConfidence = 0.35;

    /// <summary>Shared compiled-regex options used by every pattern.</summary>
    internal static readonly RegexOptions Opts = RegexOptions.Compiled;

    // -----------------------------------------------------------------
    // Context arrays shared across domains (primarily Financial)
    // -----------------------------------------------------------------
    public static readonly HashSet<string> KnownAssets = new(StringComparer.OrdinalIgnoreCase)
    {
        "BTC", "ETH", "SOL", "AVAX", "MATIC", "DOT", "ADA", "LINK",
        "UNI", "AAVE", "CRV", "MKR", "SNX", "COMP", "SUSHI", "YFI",
        "DOGE", "SHIB", "PEPE", "WIF", "BONK",
        "BNB", "XRP", "LTC", "ATOM", "NEAR", "APT", "SUI", "ARB", "OP",
        "FTM", "INJ", "TIA", "JUP", "RNDR", "FET", "TAO",
        "USDT", "USDC", "DAI", "FRAX",
        "WETH", "WBTC", "stETH", "rETH", "cbETH",
        "Bitcoin", "Ethereum", "Solana",
        // DeFi protocols and bridges (context boosters)
        "Uniswap", "Aave", "Compound", "Curve", "Lido", "Convex",
        "Starkgate", "Starknet", "zkSync", "Orbiter", "Hop",
        "LayerZero", "Wormhole", "Across", "Stargate",
        "Raydium", "Orca", "Marinade", "Jupiter",
        "Osmosis", "Astroport"
    };

    internal static readonly string[] TradingContext =
    [
        "bought", "sold", "buy", "sell", "long", "short",
        "position", "portfolio", "balance", "worth", "allocated",
        "staked", "swapped", "transferred", "deposited", "withdrew",
        "liquidated", "margin", "leverage", "PnL", "profit", "loss",
        "bridge", "bridged", "minted", "burned", "claimed", "harvested",
        "airdrop", "vesting", "locked", "unlocked", "pending"
    ];

    internal static readonly string[] PriceContext =
    [
        "at", "for", "price", "cost", "entry", "exit",
        "filled", "limit", "market", "bid", "ask", "spot"
    ];

    internal static readonly string[] AmountContext =
    [
        "bought", "sold", "position", "portfolio", "balance",
        "worth", "allocated", "total", "value", "holding"
    ];

    // -----------------------------------------------------------------
    // Aggregation
    // -----------------------------------------------------------------

    /// <summary>
    /// Returns every registered pattern across all domains.
    /// Domain-specific patterns are defined in partial class files:
    /// OnChain, Credentials, Secrets, Financial, Identity.
    /// </summary>
    public static IReadOnlyList<SensitivityPattern> GetAll()
    {
        var all = new List<SensitivityPattern>();
        all.AddRange(GetOnChainPatterns());
        all.AddRange(GetCredentialPatterns());
        all.AddRange(GetSecretPatterns());
        all.AddRange(GetFinancialPatterns());
        all.AddRange(GetIdentityPatterns());
        return all;
    }

    public static IReadOnlyList<SensitivityPattern> GetForConfig(ShroudConfig config)
    {
        var all = GetAll();
        return all.Where(p =>
        {
            return p.Domain switch
            {
                SensitivityDomain.OnChain => config.Domains.OnChain.Enabled,
                SensitivityDomain.Financial => config.Domains.Financial.Enabled &&
                    IsWithinFinancialLayer(p.EntityType, config.Domains.Financial.Layer),
                SensitivityDomain.Identity => config.Domains.Identity.Enabled,
                SensitivityDomain.Credentials => config.Domains.Credentials.Enabled,
                SensitivityDomain.Secrets => config.Domains.Secrets.Enabled,
                _ => true
            };
        }).ToList();
    }

    private static bool IsWithinFinancialLayer(EntityType type, string layer) => type switch
    {
        EntityType.Quantity or EntityType.Amount or EntityType.Price => true,
        EntityType.MarketPair or EntityType.AssetName => layer is "markets" or "directional",
        _ => layer is "directional"
    };
}
