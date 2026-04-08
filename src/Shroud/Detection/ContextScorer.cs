using Shroud.Models;

namespace Shroud.Detection;

/// <summary>
/// Scores detection confidence by examining a 120-character window around each match. Patterns are
/// either structural (unique prefix like 0x or ghp_ — BaseConfidence >= 0.80, no context needed) or
/// contextual (ambiguous format — low base, boosted when domain-specific keywords appear nearby).
/// Financial-domain patterns get additional non-cumulative boosts for known asset names (BTC, ETH)
/// and currency signals ($, USD, fee). Substring matching is intentional: "sol" matches inside
/// "solana" but also "solution" — a known trade-off documented in Known Limitations.
/// </summary>
public static class ContextScorer
{
    public const int ContextWindowChars = 120;
    public const double AdditionalContextWordBoost = 0.05;
    public const int MaxAdditionalContextWords = 3;
    public const double AssetNameBoost = 0.10;
    public const double CurrencySignalBoost = 0.10;

    private static readonly string[] CurrencySignals =
    [
        "usd", "aud", "eur", "gbp", "jpy", "cad", "chf", "nzd", "sgd", "hkd",
        "krw", "cny", "inr", "brl", "usdt", "usdc", "dai",
        "$", "fee", "fees", "commission", "rate"
    ];

    public static double Score(SensitiveSpan span, SensitivityPattern pattern, string fullText)
    {
        return Score(span, pattern, fullText, out _);
    }

    internal static double Score(SensitiveSpan span, SensitivityPattern pattern, string fullText,
        out ScoringDetail detail)
    {
        var score = pattern.BaseConfidence;
        detail = new ScoringDetail
        {
            BaseConfidence = pattern.BaseConfidence,
            IsStructural = pattern.IsStructural,
            PatternService = pattern.Service
        };

        if (pattern.ContextWords.Length == 0)
        {
            detail.FinalConfidence = score;
            return score;
        }

        var contextStart = Math.Max(0, span.Start - ContextWindowChars);
        var contextEnd = Math.Min(fullText.Length, span.End + ContextWindowChars);
        var context = fullText[contextStart..contextEnd];
        detail.ContextWindowStart = contextStart;
        detail.ContextWindowEnd = contextEnd;

        var contextWordsFound = new List<string>();
        foreach (var word in pattern.ContextWords)
        {
            if (context.Contains(word, StringComparison.OrdinalIgnoreCase))
                contextWordsFound.Add(word);
        }
        detail.ContextWordsFound = contextWordsFound;

        if (contextWordsFound.Count > 0)
            score += pattern.ContextBoost;

        if (contextWordsFound.Count > 1)
            score += AdditionalContextWordBoost * Math.Min(contextWordsFound.Count - 1, MaxAdditionalContextWords);

        if (pattern.Domain == SensitivityDomain.Financial)
        {
            foreach (var asset in PatternLibrary.KnownAssets)
            {
                if (context.Contains(asset, StringComparison.OrdinalIgnoreCase))
                {
                    score += AssetNameBoost;
                    detail.AssetBoostApplied = true;
                    break;
                }
            }

            foreach (var signal in CurrencySignals)
            {
                if (context.Contains(signal, StringComparison.OrdinalIgnoreCase))
                {
                    score += CurrencySignalBoost;
                    detail.CurrencyBoostApplied = true;
                    break;
                }
            }
        }

        score = Math.Min(score, 1.0);
        detail.FinalConfidence = score;
        return score;
    }
}

internal class ScoringDetail
{
    public double BaseConfidence { get; set; }
    public double FinalConfidence { get; set; }
    public bool IsStructural { get; set; }
    public List<string> ContextWordsFound { get; set; } = [];
    public int ContextWindowStart { get; set; }
    public int ContextWindowEnd { get; set; }
    public bool AssetBoostApplied { get; set; }
    public bool CurrencyBoostApplied { get; set; }
    public string PatternService { get; set; } = "";
}
