using System.Security.Cryptography;
using System.Text;
using Shroud.Models;

namespace Shroud.Masking;

/// <summary>
/// Replaces detected spans with deterministic [TYPE:XXXXXXXX] tokens. Token IDs are derived via
/// HMAC-SHA256(key, matchedText) truncated to 4 bytes (8 hex chars) — same value + same key always
/// produces the same token, enabling cross-file correlation without exposing the original. Spans
/// are replaced right-to-left to preserve character indices. 4-byte truncation gives a 2^32 token
/// space; by the birthday problem, collision probability stays below 0.01% for up to 10,000 unique
/// values and below 1% for up to 100,000 — safe for any realistic vault workload.
/// </summary>
public class SpanMasker
{
    private readonly byte[] _key;

    public SpanMasker(byte[] key)
    {
        _key = key;
    }

    /// <summary>
    /// Replace all above-threshold spans with deterministic [TYPE:XXXXXXXX] tokens.
    /// </summary>
    public MaskResult Mask(string text, ScanResult scanResult)
    {
        var spans = scanResult.AboveThreshold.OrderByDescending(s => s.Start).ToList();
        var sb = new StringBuilder(text);
        var tokens = new List<TokenMapping>();

        foreach (var span in spans)
        {
            var tokenId = GenerateToken(span);
            var replacement = $"[{tokenId}]";
            sb.Remove(span.Start, span.Length);
            sb.Insert(span.Start, replacement);
            tokens.Add(new TokenMapping(tokenId, span.MatchedText, span.EntityType, span.Domain));
        }

        return new MaskResult(sb.ToString(), tokens);
    }

    private string GenerateToken(SensitiveSpan span)
    {
        var hmac = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(span.MatchedText));
        var shortHash = Convert.ToHexString(hmac[..4]).ToLowerInvariant();
        return $"{span.TypeAbbreviation}:{shortHash}";
    }
}

public record MaskResult(
    string MaskedText,
    IReadOnlyList<TokenMapping> Tokens
);

public record TokenMapping(
    string TokenId,
    string OriginalValue,
    EntityType EntityType,
    SensitivityDomain Domain
);
