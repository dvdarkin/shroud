using System.Text.RegularExpressions;

namespace Shroud.Vault;

/// <summary>
/// Puts original values back in place of <c>[TOKEN:id]</c> markers. The text is read once, left
/// to right: every <c>[...]</c> whose content is a key of the token map is replaced by its value,
/// and replaced text is never looked at again. A value that itself contains bracketed text is
/// therefore restored exactly as it was stored, whatever else the vault holds.
/// </summary>
public static class TokenRestorer
{
    // Innermost bracket pair: no "[" or "]" inside, so "[[ADDR:1234abcd]]" finds the inner token.
    private static readonly Regex BracketedRegex = new(
        @"\[([^\[\]]+)\]", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // What SpanMasker writes: upper-case type abbreviation, colon, lower-case hex.
    private static readonly Regex TokenIdRegex = new(
        @"\A[A-Z]+:[0-9a-f]{4,}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Restores every known token in <paramref name="text"/>.</summary>
    public static string Restore(string text, IReadOnlyDictionary<string, string> tokens) =>
        Restore(text, tokens, out _);

    /// <summary>
    /// Restores every known token in <paramref name="text"/>. <paramref name="unresolved"/> counts
    /// the markers that look like Shroud tokens but are not in <paramref name="tokens"/>; they are
    /// left as they are.
    /// </summary>
    public static string Restore(string text, IReadOnlyDictionary<string, string> tokens, out int unresolved)
    {
        var missing = 0;
        var restored = BracketedRegex.Replace(text, m =>
        {
            var id = m.Groups[1].Value;
            if (tokens.TryGetValue(id, out var value))
                return value ?? "";
            if (TokenIdRegex.IsMatch(id))
                missing++;
            return m.Value;
        });
        unresolved = missing;
        return restored;
    }
}
