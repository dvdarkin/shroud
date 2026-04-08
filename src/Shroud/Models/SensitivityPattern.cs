using System.Text.RegularExpressions;

namespace Shroud.Models;

/// <summary>
/// A compiled detection rule. IsStructural (BaseConfidence >= 0.80 or no context words) means the
/// pattern's format alone is sufficient evidence — no surrounding text analysis needed. Contextual
/// patterns start with low confidence and rely on ContextScorer finding keywords within 120 chars
/// to boost above the threshold. Service identifies the specific pattern (e.g. "evm_address",
/// "github_pat") for diagnostics and manifest metadata.
/// </summary>
public record SensitivityPattern(
    EntityType EntityType,
    SensitivityDomain Domain,
    Regex CompiledRegex,
    double BaseConfidence,
    string[] ContextWords,
    double ContextBoost,
    string Service = ""
)
{
    public bool IsStructural => ContextWords.Length == 0 || BaseConfidence >= 0.80;
}
