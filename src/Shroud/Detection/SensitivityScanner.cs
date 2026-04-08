using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

/// <summary>
/// Core detection pipeline. For each registered pattern, finds all regex matches in the input text,
/// skips matches inside exclusion zones (YAML frontmatter, file-path metadata lines), scores each
/// match via <see cref="ContextScorer"/> (structural patterns pass through, contextual patterns get
/// boosted by nearby keywords), runs post-match validators (Luhn for credit cards), deduplicates
/// overlapping spans (longest wins, containers absorb contents), and splits results at the
/// configured confidence threshold into above/below buckets.
/// </summary>
public class SensitivityScanner
{
    private readonly IReadOnlyList<SensitivityPattern> _patterns;
    private readonly double _tokenizeThreshold;

    private static readonly Regex FrontmatterRegex = new(
        @"^---\s*\n[\s\S]*?\n---\s*$",
        RegexOptions.Compiled | RegexOptions.Multiline);
    private static readonly Regex FilePathRegex = new(
        @"(?:source_file|file|path|attachment):\s*.+$",
        RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.IgnoreCase);

    public SensitivityScanner(
        IReadOnlyList<SensitivityPattern>? patterns = null,
        double tokenizeThreshold = 0.70)
    {
        _patterns = patterns ?? PatternLibrary.GetAll();
        _tokenizeThreshold = tokenizeThreshold;
    }

    public SensitivityScanner(ShroudConfig config)
    {
        _patterns = PatternLibrary.GetForConfig(config);
        _tokenizeThreshold = config.Threshold;
    }

    public ScanResult Scan(string text)
    {
        return ScanInternal(text, diagnostics: null);
    }

    internal ScanResult ScanWithDiagnostics(string text, out ScanDiagnostics diagnostics)
    {
        diagnostics = new ScanDiagnostics();
        return ScanInternal(text, diagnostics);
    }

    private ScanResult ScanInternal(string text, ScanDiagnostics? diagnostics)
    {
        var exclusions = BuildExclusions(text);
        diagnostics?.ExclusionZones.AddRange(exclusions);

        var allSpans = new List<SensitiveSpan>();

        foreach (var pattern in _patterns)
        {
            foreach (var match in pattern.CompiledRegex.EnumerateMatches(text))
            {
                if (IsExcluded(match.Index, match.Index + match.Length, exclusions))
                {
                    if (diagnostics != null)
                    {
                        var excludedText = text.Substring(match.Index, match.Length);
                        var excludedSpan = new SensitiveSpan(match.Index, match.Index + match.Length,
                            pattern.EntityType, pattern.Domain, pattern.BaseConfidence, excludedText, pattern.Service);
                        diagnostics.AllSpans.Add(new SpanDiagnostic
                        {
                            Span = excludedSpan,
                            Scoring = new ScoringDetail { BaseConfidence = pattern.BaseConfidence, PatternService = pattern.Service },
                            WasExcluded = true
                        });
                    }
                    continue;
                }

                var matchedText = text.Substring(match.Index, match.Length);
                var span = new SensitiveSpan(
                    Start: match.Index,
                    End: match.Index + match.Length,
                    EntityType: pattern.EntityType,
                    Domain: pattern.Domain,
                    Confidence: pattern.BaseConfidence,
                    MatchedText: matchedText,
                    Service: pattern.Service
                );

                double confidence;
                ScoringDetail? scoringDetail = null;
                if (diagnostics != null)
                {
                    confidence = ContextScorer.Score(span, pattern, text, out var detail);
                    scoringDetail = detail;
                }
                else
                {
                    confidence = ContextScorer.Score(span, pattern, text);
                }

                var scored = span with { Confidence = confidence };

                if (scored.EntityType == Models.EntityType.CreditCard && !LuhnValidator.IsValid(matchedText))
                {
                    diagnostics?.AllSpans.Add(new SpanDiagnostic
                    {
                        Span = scored,
                        Scoring = scoringDetail ?? new ScoringDetail { BaseConfidence = pattern.BaseConfidence, PatternService = pattern.Service },
                        FailedLuhn = true
                    });
                    continue;
                }

                diagnostics?.AllSpans.Add(new SpanDiagnostic
                {
                    Span = scored,
                    Scoring = scoringDetail ?? new ScoringDetail { BaseConfidence = pattern.BaseConfidence, PatternService = pattern.Service }
                });

                allSpans.Add(scored);
            }
        }

        var deduped = DeduplicateOverlaps(allSpans, diagnostics);

        return new ScanResult(
            AllDetected: deduped,
            AboveThreshold: deduped.Where(s => s.Confidence >= _tokenizeThreshold).ToList(),
            BelowThreshold: deduped.Where(s => s.Confidence < _tokenizeThreshold).ToList(),
            Threshold: _tokenizeThreshold
        );
    }

    internal static List<SensitiveSpan> DeduplicateOverlaps(List<SensitiveSpan> spans,
        ScanDiagnostics? diagnostics = null)
    {
        if (spans.Count <= 1) return spans;

        var sorted = spans
            .OrderByDescending(s => s.Length)
            .ThenByDescending(s => s.Confidence)
            .ToList();
        var result = new List<SensitiveSpan>();

        foreach (var span in sorted)
        {
            SensitiveSpan? winnerSpan = null;
            string? reason = null;

            var dominated = result.Any(accepted =>
            {
                var overlaps = span.Start < accepted.End && span.End > accepted.Start;
                if (!overlaps) return false;

                if (span.Start >= accepted.Start && span.End <= accepted.End)
                {
                    winnerSpan = accepted;
                    reason = "contained";
                    return true;
                }

                if (accepted.Length > span.Length)
                {
                    winnerSpan = accepted;
                    reason = "shorter";
                    return true;
                }

                if (accepted.Length == span.Length && accepted.Confidence >= span.Confidence)
                {
                    winnerSpan = accepted;
                    reason = "lower_confidence";
                    return true;
                }

                return false;
            });

            if (dominated)
            {
                if (diagnostics != null && winnerSpan != null && reason != null)
                {
                    diagnostics.OverlapResolutions.Add(new OverlapResolution
                    {
                        Dropped = span,
                        Winner = winnerSpan,
                        Reason = reason
                    });
                }
            }
            else
            {
                if (diagnostics != null)
                {
                    var removed = result.Where(accepted =>
                        accepted.Start >= span.Start && accepted.End <= span.End).ToList();
                    foreach (var r in removed)
                    {
                        diagnostics.OverlapResolutions.Add(new OverlapResolution
                        {
                            Dropped = r,
                            Winner = span,
                            Reason = "contained"
                        });
                    }
                }
                result.RemoveAll(accepted =>
                    accepted.Start >= span.Start && accepted.End <= span.End);

                result.Add(span);
            }
        }

        return result.OrderBy(s => s.Start).ToList();
    }

    private static List<(int Start, int End)> BuildExclusions(string text)
    {
        var zones = new List<(int Start, int End)>();
        foreach (Match m in FrontmatterRegex.Matches(text))
            zones.Add((m.Index, m.Index + m.Length));
        foreach (Match m in FilePathRegex.Matches(text))
            zones.Add((m.Index, m.Index + m.Length));
        return zones;
    }

    private static bool IsExcluded(int start, int end, List<(int Start, int End)> exclusions)
    {
        foreach (var zone in exclusions)
        {
            if (start >= zone.Start && end <= zone.End)
                return true;
        }
        return false;
    }
}
