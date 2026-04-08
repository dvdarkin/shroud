using Shroud.Models;

namespace Shroud.Detection;

internal class ScanDiagnostics
{
    public List<(int Start, int End)> ExclusionZones { get; } = [];
    public List<SpanDiagnostic> AllSpans { get; } = [];
    public List<OverlapResolution> OverlapResolutions { get; } = [];
}

internal class SpanDiagnostic
{
    public required SensitiveSpan Span { get; init; }
    public required ScoringDetail Scoring { get; init; }
    public bool WasExcluded { get; init; }
    public bool FailedLuhn { get; init; }
}

internal class OverlapResolution
{
    public required SensitiveSpan Dropped { get; init; }
    public required SensitiveSpan Winner { get; init; }
    public required string Reason { get; init; }
}
