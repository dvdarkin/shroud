namespace Shroud.Models;

public record ScanResult(
    IReadOnlyList<SensitiveSpan> AllDetected,
    IReadOnlyList<SensitiveSpan> AboveThreshold,
    IReadOnlyList<SensitiveSpan> BelowThreshold,
    double Threshold
);
