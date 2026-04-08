using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

public class OverlapDeduplicationTests
{
    private static SensitiveSpan MakeSpan(int start, int end, double confidence = 0.90,
        EntityType type = EntityType.CryptoAddr, string text = "match")
    {
        return new SensitiveSpan(start, end, type, SensitivityDomain.OnChain, confidence,
            text.Length == end - start ? text : new string('x', end - start));
    }

    [Fact]
    public void EmptyList_ReturnsEmpty()
    {
        var result = SensitivityScanner.DeduplicateOverlaps([]);
        result.Should().BeEmpty();
    }

    [Fact]
    public void SingleSpan_ReturnedAsIs()
    {
        var span = MakeSpan(0, 10);
        var result = SensitivityScanner.DeduplicateOverlaps([span]);

        result.Should().ContainSingle();
        result[0].Should().Be(span);
    }

    [Fact]
    public void NoOverlaps_AllReturned()
    {
        var span1 = MakeSpan(0, 5);
        var span2 = MakeSpan(10, 15);
        var span3 = MakeSpan(20, 25);

        var result = SensitivityScanner.DeduplicateOverlaps([span1, span2, span3]);

        result.Should().HaveCount(3);
    }

    [Fact]
    public void FullContainment_ContainerWins()
    {
        var container = MakeSpan(0, 20, confidence: 0.50);
        var contained = MakeSpan(5, 15, confidence: 0.95);

        var result = SensitivityScanner.DeduplicateOverlaps([container, contained]);

        result.Should().ContainSingle();
        result[0].Start.Should().Be(0);
        result[0].End.Should().Be(20);
    }

    [Fact]
    public void PartialOverlap_LongerWins()
    {
        var longer = MakeSpan(0, 15, confidence: 0.50);
        var shorter = MakeSpan(10, 20, confidence: 0.95);

        var result = SensitivityScanner.DeduplicateOverlaps([longer, shorter]);

        result.Should().ContainSingle();
        result[0].Start.Should().Be(0);
        result[0].Length.Should().Be(15);
    }

    [Fact]
    public void EqualLength_HigherConfidenceWins()
    {
        var high = MakeSpan(0, 10, confidence: 0.95);
        var low = MakeSpan(5, 15, confidence: 0.50);

        var result = SensitivityScanner.DeduplicateOverlaps([high, low]);

        result.Should().ContainSingle();
        result[0].Confidence.Should().Be(0.95);
    }

    [Fact]
    public void EqualLengthEqualConfidence_FirstInSortOrderWins()
    {
        var span1 = MakeSpan(0, 10, confidence: 0.90, text: "aaaaaaaaaa");
        var span2 = MakeSpan(5, 15, confidence: 0.90, text: "bbbbbbbbbb");

        var result = SensitivityScanner.DeduplicateOverlaps([span1, span2]);

        result.Should().ContainSingle("equal length and confidence should still deduplicate");
    }

    [Fact]
    public void ContainerRemovesPreviouslyAcceptedSmaller()
    {
        var small = MakeSpan(5, 10, confidence: 0.95);
        var large = MakeSpan(0, 30, confidence: 0.50);

        var result = SensitivityScanner.DeduplicateOverlaps([small, large]);

        result.Should().ContainSingle();
        result[0].Start.Should().Be(0);
        result[0].End.Should().Be(30);
    }

    [Fact]
    public void ThreeWayOverlap_CorrectResolution()
    {
        var a = MakeSpan(0, 20, confidence: 0.90);
        var b = MakeSpan(5, 15, confidence: 0.95);
        var c = MakeSpan(12, 25, confidence: 0.85);

        var result = SensitivityScanner.DeduplicateOverlaps([a, b, c]);

        result.Should().ContainSingle();
        result[0].Start.Should().Be(0);
        result[0].End.Should().Be(20);
    }

    [Fact]
    public void Result_SortedByStartPosition()
    {
        var span1 = MakeSpan(20, 30);
        var span2 = MakeSpan(0, 5);
        var span3 = MakeSpan(10, 15);

        var result = SensitivityScanner.DeduplicateOverlaps([span1, span2, span3]);

        result.Should().HaveCount(3);
        result[0].Start.Should().Be(0);
        result[1].Start.Should().Be(10);
        result[2].Start.Should().Be(20);
    }

    [Fact]
    public void AdjacentSpans_NotDeduped()
    {
        var span1 = MakeSpan(0, 10);
        var span2 = MakeSpan(10, 20);

        var result = SensitivityScanner.DeduplicateOverlaps([span1, span2]);

        result.Should().HaveCount(2, "adjacent non-overlapping spans should both survive");
    }

    [Fact]
    public void DiagnosticsPopulated_WhenProvided()
    {
        var container = MakeSpan(0, 20, confidence: 0.90);
        var contained = MakeSpan(5, 15, confidence: 0.95);
        var diagnostics = new ScanDiagnostics();

        var result = SensitivityScanner.DeduplicateOverlaps([container, contained], diagnostics);

        result.Should().ContainSingle();
        diagnostics.OverlapResolutions.Should().ContainSingle();
        diagnostics.OverlapResolutions[0].Reason.Should().Be("contained");
    }
}
