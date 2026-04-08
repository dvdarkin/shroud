using FluentAssertions;
using Shroud.Masking;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

public class SpanMaskerTests
{
    private static readonly byte[] TestKey = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    private static readonly byte[] AltKey = new byte[]
    {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
        0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0
    };

    [Fact]
    public void Determinism_SameInputSameKey_SameTokens()
    {
        var masker = new SpanMasker(TestKey);
        var text = "Send to 0x1111111111111111111111111111111111111111 now";
        var span = MakeSpan(8, 50, EntityType.CryptoAddr, "0x1111111111111111111111111111111111111111");
        var scanResult = MakeScanResult(span);

        var result1 = masker.Mask(text, scanResult);
        var result2 = masker.Mask(text, scanResult);

        result1.MaskedText.Should().Be(result2.MaskedText);
        result1.Tokens[0].TokenId.Should().Be(result2.Tokens[0].TokenId);
    }

    [Fact]
    public void DifferentKeys_DifferentTokenIds()
    {
        var text = "Send to 0x1111111111111111111111111111111111111111 now";
        var span = MakeSpan(8, 50, EntityType.CryptoAddr, "0x1111111111111111111111111111111111111111");
        var scanResult = MakeScanResult(span);

        var result1 = new SpanMasker(TestKey).Mask(text, scanResult);
        var result2 = new SpanMasker(AltKey).Mask(text, scanResult);

        result1.Tokens[0].TokenId.Should().NotBe(result2.Tokens[0].TokenId);
    }

    [Fact]
    public void TokenFormat_MatchesExpectedPattern()
    {
        var masker = new SpanMasker(TestKey);
        var text = "Key: 0x1111111111111111111111111111111111111111";
        var span = MakeSpan(5, 47, EntityType.CryptoAddr, "0x1111111111111111111111111111111111111111");
        var scanResult = MakeScanResult(span);

        var result = masker.Mask(text, scanResult);

        result.Tokens[0].TokenId.Should().MatchRegex(@"^ADDR:[0-9a-f]{8}$");
        result.MaskedText.Should().MatchRegex(@"\[ADDR:[0-9a-f]{8}\]");
    }

    [Fact]
    public void EmptyAboveThreshold_TextUnchanged()
    {
        var masker = new SpanMasker(TestKey);
        var text = "Nothing sensitive here";
        var scanResult = new ScanResult(
            AllDetected: new List<SensitiveSpan>(),
            AboveThreshold: new List<SensitiveSpan>(),
            BelowThreshold: new List<SensitiveSpan>(),
            Threshold: 0.70);

        var result = masker.Mask(text, scanResult);

        result.MaskedText.Should().Be(text);
        result.Tokens.Should().BeEmpty();
    }

    [Fact]
    public void MultipleSpans_AllReplacedCorrectly()
    {
        var masker = new SpanMasker(TestKey);
        var text = "Send $500 to addr@test.com today";
        var spans = new List<SensitiveSpan>
        {
            MakeSpan(5, 9, EntityType.Amount, "$500"),
            MakeSpan(13, 26, EntityType.Email, "addr@test.com")
        };
        var scanResult = new ScanResult(
            AllDetected: spans,
            AboveThreshold: spans,
            BelowThreshold: new List<SensitiveSpan>(),
            Threshold: 0.70);

        var result = masker.Mask(text, scanResult);

        result.MaskedText.Should().NotContain("$500");
        result.MaskedText.Should().NotContain("addr@test.com");
        result.Tokens.Should().HaveCount(2);
        result.MaskedText.Should().StartWith("Send ");
        result.MaskedText.Should().EndWith(" today");
    }

    [Fact]
    public void PositionCorrectness_RightToLeftPreservesIndices()
    {
        var masker = new SpanMasker(TestKey);
        var text = "A 123 B 456 C";
        var span1 = MakeSpan(2, 5, EntityType.Amount, "123");
        var span2 = MakeSpan(8, 11, EntityType.Amount, "456");
        var scanResult = new ScanResult(
            AllDetected: new List<SensitiveSpan> { span1, span2 },
            AboveThreshold: new List<SensitiveSpan> { span1, span2 },
            BelowThreshold: new List<SensitiveSpan>(),
            Threshold: 0.70);

        var result = masker.Mask(text, scanResult);

        result.MaskedText.Should().StartWith("A ");
        result.MaskedText.Should().Contain(" B ");
        result.MaskedText.Should().EndWith(" C");
        result.MaskedText.Should().NotContain("123");
        result.MaskedText.Should().NotContain("456");
    }

    [Fact]
    public void TypeAbbreviations_CorrectInTokens()
    {
        var masker = new SpanMasker(TestKey);
        var text = "SSN: 123-45-6789";
        var span = MakeSpan(5, 16, EntityType.Ssn, "123-45-6789");
        var scanResult = MakeScanResult(span);

        var result = masker.Mask(text, scanResult);

        result.Tokens[0].TokenId.Should().StartWith("SSN:");
    }

    // --- Helpers ---

    private static SensitiveSpan MakeSpan(int start, int end, EntityType type, string text,
        SensitivityDomain domain = SensitivityDomain.OnChain, double confidence = 0.90)
    {
        return new SensitiveSpan(start, end, type, domain, confidence, text);
    }

    private static ScanResult MakeScanResult(params SensitiveSpan[] spans)
    {
        var list = spans.ToList();
        return new ScanResult(
            AllDetected: list,
            AboveThreshold: list,
            BelowThreshold: new List<SensitiveSpan>(),
            Threshold: 0.70);
    }
}
