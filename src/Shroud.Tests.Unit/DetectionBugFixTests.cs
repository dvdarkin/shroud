using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

public class DetectionBugFixTests
{
    private readonly SensitivityScanner _scanner = new();

    [Fact]
    public void CommaNumber_WithAsset_DetectsFullNumber()
    {
        var result = _scanner.Scan("Deposited 15,000 USDC into the pool.");

        var assetMatch = result.AllDetected
            .Where(s => s.Domain == SensitivityDomain.Financial)
            .Where(s => s.MatchedText.Contains("15,000") || s.MatchedText.Contains("15,000 USDC"))
            .ToList();

        assetMatch.Should().NotBeEmpty("15,000 USDC should be detected as a full amount, not just '000'");

        result.AllDetected.Should().NotContain(s =>
            s.MatchedText == "000" && s.Domain == SensitivityDomain.Financial,
            "bare '000' should not be a standalone financial detection");
    }

    [Fact]
    public void PricePattern_AtWithoutDollar_NoFalsePositive()
    {
        var result = _scanner.Scan("The server runs at 512 MB of memory.");

        result.AboveThreshold.Should().NotContain(s =>
            s.EntityType == EntityType.Price && s.MatchedText.Contains("512"),
            "'at 512 MB' should not be detected as a price");
    }

    [Fact]
    public void PricePattern_AtWithDollar_StillDetects()
    {
        var result = _scanner.Scan("Filled the order at $512 per unit.");

        result.AllDetected.Should().Contain(s =>
            s.EntityType == EntityType.Price && s.MatchedText.Contains("$512"),
            "'at $512' should still be detected as a price");
    }

    [Fact]
    public void Arithmetic_DistantDollarSign_NoFalsePositive()
    {
        var padding = new string('x', 100);
        var text = $"The formula is 10 / 2 = 5. {padding} The cost was $50.";

        var result = _scanner.Scan(text);

        var arithmeticNearFormula = result.AboveThreshold
            .Where(s => s.Service is "arithmetic_operand" or "arithmetic_result")
            .Where(s => s.Start < 30)
            .ToList();

        arithmeticNearFormula.Should().BeEmpty(
            "arithmetic near 'The formula is 10 / 2' should not trigger when '$' is 100+ chars away");
    }

    [Fact]
    public void Arithmetic_NearCurrencyContext_StillDetects()
    {
        var result = _scanner.Scan("Profit calculation: $1,234.56+500.00+100.00=1,834.56 USD");

        result.AllDetected.Should().Contain(s =>
            s.Domain == SensitivityDomain.Financial,
            "arithmetic with adjacent currency context should still detect");
    }

    [Fact]
    public void VerbQuantity_PreservesVerb()
    {
        var result = _scanner.Scan("bought 100 NVDA for cash");

        // "bought" should NOT be part of the matched text
        var verbMatch = result.AllDetected
            .FirstOrDefault(s => s.Service == "verb_quantity");

        verbMatch.Should().NotBeNull("verb_quantity should detect the number");
        verbMatch!.MatchedText.Should().NotContain("bought",
            "the verb should not be captured — only the number");
        verbMatch.MatchedText.Should().Be("100");
    }

    [Fact]
    public void DateNumber_NotDetectedAsQuantity()
    {
        var result = _scanner.Scan("17 JUL 2025 was a good day");

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "17" && s.Domain == SensitivityDomain.Financial,
            "day-of-month before a month name should not be a financial quantity");
    }

    [Fact]
    public void Timestamp_ComponentsNotDetected()
    {
        var result = _scanner.Scan("April 8, 2025 at 10:36:54 AM GMT+3\n\nbought 100 NVDA");

        // Time components (8, 10, 36, 54, 3) should not be detected
        var timestampFP = result.AboveThreshold
            .Where(s => s.Service == "large_number")
            .Where(s => s.MatchedText is "8" or "10" or "36" or "54" or "3")
            .ToList();

        timestampFP.Should().BeEmpty(
            "timestamp components should not be detected as financial quantities");

        // The actual financial data should still be detected
        result.AboveThreshold.Should().Contain(s =>
            s.MatchedText == "100",
            "'100' (the quantity) should still be detected");
    }
}
