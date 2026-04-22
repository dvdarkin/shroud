using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

public class DateTimeExclusionTests
{
    private readonly SensitivityScanner _scanner = new();

    [Theory]
    [InlineData("2026-04-20")]
    [InlineData("2019-12-31")]
    [InlineData("1999-01-01")]
    [InlineData("2026-04-20T17:30:34")]
    [InlineData("2026-04-20 17:30:34")]
    [InlineData("2026-04-20T17:30:34.123Z")]
    [InlineData("2026-04-20T17:30:34+02:00")]
    public void IsoDate_NotDetectedAsAmount(string date)
    {
        // Surround with USD/trading context so any stray year-pattern would otherwise fire.
        var text = $"Filled on {date} for USDC deposit";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "2026" || s.MatchedText == "2019" || s.MatchedText == "1999",
            "date components inside an ISO date should not be detected as amounts");
    }

    [Theory]
    [InlineData("04/20/2026")]
    [InlineData("4-20-2026")]
    [InlineData("4.20.26")]
    [InlineData("20/04/2026")]
    [InlineData("20-04-2026")]
    public void NumericDate_NotDetectedAsAmount(string date)
    {
        var text = $"Trade executed {date} for USDC profit";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "2026" || s.MatchedText == "26",
            "year in slash/dash-separated date should be excluded");
    }

    [Theory]
    [InlineData("20 Apr 2026")]
    [InlineData("April 20, 2026")]
    [InlineData("Apr 20 2026")]
    [InlineData("Jan 2026")]
    public void MonthNameDate_NotDetectedAsAmount(string date)
    {
        var text = $"Position opened {date} in USDC";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "2026",
            "year in month-name date should be excluded");
    }

    [Theory]
    [InlineData("17:30:34")]
    [InlineData("14:25")]
    [InlineData("5:00")]
    [InlineData("5pm")]
    [InlineData("11:45 AM")]
    [InlineData("5:30pm")]
    public void Time_NotDetectedAsQuantity(string time)
    {
        var text = $"Entry at {time} for trading USDC position";

        var result = _scanner.Scan(text);

        // Above threshold in Financial domain would indicate a false positive from the time digits.
        // Allow above-threshold ONLY if the span extends beyond the time tokens.
        var financialMatches = result.AboveThreshold
            .Where(s => s.Domain == SensitivityDomain.Financial)
            .ToList();

        foreach (var match in financialMatches)
        {
            match.MatchedText.Should().NotBe("17", "time digits should be excluded");
            match.MatchedText.Should().NotBe("30", "time digits should be excluded");
            match.MatchedText.Should().NotBe("34", "time digits should be excluded");
            match.MatchedText.Should().NotBe("14", "time digits should be excluded");
            match.MatchedText.Should().NotBe("45", "time digits should be excluded");
        }
    }

    [Fact]
    public void IsoWeek_NotDetectedAsAmount()
    {
        var text = "Sprint 2026-W17 closed out USDC positions";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "2026" || s.MatchedText == "17",
            "ISO week components should be excluded");
    }

    [Fact]
    public void BareYear_NotDetectedAsAmount()
    {
        // "2026" alone with surrounding trading context used to match arithmetic_sum_operand
        // (4-digit number followed by "-") and cross the 0.70 threshold.
        var text = "2026-04-20 17:30:34 | ETH_USDC | Buy | 100 USDC";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "2026",
            "bare year should never appear as a financial amount");
    }

    // Positive cases: the exclusion zones must NOT mask out truly sensitive amounts
    // that happen to include or abut year-like digits.

    [Fact]
    public void SymbolAmount_Year_StillDetected()
    {
        var text = "Bought for $2026 total";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().Contain(s =>
            s.EntityType == EntityType.Amount && s.MatchedText == "$2026",
            "$2026 extends past the 4-char year zone and must still be masked");
    }

    [Fact]
    public void AssetQuantity_YearDigits_StillDetected()
    {
        var text = "Wallet holds 2026 USDC at entry";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().Contain(s =>
            s.Domain == SensitivityDomain.Financial &&
            s.MatchedText.Contains("2026") && s.MatchedText.Contains("USDC"),
            "2026 USDC is an asset-adjacent quantity and must still be masked");
    }

    [Fact]
    public void UsdCodeAmount_Year_StillDetected()
    {
        var text = "Paid 2026 USD to vendor";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().Contain(s =>
            s.EntityType == EntityType.Amount && s.MatchedText.Contains("2026") && s.MatchedText.Contains("USD"),
            "2026 USD extends past the year zone and must still be masked");
    }

    [Fact]
    public void InvalidDate_NotExcluded()
    {
        // 2026-15 is not a valid year-month (month > 12), so the year-month regex should
        // not match and the year zone should be the only exclusion. An amount-like
        // pattern that happens to overlap still has to be checked.
        var text = "ID tag 2026-15 with 15,000 USDC deposit";

        var result = _scanner.Scan(text);

        // "15,000 USDC" should still detect regardless.
        result.AboveThreshold.Should().Contain(s =>
            s.Domain == SensitivityDomain.Financial && s.MatchedText.Contains("15,000"),
            "real amount after a non-date string should still be detected");
    }
}
