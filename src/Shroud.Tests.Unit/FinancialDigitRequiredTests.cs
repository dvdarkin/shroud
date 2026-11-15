using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

/// <summary>
/// A financial numeric span (Amount, Quantity, Price) must contain at least one digit.
/// Several financial regexes use [\d,]+ and can otherwise match separator-only text.
/// </summary>
public class FinancialDigitRequiredTests
{
    private readonly SensitivityScanner _scanner = new(tokenizeThreshold: 0.0);

    private static bool IsNumericFinancial(SensitiveSpan s) =>
        s.Domain == SensitivityDomain.Financial &&
        s.EntityType is EntityType.Amount or EntityType.Quantity or EntityType.Price;

    [Theory]
    [InlineData("fee x, = 5 usd")]            // arithmetic_equals_left
    [InlineData("usd fee: total = , then")]   // arithmetic_equals_right
    [InlineData("usd fee x, * 2")]            // arithmetic_operand
    [InlineData("usd fee 2 * , x")]           // arithmetic_result
    [InlineData("usd fee x,,,, - 3")]         // arithmetic_sum_operand
    [InlineData("Paid $, then left")]         // symbol_amount
    [InlineData("Balance x, USD")]            // usd_code_amount
    [InlineData("Paid EUR , ok")]             // fiat_currency_amount
    [InlineData("Paid x, EUR ok")]            // fiat_amount_trailing
    [InlineData("filled at $,x price")]       // price_dollar
    [InlineData("filled at ,x price")]        // price_bare
    public void SeparatorOnlyText_IsNotAFinancialSpan(string text)
    {
        var result = _scanner.Scan(text);

        result.AllDetected.Where(IsNumericFinancial)
            .Should().OnlyContain(s => s.MatchedText.Any(char.IsDigit),
                "a financial numeric span must contain at least one digit");
    }

    [Fact]
    public void LoneComma_NearCurrencyWords_IsNotMasked()
    {
        var result = new SensitivityScanner().Scan("fee x, = 5 usd");

        result.AboveThreshold.Should().NotContain(s => s.MatchedText == ",");
        result.AboveThreshold.Should().Contain(s => s.MatchedText == "5" && s.EntityType == EntityType.Amount,
            "the real number is still detected");
    }

    [Fact]
    public void RealNumbers_InSameShapes_AreStillDetected()
    {
        var result = new SensitivityScanner().Scan("fee 1,250 = 5 usd and paid $1,200 and EUR 300");

        result.AboveThreshold.Should().Contain(s => s.MatchedText == "1,250");
        result.AboveThreshold.Should().Contain(s => s.MatchedText == "$1,200");
        result.AboveThreshold.Should().Contain(s => s.MatchedText == "EUR 300");
    }
}
