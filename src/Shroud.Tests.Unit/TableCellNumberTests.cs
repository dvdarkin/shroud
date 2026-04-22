using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

public class TableCellNumberTests
{
    private readonly SensitivityScanner _scanner = new();

    [Fact]
    public void BareIntegerInFinancialTableRow_Detected()
    {
        // Representative of the Binance order-history paste in the user's trading-diary:
        // small integer amounts sit alone in table cells, with column headers (Amount,
        // Price, Total) far up in the file beyond the context window. The only in-window
        // signals are row neighbours: Limit, Buy, QTY placeholders, the asset URL.
        var row = "| 2026-04-20 12:17:52 | [TRX_USDT?type=spot] | Limit | Buy | 0.12 | 0.12 | 30 | 30 | 0 | 3.6 | Filled |";

        var result = _scanner.Scan(row);

        result.AboveThreshold.Should().Contain(s => s.MatchedText == "30",
            "bare integer 30 in a table cell with Limit/Buy/Filled context should be masked");
    }

    [Fact]
    public void BareZeroInFinancialTableRow_Detected()
    {
        var row = "| Limit | Buy | [QTY:aaaa1111] | [QTY:aaaa2222] | 0 | [QTY:aaaa3333] | Filled | USDT |";

        var result = _scanner.Scan(row);

        result.AboveThreshold.Should().Contain(s => s.MatchedText == "0",
            "bare 0 in a Total-column cell surrounded by trading signals should be masked");
    }

    [Fact]
    public void BareNumberInNonFinancialTable_NotDetected()
    {
        // A schedule/inventory table without trading context. Must NOT fire or we get
        // false positives on every markdown table in the user's vault.
        var text = "| Task | Hours |\n| ---- | ----- |\n| write | 3 |\n| review | 2 |";

        var result = _scanner.Scan(text);

        result.AboveThreshold.Should().NotContain(s =>
            s.MatchedText == "3" || s.MatchedText == "2",
            "bare numbers in a non-financial table must stay below threshold");
    }

    [Fact]
    public void TableCellDecimal_Detected()
    {
        var row = "| Limit | Buy | 0.5 | price | USDT |";

        var result = _scanner.Scan(row);

        result.AboveThreshold.Should().Contain(s => s.MatchedText == "0.5",
            "decimals in table cells with financial context should be masked");
    }

    [Fact]
    public void TableCellCommaFormatted_Detected()
    {
        var row = "| Limit | Buy | 1,234 | price | USDT |";

        var result = _scanner.Scan(row);

        result.AboveThreshold.Should().Contain(s => s.MatchedText.Contains("1,234"),
            "comma-formatted numbers in table cells should be masked");
    }
}
