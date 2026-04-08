using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using System.Text.RegularExpressions;
using Xunit;

namespace Shroud.Tests.Unit;

public class ContextScorerTests
{
    private static SensitivityPattern MakePattern(
        double baseConfidence, string[] contextWords, double contextBoost,
        SensitivityDomain domain = SensitivityDomain.OnChain)
    {
        return new SensitivityPattern(
            EntityType.CryptoAddr, domain,
            new Regex(@"\bTEST\b"), baseConfidence, contextWords, contextBoost, "test_pattern");
    }

    private static SensitiveSpan MakeSpan(int start, int end,
        SensitivityDomain domain = SensitivityDomain.OnChain)
    {
        return new SensitiveSpan(start, end, EntityType.CryptoAddr, domain, 0, "TEST");
    }

    [Fact]
    public void NoContextWords_ReturnsBaseConfidence()
    {
        var pattern = MakePattern(0.90, [], 0);
        var text = "some text TEST more text";
        var span = MakeSpan(10, 14);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.90);
    }

    [Fact]
    public void SingleContextWord_AppliesContextBoost()
    {
        var pattern = MakePattern(0.30, ["solana"], 0.55);
        var text = "solana address: TEST here";
        var span = MakeSpan(16, 20);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.55);
    }

    [Fact]
    public void MultipleContextWords_AdditionalBoostCapped()
    {
        var pattern = MakePattern(0.30, ["word1", "word2", "word3", "word4", "word5"], 0.20);
        var text = "word1 word2 word3 word4 word5 TEST here";
        var span = MakeSpan(30, 34);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.20 + ContextScorer.AdditionalContextWordBoost * ContextScorer.MaxAdditionalContextWords);
    }

    [Fact]
    public void TwoContextWords_OneAdditionalBoost()
    {
        var pattern = MakePattern(0.30, ["word1", "word2"], 0.20);
        var text = "word1 word2 TEST here";
        var span = MakeSpan(12, 16);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.20 + ContextScorer.AdditionalContextWordBoost);
    }

    [Fact]
    public void ScoreCapped_AtOne()
    {
        var pattern = MakePattern(0.80, ["word1", "word2", "word3", "word4", "word5"], 0.50);
        var text = "word1 word2 word3 word4 word5 TEST here";
        var span = MakeSpan(30, 34);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(1.0);
    }

    [Fact]
    public void ContextWord_AtEdgeOfWindow_Found()
    {
        var padding = new string('x', 120 - "solana".Length);
        var text = $"solana{padding}TEST";
        var span = MakeSpan(text.Length - 4, text.Length);
        var pattern = MakePattern(0.30, ["solana"], 0.55);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().BeGreaterThan(0.30, "context word within 120 chars should be found");
    }

    [Fact]
    public void ContextWord_BeyondWindow_NotFound()
    {
        var padding = new string('x', 121);
        var text = $"solana{padding}TEST";
        var span = MakeSpan(text.Length - 4, text.Length);
        var pattern = MakePattern(0.30, ["solana"], 0.55);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30, "context word beyond 120 chars should not be found");
    }

    [Fact]
    public void CaseInsensitive_ContextMatching()
    {
        var pattern = MakePattern(0.30, ["USD"], 0.55);

        var text1 = "USD TEST here";
        var text2 = "usd TEST here";
        var text3 = "Usd TEST here";
        var span = MakeSpan(4, 8);

        var score1 = ContextScorer.Score(span, pattern, text1);
        var score2 = ContextScorer.Score(span, pattern, text2);
        var score3 = ContextScorer.Score(span, pattern, text3);

        score1.Should().Be(score2);
        score2.Should().Be(score3);
    }

    [Fact]
    public void FinancialDomain_AssetNameBoost_NonCumulative()
    {
        var pattern = MakePattern(0.30, ["position"], 0.20, SensitivityDomain.Financial);
        var text = "BTC ETH position TEST here";
        var span = MakeSpan(21, 25, SensitivityDomain.Financial);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.20 + ContextScorer.AssetNameBoost);
    }

    [Fact]
    public void FinancialDomain_CurrencySignalBoost_NonCumulative()
    {
        var pattern = MakePattern(0.30, ["position"], 0.20, SensitivityDomain.Financial);
        var text = "usd eur position TEST here";
        var span = MakeSpan(21, 25, SensitivityDomain.Financial);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.20 + ContextScorer.CurrencySignalBoost);
    }

    [Fact]
    public void NonFinancialDomain_AssetCurrencyBoosts_DontApply()
    {
        var pattern = MakePattern(0.30, ["solana"], 0.55, SensitivityDomain.OnChain);
        var text = "BTC USD solana $ TEST here";
        var span = MakeSpan(21, 25, SensitivityDomain.OnChain);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30 + 0.55);
    }

    [Fact]
    public void SubstringMatch_DocumentedBehavior()
    {
        var pattern = MakePattern(0.30, ["sol"], 0.55);
        var text = "solution TEST here";
        var span = MakeSpan(9, 13);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().BeGreaterThan(0.30,
            "substring matching is current behavior: 'sol' matches inside 'solution'");
    }

    [Fact]
    public void NoContextWordsFound_NoBoost()
    {
        var pattern = MakePattern(0.30, ["solana", "phantom"], 0.55);
        var text = "nothing relevant TEST here";
        var span = MakeSpan(18, 22);

        var score = ContextScorer.Score(span, pattern, text);

        score.Should().Be(0.30);
    }

    [Fact]
    public void InternalOverload_ReturnsScoringDetail()
    {
        var pattern = MakePattern(0.30, ["solana", "phantom"], 0.55);
        var text = "solana phantom TEST here";
        var span = MakeSpan(15, 19);

        var score = ContextScorer.Score(span, pattern, text, out var detail);

        detail.BaseConfidence.Should().Be(0.30);
        detail.FinalConfidence.Should().Be(score);
        detail.IsStructural.Should().BeFalse();
        detail.ContextWordsFound.Should().Contain("solana");
        detail.ContextWordsFound.Should().Contain("phantom");
    }
}
