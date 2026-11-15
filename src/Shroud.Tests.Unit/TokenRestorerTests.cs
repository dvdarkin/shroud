using FluentAssertions;
using Shroud.Vault;
using Xunit;

namespace Shroud.Tests.Unit;

public class TokenRestorerTests
{
    [Fact]
    public void Restore_ReplacesEveryOccurrenceOfKnownTokens()
    {
        var tokens = new Dictionary<string, string> { ["ADDR:11111111"] = "0xabc", ["AMT:22222222"] = "$5" };

        var text = TokenRestorer.Restore("[ADDR:11111111] paid [AMT:22222222] to [ADDR:11111111]", tokens, out var unresolved);

        text.Should().Be("0xabc paid $5 to 0xabc");
        unresolved.Should().Be(0);
    }

    [Fact]
    public void Restore_ValueContainingAnotherTokensMarker_IsRestoredVerbatim()
    {
        // The sequential string.Replace this replaces expanded the inner marker a second time.
        var tokens = new Dictionary<string, string>
        {
            ["PASSWD:11111111"] = "password=[AMT:22222222]",
            ["AMT:22222222"] = "$5",
        };

        TokenRestorer.Restore("[PASSWD:11111111] and [AMT:22222222]", tokens)
            .Should().Be("password=[AMT:22222222] and $5");
    }

    [Fact]
    public void Restore_UnknownTokens_AreLeftInPlaceAndCounted()
    {
        var tokens = new Dictionary<string, string> { ["ADDR:11111111"] = "0xabc" };

        var text = TokenRestorer.Restore("[ADDR:11111111] [ADDR:99999999] [KEY:0000aaaa]", tokens, out var unresolved);

        text.Should().Be("0xabc [ADDR:99999999] [KEY:0000aaaa]");
        unresolved.Should().Be(2);
    }

    [Fact]
    public void Restore_OrdinaryBrackets_AreNotCountedAsTokens()
    {
        var tokens = new Dictionary<string, string> { ["ADDR:11111111"] = "0xabc" };

        var text = TokenRestorer.Restore("[link](url) [x] [TODO: later] [[ADDR:11111111]] [ADDR:1111111", tokens, out var unresolved);

        text.Should().Be("[link](url) [x] [TODO: later] [0xabc] [ADDR:1111111");
        unresolved.Should().Be(0);
    }

    [Fact]
    public void MaskThenRestore_InMemory_RoundTrips_AsInTheCookbook()
    {
        var scanner = new Shroud.Detection.SensitivityScanner(Shroud.Models.ShroudConfig.ForPreset("dev"));
        var masker = new Shroud.Masking.SpanMasker(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        const string text = "send 0x52908400098527886E0F7030069857D2E4169EE7 to bob@example.com, again bob@example.com";

        var masked = masker.Mask(text, scanner.Scan(text));
        var tokens = new Dictionary<string, string>();
        foreach (var t in masked.Tokens) tokens[t.TokenId] = t.OriginalValue;

        masked.MaskedText.Should().NotContain("0x5290").And.NotContain("bob@example.com");
        TokenRestorer.Restore("reply: " + masked.MaskedText, tokens).Should().Be("reply: " + text);
    }

    [Fact]
    public void Restore_NullValue_RestoresAsEmpty()
    {
        var tokens = new Dictionary<string, string> { ["ADDR:11111111"] = null! };

        TokenRestorer.Restore("a[ADDR:11111111]b", tokens).Should().Be("ab");
    }
}
