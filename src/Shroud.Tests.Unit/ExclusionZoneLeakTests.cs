using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

/// <summary>
/// Exclusion zones must not hide secrets that are not really metadata:
/// front matter only at offset 0, metadata keys only as whole words.
/// </summary>
public class ExclusionZoneLeakTests
{
    private const string AddrA = "0x1111111111111111111111111111111111111111";
    private const string AddrB = "0x2222222222222222222222222222222222222222";
    private const string GithubPat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private readonly SensitivityScanner _scanner = new();

    private bool Detects(string text, string value) =>
        _scanner.Scan(text).AboveThreshold.Any(s => s.MatchedText == value);

    // ---- Fix 1: front matter only at the very start of the text ----

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void FrontMatter_AtOffsetZero_IsStillExcluded(string nl)
    {
        var text = $"---{nl}title: Notes{nl}wallet: {AddrA}{nl}---{nl}{nl}Body wallet: {AddrB}{nl}";

        Detects(text, AddrA).Should().BeFalse("a real front matter block at offset 0 is excluded");
        Detects(text, AddrB).Should().BeTrue("the body after the front matter is scanned");
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void HorizontalRules_MidDocument_DoNotHideSecrets(string nl)
    {
        var text = $"# Title{nl}{nl}Intro text.{nl}{nl}---{nl}{nl}Wallet: {AddrA}{nl}{nl}---{nl}{nl}Footer.{nl}";

        Detects(text, AddrA).Should().BeTrue("two horizontal rules are not front matter");
    }

    [Fact]
    public void FrontMatter_PrecededByBlankLine_IsNotFrontMatter()
    {
        var text = $"\n---\nwallet: {AddrA}\n---\n";

        Detects(text, AddrA).Should().BeTrue("front matter must start at offset 0");
    }

    [Fact]
    public void RulePairAfterRealFrontMatter_IsScanned()
    {
        var text = $"---\ntitle: x\n---\n\nText\n\n---\n\nwallet: {AddrB}\n\n---\n";

        Detects(text, AddrB).Should().BeTrue("only the first block at offset 0 is front matter");
    }

    [Fact]
    public void FrontMatter_EndsAtFirstClosingLine()
    {
        var text = $"---\ntitle: x\n---\nwallet: {AddrB}\n---\n";

        Detects(text, AddrB).Should().BeTrue("front matter ends at the next --- line");
    }

    [Fact]
    public void EmptyFrontMatter_DoesNotSwallowFollowingBlock()
    {
        var text = $"---\n---\nwallet: {AddrB}\n\n---\n";

        Detects(text, AddrB).Should().BeTrue("an empty front matter block ends at its own closing line");
    }

    // ---- Fix 2: metadata keys must be whole words ----

    [Theory]
    [InlineData("Your profile: " + AddrA, AddrA)]
    [InlineData("profile: " + AddrA, AddrA)]
    [InlineData("classpath: " + GithubPat, GithubPat)]
    [InlineData("my-file: " + AddrA, AddrA)]
    [InlineData("my_file: " + AddrA, AddrA)]
    [InlineData("Docfile: " + AddrA, AddrA)]
    [InlineData("file2path: " + AddrA, AddrA)]
    public void KeySubstringOfLongerWord_DoesNotHideLine(string line, string value)
    {
        Detects("## Notes\n\n" + line + "\n", value).Should().BeTrue(
            $"'{line}' is not a file-path metadata line");
    }

    [Theory]
    [InlineData(@"file: C:\wallets\" + AddrA)]
    [InlineData("FILE: wallet-" + AddrA + ".txt")]
    [InlineData("source_file: notes/" + AddrA + ".md")]
    [InlineData("path: /home/x/" + AddrA)]
    [InlineData("Attachment: " + AddrA)]
    [InlineData("- file: " + AddrA)]
    public void GenuineMetadataLine_IsStillExcluded(string line)
    {
        Detects("## Notes\n\n" + line + "\n", AddrA).Should().BeFalse(
            $"'{line}' is a genuine metadata line");
    }

    [Theory]
    [InlineData("file:\n" + AddrA + "\n")]
    [InlineData("path:   \n" + AddrA + "\n")]
    [InlineData("attachment:\r\n" + AddrA + "\r\n")]
    public void MetadataKeyAtEndOfLine_DoesNotHideTheNextLine(string text)
    {
        Detects("## Notes\n\n" + text, AddrA).Should().BeTrue(
            "a metadata key with nothing after it must not exclude the following line");
    }
}
