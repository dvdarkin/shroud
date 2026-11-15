using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

/// <summary>
/// Exclusion zones must not hide secrets that are not really metadata:
/// front matter only at offset 0, metadata keys only at a line start or after a space, tab or "(".
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
    [InlineData("(path: " + AddrA + ")")]
    [InlineData("  file: " + AddrA)]
    [InlineData("\tpath: " + AddrA)]
    [InlineData("see (attachment: " + AddrA + ")")]
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

    // ---- Fix A: a key is metadata only at a line start or after a space, a tab or "(" ----

    [Theory]
    [InlineData("e\u0301")]       // combining acute accent (Mn)
    [InlineData("\u200D")]        // ZERO WIDTH JOINER
    [InlineData("\u200C")]        // ZERO WIDTH NON-JOINER
    [InlineData("\U0001D400")]    // MATHEMATICAL BOLD CAPITAL A (non-BMP letter, a surrogate pair)
    [InlineData("\U0001F600")]    // emoji (surrogate pair)
    [InlineData("|")]
    [InlineData(">")]
    [InlineData("\"")]
    [InlineData("[")]
    [InlineData("*")]
    [InlineData("`")]
    [InlineData("<")]
    [InlineData(".")]
    [InlineData("\u00A0")]        // NO-BREAK SPACE is not one of the allowed separators
    public void KeyGluedToAnyOtherCharacter_DoesNotHideLine(string glue)
    {
        foreach (var key in new[] { "file:", "FILE:", "path:", "source_file:", "attachment:" })
        {
            var line = glue + key + " " + AddrA;
            Detects("## Notes\n\n" + line + "\n", AddrA).Should().BeTrue(
                $"'{line}' is ordinary text: the key is not at a line start or after a space, tab or '('");
        }
    }

    [Theory]
    [InlineData("x\rfile: " + AddrA + "\r")]
    [InlineData("## Notes\rpath: " + AddrA + "\r")]
    public void KeyAfterLoneCarriageReturn_IsScanned(string text)
    {
        // Multiline ^ matches only at the start of the text and after "\n", so with lone-CR line
        // endings a key after "\r" is not at a line start: the line is scanned.
        Detects(text, AddrA).Should().BeTrue("a key preceded by a lone CR is not a metadata key");
    }

    [Fact]
    public void KeyAtStartOfText_IsStillExcluded()
    {
        Detects("file: " + AddrA + "\n", AddrA).Should().BeFalse("offset 0 is a line start");
    }

    [Theory]
    [InlineData("file: notes.md\rwallet " + AddrA + "\r")]
    [InlineData("file: notes.md\rwallet " + AddrA + "\r\n")]
    [InlineData("- path: notes.md\rsecond line\rthird " + AddrA + "\n")]
    public void MetadataZone_EndsAtALoneCarriageReturn(string text)
    {
        Detects(text, AddrA).Should().BeTrue(
            "a metadata line ends at the first CR or LF; later lone-CR lines are scanned");
    }

    [Theory]
    [InlineData("file: " + AddrA + "\r\nnext line\r\n")]
    [InlineData("file: " + AddrA + "\rnext line\r")]
    public void MetadataValue_BeforeACarriageReturn_IsStillExcluded(string text)
    {
        Detects(text, AddrA).Should().BeFalse("the value on the key's own line stays excluded");
    }
}
