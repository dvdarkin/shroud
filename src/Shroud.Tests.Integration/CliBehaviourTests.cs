using System.Globalization;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Shroud.Tests.Integration;

/// <summary>
/// The CLI reads shroud.json and .shroud/vault.key relative to the current directory and
/// writes to Console, both process-global, so these tests never run in parallel with others.
/// </summary>
[CollectionDefinition("Cli", DisableParallelization = true)]
public class CliCollection;

[Collection("Cli")]
public class CliBehaviourTests : IDisposable
{
    private readonly string _dir;
    private readonly string _oldCwd;

    public CliBehaviourTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"shroud-cli-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _oldCwd = Directory.GetCurrentDirectory();
        Directory.SetCurrentDirectory(_dir);
    }

    public void Dispose()
    {
        Directory.SetCurrentDirectory(_oldCwd);
        Shroud.Cli.Program.VaultMaskingKeyOverride = null;
        if (Directory.Exists(_dir)) Directory.Delete(_dir, true);
    }

    private static (int Exit, string Out, string Err) Run(params string[] args)
    {
        var oldOut = Console.Out;
        var oldErr = Console.Error;
        var o = new StringWriter();
        var e = new StringWriter();
        Console.SetOut(o);
        Console.SetError(e);
        try
        {
            var exit = Shroud.Cli.Program.Main(args);
            return (exit, o.ToString(), e.ToString());
        }
        finally
        {
            Console.SetOut(oldOut);
            Console.SetError(oldErr);
        }
    }

    // ---- Fix 6 (CLI side) ----

    [Fact]
    public void Vault_TokenCollision_PrintsOneLineError_ExitsNonZero_WritesNothing()
    {
        Directory.CreateDirectory("src");
        const string a = "ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF71177";
        const string b = "ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF105486";
        File.WriteAllText(Path.Combine("src", "a.md"), $"first {a}\nsecond {b}\n");
        Shroud.Cli.Program.VaultMaskingKeyOverride = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        var (exit, stdout, stderr) = Run("vault", "src", "-p", "pw", "-o", "out");

        exit.Should().NotBe(0);
        var errorLines = stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        errorLines.Should().ContainSingle().Which.Should().Contain("TOKEN:908a4613");
        (stdout + stderr).Should().NotContain(a).And.NotContain(b);
        Directory.Exists("out").Should().BeFalse();
    }

    // ---- Fix 7 (relative source) ----

    [Fact]
    public void Vault_DotSource_ManifestSourceIsTheResolvedDirectoryName()
    {
        var project = Path.Combine(_dir, "alice-project");
        Directory.CreateDirectory(project);
        File.WriteAllText(Path.Combine(project, "a.md"), "wallet 0x1111111111111111111111111111111111111111\n");
        Directory.SetCurrentDirectory(project);

        var (exit, _, _) = Run("vault", ".", "-p", "pw", "-o", Path.Combine(_dir, "out"));

        exit.Should().Be(0);
        var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(_dir, "out", "manifest.json")));
        manifest.RootElement.GetProperty("source").GetString().Should().Be("alice-project");
    }

    // ---- Fix 8 ----

    [Fact]
    public void Mask_SeveralInputsWithOutputFile_IsRefused_BeforeWritingAnything()
    {
        const string a = "wallet 0x1111111111111111111111111111111111111111\n";
        const string b = "wallet 0x2222222222222222222222222222222222222222\n";
        File.WriteAllText("a.md", a);
        File.WriteAllText("b.md", b);

        var (exit, _, stderr) = Run("mask", "a.md", "b.md", "-o", "out.md");

        exit.Should().NotBe(0);
        stderr.Should().Contain("-o");
        File.Exists("out.md").Should().BeFalse();
        File.ReadAllText("a.md").Should().Be(a);
        File.ReadAllText("b.md").Should().Be(b);
        Directory.Exists(".shroud").Should().BeFalse("no key file is generated either");
    }

    [Fact]
    public void Mask_GlobExpandingToSeveralFilesWithOutputFile_IsRefused()
    {
        File.WriteAllText("a.md", "wallet 0x1111111111111111111111111111111111111111\n");
        File.WriteAllText("b.md", "wallet 0x2222222222222222222222222222222222222222\n");

        var (exit, _, _) = Run("mask", "*.md", "-o", "out.md");

        exit.Should().NotBe(0);
        File.Exists("out.md").Should().BeFalse();
    }

    [Fact]
    public void Mask_SingleInputWithOutputFile_StillWorks()
    {
        File.WriteAllText("a.md", "wallet 0x1111111111111111111111111111111111111111\n");

        var (exit, _, _) = Run("mask", "a.md", "-o", "out.md");

        exit.Should().Be(0);
        File.ReadAllText("out.md").Should().StartWith("wallet [ADDR:");
    }

    // ---- Fix 9 ----

    [Fact]
    public void Init_UnknownPreset_FailsListingValidPresets_WritesNothing()
    {
        var (exit, stdout, stderr) = Run("init", "--preset", "bogus");

        exit.Should().NotBe(0);
        File.Exists("shroud.json").Should().BeFalse();
        stderr.Should().Contain("bogus").And.Contain("paranoid").And.Contain("financial").And.Contain("dev");
        stdout.Should().NotContain("Created");
    }

    [Fact]
    public void Init_KnownPreset_StillWorks()
    {
        var (exit, _, _) = Run("init", "--preset", "dev");

        exit.Should().Be(0);
        File.ReadAllText("shroud.json").Should().Contain("\"preset\": \"dev\"");
    }

    // ---- Fix 10 ----

    [Fact]
    public void ScanVerbose_StructuralPatternWithContextWords_ShowsRealBreakdown()
    {
        // visa: base 0.80, context "card" +0.15 -> 0.95
        File.WriteAllText("a.md", "card 4111 1111 1111 1111\n");

        var (exit, stdout, _) = Run("scan", "a.md", "--verbose");

        exit.Should().Be(0);
        stdout.Should().Contain("0.95  4111 1111 1111 1111");
        stdout.Should().NotContain("structural match (base: 0.80)\n").And.NotContain("structural match (base: 0.80)\r");
        stdout.Should().Contain("(base: 0.80 + context: +0.15)");
        stdout.Should().Contain("\"card\"");
    }

    [Fact]
    public void ScanVerbose_StructuralPatternWithoutContextWords_Unchanged()
    {
        File.WriteAllText("a.md", "wallet 0x1111111111111111111111111111111111111111\n");

        var (_, stdout, _) = Run("scan", "a.md", "--verbose");

        stdout.Should().Contain("structural match (base: 0.95)");
    }

    [Fact]
    public void ScanVerbose_TwoSameTypePatternsOnOneSpan_ShowsTheWinnersScoring()
    {
        // "1234.56" is a Quantity for large_number (0.20 + 0.45) and table_quantity (0.15 + 0.55);
        // table_quantity wins with 0.70, but large_number comes first in pattern order.
        File.WriteAllText("a.md", "balance 1234.56\n");

        var (_, stdout, _) = Run("scan", "a.md", "--verbose");

        stdout.Should().Contain("table_quantity");
        stdout.Should().Contain("(base: 0.15 + context: +0.55)");
        stdout.Should().NotContain("(base: 0.20 + context: +0.45)");
    }

    // ---- Culture independence: numbers in CLI output are invariant ----

    private static T WithCulture<T>(string name, Func<T> action)
    {
        var oldCulture = CultureInfo.CurrentCulture;
        var oldUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo(name);
            CultureInfo.CurrentUICulture = new CultureInfo(name);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = oldCulture;
            CultureInfo.CurrentUICulture = oldUiCulture;
        }
    }

    [Fact]
    public void ScanVerbose_UnderTurkishCulture_PrintsInvariantNumbers()
    {
        // tr-TR writes 0.95 as "0,95"; the report must not depend on the user's locale.
        File.WriteAllText("a.md", "card 4111 1111 1111 1111\nseed abandon\n");

        var (exit, stdout, _) = WithCulture("tr-TR", () => Run("scan", "a.md", "--verbose", "--debug"));

        exit.Should().Be(0);
        stdout.Should().Contain("0.95  4111 1111 1111 1111");
        stdout.Should().Contain("(base: 0.80 + context: +0.15)");
        stdout.Should().Contain("Below threshold (0.50):");
        stdout.Should().NotContain("0,95").And.NotContain("0,80").And.NotContain("0,15").And.NotContain("0,50");
    }

    [Fact]
    public void Init_UnderTurkishCulture_PrintsInvariantThreshold()
    {
        var (exit, stdout, _) = WithCulture("tr-TR", () => Run("init", "--preset", "dev"));

        exit.Should().Be(0);
        stdout.Should().Contain("Threshold: 0.7");
        stdout.Should().NotContain("0,7");
    }
}
