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
        Shroud.Cli.Program.OpenStdin = Console.OpenStandardInput;
        Shroud.Cli.Program.OpenStdout = Console.OpenStandardOutput;
        Environment.SetEnvironmentVariable("SHROUD_PASSWORD", null);
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

    // ---- CLI audit: output locations ----

    private const string Wallet = "0x1111111111111111111111111111111111111111";

    private static string[] FilesUnder(string dir) =>
        Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(dir, f).Replace('\\', '/'))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToArray();

    [Fact]
    public void Reveal_VaultDirWithoutShroudSuffix_RevealsNextToIt_NeverIntoTheVault()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        Run("vault", "notes", "-p", "pw", "-o", "out").Exit.Should().Be(0);

        var (exit, _, _) = Run("reveal", "out", "-p", "pw");

        exit.Should().Be(0);
        FilesUnder("out").Should().Equal("manifest.json", "public/a.md", "vault.shroud");
        File.ReadAllText(Path.Combine("out.revealed", "a.md")).Should().Be($"wallet {Wallet}\n");
    }

    [Fact]
    public void Reveal_DefaultOutput_ReplacesOnlyTheTrailingShroudSuffix()
    {
        var notes = Path.Combine("my.shroud.stuff", "notes");
        Directory.CreateDirectory(notes);
        File.WriteAllText(Path.Combine(notes, "a.md"), $"wallet {Wallet}\n");
        Run("vault", notes, "-p", "pw").Exit.Should().Be(0);

        var (exit, _, _) = Run("reveal", notes + ".shroud" + Path.DirectorySeparatorChar, "-p", "pw");

        exit.Should().Be(0);
        File.Exists(Path.Combine("my.shroud.stuff", "notes.revealed", "a.md")).Should().BeTrue();
        Directory.Exists("my.revealed.stuff").Should().BeFalse();
    }

    [Fact]
    public void Reveal_OutputInsideTheVaultDirectory_IsRefused()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        Run("vault", "notes", "-p", "pw").Exit.Should().Be(0);

        var (exit, _, stderr) = Run("reveal", "notes.shroud", "-p", "pw", "-o", Path.Combine("notes.shroud", "public"));

        exit.Should().NotBe(0);
        stderr.Should().Contain("inside the vault directory");
        File.ReadAllText(Path.Combine("notes.shroud", "public", "a.md")).Should().NotContain(Wallet);
    }

    [Fact]
    public void Vault_DotSource_DefaultOutputIsASiblingOfTheSource_AndASecondRunDoesNotNest()
    {
        var project = Path.Combine(_dir, "alice-project");
        Directory.CreateDirectory(project);
        File.WriteAllText(Path.Combine(project, "a.md"), $"wallet {Wallet}\n");
        Directory.SetCurrentDirectory(project);

        Run("vault", ".", "-p", "pw").Exit.Should().Be(0);
        Run("vault", ".", "-p", "pw").Exit.Should().Be(0);

        FilesUnder(project).Should().Equal("a.md");
        FilesUnder(Path.Combine(_dir, "alice-project.shroud")).Should().Equal("manifest.json", "public/a.md", "vault.shroud");
    }

    [Fact]
    public void Vault_OutputInsideTheSource_IsRefused_WritesNothing()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");

        var (exit, _, stderr) = Run("vault", "notes", "-p", "pw", "-o", Path.Combine("notes", "out"));

        exit.Should().NotBe(0);
        stderr.Should().Contain("inside the source directory");
        Directory.Exists(Path.Combine("notes", "out")).Should().BeFalse();
    }

    [Fact]
    public void Vault_SecondRun_RemovesMaskedCopiesOfFilesNoLongerInTheSource()
    {
        Directory.CreateDirectory(Path.Combine("notes", "sub"));
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        File.WriteAllText(Path.Combine("notes", "sub", "gone.md"), "wallet 0x2222222222222222222222222222222222222222\n");
        Run("vault", "notes", "-p", "pw").Exit.Should().Be(0);
        File.WriteAllText(Path.Combine("notes.shroud", "public", "keep.txt"), "not ours");
        File.Delete(Path.Combine("notes", "sub", "gone.md"));

        Run("vault", "notes", "-p", "pw").Exit.Should().Be(0);

        FilesUnder("notes.shroud").Should().Equal("manifest.json", "public/a.md", "public/keep.txt", "vault.shroud");
        var (exit, _, stderr) = Run("reveal", "notes.shroud", "-p", "pw");
        exit.Should().Be(0);
        stderr.Should().BeEmpty();
    }

    // ---- CLI audit: reveal integrity ----

    [Fact]
    public void Reveal_PublicFileChangedOrAdded_Warns_AndLeavesUnknownTokensInPlace()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        Run("vault", "notes", "-p", "pw").Exit.Should().Be(0);
        var publicDir = Path.Combine("notes.shroud", "public");
        File.AppendAllText(Path.Combine(publicDir, "a.md"), "edited [ADDR:00000000]\n");
        File.WriteAllText(Path.Combine(publicDir, "extra.md"), "hello\n");

        var (exit, _, stderr) = Run("reveal", "notes.shroud", "-p", "pw");

        exit.Should().Be(0);
        stderr.Should().Contain("a.md was changed after it was vaulted");
        stderr.Should().Contain("a.md: 1 token(s) are not in this vault");
        stderr.Should().Contain("extra.md is not part of this vault");
        File.ReadAllText(Path.Combine("notes.revealed", "a.md")).Should().Be($"wallet {Wallet}\nedited [ADDR:00000000]\n");
    }

    // ---- CLI audit: arguments and exit codes ----

    [Fact]
    public void Scan_MissingFile_ExitsOne_ButStillScansTheOthers()
    {
        File.WriteAllText("a.md", $"wallet {Wallet}\n");

        var (exit, stdout, stderr) = Run("scan", "nope.md", "a.md");

        exit.Should().Be(1);
        stderr.Should().Contain("File not found: nope.md");
        stdout.Should().Contain("evm_address");
    }

    [Fact]
    public void Scan_UnknownOption_IsRefused_NotTreatedAsAFile()
    {
        File.WriteAllText("a.md", $"wallet {Wallet}\n");

        var (exit, stdout, stderr) = Run("scan", "a.md", "--json");

        exit.Should().Be(1);
        stderr.Should().Contain("Unknown option: --json");
        stdout.Should().BeEmpty();
    }

    [Fact]
    public void Scan_ExitCodeFlag_TwoWhenSomethingWouldBeTokenized_ZeroWhenClean()
    {
        File.WriteAllText("dirty.md", $"wallet {Wallet}\n");
        File.WriteAllText("clean.md", "nothing to see here\n");

        Run("scan", "dirty.md").Exit.Should().Be(0);
        Run("scan", "dirty.md", "--exit-code").Exit.Should().Be(2);
        Run("scan", "clean.md", "dirty.md", "--exit-code").Exit.Should().Be(2);
        Run("scan", "clean.md", "--exit-code").Exit.Should().Be(0);
    }

    [Fact]
    public void Options_WithoutAValue_OrUnknown_AreRefused()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");

        var (exit, _, stderr) = Run("vault", "notes", "-p");
        exit.Should().Be(1);
        stderr.Should().Contain("Option -p needs a value.");

        (exit, _, stderr) = Run("vault", "notes", "-p", "pw", "--force");
        exit.Should().Be(1);
        stderr.Should().Contain("Unknown option: --force");
        Directory.Exists("notes.shroud").Should().BeFalse();
    }

    [Fact]
    public void CommandName_WinsOverADirectoryOfTheSameName()
    {
        Directory.CreateDirectory("scan");
        File.WriteAllText(Path.Combine("scan", "a.md"), $"wallet {Wallet}\n");
        File.WriteAllText("a.md", $"wallet {Wallet}\n");

        var (exit, stdout, _) = Run("scan", "a.md");

        exit.Should().Be(0);
        stdout.Should().Contain("evm_address");
        Directory.Exists("scan.shroud").Should().BeFalse();
    }

    [Fact]
    public void Directory_AsFirstArgument_IsStillTheVaultCommand()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");

        Run("notes", "-p", "pw").Exit.Should().Be(0);

        File.Exists(Path.Combine("notes.shroud", "vault.shroud")).Should().BeTrue();
    }

    // ---- CLI audit: init and mask wording ----

    [Fact]
    public void Init_WithoutPreset_WritesParanoid_TheSameAsHavingNoConfig()
    {
        var (exit, stdout, _) = Run("init");

        exit.Should().Be(0);
        File.ReadAllText("shroud.json").Should().Contain("\"preset\": \"paranoid\"");
        stdout.Should().Contain("Threshold: 0.5");
        stdout.Should().Contain("credentials=True, secrets=True");
    }

    [Fact]
    public void Mask_InPlace_SaysItIsOneWay_AndTheKeyMessageDoesNotPromiseUnmasking()
    {
        File.WriteAllText("a.md", $"wallet {Wallet}\n");

        var (exit, _, stderr) = Run("mask", "a.md");

        exit.Should().Be(0);
        stderr.Should().Contain("Generated new key");
        stderr.Should().Contain("cannot unmask");
        stderr.Should().Contain("one-way");
        stderr.Should().NotContain("cannot be unmasked");
    }

    [Fact]
    public void Mask_ToOutputFile_PrintsNoInPlaceNote()
    {
        File.WriteAllText("a.md", $"wallet {Wallet}\n");

        var (_, _, stderr) = Run("mask", "a.md", "-o", "out.md");

        stderr.Should().NotContain("one-way");
        File.ReadAllText("a.md").Should().Be($"wallet {Wallet}\n");
    }

    // ---- Hooks and pipelines: stdin, --no-values, --config, SHROUD_PASSWORD, reveal --text ----

    private static void StdinIs(string text) =>
        Shroud.Cli.Program.OpenStdin = () => new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text));

    private static MemoryStream CaptureStdout()
    {
        var stream = new MemoryStream();
        Shroud.Cli.Program.OpenStdout = () => new NonClosingStream(stream);
        return stream;
    }

    private sealed class NonClosingStream(MemoryStream inner) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    }

    [Fact]
    public void Scan_Dash_ReadsStdin_AndWorksWithExitCode()
    {
        StdinIs($"wallet {Wallet}\n");

        var (exit, stdout, _) = Run("scan", "-", "--exit-code");

        exit.Should().Be(2);
        stdout.Should().Contain("<stdin>").And.Contain("evm_address");
    }

    [Fact]
    public void Scan_Dash_WithBom_ScansTheSameAsAFile()
    {
        Shroud.Cli.Program.OpenStdin = () => new MemoryStream(
            new byte[] { 0xEF, 0xBB, 0xBF }.Concat(System.Text.Encoding.UTF8.GetBytes("clean text\n")).ToArray());

        Run("scan", "-", "--exit-code").Exit.Should().Be(0);
    }

    [Fact]
    public void Scan_NoValues_NeverPrintsMatchedText_InAnyMode()
    {
        File.WriteAllText("a.md", $"wallet {Wallet}\ncard 4111 1111 1111 1111 total 12,500 / 4\nseed abandon\n");

        foreach (var mode in new[] { Array.Empty<string>(), ["--verbose"], ["--debug"] })
        {
            var (exit, stdout, stderr) = Run(["scan", "a.md", "--no-values", .. mode]);

            exit.Should().Be(0);
            stdout.Should().Contain("evm_address").And.Contain("<42 chars>");
            (stdout + stderr).Should().NotContain(Wallet).And.NotContain("4111").And.NotContain("12,500").And.NotContain("abandon");
        }
    }

    [Fact]
    public void Config_Option_SelectsTheConfigFile_AndAMissingOneIsAnError()
    {
        File.WriteAllText("a.md", "bought 100 ETH at $2,000\n");
        Directory.CreateDirectory("cfg");
        Run("init", "--preset", "dev").Exit.Should().Be(0);
        File.Move("shroud.json", Path.Combine("cfg", "dev.json"));

        Run("scan", "a.md", "--exit-code").Exit.Should().Be(2);
        Run("scan", "a.md", "--exit-code", "--config", Path.Combine("cfg", "dev.json")).Exit.Should().Be(0);

        var (exit, _, stderr) = Run("scan", "a.md", "--config", "nope.json");
        exit.Should().Be(1);
        stderr.Should().Contain("Config file not found: nope.json");
    }

    [Fact]
    public void PasswordVariable_IsUsedByVaultAndReveal_AndDashPWins()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        Environment.SetEnvironmentVariable("SHROUD_PASSWORD", "from-env");

        Run("vault", "notes").Exit.Should().Be(0);
        Run("reveal", "notes.shroud").Exit.Should().Be(0);
        File.ReadAllText(Path.Combine("notes.revealed", "a.md")).Should().Be($"wallet {Wallet}\n");

        var (exit, _, stderr) = Run("reveal", "notes.shroud", "-p", "other");
        exit.Should().Be(1);
        stderr.Should().Contain("Wrong password.");
    }

    private static string VaultNotesAndGetToken()
    {
        Directory.CreateDirectory("notes");
        File.WriteAllText(Path.Combine("notes", "a.md"), $"wallet {Wallet}\n");
        Run("vault", "notes", "-p", "pw").Exit.Should().Be(0);
        var masked = File.ReadAllText(Path.Combine("notes.shroud", "public", "a.md"));
        return masked["wallet ".Length..].TrimEnd();
    }

    [Fact]
    public void RevealText_File_RestoresTokensToStdout_AndNothingElse()
    {
        var token = VaultNotesAndGetToken();
        File.WriteAllText("answer.md", $"The wallet {token} appears once. Café [ADDR:00000000]\n");
        var captured = CaptureStdout();

        var (exit, stdout, stderr) = Run("reveal", "notes.shroud", "--text", "answer.md", "-p", "pw");

        exit.Should().Be(0);
        stdout.Should().BeEmpty();
        System.Text.Encoding.UTF8.GetString(captured.ToArray())
            .Should().Be($"The wallet {Wallet} appears once. Café [ADDR:00000000]\n");
        stderr.Should().Contain("1 token(s) are not in this vault");
        Directory.Exists("notes.revealed").Should().BeFalse();
    }

    [Fact]
    public void RevealText_Stdin_WithPasswordVariable_WritesToOutputFile()
    {
        var token = VaultNotesAndGetToken();
        StdinIs($"seen {token}\n");
        Environment.SetEnvironmentVariable("SHROUD_PASSWORD", "pw");

        var (exit, _, _) = Run("reveal", "notes.shroud", "--text", "-", "-o", "answer.txt");

        exit.Should().Be(0);
        File.ReadAllText("answer.txt").Should().Be($"seen {Wallet}\n");
    }

    [Fact]
    public void RevealText_Stdin_WithoutAPassword_IsRefused()
    {
        VaultNotesAndGetToken();
        StdinIs("anything\n");

        var (exit, _, stderr) = Run("reveal", "notes.shroud", "--text", "-");

        exit.Should().Be(1);
        stderr.Should().Contain("SHROUD_PASSWORD");
    }

    [Fact]
    public void RevealText_OutputInsideTheVault_OrWrongPassword_WritesNothing()
    {
        var token = VaultNotesAndGetToken();
        File.WriteAllText("answer.md", $"{token}\n");

        Run("reveal", "notes.shroud", "--text", "answer.md", "-p", "pw", "-o", Path.Combine("notes.shroud", "public", "x.md"))
            .Exit.Should().Be(1);
        Run("reveal", "notes.shroud", "--text", "answer.md", "-p", "bad", "-o", "out.md").Exit.Should().Be(1);

        File.Exists(Path.Combine("notes.shroud", "public", "x.md")).Should().BeFalse();
        File.Exists("out.md").Should().BeFalse();
    }
}
