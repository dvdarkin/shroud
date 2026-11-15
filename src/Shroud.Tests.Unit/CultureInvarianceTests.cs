using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.RegularExpressions;
using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Shroud.Vault;
using Xunit;

namespace Shroud.Tests.Unit;

/// <summary>
/// Changing CultureInfo.CurrentCulture is per thread, but a Regex captures the culture when it
/// is constructed and the scanner's exclusion regexes are statics built once per process, so
/// these tests never run in parallel with other tests (a static first touched here must not
/// leak a Turkish culture into another test).
/// </summary>
[CollectionDefinition("Culture", DisableParallelization = true)]
public class CultureCollection;

/// <summary>
/// Detection, token input and vault file order must not depend on the process culture.
/// Under tr-TR, IgnoreCase without CultureInvariant stops matching uppercase ASCII "I"
/// ("VALIDATOR", "LOGIN", "FILE:"), and a culture-sensitive OrderBy reorders files.
/// </summary>
[Collection("Culture")]
public class CultureInvarianceTests
{
    private const string AddrA = "0x1111111111111111111111111111111111111111";

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

    private static List<string> Describe(ScanResult result) =>
        result.AllDetected.Select(s => string.Create(CultureInfo.InvariantCulture,
            $"{s.Start}-{s.End} {s.Service} {s.Confidence:R} {s.MatchedText}")).ToList();

    // Every regex the library builds: the pattern library and the scanner's exclusion zones.
    private static IEnumerable<(string Name, Regex Regex)> LibraryRegexes()
    {
        foreach (var p in PatternLibrary.GetAll())
            yield return (p.Service, p.CompiledRegex);
        foreach (var field in typeof(SensitivityScanner).GetFields(BindingFlags.NonPublic | BindingFlags.Static))
        {
            if (field.GetValue(null) is Regex rx) yield return (field.Name, rx);
            if (field.GetValue(null) is Regex[] array)
                for (var i = 0; i < array.Length; i++) yield return ($"{field.Name}[{i}]", array[i]);
        }
    }

    [Fact]
    public void EveryLibraryRegex_IsCultureInvariant()
    {
        var regexes = LibraryRegexes().ToList();
        regexes.Should().HaveCountGreaterThan(100, "the pattern library and the exclusion regexes are all checked");
        regexes.Where(r => !r.Regex.Options.HasFlag(RegexOptions.CultureInvariant)).Select(r => r.Name)
            .Should().BeEmpty("a Regex captures the current culture at construction unless it is CultureInvariant");
    }

    [Theory]
    [InlineData("VALIDATOR #548231", "eth_validator_index")]
    [InlineData("LOGIN = \"bobby\"", "login_assignment")]
    [InlineData("API_KEY = \"key-67890\"", "password_assignment")]
    [InlineData("POSITION #77 UNISWAP LIQUIDITY", "lp_position_id")]
    public void PatternLibrary_UnderTurkishCulture_MatchesUppercaseAsciiI(string line, string service)
    {
        // The pattern regexes are built when the scanner is constructed, so building it under
        // tr-TR is exactly what a process running in a Turkish locale does.
        var turkish = WithCulture("tr-TR", () => new SensitivityScanner().Scan(line));
        var invariant = new SensitivityScanner().Scan(line);

        turkish.AboveThreshold.Should().Contain(s => s.Service == service);
        Describe(turkish).Should().Equal(Describe(invariant));
    }

    [Fact]
    public void ExclusionRegexes_RebuiltUnderTurkishCulture_MatchLikeTheInvariantOnes()
    {
        // The exclusion regexes are statics: rebuilding each one from its own source and options
        // under tr-TR is what the static initializer does in a Turkish process.
        const string text = "FILE: " + AddrA + "\nSOURCE_FILE: x\nPATH: y\nATTACHMENT: z\nAPRIL 8, 2025 at 5 PM\n";
        foreach (var (name, rx) in LibraryRegexes().Where(r => r.Name.StartsWith("Frontmatter") ||
                     r.Name.StartsWith("FilePath") || r.Name.StartsWith("DateTime")))
        {
            var rebuilt = WithCulture("tr-TR", () => new Regex(rx.ToString(), rx.Options));
            var expected = rx.Matches(text).Select(m => (m.Index, m.Length)).ToList();
            rebuilt.Matches(text).Select(m => (m.Index, m.Length)).Should().Equal(expected, name);
        }
    }

    [Fact]
    public void FreshlyLoadedScanner_UnderTurkishCulture_ScansLikeTheInvariantOne()
    {
        // A second copy of the library in its own load context has fresh statics, so its
        // exclusion regexes are really built under tr-TR, as in a process started in Turkey.
        const string text = "## Notes\n\nVALIDATOR #548231\nFILE: " + AddrA + "\nLOGIN = \"bobby\"\n" +
                            "API_KEY = \"key-67890\"\nPOSITION #77 UNISWAP LIQUIDITY\n";
        var expected = Describe(new SensitivityScanner().Scan(text));

        var context = new AssemblyLoadContext("shroud-tr-TR", isCollectible: true);
        try
        {
            var actual = WithCulture("tr-TR", () =>
            {
                var assembly = context.LoadFromAssemblyPath(typeof(SensitivityScanner).Assembly.Location);
                var scannerType = assembly.GetType(typeof(SensitivityScanner).FullName!)!;
                var scanner = Activator.CreateInstance(scannerType, [null, 0.70])!;
                var result = scannerType.GetMethod(nameof(SensitivityScanner.Scan))!.Invoke(scanner, [text])!;
                var spans = (System.Collections.IEnumerable)result.GetType()
                    .GetProperty(nameof(ScanResult.AllDetected))!.GetValue(result)!;
                var list = new List<string>();
                foreach (var s in spans)
                {
                    var t = s.GetType();
                    string P(string n) => Convert.ToString(t.GetProperty(n)!.GetValue(s), CultureInfo.InvariantCulture)!;
                    var confidence = ((double)t.GetProperty(nameof(SensitiveSpan.Confidence))!.GetValue(s)!)
                        .ToString("R", CultureInfo.InvariantCulture);
                    list.Add($"{P("Start")}-{P("End")} {P("Service")} {confidence} {P("MatchedText")}");
                }
                return list;
            });

            actual.Should().Equal(expected);
            actual.Should().NotContain(s => s.Contains(AddrA), "the FILE: line is a metadata line in every culture");
        }
        finally
        {
            context.Unload();
        }
    }

    [Fact]
    public void Build_UnderTurkishCulture_OrdersFilesOrdinallyByRelativePath()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"shroud-order-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "sub"));
            foreach (var name in new[] { "c.md", "sub_y.md", "a.md", "Index.md", "sub-x.md", "B.md", Path.Combine("sub", "z.md"), "ilk.md" })
                File.WriteAllText(Path.Combine(dir, name), "plain text\n");

            var turkish = WithCulture("tr-TR", () => new VaultBuilder().Build(dir));
            var invariant = new VaultBuilder().Build(dir);

            var sep = Path.DirectorySeparatorChar;
            // Ordinal (UTF-16 code unit) order of the stored relative path, separator included:
            // '-' (0x2D) < '/' (0x2F) and '\' (0x5C) < '_' (0x5F); uppercase before lowercase.
            var expected = new[] { "B.md", "Index.md", "a.md", "c.md", "ilk.md", "sub-x.md", $"sub{sep}z.md", "sub_y.md" };
            turkish.MaskedFiles.Select(f => f.RelativePath).Should().Equal(expected);
            invariant.MaskedFiles.Select(f => f.RelativePath).Should().Equal(expected);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void WriteOutput_UnderTurkishCulture_ManifestAndVaultFollowTheOrdinalFileOrder()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"shroud-order-{Guid.NewGuid():N}");
        try
        {
            var src = Path.Combine(dir, "src");
            Directory.CreateDirectory(src);
            // The same address in every file: its manifest "files" list is the file order.
            foreach (var name in new[] { "b.md", "README.md", "a.md" })
                File.WriteAllText(Path.Combine(src, name), $"wallet {AddrA}\n");

            var output = Path.Combine(dir, "out");
            WithCulture("tr-TR", () =>
            {
                var builder = new VaultBuilder();
                builder.WriteOutput(builder.Build(src), output, "pw");
                return 0;
            });

            using var manifest = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(output, "manifest.json")));
            var token = manifest.RootElement.GetProperty("tokens").EnumerateObject().Single();
            token.Value.GetProperty("files").EnumerateArray().Select(e => e.GetString())
                .Should().Equal("README.md", "a.md", "b.md");

            var json = VaultEncryption.DecryptString(File.ReadAllBytes(Path.Combine(output, "vault.shroud")), "pw")!;
            using var vault = System.Text.Json.JsonDocument.Parse(json);
            vault.RootElement.GetProperty("fileHashes").EnumerateObject().Select(p => p.Name)
                .Should().Equal("README.md", "a.md", "b.md");
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }
}
