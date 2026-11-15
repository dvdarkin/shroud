using System.Text.Json;
using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Shroud.Vault;
using Xunit;

namespace Shroud.Tests.Integration;

/// <summary>
/// VaultBuilder correctness: manifest service ids, token id collisions, and no absolute
/// paths in the public manifest.
/// </summary>
public class VaultBuilderIntegrityTests : IDisposable
{
    // Two different GitHub PAT-shaped fake values whose 4-byte HMAC prefix collides under
    // the fixed key 0x00..0x1f (found by brute force): both mask to TOKEN:908a4613.
    private const string CollidingA = "ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF71177";
    private const string CollidingB = "ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF105486";
    private const string CollidingId = "TOKEN:908a4613";
    private static readonly byte[] FixedKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    private readonly string _root;
    private readonly string _sourceDir;

    public VaultBuilderIntegrityTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"shroud-vb-{Guid.NewGuid():N}");
        _sourceDir = Path.Combine(_root, "my-notes");
        Directory.CreateDirectory(_sourceDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    private VaultBuilder FixedKeyBuilder() =>
        new(new SensitivityScanner(ShroudConfig.Default()), FixedKey);

    // ---- Fix 5 ----

    [Fact]
    public void ManifestService_BelongsToAPatternOfTheTokensOwnEntityType()
    {
        // The same text "1,234" is a Quantity on line 1 and an Amount on line 3.
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"),
            "bought 1,234 units.\n\nfee 1,234 = 5 usd\n");

        var result = new VaultBuilder(ShroudConfig.Default()).Build(_sourceDir);

        var byService = PatternLibrary.GetAll().GroupBy(p => p.Service)
            .ToDictionary(g => g.Key, g => g.Select(p => p.EntityType).ToHashSet());
        result.Tokens.Should().Contain(kv => kv.Key.StartsWith("AMT:"), "the Amount token exists");
        result.Tokens.Should().Contain(kv => kv.Key.StartsWith("QTY:"), "the Quantity token exists");
        foreach (var (tokenId, entry) in result.Tokens)
        {
            byService.Should().ContainKey(entry.ServiceId, $"{tokenId} has a known service id");
            byService[entry.ServiceId].Should().Contain(Enum.Parse<EntityType>(entry.Service),
                $"{tokenId} ({entry.Service}) must not be labelled with another type's pattern '{entry.ServiceId}'");
        }
    }

    // ---- Fix 6 ----

    [Fact]
    public void Seam_TheTwoFixtureValuesReallyCollide()
    {
        var builder = FixedKeyBuilder();
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), $"token {CollidingA}\n");
        var r1 = builder.Build(_sourceDir);
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), $"token {CollidingB}\n");
        var r2 = builder.Build(_sourceDir);

        r1.Tokens.Keys.Should().Equal(CollidingId);
        r2.Tokens.Keys.Should().Equal(CollidingId);
    }

    [Fact]
    public void TokenIdCollision_InOneFile_Throws_WithoutPrintingValues()
    {
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), $"first {CollidingA}\nsecond {CollidingB}\n");

        var act = () => FixedKeyBuilder().Build(_sourceDir);

        var ex = act.Should().Throw<TokenCollisionException>().Which;
        ex.TokenId.Should().Be(CollidingId);
        ex.Message.Should().Contain(CollidingId);
        ex.Message.Should().NotContain(CollidingA).And.NotContain(CollidingB);
        ex.Message.Should().NotContain("FFFFFFFF", "no fragment of an original value is printed");
    }

    [Fact]
    public void TokenIdCollision_AcrossFiles_Throws()
    {
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), $"first {CollidingA}\n");
        File.WriteAllText(Path.Combine(_sourceDir, "b.md"), $"second {CollidingB}\n");

        var act = () => FixedKeyBuilder().Build(_sourceDir);

        act.Should().Throw<TokenCollisionException>().Which.TokenId.Should().Be(CollidingId);
    }

    [Fact]
    public void SameValueSeenAgain_IsNotACollision()
    {
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), $"first {CollidingA}\nagain {CollidingA}\n");
        File.WriteAllText(Path.Combine(_sourceDir, "b.md"), $"third {CollidingA}\n");

        var result = FixedKeyBuilder().Build(_sourceDir);

        result.Tokens.Should().ContainKey(CollidingId);
        result.Tokens[CollidingId].Value.Should().Be(CollidingA);
        result.Tokens[CollidingId].Occurrences.Should().Be(3);
    }

    // ---- Fix 7 ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ManifestSource_IsOnlyTheDirectoryName(bool trailingSeparator)
    {
        File.WriteAllText(Path.Combine(_sourceDir, "a.md"), "wallet 0x1111111111111111111111111111111111111111\n");
        var source = trailingSeparator ? _sourceDir + Path.DirectorySeparatorChar : _sourceDir;
        var outDir = Path.Combine(_root, "out");

        var builder = new VaultBuilder(ShroudConfig.Default());
        builder.WriteOutput(builder.Build(source), outDir, "pw");

        var manifestText = File.ReadAllText(Path.Combine(outDir, "manifest.json"));
        JsonDocument.Parse(manifestText).RootElement.GetProperty("source").GetString().Should().Be("my-notes");
        manifestText.Should().NotContain(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar).Replace("\\", "\\\\"),
            "the public manifest must not leak the absolute location");
    }
}
