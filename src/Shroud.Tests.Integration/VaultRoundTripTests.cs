using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Shroud.Vault;
using Xunit;
using Xunit.Abstractions;

namespace Shroud.Tests.Integration;

/// <summary>
/// End-to-end vault round-trip: original files → vault → reveal → compare SHA-256 hashes.
/// Verifies that the full pipeline (scan, mask, encrypt, decrypt, unmask) preserves
/// every byte of the original content.
/// </summary>
public class VaultRoundTripTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _sourceDir;
    private readonly string _vaultDir;
    private readonly string _revealDir;
    private const string Password = "test-password-1234";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public VaultRoundTripTests(ITestOutputHelper output)
    {
        _output = output;
        var testId = Guid.NewGuid().ToString("N")[..8];
        _sourceDir = Path.Combine(Path.GetTempPath(), $"shroud-test-{testId}");
        _vaultDir = _sourceDir + ".shroud";
        _revealDir = _sourceDir + ".revealed";
        Directory.CreateDirectory(_sourceDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_sourceDir)) Directory.Delete(_sourceDir, true);
        if (Directory.Exists(_vaultDir)) Directory.Delete(_vaultDir, true);
        if (Directory.Exists(_revealDir)) Directory.Delete(_revealDir, true);
    }

    [Fact]
    public void SingleFile_RoundTrip_PreservesContent()
    {
        var original = "Sent 0.5 ETH to 0x1111111111111111111111111111111111111111 at $1,234.";
        File.WriteAllText(Path.Combine(_sourceDir, "notes.md"), original);

        var hashes = VaultAndReveal();

        hashes.Should().ContainKey("notes.md");
        hashes["notes.md"].revealed.Should().Be(hashes["notes.md"].original,
            "revealed file should be byte-identical to original");
    }

    [Fact]
    public void ThreeFiles_RoundTrip_AllPreserved()
    {
        var files = new Dictionary<string, string>
        {
            ["wallet.md"] = """
                ## Wallet Summary
                Main: 0x2222222222222222222222222222222222222222
                Cold: bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                Balance: $45,000 across both wallets.
                API key for alerts: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA
                """,
            ["trades.md"] = """
                ## 2026-04-01
                bought 100 NVDA for $120 each. Total: $12,000.
                SSN on file: 123-45-6789
                """,
            ["subdir/defi.md"] = """
                ## DeFi Positions
                Staked 1,000 USDC in pool 0x3333333333333333333333333333333333333333
                Tx: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                Yield so far: $42.50
                """
        };

        foreach (var (name, content) in files)
        {
            var path = Path.Combine(_sourceDir, name);
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, content);
        }

        var hashes = VaultAndReveal();

        hashes.Should().HaveCount(3, "all 3 files should be vaulted and revealed");

        foreach (var (name, (original, revealed)) in hashes)
        {
            _output.WriteLine($"  {name}: original={original[..16]}... revealed={revealed[..16]}...");
            revealed.Should().Be(original, $"{name} should be byte-identical after round-trip");
        }
    }

    [Fact]
    public void CleanFile_NoDetections_PreservedVerbatim()
    {
        var original = "This file has no sensitive data whatsoever. Just plain text.";
        File.WriteAllText(Path.Combine(_sourceDir, "clean.md"), original);

        var hashes = VaultAndReveal();

        hashes["clean.md"].revealed.Should().Be(hashes["clean.md"].original,
            "file with no detections should pass through unchanged");
    }

    [Fact]
    public void WrongPassword_RevealFails()
    {
        File.WriteAllText(Path.Combine(_sourceDir, "secret.md"),
            "Key: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA");

        var builder = new VaultBuilder();
        var result = builder.Build(_sourceDir);
        builder.WriteOutput(result, _vaultDir, Password);

        var encrypted = File.ReadAllBytes(Path.Combine(_vaultDir, "vault.shroud"));
        var json = VaultEncryption.DecryptString(encrypted, "wrong-password");

        json.Should().BeNull("wrong password should fail decryption");
    }

    /// <summary>
    /// Runs the full vault → reveal pipeline and returns SHA-256 hashes
    /// of each file's original and revealed content.
    /// </summary>
    private Dictionary<string, (string original, string revealed)> VaultAndReveal()
    {
        // Capture original hashes
        var originalHashes = new Dictionary<string, string>();
        foreach (var file in Directory.EnumerateFiles(_sourceDir, "*.md", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(_sourceDir, file);
            originalHashes[relative] = HashFile(file);
        }

        // Vault
        var builder = new VaultBuilder();
        var result = builder.Build(_sourceDir);
        builder.WriteOutput(result, _vaultDir, Password);

        _output.WriteLine($"  Vaulted: {result.MaskedFiles.Count} files, {result.Tokens.Count} tokens");

        // Verify masked files exist and contain tokens (if any detections)
        var publicDir = Path.Combine(_vaultDir, "public");
        Directory.Exists(publicDir).Should().BeTrue();

        // Reveal: decrypt vault, replace tokens in public files
        var vaultFile = Path.Combine(_vaultDir, "vault.shroud");
        var encrypted = File.ReadAllBytes(vaultFile);
        var json = VaultEncryption.DecryptString(encrypted, Password);
        json.Should().NotBeNull("decryption with correct password should succeed");

        var vaultData = JsonSerializer.Deserialize<VaultData>(json!, JsonOpts);
        vaultData.Should().NotBeNull();

        Directory.CreateDirectory(_revealDir);
        foreach (var file in Directory.EnumerateFiles(publicDir, "*.md", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(publicDir, file);
            var content = File.ReadAllText(file);

            foreach (var (tokenId, value) in vaultData!.Tokens)
                content = content.Replace($"[{tokenId}]", value);

            var outPath = Path.Combine(_revealDir, relative);
            var dir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(outPath, content);
        }

        // Collect revealed hashes
        var hashes = new Dictionary<string, (string original, string revealed)>();
        foreach (var (relative, origHash) in originalHashes)
        {
            var revealedPath = Path.Combine(_revealDir, relative);
            File.Exists(revealedPath).Should().BeTrue($"revealed file {relative} should exist");
            hashes[relative] = (origHash, HashFile(revealedPath));
        }

        return hashes;
    }

    private static string HashFile(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
