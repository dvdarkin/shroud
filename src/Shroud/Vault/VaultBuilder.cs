using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Shroud.Detection;
using Shroud.Masking;
using Shroud.Models;

namespace Shroud.Vault;

/// <summary>
/// Orchestrates the scan-mask-vault pipeline. Scans all .md files in a directory, masks detected
/// spans, and produces three outputs: public/ (masked copies safe to share), manifest.json (token
/// metadata without secret values — for agents and reviewers), and vault.shroud (encrypted JSON
/// mapping token IDs to original values, password-gated). This is the trust boundary: manifest is
/// Tier 0 (anyone can read), vault is Tier 2 (owner-only via password).
/// </summary>
public class VaultBuilder
{
    private readonly SensitivityScanner _scanner;
    private readonly byte[] _maskingKey;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public VaultBuilder(ShroudConfig? config = null)
    {
        config ??= ShroudConfig.Default();
        _scanner = new SensitivityScanner(config);
        _maskingKey = RandomNumberGenerator.GetBytes(32);
    }

    public VaultBuilder(SensitivityScanner scanner)
        : this(scanner, RandomNumberGenerator.GetBytes(32))
    {
    }

    /// <summary>Test seam: a fixed masking key makes token ids (and collisions) reproducible.</summary>
    internal VaultBuilder(SensitivityScanner scanner, byte[] maskingKey)
    {
        _scanner = scanner;
        _maskingKey = maskingKey;
    }

    public VaultResult Build(string sourceDir)
    {
        // Files are processed in ordinal (UTF-16 code unit) order of the relative path exactly as
        // it is stored in the output (platform separator included), so token order, manifest
        // "files" lists and fileHashes keys never depend on the process culture.
        var mdFiles = Directory.EnumerateFiles(sourceDir, "*.md", SearchOption.AllDirectories)
            .Select(f => (FullPath: f, RelativePath: Path.GetRelativePath(sourceDir, f)))
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
            .ToList();

        var masker = new SpanMasker(_maskingKey);
        var allTokens = new Dictionary<string, TokenEntry>();
        var maskedFiles = new List<MaskedFile>();

        foreach (var (filePath, relativePath) in mdFiles)
        {
            var text = File.ReadAllText(filePath);
            var scanResult = _scanner.Scan(text);

            if (scanResult.AboveThreshold.Count == 0)
            {
                // Clean file -- copy as-is
                maskedFiles.Add(new MaskedFile(relativePath, text, 0));
                continue;
            }

            var maskResult = masker.Mask(text, scanResult);

            // Build token registry
            foreach (var token in maskResult.Tokens)
            {
                if (allTokens.TryGetValue(token.TokenId, out var existing))
                {
                    // Same id, different value: the second value would be lost and reveal
                    // would restore the wrong text. Fail before anything is written.
                    if (existing.Value != token.OriginalValue)
                        throw new TokenCollisionException(token.TokenId);

                    existing.Files.Add(relativePath);
                    existing.Occurrences++;
                }
                else
                {
                    allTokens[token.TokenId] = new TokenEntry
                    {
                        Value = token.OriginalValue,
                        Service = token.EntityType.ToString(),
                        ServiceId = GetServiceId(scanResult, token),
                        Domain = token.Domain.ToString().ToLowerInvariant(),
                        Files = [relativePath],
                        Occurrences = 1
                    };
                }
            }

            maskedFiles.Add(new MaskedFile(relativePath, maskResult.MaskedText, maskResult.Tokens.Count));
        }

        return new VaultResult(sourceDir, maskedFiles, allTokens);
    }

    public void WriteOutput(VaultResult result, string outputDir, string password)
    {
        var publicDir = Path.Combine(outputDir, "public");
        Directory.CreateDirectory(publicDir);

        // Write masked files preserving directory structure
        foreach (var file in result.MaskedFiles)
        {
            var outPath = Path.Combine(publicDir, file.RelativePath);
            var dir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(outPath, file.MaskedContent);
        }

        // Build and write manifest (public, no secret values)
        var manifest = new ManifestFile
        {
            Created = DateTime.UtcNow.ToString("o"),
            Source = SourceDirectoryName(result.SourceDir),
            FileCount = result.MaskedFiles.Count,
            TokenCount = result.Tokens.Count,
            Tokens = result.Tokens.ToDictionary(
                kv => kv.Key,
                kv => new ManifestToken
                {
                    Service = kv.Value.ServiceId,
                    Domain = kv.Value.Domain,
                    Files = kv.Value.Files.Distinct().ToList(),
                    Occurrences = kv.Value.Occurrences
                }),
            Summary = result.Tokens.Values
                .GroupBy(t => t.Domain)
                .ToDictionary(g => g.Key, g => g.Sum(t => t.Occurrences))
        };

        var manifestJson = JsonSerializer.Serialize(manifest, JsonOpts);
        File.WriteAllText(Path.Combine(outputDir, "manifest.json"), manifestJson);

        // Build and encrypt vault (secret values + file hashes)
        var vaultData = new VaultData
        {
            Version = 1,
            Created = manifest.Created,
            Tokens = result.Tokens.ToDictionary(
                kv => kv.Key,
                kv => kv.Value.Value),
            FileHashes = result.MaskedFiles.ToDictionary(
                f => f.RelativePath,
                f => ComputeHash(f.MaskedContent))
        };

        var vaultJson = JsonSerializer.Serialize(vaultData, JsonOpts);
        var encrypted = VaultEncryption.EncryptString(vaultJson, password);
        File.WriteAllBytes(Path.Combine(outputDir, "vault.shroud"), encrypted);
    }

    private static string GetServiceId(ScanResult scanResult, TokenMapping token)
    {
        var span = scanResult.AboveThreshold
            .FirstOrDefault(s => s.MatchedText == token.OriginalValue && s.EntityType == token.EntityType);
        return span?.Service ?? "";
    }

    /// <summary>
    /// manifest.json is public, so it records only the final directory name of the source
    /// ("." and relative paths are resolved first), never the absolute path.
    /// </summary>
    internal static string SourceDirectoryName(string sourceDir)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourceDir));
        var name = Path.GetFileName(full);
        // A filesystem root ("/", "C:\") has no name; the root itself carries no user path.
        return string.IsNullOrEmpty(name) ? full : name;
    }

    private static string ComputeHash(string content)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return $"sha256:{Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}

public record VaultResult(
    string SourceDir,
    List<MaskedFile> MaskedFiles,
    Dictionary<string, TokenEntry> Tokens
);

public record MaskedFile(
    string RelativePath,
    string MaskedContent,
    int TokensApplied
);

public class TokenEntry
{
    public string Value { get; set; } = "";
    public string Service { get; set; } = "";
    public string ServiceId { get; set; } = "";
    public string Domain { get; set; } = "";
    public List<string> Files { get; set; } = [];
    public int Occurrences { get; set; }
}

// --- Serialization models ---

public class ManifestFile
{
    public string Created { get; set; } = "";
    public string Source { get; set; } = "";
    public int FileCount { get; set; }
    public int TokenCount { get; set; }
    public Dictionary<string, ManifestToken> Tokens { get; set; } = new();
    public Dictionary<string, int> Summary { get; set; } = new();
}

public class ManifestToken
{
    public string Service { get; set; } = "";
    public string Domain { get; set; } = "";
    public List<string> Files { get; set; } = [];
    public int Occurrences { get; set; }
}

public class VaultData
{
    public int Version { get; set; }
    public string Created { get; set; } = "";
    public Dictionary<string, string> Tokens { get; set; } = new();
    public Dictionary<string, string> FileHashes { get; set; } = new();
}
