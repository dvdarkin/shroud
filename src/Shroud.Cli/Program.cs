using System.Security.Cryptography;
using Shroud.Detection;
using static System.FormattableString;
using Shroud.Masking;
using Shroud.Models;
using Shroud.Vault;
#if HAS_PRIVATE_PATTERNS
using Shroud.Private;
#endif

namespace Shroud.Cli;

public static class Program
{
    private const string ConfigFileName = "shroud.json";

    /// <summary>Test seam: when set, `vault` uses this masking key instead of a random one.</summary>
    internal static byte[]? VaultMaskingKeyOverride { get; set; }

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        // A command name always means the command, even when a directory of that name exists
        // (write "./scan" to vault a directory called "scan").
        return args[0] switch
        {
            "vault" => RunVault(args[1..]),
            "reveal" => RunReveal(args[1..]),
            "scan" => RunScan(args[1..]),
            "mask" => RunMask(args[1..]),
            "init" => RunInit(args[1..]),
            "help" or "--help" or "-h" => PrintUsage(),
            // Any other first argument that is a directory: vault it (the default command).
            _ => Directory.Exists(args[0]) ? RunVault(args) : Error($"Unknown command: {args[0]}")
        };
    }

    /// <summary>
    /// Splits arguments into flags, options that take a value, and positionals. Returns an error
    /// message for an option that is not known or has no value, otherwise null. A lone "-" and
    /// anything not starting with "-" is a positional.
    /// </summary>
    private static string? ParseArgs(string[] args, string[] flagNames, string[] valueNames,
        HashSet<string> flags, Dictionary<string, string> values, List<string> positionals)
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.Length < 2 || arg[0] != '-')
                positionals.Add(arg);
            else if (flagNames.Contains(arg))
                flags.Add(arg);
            else if (valueNames.Contains(arg))
            {
                if (i + 1 >= args.Length)
                    return $"Option {arg} needs a value.";
                values[arg] = args[++i];
            }
            else
                return $"Unknown option: {arg}";
        }
        return null;
    }

    private static string? Value(Dictionary<string, string> values, string shortName, string longName) =>
        values.TryGetValue(longName, out var v) ? v : values.GetValueOrDefault(shortName);

    /// <summary>
    /// The directory path without trailing separators. ".", ".." and roots have no name of their
    /// own to append a suffix to, so they are resolved to a full path first.
    /// </summary>
    private static string NamedDirectory(string dir)
    {
        var trimmed = dir.TrimEnd('/', '\\');
        var name = Path.GetFileName(trimmed);
        return name is "" or "." or ".."
            ? Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir))
            : trimmed;
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="dir"/> or lies under it.</summary>
    private static bool IsSameOrInside(string dir, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(dir), Path.GetFullPath(path));
        return relative == "." ||
               (!Path.IsPathRooted(relative) && relative != ".." &&
                !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal));
    }

    private static int RunScan(string[] args)
    {
        var files = new List<string>();
        var flags = new HashSet<string>();
        var parseError = ParseArgs(args, ["--verbose", "-v", "--debug", "--exit-code"], [], flags, [], files);
        if (parseError is not null)
            return Error(parseError);

        if (files.Count == 0)
            return Error("Usage: shroud scan <file.md> [file2.md ...] [--verbose] [--debug] [--exit-code]");

        var debug = flags.Contains("--debug");
        var verbose = debug || flags.Contains("--verbose") || flags.Contains("-v");
        var missing = 0;
        var detected = false;

        var config = LoadConfig();
        var scanner = CreateScanner(config);

        foreach (var path in ExpandGlobs(files))
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"  File not found: {path}");
                missing++;
                continue;
            }

            var text = File.ReadAllText(path);

            ScanResult result;
            if (verbose)
            {
                result = scanner.ScanWithDiagnostics(text, out var diagnostics);
                PrintScanResultVerbose(path, result, diagnostics, debug);
            }
            else
            {
                result = scanner.Scan(text);
                PrintScanResult(path, result);
            }
            if (result.AboveThreshold.Count > 0) detected = true;
        }

        // 1: a file was not found. 2 (only with --exit-code): something would be tokenized.
        if (missing > 0) return 1;
        return detected && flags.Contains("--exit-code") ? 2 : 0;
    }

    private static int RunMask(string[] args)
    {
        var files = new List<string>();
        var values = new Dictionary<string, string>();
        var parseError = ParseArgs(args, [], ["-o", "--output"], [], values, files);
        if (parseError is not null)
            return Error(parseError);
        var outputPath = Value(values, "-o", "--output");

        if (files.Count == 0)
            return Error("Usage: shroud mask <file.md> [-o output.md]");

        var inputs = ExpandGlobs(files).ToList();
        if (outputPath is not null && inputs.Count > 1)
            return Error($"-o {outputPath} names one output file but {inputs.Count} input files were given; " +
                         "mask them one at a time, or omit -o to mask each file in place.");

        var config = LoadConfig();
        var scanner = CreateScanner(config);
        var key = LoadOrCreateKey(config);
        var masker = new SpanMasker(key);
        var missing = 0;
        var maskedInPlace = false;

        foreach (var path in inputs)
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"  File not found: {path}");
                missing++;
                continue;
            }

            var text = File.ReadAllText(path);
            var scanResult = scanner.Scan(text);

            if (scanResult.AboveThreshold.Count == 0)
            {
                Console.WriteLine($"  {path}: clean (no sensitive spans detected)");
                continue;
            }

            var maskResult = masker.Mask(text, scanResult);
            var target = outputPath ?? path;
            File.WriteAllText(target, maskResult.MaskedText);
            if (outputPath is null) maskedInPlace = true;

            Console.WriteLine($"  {path} -> {target}");
            Console.WriteLine($"    Masked {maskResult.Tokens.Count} spans:");
            foreach (var token in maskResult.Tokens)
            {
                Console.WriteLine($"      [{token.TokenId}] {token.Domain}/{token.EntityType}");
            }
        }

        if (maskedInPlace)
        {
            Console.Error.WriteLine("  Note: files were masked in place. mask is one-way: the original values are not stored anywhere.");
            Console.Error.WriteLine("  Use 'shroud vault' when you need to reveal them later.");
        }

        return missing > 0 ? 1 : 0;
    }

    private static int RunVault(string[] args)
    {
        var positionals = new List<string>();
        var values = new Dictionary<string, string>();
        var parseError = ParseArgs(args, [], ["-o", "--output", "-p", "--password"], [], values, positionals);
        if (parseError is not null)
            return Error(parseError);
        if (positionals.Count != 1)
            return Error("Usage: shroud vault <directory> [-o output] [-p password]");

        var sourceDir = positionals[0];
        if (!Directory.Exists(sourceDir))
            return Error($"Directory not found: {sourceDir}");

        var passwordArg = Value(values, "-p", "--password");
        var outputDir = Value(values, "-o", "--output") ?? NamedDirectory(sourceDir) + ".shroud";

        // An output inside the source would be scanned by the next run (masked copies of masked copies).
        if (IsSameOrInside(sourceDir, outputDir))
            return Error($"Output directory {outputDir} is inside the source directory. Choose a location outside it with -o.");

        var config = LoadConfig();
        var builder = VaultMaskingKeyOverride is { } fixedKey
            ? new VaultBuilder(CreateScanner(config), fixedKey)
            : new VaultBuilder(CreateScanner(config));

        Console.WriteLine($"\n  Scanning {sourceDir}...\n");
        VaultResult result;
        try
        {
            result = builder.Build(sourceDir);
        }
        catch (TokenCollisionException ex)
        {
            return Error(ex.Message);
        }

        if (result.Tokens.Count == 0)
        {
            Console.WriteLine("  No sensitive data detected. Nothing to vault.");
            return 0;
        }

        // Print summary by domain
        var byDomain = result.Tokens.Values
            .GroupBy(t => t.Domain)
            .OrderByDescending(g => g.Sum(t => t.Occurrences));
        foreach (var group in byDomain)
        {
            var files = group.SelectMany(t => t.Files).Distinct().Count();
            Console.WriteLine($"    {group.Key,-14} {group.Sum(t => t.Occurrences),3} spans across {files} files");
        }
        Console.WriteLine();

        // Get password
        var password = passwordArg ?? ReadPassword("  Vault password: ");
        if (string.IsNullOrEmpty(password))
            return Error("Password required.");

        // A piped password is one line on stdin; there is nothing to confirm it against.
        if (passwordArg is null && !Console.IsInputRedirected)
        {
            var confirm = ReadPassword("  Confirm: ");
            if (password != confirm)
                return Error("Passwords don't match.");
        }

        Console.WriteLine();
        builder.WriteOutput(result, outputDir, password);

        var maskedCount = result.MaskedFiles.Count(f => f.TokensApplied > 0);
        var cleanCount = result.MaskedFiles.Count - maskedCount;

        Console.WriteLine($"  {outputDir}/");
        Console.WriteLine($"    public/          {result.MaskedFiles.Count} files ({maskedCount} masked, {cleanCount} clean)");
        Console.WriteLine($"    vault.shroud     {result.Tokens.Count} tokens (encrypted)");
        Console.WriteLine($"    manifest.json    metadata for agents");
        Console.WriteLine($"\n  Source untouched. To reveal: shroud reveal \"{outputDir}\"");

        return 0;
    }

    private static int RunReveal(string[] args)
    {
        var positionals = new List<string>();
        var values = new Dictionary<string, string>();
        var parseError = ParseArgs(args, [], ["-o", "--output", "-p", "--password"], [], values, positionals);
        if (parseError is not null)
            return Error(parseError);
        if (positionals.Count != 1)
            return Error("Usage: shroud reveal <vault-dir> [-o output] [-p password]");

        var vaultDir = positionals[0];
        var vaultFile = Path.Combine(vaultDir, "vault.shroud");
        var publicDir = Path.Combine(vaultDir, "public");

        if (!File.Exists(vaultFile))
            return Error($"No vault.shroud found in {vaultDir}");

        var passwordArg = Value(values, "-p", "--password");
        var outputDir = Value(values, "-o", "--output");

        // Default: "<name>.shroud" reveals to "<name>.revealed", any other name to
        // "<name>.revealed" next to it. Never into the vault directory, whose public/ is shared.
        if (outputDir is null)
        {
            var named = NamedDirectory(vaultDir);
            const string suffix = ".shroud";
            var stem = named.EndsWith(suffix, StringComparison.Ordinal) && Path.GetFileName(named).Length > suffix.Length
                ? named[..^suffix.Length]
                : named;
            outputDir = stem + ".revealed";
        }
        if (IsSameOrInside(vaultDir, outputDir))
            return Error($"Output directory {outputDir} is inside the vault directory, which holds the shareable copies. Choose a location outside it with -o.");

        var password = passwordArg ?? ReadPassword("  Vault password: ");
        if (string.IsNullOrEmpty(password))
            return Error("Password required.");

        Console.WriteLine("  Decrypting...");
        var encrypted = File.ReadAllBytes(vaultFile);
        var json = VaultEncryption.DecryptString(encrypted, password);
        if (json is null)
            return Error("Wrong password.");

        var vaultData = System.Text.Json.JsonSerializer.Deserialize<VaultData>(json,
            new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
        if (vaultData?.Tokens is null)
            return Error("Corrupt vault file.");

        Directory.CreateDirectory(outputDir);
        var hashes = vaultData.FileHashes ?? new Dictionary<string, string>();

        var filesRevealed = 0;
        if (Directory.Exists(publicDir))
        {
            foreach (var file in Directory.EnumerateFiles(publicDir, "*.md", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(publicDir, file);
                var content = File.ReadAllText(file);

                // The vault records a hash of every masked copy it was built with (keys use the
                // writer's path separator). A vault without hashes is not checked.
                if (hashes.Count > 0)
                {
                    if (!hashes.TryGetValue(relative, out var expected) &&
                        !hashes.TryGetValue(relative.Replace('\\', '/'), out expected) &&
                        !hashes.TryGetValue(relative.Replace('/', '\\'), out expected))
                        Console.Error.WriteLine($"  Warning: {relative} is not part of this vault.");
                    else if (expected != VaultBuilder.ComputeHash(content))
                        Console.Error.WriteLine($"  Warning: {relative} was changed after it was vaulted.");
                }

                content = TokenRestorer.Restore(content, vaultData.Tokens, out var unresolved);
                if (unresolved > 0)
                    Console.Error.WriteLine($"  Warning: {relative}: {unresolved} token(s) are not in this vault and were left in place.");

                var outPath = Path.Combine(outputDir, relative);
                var dir = Path.GetDirectoryName(outPath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllText(outPath, content);
                filesRevealed++;
            }
        }

        Console.WriteLine($"\n  {filesRevealed} files revealed to {outputDir}/");
        return 0;
    }

    private static string ReadPassword(string prompt)
    {
        Console.Error.Write(prompt);

        // Piped or redirected input: the password is the first line of stdin.
        if (Console.IsInputRedirected)
        {
            var line = Console.In.ReadLine();
            Console.Error.WriteLine();
            return line ?? "";
        }

        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Error.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
                Console.Error.Write('*');
            }
        }
        return password.ToString();
    }

    private static int RunInit(string[] args)
    {
        var positionals = new List<string>();
        var values = new Dictionary<string, string>();
        var parseError = ParseArgs(args, [], ["-p", "--preset"], [], values, positionals);
        if (parseError is not null)
            return Error(parseError);
        if (positionals.Count > 0)
            return Error("Usage: shroud init [--preset paranoid|financial|dev]");

        // Same detection as running without a shroud.json at all.
        var preset = Value(values, "-p", "--preset") ?? "paranoid";

        if (!ShroudConfig.PresetNames.Contains(preset))
            return Error($"Unknown preset: {preset}. Valid presets: {string.Join(", ", ShroudConfig.PresetNames)}.");

        var config = ShroudConfig.ForPreset(preset);

        if (File.Exists(ConfigFileName))
        {
            Console.Error.WriteLine($"  {ConfigFileName} already exists. Delete it first to reinitialize.");
            return 1;
        }

        config.Save(ConfigFileName);
        Console.WriteLine($"  Created {ConfigFileName} with preset: {preset}");
        Console.WriteLine($"  Domains: onchain={config.Domains.OnChain.Enabled}, " +
                          $"financial={config.Domains.Financial.Enabled} ({config.Domains.Financial.Layer}), " +
                          $"identity={config.Domains.Identity.Enabled}, " +
                          $"credentials={config.Domains.Credentials.Enabled}, " +
                          $"secrets={config.Domains.Secrets.Enabled}");
        Console.WriteLine(Invariant($"  Threshold: {config.Threshold}"));
        return 0;
    }

    private static void PrintScanResult(string path, ScanResult result)
    {
        Console.WriteLine($"\n  {path}");
        Console.WriteLine($"  Detected: {result.AllDetected.Count} " +
                          $"(tokenize: {result.AboveThreshold.Count}, " +
                          $"below threshold: {result.BelowThreshold.Count})");

        if (result.AboveThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"    {"Domain",-12} {"Type",-18} {"Service",-24} {"Conf",5}  Value");
            Console.WriteLine($"    {new string('-', 90)}");
            foreach (var span in result.AboveThreshold)
            {
                var display = span.MatchedText.Length > 35
                    ? span.MatchedText[..35] + "..."
                    : span.MatchedText;
                var svc = string.IsNullOrEmpty(span.Service) ? "-" : span.Service;
                Console.WriteLine(Invariant($"    {span.Domain,-12} {span.EntityType,-18} {svc,-24} {span.Confidence,5:F2}  {display}"));
            }
        }

        if (result.BelowThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine(Invariant($"    Below threshold ({result.Threshold:F2}):"));
            foreach (var span in result.BelowThreshold)
            {
                var display = span.MatchedText.Length > 40
                    ? span.MatchedText[..40] + "..."
                    : span.MatchedText;
                Console.WriteLine(Invariant($"      {span.Domain,-12} {span.EntityType,-18} {span.Confidence,5:F2}  {display}"));
            }
        }
    }

    private static void PrintScanResultVerbose(string path, ScanResult result,
        ScanDiagnostics diagnostics, bool debug)
    {
        Console.WriteLine($"\n  {path}");
        Console.WriteLine($"  Detected: {result.AllDetected.Count} " +
                          $"(tokenize: {result.AboveThreshold.Count}, " +
                          $"below threshold: {result.BelowThreshold.Count})");

        if (debug && diagnostics.ExclusionZones.Count > 0)
        {
            Console.WriteLine($"\n    Exclusion zones:");
            foreach (var zone in diagnostics.ExclusionZones)
                Console.WriteLine($"      chars {zone.Start}-{zone.End}");
        }

        if (result.AboveThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"    {"Domain",-12} {"Type",-18} {"Service",-24} {"Conf",5}  Value");
            Console.WriteLine($"    {new string('-', 90)}");
            foreach (var span in result.AboveThreshold)
            {
                var display = span.MatchedText.Length > 35
                    ? span.MatchedText[..35] + "..."
                    : span.MatchedText;
                var svc = string.IsNullOrEmpty(span.Service) ? "-" : span.Service;
                Console.WriteLine(Invariant($"    {span.Domain,-12} {span.EntityType,-18} {svc,-24} {span.Confidence,5:F2}  {display}"));

                var diag = diagnostics.AllSpans
                    .FirstOrDefault(d => d.Span.Start == span.Start && d.Span.End == span.End && d.Span.EntityType == span.EntityType && d.Span.Service == span.Service && !d.WasExcluded && !d.FailedLuhn);
                if (diag != null)
                    PrintScoringDetail(diag.Scoring, debug);
            }
        }

        if (result.BelowThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine(Invariant($"    Below threshold ({result.Threshold:F2}):"));
            foreach (var span in result.BelowThreshold)
            {
                var display = span.MatchedText.Length > 40
                    ? span.MatchedText[..40] + "..."
                    : span.MatchedText;
                Console.WriteLine(Invariant($"      {span.Domain,-12} {span.EntityType,-18} {span.Confidence,5:F2}  {display}"));

                var diag = diagnostics.AllSpans
                    .FirstOrDefault(d => d.Span.Start == span.Start && d.Span.End == span.End && d.Span.EntityType == span.EntityType && d.Span.Service == span.Service && !d.WasExcluded && !d.FailedLuhn);
                if (diag != null)
                    PrintScoringDetail(diag.Scoring, debug);
            }
        }

        if (debug && diagnostics.OverlapResolutions.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"    Overlap resolutions:");
            foreach (var res in diagnostics.OverlapResolutions)
            {
                var droppedText = res.Dropped.MatchedText.Length > 30
                    ? res.Dropped.MatchedText[..30] + "..."
                    : res.Dropped.MatchedText;
                var winnerText = res.Winner.MatchedText.Length > 30
                    ? res.Winner.MatchedText[..30] + "..."
                    : res.Winner.MatchedText;
                Console.WriteLine($"      dropped \"{droppedText}\" ({res.Reason}) -> winner \"{winnerText}\"");
            }
        }

        if (debug)
        {
            var excluded = diagnostics.AllSpans.Count(d => d.WasExcluded);
            var luhnFailed = diagnostics.AllSpans.Count(d => d.FailedLuhn);
            if (excluded > 0 || luhnFailed > 0)
            {
                Console.WriteLine();
                if (excluded > 0) Console.WriteLine($"    {excluded} matches excluded (in exclusion zones)");
                if (luhnFailed > 0) Console.WriteLine($"    {luhnFailed} matches rejected (failed Luhn validation)");
            }
        }
    }

    private static void PrintScoringDetail(ScoringDetail scoring, bool debug)
    {
        if (!scoring.HasContextWords)
        {
            // No context words: the final confidence IS the base.
            Console.WriteLine(Invariant($"              structural match (base: {scoring.BaseConfidence:F2})"));
        }
        else
        {
            // Context words can boost even a structural (base >= 0.80) pattern, so show the real
            // breakdown whenever the pattern has any.
            var kind = scoring.IsStructural ? "structural" : "contextual";
            var boostStr = scoring.FinalConfidence - scoring.BaseConfidence;
            Console.WriteLine(Invariant($"              {kind} match (base: {scoring.BaseConfidence:F2} + context: +{boostStr:F2})"));
            if (scoring.ContextWordsFound.Count > 0)
            {
                var words = string.Join(", ", scoring.ContextWordsFound.Select(w => $"\"{w}\""));
                Console.WriteLine($"              context words: {words} (within {ContextScorer.ContextWindowChars} chars)");
            }
            if (debug)
            {
                if (scoring.AssetBoostApplied) Console.WriteLine(Invariant($"              + asset name boost (+{ContextScorer.AssetNameBoost:F2})"));
                if (scoring.CurrencyBoostApplied) Console.WriteLine(Invariant($"              + currency signal boost (+{ContextScorer.CurrencySignalBoost:F2})"));
                Console.WriteLine($"              context window: chars {scoring.ContextWindowStart}-{scoring.ContextWindowEnd}");
            }
        }
    }

    private static ShroudConfig LoadConfig()
    {
        return File.Exists(ConfigFileName)
            ? ShroudConfig.Load(ConfigFileName)
            : ShroudConfig.Default();
    }

    private static SensitivityScanner CreateScanner(ShroudConfig config)
    {
        var patterns = PatternLibrary.GetForConfig(config);
#if HAS_PRIVATE_PATTERNS
        patterns = patterns.Concat(EtherscanPatterns.GetAll()).ToList();
#endif
        return new SensitivityScanner(patterns, config.Threshold);
    }

    private static byte[] LoadOrCreateKey(ShroudConfig config)
    {
        var keyPath = config.KeyFile ?? ".shroud/vault.key";
        var dir = Path.GetDirectoryName(keyPath);

        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        if (File.Exists(keyPath))
            return File.ReadAllBytes(keyPath);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        File.WriteAllBytes(keyPath, key);
        Console.Error.WriteLine($"  Generated new key: {keyPath}");
        Console.Error.WriteLine("  Keep it to get the same token for the same value in later runs. It cannot unmask anything.");
        return key;
    }

    private static IEnumerable<string> ExpandGlobs(IEnumerable<string> args)
    {
        foreach (var arg in args)
        {
            if (arg.Contains('*') || arg.Contains('?'))
            {
                var dir = Path.GetDirectoryName(arg);
                var pattern = Path.GetFileName(arg);
                if (string.IsNullOrEmpty(dir)) dir = ".";
                foreach (var file in Directory.EnumerateFiles(dir, pattern))
                    yield return file;
            }
            else
            {
                yield return arg;
            }
        }
    }

    private static int PrintUsage()
    {
        Console.WriteLine("""
        shroud - Sensitive data detection and masking for text files

        Usage:
          shroud <directory>                         Vault a directory (safe copy + encrypted registry)
          shroud vault <directory> [-o output]        Same as above, explicit command
          shroud reveal <vault-dir> [-o output]       Decrypt and restore original files
          shroud scan <file.md> [--verbose] [--debug]      Detect sensitive spans, print report
          shroud mask <file.md> [-o output.md]        Replace spans with tokens, one-way (-o: one input only)
          shroud init [--preset paranoid|financial|dev]     Create shroud.json config (default: paranoid)

        Exit codes:
          0 success, 1 error (including a file that was not found).
          scan --exit-code exits 2 when a file has spans that would be tokenized.

        Passwords:
          vault and reveal prompt for the password, take it from -p, or read one line
          from piped stdin.

        Vault mode:
          Point at a directory. Shroud scans all .md files, produces:
            <dir>.shroud/public/       Masked copies (safe to share)
            <dir>.shroud/vault.shroud  Encrypted token registry (password required)
            <dir>.shroud/manifest.json Metadata for agents (no secret values)
          Only vault output can be revealed; 'mask' keeps no record of the original values.

        Presets:
          paranoid   All domains, lower threshold, directional financial (DEFAULT)
          financial  All domains, markets-level financial detection
          dev        On-chain + identity + credentials + secrets (no financial)

        Without shroud.json, paranoid mode is used. Run 'shroud init' to customize.

        Diagnostics:
          --verbose  Show confidence scoring breakdown for each detection
          --debug    Full diagnostics: exclusion zones, overlap resolutions, context windows

        Trust:
          Zero runtime dependencies. Source-auditable.
          https://github.com/dvdarkin/shroud
        """);
        return 0;
    }

    private static int Error(string message)
    {
        Console.Error.WriteLine($"  Error: {message}");
        return 1;
    }
}
