using System.Security.Cryptography;
using Shroud.Detection;
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

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        // If first arg is a directory path (no command prefix), treat as vault
        if (Directory.Exists(args[0]))
            return RunVault(args);

        return args[0] switch
        {
            "vault" => RunVault(args[1..]),
            "reveal" => RunReveal(args[1..]),
            "scan" => RunScan(args[1..]),
            "mask" => RunMask(args[1..]),
            "init" => RunInit(args[1..]),
            "help" or "--help" or "-h" => PrintUsage(),
            _ => Error($"Unknown command: {args[0]}")
        };
    }

    private static int RunScan(string[] args)
    {
        var files = new List<string>();
        var verbose = false;
        var debug = false;

        foreach (var arg in args)
        {
            if (arg is "--verbose" or "-v") verbose = true;
            else if (arg is "--debug") debug = true;
            else files.Add(arg);
        }

        if (files.Count == 0)
            return Error("Usage: shroud scan <file.md> [file2.md ...] [--verbose] [--debug]");

        if (debug) verbose = true;

        var config = LoadConfig();
        var scanner = CreateScanner(config);

        foreach (var path in ExpandGlobs(files))
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"  File not found: {path}");
                continue;
            }

            var text = File.ReadAllText(path);

            if (verbose)
            {
                var result = scanner.ScanWithDiagnostics(text, out var diagnostics);
                PrintScanResultVerbose(path, result, diagnostics, debug);
            }
            else
            {
                var result = scanner.Scan(text);
                PrintScanResult(path, result);
            }
        }

        return 0;
    }

    private static int RunMask(string[] args)
    {
        string? outputPath = null;
        var files = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            {
                outputPath = args[++i];
            }
            else
            {
                files.Add(args[i]);
            }
        }

        if (files.Count == 0)
            return Error("Usage: shroud mask <file.md> [-o output.md]");

        var config = LoadConfig();
        var scanner = CreateScanner(config);
        var key = LoadOrCreateKey(config);
        var masker = new SpanMasker(key);

        foreach (var path in ExpandGlobs(files))
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"  File not found: {path}");
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

            Console.WriteLine($"  {path} -> {target}");
            Console.WriteLine($"    Masked {maskResult.Tokens.Count} spans:");
            foreach (var token in maskResult.Tokens)
            {
                Console.WriteLine($"      [{token.TokenId}] {token.Domain}/{token.EntityType}");
            }
        }

        return 0;
    }

    private static int RunVault(string[] args)
    {
        if (args.Length == 0)
            return Error("Usage: shroud vault <directory>");

        var sourceDir = args[0];
        if (!Directory.Exists(sourceDir))
            return Error($"Directory not found: {sourceDir}");

        string? outputDir = null;
        string? passwordArg = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] is "-o" or "--output" && i + 1 < args.Length)
                outputDir = args[++i];
            else if (args[i] is "-p" or "--password" && i + 1 < args.Length)
                passwordArg = args[++i];
        }

        outputDir ??= sourceDir.TrimEnd('/', '\\') + ".shroud";

        var config = LoadConfig();
        var builder = new VaultBuilder(CreateScanner(config));

        Console.WriteLine($"\n  Scanning {sourceDir}...\n");
        var result = builder.Build(sourceDir);

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

        if (passwordArg is null)
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
        if (args.Length == 0)
            return Error("Usage: shroud reveal <vault-dir>");

        var vaultDir = args[0];
        var vaultFile = Path.Combine(vaultDir, "vault.shroud");
        var publicDir = Path.Combine(vaultDir, "public");

        if (!File.Exists(vaultFile))
            return Error($"No vault.shroud found in {vaultDir}");

        string? passwordArg = null;
        string? outputDir = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] is "-p" or "--password" && i + 1 < args.Length)
                passwordArg = args[++i];
            else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
                outputDir = args[++i];
        }

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
        if (vaultData is null)
            return Error("Corrupt vault file.");

        outputDir ??= vaultDir.Replace(".shroud", ".revealed");
        Directory.CreateDirectory(outputDir);

        var filesRevealed = 0;
        if (Directory.Exists(publicDir))
        {
            foreach (var file in Directory.EnumerateFiles(publicDir, "*.md", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(publicDir, file);
                var content = File.ReadAllText(file);

                // Replace all tokens with original values
                foreach (var (tokenId, value) in vaultData.Tokens)
                    content = content.Replace($"[{tokenId}]", value);

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
        var preset = "financial";
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--preset" or "-p" && i + 1 < args.Length)
                preset = args[++i];
        }

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
                          $"identity={config.Domains.Identity.Enabled}");
        Console.WriteLine($"  Threshold: {config.Threshold}");
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
                Console.WriteLine($"    {span.Domain,-12} {span.EntityType,-18} {svc,-24} {span.Confidence,5:F2}  {display}");
            }
        }

        if (result.BelowThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"    Below threshold ({result.Threshold:F2}):");
            foreach (var span in result.BelowThreshold)
            {
                var display = span.MatchedText.Length > 40
                    ? span.MatchedText[..40] + "..."
                    : span.MatchedText;
                Console.WriteLine($"      {span.Domain,-12} {span.EntityType,-18} {span.Confidence,5:F2}  {display}");
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
                Console.WriteLine($"    {span.Domain,-12} {span.EntityType,-18} {svc,-24} {span.Confidence,5:F2}  {display}");

                var diag = diagnostics.AllSpans
                    .FirstOrDefault(d => d.Span.Start == span.Start && d.Span.End == span.End && d.Span.EntityType == span.EntityType && !d.WasExcluded && !d.FailedLuhn);
                if (diag != null)
                    PrintScoringDetail(diag.Scoring, debug);
            }
        }

        if (result.BelowThreshold.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"    Below threshold ({result.Threshold:F2}):");
            foreach (var span in result.BelowThreshold)
            {
                var display = span.MatchedText.Length > 40
                    ? span.MatchedText[..40] + "..."
                    : span.MatchedText;
                Console.WriteLine($"      {span.Domain,-12} {span.EntityType,-18} {span.Confidence,5:F2}  {display}");

                var diag = diagnostics.AllSpans
                    .FirstOrDefault(d => d.Span.Start == span.Start && d.Span.End == span.End && d.Span.EntityType == span.EntityType && !d.WasExcluded && !d.FailedLuhn);
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
        if (scoring.IsStructural)
        {
            Console.WriteLine($"              structural match (base: {scoring.BaseConfidence:F2})");
        }
        else
        {
            var boostStr = scoring.FinalConfidence - scoring.BaseConfidence;
            Console.WriteLine($"              contextual match (base: {scoring.BaseConfidence:F2} + context: +{boostStr:F2})");
            if (scoring.ContextWordsFound.Count > 0)
            {
                var words = string.Join(", ", scoring.ContextWordsFound.Select(w => $"\"{w}\""));
                Console.WriteLine($"              context words: {words} (within {ContextScorer.ContextWindowChars} chars)");
            }
            if (debug)
            {
                if (scoring.AssetBoostApplied) Console.WriteLine($"              + asset name boost (+{ContextScorer.AssetNameBoost:F2})");
                if (scoring.CurrencyBoostApplied) Console.WriteLine($"              + currency signal boost (+{ContextScorer.CurrencySignalBoost:F2})");
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
        Console.Error.WriteLine($"  Back this up. Losing it means masked data cannot be unmasked.");
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
          shroud mask <file.md> [-o output.md]        Replace sensitive spans with tokens
          shroud init [--preset financial|dev|paranoid]     Create shroud.json config

        Vault mode:
          Point at a directory. Shroud scans all .md files, produces:
            <dir>.shroud/public/       Masked copies (safe to share)
            <dir>.shroud/vault.shroud  Encrypted token registry (password required)
            <dir>.shroud/manifest.json Metadata for agents (no secret values)

        Presets:
          paranoid   All domains, lower threshold, directional financial (DEFAULT)
          financial  All domains, markets-level financial detection
          dev        On-chain + identity + credentials + secrets (no financial)

        Without shroud.json, paranoid mode is used. Run 'shroud init' to customize.

        Diagnostics:
          --verbose  Show confidence scoring breakdown for each detection
          --debug    Full diagnostics: exclusion zones, overlap resolutions, context windows

        Trust:
          Zero dependencies beyond .NET 8 runtime. Source-auditable.
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
