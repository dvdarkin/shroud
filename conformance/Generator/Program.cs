using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Shroud.Detection;
using Shroud.Masking;
using Shroud.Models;
using Shroud.Vault;

namespace Shroud.Conformance.Generator;

/// <summary>
/// Generates the Shroud conformance corpus ("golden oracle") from the C# implementation.
/// Uses only the public API of the Shroud library project. See conformance/README.md.
///
/// Usage: dotnet run --project conformance/Generator -- [--out DIR] [--vaults] [--culture NAME]
///   --out DIR       write expected/ output under DIR instead of conformance/expected
///   --vaults        (re)generate the vault fixtures (random salts/nonces/masking keys: output
///                   differs on every run). Without it, existing vault fixtures are only verified.
///   --culture NAME  run under this culture instead of the invariant culture (experiments only)
/// </summary>
public static class Program
{
    // Fixed masking key used for every mask golden: bytes 0x00..0x1f.
    private static readonly byte[] MaskKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    private static readonly (string Name, string Passphrase, string Config)[] VaultDefs =
    [
        ("v1-basic-mixed-nested", "correct horse battery staple (test only)", "default"),
        ("v2-unicode-passphrase-crlf", "pässwörd-тест-密码-\U0001F600", "default"),
        ("v3-dev-preset-credentials", "simple-test-passphrase-3", "dev"),
        ("v4-clean-only-no-tokens", "empty-vault-passphrase", "default"),
        ("v5-large-many-tokens", "large-vault-passphrase-5", "financial"),
    ];

    private static readonly List<string> Problems = [];

    public static int Main(string[] args)
    {
        string? outArg = null;
        string? cultureArg = null;
        var regenVaults = false;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--out" && i + 1 < args.Length) outArg = args[++i];
            else if (args[i] == "--culture" && i + 1 < args.Length) cultureArg = args[++i];
            else if (args[i] == "--vaults") regenVaults = true;
            else { Console.Error.WriteLine("Unknown argument: " + args[i]); return 2; }
        }

        // Determinism: pin the culture BEFORE any Regex is constructed (patterns capture it).
        var culture = cultureArg is null ? CultureInfo.InvariantCulture : new CultureInfo(cultureArg);
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;

        var root = FindRoot();
        var conf = Path.Combine(root, "conformance");
        var inputsDir = Path.Combine(conf, "inputs");
        var configsDir = Path.Combine(conf, "configs");
        var outDir = outArg is null ? Path.Combine(conf, "expected") : Path.GetFullPath(outArg);

        Console.WriteLine($"culture={(culture.Name.Length == 0 ? "invariant" : culture.Name)} out={outDir}");

        foreach (var sub in new[] { "scan", "mask", "config", "tokens" })
        {
            var p = Path.Combine(outDir, sub);
            if (Directory.Exists(p)) Directory.Delete(p, recursive: true);
        }
        Directory.CreateDirectory(outDir);

        var inputFiles = Directory.GetFiles(inputsDir, "*.md").OrderBy(f => f, StringComparer.Ordinal).ToList();
        var configFiles = Directory.GetFiles(configsDir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList();

        // ---- master pattern table ----
        var master = PatternLibrary.GetAll();
        WriteJson(Path.Combine(outDir, "patterns.json"), BuildPatternDump(master));

        // ---- inputs read once (File.ReadAllText, exactly as the CLI does) ----
        var inputs = inputFiles.Select(f => new InputFile(
            Path.GetFileNameWithoutExtension(f),
            File.ReadAllBytes(f),
            File.ReadAllText(f))).ToList();

        // ---- configs ----
        var configs = new List<(string Name, ShroudConfig Cfg, SensitivityScanner Scanner)>();
        foreach (var cf in configFiles)
        {
            var name = Path.GetFileNameWithoutExtension(cf);
            var cfg = ShroudConfig.Load(cf);
            var patterns = PatternLibrary.GetForConfig(cfg);
            var scanner = new SensitivityScanner(patterns, cfg.Threshold); // exactly what the CLI does
            configs.Add((name, cfg, scanner));
            WriteJson(Path.Combine(outDir, "config", name + ".json"), BuildConfigDump(name, cfg, patterns, master));
        }
        SelfCheckPresets(configsDir);

        // ---- scan goldens ----
        var scanCount = 0;
        foreach (var (cname, _, scanner) in configs)
        {
            foreach (var input in inputs)
            {
                var result = scanner.Scan(input.Text);
                WriteJson(Path.Combine(outDir, "scan", cname, input.Stem + ".json"),
                    BuildScanJson(input, cname, result));
                scanCount++;
            }
        }

        // ---- mask goldens (default config, fixed key) ----
        var defaultScanner = configs.First(c => c.Name == "default").Scanner;
        var masker = new SpanMasker(MaskKey);
        var maskCount = 0;
        foreach (var input in inputs)
        {
            var scan = defaultScanner.Scan(input.Text);
            var mask = masker.Mask(input.Text, scan);
            var maskedBytes = Utf8.GetBytes(mask.MaskedText);
            WriteBytes(Path.Combine(outDir, "mask", input.Stem + ".md"), maskedBytes);
            var ordered = scan.AboveThreshold.OrderByDescending(s => s.Start).ToList();
            var tokens = new List<object?>();
            for (var i = 0; i < mask.Tokens.Count; i++)
            {
                var t = mask.Tokens[i];
                tokens.Add(new O()
                    .P("tokenId", t.TokenId)
                    .P("start", ordered[i].Start)
                    .P("end", ordered[i].End)
                    .P("originalValue", t.OriginalValue)
                    .P("entityType", t.EntityType.ToString())
                    .P("domain", t.Domain.ToString()));
            }
            WriteJson(Path.Combine(outDir, "mask", input.Stem + ".tokens.json"), new O()
                .P("input", input.Stem + ".md")
                .P("config", "default")
                .P("maskKeyHex", Convert.ToHexString(MaskKey).ToLowerInvariant())
                .P("maskedUtf16Length", mask.MaskedText.Length)
                .P("maskedSha256", Sha256Hex(maskedBytes))
                .P("tokenCount", tokens.Count)
                .P("tokensInReplacementOrder", tokens));
            maskCount++;
        }

        // ---- token derivation vectors ----
        WriteJson(Path.Combine(outDir, "tokens", "derivation-vectors.json"), BuildTokenVectors());

        // ---- index ----
        WriteJson(Path.Combine(outDir, "index.json"), new O()
            .P("inputs", inputs.Select(i => (object?)new O()
                .P("name", i.Stem + ".md")
                .P("bytes", i.Bytes.Length)
                .P("utf16Length", i.Text.Length)
                .P("sha256", Sha256Hex(i.Bytes))).ToList())
            .P("configs", configs.Select(c => (object?)c.Name).ToList())
            .P("maskKeyHex", Convert.ToHexString(MaskKey).ToLowerInvariant()));

        Console.WriteLine($"inputs={inputs.Count} configs={configs.Count} scanFiles={scanCount} maskFiles={maskCount}x2");

        // ---- vaults ----
        ProcessVaults(conf, configsDir, regenVaults);

        if (Problems.Count > 0)
        {
            Console.WriteLine("PROBLEMS:");
            foreach (var p in Problems) Console.WriteLine("  " + p);
        }
        return Problems.Count == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------ scan

    private sealed record InputFile(string Stem, byte[] Bytes, string Text);

    private static O BuildScanJson(InputFile input, string config, ScanResult r)
    {
        // AboveThreshold elements are the same instances as in AllDetected (Where over the same list).
        var above = new HashSet<SensitiveSpan>(r.AboveThreshold, ReferenceEqualityComparer.Instance as IEqualityComparer<SensitiveSpan>);
        var spans = new List<object?>();
        for (var i = 0; i < r.AllDetected.Count; i++)
        {
            var s = r.AllDetected[i];
            spans.Add(new O()
                .P("index", i)
                .P("start", s.Start)
                .P("end", s.End)
                .P("length", s.Length)
                .P("matchedText", s.MatchedText)
                .P("entityType", s.EntityType.ToString())
                .P("domain", s.Domain.ToString())
                .P("service", s.Service)
                .P("typeAbbreviation", s.TypeAbbreviation)
                .P("confidence", s.Confidence)
                .P("confidenceString", Json.Num(s.Confidence))
                .P("aboveThreshold", above.Contains(s)));
        }
        return new O()
            .P("input", input.Stem + ".md")
            .P("config", config)
            .P("inputBytes", input.Bytes.Length)
            .P("inputSha256", Sha256Hex(input.Bytes))
            .P("inputUtf16Length", input.Text.Length)
            .P("threshold", r.Threshold)
            .P("thresholdString", Json.Num(r.Threshold))
            .P("counts", new O()
                .P("allDetected", r.AllDetected.Count)
                .P("aboveThreshold", r.AboveThreshold.Count)
                .P("belowThreshold", r.BelowThreshold.Count))
            .P("allDetected", spans);
    }

    // ------------------------------------------------------------------ patterns / configs

    private static O BuildPatternDump(IReadOnlyList<SensitivityPattern> master)
    {
        var list = new List<object?>();
        for (var i = 0; i < master.Count; i++)
        {
            var p = master[i];
            list.Add(new O()
                .P("index", i)
                .P("service", p.Service)
                .P("entityType", p.EntityType.ToString())
                .P("domain", p.Domain.ToString())
                .P("regex", p.CompiledRegex.ToString())
                .P("regexOptionsDotNet", p.CompiledRegex.Options.ToString())
                .P("regexOptionsDotNetValue", (int)p.CompiledRegex.Options)
                .P("baseConfidence", p.BaseConfidence)
                .P("baseConfidenceString", Json.Num(p.BaseConfidence))
                .P("contextWords", p.ContextWords.ToList())
                .P("contextBoost", p.ContextBoost)
                .P("contextBoostString", Json.Num(p.ContextBoost))
                .P("isStructural", p.IsStructural));
        }
        return new O()
            .P("note", "Pattern library in evaluation order. regex is Regex.ToString() (the .NET pattern source). " +
                       "Evaluation order matters: overlap tie-breaking depends on it.")
            .P("contextWindowChars", ContextScorer.ContextWindowChars)
            .P("additionalContextWordBoost", ContextScorer.AdditionalContextWordBoost)
            .P("maxAdditionalContextWords", ContextScorer.MaxAdditionalContextWords)
            .P("assetNameBoost", ContextScorer.AssetNameBoost)
            .P("currencySignalBoost", ContextScorer.CurrencySignalBoost)
            .P("knownAssets", PatternLibrary.KnownAssets.OrderBy(a => a, StringComparer.Ordinal).ToList())
            .P("patternCount", master.Count)
            .P("patterns", list);
    }

    private static O BuildConfigDump(string name, ShroudConfig cfg, IReadOnlyList<SensitivityPattern> enabled,
        IReadOnlyList<SensitivityPattern> master)
    {
        static O Dom(DomainToggle t) => new O().P("enabled", t.Enabled).P("layer", t.Layer);
        var idx = new List<object?>();
        var services = new List<object?>();
        foreach (var p in enabled)
        {
            var found = -1;
            for (var i = 0; i < master.Count; i++)
            {
                if (master[i].Service == p.Service && master[i].CompiledRegex.ToString() == p.CompiledRegex.ToString())
                { found = i; break; }
            }
            idx.Add(found);
            services.Add(p.Service);
        }
        return new O()
            .P("config", name)
            .P("sourceFile", "configs/" + name + ".json")
            .P("threshold", cfg.Threshold)
            .P("thresholdString", Json.Num(cfg.Threshold))
            .P("preset", cfg.Preset)
            .P("keyFile", cfg.KeyFile)
            .P("domains", new O()
                .P("onChain", Dom(cfg.Domains.OnChain))
                .P("financial", Dom(cfg.Domains.Financial))
                .P("identity", Dom(cfg.Domains.Identity))
                .P("credentials", Dom(cfg.Domains.Credentials))
                .P("secrets", Dom(cfg.Domains.Secrets)))
            .P("patternCount", enabled.Count)
            .P("patternIndexes", idx)
            .P("patternServices", services);
    }

    /// <summary>The preset config files must equal ShroudConfig.ForPreset(...) / Default().</summary>
    private static void SelfCheckPresets(string configsDir)
    {
        static string Canon(ShroudConfig c) => JsonSerializer.Serialize(c);
        foreach (var (file, expected) in new (string, ShroudConfig)[]
                 {
                     ("default.json", ShroudConfig.Default()),
                     ("paranoid.json", ShroudConfig.ForPreset("paranoid")),
                     ("financial.json", ShroudConfig.ForPreset("financial")),
                     ("dev.json", ShroudConfig.ForPreset("dev")),
                 })
        {
            var loaded = ShroudConfig.Load(Path.Combine(configsDir, file));
            if (Canon(loaded) != Canon(expected))
                Problems.Add($"configs/{file} differs from the in-code preset");
        }
    }

    // ------------------------------------------------------------------ token vectors

    private static O BuildTokenVectors()
    {
        var keys = new (string Label, byte[] Key)[]
        {
            ("fixed-32 (bytes 0x00..0x1f)", MaskKey),
            ("ascii-9 (short-key)", Encoding.ASCII.GetBytes("short-key")),
            ("repeat-100 (0xAB x 100, longer than the HMAC block size)", Enumerable.Repeat((byte)0xAB, 100).ToArray()),
            ("empty-0", Array.Empty<byte>()),
        };
        var texts = new[]
        {
            "0x" + new string('1', 40),
            "alice@example.com",
            "123-45-6789",
            "",
            "café É",
            "привет",
            "钱包地址",
            "\U0001F600 emoji \U0001F511",
            "line1\r\nline2",
            "tab\there",
            "$1,234.56",
            new string('x', 5000),
        };
        var vectors = new List<object?>();
        foreach (var (label, key) in keys)
        {
            var m = new SpanMasker(key);
            foreach (var text in texts)
            {
                var token = TokenFor(m, text, EntityType.Email, SensitivityDomain.Identity);
                var big = text.Length > 100;
                vectors.Add(new O()
                    .P("keyLabel", label)
                    .P("keyHex", Convert.ToHexString(key).ToLowerInvariant())
                    .P("textUtf8Hex", big ? null : Convert.ToHexString(Utf8.GetBytes(text)).ToLowerInvariant())
                    .P("text", big ? "the character x repeated " + text.Length + " times" : text)
                    .P("textUtf16Length", text.Length)
                    .P("entityType", "Email")
                    .P("tokenId", token));
            }
        }
        var abbreviations = new List<object?>();
        var mk = new SpanMasker(MaskKey);
        foreach (var et in Enum.GetValues<EntityType>())
        {
            var span = new SensitiveSpan(0, 6, et, SensitivityDomain.OnChain, 0.9, "sample");
            abbreviations.Add(new O()
                .P("entityType", et.ToString())
                .P("typeAbbreviation", span.TypeAbbreviation)
                .P("tokenIdForTextSampleWithFixedKey", TokenFor(mk, "sample", et, SensitivityDomain.OnChain)));
        }
        return new O()
            .P("algorithm", "tokenId = TypeAbbreviation + \":\" + lowercaseHex(HMAC-SHA256(key, UTF8(matchedText))[0..4]); masked text contains \"[\" + tokenId + \"]\"")
            .P("vectors", vectors)
            .P("typeAbbreviations", abbreviations);
    }

    private static string TokenFor(SpanMasker masker, string text, EntityType type, SensitivityDomain domain)
    {
        var span = new SensitiveSpan(0, text.Length, type, domain, 0.9, text);
        var scan = new ScanResult([span], [span], [], 0.7);
        return masker.Mask(text, scan).Tokens[0].TokenId;
    }

    // ------------------------------------------------------------------ vaults

    private static void ProcessVaults(string conf, string configsDir, bool regen)
    {
        var vaultsDir = Path.Combine(conf, "vaults");
        var originalCwd = Environment.CurrentDirectory;
        foreach (var (name, pass, configName) in VaultDefs)
        {
            var vdir = Path.Combine(vaultsDir, name);
            var inputDir = Path.Combine(vdir, "input");
            if (!Directory.Exists(inputDir)) { Problems.Add("missing vault input dir: " + inputDir); continue; }
            var vaultOut = Path.Combine(vdir, "vault");
            var cfg = ShroudConfig.Load(Path.Combine(configsDir, configName + ".json"));

            if (regen)
            {
                foreach (var d in new[] { vaultOut, Path.Combine(vdir, "restored") })
                    if (Directory.Exists(d)) Directory.Delete(d, recursive: true);
                foreach (var f in new[] { "vault-data.decrypted.json", "meta.json" })
                    if (File.Exists(Path.Combine(vdir, f))) File.Delete(Path.Combine(vdir, f));

                // Relative source dir so manifest.json "source" is "input", not an absolute path.
                Environment.CurrentDirectory = vdir;
                try
                {
                    var builder = new VaultBuilder(cfg);
                    var result = builder.Build("input");
                    builder.WriteOutput(result, "vault", pass);
                }
                finally { Environment.CurrentDirectory = originalCwd; }
            }

            if (!File.Exists(Path.Combine(vaultOut, "vault.shroud")))
            {
                Problems.Add($"{name}: vault.shroud missing (run with --vaults)");
                continue;
            }

            // Verify: wrong passphrase rejected, right passphrase decrypts, reveal == source.
            var enc = File.ReadAllBytes(Path.Combine(vaultOut, "vault.shroud"));
            if (VaultEncryption.Decrypt(enc, pass + "x") is not null)
                Problems.Add($"{name}: wrong passphrase was NOT rejected");
            var json = VaultEncryption.DecryptString(enc, pass);
            if (json is null) { Problems.Add($"{name}: could not decrypt with the documented passphrase"); continue; }
            var data = JsonSerializer.Deserialize<VaultData>(json,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })!;

            var restored = new SortedDictionary<string, string>(StringComparer.Ordinal);
            var publicDir = Path.Combine(vaultOut, "public");
            foreach (var file in Directory.EnumerateFiles(publicDir, "*.md", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(publicDir, file).Replace('\\', '/');
                var content = File.ReadAllText(file);
                var maskedBytes = File.ReadAllBytes(file);
                // same algorithm as the CLI "reveal" command
                var plain = content;
                foreach (var (tokenId, value) in data.Tokens)
                    plain = plain.Replace($"[{tokenId}]", value);
                restored[rel] = plain;

                var srcPath = Path.Combine(inputDir, rel.Replace('/', Path.DirectorySeparatorChar));
                var src = File.ReadAllText(srcPath);
                if (src != plain)
                    Problems.Add($"{name}: reveal of {rel} does not equal the source file (C# round-trip defect)");

                // file hash recorded inside the vault: sha256 of UTF-8 bytes of the masked content
                var hashKeyBackslash = rel.Replace('/', '\\');
                if (!data.FileHashes.TryGetValue(rel, out var hv) && !data.FileHashes.TryGetValue(hashKeyBackslash, out hv))
                    Problems.Add($"{name}: no fileHashes entry for {rel}");
                else if (hv != "sha256:" + Sha256Hex(maskedBytes))
                    Problems.Add($"{name}: fileHashes mismatch for {rel}");
            }

            var srcCount = Directory.EnumerateFiles(inputDir, "*.md", SearchOption.AllDirectories).Count();
            if (srcCount != restored.Count)
                Problems.Add($"{name}: source has {srcCount} files, public has {restored.Count}");

            if (regen)
            {
                foreach (var (rel, plain) in restored)
                    WriteBytes(Path.Combine(vdir, "restored", rel), Utf8.GetBytes(plain));
                WriteBytes(Path.Combine(vdir, "vault-data.decrypted.json"), Utf8.GetBytes(json));

                var meta = new O()
                    .P("name", name)
                    .P("passphrase", pass)
                    .P("passphraseUtf8Hex", Convert.ToHexString(Utf8.GetBytes(pass)).ToLowerInvariant())
                    .P("config", "configs/" + configName + ".json")
                    .P("vaultFileBytes", enc.Length)
                    .P("tokenCount", data.Tokens.Count)
                    .P("sourceFiles", restored.Keys.Cast<object?>().ToList())
                    .P("note", "vault/vault.shroud, vault/manifest.json and vault/public/ were written by the C# VaultBuilder on Windows; " +
                               "relative paths inside manifest.json and vault-data.decrypted.json (files lists, fileHashes keys) use the OS separator, i.e. backslash here.");
                WriteJson(Path.Combine(vdir, "meta.json"), meta);
            }
            Console.WriteLine($"vault {name}: ok tokens={data.Tokens.Count} files={restored.Count} bytes={enc.Length}");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static string FindRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        {
            var d = new DirectoryInfo(start);
            while (d != null)
            {
                if (Directory.Exists(Path.Combine(d.FullName, "conformance", "inputs"))) return d.FullName;
                d = d.Parent;
            }
        }
        throw new InvalidOperationException("Could not locate the repo root (a directory containing conformance/inputs).");
    }

    private static string Sha256Hex(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static void WriteJson(string path, object value) => WriteBytes(path, Utf8.GetBytes(Json.Write(value)));

    private static void WriteBytes(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
    }
}
