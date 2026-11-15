using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Shroud.Detection;
using Shroud.Models;

var mode = args[0];
switch (mode)
{
    case "classes": Classes(args[1]); break;
    case "json": JsonEsc(args[1]); break;
    case "fmt": Fmt(args[1], args[2]); break;
    case "scan": Scan(args[1], args[2]); break;
    case "sort": SortProbe(args[1], args[2]); break;
    case "oic": Oic.Run(args[1]); break;
    case "bench": Bench.Run(args[1]); break;
    case "vectors": Vectors.Run(args[1]); break;
}

static List<int[]> Ranges(Func<char, bool> pred)
{
    var res = new List<int[]>();
    int start = -1;
    for (int i = 0; i <= 0x10000; i++)
    {
        bool m = i < 0x10000 && pred((char)i);
        if (m && start < 0) start = i;
        if (!m && start >= 0) { res.Add([start, i - 1]); start = -1; }
    }
    return res;
}

static void Classes(string outPath)
{
    var d = new Regex(@"^\d$");
    var w = new Regex(@"^\w$");
    var s = new Regex(@"^\s$");
    var dot = new Regex(@"^.$");
    var b = new Regex(@"\b");
    var ciAz = new Regex(@"^[a-z]$", RegexOptions.IgnoreCase);
    var ciAzInline = new Regex(@"(?i)^[a-z]$");
    var ciAf = new Regex(@"^[a-fA-F0-9]$", RegexOptions.IgnoreCase);
    var ciAll = new Dictionary<string, List<int[]>>();
    for (int a = 0x20; a < 0x7F; a++)
    {
        var rx = new Regex("^" + Regex.Escape(((char)a).ToString()) + "$", RegexOptions.IgnoreCase);
        var rxInline = new Regex("(?i)^" + Regex.Escape(((char)a).ToString()) + "$");
        var r1 = Ranges(c => rx.IsMatch(c.ToString()));
        var r2 = Ranges(c => rxInline.IsMatch(c.ToString()));
        if (JsonSerializer.Serialize(r1) != JsonSerializer.Serialize(r2)) throw new Exception("inline vs option differ " + a);
        ciAll[a.ToString()] = r1;
    }
    var result = new Dictionary<string, object>
    {
        ["culture"] = CultureInfo.CurrentCulture.Name,
        ["digit"] = Ranges(c => d.IsMatch(c.ToString())),
        ["word"] = Ranges(c => w.IsMatch(c.ToString())),
        ["space"] = Ranges(c => s.IsMatch(c.ToString())),
        ["dot"] = Ranges(c => dot.IsMatch(c.ToString())),
        ["boundaryWord"] = Ranges(c => b.IsMatch(c.ToString())),
        ["ciAz"] = Ranges(c => ciAz.IsMatch(c.ToString())),
        ["ciAzInline"] = Ranges(c => ciAzInline.IsMatch(c.ToString())),
        ["ciAf"] = Ranges(c => ciAf.IsMatch(c.ToString())),
        ["isDigit"] = Ranges(char.IsDigit),
        ["isControl"] = Ranges(char.IsControl),
        ["ci"] = ciAll,
    };
    File.WriteAllText(outPath, JsonSerializer.Serialize(result));
}

static void JsonEsc(string outPath)
{
    var opts = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };
    var sb = new StringBuilder();
    for (int i = 0; i < 0x10000; i++)
    {
        string enc;
        try { enc = JsonSerializer.Serialize(((char)i).ToString(), opts); }
        catch (Exception e) { enc = "THROW:" + e.GetType().Name; }
        sb.Append(enc).Append('\n');
    }
    // surrogate pair and nested structure samples
    sb.Append(JsonSerializer.Serialize("a😀b", opts)).Append('\n');
    var nested = new Dictionary<string, object>
    {
        ["k"] = new List<string> { "x", "y" },
        ["e"] = new List<string>(),
        ["o"] = new Dictionary<string, int>(),
        ["n"] = 0.7,
        ["m"] = new Dictionary<string, int> { ["a"] = 1 },
    };
    sb.Append(JsonSerializer.Serialize(nested, opts).Replace("\r", "<CR>").Replace("\n", "<LF>")).Append('\n');
    File.WriteAllText(outPath, sb.ToString());
}

static void Fmt(string inPath, string outPath)
{
    // input: one double per line as 16-hex-digit bit pattern
    var sb = new StringBuilder();
    foreach (var line in File.ReadAllLines(inPath))
    {
        if (line.Length == 0) continue;
        var dbl = BitConverter.Int64BitsToDouble(Convert.ToInt64(line, 16));
        sb.Append(line).Append('\t')
          .Append(dbl.ToString("F2")).Append('\t')
          .Append($"{dbl,5:F2}").Append('\t')
          .Append(dbl.ToString()).Append('\t')
          .Append(JsonSerializer.Serialize(dbl)).Append('\n');
    }
    File.WriteAllText(outPath, sb.ToString());
}

static void SortProbe(string inPath, string outPath)
{
    var items = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(inPath))!;
    var sorted = items.OrderBy(f => f).ToList();
    File.WriteAllText(outPath, JsonSerializer.Serialize(sorted));
}

static string Bits(double d) => BitConverter.DoubleToInt64Bits(d).ToString("x16");

static void Scan(string inPath, string outPath)
{
    var inputs = new List<string>();
    using (var br = new BinaryReader(File.OpenRead(inPath)))
    {
        while (br.BaseStream.Position < br.BaseStream.Length)
        {
            int n = br.ReadInt32();
            var chars = new char[n];
            for (int i = 0; i < n; i++) chars[i] = (char)br.ReadUInt16();
            inputs.Add(new string(chars));
        }
    }
    var patterns = PatternLibrary.GetAll();
    var t = typeof(SensitivityScanner);
    var fm = (Regex)t.GetField("FrontmatterRegex", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
    var fp = (Regex)t.GetField("FilePathRegex", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
    var dt = (Regex[])t.GetField("DateTimeExclusionRegexes", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
    var excl = new List<Regex> { fm, fp };
    excl.AddRange(dt);

    var scanners = new (string Name, SensitivityScanner S)[]
    {
        ("all", new SensitivityScanner()),
        ("paranoid", new SensitivityScanner(ShroudConfig.ForPreset("paranoid"))),
        ("financial", new SensitivityScanner(ShroudConfig.ForPreset("financial"))),
        ("dev", new SensitivityScanner(ShroudConfig.ForPreset("dev"))),
    };
    var swd = t.GetMethod("ScanWithDiagnostics", BindingFlags.NonPublic | BindingFlags.Instance)!;

    using var fs = File.Create(outPath);
    using var w = new Utf8JsonWriter(fs);
    w.WriteStartArray();
    foreach (var text in inputs)
    {
        w.WriteStartObject();
        w.WriteStartArray("m");
        for (int pi = 0; pi < patterns.Count; pi++)
            foreach (Match m in patterns[pi].CompiledRegex.Matches(text))
            { w.WriteStartArray(); w.WriteNumberValue(pi); w.WriteNumberValue(m.Index); w.WriteNumberValue(m.Length); w.WriteEndArray(); }
        w.WriteEndArray();
        w.WriteStartArray("x");
        for (int ri = 0; ri < excl.Count; ri++)
            foreach (Match m in excl[ri].Matches(text))
            { w.WriteStartArray(); w.WriteNumberValue(ri); w.WriteNumberValue(m.Index); w.WriteNumberValue(m.Length); w.WriteEndArray(); }
        w.WriteEndArray();
        foreach (var (name, sc) in scanners)
        {
            var callArgs = new object?[] { text, null };
            var res = (ScanResult)swd.Invoke(sc, callArgs)!;
            var diag = callArgs[1]!;
            w.WriteStartArray(name);
            foreach (var s in res.AllDetected) WriteSpan(w, s);
            w.WriteEndArray();
            w.WriteNumber(name + "_above", res.AboveThreshold.Count);
            // diagnostics
            var dType = diag.GetType();
            var zones = (List<(int Start, int End)>)dType.GetProperty("ExclusionZones")!.GetValue(diag)!;
            w.WriteStartArray(name + "_zones");
            foreach (var z in zones) { w.WriteNumberValue(z.Start); w.WriteNumberValue(z.End); }
            w.WriteEndArray();
            var all = (System.Collections.IList)dType.GetProperty("AllSpans")!.GetValue(diag)!;
            w.WriteStartArray(name + "_diag");
            foreach (var sd in all)
            {
                var sdt = sd!.GetType();
                var sp = (SensitiveSpan)sdt.GetProperty("Span")!.GetValue(sd)!;
                var sc2 = sdt.GetProperty("Scoring")!.GetValue(sd)!;
                var sct = sc2.GetType();
                w.WriteStartArray();
                WriteSpan(w, sp);
                w.WriteBooleanValue((bool)sdt.GetProperty("WasExcluded")!.GetValue(sd)!);
                w.WriteBooleanValue((bool)sdt.GetProperty("FailedLuhn")!.GetValue(sd)!);
                w.WriteStringValue(Bits((double)sct.GetProperty("BaseConfidence")!.GetValue(sc2)!));
                w.WriteStringValue(Bits((double)sct.GetProperty("FinalConfidence")!.GetValue(sc2)!));
                w.WriteBooleanValue((bool)sct.GetProperty("IsStructural")!.GetValue(sc2)!);
                w.WriteStringValue(string.Join("|", (List<string>)sct.GetProperty("ContextWordsFound")!.GetValue(sc2)!));
                w.WriteNumberValue((int)sct.GetProperty("ContextWindowStart")!.GetValue(sc2)!);
                w.WriteNumberValue((int)sct.GetProperty("ContextWindowEnd")!.GetValue(sc2)!);
                w.WriteBooleanValue((bool)sct.GetProperty("AssetBoostApplied")!.GetValue(sc2)!);
                w.WriteBooleanValue((bool)sct.GetProperty("CurrencyBoostApplied")!.GetValue(sc2)!);
                w.WriteStringValue((string)sct.GetProperty("PatternService")!.GetValue(sc2)!);
                w.WriteEndArray();
            }
            w.WriteEndArray();
            var ovl = (System.Collections.IList)dType.GetProperty("OverlapResolutions")!.GetValue(diag)!;
            w.WriteStartArray(name + "_ovl");
            foreach (var o in ovl)
            {
                var ot = o!.GetType();
                w.WriteStartArray();
                WriteSpan(w, (SensitiveSpan)ot.GetProperty("Dropped")!.GetValue(o)!);
                WriteSpan(w, (SensitiveSpan)ot.GetProperty("Winner")!.GetValue(o)!);
                w.WriteStringValue((string)ot.GetProperty("Reason")!.GetValue(o)!);
                w.WriteEndArray();
            }
            w.WriteEndArray();
        }
        w.WriteEndObject();
    }
    w.WriteEndArray();
}

static string Hex(string t) => string.Concat(t.Select(c => ((int)c).ToString("x4")));

static void WriteSpan(Utf8JsonWriter w, SensitiveSpan s)
{
    w.WriteStartArray();
    w.WriteNumberValue(s.Start);
    w.WriteNumberValue(s.End);
    w.WriteStringValue(s.EntityType.ToString());
    w.WriteStringValue(s.Domain.ToString());
    w.WriteStringValue(Bits(s.Confidence));
    w.WriteStringValue(s.Service);
    w.WriteStringValue(Hex(s.MatchedText));
    w.WriteEndArray();
}

static class Oic
{
    public static void Run(string outPath)
    {
        var res = new Dictionary<string, List<int>>();
        for (int a = 0x20; a < 0x7F; a++)
        {
            var n = ((char)a).ToString();
            var l = new List<int>();
            for (int h = 0; h < 0x10000; h++)
                if (((char)h).ToString().Contains(n, StringComparison.OrdinalIgnoreCase)) l.Add(h);
            res[a.ToString()] = l;
        }
        File.WriteAllText(outPath, JsonSerializer.Serialize(res));
    }
}

static class Bench
{
    public static void Run(string inPath)
    {
        var inputs = new List<string>();
        using (var br = new BinaryReader(File.OpenRead(inPath)))
            while (br.BaseStream.Position < br.BaseStream.Length)
            {
                int n = br.ReadInt32();
                var chars = new char[n];
                for (int i = 0; i < n; i++) chars[i] = (char)br.ReadUInt16();
                inputs.Add(new string(chars));
            }
        var s = new SensitivityScanner();
        foreach (var t in inputs.Take(200)) s.Scan(t);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long chars2 = 0; int spans = 0;
        foreach (var t in inputs) { spans += s.Scan(t).AllDetected.Count; chars2 += t.Length; }
        Console.WriteLine($"dotnet scan: {inputs.Count} inputs, {chars2} chars, {spans} spans, {sw.ElapsedMilliseconds} ms");
    }
}

static class Vectors
{
    // Emits interop vectors produced by the real C# code paths (VaultBuilder.WriteOutput,
    // VaultEncryption, SpanMasker, ShroudConfig.Save) for test/fixtures/dotnet-vectors.json.
    public static void Run(string outPath)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "shroud-vectors-" + Guid.NewGuid().ToString("N")[..8]);
        var src = Path.Combine(tmp, "src");
        Directory.CreateDirectory(Path.Combine(src, "sub"));
        File.WriteAllText(Path.Combine(src, "a.md"),
            "Sent 0.5 ETH to 0x1111111111111111111111111111111111111111 at $1,234.\n" +
            @"password = ""p<a>&'+`\\x"" and \\192.168.10.2\share\f.md" + "\n" +
            "bought ١٢٣ ETH été 😀 nonce:\u0085123456 tx\n");
        File.WriteAllText(Path.Combine(src, "sub", "b.md"), "SSN 123-45-6789\r\nghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA\r\nSent 0.5 ETH again\r\n");
        File.WriteAllText(Path.Combine(src, "clean.md"), "Nothing here.");
        var builder = new Shroud.Vault.VaultBuilder();
        var result = builder.Build(src);
        var vaultDir = Path.Combine(tmp, "out");
        const string password = "pässwörd 🔒";
        builder.WriteOutput(result, vaultDir, password);
        var blob = File.ReadAllBytes(Path.Combine(vaultDir, "vault.shroud"));
        var json = Shroud.Vault.VaultEncryption.DecryptString(blob, password)!;
        var manifest = File.ReadAllText(Path.Combine(vaultDir, "manifest.json"));
        var publicFiles = new Dictionary<string, string>();
        foreach (var f in Directory.EnumerateFiles(Path.Combine(vaultDir, "public"), "*", SearchOption.AllDirectories))
            publicFiles[Path.GetRelativePath(Path.Combine(vaultDir, "public"), f).Replace(Path.DirectorySeparatorChar, '/')] = Convert.ToBase64String(File.ReadAllBytes(f));

        var small = new Dictionary<string, string>();
        foreach (var (pw, text) in new[] { ("", ""), ("test-password-123", "Hello, Shroud!"), ("日本語", "{\"version\":1}") })
            small[pw] = Convert.ToBase64String(Shroud.Vault.VaultEncryption.EncryptString(text, pw)) + "|" + text;

        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var masker = new Shroud.Masking.SpanMasker(key);
        var tokens = new List<string[]>();
        foreach (var (type, text) in new[] { (EntityType.CryptoAddr, "0x1111111111111111111111111111111111111111"), (EntityType.Ssn, "123-45-6789"), (EntityType.Amount, "$500"), (EntityType.Email, "é😀@x.io"), (EntityType.PhoneNumber, ""), (EntityType.Quantity, "\uD800") })
        {
            var span = new SensitiveSpan(0, text.Length, type, SensitivityDomain.OnChain, 1, text);
            var r = masker.Mask(text, new ScanResult([span], [span], [], 0.7));
            tokens.Add([type.ToString(), Hex(text), r.Tokens[0].TokenId, r.MaskedText]);
        }
        static string Hex(string t) => string.Concat(t.Select(c => ((int)c).ToString("x4")));

        var configs = new Dictionary<string, string>();
        foreach (var preset in new[] { "financial", "dev", "paranoid" })
        {
            var p = Path.Combine(tmp, preset + ".json");
            ShroudConfig.ForPreset(preset).Save(p);
            configs[preset] = File.ReadAllText(p);
        }
        var custom = new ShroudConfig { KeyFile = "keys/k.bin", Threshold = 1e-7 };
        custom.Domains.Financial.Layer = null!;
        custom.Domains.Secrets = null!;
        var cp = Path.Combine(tmp, "custom.json"); custom.Save(cp); configs["custom"] = File.ReadAllText(cp);

        var o = new Dictionary<string, object>
        {
            ["runtime"] = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            ["password"] = password,
            ["vaultShroudBase64"] = Convert.ToBase64String(blob),
            ["vaultJson"] = json,
            ["manifestJson"] = manifest,
            ["publicFilesBase64"] = publicFiles,
            ["smallBlobs"] = small,
            ["maskKeyHex"] = Convert.ToHexString(key).ToLowerInvariant(),
            ["tokens"] = tokens,
            ["configs"] = configs,
        };
        File.WriteAllText(outPath, JsonSerializer.Serialize(o, new JsonSerializerOptions { WriteIndented = true }));
        Directory.Delete(tmp, true);
    }
}
