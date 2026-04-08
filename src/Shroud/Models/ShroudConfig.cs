using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shroud.Models;

/// <summary>
/// Detection configuration with three presets: paranoid (all domains, directional financial,
/// threshold 0.50 — catches more but noisier), financial (all domains, markets-level financial,
/// threshold 0.70 — balanced), dev (no financial domain, threshold 0.70 — for codebases where
/// dollar amounts are irrelevant). Financial sensitivity is compositional and layered: "magnitudes"
/// detects amounts/prices/quantities, "markets" adds market pairs (EUR/USD), and "directional"
/// adds direction words (buy/sell/long/short) which are only sensitive in combination.
/// </summary>
public class ShroudConfig
{
    public DomainConfig Domains { get; set; } = new();
    public double Threshold { get; set; } = 0.70;
    public string? KeyFile { get; set; }
    public string? Preset { get; set; }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static ShroudConfig Load(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<ShroudConfig>(json, JsonOpts) ?? new ShroudConfig();
    }

    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(path, json);
    }

    public static ShroudConfig Default() => ForPreset("paranoid");

    public static ShroudConfig ForPreset(string preset) => preset switch
    {
        "financial" => new ShroudConfig
        {
            Domains = new DomainConfig
            {
                OnChain = new DomainToggle { Enabled = true },
                Financial = new DomainToggle { Enabled = true, Layer = "markets" },
                Identity = new DomainToggle { Enabled = true }
            },
            Threshold = 0.70,
            Preset = "financial"
        },
        "dev" => new ShroudConfig
        {
            Domains = new DomainConfig
            {
                OnChain = new DomainToggle { Enabled = true },
                Financial = new DomainToggle { Enabled = false },
                Identity = new DomainToggle { Enabled = true }
            },
            Threshold = 0.70,
            Preset = "dev"
        },
        "paranoid" => new ShroudConfig
        {
            Domains = new DomainConfig
            {
                OnChain = new DomainToggle { Enabled = true },
                Financial = new DomainToggle { Enabled = true, Layer = "directional" },
                Identity = new DomainToggle { Enabled = true }
            },
            Threshold = 0.50,
            Preset = "paranoid"
        },
        _ => Default()
    };
}

public class DomainConfig
{
    public DomainToggle OnChain { get; set; } = new() { Enabled = true };
    public DomainToggle Financial { get; set; } = new() { Enabled = true, Layer = "markets" };
    public DomainToggle Identity { get; set; } = new() { Enabled = true };
    public DomainToggle Credentials { get; set; } = new() { Enabled = true };
    public DomainToggle Secrets { get; set; } = new() { Enabled = true };
}

public class DomainToggle
{
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Financial detection granularity. "magnitudes" = amounts/prices/quantities only.
    /// "markets" = magnitudes + market pairs (EUR/USD). "directional" = markets + direction
    /// words (buy/sell/long/short). Each level includes all previous levels.
    /// </summary>
    public string Layer { get; set; } = "markets";
}
