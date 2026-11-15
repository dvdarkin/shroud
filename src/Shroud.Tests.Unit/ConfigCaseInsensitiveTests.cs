using FluentAssertions;
using Shroud.Models;
using Xunit;

namespace Shroud.Tests.Unit;

/// <summary>
/// shroud.json property names are matched case-insensitively at every level, so a user who
/// writes "onchain" instead of "onChain" gets the configuration they wrote.
/// </summary>
public class ConfigCaseInsensitiveTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"shroud-config-{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }

    private ShroudConfig LoadJson(string json)
    {
        File.WriteAllText(_path, json);
        return ShroudConfig.Load(_path);
    }

    [Fact]
    public void LowercaseNestedKey_IsHonoured()
    {
        var cfg = LoadJson("""{ "domains": { "onchain": { "enabled": false } } }""");

        cfg.Domains.OnChain.Enabled.Should().BeFalse("\"onchain\" must configure the onChain domain");
    }

    [Fact]
    public void MixedCaseKeys_AtEveryLevel_AreHonoured()
    {
        var cfg = LoadJson("""
            {
              "DOMAINS": {
                "OnChain": { "ENABLED": false },
                "FINANCIAL": { "Enabled": true, "LAYER": "magnitudes" },
                "identity": { "enabled": false },
                "Credentials": { "Enabled": false },
                "SECRETS": { "enabled": false }
              },
              "Threshold": 0.9,
              "KEYFILE": "k.key",
              "Preset": "custom"
            }
            """);

        cfg.Domains.OnChain.Enabled.Should().BeFalse();
        cfg.Domains.Financial.Enabled.Should().BeTrue();
        cfg.Domains.Financial.Layer.Should().Be("magnitudes");
        cfg.Domains.Identity.Enabled.Should().BeFalse();
        cfg.Domains.Credentials.Enabled.Should().BeFalse();
        cfg.Domains.Secrets.Enabled.Should().BeFalse();
        cfg.Threshold.Should().Be(0.9);
        cfg.KeyFile.Should().Be("k.key");
        cfg.Preset.Should().Be("custom");
    }

    [Fact]
    public void EmptyObject_KeepsClassDefaults_NotTheParanoidPreset()
    {
        // Unchanged behaviour: {} is not Default(); it keeps the property defaults.
        var cfg = LoadJson("{}");

        cfg.Threshold.Should().Be(0.70);
        cfg.Domains.Financial.Layer.Should().Be("markets");
        cfg.Preset.Should().BeNull();
    }
}
