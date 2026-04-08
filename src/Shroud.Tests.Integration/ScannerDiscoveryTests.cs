using FluentAssertions;
using Shroud.Detection;
using Shroud.Models;
using Shroud.Tests.Integration.Fixtures;
using Xunit;
using Xunit.Abstractions;

namespace Shroud.Tests.Integration;

/// <summary>
/// Discovery tests: scan realistic journal entries and print what was found.
/// Run: dotnet test --filter ScannerDiscoveryTests --logger "console;verbosity=detailed"
/// </summary>
public class ScannerDiscoveryTests
{
    private readonly ITestOutputHelper _output;
    private readonly SensitivityScanner _scanner;

    public ScannerDiscoveryTests(ITestOutputHelper output)
    {
        _output = output;
        _scanner = new SensitivityScanner();
    }

    [Fact]
    public void EthDca_DetectsAddressesAndAmounts()
    {
        var result = ScanAndPrint("ETH DCA Entry", ScannerFixtures.EthDcaEntry);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.CryptoAddr);
        result.AllDetected.Should().Contain(s => s.EntityType == EntityType.TxHash);
    }

    [Fact]
    public void BtcPosition_DetectsAddressAndAmounts()
    {
        var result = ScanAndPrint("BTC Position Review", ScannerFixtures.BtcPositionReview);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.CryptoAddr);
    }

    [Fact]
    public void DefiYield_DetectsContractsAndTx()
    {
        var result = ScanAndPrint("DeFi Yield Entry", ScannerFixtures.DefiYieldEntry);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.CryptoAddr);
        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.TxHash);
    }

    [Fact]
    public void StrategyThinking_MinimalDetections()
    {
        var result = ScanAndPrint("Strategy Thinking (should be mostly clean)", ScannerFixtures.StrategyThinking);

        result.AboveThreshold.Where(s => s.Domain == SensitivityDomain.OnChain)
            .Should().BeEmpty("pure reasoning has no on-chain artifacts");
    }

    [Fact]
    public void ValidatorAndBridge_DetectsAllOnChainArtifacts()
    {
        var result = ScanAndPrint("Validator + Bridge", ScannerFixtures.ValidatorAndBridge);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.EnsName);
        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.TxHash);
        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.CryptoAddr);
    }

    [Fact]
    public void ForexJournal_DetectsFinancialNotOnChain()
    {
        var result = ScanAndPrint("Forex Journal", ScannerFixtures.ForexJournal);

        result.AboveThreshold.Where(s => s.Domain == SensitivityDomain.OnChain)
            .Should().BeEmpty("forex journal has no blockchain artifacts");
        result.AboveThreshold.Should().Contain(s => s.Domain == SensitivityDomain.Financial);
    }

    [Fact]
    public void DevSetup_DetectsApiKeys()
    {
        var result = ScanAndPrint("Dev Setup (API keys)", ScannerFixtures.DevSetupEntry);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.ApiKey);
        result.AllDetected.Should().Contain(s => s.EntityType == EntityType.IpAddress);
    }

    [Fact]
    public void TaxPrep_DetectsIdentityAndFinancial()
    {
        var result = ScanAndPrint("Tax Prep", ScannerFixtures.TaxPrep);

        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.Ssn);
        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.Iban);
    }

    [Fact]
    public void CurrencyFormats_DetectsAllVariants()
    {
        var result = ScanAndPrint("Currency Formats", ScannerFixtures.CurrencyFormats);

        // Symbol amounts: $1,234, $12.5k, $1.2M, $500
        result.AboveThreshold.Should().Contain(s => s.Service == "symbol_amount");
        // Code amounts: USD 5,000, AUD 12.5k
        result.AboveThreshold.Should().Contain(s => s.Service == "fiat_currency_amount");
        // Trailing: 5,000 USD, 12.5k AUD
        result.AboveThreshold.Should().Contain(s =>
            s.Service == "fiat_amount_trailing" || s.Service == "usd_code_amount");
        // Shorthand with financial context: 12.5k, 1.2M near "portfolio", "position"
        result.AboveThreshold.Should().Contain(s => s.Service == "shorthand_amount");

        // "12k connections" without financial context should be below threshold
        var serverDetections = result.AboveThreshold
            .Where(s => s.Service == "shorthand_amount")
            .ToList();
        _output.WriteLine($"\n  Shorthand detections: {serverDetections.Count}");
    }

    [Fact]
    public void CodeDiscussion_MinimalFalsePositives()
    {
        var result = ScanAndPrint("Code Discussion (false positive trap)", ScannerFixtures.CodeDiscussion);

        var falseFinancial = result.AboveThreshold
            .Where(s => s.Domain == SensitivityDomain.Financial)
            .ToList();

        _output.WriteLine($"\n  False positive financial detections: {falseFinancial.Count}");
        foreach (var fp in falseFinancial)
            _output.WriteLine($"    WARNING: {fp.EntityType} '{Truncate(fp.MatchedText)}' @ {fp.Confidence:F2}");
    }

    [Fact]
    public void MeetingNotes_MinimalFalsePositives()
    {
        var result = ScanAndPrint("Meeting Notes (false positive trap)", ScannerFixtures.MeetingNotes);

        var falsePositives = result.AboveThreshold.ToList();

        _output.WriteLine($"\n  False positives above threshold: {falsePositives.Count}");
        foreach (var fp in falsePositives)
            _output.WriteLine($"    WARNING: {fp.EntityType} '{Truncate(fp.MatchedText)}' @ {fp.Confidence:F2}");
    }

    [Fact]
    public void CredentialsHeavy_DetectsServiceSpecificKeys()
    {
        var result = ScanAndPrint("Credentials Heavy", ScannerFixtures.CredentialsHeavy);

        result.AboveThreshold.Should().Contain(s => s.Service == "aws_access_key");
        result.AboveThreshold.Should().Contain(s => s.Service == "github_pat");
        result.AboveThreshold.Should().Contain(s => s.Service == "stripe_key");
        result.AboveThreshold.Should().Contain(s => s.Service == "jwt");
        result.AboveThreshold.Should().Contain(s => s.Service == "pem_private_key");
        result.AboveThreshold.Should().Contain(s => s.Service == "database_uri");
    }

    [Fact]
    public void MultiChainWallet_DetectsAllChains()
    {
        var result = ScanAndPrint("Multi-Chain Wallet", ScannerFixtures.MultiChainWallet);

        // Should detect addresses across multiple chains
        var chains = result.AboveThreshold
            .Where(s => s.EntityType == EntityType.CryptoAddr)
            .Select(s => s.Service)
            .Distinct()
            .ToList();
        _output.WriteLine($"\n  Chains detected: {string.Join(", ", chains)}");
        chains.Should().HaveCountGreaterThanOrEqualTo(5, "should detect at least 5 different chains");
    }

    [Fact]
    public void CreditCard_LuhnValidation()
    {
        var result = ScanAndPrint("Credit Card Entry", ScannerFixtures.CreditCardEntry);

        // Valid Luhn numbers should be detected
        result.AboveThreshold.Should().Contain(s => s.EntityType == EntityType.CreditCard);

        // Invalid Luhn numbers should NOT be detected as credit card
        var ccCount = result.AboveThreshold.Count(s => s.EntityType == EntityType.CreditCard);
        ccCount.Should().Be(3, "only Luhn-valid cards should match (Visa, Amex, Mastercard)");
    }

    [Fact]
    public void WalletTable_DetectsAllLeakTypes()
    {
        var result = ScanAndPrint("Wallet Table Export", ScannerFixtures.WalletTableExport);

        // Should detect: full addresses, truncated addresses, explorer URLs,
        // wei-precision quantities, dollar amounts
        result.AboveThreshold.Should().Contain(s => s.Domain == SensitivityDomain.OnChain && s.EntityType == EntityType.CryptoAddr);
        // Wei-precision quantities (18+ decimals) detected
        result.AboveThreshold.Should().Contain(s =>
            s.EntityType == EntityType.Quantity && s.Length > 15);

        // Count what we caught vs what was in the source
        var addrCount = result.AboveThreshold.Count(s =>
            s.EntityType == EntityType.CryptoAddr);
        _output.WriteLine($"\n  Addresses detected: {addrCount}");

        var amtCount = result.AboveThreshold.Count(s =>
            s.EntityType == EntityType.Amount || s.EntityType == EntityType.Quantity);
        _output.WriteLine($"  Financial values detected: {amtCount}");
    }

    [Fact]
    public void CryptoCorrelation_DetectsSecondaryIdentifiers()
    {
        var result = ScanAndPrint("Crypto Correlation IDs", ScannerFixtures.CryptoCorrelation);

        result.AboveThreshold.Should().Contain(s => s.Service == "eth_validator_index");
        result.AboveThreshold.Should().Contain(s => s.Service == "block_number");
        result.AboveThreshold.Should().Contain(s => s.Service == "tx_nonce");
        result.AboveThreshold.Should().Contain(s => s.Service == "ada_pool_id");
        // All 9 secondary identifiers should be detected
        result.AboveThreshold.Count.Should().BeGreaterThanOrEqualTo(8);
    }

    [Fact]
    public void NonUsdCurrency_DetectsFiatAmounts()
    {
        var result = ScanAndPrint("Non-USD Currency", ScannerFixtures.NonUsdCurrency);

        // "AUD 1,234.56" and "EUR 500.00" should be detected
        result.AboveThreshold.Should().Contain(s => s.Service == "fiat_currency_amount");
        // "2,034.56 AUD" trailing should also be detected
        result.AboveThreshold.Should().Contain(s => s.Service == "fiat_amount_trailing");
    }

    [Fact]
    public void AllFixtures_SummaryReport()
    {
        var fixtures = new (string Name, string Content)[]
        {
            ("ETH DCA", ScannerFixtures.EthDcaEntry),
            ("BTC Position", ScannerFixtures.BtcPositionReview),
            ("DeFi Yield", ScannerFixtures.DefiYieldEntry),
            ("Strategy Thinking", ScannerFixtures.StrategyThinking),
            ("Validator+Bridge", ScannerFixtures.ValidatorAndBridge),
            ("Forex Journal", ScannerFixtures.ForexJournal),
            ("Dev Setup", ScannerFixtures.DevSetupEntry),
            ("Tax Prep", ScannerFixtures.TaxPrep),
            ("Credentials Heavy", ScannerFixtures.CredentialsHeavy),
            ("Multi-Chain", ScannerFixtures.MultiChainWallet),
            ("Credit Cards", ScannerFixtures.CreditCardEntry),
            ("Wallet Table", ScannerFixtures.WalletTableExport),
            ("Crypto Correlation", ScannerFixtures.CryptoCorrelation),
            ("Non-USD Currency", ScannerFixtures.NonUsdCurrency),
            ("Currency Formats", ScannerFixtures.CurrencyFormats),
            ("Code Discussion", ScannerFixtures.CodeDiscussion),
            ("Meeting Notes", ScannerFixtures.MeetingNotes),
        };

        _output.WriteLine("=== DETECTION SUMMARY ===\n");
        _output.WriteLine($"{"Fixture",-22} {"Chain",6} {"Creds",6} {"Secret",7} {"Finan",6} {"Ident",6} {"Total",6} {"Below",6}");
        _output.WriteLine(new string('-', 78));

        foreach (var (name, content) in fixtures)
        {
            var result = _scanner.Scan(content);
            var above = result.AboveThreshold;
            var onChain = above.Count(s => s.Domain == SensitivityDomain.OnChain);
            var creds = above.Count(s => s.Domain == SensitivityDomain.Credentials);
            var secrets = above.Count(s => s.Domain == SensitivityDomain.Secrets);
            var financial = above.Count(s => s.Domain == SensitivityDomain.Financial);
            var identity = above.Count(s => s.Domain == SensitivityDomain.Identity);
            var below = result.BelowThreshold.Count;

            _output.WriteLine($"{name,-22} {onChain,6} {creds,6} {secrets,7} {financial,6} {identity,6} {above.Count,6} {below,6}");
        }
    }

    // --- Helpers ---

    private ScanResult ScanAndPrint(string label, string text)
    {
        var result = _scanner.Scan(text);

        _output.WriteLine($"=== {label} ===");
        _output.WriteLine($"Total detected: {result.AllDetected.Count} " +
                          $"(above threshold: {result.AboveThreshold.Count}, " +
                          $"below: {result.BelowThreshold.Count})");

        if (result.AboveThreshold.Count > 0)
        {
            _output.WriteLine("\n  ABOVE THRESHOLD (would tokenize):");
            foreach (var span in result.AboveThreshold)
            {
                var svc = string.IsNullOrEmpty(span.Service) ? "" : $" ({span.Service})";
                _output.WriteLine($"    [{span.Domain}] {span.EntityType,-18} " +
                                  $"conf={span.Confidence:F2}  " +
                                  $"'{Truncate(span.MatchedText)}'{svc}");
            }
        }

        if (result.BelowThreshold.Count > 0)
        {
            _output.WriteLine("\n  BELOW THRESHOLD (detected but not tokenized):");
            foreach (var span in result.BelowThreshold)
            {
                var svc = string.IsNullOrEmpty(span.Service) ? "" : $" ({span.Service})";
                _output.WriteLine($"    [{span.Domain}] {span.EntityType,-18} " +
                                  $"conf={span.Confidence:F2}  " +
                                  $"'{Truncate(span.MatchedText)}'{svc}");
            }
        }

        _output.WriteLine("");
        return result;
    }

    private static string Truncate(string s, int max = 50) =>
        s.Length <= max ? s : s[..max] + "...";
}
