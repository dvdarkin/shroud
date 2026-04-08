namespace Shroud.Models;

public record SensitiveSpan(
    int Start,
    int End,
    EntityType EntityType,
    SensitivityDomain Domain,
    double Confidence,
    string MatchedText,
    string Service = ""
)
{
    public int Length => End - Start;

    public string TypeAbbreviation => EntityType switch
    {
        // On-chain
        EntityType.CryptoAddr => "ADDR",
        EntityType.TxHash => "TX",
        EntityType.ValidatorKey => "VKEY",
        EntityType.EnsName => "ENS",
        EntityType.SeedPhrase => "SEED",

        // Credentials
        EntityType.ApiKey => "KEY",
        EntityType.AccessToken => "TOKEN",
        EntityType.WebhookSecret => "WHSEC",

        // Secrets
        EntityType.PrivateKey => "PRIVKEY",
        EntityType.Jwt => "JWT",
        EntityType.ConnectionString => "CONNSTR",
        EntityType.PasswordInContext => "PASSWD",

        // Financial
        EntityType.Quantity => "QTY",
        EntityType.Amount => "AMT",
        EntityType.Price => "PRICE",
        EntityType.MarketPair => "MKT",
        EntityType.AssetName => "ASSET",
        EntityType.CreditCard => "CC",

        // Identity
        EntityType.Ssn => "SSN",
        EntityType.Iban => "IBAN",
        EntityType.IpAddress => "IP",
        EntityType.MacAddress => "MAC",
        EntityType.Email => "EMAIL",
        EntityType.PhoneNumber => "PHONE",

        _ => "UNK"
    };
}
