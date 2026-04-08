namespace Shroud.Models;

public enum EntityType
{
    // On-chain domain (atomic)
    CryptoAddr,
    TxHash,
    ValidatorKey,
    EnsName,
    SeedPhrase,

    // Credentials domain (service-specific API keys and tokens)
    ApiKey,
    AccessToken,
    WebhookSecret,

    // Secrets domain (structural secrets)
    PrivateKey,
    Jwt,
    ConnectionString,
    PasswordInContext,

    // Financial domain (compositional)
    Quantity,
    Amount,
    Price,
    MarketPair,
    AssetName,
    CreditCard,

    // Identity domain
    Ssn,
    Iban,
    IpAddress,
    MacAddress,
    Email,
    PhoneNumber
}
