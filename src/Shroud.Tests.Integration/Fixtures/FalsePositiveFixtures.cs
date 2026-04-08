namespace Shroud.Tests.Integration.Fixtures;

public static class FalsePositiveFixtures
{
    public const string DevOpsLog = """
        ## CI-CD Pipeline Run #4521

        Build 1234 completed in 128m memory. Container position: absolute.
        Hash of artifact: verified. Block storage: 500GB allocated.
        Deploy to staging at 10:43 UTC. Balance check: 0 errors.
        Service mesh routing: dot notation for service.namespace.svc.cluster.local

        Worker pool: 12k connections, 500m requests/day capacity.
        CPU allocation: 4 cores at 2.4 GHz. Memory limit: 8192m.
        """;

    public const string AcademicPaper = """
        ## Abstract

        We compute the sol (solar luminosity) ratio for stellar classification.
        The dot product of vectors A and B yields a scalar magnitude.
        Using hash function SHA-256 with output ab01cd23ef45678901234567890abcdef01234567890abcdef01234567890abcd
        to verify checksums. At 512 dimensions, the embedding space captures
        semantic relationships. The position vector p has 1024 components.
        Balance of forces: F = ma = 50 * 9.81 = 490.5 newtons.
        """;

    public const string LegalContract = """
        ## Terms and Conditions

        The balance of payments between Party A and Party B shall be settled
        within 30 days. The position of the parties regarding liability is
        defined in Section 12. The total contract value is $50,000 payable
        in installments. At 5% interest rate, the annual cost is $2,500.
        Portfolio of assets includes real property at 123 Main Street.
        """;

    public const string ServerMetrics = """
        ## Infrastructure Report

        Load balancer metrics: balance: 0, healthy: 12, unhealthy: 0.
        Active sessions: 12k connections across 3 regions.
        Request throughput: 500m per month, p99 latency at 45ms.

        Internal endpoints:
        - API gateway: 192.168.1.100:8080
        - Database primary: 10.0.0.50:5432
        - Cache cluster: 172.16.0.10:6379

        MAC address of primary NIC: AA:BB:CC:DD:EE:FF
        """;

    public const string CryptoTechDoc = """
        ## How Ethereum Addresses Work

        An Ethereum address is derived from the public key. For example,
        a zero address looks like 0x0000000000000000000000000000000000000000.
        This is used as a burn address and is not a real wallet.

        Transaction hashes are 32 bytes (64 hex characters). Example:
        0x0000000000000000000000000000000000000000000000000000000000000000

        The process involves keccak256 hashing of the public key, then
        taking the last 20 bytes as the address.
        """;

    public const string SpreadsheetExport = """
        Item,Qty,Unit Price,Total
        Widget A,100,2.50,250.00
        Widget B,200,3.75,750.00
        Widget C,50,10.00,500.00
        Subtotal,,,1500.00
        Tax (10%),,,150.00
        Grand Total,,,1650.00

        Row count: 1234. Last updated: 2026-04-01.
        Batch processing: 500 / 10 = 50 batches.
        """;

    public const string MarkdownFormatting = """
        ## Code Examples

        Use `0xDEADBEEF` as a placeholder constant in examples.
        The config key looks like `AKIA_EXAMPLE_NOT_REAL_KEY_123456` in docs.

        ```
        hash = sha256("hello world")
        # Output: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        ```

        Links: [documentation](https://docs.example.com/path/to/guide)
        Images: ![diagram](assets/architecture-diagram.png)

        ### Heading with # symbols and numbers 1234
        """;

    public const string MultiLanguageText = """
        ## Project Notes

        El sol brilla sobre la ciudad. Die Position der Firma ist stark.
        Le solde du compte est positif. Das Gleichgewicht der Kräfte.

        Currency symbols in non-financial context:
        The $ character is used as a variable prefix in PHP and bash.
        The ¥ symbol appears in character encoding documentation.

        Dot notation: object.property.method() is standard in most languages.
        Sol is also a Martian day (approximately 24 hours 39 minutes).
        """;
}
