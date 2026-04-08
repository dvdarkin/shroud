namespace Shroud.Tests.Integration.Fixtures;

/// <summary>
/// Test fixtures for pattern detection. Values are obviously synthetic
/// but structurally valid for regex matching. No real addresses, keys, or amounts.
/// </summary>
public static class ScannerFixtures
{
    // === Mixed: on-chain + financial ===

    public const string EthDcaEntry = """
        ## 2026-04-01 09:15

        DCA day. Bought 0.5 ETH at $1,234 on Uniswap.
        Swapped from USDC via 0x1111111111111111111111111111111111111111 (router).
        Tx: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        Sent to cold wallet 0x2222222222222222222222222222222222222222.
        Running total position now around 10 ETH, avg entry $1,200.
        Thinking DCA continues to make sense below $1,500.

        context: Uniswap, Chrome
        """;

    public const string BtcPositionReview = """
        ## 2026-03-28 21:30

        Reviewing BTC position. Current allocation: 0.5 BTC worth roughly $12,345.
        Half is on bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (hardware wallet),
        rest on exchange. Considering taking profit at $50,000 -- that would be
        about $25,000 total if price reaches target.

        BTC/USD weekly looks strong, cautious about the monthly divergence.
        Will set a limit sell for 0.1 BTC at $50,000 as a partial exit.

        context: TradingView, Chrome
        """;

    public const string DefiYieldEntry = """
        ## 2026-04-02 14:22

        Moved 1,000 USDC into lending pool on Arbitrum.
        Deposit tx: 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        Pool contract: 0x3333333333333333333333333333333333333333
        Current APY around 4.2%, decent for stable yield.

        Total DeFi exposure now $5,000 across protocols.
        Need to keep this below $10,000 per risk framework.

        context: Aave, Chrome
        """;

    // === Pure reasoning (should have minimal detections) ===

    public const string StrategyThinking = """
        ## 2026-04-01 22:00

        Thinking about overall market structure. The macro picture suggests
        we might see a pullback before the next leg up. DCA strategy has been
        working well -- mechanically buying on red days removes the emotional
        component. Need to revisit my rebalancing schedule. Currently overweight
        crypto relative to equities. Should probably trim if we get another
        sustained rally.

        Note: review tax implications of any sells before EOQ.

        context: Notes, Desktop
        """;

    // === On-chain heavy (validator, L2, bridge) ===

    public const string ValidatorAndBridge = """
        ## 2026-04-03 11:45

        Checked validator status. Performing fine, no missed attestations.

        Bridged 500 USDC from Ethereum to Arbitrum via the official bridge.
        Bridge tx on L1: 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
        Receiving address on Arb: 0x4444444444444444444444444444444444444444

        Also checked testname.eth on ENS -- still pointing to the same address.
        Need to renew myname.eth before it expires in June.

        context: Etherscan, Chrome
        """;

    // === Financial only (no on-chain artifacts) ===

    public const string ForexJournal = """
        ## 2026-04-02 08:30

        Opened a long EUR/USD position at 1.0845, size 1,000 units.
        Stop loss at 1.0790, target 1.0920. Risk roughly $100.
        AUD/JPY looking interesting too -- if it breaks above 98.50
        might enter with 500 units.

        Current open P&L: EUR/USD +$50, GBP/USD -$25.
        Portfolio margin usage at 12%, well within limits.

        context: MT5, Desktop
        """;

    // === API keys and credentials ===

    public const string DevSetupEntry = """
        ## 2026-04-01 16:00

        Setting up trading bot. API keys:
        Exchange key: sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK
        Connected to RPC endpoint at 192.168.1.100 for local node.
        Backup node at 10.0.0.200 running Geth.

        xpub6abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123ab

        Need to rotate these keys monthly per security policy.

        context: VS Code, Terminal
        """;

    // === Identity data mixed with financial ===

    public const string TaxPrep = """
        ## 2026-04-03 09:00

        Tax prep notes. Need to report crypto gains.
        Total realized gains approximately $1,234 from trading.
        SSN for filing: 123-45-6789
        Wire transfer to accountant from IBAN: DE89370400440532013000

        Cost basis method: FIFO across all exchanges.

        context: Excel, Desktop
        """;

    // === Currency formats: symbols, codes, shorthand multipliers ===

    public const string CurrencyFormats = """
        ## 2026-04-06 10:00

        Symbol before: $1,234 and $12.5k and $1.2M portfolio value.
        Also: the position is worth roughly $500.
        Euro: need to wire payment.
        Pound: some amount.

        Code before: USD 5,000 and AUD 12.5k and EUR 1.2M allocation.
        Code after: 5,000 USD and 12.5k AUD and 750 EUR.
        Also: 1,234 US$ equivalent.

        Shorthand in context: portfolio worth 12.5k, position is 1.2M,
        budget is 500k, total value 2.5B.

        Without context (should not match shorthand):
        The server has 12k connections and 500k requests per hour.

        context: Trading, Desktop
        """;

    // === Benign content (false positive traps) ===

    public const string CodeDiscussion = """
        ## 2026-04-01 12:00

        Working on the authentication module. The session tokens use
        a 256-bit random value, similar to how wallet addresses work.
        Performance test shows 10000 requests per second on the test server
        at port 8080. Memory usage stable at 512 MB after 24 hours.

        The function at line 342 handles the key rotation logic.
        Fixed bug where timestamps after 2026-01-01 weren't parsed correctly.
        Build number 20260401 passed all 1847 tests.

        PR #1234 merged, deploying to staging.

        context: VS Code, Terminal
        """;

    // === Credentials and secrets ===

    public const string CredentialsHeavy = """
        ## 2026-04-04 15:00

        Setting up pipeline. Keys collected:

        AWS access key: AKIAIOSFODNN7EXAMPLE
        GitHub PAT: ghp_abc123def456abc123def456abc123def456
        GitLab token: glpat-abc123def456abc123de
        Slack bot: xoxb-0000000000-0000000000-FAKEFAKEFAKEFAKEFAKEFAKE
        Google API: AIzaSyabc123def456abc123def456abc123def
        OpenAI: sk-proj-abc123def456abc123def456abc123def456abc123def456
        Stripe test: sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK
        SendGrid: SG.FAKEFAKEFAKEFAKEFAKEFA.FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEfak
        Shopify: shpat_abcdef0123456789abcdef01234567
        npm: npm_abc123DEF456abc123DEF456abc123DEF456

        Also found a JWT in the logs:
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

        Private key in deploy config:
        -----BEGIN RSA PRIVATE KEY-----
        MIIBTEST1234...
        -----END RSA PRIVATE KEY-----

        Database: postgres://admin:testpass@db.example.com:5432/testdb
        Redis config: password = "test_password_123"

        context: VS Code, Terminal
        """;

    public const string MultiChainWallet = """
        ## 2026-04-05 09:00

        Wallet inventory across chains:

        ETH: 0x5555555555555555555555555555555555555555
        BTC (segwit): bc1qabc123def456abc123def456abc123def456abc1
        BTC (taproot): bc1pabc123def456abc123def456abc123def456abc123def456abc123def456ab
        Cardano: addr1qabc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc1
        Cosmos: cosmos1abc123def456abc123def456abc123def456ab
        XRP: rN7n3473SaZBCG4dFL83w7p1W9cganksPc
        Tron: TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW
        Tezos: tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb
        Litecoin: ltc1qabc123def456abc123def456abc123def456abc1
        Monero: 4A1abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def4

        Do NOT share this list.

        context: Notes, Desktop
        """;

    public const string CreditCardEntry = """
        ## 2026-04-03 12:00

        Expense tracking. Corporate card:
        Full number for receipt: 4532015112830366
        Backup Amex: 371449635398431
        Mastercard: 5425233430109903

        Random numbers that should NOT match:
        Order number: 4532015112830367
        Invoice: 1234567890123456

        context: Excel, Desktop
        """;

    // === Markdown table with addresses, URLs, and financial data ===

    public const string WalletTableExport = """
        Assets in Wallet (3)

        $1,234

        | **Asset** | **Symbol** | **Contract Address** | **Quantity** | **Price** | **Change (24H)** | **Value** | ** ** |
        | --- | --- | --- | --- | --- | --- | --- | --- |
        | Ethereum | ETH | - | 0.123456789012345678 | $1,234 | 2.88% | $152.39 | More |
        | [stETH](https://etherscan.io/token/0x6666666666666666666666666666666666666666?a=0x7777777777777777777777777777777777777777) | stETH | [0x66666666...666666666](https://etherscan.io/token/0x6666666666666666666666666666666666666666) | 1.234567890123456789 | $1,235 | 3.4% | $1,524.69 | More |
        | [Tether USD](https://etherscan.io/token/0x8888888888888888888888888888888888888888?a=0x7777777777777777777777777777777777777777) | USDT | [0x88888888...888888888](https://etherscan.io/token/0x8888888888888888888888888888888888888888) | 1234.56 | $1.00 | 0.07% | $1,234.56 | More |

        context: Etherscan, Chrome
        """;

    // === Crypto-native correlation identifiers ===

    public const string CryptoCorrelation = """
        ## 2026-04-06 08:00

        Validator check. My validator #548231 proposed in slot #9234567 during
        epoch #298445. No missed attestations.

        Reviewed tx at block #24808457, nonce: 1247.
        Gas was 0.107 Gwei, priority tip 2 Gwei.

        My Uniswap v3 position #482331 is in range.

        NFT token ID #4532 from the collection sold.

        Staked to pool1abc123def456abc123def456abc123def456abc123def456abc123de

        context: Beaconcha.in, Chrome
        """;

    public const string NonUsdCurrency = """
        ## 2026-04-05 14:00

        A withdrawal for AUD 1,234.56 is pending, and will be processed shortly.
        Previous withdrawal was EUR 500.00 to same account.
        Total fees this month: GBP 12.50

        Napkin math for tax:
        Total : 1,234.56+500.00+ 100.00+200.00=2,034.56 AUD

        context: Exchange, Chrome
        """;

    public const string MeetingNotes = """
        ## 2026-04-02 10:00

        Team standup. Discussed the Q2 roadmap. Sprint velocity was 42 points
        last iteration, targeting 45 this sprint. Budget for cloud infra is
        $3,500 per month, currently using $2,800. Need 3 more engineers for
        the platform team. Release scheduled for April 15.

        Action items: review the 128-page security audit, update documentation
        for API v2, schedule 1-on-1s with new hires.

        context: Zoom, Desktop
        """;
}
