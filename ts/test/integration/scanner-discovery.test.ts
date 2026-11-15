// Port of src/Shroud.Tests.Integration/ScannerDiscoveryTests.cs
// Discovery tests: scan realistic journal entries and report what was found (the
// report goes to node:test diagnostics, the analogue of xUnit's ITestOutputHelper).
import assert from 'node:assert/strict';
import { describe, test, type TestContext } from 'node:test';
import { align, formatFixed } from '../../src/internal/dotnet-format.js';
import type { ScanResult } from '../../src/models.js';
import { SensitivityScanner } from '../../src/scanner.js';
import * as ScannerFixtures from './fixtures/scanner-fixtures.js';

const truncate = (s: string, max = 50) => (s.length <= max ? s : s.slice(0, max) + '...');

describe('ScannerDiscoveryTests', () => {
  const scanner = new SensitivityScanner();

  function scanAndPrint(t: TestContext, label: string, text: string): ScanResult {
    const result = scanner.scan(text);

    t.diagnostic(`=== ${label} ===`);
    t.diagnostic(
      `Total detected: ${result.allDetected.length} ` +
        `(above threshold: ${result.aboveThreshold.length}, below: ${result.belowThreshold.length})`,
    );

    const print = (heading: string, spans: ScanResult['aboveThreshold']) => {
      if (spans.length === 0) return;
      t.diagnostic(heading);
      for (const span of spans) {
        const svc = span.service ? ` (${span.service})` : '';
        t.diagnostic(
          `    [${span.domain}] ${align(span.entityType, -18)} conf=${formatFixed(span.confidence, 2)}  '${truncate(span.matchedText)}'${svc}`,
        );
      }
    };
    print('  ABOVE THRESHOLD (would tokenize):', result.aboveThreshold);
    print('  BELOW THRESHOLD (detected but not tokenized):', result.belowThreshold);
    return result;
  }

  test('eth dca, detects addresses and amounts', (t) => {
    const result = scanAndPrint(t, 'ETH DCA Entry', ScannerFixtures.ethDcaEntry);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'CryptoAddr'));
    assert.ok(result.allDetected.some((s) => s.entityType === 'TxHash'));
  });

  test('btc position, detects address and amounts', (t) => {
    const result = scanAndPrint(t, 'BTC Position Review', ScannerFixtures.btcPositionReview);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'CryptoAddr'));
  });

  test('defi yield, detects contracts and tx', (t) => {
    const result = scanAndPrint(t, 'DeFi Yield Entry', ScannerFixtures.defiYieldEntry);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'CryptoAddr'));
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'TxHash'));
  });

  test('strategy thinking, minimal detections', (t) => {
    const result = scanAndPrint(t, 'Strategy Thinking (should be mostly clean)', ScannerFixtures.strategyThinking);

    assert.equal(
      result.aboveThreshold.filter((s) => s.domain === 'OnChain').length,
      0,
      'pure reasoning has no on-chain artifacts',
    );
  });

  test('validator and bridge, detects all on chain artifacts', (t) => {
    const result = scanAndPrint(t, 'Validator + Bridge', ScannerFixtures.validatorAndBridge);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'EnsName'));
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'TxHash'));
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'CryptoAddr'));
  });

  test('forex journal, detects financial not on chain', (t) => {
    const result = scanAndPrint(t, 'Forex Journal', ScannerFixtures.forexJournal);

    assert.equal(
      result.aboveThreshold.filter((s) => s.domain === 'OnChain').length,
      0,
      'forex journal has no blockchain artifacts',
    );
    assert.ok(result.aboveThreshold.some((s) => s.domain === 'Financial'));
  });

  test('dev setup, detects api keys', (t) => {
    const result = scanAndPrint(t, 'Dev Setup (API keys)', ScannerFixtures.devSetupEntry);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'ApiKey'));
    assert.ok(result.allDetected.some((s) => s.entityType === 'IpAddress'));
  });

  test('tax prep, detects identity and financial', (t) => {
    const result = scanAndPrint(t, 'Tax Prep', ScannerFixtures.taxPrep);

    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'Ssn'));
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'Iban'));
  });

  test('currency formats, detects all variants', (t) => {
    const result = scanAndPrint(t, 'Currency Formats', ScannerFixtures.currencyFormats);

    // Symbol amounts: $1,234, $12.5k, $1.2M, $500
    assert.ok(result.aboveThreshold.some((s) => s.service === 'symbol_amount'));
    // Code amounts: USD 5,000, AUD 12.5k
    assert.ok(result.aboveThreshold.some((s) => s.service === 'fiat_currency_amount'));
    // Trailing: 5,000 USD, 12.5k AUD
    assert.ok(result.aboveThreshold.some((s) => s.service === 'fiat_amount_trailing' || s.service === 'usd_code_amount'));
    // Shorthand with financial context: 12.5k, 1.2M near "portfolio", "position"
    assert.ok(result.aboveThreshold.some((s) => s.service === 'shorthand_amount'));

    // "12k connections" without financial context should be below threshold
    const serverDetections = result.aboveThreshold.filter((s) => s.service === 'shorthand_amount');
    t.diagnostic(`  Shorthand detections: ${serverDetections.length}`);
  });

  test('code discussion, minimal false positives', (t) => {
    const result = scanAndPrint(t, 'Code Discussion (false positive trap)', ScannerFixtures.codeDiscussion);

    const falseFinancial = result.aboveThreshold.filter((s) => s.domain === 'Financial');

    t.diagnostic(`  False positive financial detections: ${falseFinancial.length}`);
    for (const fp of falseFinancial) {
      t.diagnostic(`    WARNING: ${fp.entityType} '${truncate(fp.matchedText)}' @ ${formatFixed(fp.confidence, 2)}`);
    }
  });

  test('meeting notes, minimal false positives', (t) => {
    const result = scanAndPrint(t, 'Meeting Notes (false positive trap)', ScannerFixtures.meetingNotes);

    const falsePositives = [...result.aboveThreshold];

    t.diagnostic(`  False positives above threshold: ${falsePositives.length}`);
    for (const fp of falsePositives) {
      t.diagnostic(`    WARNING: ${fp.entityType} '${truncate(fp.matchedText)}' @ ${formatFixed(fp.confidence, 2)}`);
    }
  });

  test('credentials heavy, detects service specific keys', (t) => {
    const result = scanAndPrint(t, 'Credentials Heavy', ScannerFixtures.credentialsHeavy);

    for (const service of ['aws_access_key', 'github_pat', 'stripe_key', 'jwt', 'pem_private_key', 'database_uri']) {
      assert.ok(result.aboveThreshold.some((s) => s.service === service), service);
    }
  });

  test('multi chain wallet, detects all chains', (t) => {
    const result = scanAndPrint(t, 'Multi-Chain Wallet', ScannerFixtures.multiChainWallet);

    // Should detect addresses across multiple chains
    const chains = [...new Set(result.aboveThreshold.filter((s) => s.entityType === 'CryptoAddr').map((s) => s.service))];
    t.diagnostic(`  Chains detected: ${chains.join(', ')}`);
    assert.ok(chains.length >= 5, 'should detect at least 5 different chains');
  });

  test('credit card, luhn validation', (t) => {
    const result = scanAndPrint(t, 'Credit Card Entry', ScannerFixtures.creditCardEntry);

    // Valid Luhn numbers should be detected
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'CreditCard'));

    // Invalid Luhn numbers should NOT be detected as credit card
    const ccCount = result.aboveThreshold.filter((s) => s.entityType === 'CreditCard').length;
    assert.equal(ccCount, 3, 'only Luhn-valid cards should match (Visa, Amex, Mastercard)');
  });

  test('wallet table, detects all leak types', (t) => {
    const result = scanAndPrint(t, 'Wallet Table Export', ScannerFixtures.walletTableExport);

    // Should detect: full addresses, truncated addresses, explorer URLs,
    // wei-precision quantities, dollar amounts
    assert.ok(result.aboveThreshold.some((s) => s.domain === 'OnChain' && s.entityType === 'CryptoAddr'));
    // Wei-precision quantities (18+ decimals) detected
    assert.ok(result.aboveThreshold.some((s) => s.entityType === 'Quantity' && s.end - s.start > 15));

    // Count what we caught vs what was in the source
    const addrCount = result.aboveThreshold.filter((s) => s.entityType === 'CryptoAddr').length;
    t.diagnostic(`  Addresses detected: ${addrCount}`);

    const amtCount = result.aboveThreshold.filter((s) => s.entityType === 'Amount' || s.entityType === 'Quantity').length;
    t.diagnostic(`  Financial values detected: ${amtCount}`);
  });

  test('crypto correlation, detects secondary identifiers', (t) => {
    const result = scanAndPrint(t, 'Crypto Correlation IDs', ScannerFixtures.cryptoCorrelation);

    for (const service of ['eth_validator_index', 'block_number', 'tx_nonce', 'ada_pool_id']) {
      assert.ok(result.aboveThreshold.some((s) => s.service === service), service);
    }
    // All 9 secondary identifiers should be detected
    assert.ok(result.aboveThreshold.length >= 8);
  });

  test('non usd currency, detects fiat amounts', (t) => {
    const result = scanAndPrint(t, 'Non-USD Currency', ScannerFixtures.nonUsdCurrency);

    // "AUD 1,234.56" and "EUR 500.00" should be detected
    assert.ok(result.aboveThreshold.some((s) => s.service === 'fiat_currency_amount'));
    // "2,034.56 AUD" trailing should also be detected
    assert.ok(result.aboveThreshold.some((s) => s.service === 'fiat_amount_trailing'));
  });

  test('all fixtures, summary report', (t) => {
    const fixtures: [string, string][] = [
      ['ETH DCA', ScannerFixtures.ethDcaEntry],
      ['BTC Position', ScannerFixtures.btcPositionReview],
      ['DeFi Yield', ScannerFixtures.defiYieldEntry],
      ['Strategy Thinking', ScannerFixtures.strategyThinking],
      ['Validator+Bridge', ScannerFixtures.validatorAndBridge],
      ['Forex Journal', ScannerFixtures.forexJournal],
      ['Dev Setup', ScannerFixtures.devSetupEntry],
      ['Tax Prep', ScannerFixtures.taxPrep],
      ['Credentials Heavy', ScannerFixtures.credentialsHeavy],
      ['Multi-Chain', ScannerFixtures.multiChainWallet],
      ['Credit Cards', ScannerFixtures.creditCardEntry],
      ['Wallet Table', ScannerFixtures.walletTableExport],
      ['Crypto Correlation', ScannerFixtures.cryptoCorrelation],
      ['Non-USD Currency', ScannerFixtures.nonUsdCurrency],
      ['Currency Formats', ScannerFixtures.currencyFormats],
      ['Code Discussion', ScannerFixtures.codeDiscussion],
      ['Meeting Notes', ScannerFixtures.meetingNotes],
    ];

    t.diagnostic('=== DETECTION SUMMARY ===');
    t.diagnostic(
      `${align('Fixture', -22)} ${align('Chain', 6)} ${align('Creds', 6)} ${align('Secret', 7)} ${align('Finan', 6)} ${align('Ident', 6)} ${align('Total', 6)} ${align('Below', 6)}`,
    );
    t.diagnostic('-'.repeat(78));

    for (const [name, content] of fixtures) {
      const result = scanner.scan(content);
      const above = result.aboveThreshold;
      const count = (domain: string) => String(above.filter((s) => s.domain === domain).length);
      t.diagnostic(
        `${align(name, -22)} ${align(count('OnChain'), 6)} ${align(count('Credentials'), 6)} ${align(count('Secrets'), 7)} ` +
          `${align(count('Financial'), 6)} ${align(count('Identity'), 6)} ${align(String(above.length), 6)} ${align(String(result.belowThreshold.length), 6)}`,
      );
    }
  });
});
