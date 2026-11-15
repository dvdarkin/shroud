// Port of src/Shroud.Tests.Unit/DateTimeExclusionTests.cs
// Each xUnit [InlineData] case of a [Theory] is its own test here.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SensitivityScanner } from '../../src/scanner.js';

describe('DateTimeExclusionTests', () => {
  const scanner = new SensitivityScanner();

  describe('iso date, not detected as amount', () => {
    for (const date of [
      '2026-04-20',
      '2019-12-31',
      '1999-01-01',
      '2026-04-20T17:30:34',
      '2026-04-20 17:30:34',
      '2026-04-20T17:30:34.123Z',
      '2026-04-20T17:30:34+02:00',
    ]) {
      test(date, () => {
        // Surround with USD/trading context so any stray year-pattern would otherwise fire.
        const text = `Filled on ${date} for USDC deposit`;

        const result = scanner.scan(text);

        assert.ok(
          !result.aboveThreshold.some((s) => s.matchedText === '2026' || s.matchedText === '2019' || s.matchedText === '1999'),
          'date components inside an ISO date should not be detected as amounts',
        );
      });
    }
  });

  describe('numeric date, not detected as amount', () => {
    for (const date of ['04/20/2026', '4-20-2026', '4.20.26', '20/04/2026', '20-04-2026']) {
      test(date, () => {
        const text = `Trade executed ${date} for USDC profit`;

        const result = scanner.scan(text);

        assert.ok(
          !result.aboveThreshold.some((s) => s.matchedText === '2026' || s.matchedText === '26'),
          'year in slash/dash-separated date should be excluded',
        );
      });
    }
  });

  describe('month name date, not detected as amount', () => {
    for (const date of ['20 Apr 2026', 'April 20, 2026', 'Apr 20 2026', 'Jan 2026']) {
      test(date, () => {
        const text = `Position opened ${date} in USDC`;

        const result = scanner.scan(text);

        assert.ok(!result.aboveThreshold.some((s) => s.matchedText === '2026'), 'year in month-name date should be excluded');
      });
    }
  });

  describe('time, not detected as quantity', () => {
    for (const time of ['17:30:34', '14:25', '5:00', '5pm', '11:45 AM', '5:30pm']) {
      test(time, () => {
        const text = `Entry at ${time} for trading USDC position`;

        const result = scanner.scan(text);

        // Above threshold in Financial domain would indicate a false positive from the time digits.
        // Allow above-threshold ONLY if the span extends beyond the time tokens.
        const financialMatches = result.aboveThreshold.filter((s) => s.domain === 'Financial');

        for (const match of financialMatches) {
          assert.notEqual(match.matchedText, '17', 'time digits should be excluded');
          assert.notEqual(match.matchedText, '30', 'time digits should be excluded');
          assert.notEqual(match.matchedText, '34', 'time digits should be excluded');
          assert.notEqual(match.matchedText, '14', 'time digits should be excluded');
          assert.notEqual(match.matchedText, '45', 'time digits should be excluded');
        }
      });
    }
  });

  test('iso week, not detected as amount', () => {
    const text = 'Sprint 2026-W17 closed out USDC positions';

    const result = scanner.scan(text);

    assert.ok(
      !result.aboveThreshold.some((s) => s.matchedText === '2026' || s.matchedText === '17'),
      'ISO week components should be excluded',
    );
  });

  test('bare year, not detected as amount', () => {
    // "2026" alone with surrounding trading context used to match arithmetic_sum_operand
    // (4-digit number followed by "-") and cross the 0.70 threshold.
    const text = '2026-04-20 17:30:34 | ETH_USDC | Buy | 100 USDC';

    const result = scanner.scan(text);

    assert.ok(!result.aboveThreshold.some((s) => s.matchedText === '2026'), 'bare year should never appear as a financial amount');
  });

  // Positive cases: the exclusion zones must NOT mask out truly sensitive amounts
  // that happen to include or abut year-like digits.

  test('symbol amount year, still detected', () => {
    const text = 'Bought for $2026 total';

    const result = scanner.scan(text);

    assert.ok(
      result.aboveThreshold.some((s) => s.entityType === 'Amount' && s.matchedText === '$2026'),
      '$2026 extends past the 4-char year zone and must still be masked',
    );
  });

  test('asset quantity year digits, still detected', () => {
    const text = 'Wallet holds 2026 USDC at entry';

    const result = scanner.scan(text);

    assert.ok(
      result.aboveThreshold.some(
        (s) => s.domain === 'Financial' && s.matchedText.includes('2026') && s.matchedText.includes('USDC'),
      ),
      '2026 USDC is an asset-adjacent quantity and must still be masked',
    );
  });

  test('usd code amount year, still detected', () => {
    const text = 'Paid 2026 USD to vendor';

    const result = scanner.scan(text);

    assert.ok(
      result.aboveThreshold.some(
        (s) => s.entityType === 'Amount' && s.matchedText.includes('2026') && s.matchedText.includes('USD'),
      ),
      '2026 USD extends past the year zone and must still be masked',
    );
  });

  test('invalid date, not excluded', () => {
    // 2026-15 is not a valid year-month (month > 12), so the year-month regex should
    // not match and the year zone should be the only exclusion. An amount-like
    // pattern that happens to overlap still has to be checked.
    const text = 'ID tag 2026-15 with 15,000 USDC deposit';

    const result = scanner.scan(text);

    // "15,000 USDC" should still detect regardless.
    assert.ok(
      result.aboveThreshold.some((s) => s.domain === 'Financial' && s.matchedText.includes('15,000')),
      'real amount after a non-date string should still be detected',
    );
  });
});
