// Port of src/Shroud.Tests.Unit/FinancialDigitRequiredTests.cs
// A financial numeric span (Amount, Quantity, Price) must contain at least one digit.
// Several financial regexes use [\d,]+ and can otherwise match separator-only text.
// Each xUnit [InlineData] case of a [Theory] is its own test here.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { contains, normalize } from '../../src/internal/charset.js';
import { DOTNET_DIGIT } from '../../src/internal/unicode-tables.js';
import type { SensitiveSpan } from '../../src/models.js';
import { SensitivityScanner } from '../../src/scanner.js';

// char.IsDigit (Unicode Nd); the probe-generated table is verified equal to it.
const DIGITS = normalize(DOTNET_DIGIT);
const anyDigit = (s: string) => [...Array(s.length).keys()].some((i) => contains(DIGITS, s.charCodeAt(i)));

const isNumericFinancial = (s: SensitiveSpan) =>
  s.domain === 'Financial' && (s.entityType === 'Amount' || s.entityType === 'Quantity' || s.entityType === 'Price');

describe('FinancialDigitRequiredTests', () => {
  const scanner = new SensitivityScanner(null, 0.0);

  describe('separator only text, is not a financial span', () => {
    for (const text of [
      'fee x, = 5 usd', // arithmetic_equals_left
      'usd fee: total = , then', // arithmetic_equals_right
      'usd fee x, * 2', // arithmetic_operand
      'usd fee 2 * , x', // arithmetic_result
      'usd fee x,,,, - 3', // arithmetic_sum_operand
      'Paid $, then left', // symbol_amount
      'Balance x, USD', // usd_code_amount
      'Paid EUR , ok', // fiat_currency_amount
      'Paid x, EUR ok', // fiat_amount_trailing
      'filled at $,x price', // price_dollar
      'filled at ,x price', // price_bare
    ]) {
      test(text, () => {
        const result = scanner.scan(text);

        for (const s of result.allDetected.filter(isNumericFinancial)) {
          assert.ok(anyDigit(s.matchedText), `a financial numeric span must contain at least one digit: ${JSON.stringify(s.matchedText)}`);
        }
      });
    }
  });

  test('lone comma, near currency words, is not masked', () => {
    const result = new SensitivityScanner().scan('fee x, = 5 usd');

    assert.ok(!result.aboveThreshold.some((s) => s.matchedText === ','));
    assert.ok(
      result.aboveThreshold.some((s) => s.matchedText === '5' && s.entityType === 'Amount'),
      'the real number is still detected',
    );
  });

  test('real numbers, in same shapes, are still detected', () => {
    const result = new SensitivityScanner().scan('fee 1,250 = 5 usd and paid $1,200 and EUR 300');

    assert.ok(result.aboveThreshold.some((s) => s.matchedText === '1,250'));
    assert.ok(result.aboveThreshold.some((s) => s.matchedText === '$1,200'));
    assert.ok(result.aboveThreshold.some((s) => s.matchedText === 'EUR 300'));
  });
});
