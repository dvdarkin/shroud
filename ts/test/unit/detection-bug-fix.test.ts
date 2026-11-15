// Port of src/Shroud.Tests.Unit/DetectionBugFixTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SensitivityScanner } from '../../src/scanner.js';

describe('DetectionBugFixTests', () => {
  const scanner = new SensitivityScanner();

  test('comma number with asset, detects full number', () => {
    const result = scanner.scan('Deposited 15,000 USDC into the pool.');

    const assetMatch = result.allDetected
      .filter((s) => s.domain === 'Financial')
      .filter((s) => s.matchedText.includes('15,000') || s.matchedText.includes('15,000 USDC'));

    assert.ok(assetMatch.length > 0, "15,000 USDC should be detected as a full amount, not just '000'");

    assert.ok(
      !result.allDetected.some((s) => s.matchedText === '000' && s.domain === 'Financial'),
      "bare '000' should not be a standalone financial detection",
    );
  });

  test('price pattern at without dollar, no false positive', () => {
    const result = scanner.scan('The server runs at 512 MB of memory.');

    assert.ok(
      !result.aboveThreshold.some((s) => s.entityType === 'Price' && s.matchedText.includes('512')),
      "'at 512 MB' should not be detected as a price",
    );
  });

  test('price pattern at with dollar, still detects', () => {
    const result = scanner.scan('Filled the order at $512 per unit.');

    assert.ok(
      result.allDetected.some((s) => s.entityType === 'Price' && s.matchedText.includes('$512')),
      "'at $512' should still be detected as a price",
    );
  });

  test('arithmetic distant dollar sign, no false positive', () => {
    const padding = 'x'.repeat(100);
    const text = `The formula is 10 / 2 = 5. ${padding} The cost was $50.`;

    const result = scanner.scan(text);

    const arithmeticNearFormula = result.aboveThreshold
      .filter((s) => s.service === 'arithmetic_operand' || s.service === 'arithmetic_result')
      .filter((s) => s.start < 30);

    assert.equal(
      arithmeticNearFormula.length,
      0,
      "arithmetic near 'The formula is 10 / 2' should not trigger when '$' is 100+ chars away",
    );
  });

  test('arithmetic near currency context, still detects', () => {
    const result = scanner.scan('Profit calculation: $1,234.56+500.00+100.00=1,834.56 USD');

    assert.ok(
      result.allDetected.some((s) => s.domain === 'Financial'),
      'arithmetic with adjacent currency context should still detect',
    );
  });

  test('verb quantity, preserves verb', () => {
    const result = scanner.scan('bought 100 NVDA for cash');

    // "bought" should NOT be part of the matched text
    const verbMatch = result.allDetected.find((s) => s.service === 'verb_quantity');

    assert.ok(verbMatch !== undefined, 'verb_quantity should detect the number');
    assert.ok(!verbMatch.matchedText.includes('bought'), 'the verb should not be captured - only the number');
    assert.equal(verbMatch.matchedText, '100');
  });

  test('date number, not detected as quantity', () => {
    const result = scanner.scan('17 JUL 2025 was a good day');

    assert.ok(
      !result.aboveThreshold.some((s) => s.matchedText === '17' && s.domain === 'Financial'),
      'day-of-month before a month name should not be a financial quantity',
    );
  });

  test('timestamp, components not detected', () => {
    const result = scanner.scan('April 8, 2025 at 10:36:54 AM GMT+3\n\nbought 100 NVDA');

    // Time components (8, 10, 36, 54, 3) should not be detected
    const timestampFP = result.aboveThreshold
      .filter((s) => s.service === 'large_number')
      .filter((s) => ['8', '10', '36', '54', '3'].includes(s.matchedText));

    assert.equal(timestampFP.length, 0, 'timestamp components should not be detected as financial quantities');

    // The actual financial data should still be detected
    assert.ok(result.aboveThreshold.some((s) => s.matchedText === '100'), "'100' (the quantity) should still be detected");
  });
});
