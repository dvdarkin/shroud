// Port of src/Shroud.Tests.Unit/TableCellNumberTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SensitivityScanner } from '../../src/scanner.js';

describe('TableCellNumberTests', () => {
  const scanner = new SensitivityScanner();

  test('bare integer in financial table row, detected', () => {
    // Representative of an exchange order-history paste: small integer amounts sit alone
    // in table cells, with column headers (Amount, Price, Total) far up in the file
    // beyond the context window. The only in-window signals are row neighbours.
    const row = '| 2026-04-20 12:17:52 | [TRX_USDT?type=spot] | Limit | Buy | 0.12 | 0.12 | 30 | 30 | 0 | 3.6 | Filled |';

    const result = scanner.scan(row);

    assert.ok(
      result.aboveThreshold.some((s) => s.matchedText === '30'),
      'bare integer 30 in a table cell with Limit/Buy/Filled context should be masked',
    );
  });

  test('bare zero in financial table row, detected', () => {
    const row = '| Limit | Buy | [QTY:aaaa1111] | [QTY:aaaa2222] | 0 | [QTY:aaaa3333] | Filled | USDT |';

    const result = scanner.scan(row);

    assert.ok(
      result.aboveThreshold.some((s) => s.matchedText === '0'),
      'bare 0 in a Total-column cell surrounded by trading signals should be masked',
    );
  });

  test('bare number in non financial table, not detected', () => {
    // A schedule/inventory table without trading context. Must NOT fire or we get
    // false positives on every markdown table in the vault.
    const text = '| Task | Hours |\n| ---- | ----- |\n| write | 3 |\n| review | 2 |';

    const result = scanner.scan(text);

    assert.ok(
      !result.aboveThreshold.some((s) => s.matchedText === '3' || s.matchedText === '2'),
      'bare numbers in a non-financial table must stay below threshold',
    );
  });

  test('table cell decimal, detected', () => {
    const row = '| Limit | Buy | 0.5 | price | USDT |';

    const result = scanner.scan(row);

    assert.ok(
      result.aboveThreshold.some((s) => s.matchedText === '0.5'),
      'decimals in table cells with financial context should be masked',
    );
  });

  test('table cell comma formatted, detected', () => {
    const row = '| Limit | Buy | 1,234 | price | USDT |';

    const result = scanner.scan(row);

    assert.ok(
      result.aboveThreshold.some((s) => s.matchedText.includes('1,234')),
      'comma-formatted numbers in table cells should be masked',
    );
  });
});
