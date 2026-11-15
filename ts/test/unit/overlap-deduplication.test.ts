// Port of src/Shroud.Tests.Unit/OverlapDeduplicationTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { type EntityType, type SensitiveSpan, spanLength } from '../../src/models.js';
import { createScanDiagnostics, deduplicateOverlaps } from '../../src/scanner.js';

function makeSpan(start: number, end: number, confidence = 0.9, type: EntityType = 'CryptoAddr', text = 'match'): SensitiveSpan {
  return {
    start,
    end,
    entityType: type,
    domain: 'OnChain',
    confidence,
    matchedText: text.length === end - start ? text : 'x'.repeat(end - start),
    service: '',
  };
}

describe('OverlapDeduplicationTests', () => {
  test('empty list, returns empty', () => {
    const result = deduplicateOverlaps([]);
    assert.equal(result.length, 0);
  });

  test('single span, returned as is', () => {
    const span = makeSpan(0, 10);
    const result = deduplicateOverlaps([span]);

    assert.equal(result.length, 1);
    assert.deepEqual(result[0], span);
  });

  test('no overlaps, all returned', () => {
    const span1 = makeSpan(0, 5);
    const span2 = makeSpan(10, 15);
    const span3 = makeSpan(20, 25);

    const result = deduplicateOverlaps([span1, span2, span3]);

    assert.equal(result.length, 3);
  });

  test('full containment, container wins', () => {
    const container = makeSpan(0, 20, 0.5);
    const contained = makeSpan(5, 15, 0.95);

    const result = deduplicateOverlaps([container, contained]);

    assert.equal(result.length, 1);
    assert.equal(result[0]!.start, 0);
    assert.equal(result[0]!.end, 20);
  });

  test('partial overlap, longer wins', () => {
    const longer = makeSpan(0, 15, 0.5);
    const shorter = makeSpan(10, 20, 0.95);

    const result = deduplicateOverlaps([longer, shorter]);

    assert.equal(result.length, 1);
    assert.equal(result[0]!.start, 0);
    assert.equal(spanLength(result[0]!), 15);
  });

  test('equal length, higher confidence wins', () => {
    const high = makeSpan(0, 10, 0.95);
    const low = makeSpan(5, 15, 0.5);

    const result = deduplicateOverlaps([high, low]);

    assert.equal(result.length, 1);
    assert.equal(result[0]!.confidence, 0.95);
  });

  test('equal length equal confidence, first in sort order wins', () => {
    const span1 = makeSpan(0, 10, 0.9, 'CryptoAddr', 'aaaaaaaaaa');
    const span2 = makeSpan(5, 15, 0.9, 'CryptoAddr', 'bbbbbbbbbb');

    const result = deduplicateOverlaps([span1, span2]);

    assert.equal(result.length, 1, 'equal length and confidence should still deduplicate');
  });

  test('container removes previously accepted smaller', () => {
    const small = makeSpan(5, 10, 0.95);
    const large = makeSpan(0, 30, 0.5);

    const result = deduplicateOverlaps([small, large]);

    assert.equal(result.length, 1);
    assert.equal(result[0]!.start, 0);
    assert.equal(result[0]!.end, 30);
  });

  test('three way overlap, correct resolution', () => {
    const a = makeSpan(0, 20, 0.9);
    const b = makeSpan(5, 15, 0.95);
    const c = makeSpan(12, 25, 0.85);

    const result = deduplicateOverlaps([a, b, c]);

    assert.equal(result.length, 1);
    assert.equal(result[0]!.start, 0);
    assert.equal(result[0]!.end, 20);
  });

  test('result, sorted by start position', () => {
    const span1 = makeSpan(20, 30);
    const span2 = makeSpan(0, 5);
    const span3 = makeSpan(10, 15);

    const result = deduplicateOverlaps([span1, span2, span3]);

    assert.equal(result.length, 3);
    assert.equal(result[0]!.start, 0);
    assert.equal(result[1]!.start, 10);
    assert.equal(result[2]!.start, 20);
  });

  test('adjacent spans, not deduped', () => {
    const span1 = makeSpan(0, 10);
    const span2 = makeSpan(10, 20);

    const result = deduplicateOverlaps([span1, span2]);

    assert.equal(result.length, 2, 'adjacent non-overlapping spans should both survive');
  });

  test('diagnostics populated, when provided', () => {
    const container = makeSpan(0, 20, 0.9);
    const contained = makeSpan(5, 15, 0.95);
    const diagnostics = createScanDiagnostics();

    const result = deduplicateOverlaps([container, contained], diagnostics);

    assert.equal(result.length, 1);
    assert.equal(diagnostics.overlapResolutions.length, 1);
    assert.equal(diagnostics.overlapResolutions[0]!.reason, 'contained');
  });
});
