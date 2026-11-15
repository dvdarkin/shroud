// Port of src/Shroud.Tests.Unit/SpanMaskerTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SpanMasker } from '../../src/masker.js';
import type { EntityType, ScanResult, SensitiveSpan, SensitivityDomain } from '../../src/models.js';

const TEST_KEY = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
]);

const ALT_KEY = new Uint8Array([
  0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
  0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
  0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
  0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
]);

// --- Helpers ---

function makeSpan(
  start: number,
  end: number,
  type: EntityType,
  text: string,
  domain: SensitivityDomain = 'OnChain',
  confidence = 0.9,
): SensitiveSpan {
  return { start, end, entityType: type, domain, confidence, matchedText: text, service: '' };
}

function makeScanResult(...spans: SensitiveSpan[]): ScanResult {
  return { allDetected: spans, aboveThreshold: spans, belowThreshold: [], threshold: 0.7 };
}

describe('SpanMaskerTests', () => {
  test('determinism, same input same key, same tokens', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'Send to 0x1111111111111111111111111111111111111111 now';
    const span = makeSpan(8, 50, 'CryptoAddr', '0x1111111111111111111111111111111111111111');
    const scanResult = makeScanResult(span);

    const result1 = masker.mask(text, scanResult);
    const result2 = masker.mask(text, scanResult);

    assert.equal(result1.maskedText, result2.maskedText);
    assert.equal(result1.tokens[0]!.tokenId, result2.tokens[0]!.tokenId);
  });

  test('different keys, different token ids', () => {
    const text = 'Send to 0x1111111111111111111111111111111111111111 now';
    const span = makeSpan(8, 50, 'CryptoAddr', '0x1111111111111111111111111111111111111111');
    const scanResult = makeScanResult(span);

    const result1 = new SpanMasker(TEST_KEY).mask(text, scanResult);
    const result2 = new SpanMasker(ALT_KEY).mask(text, scanResult);

    assert.notEqual(result1.tokens[0]!.tokenId, result2.tokens[0]!.tokenId);
  });

  test('token format, matches expected pattern', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'Key: 0x1111111111111111111111111111111111111111';
    const span = makeSpan(5, 47, 'CryptoAddr', '0x1111111111111111111111111111111111111111');
    const scanResult = makeScanResult(span);

    const result = masker.mask(text, scanResult);

    assert.match(result.tokens[0]!.tokenId, /^ADDR:[0-9a-f]{8}$/);
    assert.match(result.maskedText, /\[ADDR:[0-9a-f]{8}\]/);
  });

  test('empty above threshold, text unchanged', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'Nothing sensitive here';
    const scanResult: ScanResult = { allDetected: [], aboveThreshold: [], belowThreshold: [], threshold: 0.7 };

    const result = masker.mask(text, scanResult);

    assert.equal(result.maskedText, text);
    assert.equal(result.tokens.length, 0);
  });

  test('multiple spans, all replaced correctly', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'Send $500 to addr@test.com today';
    const spans = [makeSpan(5, 9, 'Amount', '$500'), makeSpan(13, 26, 'Email', 'addr@test.com')];
    const scanResult: ScanResult = { allDetected: spans, aboveThreshold: spans, belowThreshold: [], threshold: 0.7 };

    const result = masker.mask(text, scanResult);

    assert.ok(!result.maskedText.includes('$500'));
    assert.ok(!result.maskedText.includes('addr@test.com'));
    assert.equal(result.tokens.length, 2);
    assert.ok(result.maskedText.startsWith('Send '));
    assert.ok(result.maskedText.endsWith(' today'));
  });

  test('position correctness, right to left preserves indices', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'A 123 B 456 C';
    const span1 = makeSpan(2, 5, 'Amount', '123');
    const span2 = makeSpan(8, 11, 'Amount', '456');
    const scanResult: ScanResult = {
      allDetected: [span1, span2],
      aboveThreshold: [span1, span2],
      belowThreshold: [],
      threshold: 0.7,
    };

    const result = masker.mask(text, scanResult);

    assert.ok(result.maskedText.startsWith('A '));
    assert.ok(result.maskedText.includes(' B '));
    assert.ok(result.maskedText.endsWith(' C'));
    assert.ok(!result.maskedText.includes('123'));
    assert.ok(!result.maskedText.includes('456'));
  });

  test('type abbreviations, correct in tokens', () => {
    const masker = new SpanMasker(TEST_KEY);
    const text = 'SSN: 123-45-6789';
    const span = makeSpan(5, 16, 'Ssn', '123-45-6789');
    const scanResult = makeScanResult(span);

    const result = masker.mask(text, scanResult);

    assert.ok(result.tokens[0]!.tokenId.startsWith('SSN:'));
  });
});
