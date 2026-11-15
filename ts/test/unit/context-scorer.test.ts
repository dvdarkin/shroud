// Port of src/Shroud.Tests.Unit/ContextScorerTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  ADDITIONAL_CONTEXT_WORD_BOOST,
  ASSET_NAME_BOOST,
  CURRENCY_SIGNAL_BOOST,
  MAX_ADDITIONAL_CONTEXT_WORDS,
  score,
  scoreWithDetail,
} from '../../src/context-scorer.js';
import { dotnetRegex } from '../../src/internal/dotnet-regex.js';
import type { SensitiveSpan, SensitivityDomain, SensitivityPattern } from '../../src/models.js';

function makePattern(
  baseConfidence: number,
  contextWords: string[],
  contextBoost: number,
  domain: SensitivityDomain = 'OnChain',
): SensitivityPattern {
  return {
    entityType: 'CryptoAddr',
    domain,
    regex: dotnetRegex(String.raw`\bTEST\b`),
    baseConfidence,
    contextWords,
    contextBoost,
    service: 'test_pattern',
  };
}

function makeSpan(start: number, end: number, domain: SensitivityDomain = 'OnChain'): SensitiveSpan {
  return { start, end, entityType: 'CryptoAddr', domain, confidence: 0, matchedText: 'TEST', service: '' };
}

describe('ContextScorerTests', () => {
  test('no context words, returns base confidence', () => {
    const pattern = makePattern(0.9, [], 0);
    const text = 'some text TEST more text';
    const span = makeSpan(10, 14);

    assert.equal(score(span, pattern, text), 0.9);
  });

  test('single context word, applies context boost', () => {
    const pattern = makePattern(0.3, ['solana'], 0.55);
    const text = 'solana address: TEST here';
    const span = makeSpan(16, 20);

    assert.equal(score(span, pattern, text), 0.3 + 0.55);
  });

  test('multiple context words, additional boost capped', () => {
    const pattern = makePattern(0.3, ['word1', 'word2', 'word3', 'word4', 'word5'], 0.2);
    const text = 'word1 word2 word3 word4 word5 TEST here';
    const span = makeSpan(30, 34);

    assert.equal(score(span, pattern, text), 0.3 + 0.2 + ADDITIONAL_CONTEXT_WORD_BOOST * MAX_ADDITIONAL_CONTEXT_WORDS);
  });

  test('two context words, one additional boost', () => {
    const pattern = makePattern(0.3, ['word1', 'word2'], 0.2);
    const text = 'word1 word2 TEST here';
    const span = makeSpan(12, 16);

    assert.equal(score(span, pattern, text), 0.3 + 0.2 + ADDITIONAL_CONTEXT_WORD_BOOST);
  });

  test('score capped, at one', () => {
    const pattern = makePattern(0.8, ['word1', 'word2', 'word3', 'word4', 'word5'], 0.5);
    const text = 'word1 word2 word3 word4 word5 TEST here';
    const span = makeSpan(30, 34);

    assert.equal(score(span, pattern, text), 1.0);
  });

  test('context word at edge of window, found', () => {
    const padding = 'x'.repeat(120 - 'solana'.length);
    const text = `solana${padding}TEST`;
    const span = makeSpan(text.length - 4, text.length);
    const pattern = makePattern(0.3, ['solana'], 0.55);

    assert.ok(score(span, pattern, text) > 0.3, 'context word within 120 chars should be found');
  });

  test('context word beyond window, not found', () => {
    const padding = 'x'.repeat(121);
    const text = `solana${padding}TEST`;
    const span = makeSpan(text.length - 4, text.length);
    const pattern = makePattern(0.3, ['solana'], 0.55);

    assert.equal(score(span, pattern, text), 0.3, 'context word beyond 120 chars should not be found');
  });

  test('case insensitive, context matching', () => {
    const pattern = makePattern(0.3, ['USD'], 0.55);
    const span = makeSpan(4, 8);

    const score1 = score(span, pattern, 'USD TEST here');
    const score2 = score(span, pattern, 'usd TEST here');
    const score3 = score(span, pattern, 'Usd TEST here');

    assert.equal(score1, score2);
    assert.equal(score2, score3);
  });

  test('financial domain, asset name boost non cumulative', () => {
    const pattern = makePattern(0.3, ['position'], 0.2, 'Financial');
    const text = 'BTC ETH position TEST here';
    const span = makeSpan(21, 25, 'Financial');

    assert.equal(score(span, pattern, text), 0.3 + 0.2 + ASSET_NAME_BOOST);
  });

  test('financial domain, currency signal boost non cumulative', () => {
    const pattern = makePattern(0.3, ['position'], 0.2, 'Financial');
    const text = 'usd eur position TEST here';
    const span = makeSpan(21, 25, 'Financial');

    assert.equal(score(span, pattern, text), 0.3 + 0.2 + CURRENCY_SIGNAL_BOOST);
  });

  test('non financial domain, asset currency boosts do not apply', () => {
    const pattern = makePattern(0.3, ['solana'], 0.55, 'OnChain');
    const text = 'BTC USD solana $ TEST here';
    const span = makeSpan(21, 25, 'OnChain');

    assert.equal(score(span, pattern, text), 0.3 + 0.55);
  });

  test('substring match, documented behavior', () => {
    const pattern = makePattern(0.3, ['sol'], 0.55);
    const text = 'solution TEST here';
    const span = makeSpan(9, 13);

    assert.ok(score(span, pattern, text) > 0.3, "substring matching is current behavior: 'sol' matches inside 'solution'");
  });

  test('no context words found, no boost', () => {
    const pattern = makePattern(0.3, ['solana', 'phantom'], 0.55);
    const text = 'nothing relevant TEST here';
    const span = makeSpan(18, 22);

    assert.equal(score(span, pattern, text), 0.3);
  });

  test('internal overload, returns scoring detail', () => {
    const pattern = makePattern(0.3, ['solana', 'phantom'], 0.55);
    const text = 'solana phantom TEST here';
    const span = makeSpan(15, 19);

    const { confidence, detail } = scoreWithDetail(span, pattern, text);

    assert.equal(detail.baseConfidence, 0.3);
    assert.equal(detail.finalConfidence, confidence);
    assert.equal(detail.isStructural, false);
    assert.ok(detail.contextWordsFound.includes('solana'));
    assert.ok(detail.contextWordsFound.includes('phantom'));
  });
});
