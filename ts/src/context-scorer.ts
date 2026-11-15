/**
 * Scores detection confidence by examining a 120-character window around each match.
 * Structural patterns (no context words) return their base confidence. Contextual
 * patterns are boosted when any of their context words appears in the window, plus a
 * small capped bonus per additional word. Financial-domain patterns get extra
 * non-cumulative boosts for a known asset name and for a currency signal.
 *
 * Matching is case-insensitive substring search (.NET OrdinalIgnoreCase): "sol"
 * matches inside "solution". That trade-off is intentional and documented.
 */
import { KNOWN_ASSETS } from './pattern-library.js';
import { type SensitiveSpan, type SensitivityPattern, isStructural } from './models.js';
import { ordinalIgnoreCaseSearcher } from './internal/ordinal.js';

export const CONTEXT_WINDOW_CHARS = 120;
export const ADDITIONAL_CONTEXT_WORD_BOOST = 0.05;
export const MAX_ADDITIONAL_CONTEXT_WORDS = 3;
export const ASSET_NAME_BOOST = 0.1;
export const CURRENCY_SIGNAL_BOOST = 0.1;

const CURRENCY_SIGNALS: readonly string[] = [
  'usd', 'aud', 'eur', 'gbp', 'jpy', 'cad', 'chf', 'nzd', 'sgd', 'hkd',
  'krw', 'cny', 'inr', 'brl', 'usdt', 'usdc', 'dai',
  '$', 'fee', 'fees', 'commission', 'rate',
];

/** How a confidence value was reached; feeds `scan --verbose` / `--debug` output. */
export interface ScoringDetail {
  baseConfidence: number;
  finalConfidence: number;
  isStructural: boolean;
  contextWordsFound: string[];
  contextWindowStart: number;
  contextWindowEnd: number;
  assetBoostApplied: boolean;
  currencyBoostApplied: boolean;
  patternService: string;
}

export function emptyScoringDetail(baseConfidence = 0, patternService = ''): ScoringDetail {
  return {
    baseConfidence,
    finalConfidence: 0,
    isStructural: false,
    contextWordsFound: [],
    contextWindowStart: 0,
    contextWindowEnd: 0,
    assetBoostApplied: false,
    currencyBoostApplied: false,
    patternService,
  };
}

export function score(span: SensitiveSpan, pattern: SensitivityPattern, fullText: string): number {
  return scoreWithDetail(span, pattern, fullText).confidence;
}

export function scoreWithDetail(
  span: SensitiveSpan,
  pattern: SensitivityPattern,
  fullText: string,
): { confidence: number; detail: ScoringDetail } {
  let value = pattern.baseConfidence;
  const detail = emptyScoringDetail(pattern.baseConfidence, pattern.service);
  detail.isStructural = isStructural(pattern);

  if (pattern.contextWords.length === 0) {
    detail.finalConfidence = value;
    return { confidence: value, detail };
  }

  const contextStart = Math.max(0, span.start - CONTEXT_WINDOW_CHARS);
  const contextEnd = Math.min(fullText.length, span.end + CONTEXT_WINDOW_CHARS);
  if (contextStart > contextEnd) {
    // C# range slicing (fullText[a..b]) throws ArgumentOutOfRangeException here.
    throw new RangeError(`Span [${span.start}, ${span.end}) lies outside the text`);
  }
  const context = fullText.slice(contextStart, contextEnd);
  detail.contextWindowStart = contextStart;
  detail.contextWindowEnd = contextEnd;

  const contains = ordinalIgnoreCaseSearcher(context);
  const found = pattern.contextWords.filter(contains);
  detail.contextWordsFound = found;

  if (found.length > 0) value += pattern.contextBoost;
  if (found.length > 1) {
    value += ADDITIONAL_CONTEXT_WORD_BOOST * Math.min(found.length - 1, MAX_ADDITIONAL_CONTEXT_WORDS);
  }

  if (pattern.domain === 'Financial') {
    if (KNOWN_ASSETS.some(contains)) {
      value += ASSET_NAME_BOOST;
      detail.assetBoostApplied = true;
    }
    if (CURRENCY_SIGNALS.some(contains)) {
      value += CURRENCY_SIGNAL_BOOST;
      detail.currencyBoostApplied = true;
    }
  }

  value = Math.min(value, 1.0);
  detail.finalConfidence = value;
  return { confidence: value, detail };
}
