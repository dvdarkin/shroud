/**
 * Replaces detected spans with deterministic `[TYPE:xxxxxxxx]` tokens. The token id
 * is the type abbreviation plus HMAC-SHA256(key, UTF-8(matchedText)) truncated to the
 * first 4 bytes, as lower-case hex: the same value and key always give the same token,
 * so tokens correlate across files without exposing the value. Spans are replaced
 * right to left so earlier offsets stay valid.
 */
import { createHmac } from 'node:crypto';
import {
  type EntityType,
  type ScanResult,
  type SensitiveSpan,
  type SensitivityDomain,
  spanLength,
  typeAbbreviation,
} from './models.js';

export interface TokenMapping {
  readonly tokenId: string;
  readonly originalValue: string;
  readonly entityType: EntityType;
  readonly domain: SensitivityDomain;
}

export interface MaskResult {
  readonly maskedText: string;
  readonly tokens: readonly TokenMapping[];
}

/** The token id (without brackets) for a value: `${abbreviation}:${8 hex chars}`. */
export function generateTokenId(key: Uint8Array, entityType: EntityType, matchedText: string): string {
  const mac = createHmac('sha256', key).update(Buffer.from(matchedText, 'utf8')).digest();
  return `${typeAbbreviation(entityType)}:${mac.subarray(0, 4).toString('hex')}`;
}

export class SpanMasker {
  private readonly key: Uint8Array;

  constructor(key: Uint8Array) {
    this.key = key;
  }

  /** Replace all above-threshold spans with deterministic `[TYPE:XXXXXXXX]` tokens. */
  mask(text: string, scanResult: ScanResult): MaskResult {
    // Stable descending sort by start, like LINQ OrderByDescending.
    const spans = [...scanResult.aboveThreshold].sort((a, b) => b.start - a.start);
    let masked = text;
    const tokens: TokenMapping[] = [];

    for (const span of spans) {
      const tokenId = this.tokenFor(span);
      masked = replaceRange(masked, span.start, spanLength(span), `[${tokenId}]`);
      tokens.push({ tokenId, originalValue: span.matchedText, entityType: span.entityType, domain: span.domain });
    }

    return { maskedText: masked, tokens };
  }

  private tokenFor(span: SensitiveSpan): string {
    return generateTokenId(this.key, span.entityType, span.matchedText);
  }
}

/** StringBuilder.Remove(start, length) + Insert(start, value), including its range checks. */
function replaceRange(text: string, start: number, length: number, value: string): string {
  if (start < 0 || length < 0 || start + length > text.length) {
    throw new RangeError(`Span [${start}, ${start + length}) is outside the text (length ${text.length})`);
  }
  return text.slice(0, start) + value + text.slice(start + length);
}
