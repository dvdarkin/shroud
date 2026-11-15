/**
 * Core detection pipeline. For each registered pattern, finds all regex matches,
 * skips matches fully inside exclusion zones (YAML frontmatter at offset 0, file-path
 * metadata lines, dates and times), drops digit-less financial numbers, scores each
 * match, runs the Luhn check for credit cards,
 * deduplicates overlapping spans (longest wins, containers absorb contents) and splits
 * the result at the confidence threshold.
 */
import type { ShroudConfig } from './config.js';
import { type ScoringDetail, emptyScoringDetail, scoreWithDetail } from './context-scorer.js';
import { contains, normalize } from './internal/charset.js';
import { dotnetRegex } from './internal/dotnet-regex.js';
import { DOTNET_DIGIT } from './internal/unicode-tables.js';
import { isValidLuhn } from './luhn.js';
import {
  type ScanResult,
  type SensitiveSpan,
  type SensitivityPattern,
  spanLength,
} from './models.js';
import { getAllPatterns, getPatternsForConfig } from './pattern-library.js';

export interface ExclusionZone {
  readonly start: number;
  readonly end: number;
}

export interface SpanDiagnostic {
  readonly span: SensitiveSpan;
  readonly scoring: ScoringDetail;
  readonly wasExcluded: boolean;
  readonly failedLuhn: boolean;
}

export interface OverlapResolution {
  readonly dropped: SensitiveSpan;
  readonly winner: SensitiveSpan;
  readonly reason: 'contained' | 'shorter' | 'lower_confidence';
}

export interface ScanDiagnostics {
  readonly exclusionZones: ExclusionZone[];
  readonly allSpans: SpanDiagnostic[];
  readonly overlapResolutions: OverlapResolution[];
}

export function createScanDiagnostics(): ScanDiagnostics {
  return { exclusionZones: [], allSpans: [], overlapResolutions: [] };
}

// YAML front matter: only when the text STARTS with a "---" line (offset 0; readAllText has
// already stripped a BOM), ending at the next "---" line. Whole lines are consumed one at a
// time, so LF and CRLF both work and an empty block ("---\n---") ends at its own closing
// line. A pair of "---" lines later in the document is a pair of horizontal rules.
const FRONTMATTER = dotnetRegex(String.raw`\A---[ \t]*\r?\n(?:[^\n]*\n)*?---[ \t]*\r?$`, { multiline: true });
// File-path metadata line ("file: ...", "source_file: ..."). The key must be a whole word:
// not preceded by a letter, digit, underscore or hyphen, and its value is on the same line.
const FILE_PATH = dotnetRegex(String.raw`(?<![\p{L}\p{Nd}_\-])(?:source_file|file|path|attachment):[ \t]*.+$`, {
  multiline: true,
  ignoreCase: true,
});

// Date and time patterns. They never produce spans; they carve "do not touch" zones so
// numeric patterns do not match inside temporal text. A span is dropped only when FULLY
// contained in a zone, so "$2026" and "2026 USDC" still match.
const DATE_TIME_EXCLUSIONS: readonly RegExp[] = [
  // ISO date with optional time: 2026-04-20, 2026-04-20T17:30, 2026-04-20 17:30:34.123Z
  dotnetRegex(String.raw`\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b`),
  // Year-month: 2026-04
  dotnetRegex(String.raw`\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])\b`),
  // Clock time: 17:30:34, 14:25, 5:00
  dotnetRegex(String.raw`\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?\b`),
  // MM/DD/YYYY, MM-DD-YYYY, MM.DD.YYYY with 2- or 4-digit year
  dotnetRegex(String.raw`\b(?:0?[1-9]|1[0-2])[/.\-](?:0?[1-9]|[12]\d|3[01])[/.\-](?:19|20)?\d{2}\b`),
  // DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY (4-digit year only to disambiguate)
  dotnetRegex(String.raw`\b(?:0?[1-9]|[12]\d|3[01])[/.\-](?:0?[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b`),
  // Month-name dates: "20 Apr 2026", "April 20, 2026", "Apr 2026"
  dotnetRegex(
    String.raw`\b(?:(?:0?[1-9]|[12]\d|3[01])\s+)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*(?:\s+(?:0?[1-9]|[12]\d|3[01]))?[,\s]+(?:19|20)\d{2}\b`,
    { ignoreCase: true },
  ),
  // ISO week: 2026-W17, 2026-W17-3
  dotnetRegex(String.raw`\b(?:19|20)\d{2}-W(?:0[1-9]|[1-4]\d|5[0-3])(?:-[1-7])?\b`),
  // 12-hour clock: 5pm, 5:30pm, 11:45 AM
  dotnetRegex(String.raw`\b(?:0?[1-9]|1[0-2])(?::[0-5]\d)?\s*[ap]m\b`, { ignoreCase: true }),
  // Bare 4-digit year (1900-2099). Last-resort zone.
  dotnetRegex(String.raw`\b(?:19|20)\d{2}\b`),
];

/** The exclusion-zone regexes in evaluation order (frontmatter, file path, dates). Internal. */
export const EXCLUSION_REGEXES: readonly RegExp[] = [FRONTMATTER, FILE_PATH, ...DATE_TIME_EXCLUSIONS];

const globalCopies = new WeakMap<RegExp, RegExp>();

/** A global, non-sticky RegExp for `regex`, reusing it when it already is one. */
function globalOf(regex: RegExp): RegExp {
  if (regex.global && !regex.sticky) return regex;
  let copy = globalCopies.get(regex);
  if (!copy) {
    copy = new RegExp(regex.source, regex.flags.replace('y', '') + (regex.global ? '' : 'g'));
    globalCopies.set(regex, copy);
  }
  return copy;
}

/**
 * All non-overlapping matches, left to right (Regex.Matches semantics): the next
 * search starts at the end of the previous match, or one code unit further after an
 * empty match. Collected eagerly so the shared RegExp's lastIndex is never observed
 * by interleaved callers. (Cloning per call is avoided: it recompiles the very large
 * translated sources.)
 */
export function matchesOf(regex: RegExp, text: string): { index: number; length: number }[] {
  const rx = globalOf(regex);
  const unicode = rx.unicode || rx.flags.includes('v');
  const found: { index: number; length: number }[] = [];
  rx.lastIndex = 0;
  for (let m = rx.exec(text); m !== null; m = rx.exec(text)) {
    const length = m[0].length;
    found.push({ index: m.index, length });
    if (length === 0) rx.lastIndex = advanceIndex(text, rx.lastIndex, unicode);
  }
  rx.lastIndex = 0;
  return found;
}

function advanceIndex(text: string, index: number, unicode: boolean): number {
  if (!unicode || index + 1 >= text.length) return index + 1;
  const c = text.charCodeAt(index);
  const d = text.charCodeAt(index + 1);
  return c >= 0xd800 && c <= 0xdbff && d >= 0xdc00 && d <= 0xdfff ? index + 2 : index + 1;
}

function buildExclusions(text: string): ExclusionZone[] {
  const zones: ExclusionZone[] = [];
  for (const rx of EXCLUSION_REGEXES) {
    for (const m of matchesOf(rx, text)) zones.push({ start: m.index, end: m.index + m.length });
  }
  return zones;
}

const DIGITS = normalize(DOTNET_DIGIT);

/**
 * True for a Financial Amount/Quantity/Price match with no decimal digit (char.IsDigit is
 * Unicode Nd, the same class as .NET regex \d). Several financial regexes are built from
 * [\d,]+ and can match separator-only text such as a lone ",".
 */
function isDigitlessFinancialNumber(pattern: SensitivityPattern, matchedText: string): boolean {
  if (pattern.domain !== 'Financial') return false;
  if (pattern.entityType !== 'Amount' && pattern.entityType !== 'Quantity' && pattern.entityType !== 'Price') return false;
  for (let i = 0; i < matchedText.length; i++) {
    if (contains(DIGITS, matchedText.charCodeAt(i))) return false;
  }
  return true;
}

function isExcluded(start: number, end: number, zones: readonly ExclusionZone[]): boolean {
  return zones.some((z) => start >= z.start && end <= z.end);
}

export class SensitivityScanner {
  private readonly patterns: readonly SensitivityPattern[];
  private readonly tokenizeThreshold: number;

  /** Scanner for a config: its enabled patterns and threshold. */
  constructor(config: ShroudConfig);
  /** Scanner over explicit patterns (default: all built-in patterns) and threshold (default 0.70). */
  constructor(patterns?: readonly SensitivityPattern[] | null, tokenizeThreshold?: number);
  constructor(patternsOrConfig?: readonly SensitivityPattern[] | ShroudConfig | null, tokenizeThreshold = 0.7) {
    if (patternsOrConfig && !Array.isArray(patternsOrConfig)) {
      const config = patternsOrConfig as ShroudConfig;
      this.patterns = getPatternsForConfig(config);
      this.tokenizeThreshold = config.threshold;
    } else {
      this.patterns = (patternsOrConfig as readonly SensitivityPattern[] | null | undefined) ?? getAllPatterns();
      this.tokenizeThreshold = tokenizeThreshold;
    }
  }

  get threshold(): number {
    return this.tokenizeThreshold;
  }

  scan(text: string): ScanResult {
    return this.scanInternal(text, undefined);
  }

  /** Scan and also return the pipeline diagnostics used by `scan --verbose/--debug`. */
  scanWithDiagnostics(text: string): { result: ScanResult; diagnostics: ScanDiagnostics } {
    const diagnostics = createScanDiagnostics();
    return { result: this.scanInternal(text, diagnostics), diagnostics };
  }

  private scanInternal(text: string, diagnostics: ScanDiagnostics | undefined): ScanResult {
    const exclusions = buildExclusions(text);
    diagnostics?.exclusionZones.push(...exclusions);

    const allSpans: SensitiveSpan[] = [];

    for (const pattern of this.patterns) {
      for (const match of matchesOf(pattern.regex, text)) {
        const start = match.index;
        const end = match.index + match.length;
        const matchedText = text.substring(start, end);
        const span: SensitiveSpan = {
          start,
          end,
          entityType: pattern.entityType,
          domain: pattern.domain,
          confidence: pattern.baseConfidence,
          matchedText,
          service: pattern.service,
        };

        if (isExcluded(start, end, exclusions)) {
          diagnostics?.allSpans.push({
            span,
            scoring: emptyScoringDetail(pattern.baseConfidence, pattern.service),
            wasExcluded: true,
            failedLuhn: false,
          });
          continue;
        }

        // A financial number must contain at least one digit. The match is dropped before
        // scoring and leaves no diagnostic record (C# `continue`s here too).
        if (isDigitlessFinancialNumber(pattern, matchedText)) continue;

        const { confidence, detail } = scoreWithDetail(span, pattern, text);
        const scored: SensitiveSpan = { ...span, confidence };

        if (scored.entityType === 'CreditCard' && !isValidLuhn(matchedText)) {
          diagnostics?.allSpans.push({ span: scored, scoring: detail, wasExcluded: false, failedLuhn: true });
          continue;
        }

        diagnostics?.allSpans.push({ span: scored, scoring: detail, wasExcluded: false, failedLuhn: false });
        allSpans.push(scored);
      }
    }

    const deduped = deduplicateOverlaps(allSpans, diagnostics);
    return {
      allDetected: deduped,
      aboveThreshold: deduped.filter((s) => s.confidence >= this.tokenizeThreshold),
      belowThreshold: deduped.filter((s) => s.confidence < this.tokenizeThreshold),
      threshold: this.tokenizeThreshold,
    };
  }
}

/**
 * Removes overlapping spans. Candidates are visited longest first, then highest
 * confidence (stable for ties, like LINQ OrderByDescending().ThenByDescending()); a
 * candidate is dropped when an accepted span contains it, is longer, or is equally
 * long with at least its confidence. The result is ordered by start (stable).
 */
export function deduplicateOverlaps(spans: SensitiveSpan[], diagnostics?: ScanDiagnostics): SensitiveSpan[] {
  if (spans.length <= 1) return spans;

  const sorted = [...spans].sort((a, b) => spanLength(b) - spanLength(a) || b.confidence - a.confidence);
  let result: SensitiveSpan[] = [];

  for (const span of sorted) {
    let winner: SensitiveSpan | undefined;
    let reason: OverlapResolution['reason'] | undefined;

    const dominated = result.some((accepted) => {
      const overlaps = span.start < accepted.end && span.end > accepted.start;
      if (!overlaps) return false;
      if (span.start >= accepted.start && span.end <= accepted.end) {
        winner = accepted;
        reason = 'contained';
        return true;
      }
      if (spanLength(accepted) > spanLength(span)) {
        winner = accepted;
        reason = 'shorter';
        return true;
      }
      if (spanLength(accepted) === spanLength(span) && accepted.confidence >= span.confidence) {
        winner = accepted;
        reason = 'lower_confidence';
        return true;
      }
      return false;
    });

    if (dominated) {
      if (diagnostics && winner && reason) {
        diagnostics.overlapResolutions.push({ dropped: span, winner, reason });
      }
    } else {
      const contained = (accepted: SensitiveSpan) => accepted.start >= span.start && accepted.end <= span.end;
      if (diagnostics) {
        for (const r of result.filter(contained)) {
          diagnostics.overlapResolutions.push({ dropped: r, winner: span, reason: 'contained' });
        }
      }
      result = result.filter((accepted) => !contained(accepted));
      result.push(span);
    }
  }

  return [...result].sort((a, b) => a.start - b.start);
}
