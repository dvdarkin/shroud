/**
 * Translates the subset of .NET regular-expression syntax used by Shroud into an
 * equivalent JavaScript RegExp.
 *
 * The goal is match-for-match parity with System.Text.RegularExpressions on .NET 8,
 * not "similar" behaviour. JavaScript and .NET disagree on several constructs that
 * look identical, so the translator never passes them through:
 *
 *  - \d, \w, \s and their negations become explicit code-unit classes extracted from
 *    the .NET engine (see unicode-tables.ts). .NET classes are Unicode-aware but
 *    operate on UTF-16 code units; JS without the `u` flag is ASCII-only for \d/\w
 *    and has a different \s (JS includes U+FEFF, .NET includes U+0085).
 *  - Unicode category escapes (\p{..}, \P{..}) are not supported and throw: no Shroud
 *    pattern uses one.
 *  - \A is the start of the input in every mode.
 *  - \b is rebuilt from lookarounds over the .NET word set (which also counts
 *    U+200C/U+200D as word characters for boundaries). JS \b is ASCII-only.
 *  - `.` becomes [^\n] (.NET); JS `.` also excludes \r, U+2028 and U+2029.
 *  - ^ and $ follow .NET rules: with Multiline they are anchored at \n only (JS `m`
 *    mode also honours \r, U+2028, U+2029); without Multiline .NET `$` also
 *    matches before a final \n.
 *  - IgnoreCase is expanded into explicit classes using the .NET case equivalence
 *    table (for example `k` also matches U+212A KELVIN SIGN), instead of relying on JS
 *    `i` flag canonicalization. Shroud builds every .NET regex with
 *    RegexOptions.CultureInvariant, so this is the culture-invariant table: `i` does not
 *    match U+0130 (it would without CultureInvariant under a non-Turkish culture) and `I`
 *    does not match U+0131 (it would under tr-TR).
 *
 * The output RegExp uses no flags at all (no `u`, `i`, `m` or `s`), so JS matches on
 * UTF-16 code units exactly like .NET does and match indices are directly comparable.
 * Any construct outside the supported subset throws, rather than being translated
 * approximately.
 */
import {
  type CharSet,
  complement,
  contains,
  isDisjoint,
  isSubset,
  normalize,
  single,
  size,
  union,
} from './charset.js';
import {
  DOTNET_BOUNDARY_EXTRA,
  DOTNET_DIGIT,
  DOTNET_IGNORECASE_EXTRAS,
  DOTNET_SPACE,
  DOTNET_WORD,
} from './unicode-tables.js';

export interface DotnetRegexOptions {
  /** RegexOptions.IgnoreCase (also enabled by a leading `(?i)`). */
  readonly ignoreCase?: boolean;
  /** RegexOptions.Multiline. */
  readonly multiline?: boolean;
}

const DIGIT: CharSet = normalize(DOTNET_DIGIT);
const WORD: CharSet = normalize(DOTNET_WORD);
const SPACE: CharSet = normalize(DOTNET_SPACE);
const BOUNDARY_WORD: CharSet = union(WORD, DOTNET_BOUNDARY_EXTRA.map((c) => [c, c] as const));
const NEWLINE = 0x0a;

interface Quantifier {
  readonly min: number;
  readonly max: number; // Infinity when unbounded
  readonly lazy: boolean;
}

type GroupOpen = '(' | '(?:' | '(?=' | '(?!' | '(?<=' | '(?<!';

type Node =
  | { readonly kind: 'set'; readonly set: CharSet }
  | { readonly kind: 'group'; readonly open: GroupOpen; readonly body: Alternation }
  | { readonly kind: 'bol' }
  | { readonly kind: 'bos' }
  | { readonly kind: 'eol' }
  | { readonly kind: 'boundary'; readonly negated: boolean };

interface Item {
  readonly node: Node;
  readonly quantifier?: Quantifier;
}

type Sequence = readonly Item[];
type Alternation = readonly Sequence[];

export class UnsupportedRegexError extends Error {
  constructor(pattern: string, position: number, detail: string) {
    super(`Unsupported .NET regex construct at ${position} in /${pattern}/: ${detail}`);
    this.name = 'UnsupportedRegexError';
  }
}

class Parser {
  private pos = 0;
  ignoreCase: boolean;

  constructor(
    private readonly pattern: string,
    options: DotnetRegexOptions,
  ) {
    this.ignoreCase = options.ignoreCase ?? false;
  }

  parse(): Alternation {
    if (this.pattern.startsWith('(?i)')) {
      this.ignoreCase = true;
      this.pos = 4;
    }
    const alt = this.parseAlternation();
    if (this.pos < this.pattern.length) this.fail(`unexpected '${this.pattern[this.pos]}'`);
    return alt;
  }

  private fail(detail: string): never {
    throw new UnsupportedRegexError(this.pattern, this.pos, detail);
  }

  private peek(offset = 0): string | undefined {
    return this.pattern[this.pos + offset];
  }

  private parseAlternation(): Alternation {
    const seqs: Sequence[] = [this.parseSequence()];
    while (this.peek() === '|') {
      this.pos++;
      seqs.push(this.parseSequence());
    }
    return seqs;
  }

  private parseSequence(): Sequence {
    const items: Item[] = [];
    while (this.pos < this.pattern.length) {
      const c = this.peek();
      if (c === '|' || c === ')') break;
      const node = this.parseAtom();
      const quantifier = this.parseQuantifier();
      if (quantifier && (node.kind === 'bol' || node.kind === 'bos' || node.kind === 'eol' || node.kind === 'boundary')) {
        this.fail('quantified anchor');
      }
      items.push(quantifier ? { node, quantifier } : { node });
    }
    return items;
  }

  private parseAtom(): Node {
    const c = this.pattern[this.pos]!;
    switch (c) {
      case '(':
        return this.parseGroup();
      case '[':
        return { kind: 'set', set: this.parseClass() };
      case '.':
        this.pos++;
        return { kind: 'set', set: complement(single(NEWLINE)) };
      case '^':
        this.pos++;
        return { kind: 'bol' };
      case '$':
        this.pos++;
        return { kind: 'eol' };
      case '\\':
        return this.parseEscape();
      case '*':
      case '+':
      case '?':
        return this.fail('quantifier follows nothing');
      case '{':
        if (/^\{\d+(,\d*)?\}/.test(this.pattern.slice(this.pos))) this.fail('quantifier follows nothing');
        this.pos++;
        return this.literal(c.charCodeAt(0));
      default:
        this.pos++;
        return this.literal(c.charCodeAt(0));
    }
  }

  private literal(code: number): Node {
    return { kind: 'set', set: this.ignoreCase ? caseClose(single(code), this.pattern) : single(code) };
  }

  private parseGroup(): Node {
    const rest = this.pattern.slice(this.pos);
    let open: GroupOpen;
    if (rest.startsWith('(?<=')) open = '(?<=';
    else if (rest.startsWith('(?<!')) open = '(?<!';
    else if (rest.startsWith('(?:')) open = '(?:';
    else if (rest.startsWith('(?=')) open = '(?=';
    else if (rest.startsWith('(?!')) open = '(?!';
    else if (rest.startsWith('(?')) return this.fail('group construct (only (?:, (?=, (?!, (?<=, (?<! and a leading (?i) are supported)');
    else open = '(';
    this.pos += open.length;
    const body = this.parseAlternation();
    if (this.peek() !== ')') this.fail('unterminated group');
    this.pos++;
    return { kind: 'group', open, body };
  }

  private parseQuantifier(): Quantifier | undefined {
    const c = this.peek();
    let min: number;
    let max: number;
    if (c === '*') {
      min = 0;
      max = Infinity;
      this.pos++;
    } else if (c === '+') {
      min = 1;
      max = Infinity;
      this.pos++;
    } else if (c === '?') {
      min = 0;
      max = 1;
      this.pos++;
    } else if (c === '{') {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(this.pattern.slice(this.pos));
      if (!m) return undefined; // literal '{' handled by parseAtom on the next iteration
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
      if (max < min) this.fail('illegal {x,y} with x > y');
      this.pos += m[0].length;
    } else {
      return undefined;
    }
    let lazy = false;
    if (this.peek() === '?') {
      lazy = true;
      this.pos++;
    }
    const next = this.peek();
    if (next === '*' || next === '+' || next === '?' || (next === '{' && /^\{\d+(,\d*)?\}/.test(this.pattern.slice(this.pos)))) {
      this.fail('nested quantifier');
    }
    return { min, max, lazy };
  }

  private parseEscape(): Node {
    const e = this.pattern[this.pos + 1];
    if (e === undefined) this.fail('trailing backslash');
    if (e === 'b' || e === 'B') {
      this.pos += 2;
      return { kind: 'boundary', negated: e === 'B' };
    }
    if (e === 'A') {
      this.pos += 2;
      return { kind: 'bos' };
    }
    const shorthand = shorthandSet(e);
    if (shorthand) {
      this.pos += 2;
      return { kind: 'set', set: shorthand };
    }
    return this.literal(this.parseCharEscape(false));
  }

  /** Parses an escape that denotes a single code unit; positioned at the backslash. */
  private parseCharEscape(inClass: boolean): number {
    const e = this.pattern[this.pos + 1];
    if (e === undefined) this.fail('trailing backslash');
    const simple: Record<string, number> = { n: 0x0a, r: 0x0d, t: 0x09, f: 0x0c, v: 0x0b, e: 0x1b, a: 0x07 };
    if (inClass && e === 'b') {
      this.pos += 2;
      return 0x08;
    }
    if (e in simple) {
      this.pos += 2;
      return simple[e]!;
    }
    if (e === 'u') {
      const hex = this.pattern.slice(this.pos + 2, this.pos + 6);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail('bad \\u escape');
      this.pos += 6;
      return parseInt(hex, 16);
    }
    if (e === 'x') {
      const hex = this.pattern.slice(this.pos + 2, this.pos + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) this.fail('bad \\x escape');
      this.pos += 4;
      return parseInt(hex, 16);
    }
    if (/[A-Za-z0-9_]/.test(e)) this.fail(`escape \\${e}`);
    this.pos += 2;
    return e.charCodeAt(0);
  }

  private parseClass(): CharSet {
    this.pos++; // [
    let negated = false;
    if (this.peek() === '^') {
      negated = true;
      this.pos++;
    }
    const explicit: [number, number][] = [];
    const shorthands: CharSet[] = [];
    let first = true;
    for (;;) {
      const c = this.peek();
      if (c === undefined) this.fail('unterminated character class');
      if (c === ']' && !first) {
        this.pos++;
        break;
      }
      first = false;
      if (c === '-' && this.peek(1) === '[') this.fail('character class subtraction');
      if (c === '\\') {
        const s = shorthandSet(this.pattern[this.pos + 1] ?? '');
        if (s) {
          this.pos += 2;
          if (this.peek() === '-' && this.peek(1) !== ']') this.fail('class shorthand used as range start');
          shorthands.push(s);
          continue;
        }
      }
      const lo = this.classChar();
      if (this.peek() === '-' && this.peek(1) !== ']' && this.peek(1) !== undefined) {
        if (this.peek(1) === '[') this.fail('character class subtraction');
        this.pos++; // -
        if (this.peek() === '\\' && shorthandSet(this.pattern[this.pos + 1] ?? '')) {
          this.fail('class shorthand used as range end');
        }
        const hi = this.classChar();
        if (hi < lo) this.fail('range in reverse order');
        explicit.push([lo, hi]);
      } else {
        explicit.push([lo, lo]);
      }
    }
    let set = normalize(explicit);
    if (this.ignoreCase) set = caseClose(set, this.pattern);
    set = union(set, ...shorthands);
    return negated ? complement(set) : set;
  }

  private classChar(): number {
    const c = this.pattern[this.pos]!;
    if (c === '\\') return this.parseCharEscape(true);
    if (c === '[' && this.peek(1) === ':') this.fail('POSIX-like class syntax');
    this.pos++;
    return c.charCodeAt(0);
  }
}

function shorthandSet(e: string): CharSet | undefined {
  switch (e) {
    case 'd':
      return DIGIT;
    case 'D':
      return complement(DIGIT);
    case 'w':
      return WORD;
    case 'W':
      return complement(WORD);
    case 's':
      return SPACE;
    case 'S':
      return complement(SPACE);
    default:
      return undefined;
  }
}

const CASE_EXTRAS = new Map<number, number[]>();
for (const [from, to] of DOTNET_IGNORECASE_EXTRAS) {
  const list = CASE_EXTRAS.get(from) ?? [];
  list.push(to);
  CASE_EXTRAS.set(from, list);
}

/**
 * Adds .NET IgnoreCase equivalents to a set of explicitly listed characters.
 * Only ASCII pattern characters are supported (that is all Shroud uses); a cased
 * non-ASCII character throws, because its .NET equivalence class was not extracted.
 */
function caseClose(set: CharSet, pattern: string): CharSet {
  const extra: [number, number][] = [];
  for (const [lo, hi] of set) {
    for (let c = lo; c <= hi; c++) {
      if (c < 0x80) {
        const ch = String.fromCharCode(c);
        const lower = ch.toLowerCase().charCodeAt(0);
        const upper = ch.toUpperCase().charCodeAt(0);
        extra.push([lower, lower], [upper, upper]);
        for (const e of CASE_EXTRAS.get(c) ?? []) extra.push([e, e]);
      } else {
        const ch = String.fromCharCode(c);
        if (ch.toLowerCase() !== ch.toUpperCase()) {
          throw new UnsupportedRegexError(pattern, -1, `IgnoreCase with non-ASCII cased character U+${hex4(c)}`);
        }
      }
    }
  }
  return union(set, extra);
}

function hex4(code: number): string {
  return code.toString(16).toUpperCase().padStart(4, '0');
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

function classAtom(code: number): string {
  if ((code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
    return String.fromCharCode(code);
  }
  return `\\u${hex4(code)}`;
}

function emitClass(set: CharSet): string {
  if (set.length === 0) return '[]';
  return '[' + set.map(([lo, hi]) => (lo === hi ? classAtom(lo) : `${classAtom(lo)}-${classAtom(hi)}`)).join('') + ']';
}

const SYNTAX_CHARS = new Set('\\^$.*+?()[]{}|/');

function emitLiteral(code: number): string {
  if (code >= 0x20 && code <= 0x7e) {
    const ch = String.fromCharCode(code);
    return SYNTAX_CHARS.has(ch) ? `\\${ch}` : ch;
  }
  return `\\u${hex4(code)}`;
}

function emitSet(set: CharSet): string {
  return size(set) === 1 ? emitLiteral(set[0]![0]) : emitClass(set);
}

const W = emitClass(BOUNDARY_WORD);

function isZeroWidth(item: Item): boolean {
  const n = item.node;
  return n.kind === 'bol' || n.kind === 'bos' || n.kind === 'eol' || n.kind === 'boundary' || (n.kind === 'group' && n.open !== '(' && n.open !== '(?:');
}

/**
 * FIRST/LAST-set analysis. `set` is a superset of the code units that can be consumed
 * first (or last) by the items; `nonEmpty` says the items always consume at least one
 * code unit. `set` is undefined when it cannot be determined.
 */
interface EdgeInfo {
  readonly set: CharSet | undefined;
  readonly nonEmpty: boolean;
}

function itemEdge(item: Item, first: boolean): EdgeInfo {
  const min = item.quantifier?.min ?? 1;
  const n = item.node;
  if (n.kind === 'set') return { set: n.set, nonEmpty: min >= 1 };
  if (n.kind === 'group' && (n.open === '(' || n.open === '(?:')) {
    const infos = n.body.map((alt) => itemsEdge(alt, first));
    if (infos.some((i) => i.set === undefined)) return { set: undefined, nonEmpty: false };
    return { set: union(...infos.map((i) => i.set!)), nonEmpty: min >= 1 && infos.every((i) => i.nonEmpty) };
  }
  return { set: undefined, nonEmpty: false };
}

function itemsEdge(items: Sequence, first: boolean): EdgeInfo {
  const ordered = first ? items : [...items].reverse();
  const sets: CharSet[] = [];
  for (const item of ordered) {
    if (isZeroWidth(item)) continue; // does not move the position
    const info = itemEdge(item, first);
    if (info.set === undefined) return info;
    sets.push(info.set);
    if (info.nonEmpty) return { set: union(...sets), nonEmpty: true };
  }
  return { set: union(...sets), nonEmpty: false };
}

/** FIRST set of a sequence that always consumes, else undefined. */
function sequenceEdgeSet(seq: Sequence, first: boolean): CharSet | undefined {
  const info = itemsEdge(seq, first);
  return info.nonEmpty ? info.set : undefined;
}

/**
 * A superset of the code unit on one side of position `index` in `seq`, when the
 * rest of the sequence on that side must consume it; undefined otherwise.
 */
function sideSet(seq: Sequence, index: number, before: boolean): CharSet | undefined {
  return before ? sequenceEdgeSet(seq.slice(0, index), false) : sequenceEdgeSet(seq.slice(index + 1), true);
}

function intersect(a: CharSet, b: CharSet): CharSet {
  return complement(union(complement(a), complement(b)));
}

function wordnessOf(set: CharSet | undefined): boolean | undefined {
  if (!set) return undefined;
  if (isSubset(set, BOUNDARY_WORD)) return true;
  if (isDisjoint(set, BOUNDARY_WORD)) return false;
  return undefined;
}

function emitBoundary(negated: boolean, prevSet: CharSet | undefined, nextSet: CharSet | undefined): string {
  // .NET: boundary at i  <=>  isWord(text[i-1]) != isWord(text[i]), out of range = false.
  const prev = wordnessOf(prevSet);
  const next = wordnessOf(nextSet);
  if (prev === undefined && next === undefined && nextSet) {
    // The next code unit is known to come from a mixed set: split it into its word and
    // non-word parts so each branch needs a single lookbehind (and starts with a cheap
    // lookahead that V8 can use as a first-character filter).
    const word = emitClass(intersect(nextSet, BOUNDARY_WORD));
    const nonWord = emitClass(intersect(nextSet, complement(BOUNDARY_WORD)));
    return negated
      ? `(?:(?=${word})(?<=${W})|(?=${nonWord})(?<!${W}))`
      : `(?:(?=${word})(?<!${W})|(?=${nonWord})(?<=${W}))`;
  }
  if (prev === undefined && next === undefined && prevSet) {
    const word = emitClass(intersect(prevSet, BOUNDARY_WORD));
    const nonWord = emitClass(intersect(prevSet, complement(BOUNDARY_WORD)));
    return negated
      ? `(?:(?<=${word})(?=${W})|(?<=${nonWord})(?!${W}))`
      : `(?:(?<=${word})(?!${W})|(?<=${nonWord})(?=${W}))`;
  }
  if (prev !== undefined && next !== undefined) {
    const isBoundary = prev !== next;
    return isBoundary !== negated ? '(?:)' : '(?!)';
  }
  if (prev !== undefined) {
    const nextMustBeWord = negated ? prev : !prev;
    return nextMustBeWord ? `(?=${W})` : `(?!${W})`;
  }
  if (next !== undefined) {
    const prevMustBeWord = negated ? next : !next;
    return prevMustBeWord ? `(?<=${W})` : `(?<!${W})`;
  }
  return negated ? `(?:(?<=${W})(?=${W})|(?<!${W})(?!${W}))` : `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`;
}

function emitQuantifier(q: Quantifier | undefined): string {
  if (!q) return '';
  let s: string;
  if (q.min === 0 && q.max === Infinity) s = '*';
  else if (q.min === 1 && q.max === Infinity) s = '+';
  else if (q.min === 0 && q.max === 1) s = '?';
  else if (q.max === Infinity) s = `{${q.min},}`;
  else if (q.min === q.max) s = `{${q.min}}`;
  else s = `{${q.min},${q.max}}`;
  return q.lazy ? s + '?' : s;
}

function emitSequence(seq: Sequence, multiline: boolean): string {
  let out = '';
  for (let i = 0; i < seq.length; i++) {
    const item = seq[i]!;
    const node = item.node;
    switch (node.kind) {
      case 'set':
        out += emitSet(node.set) + emitQuantifier(item.quantifier);
        break;
      case 'group': {
        const body = node.body.map((s) => emitSequence(s, multiline)).join('|');
        out += node.open + body + ')' + emitQuantifier(item.quantifier);
        break;
      }
      case 'bol':
        // Multiline: start of input or just after \n. Otherwise: start of input.
        out += multiline ? '(?<![^\\n])' : '^';
        break;
      case 'bos':
        // \A: start of input in every mode (the output RegExp has no `m` flag).
        out += '^';
        break;
      case 'eol':
        // Multiline: end of input or just before \n. Otherwise: end, or before a final \n.
        out += multiline ? '(?![^\\n])' : '(?=\\n?$)';
        break;
      case 'boundary':
        out += emitBoundary(node.negated, sideSet(seq, i, true), sideSet(seq, i, false));
        break;
    }
  }
  return out;
}

/** Returns the JavaScript source equivalent to a .NET pattern (no flags needed besides `g`). */
export function translateDotnetPattern(pattern: string, options: DotnetRegexOptions = {}): string {
  const parser = new Parser(pattern, options);
  const ast = parser.parse();
  const multiline = options.multiline ?? false;
  const body = ast.map((s) => emitSequence(s, multiline)).join('|');
  // When every match must start by consuming a code unit from a known set, say so up
  // front. This does not change what matches; it lets V8 reject start positions with a
  // one-character test before evaluating leading lookbehinds.
  const firstSets = ast.map((s) => sequenceEdgeSet(s, true));
  if (firstSets.every((s) => s !== undefined) && startsWithLookaround(ast)) {
    return `(?=${emitClass(union(...(firstSets as CharSet[])))})(?:${body})`;
  }
  return body;
}

function startsWithLookaround(ast: Alternation): boolean {
  return ast.some((seq) => seq[0] !== undefined && isZeroWidth(seq[0]));
}

/**
 * Compiles a .NET-syntax pattern into a JavaScript RegExp with .NET 8 matching
 * semantics on UTF-16 code units. See the module comment for the supported subset.
 * The RegExp has no flags (so it carries no lastIndex state); iterate matches with
 * `text.matchAll(new RegExp(re, "g"))`, or let SensitivityScanner do it.
 */
export function dotnetRegex(pattern: string, options: DotnetRegexOptions = {}): RegExp {
  return new RegExp(translateDotnetPattern(pattern, options));
}

/** True when `code` is a .NET word character for \b purposes. Exposed for tests. */
export function isDotnetBoundaryWordChar(code: number): boolean {
  return contains(BOUNDARY_WORD, code);
}
