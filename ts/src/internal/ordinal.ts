/**
 * .NET StringComparison.OrdinalIgnoreCase helpers.
 *
 * OrdinalIgnoreCase compares UTF-16 code units after simple (1:1) upper-casing; it
 * never expands characters (no "ß" == "ss") and, verified against .NET 8 for every
 * code unit, a non-ASCII code unit never equals an ASCII one (U+0130, U+0131, U+017F
 * and U+212A do not match i/I/s/k). JS toLowerCase/toUpperCase can change string
 * length and would break that, so the ASCII path folds only A-Z.
 */

const NON_ASCII = /[^\u0000-\u007f]/;

function foldAscii(s: string): string {
  // For pure-ASCII strings toLowerCase maps exactly A-Z; otherwise fold A-Z runs only.
  return NON_ASCII.test(s) ? s.replace(/[A-Z]+/g, (run) => run.toLowerCase()) : s.toLowerCase();
}

/** Per-code-unit simple upper-case mapping; length preserving. */
function foldSimple(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    const up = ch.toUpperCase();
    out += up.length === 1 ? up : ch;
  }
  return out;
}

interface Needle {
  readonly ascii: boolean;
  readonly folded: string;
}

const needles = new Map<string, Needle>();

function needleOf(text: string): Needle {
  let n = needles.get(text);
  if (!n) {
    const ascii = !NON_ASCII.test(text);
    n = { ascii, folded: ascii ? foldAscii(text) : foldSimple(text) };
    if (needles.size < 4096) needles.set(text, n);
  }
  return n;
}

/**
 * Returns a predicate equivalent to `needle => containsOrdinalIgnoreCase(haystack, needle)`
 * that folds the haystack only once.
 */
export function ordinalIgnoreCaseSearcher(haystack: string): (needle: string) => boolean {
  let ascii: string | undefined;
  let simple: string | undefined;
  return (needle) => {
    if (needle.length === 0) return true;
    const n = needleOf(needle);
    // Non-ASCII needles are not used by Shroud; that path approximates .NET's
    // invariant simple case mapping and has not been verified against .NET.
    return n.ascii ? (ascii ??= foldAscii(haystack)).includes(n.folded) : (simple ??= foldSimple(haystack)).includes(n.folded);
  };
}

/** `haystack.Contains(needle, StringComparison.OrdinalIgnoreCase)`. */
export function containsOrdinalIgnoreCase(haystack: string, needle: string): boolean {
  return ordinalIgnoreCaseSearcher(haystack)(needle);
}

/**
 * `string.Equals(a, b, StringComparison.OrdinalIgnoreCase)`. ASCII letters fold only to
 * ASCII letters (verified, see above); other code units compare after a simple 1:1
 * upper-case mapping, which approximates .NET's invariant mapping (Shroud only compares
 * against ASCII names, where the approximation never decides the result).
 */
export function equalsOrdinalIgnoreCase(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x === y) continue;
    if (x < 0x80 || y < 0x80) {
      if (x >= 0x80 || y >= 0x80) return false;
      if ((x | 0x20) !== (y | 0x20) || (x | 0x20) < 0x61 || (x | 0x20) > 0x7a) return false;
      continue;
    }
    if (foldSimple(a[i]!) !== foldSimple(b[i]!)) return false;
  }
  return true;
}
