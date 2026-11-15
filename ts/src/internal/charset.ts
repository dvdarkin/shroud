/**
 * Sets of UTF-16 code units as normalized, inclusive [lo, hi] ranges.
 * Used by the .NET regex translator to build explicit character classes.
 */
export type Range = readonly [number, number];
export type CharSet = readonly Range[];

export const MAX_CODE_UNIT = 0xffff;

export function normalize(ranges: readonly Range[]): CharSet {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out: [number, number][] = [];
  for (const [lo, hi] of sorted) {
    const last = out[out.length - 1];
    if (last && lo <= last[1] + 1) {
      if (hi > last[1]) last[1] = hi;
    } else {
      out.push([lo, hi]);
    }
  }
  return out;
}

export function single(code: number): CharSet {
  return [[code, code]];
}

export function union(...sets: readonly CharSet[]): CharSet {
  return normalize(sets.flat());
}

export function complement(set: CharSet): CharSet {
  const out: [number, number][] = [];
  let next = 0;
  for (const [lo, hi] of set) {
    if (lo > next) out.push([next, lo - 1]);
    next = hi + 1;
  }
  if (next <= MAX_CODE_UNIT) out.push([next, MAX_CODE_UNIT]);
  return out;
}

export function size(set: CharSet): number {
  return set.reduce((n, [lo, hi]) => n + hi - lo + 1, 0);
}

export function contains(set: CharSet, code: number): boolean {
  let lo = 0;
  let hi = set.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = set[mid]!;
    if (code < r[0]) hi = mid - 1;
    else if (code > r[1]) lo = mid + 1;
    else return true;
  }
  return false;
}

/** True when every code unit of `a` is in `b` (both normalized). */
export function isSubset(a: CharSet, b: CharSet): boolean {
  return a.every(([lo, hi]) => b.some(([blo, bhi]) => lo >= blo && hi <= bhi));
}

/** True when `a` and `b` share no code unit (both normalized). */
export function isDisjoint(a: CharSet, b: CharSet): boolean {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const [alo, ahi] = a[i]!;
    const [blo, bhi] = b[j]!;
    if (ahi < blo) i++;
    else if (bhi < alo) j++;
    else return false;
  }
  return true;
}
