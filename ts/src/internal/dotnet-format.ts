/**
 * Number formatting that reproduces .NET 8 output (invariant / English-style culture:
 * '.' decimal separator, no group separators).
 */

/**
 * .NET `value.ToString("F<digits>")`.
 *
 * .NET Core 3.0+ formats from the exact binary value of the double and breaks exact
 * ties toward the even digit (0.125 -> "0.12", 0.375 -> "0.38"). JS `toFixed` breaks
 * ties away from zero, so this is computed exactly with BigInt instead.
 */
export function formatFixed(value: number, digits: number): string {
  if (Number.isNaN(value)) return 'NaN';
  if (value === Infinity) return '∞';
  if (value === -Infinity) return '-∞';
  const negative = value < 0 || Object.is(value, -0);
  const { mantissa, exponent } = decompose(Math.abs(value));
  // |value| * 10^digits = mantissa * 10^digits * 2^exponent = n / d
  let n = mantissa * 10n ** BigInt(digits);
  let d = 1n;
  if (exponent >= 0) n <<= BigInt(exponent);
  else d <<= BigInt(-exponent);
  let q = n / d;
  const twiceRemainder = (n % d) * 2n;
  if (twiceRemainder > d || (twiceRemainder === d && q % 2n === 1n)) q += 1n;
  let text = q.toString().padStart(digits + 1, '0');
  if (digits > 0) text = `${text.slice(0, -digits)}.${text.slice(-digits)}`;
  // .NET keeps the minus sign even when the rounded value is zero ("-0.00").
  return negative ? `-${text}` : text;
}

/** Splits a finite non-negative double into mantissa * 2^exponent exactly. */
function decompose(value: number): { mantissa: bigint; exponent: number } {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  const biased = Number((bits >> 52n) & 0x7ffn);
  const fraction = bits & 0xfffffffffffffn;
  return biased === 0
    ? { mantissa: fraction, exponent: -1074 }
    : { mantissa: fraction | (1n << 52n), exponent: biased - 1075 };
}

/**
 * .NET `double.ToString()` (Core 3.0+): shortest round-trippable digits, scientific
 * notation when the decimal exponent is >= 17 or < -4, exponent written as E+XX / E-XX.
 * System.Text.Json writes doubles the same way.
 */
export function formatDouble(value: number): string {
  if (Number.isNaN(value)) return 'NaN';
  if (value === Infinity) return '∞';
  if (value === -Infinity) return '-∞';
  if (value === 0) return Object.is(value, -0) ? '-0' : '0';
  const negative = value < 0;
  const [mantissa, exponentText] = Math.abs(value).toExponential().split('e') as [string, string];
  const digits = mantissa.replace('.', '');
  const exponent = Number(exponentText);
  const scale = exponent + 1; // value = 0.<digits> * 10^scale
  let body: string;
  if (exponent >= 17 || exponent < -4) {
    const frac = digits.length > 1 ? `.${digits.slice(1)}` : '';
    const sign = exponent < 0 ? '-' : '+';
    body = `${digits[0]}${frac}E${sign}${String(Math.abs(exponent)).padStart(2, '0')}`;
  } else if (scale <= 0) {
    body = `0.${'0'.repeat(-scale)}${digits}`;
  } else if (scale >= digits.length) {
    body = digits + '0'.repeat(scale - digits.length);
  } else {
    body = `${digits.slice(0, scale)}.${digits.slice(scale)}`;
  }
  return negative ? `-${body}` : body;
}

/** .NET composite-format alignment: `{value,width}` (right) and `{value,-width}` (left). */
export function align(text: string, width: number): string {
  return width < 0 ? text.padEnd(-width) : text.padStart(width);
}

/** .NET `bool.ToString()`. */
export function formatBool(value: boolean): string {
  return value ? 'True' : 'False';
}
