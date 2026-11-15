import { contains, normalize } from './internal/charset.js';
import { DOTNET_DIGIT } from './internal/unicode-tables.js';

const DIGITS = normalize(DOTNET_DIGIT);

/**
 * Luhn checksum over the digits of `input` (separators are skipped). Accepts 13-19
 * digits. Like the C# build, "digit" means any Unicode decimal digit (char.IsDigit)
 * and its value is taken as `code - '0'`; the credit-card patterns only ever pass
 * ASCII digits.
 */
export function isValidLuhn(input: string): boolean {
  const digits: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (contains(DIGITS, c)) digits.push(c - 0x30);
  }

  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i]!;
    if (alternate) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}
