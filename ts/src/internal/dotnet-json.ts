/**
 * A JSON writer that reproduces System.Text.Json output for the shapes Shroud writes
 * (JsonSerializerOptions { WriteIndented = true }, default JavaScriptEncoder):
 *
 *  - two-space indentation, `"key": value`, empty containers as `[]` / `{}`;
 *  - new lines are Environment.NewLine (CRLF on Windows, LF elsewhere) - .NET 8 has
 *    no option to change this, so the TS port uses os.EOL to match;
 *  - escaping: printable ASCII is written raw except `" & ' + < > \` and backtick;
 *    \b \t \n \f \r use short escapes, backslash is `\\`, everything else (other
 *    controls, DEL and all non-ASCII) is `\uXXXX` with upper-case hex; a lone
 *    surrogate is written as the escape of U+FFFD; a valid surrogate pair as two escapes;
 *  - doubles use the .NET shortest round-trip format (see formatDouble).
 *
 * Plain objects model C# POCOs: properties whose value is null or undefined are
 * omitted (JsonIgnoreCondition.WhenWritingNull). Maps model C# dictionaries and are
 * written in insertion order with every entry kept.
 */
import { EOL } from 'node:os';
import { formatDouble } from './dotnet-format.js';

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly JsonValue[]
  | ReadonlyMap<string, JsonValue>
  | { readonly [key: string]: JsonValue };

const SHORT_ESCAPES: Readonly<Record<number, string>> = {
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x5c: '\\\\',
};

const HTML_SENSITIVE = new Set([0x22, 0x26, 0x27, 0x2b, 0x3c, 0x3e, 0x60]);

function u(code: number): string {
  return '\\u' + code.toString(16).toUpperCase().padStart(4, '0');
}

export function escapeJsonString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const short = SHORT_ESCAPES[c];
    if (short !== undefined) {
      out += short;
    } else if (c >= 0x20 && c <= 0x7e && !HTML_SENSITIVE.has(c)) {
      out += value[i];
    } else if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += u(c) + u(next);
        i++;
      } else {
        out += u(0xfffd);
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      out += u(0xfffd);
    } else {
      out += u(c);
    }
  }
  return out + '"';
}

function isMap(value: unknown): value is ReadonlyMap<string, JsonValue> {
  return value instanceof Map;
}

function write(value: JsonValue, indent: string, newline: string): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return escapeJsonString(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RangeError(`.NET number values cannot be written as JSON: ${value}`);
    }
    return formatDouble(value);
  }
  const inner = indent + '  ';
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = (value as readonly JsonValue[]).map((v) => inner + write(v, inner, newline));
    return '[' + newline + items.join(',' + newline) + newline + indent + ']';
  }
  const entries: [string, JsonValue][] = isMap(value)
    ? [...value.entries()]
    : Object.entries(value as { readonly [key: string]: JsonValue }).filter(([, v]) => v !== null && v !== undefined);
  if (entries.length === 0) return '{}';
  const items = entries.map(([k, v]) => `${inner}${escapeJsonString(k)}: ${write(v, inner, newline)}`);
  return '{' + newline + items.join(',' + newline) + newline + indent + '}';
}

/** Serializes like `JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true })`. */
export function serializeIndented(value: JsonValue, newline?: string): string {
  return write(value, '', newline ?? EOL);
}

// ---------------------------------------------------------------------------
// Reading with every property kept
// ---------------------------------------------------------------------------

/**
 * A parsed JSON value in which objects keep every property in document order,
 * duplicates included (JSON.parse keeps only the last value of a duplicate name, at
 * the position of the first). System.Text.Json reads a POCO property by property in
 * document order, so this is the shape needed to reproduce its precedence rules.
 */
export type JsonNode = null | boolean | number | string | JsonNode[] | JsonObject;

export class JsonObject {
  constructor(readonly properties: readonly (readonly [string, JsonNode])[]) {}
}

/**
 * Parses JSON text into JsonNodes. Validity, error messages and number/string decoding
 * are exactly JSON.parse's: the text is first validated by JSON.parse, and every scalar
 * token is decoded by JSON.parse too.
 */
export function parseJsonPreservingProperties(json: string): JsonNode {
  JSON.parse(json); // validates; throws the same SyntaxError as before
  let pos = 0;
  const ws = () => {
    while (pos < json.length && (json[pos] === ' ' || json[pos] === '\t' || json[pos] === '\n' || json[pos] === '\r')) pos++;
  };
  const stringToken = (): string => {
    const start = pos++;
    while (json[pos] !== '"') pos += json[pos] === '\\' ? 2 : 1;
    pos++;
    return JSON.parse(json.slice(start, pos)) as string;
  };
  const value = (): JsonNode => {
    ws();
    const c = json[pos];
    if (c === '{') {
      pos++;
      const props: [string, JsonNode][] = [];
      ws();
      if (json[pos] === '}') {
        pos++;
        return new JsonObject(props);
      }
      for (;;) {
        ws();
        const key = stringToken();
        ws();
        pos++; // :
        props.push([key, value()]);
        ws();
        if (json[pos++] === '}') return new JsonObject(props);
      }
    }
    if (c === '[') {
      pos++;
      const items: JsonNode[] = [];
      ws();
      if (json[pos] === ']') {
        pos++;
        return items;
      }
      for (;;) {
        items.push(value());
        ws();
        if (json[pos++] === ']') return items;
      }
    }
    if (c === '"') return stringToken();
    const start = pos;
    while (pos < json.length && !/[\s,\]}]/.test(json[pos]!)) pos++;
    return JSON.parse(json.slice(start, pos)) as JsonNode;
  };
  return value();
}
