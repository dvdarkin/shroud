# @logmark/shroud

TypeScript port of [Shroud](../README.md) 0.2.0: sensitive data detection and masking for
markdown files. Same five detection domains, same patterns, same confidence scoring, same
CLI, same `shroud.json`, and the same vault format. A vault written by the C# build
reveals with this one and vice versa ([FORMAT.md](FORMAT.md) specifies every byte).

Zero runtime dependencies (only `node:` built-ins). Node.js 20 or later. ESM.

## CLI

```bash
npm install -g @logmark/shroud     # or: npx @logmark/shroud <command>

shroud scan notes.md --verbose     # detection report with scoring breakdown
shroud mask notes.md -o out.md     # replace spans with [TYPE:xxxxxxxx] tokens
shroud vault ./notes               # masked copy + encrypted registry in notes.shroud/
shroud reveal notes.shroud         # decrypt and restore into notes.revealed/
shroud init --preset financial     # write shroud.json
```

Commands, flags, exit codes and output text are the C# CLI's, byte for byte (including
the platform line ending). Run `shroud help` for the full usage text.

## Library

```ts
import { SensitivityScanner, SpanMasker, VaultBuilder, configForPreset } from '@logmark/shroud';

const scanner = new SensitivityScanner(configForPreset('financial'));
const result = scanner.scan(text);           // spans: start/end in UTF-16 code units

const masked = new SpanMasker(key).mask(text, result);
// masked.maskedText is safe to persist; masked.tokens maps token ids to values

const builder = new VaultBuilder(scanner);
builder.writeOutput(builder.build('./notes'), './notes.shroud', password);
```

Custom patterns can be written in .NET regex syntax and compiled with `dotnetRegex`,
which gives them the same matching semantics as the built-in ones.

## How parity is achieved

The C# patterns are kept verbatim and translated at load time by
`src/internal/dotnet-regex.ts`, because JavaScript and .NET disagree on constructs that
look identical: `\d`, `\w`, `\s` and `\b` are Unicode-aware in .NET (with different
tables than JS), `.` and `$` treat `\r` differently, and .NET IgnoreCase has its own
case-equivalence table (`k` matches the Kelvin sign). The translator emits explicit
UTF-16 code-unit classes extracted from the .NET 8 engine and uses no regex flags, so
match offsets line up with .NET exactly. Unsupported constructs throw.

Number formatting (`F2` breaks exact ties to even, `ToString` uses `E+XX` exponents),
System.Text.Json escaping, BOM handling, culture-sensitive file ordering and Win32
wildcards are reproduced the same way, each in `src/internal/`.

## Known differences from the C# build

- Console encoding: Node writes UTF-8. The C# CLI on Windows writes through the console
  code page, so non-ASCII text in its output can appear as `?` unless the console uses
  UTF-8 (`chcp 65001`). Detection results are identical either way.
- Unhandled errors print one `Unhandled exception. <Type>: <message>` line and exit with
  the .NET host's exit code, but the message text is approximate and there is no .NET
  stack trace.
- `created` timestamps have millisecond resolution (`.fff0000Z`).
- .NET picks its IgnoreCase table from the current culture; the port uses the
  non-Turkish table (under a Turkish culture .NET would match `i` differently).
- `scanWithDiagnostics` is public (it is `internal` in C#).

## Development

```bash
npm install
npm test                         # tsc, then the node:test suite
npx tsc --noEmit                 # typecheck only
node tools/differential.mjs      # needs .NET 8: diff every match against the C# scanner
```

- `tools/dotnet-probe/` is a small .NET program that reports ground truth from the C#
  library: character classes, case tables, JSON escaping, number formatting, full scan
  diagnostics and interop vectors.
- `tools/generate-unicode-tables.mjs` regenerates `src/internal/unicode-tables.ts` from
  the probe's `classes` output.
- `tools/extract-csharp-fixtures.mjs` regenerates the test fixtures from the C# test
  fixture files, so both suites run on identical text.

Tests mirror the C# test projects one file per class (`test/unit`, `test/integration`),
plus `dotnet-interop.test.ts` (vectors produced by the C# build) and
`dotnet-compat.test.ts` (the .NET-vs-JS decisions above).

## License

Apache-2.0
