# @logmark/shroud

TypeScript port of [Shroud](../README.md) 0.3.0: sensitive data detection and masking for
markdown files. Same five detection domains, same patterns, same confidence scoring, same
CLI, same `shroud.json`, and the same vault format. A vault written by the C# build
reveals with this one and vice versa ([docs/format.md](../docs/format.md) specifies every byte).

Zero runtime dependencies (only `node:` built-ins). Node.js 20 or later. ESM.

## CLI

```bash
# Not yet published to npm. Until it is, build and install from this folder:
npm ci && npm run build && npm install -g .


shroud scan notes.md --verbose     # detection report with scoring breakdown
shroud mask notes.md -o out.md     # replace spans with [TYPE:xxxxxxxx] tokens
shroud vault ./notes               # masked copy + encrypted registry in notes.shroud/
shroud reveal notes.shroud         # decrypt and restore into notes.revealed/
shroud init --preset financial     # write shroud.json
```

Commands, flags, exit codes and output text are the C# CLI's, byte for byte (including
the platform line ending). Run `shroud help` for the full usage text. `mask -o` takes
exactly one input (several inputs, also after glob expansion, are an error before any
config or key file is touched), and `init --preset` accepts only `paranoid`,
`financial` or `dev` (case-sensitive).

`shroud.json` property names are matched case-insensitively at every level, like the
C# loader (System.Text.Json `PropertyNameCaseInsensitive`): `"onchain"`, `"OnChain"`
and `"ONCHAIN"` all configure `onChain`, and a repeated name wins with its last
occurrence. [docs/format.md](../docs/format.md) section 8 has the exact rules.

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

`build` throws `TokenCollisionException` (with `tokenId`) when two different values map
to the same token id in one run, before anything is written; the CLI reports it as a
one-line error and exits 1. `manifest.json` records only the source directory's name,
never its absolute path.

A match is ignored when it lies fully inside an exclusion zone: YAML front matter (only
a `---` block that starts at offset 0, up to the next `---` line), a file-path metadata
line (`file:`, `path:`, `source_file:` or `attachment:` at the start of a line or right
after a space, a tab or `(`, with its value on the same line; a key glued to any other
character, such as `my-file:`, `|file:` or a combining mark, is ordinary text) or a date
or time. A financial amount, quantity or price must also contain a decimal digit, so
separator-only text such as a lone `,` is never a span. Detection does not depend on the
process locale (the C# build uses `RegexOptions.CultureInvariant` throughout).

Custom patterns can be written in .NET regex syntax and compiled with `dotnetRegex`,
which gives them the same matching semantics as the built-in ones.

## How parity is achieved

The C# patterns are kept verbatim and translated at load time by
`src/internal/dotnet-regex.ts`, because JavaScript and .NET disagree on constructs that
look identical: `\d`, `\w`, `\s` and `\b` are Unicode-aware in .NET (with different
tables than JS), `.` and `$` treat `\r` differently, and .NET IgnoreCase has its own
case-equivalence table (culture-invariant, as the C# build uses everywhere: `k` matches
the Kelvin sign, `i` does not match `İ`). The translator emits explicit UTF-16
code-unit classes extracted from the .NET 8 engine and uses no regex flags, so match
offsets line up with .NET exactly. Unsupported constructs (including every `\p{..}`
Unicode category) throw.

Number formatting (`F2` breaks exact ties to even, `ToString` uses `E+XX` exponents),
System.Text.Json escaping, BOM handling and Win32 wildcards are reproduced the same way,
each in `src/internal/`. Vault files are processed in ordinal (UTF-16 code unit) order
of their relative path, which needs no emulation.

## Known differences from the C# build

- Console encoding: Node writes UTF-8. The C# CLI on Windows writes through the console
  code page, so non-ASCII text in its output can appear as `?` unless the console uses
  UTF-8 (`chcp 65001`). Detection results are identical either way.
- Unhandled errors print one `Unhandled exception. <Type>: <message>` line and exit with
  the .NET host's exit code, but the message text is approximate and there is no .NET
  stack trace.
- `created` timestamps have millisecond resolution (`.fff0000Z`).
- `scanWithDiagnostics` is public (it is `internal` in C#), and so is the optional
  `maskingKey` argument of `new VaultBuilder(scanner, maskingKey)` (an `internal`
  constructor, a test seam, in C#). The other C# internals the tests use
  (`SourceDirectoryName`, `PresetNames`, the CLI's `VaultMaskingKeyOverride`) are module
  exports that the package entry point does not re-export (`sourceDirectoryName`,
  `PRESET_NAMES`, and `setVaultMaskingKeyOverride` / `setCliIo` in `src/cli-program.ts`,
  the module the `shroud` binary runs).
- Windows paths ending in `.` or a space (`shroud vault notes.`): .NET applies Win32 path
  normalization and opens `notes`; Node's file system calls do not, so the TS CLI prints
  `Directory not found`. (The manifest `source` rule applies the Win32 trimming in both.)

## Development

```bash
npm install
npm test                         # tsc, then the node:test suite
npx tsc --noEmit                 # typecheck only
node tools/differential.mjs      # needs .NET 8: diff every match against the C# scanner
```

- `tools/dotnet-probe/` is a small .NET program that reports ground truth from the C#
  library: character classes, culture-invariant case tables (checked to be the same
  when built under tr-TR), JSON escaping, number formatting, full scan
  diagnostics, interop vectors, `shroud.json` loading (`configs`) and manifest `source`
  resolution (`paths`). `tools/differential.mjs` rebuilds it on every run.
- `tools/generate-unicode-tables.mjs` regenerates `src/internal/unicode-tables.ts` from
  the probe's `classes` output.
- `tools/extract-csharp-fixtures.mjs` regenerates the test fixtures from the C# test
  fixture files, so both suites run on identical text.

Tests mirror the C# test projects one file per class (`test/unit`, `test/integration`),
plus `dotnet-interop.test.ts` (vectors produced by the C# build) and
`dotnet-compat.test.ts` (the .NET-vs-JS decisions above).

## License

Apache-2.0
