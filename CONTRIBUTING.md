# Contributing

Shroud has two implementations that must behave identically: C# (`src/`) and TypeScript (`ts/`). A shared corpus (`conformance/`) holds them together. Contributions are accepted under the repository's Apache-2.0 license; there is nothing to sign.

## Getting Started

```bash
git clone https://github.com/dvdarkin/shroud.git
cd shroud

# C# (requires the .NET 8 SDK)
dotnet build src
dotnet test src

# TypeScript (requires Node 20 or later)
cd ts
npm ci
npm test
cd ..

# The port against the corpus generated from the C# build
node conformance/run-ts.mjs
```

## The one rule: both implementations, one corpus

A change to behaviour (what is detected, how it is scored, masked output, the vault or manifest, CLI output or exit codes) lands in **both** implementations in the same pull request:

1. Change the C# implementation, with a test that fails before the change.
2. Add or adjust inputs under `conformance/inputs/` so the change is visible, then regenerate the corpus:
   ```bash
   dotnet run --project conformance/Generator              # rewrites conformance/expected/
   dotnet run --project conformance/Generator -- --vaults  # also rewrites the vault fixtures
   ```
3. Review the diff of `conformance/expected/`. Every changed file should be explained by your change; anything else is a regression.
4. Make the same change in `ts/` and port the new tests, until `node conformance/run-ts.mjs` reports zero failures.
5. For regex or scoring changes, also run the differential test, which compares the two scanners on a few thousand generated inputs:
   ```bash
   cd ts && npm run build && node tools/differential.mjs
   ```

CI runs all of this on Windows and Linux and fails if the committed corpus does not match what the C# source generates.

The file format (vault container, token derivation, manifest, `shroud.json`) is specified in [docs/format.md](docs/format.md). A format change needs a spec change in the same pull request.

## Adding a Detection Pattern

Patterns live in domain-specific files under `src/Shroud/Detection/`, mirrored in `ts/src/pattern-library.ts`:

- `PatternLibrary.OnChain.cs` - crypto addresses, transaction hashes, correlation identifiers
- `PatternLibrary.Credentials.cs` - service-specific API keys and tokens
- `PatternLibrary.Secrets.cs` - PEM keys, JWTs, connection strings
- `PatternLibrary.Financial.cs` - amounts, market pairs, credit cards
- `PatternLibrary.Identity.cs` - SSNs, IBANs, IPs, emails

Each file has a header comment explaining the domain's confidence calibration and a template for adding new patterns.

Key concepts:
- **Structural patterns** (BaseConfidence >= 0.80): unique format, no context words needed
- **Contextual patterns** (BaseConfidence < 0.80): ambiguous format, needs nearby keywords to boost above the 0.70 default threshold
- Use `shroud scan <file> --debug` to see exactly how your pattern scores

Write the regex in .NET syntax. The TypeScript port keeps the same pattern source and translates it at load time, reproducing .NET's Unicode-aware `\d`, `\w`, `\b` and case folding. Constructs the translator does not support (atomic groups, possessive quantifiers, most `\p{..}` categories) fail loudly when the port loads, so stay with plain classes, lookarounds and groups.

When in doubt, prefer scanning more over scanning less: an exclusion that hides text from the scanner is a leak when it is wrong.

## Running Tests

```bash
dotnet test src                                          # all C# tests
dotnet test src/Shroud.Tests.Unit --filter ContextScorer # one C# test class
cd ts && npm test                                        # all TypeScript tests
```

When adding patterns, add a test fixture in `ScannerFixtures.cs` or `FalsePositiveFixtures.cs` and a corresponding test method, then port both to `ts/test/`.

## Scope

The pattern library covers **general-purpose text patterns**: formats that appear across many services and contexts. Service-specific formatting quirks (for example a particular block explorer's copy-paste format that glues verbs to numbers) are out of scope. If your input has non-standard formatting, preprocess it into readable text before scanning.

The `SensitivityScanner` constructor accepts custom pattern lists in both implementations, so service-specific patterns can be maintained separately and composed at runtime.

## Pull Requests

- One concern per PR
- Tests pass in both implementations and the conformance check is green
- New patterns need both a positive detection test and a false-positive consideration
