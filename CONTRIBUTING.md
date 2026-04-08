# Contributing

## Getting Started

```bash
git clone https://github.com/dvdarkin/shroud.git
cd shroud
dotnet build src
dotnet test src
```

Requires .NET 8 SDK.

## Adding a Detection Pattern

Patterns live in domain-specific files under `src/Shroud/Detection/`:

- `PatternLibrary.OnChain.cs` — crypto addresses, transaction hashes, correlation identifiers
- `PatternLibrary.Credentials.cs` — service-specific API keys and tokens
- `PatternLibrary.Secrets.cs` — PEM keys, JWTs, connection strings
- `PatternLibrary.Financial.cs` — amounts, market pairs, credit cards
- `PatternLibrary.Identity.cs` — SSNs, IBANs, IPs, emails

Each file has a header comment explaining the domain's confidence calibration and a template for adding new patterns. Open the relevant file — the instructions are inline.

Key concepts:
- **Structural patterns** (BaseConfidence >= 0.80): unique format, no context words needed
- **Contextual patterns** (BaseConfidence < 0.80): ambiguous format, needs nearby keywords to boost above the 0.70 default threshold
- Use `shroud scan <file> --debug` to see exactly how your pattern scores

## Running Tests

```bash
dotnet test src                                          # all tests
dotnet test src/Shroud.Tests.Unit                        # unit tests only
dotnet test src/Shroud.Tests.Integration                 # integration tests only
dotnet test src/Shroud.Tests.Unit --filter ContextScorer # specific test class
```

When adding patterns, add a test fixture in `ScannerFixtures.cs` or `FalsePositiveFixtures.cs` and a corresponding test method.

## Scope

The pattern library covers **general-purpose text patterns** — formats that appear across many services and contexts. Service-specific formatting quirks (e.g., a particular block explorer's copy-paste format that glues verbs to numbers) are out of scope. If your input has non-standard formatting, preprocess it into readable text before scanning.

The `SensitivityScanner` constructor accepts custom pattern lists, so service-specific patterns can be maintained separately and composed at runtime.

## Pull Requests

- One concern per PR
- Tests must pass
- New patterns need both a positive detection test and a false-positive consideration
