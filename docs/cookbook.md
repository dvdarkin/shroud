# Shroud cookbook

Recipes for putting Shroud into a workflow. Each one uses the `shroud` command; the C# tool (`dotnet tool install --global LogMark.Shroud.Cli`) and the npm package (`npm install -g @logmark/shroud`) behave the same, so use whichever runtime you have.

The recipes rely on options added after 0.3.1: `scan -`, `scan --exit-code`, `scan --no-values`, `--config`, `SHROUD_PASSWORD` and `reveal --text`. Check `shroud help` lists them.

Three facts that every recipe depends on:

- **`scan --exit-code` exits 2** when a file has something Shroud would tokenize, 0 when it is clean, 1 on an error. Without the flag, `scan` only reports.
- **`scan` prints the values it found.** Add `--no-values` wherever the output goes to a log, a CI run or a model; it prints `<42 chars>` in place of the text.
- **`vault` is reversible, `mask` is not.** Only `vault` keeps the originals (encrypted). Use `vault` whenever you may need the values back.

Ready-to-copy files for the first two recipes are in [`examples/`](../examples).

## Contents

1. [Git pre-commit hook](#1-git-pre-commit-hook)
2. [Claude Code hooks](#2-claude-code-hooks)
3. [Reveal on demand, with the password from a secret store](#3-reveal-on-demand-with-the-password-from-a-secret-store)
4. [Round trip through a cloud model](#4-round-trip-through-a-cloud-model)
5. [CI gate for pull requests](#5-ci-gate-for-pull-requests)
6. [Sync and back up only the vault](#6-sync-and-back-up-only-the-vault)
7. [Give an agent the manifest](#7-give-an-agent-the-manifest)
8. [Library: mask before you store, scrub logs](#8-library-mask-before-you-store-scrub-logs)
9. [Calibrate before you trust](#9-calibrate-before-you-trust)
10. [Change the vault password](#10-change-the-vault-password)
11. [Vault on one machine, reveal on another](#11-vault-on-one-machine-reveal-on-another)

## 1. Git pre-commit hook

Refuse a commit when a staged file contains something Shroud would tokenize. The hook scans the staged content (`git show :file`), not the working tree, so it checks exactly what would be committed.

Save as `.git/hooks/pre-commit` and make it executable ([`examples/git/pre-commit`](../examples/git/pre-commit)):

```bash
#!/usr/bin/env bash
# Refuse a commit when a staged text file contains something Shroud would tokenize.
fail=0
while IFS= read -r -d '' file; do
  if ! report=$(git show ":$file" | shroud scan - --exit-code --no-values 2>&1); then
    printf 'shroud: %s\n%s\n' "$file" "$report" >&2
    fail=1
  fi
done < <(git diff --cached --name-only --diff-filter=ACMRT -z -- '*.md' '*.txt' '*.env' '*.json' '*.yml' '*.yaml')
if [ "$fail" -ne 0 ]; then
  echo "Commit refused. Remove the values, or bypass once with: git commit --no-verify" >&2
fi
exit "$fail"
```

Notes:

- The pathspec list at the end decides which files are scanned. Shroud reads any text file; keep binaries out of the list.
- `shroud.json` is read from the directory the hook runs in (the repository root). To pin one, add `--config path/to/shroud.json`.
- The default configuration is `paranoid`, which flags amounts and quantities as well as keys. For a code repository, `shroud init --preset dev` (no financial domain) is usually the right gate.
- An error from `shroud` itself (exit 1) also refuses the commit here, which is the safe direction for a gate.

## 2. Claude Code hooks

Two hooks, both in [`examples/claude-code/`](../examples/claude-code). Copy the two `.mjs` files to `.claude/hooks/` and merge `settings.json` into `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/shroud-prompt.mjs\"" }] }
    ],
    "PreToolUse": [
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/shroud-read.mjs\"" }] }
    ]
  }
}
```

**Prompt guard (`shroud-prompt.mjs`).** Scans each prompt before it is sent. If it contains a value Shroud would tokenize, the hook exits 2: Claude Code drops the prompt and shows you the report. The report is printed with `--no-values`, and for this event it is shown to you and not added to the model's context.

**Read guard (`shroud-read.mjs`).** Runs before every `Read`:

- If the file belongs to a vaulted directory (`notes/a/b.md` and `notes.shroud/public/a/b.md` exists), the hook rewrites the call so Claude reads the masked copy.
- Otherwise it scans the file. If it has sensitive values, the hook exits 2 and the read is refused; the reason goes to the model, so it is printed with `--no-values`.
- A clean file is read normally.

Both hooks were run in live Claude Code sessions (2.1.325, Windows, headless `claude -p`, with the C# and the TypeScript CLI) using made-up canary values. That run used the previous version of the scripts; the current ones (stdin for the read guard, fail-closed) were tested with simulated hook input only. In the redirect, refuse and clean cases the canary appeared nowhere in the session output or transcript. What that run showed about the prompt guard:

- A blocked prompt makes no API call at all (zero turns, zero tokens).
- Claude Code itself still keeps the text you typed: it echoes it back to you as "Original prompt: ..." and records it in the local session transcript under `~/.claude/projects/`. The guard keeps the value away from the model, not off your own disk.
- In headless mode the run ends with exit code 0 and the block message as its result.

Things to know:

- The hooks call `shroud` from `PATH`. Set `SHROUD_BIN` to use a specific executable.
- The read guard serves whatever masked copy exists. After editing a vaulted source file, run `shroud vault` again, or the model reads the old masked text.
- The guard covers the `Read` tool only. `Bash` (`cat notes/a.md`) and other tools are not intercepted (confirmed in the same live run: `cat` on an unvaulted file put the canary in front of the model); for a hard boundary, also deny the source directory in Claude Code's permission settings and point Claude at `notes.shroud/public`.
- Both hooks fail closed. Claude Code treats only exit 2 as blocking, so each hook turns every outcome other than a clean scan (Shroud not installed, a Shroud error, input it cannot parse) into exit 2 with a one-line reason. With Shroud missing, every prompt and every `Read` is refused until it is installed or `SHROUD_BIN` points at it.
- The read guard passes the file to Shroud on stdin (`scan -`), never as an argument, so a path with spaces or shell characters (`&`, `|`, `^`) cannot change the command that runs.

## 3. Reveal on demand, with the password from a secret store

`vault` and `reveal` take the password from `-p`, else from the `SHROUD_PASSWORD` environment variable, else from one line of piped stdin, else they prompt. `-p` puts the password into shell history and the process list, so prefer the other three.

Reveal into a temporary directory, look, and remove it on exit:

```bash
#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Any command that prints the password works here: pass, op read, secret-tool, security ...
pass show shroud/notes | shroud reveal notes.shroud -o "$tmp/notes"

${EDITOR:-less} "$tmp/notes/journal.md"
```

With an environment variable instead (PowerShell):

```powershell
$env:SHROUD_PASSWORD = <your secret store command>
shroud reveal notes.shroud -o "$env:TEMP\notes.revealed"
Remove-Item Env:SHROUD_PASSWORD
```

To look up single values without restoring any files, pipe the text through `reveal --text` (the password then has to come from `SHROUD_PASSWORD` or `-p`, because stdin carries the text):

```bash
export SHROUD_PASSWORD=$(pass show shroud/notes)
echo "[ADDR:3c604903] and [EMAIL:95aa254a]" | shroud reveal notes.shroud --text -
```

`reveal` never writes into the vault directory, and it warns when a masked copy was changed or added after vaulting.

## 4. Round trip through a cloud model

Let a model work on your notes without seeing the values, then put the values back into its answer.

```bash
# 1. Vault. notes/ stays untouched; notes.shroud/public/ is the copy to share.
shroud vault notes

# 2. Give the model notes.shroud/public/ (and manifest.json if useful), ask your question,
#    and save its answer. It will refer to values by token, e.g. [ADDR:3c604903].

# 3. Restore the tokens in the answer.
shroud reveal notes.shroud --text answer.md -o answer.revealed.md
```

`reveal --text` writes only the restored text to stdout (or to `-o`), so it also works in a pipe:

```bash
export SHROUD_PASSWORD=$(pass show shroud/notes)
some-llm-cli < prompt.txt | shroud reveal notes.shroud --text -
```

Limits worth knowing:

- Tokens are restored only when the model repeats them exactly, brackets included. Ask it to keep tokens verbatim. A token it mangled is left in place; a well-formed token that is not in the vault is reported on stderr.
- Token ids belong to one `vault` run. Running `vault` again creates new ids, so reveal an answer with the vault that produced the copies the model saw.
- The model sees everything Shroud did not detect. Do recipe 9 first.

## 5. CI gate for pull requests

Fail a pull request that adds sensitive values to text files. `--no-values` keeps them out of the build log.

```yaml
name: shroud
on: pull_request

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g @logmark/shroud
      - name: Scan changed text files
        run: |
          fail=0
          while IFS= read -r -d '' file; do
            shroud scan "$file" --exit-code --no-values || fail=1
          done < <(git diff --name-only --diff-filter=ACMRT -z "origin/${{ github.base_ref }}...HEAD" -- '*.md' '*.txt' '*.env' '*.json' '*.yml' '*.yaml')
          exit $fail
```

Commit a `shroud.json` at the repository root so CI and the pre-commit hook (recipe 1) agree on what counts. The scan step was run locally against a pull-request branch with a real `origin` (a file with a token fails the step, removing it passes, file names with spaces work). This repository's own CI runs the same diff range and loop on every pull request, with Shroud installed from the checkout (the `cookbook-gate` job in `.github/workflows/ci.yml`).

## 6. Sync and back up only the vault

Keep the source directory local and let the sync service, or a git remote, see only the vault output.

- Sync `notes.shroud/` (masked copies, `manifest.json`, `vault.shroud`). `vault.shroud` is safe to store remotely to the extent your password is strong: it is the only thing protecting the values.
- Never sync the source directory, anything `*.revealed`, or `.shroud/vault.key`.

`.gitignore` for a repository that holds vault output:

```gitignore
# Shroud: plaintext and local key material
*.revealed/
.shroud/
```

Each `vault` run creates new token ids, so every masked copy changes on every run, even when the source did not. In git that is a full rewrite of `public/` per run; vault when you have something to share, not on a timer.

## 7. Give an agent the manifest

`manifest.json` lists every token with its type, domain, files and occurrence count, and no values. An agent can answer structural questions from it without opening the vault.

```bash
node -e '
  const m = JSON.parse(require("fs").readFileSync("notes.shroud/manifest.json", "utf8"));
  for (const [id, t] of Object.entries(m.tokens))
    if (t.files.length > 1) console.log(id, t.domain, t.service, t.occurrences, t.files.join(", "));
'
```

prints the values that recur across files, by token:

```
ADDR:bee6779b onchain evm_address 12 trades.md, notes.md
```

The manifest does reveal structure: which files mention the same address, how many amounts a file has, and file names. If that is sensitive, share `public/` without it. [format.md](format.md) section 4 specifies the file.

## 8. Library: mask before you store, scrub logs

The library does the same thing as the CLI, in memory. Keep one `SpanMasker` (one key) for as long as tokens should stay comparable.

Scrub log lines (TypeScript):

```ts
import { randomBytes } from 'node:crypto';
import { SensitivityScanner, SpanMasker, configForPreset } from '@logmark/shroud';

const scanner = new SensitivityScanner(configForPreset('dev'));
const masker = new SpanMasker(randomBytes(32));

export const scrub = (line: string): string => masker.mask(line, scanner.scan(line)).maskedText;

scrub('login failed for bob@example.com with token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ');
// 'login failed for [EMAIL:95aa254a] with token [TOKEN:5b4612f5]'
```

Mask on the way out, restore on the way back, keeping the originals in memory (TypeScript):

```ts
import { restoreTokens } from '@logmark/shroud';

const masked = masker.mask(text, scanner.scan(text));
const tokens = new Map(masked.tokens.map((t) => [t.tokenId, t.originalValue]));

const answer = await askModel(masked.maskedText);      // the model sees tokens only
const restored = restoreTokens(answer, tokens).text;   // unknown tokens are left in place
```

The same in C#:

```csharp
using System.Security.Cryptography;
using Shroud.Detection;
using Shroud.Masking;
using Shroud.Models;
using Shroud.Vault;

var scanner = new SensitivityScanner(ShroudConfig.ForPreset("dev"));
var masker = new SpanMasker(RandomNumberGenerator.GetBytes(32));

var masked = masker.Mask(text, scanner.Scan(text));
var tokens = new Dictionary<string, string>();
foreach (var t in masked.Tokens) tokens[t.TokenId] = t.OriginalValue;

var answer = await AskModel(masked.MaskedText);
var restored = TokenRestorer.Restore(answer, tokens);
```

The token map holds the plaintext values. Keep it in memory, or encrypt it with `VaultEncryption` before it touches disk.

## 9. Calibrate before you trust

Detection is heuristic. Before a hook or a vault depends on it, look at what it finds in your own files.

```bash
shroud scan sample.md --verbose          # why each span was flagged, and its confidence
shroud scan sample.md --debug            # plus exclusion zones and overlap decisions
```

- Too many false positives: raise `threshold` in `shroud.json`, or pick a narrower preset (`shroud init --preset dev` drops the financial domain).
- Something was missed: check "Below threshold" in the report. A value listed there was seen but scored too low; lower the threshold or check which context words the pattern needs.
- Compare two configurations on the same file without moving files around:

```bash
shroud scan sample.md --config strict.json --exit-code; echo $?
shroud scan sample.md --config relaxed.json --exit-code; echo $?
```

YAML front matter and `file:` / `path:` metadata lines are not scanned at all; the README lists the exact rules.

## 10. Change the vault password

There is no rekey command. Reveal with the old password, vault again with the new one, and remove the plaintext:

```bash
shroud reveal notes.shroud -o /tmp/notes-plain           # old password
shroud vault /tmp/notes-plain -o notes.shroud            # new password, asked twice
rm -rf /tmp/notes-plain
```

If you still have the source directory, skip the reveal and just run `shroud vault notes` with the new password. Either way the token ids change, and a lost password cannot be recovered.

## 11. Vault on one machine, reveal on another

The two implementations write the same format, so the machine that reveals does not need the runtime that vaulted:

```bash
# Windows, .NET tool
shroud vault notes

# copy notes.shroud/ anywhere; on a machine with only Node:
npx @logmark/shroud reveal notes.shroud
```

This is checked in CI against the vaults in `conformance/`, in both directions.
