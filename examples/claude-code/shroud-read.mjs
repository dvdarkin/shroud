#!/usr/bin/env node
// PreToolUse hook for Read: serve the masked copy when one exists, otherwise refuse a
// file that contains values Shroud would tokenize. Fails closed: if the check cannot run,
// the read is refused.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

function refuse(reason) {
  process.stderr.write(`${reason}\n`);
  process.exit(2); // 2 blocks the tool call; stderr goes to the model, so it carries no values
}

// The file is passed on stdin (scan -), so no path ever reaches a command line: names with
// spaces or shell characters (&, |, ^) cannot change what runs. On Windows a shell is needed
// for shroud.cmd (the npm shim); the command text is then fixed.
function scanText(text) {
  const shroud = process.env.SHROUD_BIN ?? 'shroud';
  const useShell = process.platform === 'win32' && !shroud.toLowerCase().endsWith('.exe');
  const args = ['scan', '-', '--exit-code', '--no-values'];
  return useShell
    ? spawnSync(`"${shroud}" ${args.join(' ')}`, { input: text, encoding: 'utf8', shell: true })
    : spawnSync(shroud, args, { input: text, encoding: 'utf8' });
}

let toolInput;
try {
  toolInput = JSON.parse(readFileSync(0, 'utf8')).tool_input ?? {};
} catch {
  refuse('Read refused: the Shroud hook could not parse its input.');
}
const file = toolInput.file_path;
if (!file || !existsSync(file)) process.exit(0); // nothing to read; Read reports the error itself

// notes/a/b.md -> notes.shroud/public/a/b.md, for any ancestor directory that was vaulted.
for (let dir = dirname(file); dir !== dirname(dir); dir = dirname(dir)) {
  const masked = join(`${dir}.shroud`, 'public', relative(dir, file));
  if (existsSync(masked)) {
    console.log(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: 'Shroud: reading the masked copy',
        updatedInput: { ...toolInput, file_path: masked },
      },
    }));
    process.exit(0);
  }
}

let text;
try {
  text = readFileSync(file);
} catch {
  refuse(`Read refused: the Shroud hook could not read ${file}.`);
}
const scan = scanText(text);
if (scan.status === 0) process.exit(0);
if (scan.status === 2) refuse(`Read refused: ${file} contains sensitive values and has no masked copy.\n${scan.stdout}`);
refuse(`Read refused: Shroud could not check ${file} (${scan.error?.code ?? `exit ${scan.status}`}). Is shroud installed, or SHROUD_BIN set?`);
