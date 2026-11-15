#!/usr/bin/env node
// UserPromptSubmit hook: stop a prompt that contains values Shroud would tokenize.
// Fails closed: if the check cannot run, the prompt is not sent.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

function block(reason) {
  process.stderr.write(`${reason}\n`);
  process.exit(2); // 2 blocks the prompt; stderr is shown to you, not to the model
}

// The prompt goes on stdin; on Windows a shell is needed for shroud.cmd (the npm shim),
// and the command text is then fixed.
function scanText(text) {
  const shroud = process.env.SHROUD_BIN ?? 'shroud';
  const useShell = process.platform === 'win32' && !shroud.toLowerCase().endsWith('.exe');
  const args = ['scan', '-', '--exit-code', '--no-values'];
  return useShell
    ? spawnSync(`"${shroud}" ${args.join(' ')}`, { input: text, encoding: 'utf8', shell: true })
    : spawnSync(shroud, args, { input: text, encoding: 'utf8' });
}

let prompt;
try {
  ({ prompt = '' } = JSON.parse(readFileSync(0, 'utf8')));
} catch {
  block('Prompt not sent: the Shroud hook could not parse its input.');
}
const scan = scanText(prompt);
if (scan.status === 0) process.exit(0);
if (scan.status === 2) block(`Prompt not sent: it contains sensitive values.\n${scan.stdout}`);
block(`Prompt not sent: Shroud could not check it (${scan.error?.code ?? `exit ${scan.status}`}). Is shroud installed, or SHROUD_BIN set?`);
