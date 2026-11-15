#!/usr/bin/env node
// UserPromptSubmit hook: stop a prompt that contains values Shroud would tokenize.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const shroud = process.env.SHROUD_BIN ?? 'shroud';
const { prompt = '' } = JSON.parse(readFileSync(0, 'utf8'));
const scan = spawnSync(shroud, ['scan', '-', '--exit-code', '--no-values'], {
  input: prompt,
  encoding: 'utf8',
  shell: process.platform === 'win32' && !shroud.endsWith('.exe'),
});
if (scan.status === 2) {
  process.stderr.write(`Prompt not sent: it contains sensitive values.\n${scan.stdout}`);
  process.exit(2); // 2 blocks the prompt; stderr is shown to you, not to the model
}
