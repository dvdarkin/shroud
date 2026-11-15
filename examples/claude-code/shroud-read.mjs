#!/usr/bin/env node
// PreToolUse hook for Read: serve the masked copy when one exists, otherwise refuse a
// file that contains values Shroud would tokenize.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const shroud = process.env.SHROUD_BIN ?? 'shroud';
const input = JSON.parse(readFileSync(0, 'utf8'));
const file = input.tool_input?.file_path;
if (!file || !existsSync(file)) process.exit(0);

// notes/a/b.md -> notes.shroud/public/a/b.md, for any ancestor directory that was vaulted.
for (let dir = dirname(file); dir !== dirname(dir); dir = dirname(dir)) {
  const masked = join(`${dir}.shroud`, 'public', relative(dir, file));
  if (existsSync(masked)) {
    console.log(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: 'Shroud: reading the masked copy',
        updatedInput: { ...input.tool_input, file_path: masked },
      },
    }));
    process.exit(0);
  }
}

const scan = spawnSync(shroud, ['scan', file, '--exit-code', '--no-values'], {
  encoding: 'utf8',
  shell: process.platform === 'win32' && !shroud.endsWith('.exe'),
});
if (scan.status === 2) {
  process.stderr.write(`Read refused: ${file} contains sensitive values and has no masked copy.\n${scan.stdout}`);
  process.exit(2); // 2 blocks the tool call; stderr goes to the model, so it carries no values
}
