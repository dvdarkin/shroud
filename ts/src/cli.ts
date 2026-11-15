#!/usr/bin/env node
/**
 * The `shroud` executable: runs the CLI (cli-program.ts) on the process arguments and
 * mirrors the .NET host for an unhandled exception.
 */
import { crash, main } from './cli-program.js';

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  crash,
);
