#!/usr/bin/env node
// Checks the TypeScript port (../ts, built to ../ts/dist) against this corpus.
// The corpus was generated from the C# implementation without sight of the
// port, so a pass here is independent evidence of parity.
//
//   cd ts && npm run build && cd .. && node conformance/run-ts.mjs
//
// Exit code 0 when every check passes, 1 otherwise.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, '..', 'ts', 'dist', 'src');
const lib = await import(pathToFileURL(path.join(dist, 'index.js')).href);
const textIo = await import(pathToFileURL(path.join(dist, 'internal', 'text-io.js')).href);

const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const expected = path.join(here, 'expected');
const index = readJson(path.join(expected, 'index.json'));

const totals = {};
const failures = [];
function check(group, name, ok, detail = '') {
  totals[group] ??= { pass: 0, fail: 0 };
  if (ok) totals[group].pass++;
  else {
    totals[group].fail++;
    if (failures.length < 60) failures.push(`${group}: ${name}${detail ? ' - ' + detail : ''}`);
  }
}

// --- scan: 13 configs x 92 inputs -----------------------------------------
const texts = new Map();
for (const input of index.inputs) {
  const bytes = fs.readFileSync(path.join(here, 'inputs', input.name));
  const text = textIo.decodeText(bytes);
  texts.set(input.name, text);
  check('input-decoding', input.name, sha256(bytes) === input.sha256 && text.length === input.utf16Length,
    `utf16 length ${text.length} vs ${input.utf16Length}`);
}

const SPAN_FIELDS = ['start', 'end', 'matchedText', 'entityType', 'domain', 'service', 'confidence'];
for (const configName of index.configs) {
  const name = typeof configName === 'string' ? configName : configName.name;
  const base = name.replace(/\.json$/, '');
  const config = lib.loadConfig(path.join(here, 'configs', base + '.json'));
  const scanner = new lib.SensitivityScanner(config);
  for (const input of index.inputs) {
    const stem = input.name.replace(/\.md$/, '');
    const want = readJson(path.join(expected, 'scan', base, stem + '.json'));
    const got = scanner.scan(texts.get(input.name));
    let diff = '';
    if (got.threshold !== want.threshold) diff = `threshold ${got.threshold} vs ${want.threshold}`;
    else if (got.allDetected.length !== want.allDetected.length) diff = `span count ${got.allDetected.length} vs ${want.allDetected.length}`;
    else {
      for (let i = 0; i < want.allDetected.length && !diff; i++) {
        const w = want.allDetected[i];
        const g = got.allDetected[i];
        for (const f of SPAN_FIELDS) {
          if (g[f] !== w[f]) { diff = `span ${i} ${f}: ${JSON.stringify(g[f])} vs ${JSON.stringify(w[f])}`; break; }
        }
        if (!diff && lib.typeAbbreviation(g.entityType) !== w.typeAbbreviation) diff = `span ${i} abbreviation`;
        if (!diff && (g.confidence >= got.threshold) !== w.aboveThreshold) diff = `span ${i} aboveThreshold`;
      }
      if (!diff && got.aboveThreshold.length !== want.counts.aboveThreshold) diff = 'aboveThreshold count';
      if (!diff && got.belowThreshold.length !== want.counts.belowThreshold) diff = 'belowThreshold count';
    }
    check('scan', `${base}/${stem}`, !diff, diff);
  }
}

// --- mask: default config, fixed key --------------------------------------
const maskKey = Buffer.from(index.maskKeyHex, 'hex');
const defaultScanner = new lib.SensitivityScanner(lib.loadConfig(path.join(here, 'configs', 'default.json')));
const masker = new lib.SpanMasker(maskKey);
for (const input of index.inputs) {
  const stem = input.name.replace(/\.md$/, '');
  const text = texts.get(input.name);
  const result = masker.mask(text, defaultScanner.scan(text));
  const wantBytes = fs.readFileSync(path.join(expected, 'mask', stem + '.md'));
  const gotBytes = Buffer.from(result.maskedText, 'utf8');
  check('mask-text', stem, gotBytes.equals(wantBytes), `sha ${sha256(gotBytes).slice(0, 12)} vs ${sha256(wantBytes).slice(0, 12)}`);
  const wantTokens = readJson(path.join(expected, 'mask', stem + '.tokens.json'));
  const w = wantTokens.tokensInReplacementOrder;
  let diff = result.tokens.length !== w.length ? `token count ${result.tokens.length} vs ${w.length}` : '';
  for (let i = 0; i < w.length && !diff; i++) {
    const g = result.tokens[i];
    for (const f of ['tokenId', 'originalValue', 'entityType', 'domain']) {
      if (g[f] !== w[i][f]) { diff = `token ${i} ${f}: ${g[f]} vs ${w[i][f]}`; break; }
    }
  }
  check('mask-tokens', stem, !diff, diff);
}

// --- token derivation vectors ---------------------------------------------
const vectors = readJson(path.join(expected, 'tokens', 'derivation-vectors.json'));
for (const v of vectors.vectors) {
  if (v.textUtf8Hex == null) { check('token-vectors', `${v.keyLabel}/long-text`, true); continue; }
  const text = Buffer.from(v.textUtf8Hex, 'hex').toString('utf8');
  const got = lib.generateTokenId(Buffer.from(v.keyHex, 'hex'), v.entityType, text);
  check('token-vectors', `${v.keyLabel}/${v.entityType}/${v.textUtf8Hex.slice(0, 16)}`, got === v.tokenId, `${got} vs ${v.tokenId}`);
}
for (const t of vectors.typeAbbreviations) {
  check('type-abbreviations', t.entityType, lib.typeAbbreviation(t.entityType) === t.typeAbbreviation);
}

// --- vaults written by C#: decrypt, compare, restore ----------------------
function walk(dir, rel = '') {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...walk(path.join(dir, e.name), r));
    else out.push(r);
  }
  return out;
}
const vaultsDir = path.join(here, 'vaults');
for (const v of fs.readdirSync(vaultsDir, { withFileTypes: true }).filter((e) => e.isDirectory())) {
  const dir = path.join(vaultsDir, v.name);
  const meta = readJson(path.join(dir, 'meta.json'));
  const packed = fs.readFileSync(path.join(dir, 'vault', 'vault.shroud'));
  check('vault-wrong-passphrase', v.name, lib.decrypt(packed, meta.passphrase + 'x') === null);
  const plain = lib.decrypt(packed, meta.passphrase);
  check('vault-decrypt', v.name, plain !== null);
  if (plain === null) continue;
  const wantPlain = fs.readFileSync(path.join(dir, 'vault-data.decrypted.json'));
  check('vault-plaintext-bytes', v.name, Buffer.from(plain).equals(wantPlain));
  const data = lib.parseVaultData(Buffer.from(plain).toString('utf8'));
  check('vault-parse', v.name, data !== null);
  if (data === null) continue;
  const tokens = data.tokens instanceof Map ? [...data.tokens.entries()] : Object.entries(data.tokens);
  check('vault-token-count', v.name, tokens.length === meta.tokenCount, `${tokens.length} vs ${meta.tokenCount}`);
  const publicDir = path.join(dir, 'vault', 'public');
  for (const rel of fs.existsSync(publicDir) ? walk(publicDir) : []) {
    let content = textIo.decodeText(fs.readFileSync(path.join(publicDir, rel)));
    content = lib.restoreTokens(content, new Map(tokens)).text;
    const want = fs.readFileSync(path.join(dir, 'restored', rel));
    check('vault-restore', `${v.name}/${rel}`, Buffer.from(content, 'utf8').equals(want));
  }
}

// --- report ----------------------------------------------------------------
let failed = 0;
for (const [group, t] of Object.entries(totals)) {
  failed += t.fail;
  console.log(`${t.fail === 0 ? 'ok  ' : 'FAIL'} ${group.padEnd(24)} ${t.pass} pass, ${t.fail} fail`);
}
if (failures.length) {
  console.log('\nfirst failures:');
  for (const f of failures) console.log('  ' + f);
}
process.exit(failed === 0 ? 0 : 1);
