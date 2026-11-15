// Differential test: runs the C# scanner (via tools/dotnet-probe) and the TS scanner on
// the same corpus and compares, per input:
//   - every raw match of every pattern (pattern index, index, length),
//   - every exclusion-zone match,
//   - for four scanners (all patterns @0.70, and the paranoid/financial/dev presets):
//     the deduplicated spans (start, end, type, domain, confidence bit pattern,
//     service, matched text), above-threshold count, exclusion zones, every
//     SpanDiagnostic with its full ScoringDetail (HasContextWords included), and every
//     overlap resolution.
// The corpus mixes test strings, repository documents, Unicode edge cases, seeded fuzz
// and targeted inputs for the exclusion rules (front matter at and away from offset 0,
// metadata keys glued to any character outside the line-start/space/tab/"(" allowlist or at the
// end of a line, uppercase ASCII I in case-insensitive patterns) and digit-less financial text.
//
//   npm run build && node tools/differential.mjs [fuzzCount] [seed]
//
// Requires a .NET 8 runtime and SDK. Writes scratch files to .differential/.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));
const pkg = join(here, '..');
const repo = join(pkg, '..');
const work = join(pkg, '.differential');
mkdirSync(work, { recursive: true });

const lib = await import('../dist/src/index.js');
const scannerModule = await import('../dist/src/scanner.js');
const scannerFx = await import('../dist/test/integration/fixtures/scanner-fixtures.js');
const falsePositiveFx = await import('../dist/test/integration/fixtures/false-positive-fixtures.js');

const fuzzCount = Number(process.argv[2] ?? 4000);
let seed = Number(process.argv[3] ?? 20261115);

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------
const corpus = [];
const add = (s) => corpus.push(s);

for (const fx of [scannerFx, falsePositiveFx]) {
  for (const value of Object.values(fx)) {
    add(value);
    add(value.replace(/\n/g, '\r\n'));
  }
}

// Strings used directly by the C# unit tests.
const testStrings = [
  'Deposited 15,000 USDC into the pool.',
  'The server runs at 512 MB of memory.',
  'Filled the order at $512 per unit.',
  `The formula is 10 / 2 = 5. ${'x'.repeat(100)} The cost was $50.`,
  'Profit calculation: $1,234.56+500.00+100.00=1,834.56 USD',
  'bought 100 NVDA for cash',
  '17 JUL 2025 was a good day',
  'April 8, 2025 at 10:36:54 AM GMT+3\n\nbought 100 NVDA',
  '| 2026-04-20 12:17:52 | [TRX_USDT?type=spot] | Limit | Buy | 0.12 | 0.12 | 30 | 30 | 0 | 3.6 | Filled |',
  '| Limit | Buy | [QTY:aaaa1111] | [QTY:aaaa2222] | 0 | [QTY:aaaa3333] | Filled | USDT |',
  '| Task | Hours |\n| ---- | ----- |\n| write | 3 |\n| review | 2 |',
  '| Limit | Buy | 0.5 | price | USDT |',
  '| Limit | Buy | 1,234 | price | USDT |',
  '2026-04-20 17:30:34 | ETH_USDC | Buy | 100 USDC',
  'Bought for $2026 total',
  'Wallet holds 2026 USDC at entry',
  'Paid 2026 USD to vendor',
  'ID tag 2026-15 with 15,000 USDC deposit',
  'Sprint 2026-W17 closed out USDC positions',
  'Sent 0.5 ETH to 0x1111111111111111111111111111111111111111 at $1,234.',
  'Key: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA',
  'This file has no sensitive data whatsoever. Just plain text.',
];
for (const d of ['2026-04-20', '2019-12-31', '1999-01-01', '2026-04-20T17:30:34', '2026-04-20 17:30:34', '2026-04-20T17:30:34.123Z', '2026-04-20T17:30:34+02:00']) testStrings.push(`Filled on ${d} for USDC deposit`);
for (const d of ['04/20/2026', '4-20-2026', '4.20.26', '20/04/2026', '20-04-2026']) testStrings.push(`Trade executed ${d} for USDC profit`);
for (const d of ['20 Apr 2026', 'April 20, 2026', 'Apr 20 2026', 'Jan 2026']) testStrings.push(`Position opened ${d} in USDC`);
for (const t of ['17:30:34', '14:25', '5:00', '5pm', '11:45 AM', '5:30pm']) testStrings.push(`Entry at ${t} for trading USDC position`);
// ExclusionZoneLeakTests and FinancialDigitRequiredTests inputs.
{
  const A = '0x1111111111111111111111111111111111111111';
  const B = '0x2222222222222222222222222222222222222222';
  const pat = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  for (const nl of ['\n', '\r\n']) {
    testStrings.push(`---${nl}title: Notes${nl}wallet: ${A}${nl}---${nl}${nl}Body wallet: ${B}${nl}`);
    testStrings.push(`# Title${nl}${nl}Intro text.${nl}${nl}---${nl}${nl}Wallet: ${A}${nl}${nl}---${nl}${nl}Footer.${nl}`);
  }
  testStrings.push(`\n---\nwallet: ${A}\n---\n`, `---\ntitle: x\n---\n\nText\n\n---\n\nwallet: ${B}\n\n---\n`,
    `---\ntitle: x\n---\nwallet: ${B}\n---\n`, `---\n---\nwallet: ${B}\n\n---\n`);
  for (const line of ['Your profile: ' + A, 'profile: ' + A, 'classpath: ' + pat, 'my-file: ' + A, 'my_file: ' + A, 'Docfile: ' + A,
    'file2path: ' + A, 'file: C:\\wallets\\' + A, 'FILE: wallet-' + A + '.txt', 'source_file: notes/' + A + '.md', 'path: /home/x/' + A,
    'Attachment: ' + A, '- file: ' + A]) testStrings.push('## Notes\n\n' + line + '\n');
  for (const t of ['file:\n' + A + '\n', 'path:   \n' + A + '\n', 'attachment:\r\n' + A + '\r\n']) testStrings.push('## Notes\n\n' + t);
  // Fix A (metadata key allowlist): genuine positions, glued characters, lone CR, offset 0.
  for (const line of ['(path: ' + A + ')', '  file: ' + A, '\tpath: ' + A, 'see (attachment: ' + A + ')']) testStrings.push('## Notes\n\n' + line + '\n');
  for (const glue of ['e\u{301}', '\u{200D}', '\u{200C}', '\u{1D400}', '\u{1F600}', '|', '>', '"', '[', '*', '`', '<', '.', '\u{A0}']) {
    for (const key of ['file:', 'FILE:', 'path:', 'source_file:', 'attachment:']) testStrings.push('## Notes\n\n' + glue + key + ' ' + A + '\n');
  }
  testStrings.push('x\rfile: ' + A + '\r', '## Notes\rpath: ' + A + '\r', 'file: ' + A + '\n');
  // Fix B (culture): uppercase ASCII I in case-insensitive patterns and exclusions.
  testStrings.push('VALIDATOR #548231', 'LOGIN = "bobby"', 'API_KEY = "key-67890"', 'POSITION #77 UNISWAP LIQUIDITY',
    'FILE: ' + A + '\nSOURCE_FILE: x\nPATH: y\nATTACHMENT: z\nAPRIL 8, 2025 at 5 PM\n',
    '## Notes\n\nVALIDATOR #548231\nFILE: ' + A + '\nLOGIN = "bobby"\nAPI_KEY = "key-67890"\nPOSITION #77 UNISWAP LIQUIDITY\n',
    'VAL\u{130}DATOR #548231 val\u{131}dator #548232 F\u{130}LE: ' + A + ' f\u{131}le: ' + B);
  testStrings.push('fee 1,250 = 5 usd and paid $1,200 and EUR 300', 'bought 1,234 units.\n\nfee 1,234 = 5 usd\n',
    'card 4111 1111 1111 1111\n', 'balance 1234.56\n');
}
testStrings.forEach(add);

// Real markdown documents from the repository.
for (const f of ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'docs/trust-architecture.md']) {
  add(readFileSync(join(repo, f), 'utf8'));
}

// Unicode-sensitive edge cases, one construct per string.
const edges = [
  'block #١٢٣٤٥٦ confirmed tx', // Arabic-Indic digits in \d
  'bought １２３ units', // fullwidth digits
  'validator #১২৩', // Bengali digits
  'nonce: 123456 tx', // NBSP in \s
  'nonce:\u0085123456 tx', // NEL: .NET \s, not JS \s
  'nonce:﻿123456 tx', // BOM: JS \s, not .NET \s
  'Server=x; Password=abc', // U+2028 vs `.`
  'Server=x;\rPassword=abc', // \r vs `.`
  'file: a\rb\nnext 1,234 bought',
  '---\r\ntitle: x\r\n---\r\n1,234 bought',
  '---\ntitle: 1,234 bought\n---\n',
  'Key BLOCK #1234567 tx', // KELVIN SIGN
  'BLOCK #1234567 tx',
  'VALİDATOR #123', // dotted capital I
  'valıdator #123', // dotless i
  'poſition #1234 uniswap', // long s
  'abc‍0x1111111111111111111111111111111111111111', // ZWJ before
  '0x1111111111111111111111111111111111111111‌', // ZWNJ after
  '0x1111111111111111111111111111111111111111́', // combining mark (word)
  '0x1111111111111111111111111111111111111111ः', // spacing mark (Mc, not word)
  'ébc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAé',
  'github_pat_' + 'é'.repeat(82),
  'github_pat_' + 'a١'.repeat(41),
  '😀 0x1111111111111111111111111111111111111111 😀',
  '\uD800 lone 1,234 bought \uDC00',
  'price at $1,234٣',
  '$١٢٣ total',
  'Gas was 12 GWEI and 3 ɡwei',
  'JAN 17 2025 and 17 Jan and 17 jan 1,234 bought',
  '5 PM 5 pm 5 PΜ',
  'password = "éééé"',
  'Data Source=x;Pwd=y',
  'Data\u0085Source=x;Pwd=y',
  '\\\\192.168.10.2\\share\\file.md',
  'file:///\\\\10.0.0.1\\s\\x',
  'a@b.co c@é.com x@y.éé',
];
edges.forEach(add);

// Seeded fuzz from fragments that exercise patterns, boundaries and Unicode classes.
const rnd = () => {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return seed / 2147483648;
};
const pick = (a) => a[Math.floor(rnd() * a.length)];
const run = (alphabet, min, max) => {
  const n = min + Math.floor(rnd() * (max - min + 1));
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rnd() * alphabet.length)];
  return s;
};
const HEX = '0123456789abcdefABCDEF';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const DIG = '0123456789';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
const tricky = ['١', '３', '৩', ' ', '\u0085', '﻿', ' ', ' ', '‌', '‍', 'K', 'ſ', 'İ', 'ı', 'é', '́', 'ः', '😀', '\uD800', '\uDC00', '\r', '\r\n', '\t', '\v', '\f', '　', ' ', ' ', 'µ', 'ʰ', '‿', 'Ⅰ'];
const words = [...lib.TRADING_CONTEXT, ...lib.PRICE_CONTEXT, ...lib.AMOUNT_CONTEXT, ...lib.KNOWN_ASSETS,
  'usd', 'USD', 'EUR', 'AUD', 'GBP', 'JPY', 'US$', 'fee', 'tx', 'txid', 'hash', 'block', 'blk', 'validator', 'nonce', 'token id', 'token #', 'nft #', 'position', 'slot', 'epoch', 'Gwei', 'gwei', 'gas', 'solana', 'sol', 'phantom', 'polkadot', 'dot', 'litecoin', 'ltc', 'xrp', 'doge', 'twilio', 'nuget', 'cloudflare', 'heroku', 'HEROKU_API_KEY', 'ssn', 'social', 'iban', 'bank', 'wire', 'server', 'host', 'ssh', 'email', 'contact', 'card', 'credit', 'visa', 'amex', 'mastercard', 'payment', 'cvv',
  'Jan', 'FEB', 'mar', 'April', 'May', 'jun', 'JUL', 'Aug', 'sep', 'Oct', 'nov', 'Dec', 'AM', 'pm', 'GB', 'MB', 'tb', 'k', 'M', 'B', 'm',
  'password', 'passwd', 'pwd', 'secret', 'apikey', 'api_key', 'login', 'username', 'user', 'Server=', 'Data Source=', 'Password=', 'Pwd=',
  'mongodb://', 'postgres://', 'mysql://', 'redis://', 'mongodb+srv://', 'file:', 'path:', 'source_file:', 'attachment:', 'File:'];
// Characters before a metadata key. Only a line start, a space, a tab or "(" make it a
// metadata key; everything else (letters, digits, "_", "-", marks, joiners, surrogates,
// punctuation, other spaces, a lone CR) makes the line ordinary text.
const metadataGlue = ['', ' ', '- ', '(', '[', '"', '/', '.', ':', 'pro', 'class', 'my-', 'my_', 'Doc', 'file2', 'é', 'Ж', '中', 'ʰ', '々',
  '١', '３', '৩', '9', '_', '-', '́', 'ः', '²', '‿', 'Ⅰ', '〇', '‌', '‍', ' ', '\t', '😀', '\uD800', 'K', 'ſ', 'İ'];
metadataGlue.push('e\u{301}', '\u{1D400}', '\u{1D7CE}', '\u{1F511}', '\uDC00', '|', '>', '`', '*', '<', '=', '\r', 'x\r', '\u{A0}',
  '\u{3000}', '\u{2028}', '\u{85}', '\v', '\f', '* ', '1. ', '> ', '| ', '\t(', '((', ' (', '\u{FEFF}');
const metadataKeys = ['file:', 'FILE:', 'FİLE:', 'ATTACHMENT:', 'SOURCE_FILE:', 'File:', 'path:', 'PATH:', 'source_file:', 'Source_File:', 'attachment:', 'Attachment:', 'fıle:', 'ſource_file:', 'patħ:'];
// Separator-only text in the financial shapes built from [\d,]+.
const digitlessShapes = ['fee x, = 5 usd', 'usd fee: total = , then', 'usd fee x, * 2', 'usd fee 2 * , x', 'usd fee x,,,, - 3',
  'Paid $, then left', 'Balance x, USD', 'Paid EUR , ok', 'Paid x, EUR ok', 'filled at $,x price', 'filled at ,x price',
  'Paid $,,, USD', 'at , ETH', ', USDC', 'fee , + , = ,', 'Paid ¥, ok', 'Paid £,, ok', 'sold ,k ETH', 'bought ,,, units', 'at ١, price', 'Paid $١ ok'];
const secretValue = () => pick(['0x1111111111111111111111111111111111111111', 'ghp_' + 'A'.repeat(36), '123-45-6789', '$1,234', '4111 1111 1111 1111', 'AKIA' + 'A'.repeat(16)]);
const secretLine = () => pick(['wallet: ', 'Wallet ', 'key ', 'paid ', 'card ', '']) + secretValue();
// A "---" block at the start of the generated text: closed or not, empty or not, with
// trailing spaces/tabs, LF or CRLF, sometimes with secrets inside.
const frontMatterCandidate = (nl = pick(['\n', '\r\n'])) => {
  const open = pick(['---', '---', '--- ', '---\t', '----', ' ---', '---x']) + nl;
  const lines = [];
  for (let k = Math.floor(rnd() * 4); k > 0; k--) lines.push(pick(['title: x', 'a: 1,234', secretLine(), 'file: ' + secretValue(), '', '  ']));
  const close = pick(['---', '---', '--- ', '---\t', '---  \t', '', '...', '--']);
  return open + lines.map((l) => l + nl).join('') + close + pick([nl, '', nl + nl]);
};
const fragments = [
  () => '0x' + run(HEX, 3, 70),
  () => '0x' + run(HEX, 3, 10) + pick(['...', '..', '…', '.']) + run(HEX, 3, 12),
  () => '[0x' + run(HEX, 4, 8) + '…' + run(HEX, 4, 8) + ']',
  () => pick(['1', '3', 'L', 'M', 'T', 'r', 'D', '4', 'bc1q', 'bc1p', 'ltc1', 'addr1', 'pool1', 'cosmos1', 'osmo1', 'cosmosvaloper1', 'tz1', 'X-avax1', 'bitcoincash:q', 'xpub', 'tprv']) + run(pick([B58, LOWERNUM]), 20, 110),
  () => run(HEX, 60, 66),
  () => run(DIG, 1, 20),
  () => run(DIG, 1, 3) + ',' + run(DIG, 3, 3) + (rnd() < 0.5 ? '.' + run(DIG, 1, 4) : ''),
  () => run(DIG, 1, 6) + '.' + run(DIG, 1, 20),
  () => pick(['$', '£', '€', '¥']) + run(DIG + ',', 1, 8) + pick(['', 'k', 'M', 'b', '.5']),
  () => run(DIG, 1, 5) + pick(['', 'k', 'K', 'm', 'M', 'B']) + pick([' ', '', '  ']) + pick(['USD', 'US$', 'AUD', 'EUR', 'GBP', 'ETH', 'eth', 'USDC', 'stETH', 'SOL']),
  () => pick(['AUD', 'EUR', 'GBP', 'MXN']) + ' ' + run(DIG + ',', 1, 8),
  () => run(DIG, 1, 4) + pick([' / ', '/', ' * ', '*', ' = ', '=', '==', ' + ', '+', ' - ', '-']) + run(DIG + ',.', 1, 8),
  () => pick(['at ', '@ ', 'at  ', 'AT ']) + pick(['$', '']) + run(DIG + ',.', 1, 8) + pick(['', ' MB', 'GB', ':30', '.1.2', ' tb']),
  () => pick(['bought ', 'sold ', 'staked ', 'Sent ', 'WIRED ', 'buy ']) + run(DIG, 1, 6) + pick(['', '.5', ',000', 'k']),
  () => pick(['block', 'BLOCK', 'blk', 'validator', 'nonce', 'nonce:', 'token id', 'token #', 'NFT #', 'position', 'slot', 'epoch']) + pick([' ', '', ' #', '#', ' # ', ': ']) + run(DIG, 1, 11),
  () => run(DIG, 1, 4) + pick(['', '.', '.0']) + run(DIG, 0, 9) + pick([' Gwei', 'gwei', ' GWEI']),
  () => pick(['txHash', 'blockHash', 'stateRoot', 'graffiti', 'TXHASH']) + pick(['=', ': ', ' = ']) + '0x' + run(HEX, 1, 70),
  () => pick(['slot', 'blockNumber', 'gasUsed', 'timestamp', 'nonce']) + pick(['=', ':', ' : ']) + run(DIG, 1, 10),
  () => pick(['ghp_', 'gho_', 'ghu_', 'ghs_', 'npm_', 'pypi-', 'shpat_', 'whsec_', 'glpat-', 'AIza', 'sk-proj-', 'sk-ant-api03-', 'sk_test_', 'rk_live_', 'oy2', 'SK']) + run(pick([B64, HEX.toLowerCase(), LOWERNUM]), 10, 100),
  () => pick(['AKIA', 'ASIA', 'A3TX']) + run('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 14, 18),
  () => 'xoxb-' + run(DIG, 10, 13) + '-' + run(DIG, 10, 13) + '-' + run(LOWERNUM, 22, 26),
  () => 'SG.' + run(B64, 22, 22) + '.' + run(B64, 43, 43),
  () => run(DIG, 8, 10) + ':AA' + run(B64, 33, 33),
  () => pick(['M', 'N']) + run(B64.replace(/[_-]/g, ''), 23, 26) + '.' + run(B64, 6, 6) + '.' + run(B64, 27, 30),
  () => 'eyJ' + run(B64, 0, 20) + '.eyJ' + run(B64, 0, 20) + '.' + run(B64, 1, 20),
  () => '-----BEGIN ' + pick(['RSA ', 'EC ', '', 'OPENSSH ']) + 'PRIVATE KEY' + pick(['', ' BLOCK']) + '-----',
  () => pick(['mongodb://', 'postgres://', 'MySQL://', 'redis://']) + run(LOWERNUM, 1, 6) + ':' + run(LOWERNUM, 1, 6) + '@' + run(LOWERNUM, 1, 10),
  () => pick(['Server=', 'Data Source=', 'server=']) + run(LOWERNUM, 1, 5) + ';' + run(LOWERNUM, 0, 5) + pick([';Password=', ';pwd=', ';Pwd=']) + run(LOWERNUM, 1, 6),
  () => pick(['password', 'token', 'user', 'login', 'API_KEY']) + pick(['=', ' = ', ':', ': ']) + pick(['"', "'"]) + run(LOWERNUM, 1, 8) + pick(['"', "'"]),
  () => run(UPPER, 2, 7) + pick(['/', '-']) + run(UPPER, 2, 7),
  () => run(UPPER, 2, 2) + run(DIG, 2, 2) + run(UPPER + DIG, 4, 30),
  () => run(DIG, 3, 3) + '-' + run(DIG, 2, 2) + '-' + run(DIG, 4, 4),
  () => [1, 2, 3, 4].map(() => run(DIG, 1, 3)).join('.') + pick(['', ':8080', '.5']),
  () => '\\\\' + [1, 2, 3, 4].map(() => run(DIG, 1, 3)).join('.') + '\\' + run(LOWERNUM, 1, 8),
  () => [1, 2, 3, 4, 5, 6].map(() => run(HEX, 2, 2)).join(pick([':', '-'])),
  () => run(LOWERNUM + '._%+-', 1, 10) + '@' + run(LOWERNUM + '.-', 1, 10) + '.' + run('abcxyz', 1, 4),
  () => pick(['4', '5', '3']) + run(DIG, 3, 3) + pick(['', '-', ' ']) + run(DIG, 4, 6) + pick(['', '-', ' ']) + run(DIG, 4, 5) + pick(['', '-', ' ']) + run(DIG, 0, 4),
  () => '4532015112830366',
  () => '371449635398431',
  () => run(LOWERNUM, 1, 10) + pick(['.eth', '-x.eth', '.ETH']),
  () => pick(['abandon', 'ability', 'Abandon', 'about']),
  () => '[' + run(DIG, 1, 8) + '](https://' + pick(['etherscan.io', 'x.org']) + '/' + pick(['block', 'tx', 'address', 'token', 'foo']) + '/' + run(LOWERNUM, 1, 10) + ')',
  () => 'https://' + pick(['etherscan.io', 'solscan.io', 'example.com', 'blockscout.com']) + '/' + pick(['tx/', 'address/', 'a/b/token/', '']) + run(LOWERNUM, 1, 20),
  () => pick(['19', '20', '21']) + run(DIG, 2, 2) + pick(['-', '/', '.']) + run(DIG, 1, 2) + pick(['-', '/', '.', 'T', ' ']) + run(DIG, 1, 4),
  () => run(DIG, 1, 2) + ':' + run(DIG, 2, 2) + pick(['', ':' + run(DIG, 2, 2), ' AM', 'pm', '.5']),
  () => pick(['', run(DIG, 1, 2) + ' ']) + pick(['Jan', 'feb', 'MARCH', 'April', 'Sept', 'Dec']) + pick([' ', ', ', ' 17, ']) + pick(['2026', '1999', '2101', '26']),
  () => pick(['20', '19']) + run(DIG, 2, 2) + '-W' + run(DIG, 2, 2) + pick(['', '-3']),
  () => '| ' + run(DIG, 1, 4) + pick(['', '.5', ',000']) + ' |',
  () => '---\n' + pick(['title: x', 'a: 1,234']) + '\n---' + pick(['', '\n', '  \n']),
  () => pick(['---', '--- ', '---\t', '----', ' ---']) + pick(['\n', '\r\n', '\r', '']),
  () => pick(['file', 'path', 'Source_File', 'ATTACHMENT']) + ':' + pick([' ', '', '\t']) + run(LOWERNUM + ' /.', 1, 30),
  () => pick(metadataGlue) + pick(metadataKeys) + pick(['', ' ', '\t', '   ', ' \t']) + pick(['\n', '\r\n', '', '\r', ' x', '\u0085y']),
  () => pick(digitlessShapes),
  () => pick(words),
  () => pick(tricky),
  () => pick([' ', ' ', ' ', '\n', '  ', ', ', '. ', ' | ', ' (', ') ', '\n\n', ' - ', ' # ', '#', '-', '/', ':', '=', '+']),
];
for (let i = 0; i < fuzzCount; i++) {
  const n = 5 + Math.floor(rnd() * 60);
  // One input in eight starts with a front matter candidate, so the offset-0 rule is fuzzed too.
  let s = i % 8 === 0 ? frontMatterCandidate() : '';
  for (let j = 0; j < n; j++) s += pick(fragments)();
  add(s);
}

// Targeted inputs for the exclusion and digit rules (front matter at and away from offset 0,
// metadata keys glued to words or at the end of a line, digit-less financial shapes).
for (let i = 0; i < 300; i++) {
  const nl = pick(['\n', '\r\n']);
  const lead = i % 3 === 0 ? pick(['', '', '\n', '\r\n', ' ', '﻿', 'x\n', '# T' + nl + nl]) : '';
  const body = [secretLine(), pick(digitlessShapes), pick(metadataGlue) + pick(metadataKeys) + ' ' + secretValue()];
  add(lead + frontMatterCandidate(nl) + body.join(nl) + nl + pick(['', '---' + nl, nl + '---' + nl + secretLine() + nl + '---' + nl]));
}
for (const glue of metadataGlue) {
  for (const key of metadataKeys) {
    add(`## Notes\n\n${glue}${key} ${secretValue()}\n`);
    add(`${glue}${key}${pick(['', ' ', '\t', '  '])}${pick(['\n', '\r\n'])}${secretValue()}\n`);
  }
}
for (const shape of digitlessShapes) {
  add(shape);
  add(shape.replace(',', '1,2'));
  add(`${shape} ${pick(['usd', 'fee', 'EUR', 'bought', 'price', 'ETH'])} ${shape}`);
}

// ---------------------------------------------------------------------------
// .NET side (in batches: the probe output for a large corpus exceeds V8's max string)
// ---------------------------------------------------------------------------
const BATCH = 2500;
const probeDll = join(here, 'dotnet-probe', 'bin', 'Release', 'net8.0', 'Probe.dll');
// Always (re)build: the probe references ../../src/Shroud, so a stale build would compare the
// port against an old C# library. The build is incremental.
execFileSync('dotnet', ['build', '-c', 'Release', '-nologo', '-v', 'q', join(here, 'dotnet-probe')], { stdio: 'inherit' });
function runDotnet(batch, n) {
  const chunks = [];
  for (const s of batch) {
    const b = Buffer.alloc(4 + s.length * 2);
    b.writeInt32LE(s.length, 0);
    for (let i = 0; i < s.length; i++) b.writeUInt16LE(s.charCodeAt(i), 4 + i * 2);
    chunks.push(b);
  }
  const inputPath = join(work, `inputs-${n}.bin`);
  const netPath = join(work, `net-${n}.json`);
  writeFileSync(inputPath, Buffer.concat(chunks));
  execFileSync('dotnet', [probeDll, 'scan', inputPath, netPath], { stdio: 'inherit' });
  return JSON.parse(readFileSync(netPath, 'utf8'));
}

// ---------------------------------------------------------------------------
// TS side, same shape
// ---------------------------------------------------------------------------
const view = new DataView(new ArrayBuffer(8));
const bits = (d) => {
  view.setFloat64(0, d);
  return view.getBigUint64(0).toString(16).padStart(16, '0');
};
const hexText = (t) => [...Array(t.length).keys()].map((i) => t.charCodeAt(i).toString(16).padStart(4, '0')).join('');
const span = (s) => [s.start, s.end, s.entityType, s.domain, bits(s.confidence), s.service, hexText(s.matchedText)];

const patterns = lib.getAllPatterns();
const scanners = [
  ['all', new lib.SensitivityScanner()],
  ['paranoid', new lib.SensitivityScanner(lib.configForPreset('paranoid'))],
  ['financial', new lib.SensitivityScanner(lib.configForPreset('financial'))],
  ['dev', new lib.SensitivityScanner(lib.configForPreset('dev'))],
];

function tsResult(text) {
  const o = { m: [], x: [] };
  patterns.forEach((p, pi) => {
    for (const m of scannerModule.matchesOf(p.regex, text)) o.m.push([pi, m.index, m.length]);
  });
  scannerModule.EXCLUSION_REGEXES.forEach((rx, ri) => {
    for (const m of scannerModule.matchesOf(rx, text)) o.x.push([ri, m.index, m.length]);
  });
  for (const [name, sc] of scanners) {
    const { result, diagnostics } = sc.scanWithDiagnostics(text);
    o[name] = result.allDetected.map(span);
    o[name + '_above'] = result.aboveThreshold.length;
    o[name + '_zones'] = diagnostics.exclusionZones.flatMap((z) => [z.start, z.end]);
    o[name + '_diag'] = diagnostics.allSpans.map((d) => [
      span(d.span), d.wasExcluded, d.failedLuhn,
      bits(d.scoring.baseConfidence), bits(d.scoring.finalConfidence), d.scoring.isStructural, d.scoring.hasContextWords,
      d.scoring.contextWordsFound.join('|'), d.scoring.contextWindowStart, d.scoring.contextWindowEnd,
      d.scoring.assetBoostApplied, d.scoring.currencyBoostApplied, d.scoring.patternService,
    ]);
    o[name + '_ovl'] = diagnostics.overlapResolutions.map((r) => [span(r.dropped), span(r.winner), r.reason]);
  }
  return o;
}

let failures = 0;
let compared = 0;
let totalMatches = 0;
let totalSpans = 0;
const t0 = performance.now();
let net = [];
let netBase = 0;
for (let i = 0; i < corpus.length; i++) {
  if (i - netBase >= net.length) {
    netBase = i;
    net = runDotnet(corpus.slice(i, i + BATCH), Math.floor(i / BATCH));
  }
  const ts = tsResult(corpus[i]);
  const cs = net[i - netBase];
  totalMatches += cs.m.length;
  totalSpans += cs.all.length;
  for (const key of Object.keys(cs)) {
    compared++;
    const a = JSON.stringify(cs[key]);
    const b = JSON.stringify(ts[key]);
    if (a !== b) {
      failures++;
      if (failures <= 10) {
        console.log(`MISMATCH input #${i} key ${key}`);
        console.log('  input:', JSON.stringify(corpus[i]).slice(0, 300));
        const ca = cs[key];
        const tb = ts[key];
        if (Array.isArray(ca) && Array.isArray(tb)) {
          const sa = new Set(ca.map((x) => JSON.stringify(x)));
          const sb = new Set(tb.map((x) => JSON.stringify(x)));
          console.log('  only C#:', [...sa].filter((x) => !sb.has(x)).slice(0, 5));
          console.log('  only TS:', [...sb].filter((x) => !sa.has(x)).slice(0, 5));
        } else {
          console.log('  C#:', a.slice(0, 300), '\n  TS:', b.slice(0, 300));
        }
      }
    }
  }
}
const ms = performance.now() - t0;
console.log(
  `inputs=${corpus.length} chars=${corpus.reduce((n, s) => n + s.length, 0)} rawMatches=${totalMatches} ` +
    `spans(all)=${totalSpans} comparisons=${compared} mismatches=${failures} tsTime=${ms.toFixed(0)}ms`,
);
process.exitCode = failures === 0 ? 0 : 1;
