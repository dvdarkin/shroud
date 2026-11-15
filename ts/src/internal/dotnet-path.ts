/**
 * Path and directory-enumeration helpers that follow System.IO semantics (Path.Join,
 * Path.Combine, Path.GetDirectoryName, Path.GetFileName, Directory.EnumerateFiles),
 * so the TS CLI prints and orders paths exactly like the C# CLI.
 *
 * Node's path.join/normalize rewrite separators and resolve "." / "..", which .NET
 * does not; Node's fs.readdirSync sorts entries on POSIX, which .NET does not.
 */
import { type Dirent, opendirSync, statSync } from 'node:fs';
import { posix, win32 } from 'node:path';

const isWindows = process.platform === 'win32';
const SEP = isWindows ? '\\' : '/';

function isSeparator(c: string | undefined): boolean {
  return c === '/' || (isWindows && c === '\\');
}

/** Path.IsPathRooted. */
export function isPathRooted(p: string): boolean {
  if (isWindows) return isSeparator(p[0]) || /^[A-Za-z]:/.test(p);
  return p.startsWith('/');
}

/** Path.Join(a, b, ...): concatenates, inserting a separator only when needed. */
export function pathJoin(...parts: string[]): string {
  let out = '';
  for (const part of parts) {
    if (part.length === 0) continue;
    if (out.length === 0) out = part;
    else if (isSeparator(out[out.length - 1]) || isSeparator(part[0])) out += part;
    else out += SEP + part;
  }
  return out;
}

/** Path.Combine(a, b): like Join, but a rooted `b` replaces `a`. */
export function pathCombine(a: string, b: string): string {
  if (b.length === 0) return a;
  if (a.length === 0 || isPathRooted(b)) return b;
  return pathJoin(a, b);
}

/** Path.GetFileName: the part after the last directory separator. */
export function getFileName(p: string): string {
  for (let i = p.length - 1; i >= 0; i--) {
    if (isSeparator(p[i]) || (isWindows && i === 1 && p[1] === ':')) return p.slice(i + 1);
  }
  return p;
}

/**
 * Path.GetDirectoryName: everything before the last separator, with separators
 * normalized (on Windows '/' becomes '\', runs collapse). "" when there is none.
 */
export function getDirectoryName(p: string): string {
  const root = rootLength(p);
  if (p.length <= root) return '';
  let end = p.length;
  while (end > root && !isSeparator(p[--end]));
  while (end > root && isSeparator(p[end - 1])) end--;
  const dir = p.slice(0, end);
  if (!isWindows) return dir.replace(/\/+/g, '/');
  const unc = /^[\\/]{2}/.test(dir) ? '\\\\' : '';
  return unc + dir.slice(unc.length).replace(/[\\/]+/g, '\\');
}

function rootLength(p: string): number {
  if (!isWindows) return p.startsWith('/') ? 1 : 0;
  const m = /^(?:[\\/]{2}[^\\/]+[\\/][^\\/]+[\\/]?|[A-Za-z]:[\\/]?|[\\/])/.exec(p);
  return m ? m[0].length : 0;
}

/** Path.GetRelativePath(relativeTo, path). */
export function getRelativePath(relativeTo: string, path: string): string {
  const lib = isWindows ? win32 : posix;
  const rel = lib.relative(lib.resolve(relativeTo), lib.resolve(path));
  return rel === '' ? '.' : rel;
}

/**
 * Compiles a Win32 search pattern the way .NET's FileSystemName.TranslateWin32Expression
 * and MatchesWin32Expression treat it: `*` and `*.*` match everything, `*` matches any
 * run, `?` matches one character or nothing at a '.' or the end of the name, `.` before
 * a wildcard also matches the end of the name. Case-insensitive on Windows only.
 *
 * Simplification: a trailing "*." (DOS_STAR) is treated as "names without a dot".
 */
export function compileSearchPattern(pattern: string): (name: string) => boolean {
  if (pattern === '' || pattern === '*' || pattern === '*.*') return () => true;
  let src = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*') {
      if (i === pattern.length - 2 && pattern[i + 1] === '.') {
        src += '[^.]*';
        i++;
      } else {
        src += '[\\s\\S]*';
      }
    } else if (c === '?') {
      src += '(?:[^.]|(?=\\.|$))';
    } else if (c === '.' && (pattern[i + 1] === '?' || pattern[i + 1] === '*')) {
      src += '(?:\\.|$)';
    } else {
      src += caseInsensitiveLiteral(c);
    }
  }
  const rx = new RegExp(`^${src}$`);
  return (name) => rx.test(name);
}

function caseInsensitiveLiteral(c: string): string {
  const escaped = c.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
  if (!isWindows) return escaped;
  const lower = c.toLowerCase();
  const upper = c.toUpperCase();
  if (lower.length !== 1 || upper.length !== 1 || lower === upper) return escaped;
  // ASCII letters only fold to ASCII (OrdinalIgnoreCase); see internal/ordinal.ts.
  if (c.charCodeAt(0) < 0x80 && (lower.charCodeAt(0) >= 0x80 || upper.charCodeAt(0) >= 0x80)) return escaped;
  return `[${lower}${upper}]`;
}

function isFileEntry(dir: string, entry: Dirent): boolean {
  if (entry.isFile()) return true;
  if (entry.isSymbolicLink()) {
    try {
      return statSync(pathJoin(dir, entry.name)).isFile();
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Directory.EnumerateFiles(directory, searchPattern, recursive ? AllDirectories :
 * TopDirectoryOnly). Entries come in file-system order (no sorting); subdirectories
 * are visited breadth-first after the current directory, and returned paths are
 * built from `directory` as given, like .NET. Symbolic links to directories are not
 * followed (unverified against .NET; see FORMAT.md).
 */
export function enumerateFiles(directory: string, searchPattern: string, recursive: boolean): string[] {
  const matches = compileSearchPattern(searchPattern);
  const results: string[] = [];
  const queue: string[] = [directory];
  while (queue.length > 0) {
    const dir = queue.shift()!;
    const handle = opendirSync(dir);
    try {
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        const full = pathJoin(dir, entry.name);
        if (entry.isDirectory()) {
          if (recursive) queue.push(full);
        } else if (isFileEntry(dir, entry) && matches(entry.name)) {
          results.push(full);
        }
      }
    } finally {
      handle.closeSync();
    }
  }
  return results;
}
