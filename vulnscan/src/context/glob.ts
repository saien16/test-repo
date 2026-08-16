/**
 * 軽量 glob マッチャ。
 *
 * 新規の npm 依存を持ち込まない方針のため自前実装している。
 * 対応構文: `**`, `*`, `?`, `[abc]` / `[!abc]`, `{a,b}`
 *
 * 対象パスは常にリポジトリルートからの POSIX 相対パス（先頭 `./` なし、
 * 末尾 `/` なし）を前提とする。
 */

/** パスを比較用に正規化する（Windows 区切り・冗長な `./` を吸収） */
export function normalizePath(p: string): string {
  let out = p.replace(/\\/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  while (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  if (out.startsWith('/')) out = out.slice(1);
  return out;
}

/** 正規表現で特別な意味を持つ文字をエスケープする */
function escapeChar(c: string): string {
  return /[.^$+()|\\\]}]/.test(c) ? `\\${c}` : c;
}

/** `{a,b}` の対応する閉じ括弧位置を返す。見つからなければ -1 */
function findClosingBrace(glob: string, open: number): number {
  let depth = 0;
  for (let i = open; i < glob.length; i++) {
    const c = glob[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** ブレース内をトップレベルのカンマで分割する */
function splitTopLevel(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const c of inner) {
    if (c === '{') depth++;
    if (c === '}') depth--;
    if (c === ',' && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += c;
  }
  parts.push(current);
  return parts;
}

/** glob 文字列を正規表現ソースへ変換する（アンカーは付けない） */
function compile(glob: string): string {
  let out = '';
  let i = 0;
  const n = glob.length;

  while (i < n) {
    const c = glob[i] as string;

    if (c === '*') {
      let stars = 0;
      while (i < n && glob[i] === '*') {
        stars++;
        i++;
      }
      if (stars >= 2) {
        if (glob[i] === '/') {
          // `**/` は「0個以上のディレクトリ」を意味する
          i++;
          out += '(?:[^/]+/)*';
        } else {
          out += '.*';
        }
      } else {
        out += '[^/]*';
      }
      continue;
    }

    if (c === '?') {
      out += '[^/]';
      i++;
      continue;
    }

    if (c === '[') {
      let j = i + 1;
      let negated = false;
      if (glob[j] === '!' || glob[j] === '^') {
        negated = true;
        j++;
      }
      let body = '';
      // 先頭の `]` はリテラル扱い
      if (glob[j] === ']') {
        body += '\\]';
        j++;
      }
      while (j < n && glob[j] !== ']') {
        const ch = glob[j] as string;
        body += ch === '\\' || ch === '[' || ch === '^' ? `\\${ch}` : ch;
        j++;
      }
      if (j >= n) {
        // 閉じていない場合はリテラルの `[` として扱う
        out += '\\[';
        i++;
        continue;
      }
      out += `[${negated ? '^' : ''}${body}]`;
      i = j + 1;
      continue;
    }

    if (c === '{') {
      const close = findClosingBrace(glob, i);
      if (close < 0) {
        out += '\\{';
        i++;
        continue;
      }
      const parts = splitTopLevel(glob.slice(i + 1, close));
      out += `(?:${parts.map(compile).join('|')})`;
      i = close + 1;
      continue;
    }

    out += escapeChar(c);
    i++;
  }

  return out;
}

const regexCache = new Map<string, RegExp>();

/** glob を正規表現へ変換する（結果はキャッシュされる） */
export function globToRegExp(glob: string): RegExp {
  const cached = regexCache.get(glob);
  if (cached) return cached;
  let re: RegExp;
  try {
    re = new RegExp(`^${compile(glob)}$`);
  } catch {
    // 変換に失敗した場合は何にもマッチしない正規表現にフォールバックする
    re = /(?!)/;
  }
  regexCache.set(glob, re);
  return re;
}

/** 単一の glob がパスにマッチするか */
export function matchGlob(pattern: string, filePath: string): boolean {
  return globToRegExp(pattern).test(normalizePath(filePath));
}

/** いずれかの glob にマッチするか */
export function matchAnyGlob(patterns: readonly string[], filePath: string): boolean {
  const target = normalizePath(filePath);
  return patterns.some((p) => globToRegExp(p).test(target));
}

/**
 * ディレクトリ自体が glob 群によって除外されるか。
 *
 * `**\/node_modules/**` のようなパターンは `node_modules` ディレクトリ自身には
 * マッチしないが、走査時はサブツリーごと枝刈りしたいので末尾の `/**` を
 * 取り除いた形でも判定する。
 */
export function matchAnyGlobDirectory(patterns: readonly string[], dirPath: string): boolean {
  const target = normalizePath(dirPath);
  for (const pattern of patterns) {
    if (globToRegExp(pattern).test(target)) return true;
    if (pattern.endsWith('/**') && globToRegExp(pattern.slice(0, -3)).test(target)) return true;
    if (pattern.endsWith('/') && globToRegExp(pattern.slice(0, -1)).test(target)) return true;
  }
  return false;
}
