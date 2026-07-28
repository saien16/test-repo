/**
 * `.gitignore` の解釈。
 *
 * git の完全な仕様は再現しないが、実運用で使われる範囲
 * （否定 `!`、ディレクトリ限定 `/` 末尾、アンカー、ネストした .gitignore）
 * をカバーする。
 */

import { globToRegExp, normalizePath } from './glob.js';

interface IgnoreRule {
  /** `!` で始まる再包含ルールか */
  negated: boolean;
  /** ディレクトリにのみ適用されるか */
  dirOnly: boolean;
  regex: RegExp;
  /** デバッグ用の元パターン */
  source: string;
}

export class IgnoreMatcher {
  private readonly rules: IgnoreRule[] = [];

  /**
   * `.gitignore` の内容を取り込む。
   * `baseDir` はその .gitignore が置かれたディレクトリのルート相対パス（ルートなら ''）。
   * 走査は上位ディレクトリから行うため、追加順がそのまま優先順位（後勝ち）になる。
   */
  add(content: string, baseDir = ''): void {
    const base = normalizePath(baseDir);
    for (const rawLine of content.split(/\r?\n/)) {
      const rule = this.parseLine(rawLine, base);
      if (rule) this.rules.push(rule);
    }
  }

  private parseLine(rawLine: string, base: string): IgnoreRule | null {
    let line = rawLine.replace(/\s+$/, '');
    if (line === '' || line.startsWith('#')) return null;

    let negated = false;
    if (line.startsWith('!')) {
      negated = true;
      line = line.slice(1);
    }
    // エスケープされた先頭文字（`\#` など）を戻す
    if (line.startsWith('\\')) line = line.slice(1);
    if (line === '') return null;

    let dirOnly = false;
    if (line.endsWith('/')) {
      dirOnly = true;
      line = line.slice(0, -1);
    }
    if (line === '') return null;

    // 先頭以外に `/` を含むならリポジトリ（.gitignore の位置）基準で固定される
    const anchored = line.includes('/');
    if (line.startsWith('/')) line = line.slice(1);

    const relative = anchored ? line : `**/${line}`;
    const full = base === '' ? relative : `${base}/${relative}`;

    return { negated, dirOnly, regex: globToRegExp(full), source: rawLine };
  }

  /** 対象パスが無視されるか（後に追加されたルールが優先される） */
  ignores(relPath: string, isDir: boolean): boolean {
    const target = normalizePath(relPath);
    if (target === '') return false;
    let ignored = false;
    for (const rule of this.rules) {
      if (rule.dirOnly && !isDir) continue;
      if (rule.regex.test(target)) ignored = !rule.negated;
    }
    return ignored;
  }

  /** 取り込み済みルール数（テスト・診断用） */
  get size(): number {
    return this.rules.length;
  }
}
