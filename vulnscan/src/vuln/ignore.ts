/**
 * 抑制リスト（.grimoireignore、旧 .vulnignore）の読み込みと適用。
 *
 * 書式: 1行1エントリ。`#` 以降はコメント。空行は無視。
 *   - 指紋そのもの      : 64桁の16進文字列
 *   - Finding ID        : VS-xxxxxxxxxxxx
 *   - CWE ID            : CWE-79
 *   - glob パターン     : `src/legacy/**` のようにファイルパスへ照合するパターン
 *   - glob + CWE 限定   : `src/legacy/** CWE-89`（パターンとCWEの AND 条件）
 */

import { readFile } from 'node:fs/promises';
import { globToRegExp as compileGlob, matchGlob } from '../context/glob.js';
import type { Finding } from '../types/finding.js';
import {
  normalizeRelPath,
  toDisplayPath,
  type ResolveRepoPathOptions,
} from '../util/path.js';
import { resolvePath } from './baseline.js';

export type IgnoreRuleKind = 'fingerprint' | 'id' | 'cwe' | 'glob';

export interface IgnoreRule {
  kind: IgnoreRuleKind;
  /** 元の行（レポート用） */
  raw: string;
  /** 行番号（1始まり） */
  line: number;
  value: string;
  /** glob と併記された CWE 限定条件 */
  cwe?: string;
  /** kind='glob' のときのコンパイル済み正規表現 */
  matcher?: RegExp;
}

export interface IgnoreList {
  rules: IgnoreRule[];
  errors: string[];
}

const FINGERPRINT_RE = /^[0-9a-f]{16,64}$/i;
const ID_RE = /^VS-[0-9a-f]{6,}$/i;
const CWE_RE = /^CWE-\d+$/i;

/**
 * 抑制リストを読み込む。存在しなければ空のリストを返す（エラーではない）。
 *
 * パスはリポジトリ内へ封じ込める（未信頼の `.grimoire.yml` から任意ファイルを
 * 読ませないため）。エラーには絶対パスも生の例外メッセージも載せない。
 */
export async function loadIgnoreList(
  path: string,
  repoRoot: string,
  options: ResolveRepoPathOptions = {},
): Promise<IgnoreList> {
  const full = resolvePath(path, repoRoot, options);
  if (full === null) {
    return {
      rules: [],
      errors: ['抑制リストのパスがリポジトリ外を指しているため読み込みませんでした'],
    };
  }
  try {
    const text = await readFile(full, 'utf8');
    return parseIgnoreList(text);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return { rules: [], errors: [] };
    const shown = toDisplayPath(repoRoot, full);
    const safeCode = typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? ` / ${code}` : '';
    return {
      rules: [],
      errors: [`抑制リストを読み込めませんでした (${shown}${safeCode})`],
    };
  }
}

/** 抑制リストの本文をパースする */
export function parseIgnoreList(text: string): IgnoreList {
  const rules: IgnoreRule[] = [];
  const errors: string[] = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? '';
    // '#' 以降はコメント
    const withoutComment = rawLine.split('#')[0] ?? '';
    const trimmed = withoutComment.trim();
    if (trimmed === '') continue;

    // 'パターン CWE-89' 形式（空白区切りで CWE 限定）
    const tokens = trimmed.split(/\s+/);
    const first = tokens[0] as string;
    const second = tokens[1];
    const cweQualifier = second && CWE_RE.test(second) ? second.toUpperCase() : undefined;

    if (FINGERPRINT_RE.test(first) && !first.includes('/')) {
      rules.push({ kind: 'fingerprint', raw: trimmed, line: i + 1, value: first.toLowerCase() });
    } else if (ID_RE.test(first)) {
      rules.push({ kind: 'id', raw: trimmed, line: i + 1, value: first.toUpperCase() });
    } else if (CWE_RE.test(first)) {
      rules.push({ kind: 'cwe', raw: trimmed, line: i + 1, value: first.toUpperCase() });
    } else {
      // 共有実装は変換に失敗しても throw せず「何にもマッチしない正規表現」を返す。
      // 抑制リストの1行が壊れていてもスキャン全体は続行させたいので、この契約で良い。
      rules.push({
        kind: 'glob',
        raw: trimmed,
        line: i + 1,
        value: first,
        ...(cweQualifier ? { cwe: cweQualifier } : {}),
        matcher: globToRegExp(first),
      });
    }
  }

  return { rules, errors };
}

/** Finding が抑制対象かを判定し、一致したルールを返す */
export function matchIgnoreRule(finding: Finding, list: IgnoreList): IgnoreRule | null {
  // 照合前に必ず正規化する。以前は生のパスをそのまま当てていたため、
  // 先頭 './' の付いた Finding を取りこぼしていた。
  const file = normalizeRelPath(finding.location?.file ?? '');
  for (const rule of list.rules) {
    switch (rule.kind) {
      case 'fingerprint':
        // 前方一致も許可（短縮指紋を書けるようにするため）
        if (finding.fingerprint.toLowerCase().startsWith(rule.value)) return rule;
        break;
      case 'id':
        if (finding.id.toUpperCase() === rule.value) return rule;
        break;
      case 'cwe':
        if ((finding.cwe ?? '').toUpperCase() === rule.value) return rule;
        break;
      case 'glob':
        if (rule.matcher?.test(file)) {
          if (!rule.cwe || (finding.cwe ?? '').toUpperCase() === rule.cwe) return rule;
        }
        break;
    }
  }
  return null;
}

/**
 * glob パターンを正規表現に変換する。
 *
 * 変換の実体は `context/glob.ts`（`.gitignore` 側と同じ共有実装）。
 * 以前はここに独自の最小実装があり、`{a,b}` / `[abc]` / `[!abc]` を
 * 単なるリテラルとしてエスケープしていたため、
 * **`.gitignore` と `.grimoireignore` でパターンの解釈が食い違っていた**。
 * さらに独自版は throw する前提で呼び出し側が try/catch していたが、
 * 共有版は throw しない設計なので、エラー処理の契約まで枝分かれしていた。
 *
 * 抑制リスト固有の約束事はここだけ残す:
 *   末尾が `/` のパターン（ディレクトリ指定）は配下すべてに一致させる。
 */
export function globToRegExp(pattern: string): RegExp {
  return compileGlob(pattern.endsWith('/') ? `${pattern}**` : pattern);
}

/** パターンがパスに一致するか（パスは正規化してから照合する） */
export function matchIgnoreGlob(pattern: string, filePath: string): boolean {
  return pattern.endsWith('/')
    ? matchGlob(`${pattern}**`, filePath)
    : matchGlob(pattern, filePath);
}
