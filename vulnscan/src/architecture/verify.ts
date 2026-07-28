/**
 * LLM が返した引用の実在検証。
 *
 * LLM はもっともらしいファイル名・行番号を捏造しうる。捏造された引用が
 * inferred の basis に混ざると「根拠がある推測」に見えてしまい、
 * 事実と推測を分ける仕組み全体が壊れる。そのため:
 *
 *   - 実在しないファイルの引用は丸ごと捨てる
 *   - 行番号がファイルの行数を超えていたら行番号だけ落とす
 *   - 抜粋がファイル内に存在しなければ抜粋だけ落とす
 *
 * 捨てた事実は errors に残して、利用者が「LLM が幻覚を出した」と判る
 * ようにする。
 */

import type { Citation } from '../types/evidence.js';
import { normalizeRepoPath, truncate } from './facts.js';
import type { LlmCitation } from './schema.js';

export interface CitationIndex {
  /** リポジトリ内に実在するパス（正規化済み） */
  knownPaths: ReadonlySet<string>;
  /** 読み込み済みファイルの内容（行番号・抜粋の検証に使う） */
  contents: ReadonlyMap<string, string>;
  /** 絶対パスで返された場合に取り除くルート */
  repoRoot?: string;
}

export interface VerifyResult {
  citations: Citation[];
  /** 捨てた・削った引用の説明 */
  rejected: string[];
}

/** LLM が返したパスを比較可能な形に正規化する */
export function normalizeLlmPath(raw: string, repoRoot?: string): string {
  let path = String(raw ?? '').trim();
  if (path === '') return '';
  path = path.replace(/\\/g, '/');
  if (repoRoot !== undefined && repoRoot !== '') {
    const root = normalizeRepoPath(repoRoot);
    if (root !== '' && path.startsWith(root)) path = path.slice(root.length);
    // 絶対パスで返された場合の保険
    const rootWithSlash = `${repoRoot.replace(/\\/g, '/')}/`;
    if (path.startsWith(rootWithSlash)) path = path.slice(rootWithSlash.length);
  }
  return normalizeRepoPath(path);
}

/** 引用 1 件を検証する。実在しなければ null */
export function verifyCitation(
  raw: LlmCitation | Citation,
  index: CitationIndex,
  rejected: string[],
): Citation | null {
  const file = normalizeLlmPath(String((raw as { file?: unknown }).file ?? ''), index.repoRoot);
  if (file === '') {
    rejected.push('LLM が空のファイルパスを引用しました（破棄）');
    return null;
  }
  if (!index.knownPaths.has(file)) {
    rejected.push(`LLM が実在しないファイルを引用しました: ${file}（破棄）`);
    return null;
  }

  const citation: Citation = { file };
  const content = index.contents.get(file);
  const rawLine = (raw as { line?: unknown }).line;
  const rawExcerpt = (raw as { excerpt?: unknown }).excerpt;

  if (typeof rawLine === 'number' && Number.isFinite(rawLine) && rawLine >= 1) {
    const line = Math.floor(rawLine);
    if (content === undefined) {
      // 内容を持っていないファイルは行番号を検証できない。そのまま採る
      citation.line = line;
    } else {
      const lineCount = content.split(/\r?\n/).length;
      if (line <= lineCount) citation.line = line;
      else rejected.push(`LLM の引用行がファイル行数を超えています: ${file}:${line}（行番号を破棄）`);
    }
  }

  if (typeof rawExcerpt === 'string' && rawExcerpt.trim() !== '') {
    const excerpt = rawExcerpt.trim();
    if (content === undefined || content.includes(excerpt.slice(0, 60))) {
      citation.excerpt = truncate(excerpt);
    } else {
      rejected.push(`LLM の引用抜粋がファイル内に見つかりません: ${file}（抜粋を破棄）`);
    }
  }

  return citation;
}

/** 引用の配列を検証する */
export function verifyCitations(
  raws: readonly (LlmCitation | Citation)[] | null | undefined,
  index: CitationIndex,
): VerifyResult {
  const citations: Citation[] = [];
  const rejected: string[] = [];
  for (const raw of raws ?? []) {
    if (raw === null || typeof raw !== 'object') continue;
    const verified = verifyCitation(raw, index, rejected);
    if (verified !== null) citations.push(verified);
  }
  return { citations, rejected };
}
