/**
 * 解析対象ファイルの読み出し。
 * テストから差し替えられるよう関数型で切り出している。
 */

import { readFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

/** 読み込めなかった場合は null を返す（例外を投げない） */
export type SourceReader = (repoRoot: string, relPath: string) => Promise<string | null>;

/** repoRoot の外へ出るパスを弾く（`..` や絶対パスの混入対策） */
export function resolveInside(repoRoot: string, relPath: string): string | null {
  const root = resolve(repoRoot);
  const target = resolve(root, relPath);
  const rel = relative(root, target);
  if (rel === '') return null;
  if (rel.startsWith('..') || isAbsolute(rel)) return null;
  return target;
}

export const defaultSourceReader: SourceReader = async (repoRoot, relPath) => {
  const target = resolveInside(repoRoot, relPath);
  if (target === null) return null;
  try {
    return await readFile(target, 'utf8');
  } catch {
    return null;
  }
};
