/**
 * 解析対象ファイルの読み出し。
 * テストから差し替えられるよう関数型で切り出している。
 */

import { readFile } from 'node:fs/promises';
import { resolveInside } from '../util/path.js';

/** 読み込めなかった場合は null を返す（例外を投げない） */
export type SourceReader = (repoRoot: string, relPath: string) => Promise<string | null>;

/**
 * repoRoot の外へ出るパスを弾く（`..` や絶対パスの混入対策）。
 * 実体は `src/util/path.ts` の共有実装（baseline/ignore のパス解決と共通化）。
 */
export { resolveInside };

export const defaultSourceReader: SourceReader = async (repoRoot, relPath) => {
  const target = resolveInside(repoRoot, relPath);
  if (target === null) return null;
  try {
    return await readFile(target, 'utf8');
  } catch {
    return null;
  }
};
