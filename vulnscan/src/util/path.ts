/**
 * パス解決の共有ユーティリティ。
 *
 * スキャン対象リポジトリの内容（ファイルパス・`.vulnscan.yml` の設定値など）は
 * 未信頼入力として扱う。そこ由来のパスは必ずリポジトリルート配下へ封じ込め、
 * `..` による脱出と絶対パスの混入を弾く。
 */

import { isAbsolute, relative, resolve, sep } from 'node:path';

/**
 * repoRoot の外へ出るパスを弾く（`..` や絶対パスの混入対策）。
 * ルート自身を指す場合も null を返す（ファイルとして扱えないため）。
 */
export function resolveInside(repoRoot: string, relPath: string): string | null {
  const root = resolve(repoRoot);
  const target = resolve(root, relPath);
  const rel = relative(root, target);
  if (rel === '') return null;
  if (rel.startsWith('..') || isAbsolute(rel)) return null;
  return target;
}

export interface ResolveRepoPathOptions {
  /**
   * リポジトリ外を許可するか。
   * CLIフラグ由来（オペレータが明示的に指定した値）のときだけ true にする。
   * スキャン対象リポジトリ由来の設定では決して true にしない。
   */
  allowOutside?: boolean;
}

/**
 * 設定由来のパスを解決する。
 * 封じ込めに失敗した場合は null を返す（呼び出し側で警告にする）。
 */
export function resolveRepoPath(
  repoRoot: string,
  path: string,
  options: ResolveRepoPathOptions = {},
): string | null {
  if (typeof path !== 'string' || path.trim() === '') return null;
  const root = resolve(repoRoot || process.cwd());
  if (options.allowOutside === true) {
    return isAbsolute(path) ? resolve(path) : resolve(root, path);
  }
  return resolveInside(root, path);
}

/**
 * メッセージへ載せるための表示用パス。
 *
 * 絶対パスはホスト側のディレクトリ構成を漏らすので出さない。
 * リポジトリ外を指す場合は具体的な位置を伏せる。
 */
export function toDisplayPath(repoRoot: string, target: string): string {
  const rel = relative(resolve(repoRoot || process.cwd()), resolve(target));
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return '(リポジトリ外のパス)';
  return rel.split(sep).join('/');
}
