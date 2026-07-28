/**
 * パス解決の共有ユーティリティ。
 *
 * スキャン対象リポジトリの内容（ファイルパス・`.grimoire.yml` の設定値など）は
 * 未信頼入力として扱う。そこ由来のパスは必ずリポジトリルート配下へ封じ込め、
 * `..` による脱出と絶対パスの混入を弾く。
 */

import { isAbsolute, relative, resolve, sep } from 'node:path';

/* ------------------------------------------------------------------ *
 * 比較用のパス正規化
 *
 * 以前は `context/glob.ts` / `architecture/facts.ts` / `killchain/reachability.ts`
 * / `vuln/cvss.ts` / `vuln/fingerprint.ts` の5箇所に似て非なる正規化があり、
 * `//src/a.ts` のような入力で結果が食い違っていた。
 * Finding を構成要素へ前方一致させる処理（ヒートマップの行割り当て）が
 * この差で外れるため、ここへ2段に分けて統合する。
 *
 *   1. {@link normalizeRelPath}     … 単純正規化（区切り・`./`・重複 `/`・前後の `/`）
 *   2. {@link normalizeRepoRelPath} … 上に加えて repoRoot の接頭辞を剥がす
 *
 * `context/glob.ts` の `normalizePath` は glob 照合の内部専用として現状のまま
 * 残しているが、実用上のパス（重複スラッシュを含まない相対パス）では
 * ここと同じ結果になる。差異は `util/path.test.ts` で突き合わせている。
 * ------------------------------------------------------------------ */

/**
 * 比較用にパスを正規化する。
 *
 * - Windows 区切り `\` を `/` にする
 * - 連続した `/` を1つに畳む（`a//b` → `a/b`）
 * - 先頭の `./` を**繰り返し**取り除く（`././a` → `a`）
 * - 末尾の `/` を取り除く（ルート `/` 自身は空文字になる）
 * - 先頭の `/` を**繰り返し**取り除く（`//a` → `a`）
 *
 * 先頭 `/` の除去を `while` にしてあるのが要点。`if` 一回だけだと
 * `//src/a.ts` が `/src/a.ts` のまま残り、前方一致が静かに外れる。
 */
export function normalizeRelPath(p: string | null | undefined): string {
  let out = String(p ?? '').replace(/\\/g, '/');
  out = out.replace(/\/{2,}/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  while (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  while (out.startsWith('/')) out = out.slice(1);
  return out;
}

/**
 * repoRoot 配下の絶対パス表記をリポジトリ相対へ直したうえで正規化する。
 *
 * LLM や各種収集処理は絶対パスと相対パスを混ぜて返してくるため、
 * 突き合わせの前にここを通す。repoRoot 配下でなければ単純正規化だけ行う。
 */
export function normalizeRepoRelPath(
  p: string | null | undefined,
  repoRoot?: string | null,
): string {
  let out = String(p ?? '').replace(/\\/g, '/');
  if (repoRoot !== undefined && repoRoot !== null && repoRoot !== '') {
    const root = String(repoRoot).replace(/\\/g, '/').replace(/\/+$/, '');
    if (root !== '' && out.startsWith(`${root}/`)) out = out.slice(root.length + 1);
  }
  return normalizeRelPath(out);
}

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
