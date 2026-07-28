/**
 * Finding の指紋（fingerprint）と安定IDの生成。
 *
 * 設計方針:
 *   指紋は「ファイルパス + CWE + 正規化したコード片」から算出し、**行番号を含めない**。
 *   行番号を含めると、無関係な行の追加・削除で指紋が変わり、
 *   ベースライン差分で既存の指摘が毎回 new として再出現してしまうため。
 */

import { createHash } from 'node:crypto';

// ブロックコメント（C系ブロックコメント / HTMLコメント / Pythonのドキュメント文字列）
const BLOCK_COMMENT_RE = /\/\*[\s\S]*?\*\/|<!--[\s\S]*?-->|"""[\s\S]*?"""|'''[\s\S]*?'''/g;
// 行コメント（//, #, -- ）
const LINE_COMMENT_RE = /(?:\/\/|#|--)[^\n]*/g;

/**
 * コード片を指紋計算用に正規化する。
 *
 * - コメントを除去（コメント追記だけで別の指摘扱いにしないため）
 * - 引用符の種類を統一（フォーマッタによる ' ↔ " の入れ替えを吸収）
 * - 連続する空白を単一スペースへ畳む（インデント・改行位置の変更を吸収）
 *
 * コメント除去は正規表現によるヒューリスティックで、
 * 文字列リテラル中の `//` 等も落ちることがあるが、
 * 同じ入力に対して常に同じ結果になるため指紋用途では問題ない。
 */
export function normalizeCodeSnippet(code: string): string {
  if (!code) return '';
  return code
    .replace(BLOCK_COMMENT_RE, ' ')
    .replace(LINE_COMMENT_RE, ' ')
    .replace(/['`]/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

/** リポジトリルート相対の POSIX パスに正規化する */
export function normalizeFilePath(file: string, repoRoot?: string): string {
  let p = (file ?? '').replace(/\\/g, '/');
  if (repoRoot) {
    const root = repoRoot.replace(/\\/g, '/').replace(/\/+$/, '');
    if (root && p.startsWith(`${root}/`)) {
      p = p.slice(root.length + 1);
    }
  }
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  return p;
}

/** sha256 の16進文字列 */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * コード由来 Finding の指紋を計算する。
 * `ファイルパス | CWE | 正規化コード片` の sha256。
 */
export function computeFingerprint(params: {
  file: string;
  cwe: string;
  evidence: string;
  repoRoot?: string;
}): string {
  const file = normalizeFilePath(params.file, params.repoRoot);
  const code = normalizeCodeSnippet(params.evidence);
  return sha256Hex(`${file}|${params.cwe}|${code}`);
}

/**
 * 依存脆弱性 Finding の指紋。
 * バージョン番号は含めない（未修正のままバージョンだけ上がっても
 * 「継続中の同じ指摘」として扱えるようにするため）。
 */
export function computeDependencyFingerprint(params: {
  ecosystem: string;
  name: string;
  vulnId: string;
}): string {
  return sha256Hex(
    `dep|${params.ecosystem.toLowerCase()}|${params.name.toLowerCase()}|${params.vulnId.toUpperCase()}`,
  );
}

/**
 * 指紋から安定した短いIDを生成する。
 * 例: 'VS-3f9a2c1d4b5e'
 */
export function fingerprintToId(fingerprint: string): string {
  return `VS-${fingerprint.slice(0, 12)}`;
}
