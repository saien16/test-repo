/**
 * 事実収集の共通部品。
 *
 * このコンポーネントの中核方針:
 *
 *   observed（事実）にしてよいのは「引用したテキストがその値をそのまま
 *   述べている」場合だけ。値を決めるのに業界知識や判断が要るなら
 *   inferred(heuristic)、根拠が皆無なら assumed か gaps に回す。
 *
 * 例:
 *   - Dockerfile の `FROM node:20` → ベースイメージ `node:20` は事実
 *   - そこから「実行基盤は AWS ECS」→ 推測（inferred）
 *   - 「インターネットに公開されている」→ 推測（inferred / 多くは LLM 側）
 *   - CI 設定が見つからない → 「CI なし」と断定せず gaps に「不明」と記録
 *
 * ここで作る ObservedFact は必ず Citation を伴う。引用を作れない情報は
 * ObservedFact にせず、LLM への文脈（非引用）としてのみ扱う。
 */

import type { ComponentKind } from '../types/architecture.js';
import type { Citation } from '../types/evidence.js';
import { normalizeRelPath } from '../util/path.js';

/** 引用抜粋の最大長。プロンプトとレポートが膨らまないよう切り詰める */
export const MAX_EXCERPT_CHARS = 160;

/** 観測事実の種別 */
export type FactKind =
  /** Dockerfile の FROM */
  | 'container.base-image'
  /** Dockerfile の EXPOSE */
  | 'container.exposed-port'
  /** Dockerfile の CMD / ENTRYPOINT */
  | 'container.entrypoint'
  /** docker-compose のサービス定義 */
  | 'compose.service'
  /** docker-compose の ports（ホスト側公開） */
  | 'compose.published-port'
  /** docker-compose の depends_on */
  | 'compose.depends-on'
  /** Kubernetes のリソース宣言 */
  | 'k8s.resource'
  /** Kubernetes コンテナイメージ */
  | 'k8s.container-image'
  /** Kubernetes Service の type */
  | 'k8s.service-type'
  /** Kubernetes Ingress のホスト・クラス */
  | 'k8s.ingress'
  /** Kubernetes Secret 参照 */
  | 'k8s.secret-ref'
  /** Helm チャート */
  | 'helm.chart'
  /** デプロイ設定ファイルの存在（serverless.yml / vercel.json など） */
  | 'platform.manifest'
  /** 関数・プロセス定義（serverless functions / Procfile） */
  | 'platform.process'
  /** クラウドプロバイダの明示的宣言 */
  | 'cloud.provider'
  /** IaC のリソース宣言 */
  | 'iac.resource'
  /** CI/CD 設定 */
  | 'cicd.workflow'
  /** CI/CD 中のデプロイ操作 */
  | 'cicd.deploy-step'
  /** バックエンド特定に使える依存ライブラリ */
  | 'dependency.client'
  /** 環境変数名の参照 */
  | 'env.variable'
  /** エントリポイント（ScanContext 由来） */
  | 'entrypoint'
  /** 秘密情報の受け渡し方法 */
  | 'secrets.mechanism';

/**
 * コードや設定ファイルから直接読み取れた事実 1 件。
 * value は citation の抜粋が述べている内容の restatement に留めること。
 */
export interface ObservedFact {
  kind: FactKind;
  value: string;
  citation: Citation;
  /** 補助情報（サービス名・ポートなど）。断定を含めないこと */
  detail?: Record<string, string>;
}

/**
 * 構成要素の候補シグナル。
 *
 * literal=true は「technology の文字列が引用テキストそのまま」であることを表し、
 * この場合のみ technology を observed にしてよい。
 * literal=false（例: npm の `pg` から PostgreSQL を導く）は inferred(heuristic)。
 */
export interface ServiceSignal {
  kind: ComponentKind;
  /** 構成要素の表示名 */
  name: string;
  /** 使用技術の記述 */
  technology: string;
  literal: boolean;
  /**
   * 製品を特定できない一般的なシグナル（環境変数名・ORM 経由など）。
   * 同種の具体的な構成要素があるならそちらに合流させる。
   */
  generic?: boolean;
  citation: Citation;
  /** literal=false のときの確信度 */
  confidence?: number;
  /** literal=false のときの導出理由 */
  reasoning?: string;
  /** 対応するソースパス（前方一致） */
  sourcePaths?: string[];
}

/** 事実収集の結果 */
export interface FactSet {
  facts: ObservedFact[];
  services: ServiceSignal[];
  /** 実際に読んで解析した設定ファイル */
  inspected: string[];
  /** 解析できなかった等の非致命的な問題 */
  warnings: string[];
}

/** 個々のパーサの出力 */
export interface ParseOutput {
  facts: ObservedFact[];
  services: ServiceSignal[];
  warnings: string[];
}

export function emptyOutput(): ParseOutput {
  return { facts: [], services: [], warnings: [] };
}

export function mergeOutput(target: ParseOutput, source: ParseOutput): void {
  target.facts.push(...source.facts);
  target.services.push(...source.services);
  target.warnings.push(...source.warnings);
}

// ---- テキストユーティリティ ----

export function truncate(text: string, limit = MAX_EXCERPT_CHARS): string {
  const s = String(text ?? '').trim();
  return s.length <= limit ? s : `${s.slice(0, limit)}…`;
}

/**
 * 比較用にパスを正規化する。
 * 実体は `util/path.ts` の {@link normalizeRelPath}（唯一の定義）。
 * 名前は architecture 側の呼び出し元互換のために残している。
 */
export { normalizeRelPath as normalizeRepoPath };

/** needle を含む最初の行番号（1始まり）。見つからなければ null */
export function findLineNumber(content: string, needle: string): number | null {
  if (needle === '') return null;
  const index = content.indexOf(needle);
  if (index < 0) return null;
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * ファイル内の needle を探して引用を作る。
 * 見つからなければ行番号・抜粋なしのファイル単位引用にフォールバックする
 * （存在しない行を引用するくらいなら粒度を落とす）。
 */
export function citationFor(file: string, content: string, needle: string): Citation {
  const line = findLineNumber(content, needle);
  if (line === null) return { file: normalizeRelPath(file) };
  const lines = content.split(/\r?\n/);
  const text = lines[line - 1] ?? needle;
  return { file: normalizeRelPath(file), line, excerpt: truncate(text) };
}

/**
 * YAML/JSON のキー定義行を探して引用を作る。
 * 単純な部分一致だと値の中の同名文字列（例: `postgres://db:5432`）を
 * 掴んでしまい、実在しない位置を引用することになるため行頭で照合する。
 */
export function citationForKey(file: string, content: string, key: string): Citation {
  const lines = content.split(/\r?\n/);
  const pattern = new RegExp(`^\\s*["']?${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i] ?? '';
    if (pattern.test(text)) {
      return { file: normalizeRelPath(file), line: i + 1, excerpt: truncate(text) };
    }
  }
  return { file: normalizeRelPath(file) };
}

/** ファイル全体を根拠とする引用（「そのファイルが存在すること」自体が事実の場合） */
export function fileCitation(file: string): Citation {
  return { file: normalizeRelPath(file) };
}

/** 同じ内容の引用を畳む */
export function dedupeCitations(citations: readonly Citation[]): Citation[] {
  const seen = new Set<string>();
  const out: Citation[] = [];
  for (const c of citations) {
    const key = `${c.file}#${c.line ?? '-'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}
