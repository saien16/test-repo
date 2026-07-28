/**
 * 脆弱性ヒートマップ。
 *
 * 「アーキテクチャ構成要素 × 脆弱性カテゴリ」の格子に対して、
 * 2つの独立した層を重ね合わせる:
 *
 *   実測層 (observed) — 実際に検出された Finding 由来。事実。
 *   想定層 (inferred) — CWEカタログとスタック構成から導かれる想定リスク。推測。
 *
 * 2層に分ける理由は、両者の食い違いにこそ価値があるため:
 *
 *   実測 高 / 想定 高 → 予想どおりの弱点。優先的に直す
 *   実測 高 / 想定 低 → 想定外。設計レビューの見落としを示唆
 *   実測 低 / 想定 高 → 死角(blind spot)。本当に安全なのか、
 *                        単にスキャンが届いていないだけなのか要確認
 *   実測 低 / 想定 低 → 現時点で懸念薄
 *
 * 3つ目の象限（死角）を可視化することが、このヒートマップの主目的である。
 * 単に検出結果を色分けするだけなら Finding 一覧で足りる。
 */

import type { Claim } from './evidence.js';

/** 弱点カテゴリ。CWEを人が扱える粒度に畳んだもの */
export interface WeaknessCategory {
  id: string;
  /** 表示名。例: 'インジェクション' */
  name: string;
  /** このカテゴリに属する代表的なCWE ID */
  cweIds: string[];
  /** OWASP Top 10 2021 のカテゴリ（対応があれば） */
  owasp?: string;
}

export type CellBasis =
  /** 実際の検出があり、かつ想定リスクも高い */
  | 'both'
  /** 検出のみ（想定外の発見） */
  | 'observed-only'
  /** 想定のみ、検出なし（＝死角の候補） */
  | 'inferred-only'
  /** どちらも無し */
  | 'none';

export interface HeatmapCell {
  componentId: string;
  categoryId: string;

  /**
   * 実測リスク 0..100。検出された Finding の CVSS と件数から算出。
   * 事実に基づく値なので Claim で包まない（引用は findingIds が兼ねる）。
   */
  observedRisk: number;
  /** このセルに寄与した Finding */
  findingIds: string[];
  /** このセルに関係する攻撃チェーン */
  chainIds: string[];

  /**
   * 想定リスク 0..100。CWEカタログの Likelihood/影響と、
   * 構成要素の露出度・技術スタックの適合性から導く。推測なので Claim。
   */
  inferredRisk: Claim<number>;

  basis: CellBasis;
}

/** 検出は無いが想定リスクが高い箇所＝死角 */
export interface BlindSpot {
  componentId: string;
  categoryId: string;
  /** 想定リスクの高さ 0..100 */
  inferredRisk: number;
  /** なぜ死角と判断したか */
  reasoning: string;
  /**
   * 死角の原因の切り分け。
   * 「スキャンが届いていない」のか「本当に該当コードが無い」のかで対応が変わる。
   */
  likelyCause:
    | 'not-scanned'        // 除外設定やレンズ未有効で走査していない
    | 'no-matching-lens'   // 該当カテゴリを見るレンズが無い
    | 'genuinely-absent'   // 該当する実装自体が無さそう
    | 'unknown';
  /** 確認すべきこと */
  recommendedAction: string;
}

export interface VulnerabilityHeatmap {
  /** 行: アーキテクチャ構成要素のID（順序を保持） */
  componentIds: string[];
  /** 列: 弱点カテゴリ */
  categories: WeaknessCategory[];
  cells: HeatmapCell[];
  blindSpots: BlindSpot[];

  /** 構成要素ごとの実測リスク合計（行方向の集計） */
  componentTotals: Record<string, { observed: number; inferred: number }>;
  /** カテゴリごとの実測リスク合計（列方向の集計） */
  categoryTotals: Record<string, { observed: number; inferred: number }>;

  /**
   * このヒートマップ全体がどれだけ推測に依存しているか 0..1。
   * 1に近いほど「実測の裏付けが薄い＝話半分に読むべき」ことを意味する。
   */
  inferenceRatio: number;
}
