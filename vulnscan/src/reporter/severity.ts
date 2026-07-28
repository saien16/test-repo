/**
 * 深刻度まわりの共通ユーティリティ。
 * 各フォーマッタとCIゲートで解釈がぶれないよう、ここに一元化する。
 */

import type { Severity } from '../types/context.js';
import type { Finding } from '../types/finding.js';

/** 表示・集計で常にこの順序を使う（高い順） */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** 比較用の数値ランク。大きいほど深刻。 */
const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

/** レポート文言用の日本語ラベル */
export const SEVERITY_LABEL_JA: Record<Severity, string> = {
  critical: '緊急',
  high: '高',
  medium: '中',
  low: '低',
  info: '情報',
};

/** 優先度スコア算出に使う深刻度の重み */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 80,
  high: 50,
  medium: 25,
  low: 10,
  info: 0,
};

/** 全キーを 0 で初期化した深刻度カウンタ */
export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * 「今このコードベースに現存する」Findingか。
 *
 * ベースライン差分で `fixed` になったものは既に直っているため集計から外す。
 * 誤検知と確定したものも同様。抑制リスト由来の件数は `suppressedCount` で
 * 別途数えるため、ここでは扱わない。
 */
export function isActiveFinding(finding: Finding): boolean {
  return finding.diffStatus !== 'fixed' && finding.status !== 'false-positive';
}

/**
 * CIゲートの評価対象か。
 * 修正済み・誤検知に加えて、明示的に受容(accepted)されたリスクもビルドを
 * 落とす理由にはしない。
 */
export function isGateTarget(finding: Finding): boolean {
  if (finding.diffStatus === 'fixed') return false;
  return (
    finding.status !== 'false-positive' &&
    finding.status !== 'accepted' &&
    finding.status !== 'fixed'
  );
}

/** SARIF の result.level へのマッピング */
export function toSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

/**
 * GitHub Code Scanning が読む `security-severity` 用の数値。
 * CVSS基本値があればそれを、無ければ深刻度から代表値を当てる。
 */
export function securitySeverityValue(finding: Finding): number {
  const score = finding.cvss?.baseScore;
  if (typeof score === 'number' && Number.isFinite(score) && score > 0) {
    return Math.round(score * 10) / 10;
  }
  switch (finding.severity) {
    case 'critical':
      return 9.5;
    case 'high':
      return 7.5;
    case 'medium':
      return 5.0;
    case 'low':
      return 2.5;
    default:
      return 0.0;
  }
}

/** HTML/CLI で使う深刻度の代表色（16進） */
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: '#b3123c',
  high: '#c2410c',
  medium: '#a16207',
  low: '#0369a1',
  info: '#4b5563',
};

/** ダークテーマ用の深刻度色 */
export const SEVERITY_HEX_DARK: Record<Severity, string> = {
  critical: '#ff6b8b',
  high: '#ff9f5a',
  medium: '#e5c04b',
  low: '#67c2f0',
  info: '#a3adba',
};
