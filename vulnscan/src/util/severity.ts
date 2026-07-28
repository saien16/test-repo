/**
 * 深刻度の比較規約。
 *
 * 「どの深刻度がどれだけ重いか」はレポート表示・CIゲート・Finding の統合
 * （どちらの深刻度を採用するか）のすべてが依存する共通の約束事である。
 * 以前は `reporter/severity.ts` / `vuln/normalize.ts` / `analyzer/verify.ts` に
 * 同じランク表が3つあり、片方だけ直すと解釈がずれる状態だったため、
 * ここを唯一の定義とする。
 *
 * 注記: `analyzer/verify.ts` のランク表は本統合の対象外（別担当）であり、
 * 現時点では未統合のまま残っている。
 */

import type { Severity } from '../types/context.js';

/** 比較用の数値ランク。大きいほど深刻。 */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** 深刻度の数値ランク。未知の値は 0（info 相当）として扱う。 */
export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

/** 深刻度の大小比較。a のほうが高ければ正、低ければ負。 */
export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}

/** 既知の深刻度か */
export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && value in SEVERITY_RANK;
}
