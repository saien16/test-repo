/**
 * CIゲート。閾値超過でビルドを落とすための終了コードを決める。
 */

import type { VulnScanConfig } from '../types/config.js';
import type { Finding } from '../types/finding.js';
import type { ScanResult } from '../types/report.js';
import { isGateTarget, severityRank } from './severity.js';

/** ゲート判定の内訳。CLI表示や検証に使う。 */
export interface GateDecision {
  exitCode: number;
  /** 閾値を超えたFindingのID */
  offendingIds: string[];
  /** 判定に使った閾値 */
  threshold: VulnScanConfig['failOn'];
  /** 新規のみを対象にしたか */
  newOnly: boolean;
  reason: string;
}

/**
 * ゲート判定の詳細を返す。
 *
 * - `failOn: 'never'` なら無条件に 0。
 * - `failOnNewOnly` が真なら `diffStatus === 'new'` のみを対象にする。
 * - 修正済み・誤検知・受容済み(accepted)は常に対象外。
 */
export function evaluateGate(result: ScanResult, config: VulnScanConfig): GateDecision {
  const threshold = config.failOn;
  const newOnly = config.failOnNewOnly === true;

  if (threshold === 'never') {
    return {
      exitCode: 0,
      offendingIds: [],
      threshold,
      newOnly,
      reason: 'failOn が never のためゲートを適用しません。',
    };
  }

  const minRank = severityRank(threshold);
  const candidates: Finding[] = result.findings.filter((finding) => {
    if (!isGateTarget(finding)) return false;
    if (newOnly && finding.diffStatus !== 'new') return false;
    return severityRank(finding.severity) >= minRank;
  });

  const scope = newOnly ? '新規Finding' : 'Finding';
  if (candidates.length === 0) {
    return {
      exitCode: 0,
      offendingIds: [],
      threshold,
      newOnly,
      reason: `閾値(${threshold})以上の${scope}はありません。`,
    };
  }

  return {
    exitCode: 1,
    offendingIds: candidates.map((f) => f.id),
    threshold,
    newOnly,
    reason: `閾値(${threshold})以上の${scope}が ${candidates.length} 件あります。`,
  };
}

/**
 * 終了コードのみを返す薄いラッパ。
 * 閾値以上が存在すれば 1、それ以外は 0。
 */
export function determineExitCode(result: ScanResult, config: VulnScanConfig): number {
  return evaluateGate(result, config).exitCode;
}
