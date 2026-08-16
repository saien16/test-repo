/**
 * CIゲート。閾値超過でビルドを落とすための終了コードを決める。
 *
 * 判定は**独立した2軸**でできている:
 *
 *   1. 検出結果  … 閾値以上の Finding があるか        → 終了コード 1
 *   2. 実行の健全性 … 走査そのものが完走したか        → 終了コード 3
 *
 * 2軸目が無いと、認証エラーやネットワーク断で**全タスクが失敗しても
 * 「検出0件」になり CI が緑になる**。実際に APIキー未設定で走らせると、
 * 12タスク全滅にもかかわらず `--fail-on high` が 0 を返していた。
 * 「検出されなかった≠安全」を掲げるツールが自分でそれを破っていたので、
 * 健全性を先に見る。
 *
 * 健全性の軸は `failOn` からは影響を受けない。`failOn: 'never'` は
 * 「検出結果でビルドを落とさない」という指定であって、
 * 「壊れた走査を成功として報告してよい」という指定ではないため。
 * 明示的に無効化したい場合は `failOnIncompleteScan: false`。
 */

import type { VulnScanConfig } from '../types/config.js';
import type { Finding } from '../types/finding.js';
import type { ScanHealth } from '../types/health.js';
import type { ScanResult } from '../types/report.js';
import { isGateTarget, severityRank } from './severity.js';

/**
 * 終了コードの意味。CI設定から参照できるように公開する。
 *
 * 1 と 3 を分けているのは、CI側で「脆弱性が出た」と
 * 「スキャナが走らなかった」に別の対応（前者はレビュー、
 * 後者は設定・認証の修復）を割り当てられるようにするため。
 */
export const EXIT_CODES = {
  /** 閾値以上の検出が無く、走査は完走した */
  clean: 0,
  /** 閾値以上の検出があった */
  findings: 1,
  /** 走査が完走しなかった（検出0件に意味が無い） */
  incompleteScan: 3,
} as const;

/** ゲート判定の内訳。CLI表示や検証に使う。 */
export interface GateDecision {
  exitCode: number;
  /** 閾値を超えたFindingのID */
  offendingIds: string[];
  /** 判定に使った閾値 */
  threshold: VulnScanConfig['failOn'];
  /** 新規のみを対象にしたか */
  newOnly: boolean;
  /** 走査が完走しなかったことが理由か（`exitCode === 3`） */
  blockedByHealth: boolean;
  reason: string;
}

/**
 * 走査が完走しなかったことによるゲート判定。健全なら null。
 *
 * 検出結果より先に評価する。「見られなかった」状態で件数を語っても
 * 意味が無く、利用者に伝えるべきなのは件数ではなく走査の破綻だから。
 */
function evaluateHealthGate(
  health: ScanHealth,
  config: VulnScanConfig,
): Pick<GateDecision, 'exitCode' | 'blockedByHealth' | 'reason'> | null {
  if (health.zeroFindingsIsMeaningful) return null;
  if (config.failOnIncompleteScan === false) return null;

  return {
    exitCode: EXIT_CODES.incompleteScan,
    blockedByHealth: true,
    reason:
      `走査が完走しませんでした（${health.level}）: ${health.reason}` +
      ' 検出件数の多寡にかかわらず、この結果を「安全」と解釈しないでください。',
  };
}

/**
 * ゲート判定の詳細を返す。
 *
 * - 走査が完走していなければ、検出件数を見る前に 3 を返す（`failOn` に関わらず）。
 * - `failOn: 'never'` なら検出結果によるゲートは適用しない。
 * - `failOnNewOnly` が真なら `diffStatus === 'new'` のみを対象にする。
 * - 修正済み・誤検知・受容済み(accepted)は常に対象外。
 */
export function evaluateGate(result: ScanResult, config: VulnScanConfig): GateDecision {
  const threshold = config.failOn;
  const newOnly = config.failOnNewOnly === true;

  const unhealthy = evaluateHealthGate(result.health, config);
  if (unhealthy) {
    return { ...unhealthy, offendingIds: [], threshold, newOnly };
  }

  if (threshold === 'never') {
    return {
      exitCode: EXIT_CODES.clean,
      offendingIds: [],
      threshold,
      newOnly,
      blockedByHealth: false,
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
      exitCode: EXIT_CODES.clean,
      offendingIds: [],
      threshold,
      newOnly,
      blockedByHealth: false,
      reason: `閾値(${threshold})以上の${scope}はありません。`,
    };
  }

  return {
    exitCode: EXIT_CODES.findings,
    offendingIds: candidates.map((f) => f.id),
    threshold,
    newOnly,
    blockedByHealth: false,
    reason: `閾値(${threshold})以上の${scope}が ${candidates.length} 件あります。`,
  };
}

/**
 * 終了コードのみを返す薄いラッパ。
 * 走査が完走していなければ 3、閾値以上が存在すれば 1、それ以外は 0。
 */
export function determineExitCode(result: ScanResult, config: VulnScanConfig): number {
  return evaluateGate(result, config).exitCode;
}
