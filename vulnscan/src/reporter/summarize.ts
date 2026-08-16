/**
 * サマリの機械的集計。
 *
 * ここは純粋関数であり、LLMには一切依存しない。
 * レポート本文の文言が揺れても、数字だけは常に同じ計算で出る。
 */

import type { ScanResult, ScanSummary } from '../types/report.js';
import { emptySeverityCounts, isActiveFinding } from './severity.js';

export interface SummarizeExtra {
  durationMs: number;
  suppressedCount: number;
  tokenUsage: ScanSummary['tokenUsage'];
}

/**
 * `ScanResult` の材料からサマリを組み立てる。
 *
 * 集計方針:
 *  - `totalFindings` / `bySeverity` / `byCategory` / `maxCvssScore` は
 *    「今このコードベースに現存するもの」だけを数える。
 *    つまり `diffStatus === 'fixed'`（前回あって今回消えた）と
 *    `status === 'false-positive'`（誤検知確定）は除外する。
 *  - `newCount` / `fixedCount` / `persistentCount` はベースライン差分の
 *    実態を示す指標なので、除外せず全件を対象に数える。
 */
export function summarize(
  // 実際に読むフィールドだけを要求する。`Omit<ScanResult, 'summary'>` にしていると
  // ScanResult へ無関係なフィールドを足すたびに呼び出し側が壊れる。
  result: Pick<ScanResult, 'context' | 'findings' | 'chains'>,
  extra: SummarizeExtra,
): ScanSummary {
  const bySeverity = emptySeverityCounts();
  const byCategory: Record<string, number> = {};

  let totalFindings = 0;
  let maxCvssScore = 0;
  let newCount = 0;
  let fixedCount = 0;
  let persistentCount = 0;

  for (const finding of result.findings) {
    switch (finding.diffStatus) {
      case 'new':
        newCount++;
        break;
      case 'fixed':
        fixedCount++;
        break;
      case 'persistent':
        persistentCount++;
        break;
      default:
        break;
    }

    if (!isActiveFinding(finding)) continue;

    totalFindings++;
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;

    const category = finding.category === '' ? '(未分類)' : finding.category;
    byCategory[category] = (byCategory[category] ?? 0) + 1;

    const score = finding.cvss?.baseScore;
    if (typeof score === 'number' && Number.isFinite(score) && score > maxCvssScore) {
      maxCvssScore = score;
    }
  }

  return {
    totalFindings,
    bySeverity,
    byCategory,
    newCount,
    fixedCount,
    persistentCount,
    suppressedCount: Math.max(0, Math.trunc(extra.suppressedCount)),
    chainCount: result.chains.length,
    maxCvssScore: Math.round(maxCvssScore * 10) / 10,
    filesScanned: result.context.files.length,
    linesScanned: result.context.files.reduce((sum, f) => sum + (f.lines ?? 0), 0),
    durationMs: Math.max(0, Math.round(extra.durationMs)),
    tokenUsage: {
      input: extra.tokenUsage.input,
      output: extra.tokenUsage.output,
      cacheRead: extra.tokenUsage.cacheRead,
      cacheWrite: extra.tokenUsage.cacheWrite,
    },
  };
}
