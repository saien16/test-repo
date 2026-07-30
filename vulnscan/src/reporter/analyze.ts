/**
 * 分析フェーズ。レポーターの核心。
 *
 * 「検出結果の羅列」から「意思決定に使える読み物」への変換を、
 * 次の役割分担で行う:
 *
 *   機械的に導出する（priority.ts / summarize.ts）
 *     - サマリ集計、深刻度分布
 *     - Finding × AttackChain の相関（チョークポイント・複数チェーン登場）
 *     - prioritizedActions の順序と、同一修正で解決するFindingの集約
 *     - keyFindings のベースライン（事実の列挙）
 *
 *   LLMに任せる（narrative.ts）
 *     - executiveSummary（非技術者向けの3-5文）
 *     - riskNarrative（筋の通ったリスクのストーリー）
 *     - trendNarrative（前回との比較コメント）
 *
 * こうすると LLM が使えなくても数字と優先順位は必ず出る。
 */

import type { LlmClient } from '../llm/client.js';
import type { VulnScanConfig } from '../types/config.js';
import type { AnalyzedReport, ScanResult } from '../types/report.js';
import {
  buildFindingSignals,
  buildKeyFindings,
  buildPrioritizedActions,
  rankSignals,
  type FindingSignal,
  type PrioritizedAction,
} from './priority.js';
import { generateNarrative, type NarrativeInput } from './narrative.js';
import { summarize } from './summarize.js';

/**
 * 分析の機械的な部分だけを実行する（LLM不要・純粋関数）。
 * テストやフォールバック経路から単独で使える。
 */
export interface MechanicalAnalysis {
  signals: Map<string, FindingSignal>;
  ranked: FindingSignal[];
  actions: PrioritizedAction[];
  keyFindings: string[];
  hasBaseline: boolean;
}

/**
 * ベースライン（前回スキャン結果）があったと判断できるか。
 * 全件が new なら初回スキャンとみなし、前回比較コメントは出さない。
 */
function detectBaseline(result: ScanResult): boolean {
  return result.findings.some((f) => f.diffStatus === 'persistent' || f.diffStatus === 'fixed');
}

export function analyzeMechanically(result: ScanResult): MechanicalAnalysis {
  const signals = buildFindingSignals(result.findings, result.chains);
  const ranked = rankSignals(signals);
  const actions = buildPrioritizedActions(result.findings, result.chains, signals);
  const keyFindings = buildKeyFindings(ranked, result.chains, actions, {
    health: result.health,
  });
  return { signals, ranked, actions, keyFindings, hasBaseline: detectBaseline(result) };
}

/**
 * 他機能の出力を横断分析し、レポートの中間表現を作る。
 *
 * この関数は例外を投げない。LLMが拒否・予算切れ・障害のいずれで失敗しても、
 * 機械生成の文章に切り替えてレポートを成立させる。
 */
export async function analyzeResult(
  result: ScanResult,
  llm: LlmClient,
  config: VulnScanConfig,
): Promise<AnalyzedReport> {
  const mechanical = analyzeMechanically(result);

  // summary は原則として入力のものを尊重するが、
  // 欠落している場合（オーケストレータが埋め忘れた場合）はここで作り直す。
  const summary = result.summary ?? summarize(result, {
    durationMs: 0,
    suppressedCount: 0,
    tokenUsage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  });

  const input: NarrativeInput = {
    context: result.context,
    summary,
    ranked: mechanical.ranked,
    chains: result.chains,
    actions: mechanical.actions,
    hasBaseline: mechanical.hasBaseline,
    errors: result.errors ?? [],
    health: result.health,
  };

  const outcome = await generateNarrative(input, mechanical.keyFindings, llm, config);
  const { narrative, fallbackReason } = outcome;

  // フォールバックした場合は、その事実をレポート本文に残す。
  // 「LLMが書いたのか機械が書いたのか」が読み手に分からないのは不誠実。
  const keyFindings = fallbackReason
    ? [...narrative.keyFindings, `※ ${fallbackReason}`]
    : narrative.keyFindings;

  const report: AnalyzedReport = {
    executiveSummary: narrative.executiveSummary,
    keyFindings,
    prioritizedActions: mechanical.actions,
    riskNarrative: narrative.riskNarrative,
    summary,
  };

  if (narrative.trendNarrative !== null && narrative.trendNarrative !== '') {
    report.trendNarrative = narrative.trendNarrative;
  }

  return report;
}
