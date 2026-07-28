/**
 * パイプライン制御。5つのステージを順に呼び、共有モデルを育てていく。
 *
 *   ① collectContext   → ScanContext
 *   ② analyze          → RawFinding[]
 *   ③ manageFindings   → Finding[]（正規化・CVSS・差分）
 *   ④ analyzeKillChains→ AttackChain[]
 *   ⑤ analyzeResult    → AnalyzedReport（レポーター側で実施）
 *
 * 各ステージの失敗は errors に積み、可能な限り部分結果を返す。
 * 途中で落ちても「何も出ない」より「途中まで出る」方が有用なため。
 */

import { collectContext } from '../context/index.js';
import { analyze } from '../analyzer/index.js';
import { manageFindings } from '../vuln/index.js';
import { analyzeKillChains } from '../killchain/index.js';
import { summarize } from '../reporter/index.js';
import { LlmClient } from '../llm/client.js';
import type { VulnScanConfig } from '../types/config.js';
import type { ScanResult } from '../types/report.js';
import type { AttackChain } from '../types/killchain.js';

export type StageName = 'context' | 'analyze' | 'vuln' | 'killchain' | 'report';

export interface ScanHooks {
  onStageStart?: (stage: StageName, detail?: string) => void;
  onStageEnd?: (stage: StageName, detail?: string) => void;
  onProgress?: (stage: StageName, completed: number, total: number) => void;
}

export interface RunScanOptions {
  repoRoot: string;
  config: VulnScanConfig;
  llm: LlmClient;
  hooks?: ScanHooks;
}

export async function runScan(options: RunScanOptions): Promise<ScanResult> {
  const { repoRoot, config, llm, hooks } = options;
  const startedAt = Date.now();
  const errors: string[] = [];

  // ① コンテキスト収集
  hooks?.onStageStart?.('context');
  const context = await collectContext(repoRoot, config);
  errors.push(...context.warnings);
  hooks?.onStageEnd?.('context', `${context.files.length} ファイル`);

  // ② ソースコード分析（LLM）
  hooks?.onStageStart?.('analyze');
  const analyzed = await analyze(context, llm, config);
  errors.push(...analyzed.errors);
  hooks?.onStageEnd?.('analyze', `${analyzed.findings.length} 件の候補`);

  // ③ 脆弱性情報管理（正規化・CVSS・重複統合・差分）
  hooks?.onStageStart?.('vuln');
  const managed = await manageFindings(analyzed.findings, context, config);
  errors.push(...managed.errors);
  hooks?.onStageEnd?.('vuln', `${managed.findings.length} 件に正規化`);

  // ④ キルチェーン分析
  let chains: AttackChain[] = [];
  if (config.killChain && managed.findings.length > 0) {
    hooks?.onStageStart?.('killchain');
    const kc = await analyzeKillChains(managed.findings, context, llm, config);
    chains = kc.chains;
    errors.push(...kc.errors);
    hooks?.onStageEnd?.('killchain', `${chains.length} 本の攻撃経路`);
  }

  const summary = summarize(
    { context, findings: managed.findings, chains, errors },
    {
      durationMs: Date.now() - startedAt,
      suppressedCount: managed.suppressedCount,
      tokenUsage: llm.getUsage(),
    },
  );

  return { context, findings: managed.findings, chains, summary, errors };
}
