/**
 * パイプライン制御。各ステージを順に呼び、共有モデルを育てていく。
 *
 *   ① collectContext     → ScanContext
 *   ② analyze            → RawFinding[]
 *   ③ manageFindings     → Finding[]（正規化・CVSS・差分）
 *   ④ analyzeKillChains  → AttackChain[]
 *   ⑤ inferArchitecture  → ArchitectureModel（事実収集＋推測）
 *   ⑥ buildHeatmap       → VulnerabilityHeatmap（実測層×想定層）
 *   ⑦ analyzeResult      → AnalyzedReport（レポーター側で実施）
 *
 * 各ステージの失敗は errors に積み、可能な限り部分結果を返す。
 * 途中で落ちても「何も出ない」より「途中まで出る」方が有用なため。
 *
 * ⑤⑥ を④の後に置いているのは、ヒートマップが Finding と AttackChain の
 * 両方を実測層の材料にするため。⑤が失敗すると⑥は成立しない（推測の土台が
 * 無いのに想定リスクを語れない）ので、その場合は⑥を飛ばして undefined を返す。
 */

import { collectContext } from '../context/index.js';
import { analyze } from '../analyzer/index.js';
import { manageFindings } from '../vuln/index.js';
import { analyzeKillChains } from '../killchain/index.js';
import { inferArchitecture } from '../architecture/index.js';
import { buildHeatmap } from '../heatmap/index.js';
import { summarize } from '../reporter/index.js';
import { LlmClient } from '../llm/client.js';
import type { VulnScanConfig } from '../types/config.js';
import type { ScanResult } from '../types/report.js';
import type { AttackChain } from '../types/killchain.js';
import type { ArchitectureModel } from '../types/architecture.js';
import type { VulnerabilityHeatmap } from '../types/heatmap.js';

/**
 * パイプラインのステージ順。**ここが唯一の真実**。
 *
 * 型を配列から導出しているので、ステージを足すときはこの配列に足すだけで
 * `Record<StageName, _>` 群（CLI のラベル表・アニメーションの語彙表など）が
 * 一斉にコンパイルエラーになる。
 * 以前は配列と union が別々に手書きされており、ステージ追加時に
 * 表示順の配列へ足し忘れても型エラーが出ず、静かに漏れたことがある。
 */
export const STAGE_SEQUENCE = [
  'context',
  'analyze',
  'vuln',
  'killchain',
  'architecture',
  'heatmap',
  'report',
] as const;

export type StageName = (typeof STAGE_SEQUENCE)[number];

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
  //    LLM を並列実行する唯一のステージなので、進捗を hooks へ流して
  //    「12/87 チャンク」のような処理件数を表示できるようにする。
  hooks?.onStageStart?.('analyze');
  const analyzed = await analyze(context, llm, config, {
    ...(hooks?.onProgress
      ? { onProgress: (p) => hooks.onProgress?.('analyze', p.completed, p.total) }
      : {}),
  });
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

  // ⑤ アーキテクチャ・デプロイスタック推定
  //    事実（マニフェスト解析）と推測（LLM）を分けて収集する。
  //    LLM が失敗しても事実部分は残るので、model は常に得られる。
  let architecture: ArchitectureModel | undefined;
  if (config.architecture) {
    hooks?.onStageStart?.('architecture');
    const arch = await inferArchitecture(context, llm, config);
    architecture = arch.model;
    errors.push(...arch.errors);
    hooks?.onStageEnd?.(
      'architecture',
      `${architecture.components.length} 構成要素` +
        `（事実 ${architecture.evidence.observed} / 推測 ${architecture.evidence.inferred}）`,
    );
  }

  // ⑥ ヒートマップ（実測層×想定層の重ね合わせ）
  //    アーキテクチャが無ければ行が作れないので生成しない。
  //    純粋関数なので失敗しない想定だが、念のため囲って部分結果を守る。
  let heatmap: VulnerabilityHeatmap | undefined;
  if (config.heatmap && architecture) {
    hooks?.onStageStart?.('heatmap');
    try {
      heatmap = buildHeatmap({
        architecture,
        findings: managed.findings,
        chains,
        context,
        config,
      });
      hooks?.onStageEnd?.(
        'heatmap',
        `死角 ${heatmap.blindSpots.length} 件` +
          `（推測依存度 ${(heatmap.inferenceRatio * 100).toFixed(0)}%）`,
      );
    } catch (err) {
      errors.push(
        `ヒートマップの生成に失敗しました: ${err instanceof Error ? err.message : String(err)}`,
      );
      hooks?.onStageEnd?.('heatmap', '生成できませんでした');
    }
  }

  const summary = summarize(
    { context, findings: managed.findings, chains, errors },
    {
      durationMs: Date.now() - startedAt,
      suppressedCount: managed.suppressedCount,
      tokenUsage: llm.getUsage(),
    },
  );

  return {
    context,
    findings: managed.findings,
    chains,
    ...(architecture ? { architecture } : {}),
    ...(heatmap ? { heatmap } : {}),
    summary,
    errors,
  };
}
