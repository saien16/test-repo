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
 * ただし部分結果を返すなら、**どこまで見たのか**も一緒に返さなければならない。
 * ②の実行統計から `ScanHealth` を算出して結果に載せるのはそのため。
 * これが無いと「全タスク失敗・検出0件」が「検出0件」と区別できず、
 * CIゲートもレポート文言も「安全」と誤って報告する。
 *
 * ④⑤ にデータ依存は無いので並列に走らせる。両者の結果を使うのは⑥だけ。
 * ⑤が失敗すると⑥は成立しない（推測の土台が無いのに想定リスクを語れない）ので、
 * その場合は⑥を飛ばして undefined を返す。
 *
 * 進捗(onProgress)を出すのは ①②③④ の4ステージ:
 *   ① 前処理したファイル数      ② 走査タスク数 → 自己検証の候補数
 *   ③ OSV の依存脆弱性取得数    ④ 候補グループ数（1グループ=LLM1回）
 * ⑤⑦ は時間の大半が LLM 1回の応答待ちで、内側に観測できる刻みが無い。
 * ⑥ は純粋な同期関数で一瞬終わる。バーが即100%のまま固まるのは
 * 「あと何割か」を偽ることになるので、これらは意図的に進捗を出さない
 * （詳細は `types/progress.ts` の {@link STAGES_WITHOUT_PROGRESS}）。
 */

import { collectContext } from '../context/index.js';
import { analyze, ANALYZE_PHASES } from '../analyzer/index.js';
import { manageFindings } from '../vuln/index.js';
import { isOperatorProvidedPath } from '../types/config.js';
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
import { assessAnalysisHealth } from '../types/health.js';
import type { StageProgress } from '../types/progress.js';

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

export type { StageProgress } from '../types/progress.js';

export interface ScanHooks {
  onStageStart?: (stage: StageName, detail?: string) => void;
  onStageEnd?: (stage: StageName, detail?: string) => void;
  onProgress?: (stage: StageName, progress: StageProgress) => void;
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

  /**
   * ステージ名を束ねた進捗コールバックを作る。
   * hooks に onProgress が無いときは undefined を返し、
   * 各ステージ側の「進捗を集める処理」ごと省略させる。
   */
  const progressFor = (stage: StageName): ((p: StageProgress) => void) | undefined =>
    hooks?.onProgress ? (p) => hooks.onProgress?.(stage, p) : undefined;

  // ① コンテキスト収集
  hooks?.onStageStart?.('context');
  const contextProgress = progressFor('context');
  const context = await collectContext(repoRoot, config, {
    ...(contextProgress ? { onProgress: contextProgress } : {}),
  });
  errors.push(...context.warnings);
  hooks?.onStageEnd?.('context', `${context.files.length} ファイル`);

  // ② ソースコード分析（LLM）
  //    走査(レンズ×チャンク)と自己検証(候補)の2局面があり、母数が変わる。
  //    局面名も一緒に渡さないと、バーが巻き戻ったように見える。
  hooks?.onStageStart?.('analyze');
  const analyzed = await analyze(context, llm, config, {
    ...(hooks?.onProgress
      ? {
          // 局面(走査/自己検証)ごとに単位も母数も違う。両方そのまま渡す。
          onProgress: (p) =>
            hooks.onProgress?.('analyze', {
              completed: p.completed,
              total: p.total,
              unit: ANALYZE_PHASES[p.phase].unit,
              phase: ANALYZE_PHASES[p.phase].label,
            }),
        }
      : {}),
  });
  errors.push(...analyzed.errors);
  // 「何件見つけたか」と「何件のタスクを走らせられたか」を両方出す。
  // 前者だけを見せると、全滅した走査が「0件＝安全」に見えてしまう。
  const health = assessAnalysisHealth(analyzed.stats);
  hooks?.onStageEnd?.(
    'analyze',
    `${analyzed.findings.length} 件の候補` +
      `（分析 ${analyzed.stats.succeeded}/${analyzed.stats.total} タスク成功）`,
  );
  if (health.level !== 'complete') errors.push(`走査の健全性: ${health.reason}`);

  // ③ 脆弱性情報管理（正規化・CVSS・重複統合・差分）
  hooks?.onStageStart?.('vuln');
  const vulnProgress = progressFor('vuln');
  const managed = await manageFindings(analyzed.findings, context, config, {
    ...(vulnProgress ? { onProgress: vulnProgress } : {}),
    // CISA KEV 照合。取得できなければ注記が付かないだけで、走査は続行する
    matchKev: config.kev !== false,
    kev: {
      catalogPath: config.kevPath,
      // 既定パスに無いのは正常なので取得へ進む。--kev-file の明示指定ならエラーにする
      fallbackToFetch: !isOperatorProvidedPath(config, 'kevPath'),
    },
  });
  errors.push(...managed.errors);
  hooks?.onStageEnd?.('vuln', `${managed.findings.length} 件に正規化`);

  // ④⑤ キルチェーン分析とアーキテクチャ推定
  //    両者にデータ依存は無く（どちらも ScanContext と Finding しか読まない）、
  //    結果を使うのは ⑥ buildHeatmap だけなので並列に走らせる。
  //    共有する LlmClient の可変状態は使用量カウンタと予算判定だけなので、
  //    並行実行しても壊れない（予算打ち切りの精度がわずかに落ちるだけ）。
  //    その代わり進捗フックの呼び出し順は乱れる。表示が前後するのは許容する。
  let chains: AttackChain[] = [];
  let architecture: ArchitectureModel | undefined;

  const killChainStage = async (): Promise<void> => {
    if (!config.killChain || managed.findings.length === 0) return;
    hooks?.onStageStart?.('killchain');
    const kcProgress = progressFor('killchain');
    const kc = await analyzeKillChains(managed.findings, context, llm, config, {
      ...(kcProgress ? { onProgress: kcProgress } : {}),
    });
    chains = kc.chains;
    errors.push(...kc.errors);
    hooks?.onStageEnd?.('killchain', `${chains.length} 本の攻撃経路`);
  };

  // 事実（マニフェスト解析）と推測（LLM）を分けて収集する。
  // LLM が失敗しても事実部分は残るので、model は常に得られる。
  const architectureStage = async (): Promise<void> => {
    if (!config.architecture) return;
    hooks?.onStageStart?.('architecture');
    const arch = await inferArchitecture(context, llm, config);
    architecture = arch.model;
    errors.push(...arch.errors);
    hooks?.onStageEnd?.(
      'architecture',
      `${arch.model.components.length} 構成要素` +
        `（事実 ${arch.model.evidence.observed} / 推測 ${arch.model.evidence.inferred}）`,
    );
  };

  await Promise.all([killChainStage(), architectureStage()]);

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
    { context, findings: managed.findings, chains },
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
    health,
    errors,
  };
}
