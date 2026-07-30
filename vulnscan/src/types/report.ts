/**
 * ⑤ レポーターの入出力モデル。
 */

import type { Finding, Severity } from './finding.js';
import type { AttackChain } from './killchain.js';
import type { ScanContext } from './context.js';
import type { ArchitectureModel } from './architecture.js';
import type { VulnerabilityHeatmap } from './heatmap.js';
import type { ScanHealth } from './health.js';

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  /** ベースライン差分 */
  newCount: number;
  fixedCount: number;
  persistentCount: number;
  /** 誤検知として抑制された件数 */
  suppressedCount: number;
  chainCount: number;
  /** 最も高いCVSSスコア */
  maxCvssScore: number;
  filesScanned: number;
  durationMs: number;
  /** LLM利用トークン数 */
  tokenUsage: {
    input: number;
    output: number;
    cacheRead: number;
    cacheWrite: number;
  };
}

/**
 * ⑤への入力。レポーターはこれを「分析」して
 * 読みやすいレポートに再構成する（単なる羅列ではない）。
 */
export interface ScanResult {
  context: ScanContext;
  findings: Finding[];
  chains: AttackChain[];
  /**
   * 推定したシステムアーキテクチャとデプロイスタック。
   * config.architecture が false なら undefined。
   * 各項目は Claim<T> で包まれており、事実か推測かを区別できる。
   */
  architecture?: ArchitectureModel;
  /**
   * 脆弱性ヒートマップ。architecture が無ければ生成できないので undefined。
   * 実測層(事実)と想定層(推測)の2層を持つ。
   */
  heatmap?: VulnerabilityHeatmap;
  summary: ScanSummary;
  /**
   * 走査が完走したかどうか。**検出結果とは独立**の軸。
   *
   * `findings` が空であることの意味はここを見ないと決まらない。
   * `health.zeroFindingsIsMeaningful` が false のときの0件は
   * 「安全」ではなく「判定できなかった」を意味する。
   * CIゲートとレポート文言の両方がこれを参照する。
   */
  health: ScanHealth;
  /** スキャン中に発生したエラー（部分的失敗の記録） */
  errors: string[];
}

export type ReportFormat = 'cli' | 'json' | 'sarif' | 'markdown' | 'html';

export interface ReportOptions {
  format: ReportFormat;
  /** 出力先パス。未指定なら stdout */
  outputPath?: string;
  /** 色付きCLI出力 */
  color: boolean;
  /** info レベルまで含めるか */
  verbose: boolean;
}

/**
 * レポーターが生成する「分析済みの読み物」。
 * 各フォーマッタはこの中間表現をレンダリングする。
 */
export interface AnalyzedReport {
  /** 経営層向け: 3-5文の要約 */
  executiveSummary: string;
  /** 今回のスキャンで最も重要な所見 */
  keyFindings: string[];
  /** 推奨される対応順序（chokePointとseverityから導出） */
  prioritizedActions: {
    order: number;
    action: string;
    /** 対応することで解決する Finding / Chain */
    resolves: { findings: string[]; chains: string[] };
    /** 見積もり難易度 */
    effort: 'low' | 'medium' | 'high';
    rationale: string;
  }[];
  /** リスクの全体像を説明する文章 */
  riskNarrative: string;
  /** 前回スキャンとの比較コメント（ベースラインがある場合） */
  trendNarrative?: string;
  summary: ScanSummary;
}
