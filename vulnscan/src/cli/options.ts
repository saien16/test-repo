/**
 * scan サブコマンドのオプション定義と、設定への変換。
 *
 * `cli/index.ts` から分離してあるのは、エントリポイントを import すると
 * `program.parseAsync(process.argv)` が走ってしまい、テストから
 * フラグの配線（特にパス系フラグの出所が 'cli' になること）を
 * 検証できないため。
 */

import { Command, Option } from 'commander';
import type { VulnScanConfig } from '../types/config.js';
import type { ReportFormat } from '../types/report.js';

export interface CliOptions {
  format: ReportFormat;
  output?: string;
  failOn?: string;
  failOnNewOnly?: boolean;
  model?: string;
  effort?: VulnScanConfig['llm']['effort'];
  concurrency?: string;
  budget?: string;
  cache: boolean;
  killChain: boolean;
  selfVerify: boolean;
  architecture: boolean;
  heatmap: boolean;
  lens?: string[];
  baseline?: string;
  /** 抑制リストのパス（設定の ignorePath に対応する CLI フラグ） */
  ignoreFile?: string;
  updateBaseline?: boolean;
  color: boolean;
  verbose: boolean;
  quiet: boolean;
}

/**
 * scan サブコマンドのオプションを登録する。
 *
 * パス系設定（CONFIG_SPEC の `kind: 'path'`）には必ず対応するフラグを置く。
 * フラグが無いと `pathSources` が構造上決して 'cli' にならず、
 * 「オペレータが明示指定したときだけリポジトリ外を許す」機構が
 * そのキーに対して空回りするため。
 */
export function registerScanOptions(command: Command): Command {
  return command
    .addOption(
      new Option('-f, --format <format>', '出力形式')
        .choices(['cli', 'json', 'sarif', 'markdown', 'html'])
        .default('cli'),
    )
    .option('-o, --output <path>', 'レポートの出力先ファイル')
    .addOption(
      new Option('--fail-on <severity>', 'この深刻度以上で非ゼロ終了').choices([
        'critical',
        'high',
        'medium',
        'low',
        'info',
        'never',
      ]),
    )
    .option('--fail-on-new-only', '新規検出のみでCIゲートを判定する')
    .option('-m, --model <model>', '使用するモデルID')
    .addOption(
      new Option('-e, --effort <level>', '思考の深さ（低いほど高速・安価）').choices([
        'low',
        'medium',
        'high',
        'xhigh',
        'max',
      ]),
    )
    .option('-c, --concurrency <n>', 'LLM同時実行数')
    .option('--budget <tokens>', 'このスキャンの出力トークン上限')
    .option('--no-cache', 'チャンク単位の結果キャッシュを使わない')
    .option('--no-kill-chain', 'キルチェーン分析を行わない')
    .option('--no-self-verify', '自己検証パスを行わない（高速だが誤検知が増える）')
    .option('--no-architecture', 'アーキテクチャ推定を行わない')
    .option('--no-heatmap', 'ヒートマップを生成しない')
    .option('--lens <lens...>', '実行する分析レンズを指定')
    .option('--baseline <path>', 'ベースラインJSONのパス')
    .option('--ignore-file <path>', '抑制リストのパス')
    .option('--update-baseline', 'スキャン後にベースラインを更新する')
    .option('--no-color', '色を付けない')
    .option('-v, --verbose', '詳細出力（infoレベルまで含める）', false)
    .option('-q, --quiet', '進捗ログを抑制する', false);
}

/** CLIオプションを設定の部分上書きに変換する */
export function toConfigOverrides(opts: CliOptions): Partial<VulnScanConfig> {
  const llm: Partial<VulnScanConfig['llm']> = {};
  if (opts.model) llm.model = opts.model;
  if (opts.effort) llm.effort = opts.effort;
  if (opts.concurrency) llm.concurrency = Number(opts.concurrency);
  if (opts.budget) llm.tokenBudget = Number(opts.budget);
  if (opts.cache === false) llm.cache = false;

  const scan: Partial<VulnScanConfig['scan']> = {};
  if (opts.lens?.length) scan.lenses = opts.lens as VulnScanConfig['scan']['lenses'];
  if (opts.selfVerify === false) scan.selfVerify = false;

  const overrides: Record<string, unknown> = {};
  if (Object.keys(llm).length) overrides.llm = llm;
  if (Object.keys(scan).length) overrides.scan = scan;
  if (opts.failOn) overrides.failOn = opts.failOn;
  if (opts.failOnNewOnly) overrides.failOnNewOnly = true;
  if (opts.killChain === false) overrides.killChain = false;
  if (opts.architecture === false) overrides.architecture = false;
  if (opts.heatmap === false) overrides.heatmap = false;
  if (opts.baseline) overrides.baselinePath = opts.baseline;
  // 出所が 'cli' になるのはここで拾った場合だけ。拾い忘れると
  // 設定ファイル由来と区別できなくなり、リポジトリ外の指定が常に拒否される。
  if (opts.ignoreFile) overrides.ignorePath = opts.ignoreFile;

  return overrides as Partial<VulnScanConfig>;
}
