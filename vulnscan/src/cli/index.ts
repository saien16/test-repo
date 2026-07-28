#!/usr/bin/env node
/**
 * GRIMOIRE CLI エントリポイント。
 *
 * 出力先の使い分け:
 *   stdout … レポート本体だけ（`grimoire -f json > out.json` が成立するように）
 *   stderr … 進捗・警告・エラー（{@link createAnimation} 経由）
 */

import { Command, Option } from 'commander';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { loadConfig } from '../config/index.js';
import { runScan, type StageName } from '../core/orchestrator.js';
import { createAnimation } from './animation.js';
import { LlmClient } from '../llm/client.js';
import { analyzeResult, generateReport, determineExitCode } from '../reporter/index.js';
import { saveBaseline } from '../vuln/index.js';
import { isOperatorProvidedPath, type VulnScanConfig } from '../types/config.js';
import type { ReportFormat, ReportOptions } from '../types/report.js';

const STAGE_LABELS: Record<StageName, string> = {
  context: 'コンテキスト収集',
  analyze: 'ソースコード分析',
  vuln: '脆弱性情報管理',
  killchain: 'キルチェーン分析',
  report: 'レポート生成',
};

interface CliOptions {
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
  lens?: string[];
  baseline?: string;
  updateBaseline?: boolean;
  color: boolean;
  verbose: boolean;
  quiet: boolean;
}

/** CLIオプションを設定の部分上書きに変換する */
function toConfigOverrides(opts: CliOptions): Partial<VulnScanConfig> {
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
  if (opts.baseline) overrides.baselinePath = opts.baseline;

  return overrides as Partial<VulnScanConfig>;
}

async function runScanCommand(target: string, opts: CliOptions): Promise<void> {
  const repoRoot = resolve(target);
  const { config, warnings } = await loadConfig(repoRoot, toConfigOverrides(opts));

  const log = (message: string): void => {
    if (!opts.quiet) process.stderr.write(`${message}\n`);
  };

  // 進捗表示は stderr 専用。TTY 判定も stderr 側で行う
  // （stdout がリダイレクトされていても端末で見えるように）。
  const animation = createAnimation({
    tty: process.stderr.isTTY === true,
    color: opts.color,
    quiet: opts.quiet,
  });

  try {
    // 警告はアニメーションより先に出し切る（行の上書きに巻き込まれないように）
    for (const warning of warnings) log(`警告: ${warning}`);

    const llm = new LlmClient(config.llm);

    animation.start();

    const result = await runScan({
      repoRoot,
      config,
      llm,
      hooks: {
        onStageStart: (stage) => animation.stageStart(stage, STAGE_LABELS[stage]),
        onStageEnd: (stage, detail) => animation.stageEnd(stage, detail),
        onProgress: (stage, completed, total) =>
          animation.stageProgress(stage, completed, total),
      },
    });

    animation.stageStart('report', STAGE_LABELS.report);
    const analyzed = await analyzeResult(result, llm, config);
    animation.stageEnd('report');

    // レポート本体を出す前にアニメーションを畳む。
    // 実行中の行が残ったまま stdout へ書くと表示が混ざる。
    animation.stop();

    const reportOptions: ReportOptions = {
      format: opts.format,
      outputPath: opts.output,
      // 出力先がファイルなら色を付けない
      color: opts.color && !opts.output && process.stdout.isTTY === true,
      verbose: opts.verbose,
    };

    const rendered = await generateReport(result, analyzed, reportOptions);

    if (opts.output) {
      const outPath = resolve(opts.output);
      await mkdir(dirname(outPath), { recursive: true });
      await writeFile(outPath, rendered, 'utf8');
      log(`✔ レポートを書き出しました: ${outPath}`);
    } else {
      process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
    }

    if (opts.updateBaseline) {
      // 事前に絶対パス化するとリポジトリ内への封じ込め判定を素通りしてしまうため、
      // 設定値と repoRoot をそのまま渡して saveBaseline 側で解決させる。
      // リポジトリ外を許すのは --baseline で明示指定された場合だけ。
      await saveBaseline(result.findings, config.baselinePath, repoRoot, {
        allowOutside: isOperatorProvidedPath(config, 'baselinePath'),
      });
      log(`✔ ベースラインを更新しました: ${config.baselinePath}`);
    }

    const usage = llm.getUsage();
    log(
      `トークン使用量: 入力 ${usage.input} / 出力 ${usage.output} ` +
        `(キャッシュ読み ${usage.cacheRead})`,
    );

    process.exitCode = determineExitCode(result, config);
  } finally {
    // 例外で抜けた場合もカーソルを必ず戻す（stop() は冪等）
    animation.stop();
  }
}

const program = new Command();

program
  .name('grimoire')
  .description(
    'GRIMOIRE — 禁書「九五九」。MITRE CWE 959件を収めた、LLMベースのソースコード脆弱性スキャナー\n' +
      '（短縮エイリアス: grim）',
  )
  .version('0.1.0');

program
  .command('scan', { isDefault: true })
  .description('リポジトリをスキャンする')
  .argument('[path]', 'スキャン対象のパス', '.')
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
  .option('--lens <lens...>', '実行する分析レンズを指定')
  .option('--baseline <path>', 'ベースラインJSONのパス')
  .option('--update-baseline', 'スキャン後にベースラインを更新する')
  .option('--no-color', '色を付けない')
  .option('-v, --verbose', '詳細出力（infoレベルまで含める）', false)
  .option('-q, --quiet', '進捗ログを抑制する', false)
  .action(async (target: string, opts: CliOptions) => {
    try {
      await runScanCommand(target, opts);
    } catch (err) {
      process.stderr.write(`エラー: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  });

program.parseAsync(process.argv);
