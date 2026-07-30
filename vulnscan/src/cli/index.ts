#!/usr/bin/env node
/**
 * GRIMOIRE CLI エントリポイント。
 *
 * 出力先の使い分け:
 *   stdout … レポート本体だけ（`grimoire -f json > out.json` が成立するように）
 *   stderr … 進捗・警告・エラー（{@link createAnimation} 経由）
 */

import { Command } from 'commander';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { loadConfig } from '../config/index.js';
import { runScan, type StageName } from '../core/orchestrator.js';
import { createAnimation } from './animation.js';
import { LlmClient } from '../llm/client.js';
import { analyzeResult, generateReport, evaluateGate } from '../reporter/index.js';
import { saveBaseline } from '../vuln/index.js';
import { isOperatorProvidedPath } from '../types/config.js';
import { registerScanOptions, toConfigOverrides, type CliOptions } from './options.js';
import type { ReportOptions } from '../types/report.js';

const STAGE_LABELS: Record<StageName, string> = {
  context: 'コンテキスト収集',
  analyze: 'ソースコード分析',
  vuln: '脆弱性情報管理',
  killchain: 'キルチェーン分析',
  architecture: 'アーキテクチャ推定',
  heatmap: 'ヒートマップ生成',
  report: 'レポート生成',
};

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

    // ゲートの判定理由は必ず stderr に出す。終了コードだけを返して黙ると、
    // 「なぜ落ちたのか」「なぜ通ったのか」を利用者が確かめられない。
    const gate = evaluateGate(result, config);
    if (gate.blockedByHealth) {
      // 完走しなかった走査を通すのは、このツールの目的そのものに反する。
      // quiet でも出す（CIログにこれだけは残す必要がある）。
      process.stderr.write(`✖ ${gate.reason}\n`);
    } else {
      log(`ゲート判定: ${gate.reason}`);
    }
    process.exitCode = gate.exitCode;
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

// オプション定義は options.ts に置いてある（テストから同じ定義を組み立てられるように）
registerScanOptions(
  program
    .command('scan', { isDefault: true })
    .description('リポジトリをスキャンする')
    .argument('[path]', 'スキャン対象のパス', '.'),
).action(async (target: string, opts: CliOptions) => {
  try {
    await runScanCommand(target, opts);
  } catch (err) {
    process.stderr.write(`エラー: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  }
});

program.parseAsync(process.argv);
