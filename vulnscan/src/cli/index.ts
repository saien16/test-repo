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
import { analyzeResult, generateReport, evaluateGate, renderToString } from '../reporter/index.js';
import { writeArchive } from '../reporter/archive.js';
import { resolvePath, saveBaseline } from '../vuln/index.js';
import { isOperatorProvidedPath } from '../types/config.js';
import { registerScanOptions, toConfigOverrides, type CliOptions } from './options.js';
import type { ReportOptions } from '../types/report.js';
import { formatDuration } from '../reporter/target.js';

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
        onProgress: (stage, progress) => animation.stageProgress(stage, progress),
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

    /*
     * HTML控えを必ず1つ残す。
     *
     * -f / -o が何であってもここは走る。走査したのに成果物が
     * どこにも残らない（stdout へ流れて消えた）状態を作らないため。
     * 既に html を書いている場合だけ、その文字列を再利用する。
     */
    if (config.archiveReport) {
      const dir = resolvePath(config.reportDir, repoRoot, {
        allowOutside: isOperatorProvidedPath(config, 'reportDir'),
      });
      if (dir === null) {
        log('警告: reportDir がリポジトリ外を指しているため、HTML控えを保存しませんでした');
      } else {
        const html =
          opts.format === 'html'
            ? rendered
            : renderToString(result, analyzed, {
                format: 'html',
                color: false,
                verbose: opts.verbose,
              });
        const archived = await writeArchive(html, dir, repoRoot, new Date());
        log(`✔ HTML控え: ${archived.path}`);
        log(`  最新版へのリンク: ${archived.latestPath}`);
      }
    }

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

    /*
     * 走査規模と消費量を完走時に出す。レポートを開かなくても
     * 「どれだけ見て、いくら使ったか」がターミナルに残るようにする。
     *
     * CLI形式を stdout へ出した場合はレポート末尾に同じものが載るので、
     * ここでは出さない（同じ数字が2回並ぶと、別々の値かと読ませてしまう）。
     */
    const printedInReport = opts.format === 'cli' && opts.output === undefined;
    if (!printedInReport) {
      const usage = llm.getUsage();
      const n = (v: number): string => v.toLocaleString('en-US');
      log(
        `処理: ${n(result.summary.filesScanned)} ファイル / ` +
          `${n(result.summary.linesScanned)} 行 / ${formatDuration(result.summary.durationMs)}`,
      );
      log(
        `トークン使用量: 入力 ${n(usage.input)} / 出力 ${n(usage.output)} ` +
          `(キャッシュ読み ${n(usage.cacheRead)} / 書き ${n(usage.cacheWrite)})`,
      );
    }

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
