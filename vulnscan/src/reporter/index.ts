/**
 * ⑤ レポーター。
 *
 * 役割は3つ:
 *   1. `summarize`      — 機械的なサマリ集計（純粋関数）
 *   2. `analyzeResult`  — 他機能の出力を横断分析して読み物の中間表現を作る
 *   3. `generateReport` — 中間表現を各フォーマットへレンダリングする
 *
 * さらにCIゲート（`determineExitCode`）もここが担う。
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AnalyzedReport, ReportOptions, ScanResult } from '../types/report.js';
import { renderCli } from './formatters/cli.js';
import { renderHtml } from './formatters/html.js';
import { renderJson } from './formatters/json.js';
import { renderMarkdown } from './formatters/markdown.js';
import { renderSarif } from './formatters/sarif.js';

/*
 * ここで再公開するのは、レポーターの外（CLI・オーケストレータ）から
 * 実際に呼ばれる入口だけに限る。
 *
 * 内部ヘルパまで barrel に並べると公開APIに見えてしまい、
 * シグネチャを変えるたびに「外部利用があるかもしれない」という判断が要る。
 * レポーター内部のモジュールやテストは具象モジュールを直接 import すること。
 */
export { analyzeResult } from './analyze.js';
export { summarize } from './summarize.js';
export { determineExitCode, evaluateGate, EXIT_CODES, type GateDecision } from './gate.js';

/**
 * 分析済みの中間表現を、指定フォーマットの文字列にレンダリングする。
 *
 * `options.outputPath` が指定されていればファイルにも書き出すが、
 * 戻り値は常に生成された文字列。書き込み失敗は例外として伝播させる
 * （出力先を指定したのに書けないのは、黙って握り潰すべきではない）。
 */
export async function generateReport(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: ReportOptions,
): Promise<string> {
  const rendered = renderToString(result, analyzed, options);

  if (options.outputPath) {
    await mkdir(dirname(options.outputPath), { recursive: true });
    await writeFile(options.outputPath, rendered, 'utf8');
  }

  return rendered;
}

/** フォーマッタの選択（同期・副作用なし。テストから直接叩ける） */
export function renderToString(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: ReportOptions,
): string {
  switch (options.format) {
    case 'cli':
      return renderCli(result, analyzed, options);
    case 'json':
      return renderJson(result, analyzed, options);
    case 'sarif':
      return renderSarif(result, analyzed);
    case 'markdown':
      return renderMarkdown(result, analyzed, options);
    case 'html':
      return renderHtml(result, analyzed, options);
    default: {
      // 型上は到達しないが、設定ファイル由来の不正値に備える
      const format: string = options.format;
      throw new Error(`未対応のレポート形式です: ${format}`);
    }
  }
}
