/**
 * ① コンテキスト収集のエントリポイント。
 *
 * リポジトリを走査し、後続ステージ（②LLM分析・③キルチェーン）が必要とする
 * 情報を `ScanContext` に詰めて返す。
 *
 * 設計方針:
 *   - 収集は「壊れないこと」を最優先する。個々の解析失敗は warnings に積み、
 *     例外は collectContext の外へ出さない。
 *   - ネイティブ依存（tree-sitter 等）を使わず Node 標準モジュールのみで完結する。
 *   - 精度が出ない部分は confidence など数値で後段に伝える。
 */

import { resolve } from 'node:path';
import type { VulnScanConfig } from '../types/config.js';
import type { StageProgress } from '../types/progress.js';
import type {
  CallGraph,
  Dependency,
  EntryPoint,
  FrameworkInfo,
  ScanContext,
  SymbolTable,
  TrustBoundary,
} from '../types/context.js';
import { buildCallGraph } from './callgraph.js';
import { collectDependencies } from './dependencies.js';
import { detectEntryPoints } from './entrypoints.js';
import { detectFrameworks } from './frameworks.js';
import { collectGitContext } from './git.js';
import { isAnalyzable, summarizeLanguages } from './language.js';
import { maskSource } from './mask.js';
import { buildSymbolTable, type AnalyzableSource } from './symbols.js';
import { detectTrustBoundaries } from './trust.js';
import { walkRepository, type ScannedFile } from './walk.js';

export { collectDependencies } from './dependencies.js';
export { detectEntryPoints } from './entrypoints.js';
export { detectFrameworks } from './frameworks.js';
export { collectGitContext } from './git.js';
export { detectLanguage, summarizeLanguages } from './language.js';
export { matchAnyGlob, matchGlob, normalizePath } from './glob.js';
export { maskSource } from './mask.js';
export { buildCallGraph } from './callgraph.js';
export { buildSymbolTable, extractFileSymbols, symbolId, SymbolLocator } from './symbols.js';
export { detectTrustBoundaries } from './trust.js';
export { walkRepository } from './walk.js';
export type { AnalyzableSource } from './symbols.js';
export type { ManifestFile, ScannedFile } from './walk.js';

/** ミニファイ判定: 行が極端に長いファイルは構文解析しても意味がない */
function looksMinified(content: string): boolean {
  if (content.length < 5000) return false;
  const lines = content.split('\n');
  const longest = lines.reduce((max, line) => Math.max(max, line.length), 0);
  return longest > 2000 && lines.length < content.length / 500;
}

/**
 * 解析対象ファイルをマスク済みソースへ変換する。
 *
 * ここが①でファイル数に比例する唯一の重い処理なので、進捗もここで数える。
 * 走査(walkRepository)側で数えないのは、走り終えるまで総数が判らず
 * 「12/? ファイル」しか出せないため。
 */
function toAnalyzableSources(
  files: readonly ScannedFile[],
  warnings: string[],
  onProgress?: (p: StageProgress) => void,
): AnalyzableSource[] {
  const sources: AnalyzableSource[] = [];
  let minified = 0;
  let seen = 0;

  for (const scanned of files) {
    seen++;
    onProgress?.({ completed: seen, total: files.length, unit: 'ファイル' });
    if (!isAnalyzable(scanned.file.language)) continue;
    if (looksMinified(scanned.content)) {
      minified++;
      continue;
    }
    try {
      sources.push({
        path: scanned.file.path,
        language: scanned.file.language,
        masked: maskSource(scanned.content, scanned.file.language),
      });
    } catch (err) {
      warnings.push(`ソースの前処理に失敗しました: ${scanned.file.path} (${String(err)})`);
    }
  }

  if (minified > 0) {
    warnings.push(`ミニファイと判定したファイルを ${minified} 件、構文解析から除外しました`);
  }
  return sources;
}

/** 失敗しても収集全体を止めないための実行ヘルパー */
function safely<T>(label: string, warnings: string[], fallback: T, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    warnings.push(`${label}に失敗しました: ${String(err)}`);
    return fallback;
  }
}

const EMPTY_SYMBOLS: SymbolTable = { symbols: [], byId: {} };
const EMPTY_CALL_GRAPH: CallGraph = { edges: [], callees: {}, callers: {} };

export interface CollectContextOptions {
  /** 前処理の進捗（ファイル単位）。省略可 */
  onProgress?: (progress: StageProgress) => void;
}

/**
 * リポジトリを走査してスキャンコンテキストを構築する。
 *
 * @param repoRoot 走査対象のリポジトリルート
 * @param config   走査設定（exclude / include / maxFileBytes を参照する）
 * @param options  進捗通知など（省略可）
 */
export async function collectContext(
  repoRoot: string,
  config: VulnScanConfig,
  options: CollectContextOptions = {},
): Promise<ScanContext> {
  const warnings: string[] = [];
  const root = resolve(repoRoot);

  // 1. ファイル走査（glob・.gitignore・バイナリ・サイズ上限）
  let walked;
  try {
    walked = await walkRepository(root, config, warnings);
  } catch (err) {
    warnings.push(`ファイル走査に失敗しました: ${String(err)}`);
    walked = { files: [], manifests: [], allPaths: [] };
  }

  const files = walked.files.map((scanned) => scanned.file);

  // 2. 言語構成
  const languages = safely('言語の集計', warnings, [], () => summarizeLanguages(files));

  // 3. 解析用にコメント・文字列をマスクしておく（以降の解析で使い回す）
  const sources = toAnalyzableSources(walked.files, warnings, options.onProgress);

  // 4. 依存関係とフレームワーク
  const dependencies: Dependency[] = safely('依存関係の抽出', warnings, [], () =>
    collectDependencies(walked.manifests, warnings),
  );
  const frameworks: FrameworkInfo[] = safely('フレームワークの推定', warnings, [], () =>
    detectFrameworks(dependencies, walked.allPaths, sources),
  );

  // 5. シンボルと呼び出しグラフ
  const symbols: SymbolTable = safely('シンボル抽出', warnings, EMPTY_SYMBOLS, () =>
    buildSymbolTable(sources, warnings),
  );
  const callGraph: CallGraph = safely('呼び出しグラフの構築', warnings, EMPTY_CALL_GRAPH, () =>
    buildCallGraph(sources, symbols, warnings),
  );

  // 6. エントリポイントと信頼境界
  const entryPoints: EntryPoint[] = safely('エントリポイント検出', warnings, [], () =>
    detectEntryPoints(sources, symbols, warnings),
  );
  const trustBoundaries: TrustBoundary[] = safely('信頼境界の検出', warnings, [], () =>
    detectTrustBoundaries(sources, symbols, warnings),
  );

  // 7. Git 情報（git リポジトリでなければ undefined のまま）
  let git;
  try {
    git = await collectGitContext(root, warnings);
  } catch (err) {
    warnings.push(`Git 情報の取得に失敗しました: ${String(err)}`);
    git = undefined;
  }

  if (files.length === 0) {
    warnings.push('走査対象のファイルが1件もありません。include / exclude の設定を確認してください');
  }

  return {
    repoRoot: root,
    scannedAt: new Date().toISOString(),
    languages,
    frameworks,
    dependencies,
    files,
    symbols,
    callGraph,
    entryPoints,
    trustBoundaries,
    git,
    warnings,
  };
}
