/**
 * ③ 脆弱性情報管理ステージのエントリポイント。
 *
 * 生の検出結果(RawFinding[])を受け取り、
 *   正規化 → CVSS付与 → 重複統合 → 依存脆弱性(OSV)の追加 →
 *   ベースライン差分 → 抑制リスト適用
 * を行って最終的な Finding[] を返す。
 */

import type { ScanContext } from '../types/context.js';
import { isOperatorProvidedPath, type VulnScanConfig } from '../types/config.js';
import type { Finding, RawFinding } from '../types/finding.js';
import { applyBaseline, loadBaseline } from './baseline.js';
import { loadIgnoreList, matchIgnoreRule } from './ignore.js';
import { mergeFindings, normalizeFinding } from './normalize.js';
import { scanDependencies, type OsvOptions } from './osv.js';

export interface ManageFindingsResult {
  findings: Finding[];
  /** 抑制リスト・確信度しきい値によって出力から除外した件数 */
  suppressedCount: number;
  /** 非致命的なエラー（ネットワーク失敗など） */
  errors: string[];
}

export interface ManageFindingsOptions {
  /** OSV 照合の設定（テストで fetch を差し替える用途など） */
  osv?: OsvOptions;
  /** 依存脆弱性の照合を行うか（既定 true） */
  scanDependencies?: boolean;
  /** 生成時刻の固定（テスト用） */
  now?: string;
}

/**
 * 脆弱性情報を管理可能な形へ整える。
 *
 * 戻り値の findings には diffStatus='fixed'（前回検出され今回消えたもの）も含まれる。
 * レポート側で「修正済み」として扱えるようにするためで、status も 'fixed' になっている。
 */
export async function manageFindings(
  raw: RawFinding[],
  ctx: ScanContext,
  config: VulnScanConfig,
  options: ManageFindingsOptions = {},
): Promise<ManageFindingsResult> {
  const errors: string[] = [];
  const now = options.now ?? new Date().toISOString();
  const repoRoot = ctx?.repoRoot ?? process.cwd();

  // --- 1. 正規化（CVSS 推定を含む） ---
  const normalized: Finding[] = [];
  for (const item of raw ?? []) {
    try {
      normalized.push(normalizeFinding(item, ctx, now));
    } catch (e) {
      errors.push(
        `Findingの正規化に失敗しました (${item?.location?.file ?? '不明'} / ${item?.cwe ?? '不明'}): ${describe(e)}`,
      );
    }
  }

  // --- 2. 依存脆弱性の照合（OSV.dev） ---
  //     ネットワークが使えなくてもコード由来の結果は返せるようにする。
  let dependencyFindings: Finding[] = [];
  if (options.scanDependencies !== false && (ctx?.dependencies?.length ?? 0) > 0) {
    try {
      const result = await scanDependencies(ctx.dependencies, { now, ...(options.osv ?? {}) });
      dependencyFindings = result.findings;
      errors.push(...result.errors);
    } catch (e) {
      errors.push(`依存脆弱性の照合に失敗しました: ${describe(e)}`);
    }
  }

  // --- 3. 重複統合 ---
  const merged = mergeFindings([...normalized, ...dependencyFindings]);

  // --- 4. ベースライン差分 ---
  let withDiff = merged;
  let fixed: Finding[] = [];
  if (config?.baselinePath) {
    // リポジトリ由来の設定値ならリポジトリ内に封じ込める（任意ファイル読み取りの防止）
    const loaded = await loadBaseline(config.baselinePath, repoRoot, {
      allowOutside: isOperatorProvidedPath(config, 'baselinePath'),
    });
    errors.push(...loaded.errors);
    const diff = applyBaseline(merged, loaded.baseline, now);
    withDiff = diff.findings;
    fixed = diff.fixed;
  }

  // --- 5. 抑制（.vulnignore と確信度しきい値） ---
  let suppressedCount = 0;
  const ignoreList = config?.ignorePath
    ? await loadIgnoreList(config.ignorePath, repoRoot, {
        allowOutside: isOperatorProvidedPath(config, 'ignorePath'),
      })
    : { rules: [], errors: [] };
  errors.push(...ignoreList.errors);

  const minConfidence = config?.scan?.minConfidence ?? 0;
  const kept: Finding[] = [];
  for (const finding of withDiff) {
    const rule = matchIgnoreRule(finding, ignoreList);
    if (rule) {
      suppressedCount++;
      continue;
    }
    if (finding.confidence < minConfidence) {
      // 確信度が設定しきい値未満のものも出力から除外する
      suppressedCount++;
      continue;
    }
    kept.push(finding);
  }

  // 修正済みの Finding も抑制ルールの対象にする（ノイズを増やさないため）
  const keptFixed = fixed.filter((f) => !matchIgnoreRule(f, ignoreList));

  return { findings: [...kept, ...keptFixed], suppressedCount, errors };
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/* --- 公開API --- */

export {
  calculateCvss3,
  parseCvss3Vector,
  buildCvss3Vector,
  inferCvss3Metrics,
  inferCvss3MetricsWithReasons,
  cvss3SeverityRating,
  cvss3RatingToSeverity,
  normalizeCweId,
} from './cvss.js';

export { saveBaseline, loadBaseline, applyBaseline, emptyBaseline } from './baseline.js';
export type { BaselineFile } from './baseline.js';

export { loadIgnoreList, parseIgnoreList, matchIgnoreRule } from './ignore.js';
export type { IgnoreList, IgnoreRule } from './ignore.js';

export { scanDependencies } from './osv.js';
export type { OsvOptions, OsvScanResult } from './osv.js';

export { normalizeFinding, mergeFindings, compareSeverity } from './normalize.js';
export {
  computeFingerprint,
  computeDependencyFingerprint,
  fingerprintToId,
  normalizeCodeSnippet,
  normalizeFilePath,
} from './fingerprint.js';

export {
  CWE_KB,
  lookupCwe,
  cweUrl,
  owaspUrl,
  buildReferences,
  lookupCweInfo,
  owaspForCwe,
  knowledgeCoverage,
} from './knowledge.js';
export type { CweEntry, CweInfo, CweInfoSource, OwaspCategoryId } from './knowledge.js';

// MITRE CWE カタログ（959件）。手作り知識ベースと名前が衝突するので別名で公開する。
export {
  lookupCwe as lookupCatalogCwe,
  catalogSize,
  catalogSource,
  allCwes,
  cweAncestors,
  cweCategory,
  allCweCategories,
  ciaFromCatalog,
  likelihoodOf,
  cwesForPlatform,
  lensForCwe,
  lensCoverage,
  resolveCatalogPath,
  catalogAvailable,
  catalogLoadError,
} from './catalog.js';
export type {
  CweEntry as CweCatalogEntry,
  CweCategory,
  CweCiaMetrics,
  CweCiaFlags,
  CweConsequence,
  CweMitigation,
  CweLikelihood,
  PlatformQuery,
} from './catalog.js';
