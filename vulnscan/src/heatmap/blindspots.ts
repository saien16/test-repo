/**
 * 死角 (blind spot) の抽出と、その原因の切り分け。
 *
 * 本機能の核心。実測が低く想定が高いセルは2通りに読める:
 *
 *   (a) 本当に該当する実装が無い（安全）
 *   (b) スキャンがそこへ届いていない（危険。安全に見えているだけ）
 *
 * この2つを混ぜたまま「低リスク」と表示するのが最も有害なので、
 * 判る範囲で原因を機械的に切り分ける。
 */

import { matchAnyGlob } from '../context/glob.js';
import { normalizeRelPath as normalizePath } from '../util/path.js';
import type { ArchitectureComponent } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import type { VulnScanConfig } from '../types/config.js';
import type { LensId } from '../types/finding.js';
import type { BlindSpot, HeatmapCell, WeaknessCategory } from '../types/heatmap.js';
import { cellKey, isUnderPath } from './assign.js';

/** 死角とみなす想定リスクの下限 */
export const BLIND_SPOT_INFERRED_MIN = 45;
/** 死角とみなす実測リスクの上限（これ以下なら「実測は低い」と判断する） */
export const BLIND_SPOT_OBSERVED_MAX = 15;

export type BlindSpotCause = BlindSpot['likelyCause'];

/* ------------------------------------------------------------------ *
 * 走査カバレッジのメモ化
 *
 * 「この構成要素のソースが走査されたか」は `component` にしか依存しないのに、
 * `diagnoseCause` はセル単位（構成要素 × 約30列）で呼ばれる。
 * 素朴に毎回 `ctx.files` を全走査すると、構成要素15件・ファイル2万件で
 * 最悪 450セル × 20,000ファイル = 900万回の照合になる。必要なのは15回。
 * ------------------------------------------------------------------ */

interface ScanCoverage {
  /** 構成要素の sourcePaths 配下にあるファイル */
  filesUnderComponent: ScanContext['files'];
  /** そのうち scan.exclude で落ちるファイル */
  excludedFiles: ScanContext['files'];
}

/** (ScanContext, config) が同じ間だけ有効なメモ。構成要素IDで引く */
const coverageCache = new WeakMap<ScanContext, WeakMap<VulnScanConfig, Map<string, ScanCoverage>>>();

function scanCoverageOf(
  component: ArchitectureComponent,
  ctx: ScanContext,
  config: VulnScanConfig,
): ScanCoverage {
  let byConfig = coverageCache.get(ctx);
  if (byConfig === undefined) {
    byConfig = new WeakMap();
    coverageCache.set(ctx, byConfig);
  }
  let byComponent = byConfig.get(config);
  if (byComponent === undefined) {
    byComponent = new Map();
    byConfig.set(config, byComponent);
  }
  const cached = byComponent.get(component.id);
  if (cached !== undefined) return cached;

  const filesUnderComponent = ctx.files.filter((file) =>
    component.sourcePaths.some((p) => isUnderPath(file.path, p)),
  );
  const excludedFiles = filesUnderComponent.filter((file) =>
    matchAnyGlob(config.scan.exclude, normalizePath(file.path)),
  );
  const coverage: ScanCoverage = { filesUnderComponent, excludedFiles };
  byComponent.set(component.id, coverage);
  return coverage;
}

export interface CauseDiagnosis {
  cause: BlindSpotCause;
  /** 切り分けの根拠（日本語） */
  detail: string;
  recommendedAction: string;
}

/**
 * 死角の原因を切り分ける。
 *
 * 判定順序には意味がある。「走査していない」が最も重く、
 * それが否定できて初めて「レンズが無い」「本当に無い」を検討できる。
 */
export function diagnoseCause(
  component: ArchitectureComponent,
  category: WeaknessCategory,
  /**
   * このセルの想定リスクの根拠になったCWE群を担当するレンズ
   * （`lensForCwe()` で引いたもの）。空なら担当レンズが存在しない。
   */
  lenses: readonly LensId[],
  ctx: ScanContext,
  config: VulnScanConfig,
): CauseDiagnosis {
  // (0) そもそもソース対応が無い構成要素は、走査の有無すら判定できない
  if (component.sourcePaths.length === 0) {
    return {
      cause: 'unknown',
      detail:
        `構成要素「${component.name}」に対応するソースパスが登録されていないため、` +
        `走査されたかどうかを判定できない。`,
      recommendedAction:
        `この構成要素のソースがリポジトリ内にあるか確認する。` +
        `外部サービスやマネージドサービスならコード走査の対象外であり、` +
        `設定レビューなど別の手段で確認する必要がある。`,
    };
  }

  // (1) 走査対象になっていない
  const { filesUnderComponent, excludedFiles } = scanCoverageOf(component, ctx, config);

  if (filesUnderComponent.length === 0) {
    return {
      cause: 'not-scanned',
      detail:
        `sourcePaths（${component.sourcePaths.join(', ')}）配下のファイルが ScanContext.files に1件も無い。` +
        `収集段階でこの構成要素に到達していない。`,
      recommendedAction:
        `${component.sourcePaths.join(', ')} がリポジトリに存在するか、` +
        `scan.include / scan.exclude の設定で丸ごと落ちていないかを確認する。`,
    };
  }

  if (excludedFiles.length === filesUnderComponent.length) {
    return {
      cause: 'not-scanned',
      detail:
        `sourcePaths 配下の ${filesUnderComponent.length} 件すべてが scan.exclude の glob に該当し、` +
        `走査対象から外れている。`,
      recommendedAction:
        `scan.exclude（${config.scan.exclude.join(', ')}）がこの構成要素を過剰に除外していないか確認する。` +
        `意図した除外なら、この行は「見ていない」ことを承知の上での空白だと記録しておく。`,
    };
  }

  // (2) 担当レンズが無い / 有効化されていない
  if (lenses.length === 0) {
    return {
      cause: 'no-matching-lens',
      detail:
        `カテゴリ「${category.name}」の想定根拠となったCWEを担当する分析レンズが、` +
        `このスキャナにそもそも存在しない（lensForCwe が該当なしを返した）。` +
        `検出が無いのは当然であり、安全を意味しない。`,
      recommendedAction:
        `このカテゴリはコード分析の射程外なので、設計レビューや設定監査など` +
        `別の手段で確認する。`,
    };
  }
  const enabledLenses = lenses.filter((lens) => config.scan.lenses.includes(lens));
  if (enabledLenses.length === 0) {
    return {
      cause: 'no-matching-lens',
      detail:
        `カテゴリ「${category.name}」を担当しうるレンズ（${lenses.join(', ')}）が` +
        `scan.lenses で1つも有効になっていない（有効: ${config.scan.lenses.join(', ') || 'なし'}）。`,
      recommendedAction:
        `レンズ ${lenses.join(' / ')} のいずれかを有効にして再スキャンし、` +
        `本当に検出が無いのかを確認する。`,
    };
  }

  // (3) 走査済み・レンズ有効で、それでも検出が無い
  const scannedCount = filesUnderComponent.length - excludedFiles.length;
  return {
    cause: 'genuinely-absent',
    detail:
      `sourcePaths 配下の ${scannedCount} 件が走査され、担当レンズ（${enabledLenses.join(', ')}）も` +
      `有効だったが検出は無かった。該当する実装自体が無いか、既に対策済みの可能性が高い。`,
    recommendedAction:
      `優先度は低い。ただしレンズの検出漏れの可能性は残るため、` +
      `このカテゴリの想定リスクが高い理由（露出度・扱うデータ）が実態と合っているかだけ確認する。`,
  };
}

/**
 * セル群から死角を抽出する。
 *
 * 想定リスクが `minInferenceConfidence` 未満で除外されたセルは値が0になるため、
 * ここで自然に対象外となる（＝低確信度の推測で死角を騒ぎ立てない）。
 */
export function extractBlindSpots(
  cells: readonly HeatmapCell[],
  componentsById: ReadonlyMap<string, ArchitectureComponent>,
  categoriesById: ReadonlyMap<string, WeaknessCategory>,
  /** セルキー `${componentId} ${categoryId}` → そのセルの根拠CWEを担当するレンズ */
  lensesByCell: ReadonlyMap<string, LensId[]>,
  ctx: ScanContext,
  config: VulnScanConfig,
  /** 想定層を評価しない構成要素（未割当の疑似構成要素など） */
  skipComponentIds: ReadonlySet<string> = new Set(),
): BlindSpot[] {
  const spots: BlindSpot[] = [];

  for (const cell of cells) {
    if (skipComponentIds.has(cell.componentId)) continue;
    const inferredRisk = cell.inferredRisk.value;
    if (inferredRisk < BLIND_SPOT_INFERRED_MIN) continue;
    if (cell.observedRisk > BLIND_SPOT_OBSERVED_MAX) continue;

    const component = componentsById.get(cell.componentId);
    const category = categoriesById.get(cell.categoryId);
    if (!component || !category) continue;

    const lenses = lensesByCell.get(cellKey(cell.componentId, cell.categoryId)) ?? [];
    const diagnosis = diagnoseCause(component, category, lenses, ctx, config);
    const observedNote =
      cell.findingIds.length === 0
        ? '検出0件'
        : `検出は ${cell.findingIds.length} 件あるが実測リスクは ${cell.observedRisk} と低い`;

    spots.push({
      componentId: cell.componentId,
      categoryId: cell.categoryId,
      inferredRisk,
      reasoning:
        `「${component.name}」×「${category.name}」は想定リスク ${inferredRisk} に対し ${observedNote}。` +
        `${diagnosis.detail}`,
      likelyCause: diagnosis.cause,
      recommendedAction: diagnosis.recommendedAction,
    });
  }

  // 想定リスクの高い順。同点は ID 順で決定的に並べる
  spots.sort(
    (a, b) =>
      b.inferredRisk - a.inferredRisk ||
      a.componentId.localeCompare(b.componentId) ||
      a.categoryId.localeCompare(b.categoryId),
  );
  return spots;
}
