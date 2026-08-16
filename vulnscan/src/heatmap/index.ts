/**
 * 脆弱性ヒートマップの構築。
 *
 * `buildHeatmap()` は**純粋関数**である。LLMを呼ばず、時刻も乱数も参照せず、
 * 引数を書き換えず、同じ入力からは必ず同じ出力を返す。想定層はCWEカタログと
 * アーキテクチャ推定から機械的に導けるため、LLMを挟む必要がない。
 * 再現性とテスト可能性を優先した設計判断である。
 *
 * 唯一の外部入力はリポジトリに同梱された CWE カタログ
 * （`src/vuln/data/cwe-catalog.json`。プロセス内で1回だけ読まれる静的データ）で、
 * これは版が固定されている限り出力を変えない。ネットワークアクセスは無い。
 *
 * 層の重ね合わせについては `src/types/heatmap.ts` 冒頭のコメントを参照。
 */

import type { ArchitectureComponent, ArchitectureModel } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import type { VulnScanConfig } from '../types/config.js';
import type { Citation, Claim } from '../types/evidence.js';
import { assumed } from '../types/evidence.js';
import type { Finding, LensId } from '../types/finding.js';
import type {
  CellBasis,
  HeatmapCell,
  VulnerabilityHeatmap,
  WeaknessCategory,
} from '../types/heatmap.js';
import type { AttackChain } from '../types/killchain.js';
import {
  assignFindingsToComponents,
  categoryIdForFinding,
  cellKey,
  isUnderPath,
  makeUnassignedComponent,
  UNASSIGNED_COMPONENT_ID,
} from './assign.js';
import { extractBlindSpots } from './blindspots.js';
import { cwesForComponent, OTHER_CATEGORY_ID, weaknessCategories } from './catalog-adapter.js';
import { computeInferred } from './inferred.js';
import { chainIndexByFinding, computeObserved } from './observed.js';
import { derivePlatform } from './platform.js';
// clamp01 / round1 は util/num.ts に一元化した（統合前は計7箇所に散在）。
import { clamp01, round1, round2 } from '../util/num.js';

export { cellKey, UNASSIGNED_COMPONENT_ID } from './assign.js';
export { BLIND_SPOT_INFERRED_MIN, BLIND_SPOT_OBSERVED_MAX, diagnoseCause } from './blindspots.js';
export { cweCategoryId, lensForCwe, weaknessCategories } from './catalog-adapter.js';
export { computeInferred } from './inferred.js';
export { computeObserved } from './observed.js';

/**
 * セルが「想定リスクあり」と言えるしきい値。
 * これ未満の想定は basis の判定上「無かった」ものとして扱う
 * （どのセルにも微小な想定値は立つので、そのままでは全セルが
 *  inferred-only になり色分けの意味が失われるため）。
 */
export const INFERRED_NOTABLE = 25;

/** 想定層の重み付けに使った基礎事実の引用として載せるファイル数の上限 */
const MAX_BASIS_CITATIONS = 3;

export interface BuildHeatmapInput {
  architecture: ArchitectureModel;
  findings: Finding[];
  chains: AttackChain[];
  context: ScanContext;
  config: VulnScanConfig;
}


/** 構成要素の実在を示す引用（想定層の basis に使う） */
function basisCitationsFor(component: ArchitectureComponent, ctx: ScanContext): Citation[] {
  const citations: Citation[] = [];
  for (const file of ctx.files) {
    if (citations.length >= MAX_BASIS_CITATIONS) break;
    if (component.sourcePaths.some((p) => isUnderPath(file.path, p))) {
      citations.push({ file: file.path });
    }
  }
  return citations;
}

function decideBasis(observedRisk: number, findingCount: number, inferredRisk: number): CellBasis {
  const hasObserved = findingCount > 0 || observedRisk > 0;
  const hasInferred = inferredRisk >= INFERRED_NOTABLE;
  if (hasObserved && hasInferred) return 'both';
  if (hasObserved) return 'observed-only';
  if (hasInferred) return 'inferred-only';
  return 'none';
}

/**
 * 「アーキテクチャ構成要素 × 弱点カテゴリ」のヒートマップを構築する。
 *
 * 実測層と想定層は独立に算出し、片方がもう片方を上書きすることはない。
 * 両者の食い違い（特に 実測低 × 想定高 ＝ 死角）を残すことが目的だからである。
 */
export function buildHeatmap(input: BuildHeatmapInput): VulnerabilityHeatmap {
  const { architecture, findings, chains, context: ctx, config } = input;

  // ---- 列（カテゴリ）を決める ----
  // カタログのカテゴリ定義をそのまま列にする。'other' 列も常に存在するので、
  // 未知のCWEを持つ Finding も必ずどこかの列に載る（取りこぼしを作らない）。
  const categories: WeaknessCategory[] = weaknessCategories();
  const findingCategoryIds = new Map<string, string>();
  for (const finding of findings) {
    findingCategoryIds.set(finding.id, categoryIdForFinding(finding));
  }

  // ---- 行（構成要素）を決める ----
  const assignments = assignFindingsToComponents(architecture, findings, ctx);
  const hasUnassigned = [...assignments.values()].some(
    (a) => a.componentId === UNASSIGNED_COMPONENT_ID,
  );

  const components: ArchitectureComponent[] = [...architecture.components];
  if (hasUnassigned) components.push(makeUnassignedComponent());

  const componentIds = components.map((c) => c.id);
  const componentsById = new Map(components.map((c) => [c.id, c]));
  const categoriesById = new Map(categories.map((c) => [c.id, c]));

  // ---- Finding をセルへ振り分ける ----
  const findingsByCell = new Map<string, Finding[]>();
  for (const finding of findings) {
    const componentId = assignments.get(finding.id)?.componentId ?? UNASSIGNED_COMPONENT_ID;
    const categoryId = findingCategoryIds.get(finding.id) ?? OTHER_CATEGORY_ID;
    const key = cellKey(componentId, categoryId);
    const list = findingsByCell.get(key) ?? [];
    list.push(finding);
    findingsByCell.set(key, list);
  }

  const chainsByFinding = chainIndexByFinding(chains);

  // ---- セルを作る ----
  const cells: HeatmapCell[] = [];
  /** セルごとの「根拠CWEを担当するレンズ」。死角の原因切り分けに渡す */
  const lensesByCell = new Map<string, LensId[]>();

  for (const component of components) {
    const isPseudo = component.id === UNASSIGNED_COMPONENT_ID;
    // 技術スタックの導出とCWEの逆引きは構成要素ごとに1回で済ませる
    // （カテゴリ数だけカタログ全件を走査すると無駄に重い）
    const platform = isPseudo ? null : derivePlatform(component, architecture, ctx);
    const candidatesByCategory = platform === null ? null : cwesForComponent(platform);
    const basis = isPseudo ? [] : basisCitationsFor(component, ctx);

    for (const category of categories) {
      const key = cellKey(component.id, category.id);
      const cellFindings = findingsByCell.get(key) ?? [];
      const observed = computeObserved(cellFindings, chainsByFinding);

      let inferredClaim: Claim<number>;
      if (platform === null || candidatesByCategory === null) {
        inferredClaim = assumed(
          0,
          '未割当Findingの受け皿である疑似構成要素であり、実在の構成要素ではないため想定リスクは算出しない。',
        );
      } else {
        const result = computeInferred(
          component,
          category,
          platform,
          candidatesByCategory.get(category.id) ?? [],
          config.minInferenceConfidence,
          basis,
        );
        inferredClaim = result.claim;
        lensesByCell.set(key, result.lenses);
      }

      cells.push({
        componentId: component.id,
        categoryId: category.id,
        observedRisk: observed.risk,
        findingIds: observed.findingIds,
        chainIds: observed.chainIds,
        inferredRisk: inferredClaim,
        basis: decideBasis(observed.risk, cellFindings.length, inferredClaim.value),
      });
    }
  }

  // ---- 死角の抽出 ----
  const blindSpots = extractBlindSpots(
    cells,
    componentsById,
    categoriesById,
    lensesByCell,
    ctx,
    config,
    new Set(hasUnassigned ? [UNASSIGNED_COMPONENT_ID] : []),
  );

  // ---- 行方向・列方向の集計 ----
  const componentTotals: Record<string, { observed: number; inferred: number }> = {};
  const categoryTotals: Record<string, { observed: number; inferred: number }> = {};
  for (const id of componentIds) componentTotals[id] = { observed: 0, inferred: 0 };
  for (const category of categories) categoryTotals[category.id] = { observed: 0, inferred: 0 };

  for (const cell of cells) {
    const row = componentTotals[cell.componentId];
    if (row) {
      row.observed += cell.observedRisk;
      row.inferred += cell.inferredRisk.value;
    }
    const column = categoryTotals[cell.categoryId];
    if (column) {
      column.observed += cell.observedRisk;
      column.inferred += cell.inferredRisk.value;
    }
  }
  for (const total of Object.values(componentTotals)) {
    total.observed = round1(total.observed);
    total.inferred = round1(total.inferred);
  }
  for (const total of Object.values(categoryTotals)) {
    total.observed = round1(total.observed);
    total.inferred = round1(total.inferred);
  }

  return {
    componentIds,
    categories,
    cells,
    blindSpots,
    componentTotals,
    categoryTotals,
    inferenceRatio: computeInferenceRatio(architecture, cells),
  };
}

/**
 * ヒートマップ全体がどれだけ推測に依存しているかを 0..1 で返す。
 *
 * **1に近いほど「実測の裏付けが薄い＝話半分に読むべき」** を意味するよう
 * 符号を揃えている。読み手はこの値が高いヒートマップを、
 * 事実の報告ではなく「観点の提示」として読むべきである。
 *
 * 2つの独立した不確実性を等分に混ぜる:
 *
 *   1. アーキテクチャ推定の不確実性
 *      = (inferred + assumed) / 全主張数
 *      土台が推測だらけなら、その上に立つ想定層も当然あてにならない。
 *
 *   2. 格子そのものの不確実性
 *      = 想定層のみのセル / 何らかの信号があるセル
 *      色が付いている箇所が全部「想定」なら、それは検出結果ではなく仮説の絵である。
 *
 * どちらも情報が無い場合は 1（最も不確実）に倒す。
 * 「判らない」を「安全」と読ませないための保守側への倒し方である。
 */
export function computeInferenceRatio(
  architecture: ArchitectureModel,
  cells: readonly HeatmapCell[],
): number {
  const ev = architecture.evidence;
  const evidenceTotal = ev.observed + ev.inferred + ev.assumed;
  const architectureUncertainty =
    evidenceTotal > 0 ? (ev.inferred + ev.assumed) / evidenceTotal : 1;

  let signalCells = 0;
  let inferredOnlyCells = 0;
  for (const cell of cells) {
    if (cell.basis === 'none') continue;
    signalCells++;
    if (cell.basis === 'inferred-only') inferredOnlyCells++;
  }
  const cellUncertainty = signalCells > 0 ? inferredOnlyCells / signalCells : 1;

  return round2(clamp01(0.5 * architectureUncertainty + 0.5 * cellUncertainty));
}
