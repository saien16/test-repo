/** 死角の抽出と、その原因の4分類のテスト */

import { describe, expect, it } from 'vitest';
import { makeFinding } from '../killchain/test-fixtures.js';
import type { BlindSpot } from '../types/heatmap.js';
import { diagnoseCause } from './blindspots.js';
import { weaknessCategories } from './catalog-adapter.js';
import {
  fact,
  makeArchitecture,
  makeComponent,
  makeConfig,
  makeCtx,
  makeFile,
} from './fixtures.js';
import { buildHeatmap } from './index.js';

const CATEGORIES = weaknessCategories();
const WEB_OUTPUT = CATEGORIES.find((c) => c.id === 'web-output')!;
const INSECURE_DESIGN = CATEGORIES.find((c) => c.id === 'insecure-design')!;

/**
 * 4種類の死角が同時に現れるように仕組んだシナリオ:
 *   api    … 走査済み・レンズ有効 → genuinely-absent
 *   admin  … exclude で丸ごと除外 → not-scanned
 *   worker … ctx.files に1件も無い → not-scanned
 *   idp    … sourcePaths が無く判定不能 → unknown
 * さらに api の insecure-design カテゴリは担当レンズが無い → no-matching-lens
 */
function scenario(overrides: { minInferenceConfidence?: number; lenses?: string[] } = {}) {
  const components = [
    makeComponent({ id: 'api', sourcePaths: ['src/api'] }),
    makeComponent({ id: 'admin', sourcePaths: ['src/admin'] }),
    makeComponent({ id: 'worker', sourcePaths: ['src/worker'] }),
    makeComponent({ id: 'idp', kind: 'auth-provider', sourcePaths: [] }),
  ];
  const architecture = makeArchitecture({ components });
  const ctx = makeCtx({
    files: [makeFile('src/api/handler.ts'), makeFile('src/admin/panel.ts')],
  });
  const config = makeConfig({
    minInferenceConfidence: overrides.minInferenceConfidence ?? 0.3,
    scan: {
      ...makeConfig().scan,
      exclude: ['**/node_modules/**', '**/admin/**'],
      ...(overrides.lenses ? { lenses: overrides.lenses as never } : {}),
    },
  });
  return buildHeatmap({ architecture, findings: [], chains: [], context: ctx, config });
}

function spotFor(spots: readonly BlindSpot[], componentId: string, categoryId: string): BlindSpot {
  const found = spots.find((s) => s.componentId === componentId && s.categoryId === categoryId);
  if (!found) {
    throw new Error(
      `死角が見つからない: ${componentId} × ${categoryId} / 実際: ` +
        spots.map((s) => `${s.componentId}×${s.categoryId}`).join(', '),
    );
  }
  return found;
}

describe('死角の原因の切り分け', () => {
  it('走査済み・担当レンズ有効なのに検出が無いなら genuinely-absent', () => {
    const heatmap = scenario();
    const spot = spotFor(heatmap.blindSpots, 'api', 'web-output');
    expect(spot.likelyCause).toBe('genuinely-absent');
    expect(spot.reasoning).toContain('web-output');
    expect(spot.recommendedAction.length).toBeGreaterThan(0);
  });

  it('exclude の glob で丸ごと除外されていれば not-scanned', () => {
    const heatmap = scenario();
    const spot = spotFor(heatmap.blindSpots, 'admin', 'web-output');
    expect(spot.likelyCause).toBe('not-scanned');
    expect(spot.reasoning).toContain('scan.exclude');
  });

  it('ctx.files に該当ファイルが1件も無ければ not-scanned', () => {
    const heatmap = scenario();
    const spot = spotFor(heatmap.blindSpots, 'worker', 'web-output');
    expect(spot.likelyCause).toBe('not-scanned');
    expect(spot.reasoning).toContain('ScanContext.files');
  });

  it('担当レンズが存在しないカテゴリは no-matching-lens', () => {
    const heatmap = scenario();
    const spot = spotFor(heatmap.blindSpots, 'api', 'insecure-design');
    expect(spot.likelyCause).toBe('no-matching-lens');
  });

  it('担当レンズはあるが scan.lenses で無効なら no-matching-lens', () => {
    const heatmap = scenario({ lenses: ['injection'] });
    const spot = spotFor(heatmap.blindSpots, 'api', 'web-output');
    expect(spot.likelyCause).toBe('no-matching-lens');
    expect(spot.reasoning).toContain('web-output');
  });

  it('ソースパスが登録されていない構成要素は unknown', () => {
    const heatmap = scenario();
    const spot = spotFor(heatmap.blindSpots, 'idp', 'web-output');
    expect(spot.likelyCause).toBe('unknown');
    expect(spot.recommendedAction).toContain('外部サービス');
  });

  it('「走査していない」は「レンズが無い」より優先して報告される', () => {
    // 除外されている構成要素 × 担当レンズの無いカテゴリ → not-scanned が勝つ
    const component = makeComponent({ id: 'admin', sourcePaths: ['src/admin'] });
    const ctx = makeCtx({ files: [makeFile('src/admin/panel.ts')] });
    const config = makeConfig({
      scan: { ...makeConfig().scan, exclude: ['**/admin/**'] },
    });
    expect(diagnoseCause(component, INSECURE_DESIGN, ctx, config).cause).toBe('not-scanned');
  });
});

describe('死角の抽出条件', () => {
  it('実測リスクが高いセルは死角にならない', () => {
    const component = makeComponent({ id: 'api', sourcePaths: ['src/api'] });
    const architecture = makeArchitecture({ components: [component] });
    const ctx = makeCtx({ files: [makeFile('src/api/handler.ts')] });
    const heatmap = buildHeatmap({
      architecture,
      findings: [makeFinding({ id: 'f1', cwe: 'CWE-79', file: 'src/api/handler.ts', baseScore: 8 })],
      chains: [],
      context: ctx,
      config: makeConfig(),
    });
    expect(
      heatmap.blindSpots.some((s) => s.componentId === 'api' && s.categoryId === 'web-output'),
    ).toBe(false);
  });

  it('確信度が minInferenceConfidence 未満の推測では死角を騒ぎ立てない', () => {
    const heatmap = scenario({ minInferenceConfidence: 0.95 });
    expect(heatmap.blindSpots).toEqual([]);
    // 想定層が全て 0 になっているので、格子は「想定のみ」のセルを持たない
    expect(heatmap.cells.every((c) => c.inferredRisk.value === 0)).toBe(true);
  });

  it('露出度が低く機微データも扱わない構成要素は死角にならない', () => {
    const component = makeComponent({
      id: 'cli',
      kind: 'cli',
      technology: fact('ローカル実行のCLI'),
      exposure: fact('local'),
      dataSensitivity: fact(['none']),
      requiresAuthentication: fact(true),
      sourcePaths: ['src/cli'],
    });
    const heatmap = buildHeatmap({
      architecture: makeArchitecture({ components: [component] }),
      findings: [],
      chains: [],
      context: makeCtx({ files: [makeFile('src/cli/main.ts')], frameworks: [] }),
      config: makeConfig(),
    });
    expect(heatmap.blindSpots).toEqual([]);
  });

  it('死角は想定リスクの高い順に並ぶ（決定的）', () => {
    const spots = scenario().blindSpots;
    expect(spots.length).toBeGreaterThan(1);
    for (let i = 1; i < spots.length; i++) {
      const previous = spots[i - 1]!;
      const current = spots[i]!;
      expect(previous.inferredRisk).toBeGreaterThanOrEqual(current.inferredRisk);
    }
  });

  it('未割当の疑似構成要素は死角の対象にしない', () => {
    const heatmap = buildHeatmap({
      architecture: makeArchitecture({ components: [makeComponent({ id: 'api' })] }),
      findings: [makeFinding({ id: 'orphan', file: 'unknown/place.ts' })],
      chains: [],
      context: makeCtx({ files: [makeFile('src/api/handler.ts')] }),
      config: makeConfig(),
    });
    expect(heatmap.blindSpots.some((s) => s.componentId === '__unassigned__')).toBe(false);
  });

  it('WEB_OUTPUT カテゴリの想定リスクは死角判定のしきい値を超える（前提の確認）', () => {
    const heatmap = scenario();
    const cell = heatmap.cells.find(
      (c) => c.componentId === 'api' && c.categoryId === WEB_OUTPUT.id,
    );
    expect(cell?.inferredRisk.value).toBeGreaterThanOrEqual(45);
  });
});
