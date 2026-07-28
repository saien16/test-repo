/** buildHeatmap 全体のテスト（格子の構築・取りこぼし・集計・純粋性） */

import { describe, expect, it } from 'vitest';
import { makeFinding } from '../killchain/test-fixtures.js';
import { UNASSIGNED_COMPONENT_ID } from './assign.js';
import {
  fact,
  makeArchitecture,
  makeChain,
  makeComponent,
  makeConfig,
  makeCtx,
  makeEntryPoint,
  makeFile,
} from './fixtures.js';
import { buildHeatmap, type BuildHeatmapInput } from './index.js';

function baseInput(overrides: Partial<BuildHeatmapInput> = {}): BuildHeatmapInput {
  const components = [
    makeComponent({ id: 'api', sourcePaths: ['src/api'] }),
    makeComponent({ id: 'db', kind: 'database', sourcePaths: ['src/db'] }),
  ];
  return {
    architecture: makeArchitecture({ components }),
    findings: [],
    chains: [],
    context: makeCtx({
      files: [makeFile('src/api/handler.ts'), makeFile('src/db/query.ts')],
    }),
    config: makeConfig(),
    ...overrides,
  };
}

describe('格子の構築', () => {
  it('行は構成要素、列は弱点カテゴリになり、全交点にセルができる', () => {
    const heatmap = buildHeatmap(baseInput());
    expect(heatmap.componentIds).toEqual(['api', 'db']);
    expect(heatmap.categories.length).toBeGreaterThan(5);
    expect(heatmap.cells).toHaveLength(heatmap.componentIds.length * heatmap.categories.length);
  });

  it('返り値のカテゴリ配列を書き換えても次回の結果に影響しない', () => {
    const first = buildHeatmap(baseInput());
    first.categories.length = 0;
    first.categories.push({ id: 'broken', name: '壊れた', cweIds: [] });
    const second = buildHeatmap(baseInput());
    expect(second.categories.length).toBeGreaterThan(5);
    expect(second.categories.some((c) => c.id === 'broken')).toBe(false);
  });

  it('Finding は CWE のカテゴリ・ファイルの構成要素のセルへ入る', () => {
    const heatmap = buildHeatmap(
      baseInput({
        findings: [
          makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts', baseScore: 9.8 }),
        ],
      }),
    );
    const cell = heatmap.cells.find((c) => c.componentId === 'api' && c.categoryId === 'injection');
    expect(cell?.findingIds).toEqual(['f1']);
    expect(cell?.observedRisk).toBe(98);
    expect(cell?.basis).toBe('both');
  });

  it('sourcePaths は最長一致で解決する', () => {
    const components = [
      makeComponent({ id: 'monolith', sourcePaths: ['src'] }),
      makeComponent({ id: 'api', sourcePaths: ['src/api'] }),
    ];
    const heatmap = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({ components }),
        findings: [makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts' })],
      }),
    );
    const cell = heatmap.cells.find((c) => c.findingIds.includes('f1'));
    expect(cell?.componentId).toBe('api');
  });

  it('sourcePaths は途中で切れた別ディレクトリに誤マッチしない', () => {
    const components = [makeComponent({ id: 'api', sourcePaths: ['src/api'] })];
    const heatmap = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({ components }),
        findings: [makeFinding({ id: 'f1', file: 'src/apiary/bee.ts' })],
      }),
    );
    const cell = heatmap.cells.find((c) => c.findingIds.includes('f1'));
    expect(cell?.componentId).toBe(UNASSIGNED_COMPONENT_ID);
  });

  it('sourcePaths で決まらない Finding は entryPointIds 経由で対応づける', () => {
    const components = [
      makeComponent({ id: 'api', sourcePaths: ['src/api'], entryPointIds: ['GET /health'] }),
    ];
    const heatmap = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({ components }),
        context: makeCtx({
          files: [makeFile('routes/health.ts')],
          entryPoints: [makeEntryPoint('GET /health', 'routes/health.ts')],
        }),
        findings: [makeFinding({ id: 'f1', cwe: 'CWE-79', file: 'routes/health.ts' })],
      }),
    );
    const cell = heatmap.cells.find((c) => c.findingIds.includes('f1'));
    expect(cell?.componentId).toBe('api');
  });
});

describe('取りこぼしを隠さない', () => {
  it('どの構成要素にも割り当たらない Finding は疑似構成要素へまとめられる', () => {
    const heatmap = buildHeatmap(
      baseInput({
        findings: [makeFinding({ id: 'orphan', cwe: 'CWE-89', file: 'scripts/legacy.ts' })],
      }),
    );
    expect(heatmap.componentIds).toContain(UNASSIGNED_COMPONENT_ID);
    const cell = heatmap.cells.find(
      (c) => c.componentId === UNASSIGNED_COMPONENT_ID && c.categoryId === 'injection',
    );
    expect(cell?.findingIds).toEqual(['orphan']);
    // 疑似構成要素には想定層を立てない（実在しないものの「起きうる話」はしない）
    expect(cell?.inferredRisk.provenance.kind).toBe('assumed');
    expect(cell?.inferredRisk.value).toBe(0);
  });

  it('未割当が無ければ疑似構成要素の行は作らない', () => {
    const heatmap = buildHeatmap(
      baseInput({ findings: [makeFinding({ id: 'f1', file: 'src/api/handler.ts' })] }),
    );
    expect(heatmap.componentIds).not.toContain(UNASSIGNED_COMPONENT_ID);
  });

  it("カタログに無い CWE の Finding も 'その他' 列で必ず残る", () => {
    const heatmap = buildHeatmap(
      baseInput({
        findings: [makeFinding({ id: 'f1', cwe: 'CWE-99999', file: 'src/api/handler.ts' })],
      }),
    );
    expect(heatmap.categories.some((c) => c.id === 'other')).toBe(true);
    const cell = heatmap.cells.find((c) => c.categoryId === 'other' && c.findingIds.length > 0);
    expect(cell?.findingIds).toEqual(['f1']);
  });

  it("'その他' 列は常に存在する（未知CWEの受け皿を切らさない）", () => {
    const heatmap = buildHeatmap(baseInput());
    expect(heatmap.categories.some((c) => c.id === 'other')).toBe(true);
  });

  it('入力した Finding は1件残らずどこかのセルに現れる', () => {
    const findings = [
      makeFinding({ id: 'a', cwe: 'CWE-89', file: 'src/api/handler.ts' }),
      makeFinding({ id: 'b', cwe: 'CWE-99999', file: 'src/db/query.ts' }),
      makeFinding({ id: 'c', cwe: 'CWE-798', file: 'nowhere/at/all.ts' }),
      makeFinding({ id: 'd', cwe: 'CWE-918', file: 'src/api/fetch.ts' }),
    ];
    const heatmap = buildHeatmap(baseInput({ findings }));
    const placed = new Set(heatmap.cells.flatMap((c) => c.findingIds));
    expect([...placed].sort()).toEqual(['a', 'b', 'c', 'd']);
    // 同じ Finding が2つのセルに重複計上されていないこと
    const all = heatmap.cells.flatMap((c) => c.findingIds);
    expect(all).toHaveLength(new Set(all).size);
  });
});

describe('攻撃チェーン', () => {
  it('セルの Finding が登場するチェーンを記録し、実測リスクを加算する', () => {
    const findings = [makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts', baseScore: 5 })];
    const withChain = buildHeatmap(
      baseInput({ findings, chains: [makeChain('chain-1', ['f1'])] }),
    );
    const without = buildHeatmap(baseInput({ findings }));

    const cellOf = (h: ReturnType<typeof buildHeatmap>) =>
      h.cells.find((c) => c.componentId === 'api' && c.categoryId === 'injection');

    expect(cellOf(withChain)?.chainIds).toEqual(['chain-1']);
    expect(cellOf(without)?.chainIds).toEqual([]);
    expect(cellOf(withChain)!.observedRisk).toBeGreaterThan(cellOf(without)!.observedRisk);
  });
});

describe('集計', () => {
  it('componentTotals / categoryTotals はセルの合計と一致する', () => {
    const heatmap = buildHeatmap(
      baseInput({
        findings: [
          makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts', baseScore: 7 }),
          makeFinding({ id: 'f2', cwe: 'CWE-79', file: 'src/db/query.ts', baseScore: 4 }),
        ],
      }),
    );

    for (const componentId of heatmap.componentIds) {
      const expected = heatmap.cells
        .filter((c) => c.componentId === componentId)
        .reduce((sum, c) => sum + c.observedRisk, 0);
      expect(heatmap.componentTotals[componentId]!.observed).toBeCloseTo(expected, 1);
    }
    for (const category of heatmap.categories) {
      const expected = heatmap.cells
        .filter((c) => c.categoryId === category.id)
        .reduce((sum, c) => sum + c.inferredRisk.value, 0);
      expect(heatmap.categoryTotals[category.id]!.inferred).toBeCloseTo(expected, 1);
    }
  });

  it('inferenceRatio は 0..1 に収まり、実測が増えるほど下がる', () => {
    const withoutFindings = buildHeatmap(baseInput());
    const withFindings = buildHeatmap(
      baseInput({
        findings: [
          makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts' }),
          makeFinding({ id: 'f2', cwe: 'CWE-79', file: 'src/api/view.ts' }),
          makeFinding({ id: 'f3', cwe: 'CWE-798', file: 'src/db/query.ts' }),
        ],
      }),
    );
    expect(withoutFindings.inferenceRatio).toBeGreaterThanOrEqual(0);
    expect(withoutFindings.inferenceRatio).toBeLessThanOrEqual(1);
    expect(withFindings.inferenceRatio).toBeLessThan(withoutFindings.inferenceRatio);
  });

  it('検出が皆無なら inferenceRatio は「推測寄り」に振れる', () => {
    const heatmap = buildHeatmap(baseInput());
    // アーキテクチャ推定の不確実性 (4/10) と 格子の不確実性 (1.0) の平均
    expect(heatmap.inferenceRatio).toBeCloseTo(0.7, 5);
  });

  it('アーキテクチャ推定が推測だらけなら inferenceRatio が上がる', () => {
    const shaky = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({
          components: [makeComponent({ id: 'api', sourcePaths: ['src/api'] })],
          evidence: { observed: 0, inferred: 8, assumed: 2, meanInferredConfidence: 0.4 },
        }),
      }),
    );
    const solid = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({
          components: [makeComponent({ id: 'api', sourcePaths: ['src/api'] })],
          evidence: { observed: 10, inferred: 0, assumed: 0, meanInferredConfidence: null },
        }),
      }),
    );
    expect(shaky.inferenceRatio).toBeGreaterThan(solid.inferenceRatio);
  });
});

describe('純粋関数であること', () => {
  const input = baseInput({
    findings: [
      makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts', baseScore: 9.1 }),
      makeFinding({ id: 'f2', cwe: 'CWE-99999', file: 'zzz/other.ts' }),
    ],
    chains: [makeChain('c1', ['f1'])],
  });

  it('同じ入力からは同じ出力を返す', () => {
    const a = buildHeatmap(input);
    const b = buildHeatmap(input);
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it('入力を変更しない', () => {
    const snapshot = JSON.stringify(input);
    buildHeatmap(input);
    buildHeatmap(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it('Finding や構成要素の並び順を変えても結果は同じ（順序非依存）', () => {
    const reversed: BuildHeatmapInput = {
      ...input,
      findings: [...input.findings].reverse(),
    };
    const a = buildHeatmap(input);
    const b = buildHeatmap(reversed);
    expect(b.cells).toEqual(a.cells);
    expect(b.blindSpots).toEqual(a.blindSpots);
  });
});

describe('層の重ね合わせ', () => {
  it('4象限が basis として区別される', () => {
    const components = [
      // 公開API: 想定は高い。CWE-89 の検出もある → both
      makeComponent({ id: 'api', sourcePaths: ['src/api'] }),
      // ローカルCLI: 想定は低い。検出だけある → observed-only
      makeComponent({
        id: 'cli',
        kind: 'cli',
        technology: fact('ローカル実行のCLI'),
        exposure: fact('local'),
        dataSensitivity: fact(['none']),
        requiresAuthentication: fact(true),
        sourcePaths: ['src/cli'],
      }),
    ];
    const heatmap = buildHeatmap(
      baseInput({
        architecture: makeArchitecture({ components }),
        context: makeCtx({
          files: [makeFile('src/api/handler.ts'), makeFile('src/cli/main.ts')],
          frameworks: [],
        }),
        findings: [
          makeFinding({ id: 'f1', cwe: 'CWE-89', file: 'src/api/handler.ts', baseScore: 9 }),
          makeFinding({ id: 'f2', cwe: 'CWE-78', file: 'src/cli/main.ts', baseScore: 6 }),
        ],
      }),
    );

    const cell = (componentId: string, categoryId: string) =>
      heatmap.cells.find((c) => c.componentId === componentId && c.categoryId === categoryId);

    expect(cell('api', 'injection')?.basis).toBe('both');
    expect(cell('cli', 'injection')?.basis).toBe('observed-only');
    // 公開APIの認証カテゴリは検出が無いが想定は高い → 想定のみ（＝死角の候補）
    expect(cell('api', 'authentication')?.basis).toBe('inferred-only');
    // ローカルCLIのログ・監視カテゴリは検出も無く想定も低い
    expect(cell('cli', 'logging')?.basis).toBe('none');
  });

  it('想定層は Claim として根拠を持ち、事実と推測の別が読み取れる', () => {
    const heatmap = buildHeatmap(baseInput());
    const cell = heatmap.cells.find(
      (c) => c.componentId === 'api' && c.categoryId === 'injection',
    );
    const provenance = cell!.inferredRisk.provenance;
    expect(provenance.kind).toBe('inferred');
    if (provenance.kind !== 'inferred') throw new Error('unreachable');
    expect(provenance.inferredBy).toBe('catalog');
    expect(provenance.reasoning).toContain('CWE-');
    expect(provenance.reasoning).toContain('露出度');
    expect(provenance.reasoning).toContain('確信度の内訳');
    expect(provenance.alternatives?.length).toBeGreaterThan(0);
    // 実測層は Claim で包まない（事実なので findingIds が引用を兼ねる）
    expect(typeof cell!.observedRisk).toBe('number');
  });
});
