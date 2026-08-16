/** 想定層の算出と、推測の確信度の減衰・伝播のテスト */

import { describe, expect, it } from 'vitest';
import type { DataSensitivity, Exposure } from '../types/architecture.js';
import { cwesForComponent, weaknessCategories } from './catalog-adapter.js';
import { ASSUMED_FACTOR } from './confidence.js';
import {
  assume,
  fact,
  guess,
  makeArchitecture,
  makeComponent,
  makeCtx,
  makeDataFlow,
  makeFile,
  type ComponentOverrides,
} from './fixtures.js';
import { computeInferred } from './inferred.js';
import { derivePlatform } from './platform.js';

const CATEGORIES = weaknessCategories();

function category(id: string) {
  const found = CATEGORIES.find((c) => c.id === id);
  if (!found) throw new Error(`テスト定義の誤り: カテゴリ ${id} が無い`);
  return found;
}

function evaluate(
  overrides: ComponentOverrides,
  categoryId: string,
  minInferenceConfidence = 0.3,
  ctxOverrides: { files?: ReturnType<typeof makeFile>[]; frameworks?: { name: string; evidence: string }[] } = {},
) {
  const component = makeComponent(overrides);
  const architecture = makeArchitecture({ components: [component] });
  const ctx = makeCtx({
    files: ctxOverrides.files ?? [makeFile('src/api/handler.ts')],
    ...(ctxOverrides.frameworks ? { frameworks: ctxOverrides.frameworks } : {}),
  });
  const platform = derivePlatform(component, architecture, ctx);
  const candidates = cwesForComponent(platform).get(categoryId) ?? [];
  return computeInferred(
    component,
    category(categoryId),
    platform,
    candidates,
    minInferenceConfidence,
  );
}

const API: ComponentOverrides = {
  id: 'api',
  kind: 'api-service',
  sourcePaths: ['src/api'],
};

describe('computeInferred: 確信度の減衰と伝播', () => {
  it('すべての根拠が事実なら、確信度はカタログ由来の基礎確信度になる', () => {
    const result = evaluate(API, 'injection');
    expect(result.suppressed).toBe(false);
    // 主根拠となるCWEの悪用可能性がカタログ上既知なので基礎確信度は 0.8
    expect(result.confidence).toBeCloseTo(0.8, 5);
    expect(result.claim.provenance.kind).toBe('inferred');
  });

  it('推測に基づく推測は確信度が掛け合わされて減衰する', () => {
    const allFacts = evaluate(API, 'injection');
    const oneGuess = evaluate({ ...API, exposure: guess<Exposure>('public-internet', 0.5) }, 'injection');
    const twoGuesses = evaluate(
      {
        ...API,
        exposure: guess<Exposure>('public-internet', 0.5),
        requiresAuthentication: guess(false, 0.8),
      },
      'injection',
    );

    expect(oneGuess.confidence).toBeCloseTo(allFacts.confidence * 0.5, 5);
    expect(twoGuesses.confidence).toBeCloseTo(allFacts.confidence * 0.5 * 0.8, 5);
    // 減衰しても「起きうる危険の大きさ」自体は変わらない（値と確信度は別の軸）
    expect(oneGuess.rawRisk).toBe(allFacts.rawRisk);
  });

  it('仮定(assumed)は確信度を持たないため一律の減衰係数が掛かる', () => {
    const allFacts = evaluate(API, 'injection');
    const withAssumption = evaluate({ ...API, exposure: assume<Exposure>('public-internet') }, 'injection');
    expect(withAssumption.confidence).toBeCloseTo(allFacts.confidence * ASSUMED_FACTOR, 5);
  });

  it('技術スタックの推測も確信度に伝播する', () => {
    const withFact = evaluate(API, 'injection');
    const withGuess = evaluate({ ...API, technology: guess('Express on Node.js 20', 0.4) }, 'injection');
    expect(withGuess.confidence).toBeCloseTo(withFact.confidence * 0.4, 5);
  });

  it('構成要素配下のファイルが特定できないと言語の特定が仮定扱いになり減衰する', () => {
    const withFiles = evaluate(API, 'injection', 0.3, { files: [makeFile('src/api/handler.ts')] });
    const withoutFiles = evaluate(API, 'injection', 0.3, { files: [makeFile('src/other/x.ts')] });
    expect(withoutFiles.confidence).toBeLessThan(withFiles.confidence);
  });

  it('データフロー経由の推測も確信度に伝播する（複数あるときは最弱の1件で代表させる）', () => {
    const api = makeComponent({ ...API, technology: fact('HTTPサービス') });
    const db = makeComponent({ id: 'db', kind: 'database', sourcePaths: [] });
    const cache = makeComponent({ id: 'cache', kind: 'cache', sourcePaths: [] });
    const architecture = makeArchitecture({
      components: [api, db, cache],
      dataFlows: [
        makeDataFlow('api', 'db', guess('SQL', 0.6)),
        makeDataFlow('api', 'cache', guess('Redis', 0.9)),
      ],
    });
    const ctx = makeCtx({ files: [makeFile('src/api/handler.ts')] });
    const platform = derivePlatform(api, architecture, ctx);

    expect(platform.technologies).toContain('Database Server');
    // 積(0.6*0.9)ではなく最弱(0.6)が採られる
    const result = computeInferred(
      api,
      category('injection'),
      platform,
      cwesForComponent(platform).get('injection') ?? [],
      0.3,
    );
    expect(result.confidence).toBeCloseTo(0.8 * 0.6, 5);
  });
});

describe('computeInferred: minInferenceConfidence による除外', () => {
  it('閾値未満の推測はセルに反映されない（値0）', () => {
    const overrides: ComponentOverrides = {
      ...API,
      exposure: guess<Exposure>('public-internet', 0.3),
      dataSensitivity: guess<DataSensitivity[]>(['credentials'], 0.3),
    };
    const result = evaluate(overrides, 'injection', 0.3);

    expect(result.confidence).toBeLessThan(0.3);
    expect(result.suppressed).toBe(true);
    expect(result.claim.value).toBe(0);
    // 素の想定リスク自体は高い（＝黙って消したのではない）
    expect(result.rawRisk).toBeGreaterThan(50);
  });

  it('除外しても理由は残る（黙って消さない）', () => {
    const result = evaluate({ ...API, exposure: assume<Exposure>('public-internet') }, 'injection', 0.9);
    expect(result.suppressed).toBe(true);
    const provenance = result.claim.provenance;
    expect(provenance.kind).toBe('inferred');
    if (provenance.kind !== 'inferred') throw new Error('unreachable');
    expect(provenance.reasoning).toContain('minInferenceConfidence');
    expect(provenance.reasoning).toContain('0.9');
  });

  it('閾値ちょうどは採用する（未満のみ除外）', () => {
    const result = evaluate(API, 'injection', 0.8);
    expect(result.confidence).toBeCloseTo(0.8, 5);
    expect(result.suppressed).toBe(false);
    expect(result.claim.value).toBeGreaterThan(0);
  });
});

describe('computeInferred: 重み付け', () => {
  it('露出度が高いほど想定リスクが高い', () => {
    const publicRisk = evaluate({ ...API, exposure: fact<Exposure>('public-internet') }, 'injection').rawRisk;
    const internalRisk = evaluate({ ...API, exposure: fact<Exposure>('internal') }, 'injection').rawRisk;
    const localRisk = evaluate({ ...API, exposure: fact<Exposure>('local') }, 'injection').rawRisk;
    expect(publicRisk).toBeGreaterThan(internalRisk);
    expect(internalRisk).toBeGreaterThan(localRisk);
  });

  it('扱うデータが機微なほど想定リスクが高い', () => {
    const credentials = evaluate(
      { ...API, dataSensitivity: fact<DataSensitivity[]>(['credentials']) },
      'access-control',
    ).rawRisk;
    const business = evaluate(
      { ...API, dataSensitivity: fact<DataSensitivity[]>(['business']) },
      'access-control',
    ).rawRisk;
    const none = evaluate(
      { ...API, dataSensitivity: fact<DataSensitivity[]>(['none']) },
      'access-control',
    ).rawRisk;
    expect(credentials).toBeGreaterThan(business);
    expect(business).toBeGreaterThan(none);
  });

  it('未認証かつインターネット公開なら大幅に加算される', () => {
    const unauthenticated = evaluate(
      { ...API, exposure: fact<Exposure>('public-internet'), requiresAuthentication: fact(false) },
      'access-control',
    ).rawRisk;
    const authenticated = evaluate(
      { ...API, exposure: fact<Exposure>('public-internet'), requiresAuthentication: fact(true) },
      'access-control',
    ).rawRisk;
    const unauthenticatedLocal = evaluate(
      { ...API, exposure: fact<Exposure>('local'), requiresAuthentication: fact(false) },
      'access-control',
    ).rawRisk;

    expect(unauthenticated).toBeGreaterThan(authenticated);
    // 公開面での未認証は、ローカルでの未認証より効きが大きい
    const publicBoost = unauthenticated / authenticated;
    const localBoost =
      unauthenticatedLocal /
      evaluate(
        { ...API, exposure: fact<Exposure>('local'), requiresAuthentication: fact(true) },
        'access-control',
      ).rawRisk;
    expect(publicBoost).toBeGreaterThan(localBoost);
  });

  it('技術スタックに該当CWEが無ければ「仮定としての0」を返す', () => {
    // 'other' はどのカテゴリにも畳めなかったCWEの受け皿で、
    // 言語・技術のいずれからも引かれない
    const result = evaluate(API, 'other');
    expect(result.matchedCweIds).toEqual([]);
    expect(result.claim.value).toBe(0);
    expect(result.claim.provenance.kind).toBe('assumed');
  });

  it('言語・技術非依存のCWEしか無いカテゴリは素点が割り引かれる', () => {
    // 'authentication' は CWE-287 など言語非依存のCWEばかり（スタック固有0件）、
    // 'xss' は CWE-79 がスタック固有として当たる
    const generic = evaluate(API, 'authentication');
    const specific = evaluate(API, 'xss');
    expect(generic.specificCweIds).toHaveLength(0);
    expect(specific.specificCweIds.length).toBeGreaterThan(0);
    expect(specific.rawRisk).toBeGreaterThan(generic.rawRisk);
    const provenance = generic.claim.provenance;
    if (provenance.kind !== 'inferred') throw new Error('unreachable');
    expect(provenance.reasoning).toContain('非依存');
  });

  it('想定リスクは 0..100 に収まる', () => {
    for (const c of CATEGORIES) {
      const result = evaluate(API, c.id);
      expect(result.claim.value).toBeGreaterThanOrEqual(0);
      expect(result.claim.value).toBeLessThanOrEqual(100);
    }
  });
});
