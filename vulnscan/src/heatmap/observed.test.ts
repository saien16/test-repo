/** 実測層の算出式のテスト */

import { describe, expect, it } from 'vitest';
import { makeFinding } from '../killchain/test-fixtures.js';
import { makeChain } from './fixtures.js';
import { chainIndexByFinding, computeObserved, COUNT_WEIGHT, CHAIN_WEIGHT } from './observed.js';

const NO_CHAINS = new Map<string, string[]>();

describe('computeObserved', () => {
  it('Finding が無ければ 0 を返す', () => {
    const result = computeObserved([], NO_CHAINS);
    expect(result).toEqual({ risk: 0, findingIds: [], chainIds: [] });
  });

  it('1件なら CVSS を10倍した値になる（0..100正規化）', () => {
    const result = computeObserved([makeFinding({ id: 'f1', baseScore: 7.5 })], NO_CHAINS);
    expect(result.risk).toBe(75);
    expect(result.findingIds).toEqual(['f1']);
  });

  it('最大値が主。低スコアが何件あっても最悪の1件を下回らない', () => {
    const oneCritical = computeObserved([makeFinding({ id: 'a', baseScore: 9.8 })], NO_CHAINS);
    const manyLow = computeObserved(
      Array.from({ length: 20 }, (_, i) => makeFinding({ id: `low-${i}`, baseScore: 3.1 })),
      NO_CHAINS,
    );
    expect(oneCritical.risk).toBeGreaterThan(manyLow.risk);
  });

  it('件数は log 補正で緩やかにしか効かない', () => {
    const one = computeObserved([makeFinding({ id: 'a', baseScore: 5 })], NO_CHAINS);
    const two = computeObserved(
      [makeFinding({ id: 'a', baseScore: 5 }), makeFinding({ id: 'b', baseScore: 5 })],
      NO_CHAINS,
    );
    const four = computeObserved(
      ['a', 'b', 'c', 'd'].map((id) => makeFinding({ id, baseScore: 5 })),
      NO_CHAINS,
    );
    expect(one.risk).toBe(50);
    expect(two.risk).toBeCloseTo(50 + COUNT_WEIGHT, 5);
    expect(four.risk).toBeCloseTo(50 + COUNT_WEIGHT * 2, 5);
  });

  it('攻撃チェーンに登場する Finding はリスクが加算され chainIds に記録される', () => {
    const findings = [makeFinding({ id: 'f1', baseScore: 5 })];
    const chains = [makeChain('c1', ['f1'])];
    const withChain = computeObserved(findings, chainIndexByFinding(chains));
    const withoutChain = computeObserved(findings, NO_CHAINS);

    expect(withChain.risk).toBeCloseTo(withoutChain.risk + CHAIN_WEIGHT * Math.log2(2), 5);
    expect(withChain.chainIds).toEqual(['c1']);
  });

  it('100 を超えない', () => {
    const findings = Array.from({ length: 50 }, (_, i) =>
      makeFinding({ id: `f${i}`, baseScore: 10 }),
    );
    const chains = [makeChain('c1', findings.map((f) => f.id))];
    expect(computeObserved(findings, chainIndexByFinding(chains)).risk).toBe(100);
  });

  it('chokePoint だけが指している Finding もチェーン登場として拾う', () => {
    const chain = makeChain('c1', [null]);
    chain.chokePoint = { findingId: 'f1', rationale: 'ここを塞ぐ' };
    const index = chainIndexByFinding([chain]);
    expect(index.get('f1')).toEqual(['c1']);
  });

  it('出力の ID 順は入力順に依存しない（決定的）', () => {
    const a = computeObserved(
      [makeFinding({ id: 'b1' }), makeFinding({ id: 'a1' })],
      NO_CHAINS,
    );
    const b = computeObserved(
      [makeFinding({ id: 'a1' }), makeFinding({ id: 'b1' })],
      NO_CHAINS,
    );
    expect(a).toEqual(b);
    expect(a.findingIds).toEqual(['a1', 'b1']);
  });
});
