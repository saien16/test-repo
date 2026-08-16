/**
 * 数値ユーティリティのテスト。
 *
 * 統合前は `clamp01` が計7箇所にあり、`vuln/normalize.ts` のものだけ
 * 非有限値のフォールバックが 0.5 だった（他は全部 0）。
 * 同名で挙動が違うのが危険なので、意図の違いを名前で分けたことを固定する。
 */

import { describe, expect, it } from 'vitest';
import { clamp01, clampConfidence, round1, round2 } from './num.js';

describe('clamp01', () => {
  it('0..1 に丸める', () => {
    expect(clamp01(-1)).toBe(0);
    expect(clamp01(0)).toBe(0);
    expect(clamp01(0.42)).toBe(0.42);
    expect(clamp01(1)).toBe(1);
    expect(clamp01(2)).toBe(1);
  });

  it('非有限値は 0 に倒す', () => {
    expect(clamp01(Number.NaN)).toBe(0);
    expect(clamp01(Number.POSITIVE_INFINITY)).toBe(0);
    expect(clamp01(Number.NEGATIVE_INFINITY)).toBe(0);
  });
});

describe('clampConfidence', () => {
  it('丸め方は clamp01 と同じ', () => {
    for (const v of [-1, 0, 0.42, 1, 2]) {
      expect(clampConfidence(v)).toBe(clamp01(v));
    }
  });

  it('非有限値は 0.5（＝判断材料が無い）に倒す。ここが clamp01 との唯一の違い', () => {
    expect(clampConfidence(Number.NaN)).toBe(0.5);
    expect(clamp01(Number.NaN)).toBe(0);
  });

  it('フォールバック値は呼び出し側で変えられる', () => {
    expect(clampConfidence(Number.NaN, 0.3)).toBe(0.3);
  });
});

describe('round1 / round2', () => {
  it('指定した桁へ四捨五入する', () => {
    expect(round1(1.24)).toBe(1.2);
    expect(round1(1.25)).toBe(1.3);
    expect(round2(1.234)).toBe(1.23);
    expect(round2(1.235)).toBe(1.24);
  });

  it('丸めても符号と 0 は保つ', () => {
    expect(round1(0)).toBe(0);
    expect(round1(-1.24)).toBe(-1.2);
  });
});
