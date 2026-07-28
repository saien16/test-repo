import { describe, expect, it } from 'vitest';
import { makeContext, makeCvss, makeFinding, makeChain } from './fixtures.js';
import { summarize } from './summarize.js';

const extra = {
  durationMs: 4567.4,
  suppressedCount: 3,
  tokenUsage: { input: 1000, output: 2000, cacheRead: 3000, cacheWrite: 4000 },
};

describe('summarize', () => {
  it('深刻度別・カテゴリ別に集計する', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [
          makeFinding({ id: 'f-1', severity: 'critical', category: 'A03:2021-Injection' }),
          makeFinding({ id: 'f-2', severity: 'high', category: 'A03:2021-Injection' }),
          makeFinding({ id: 'f-3', severity: 'high', category: 'A02:2021-Cryptographic Failures' }),
          makeFinding({ id: 'f-4', severity: 'low', category: 'A05:2021-Security Misconfiguration' }),
        ],
        chains: [],
        errors: [],
      },
      extra,
    );

    expect(summary.totalFindings).toBe(4);
    expect(summary.bySeverity).toEqual({ critical: 1, high: 2, medium: 0, low: 1, info: 0 });
    expect(summary.byCategory['A03:2021-Injection']).toBe(2);
    expect(summary.byCategory['A02:2021-Cryptographic Failures']).toBe(1);
  });

  it('全ての深刻度キーを 0 で初期化する', () => {
    const summary = summarize(
      { context: makeContext(), findings: [], chains: [], errors: [] },
      extra,
    );
    expect(Object.keys(summary.bySeverity).sort()).toEqual(
      ['critical', 'high', 'info', 'low', 'medium'].sort(),
    );
    expect(summary.totalFindings).toBe(0);
    expect(summary.maxCvssScore).toBe(0);
  });

  it('diffStatus を new/fixed/persistent に振り分ける', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [
          makeFinding({ id: 'f-1', diffStatus: 'new' }),
          makeFinding({ id: 'f-2', diffStatus: 'new' }),
          makeFinding({ id: 'f-3', diffStatus: 'persistent' }),
          makeFinding({ id: 'f-4', diffStatus: 'fixed' }),
        ],
        chains: [],
        errors: [],
      },
      extra,
    );

    expect(summary.newCount).toBe(2);
    expect(summary.persistentCount).toBe(1);
    expect(summary.fixedCount).toBe(1);
  });

  it('修正済み(fixed)と誤検知は現存件数から除外する', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [
          makeFinding({ id: 'f-1', severity: 'critical' }),
          makeFinding({ id: 'f-2', severity: 'high', diffStatus: 'fixed' }),
          makeFinding({ id: 'f-3', severity: 'high', status: 'false-positive' }),
        ],
        chains: [],
        errors: [],
      },
      extra,
    );

    // 差分カウントには残るが、現存件数からは外れる
    expect(summary.fixedCount).toBe(1);
    expect(summary.totalFindings).toBe(1);
    expect(summary.bySeverity.high).toBe(0);
    expect(summary.bySeverity.critical).toBe(1);
  });

  it('maxCvssScore は現存Findingの最大値', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [
          makeFinding({ id: 'f-1', cvss: makeCvss({ baseScore: 6.1 }) }),
          makeFinding({ id: 'f-2', cvss: makeCvss({ baseScore: 8.8 }) }),
          // fixed のものは最大値に影響しない
          makeFinding({ id: 'f-3', diffStatus: 'fixed', cvss: makeCvss({ baseScore: 10 }) }),
        ],
        chains: [],
        errors: [],
      },
      extra,
    );
    expect(summary.maxCvssScore).toBe(8.8);
  });

  it('chainCount / filesScanned / extra をそのまま反映する', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [],
        chains: [makeChain({ id: 'ch-1' }), makeChain({ id: 'ch-2' })],
        errors: [],
      },
      extra,
    );

    expect(summary.chainCount).toBe(2);
    expect(summary.filesScanned).toBe(2);
    expect(summary.suppressedCount).toBe(3);
    expect(summary.durationMs).toBe(4567);
    expect(summary.tokenUsage).toEqual(extra.tokenUsage);
  });

  it('カテゴリが空文字なら (未分類) にまとめる', () => {
    const summary = summarize(
      {
        context: makeContext(),
        findings: [makeFinding({ id: 'f-1', category: '' })],
        chains: [],
        errors: [],
      },
      extra,
    );
    expect(summary.byCategory['(未分類)']).toBe(1);
  });
});
