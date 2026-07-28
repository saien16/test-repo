import { describe, expect, it } from 'vitest';
import type { AttackTactic } from '../types/killchain.js';
import {
  computeImpactScore,
  computeLikelihoodScore,
  likelihoodLabel,
  scoreChain,
  scoreChokePoints,
  selectChokePoint,
  terminalImpactOf,
  type ChokePointCandidate,
  type ScoringInput,
} from './scoring.js';

function input(o: Partial<ScoringInput>): ScoringInput {
  return {
    cvssScores: [5.5],
    confidences: [0.8],
    reachabilityRatio: 1,
    exposure: 1,
    llmLikelihood: 'medium',
    stepCount: 1,
    tactics: ['initial-access'],
    ...o,
  };
}

/** 「単独では medium が2つ、連鎖すると RCE」のケース */
const CHAINED_MEDIUMS_TO_RCE: ScoringInput = input({
  cvssScores: [5.5, 6.1],
  confidences: [0.75, 0.8],
  reachabilityRatio: 1,
  exposure: 1,
  llmLikelihood: 'medium',
  stepCount: 3,
  tactics: ['initial-access', 'credential-access', 'execution'],
});

/** 孤立した high（単体で終わる） */
const ISOLATED_HIGH: ScoringInput = input({
  cvssScores: [7.5],
  confidences: [0.85],
  reachabilityRatio: 1,
  exposure: 1,
  llmLikelihood: 'high',
  stepCount: 1,
  tactics: ['privilege-escalation'],
});

describe('terminalImpactOf', () => {
  it('連鎖中で最も価値の高い戦術を採る', () => {
    expect(terminalImpactOf(['discovery', 'execution', 'initial-access'])).toBe(1.0);
  });

  it('戦術が空でも 0 にはならない', () => {
    expect(terminalImpactOf([])).toBeGreaterThan(0);
  });
});

describe('computeImpactScore', () => {
  it('CVSS が同じでも到達戦術が強いほど影響が大きい', () => {
    const weak = computeImpactScore(input({ tactics: ['discovery'] }));
    const strong = computeImpactScore(input({ tactics: ['execution'] }));
    expect(strong).toBeGreaterThan(weak);
  });

  it('0..1 に収まる', () => {
    const s = computeImpactScore(input({ cvssScores: [10], tactics: ['execution'] }));
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThanOrEqual(1);
  });
});

describe('computeLikelihoodScore', () => {
  it('到達性が証明されているほど高い', () => {
    const lo = computeLikelihoodScore(input({ reachabilityRatio: 0 }));
    const hi = computeLikelihoodScore(input({ reachabilityRatio: 1 }));
    expect(hi).toBeGreaterThan(lo);
  });

  it('露出度が高いほど高い', () => {
    const lo = computeLikelihoodScore(input({ exposure: 0.2 }));
    const hi = computeLikelihoodScore(input({ exposure: 1 }));
    expect(hi).toBeGreaterThan(lo);
  });

  it('ステップが増えるほど減衰する', () => {
    const short = computeLikelihoodScore(input({ stepCount: 1 }));
    const long = computeLikelihoodScore(input({ stepCount: 5 }));
    expect(long).toBeLessThan(short);
  });

  it('確信度が空でも NaN にならない', () => {
    expect(Number.isFinite(computeLikelihoodScore(input({ confidences: [] })))).toBe(true);
  });
});

describe('likelihoodLabel', () => {
  it('しきい値で 3 段階に分ける', () => {
    expect(likelihoodLabel(0.9)).toBe('high');
    expect(likelihoodLabel(0.5)).toBe('medium');
    expect(likelihoodLabel(0.2)).toBe('low');
  });
});

describe('scoreChain', () => {
  it('【本機能の核心】RCE に至る medium 連鎖は孤立した high より上位になる', () => {
    const chained = scoreChain(CHAINED_MEDIUMS_TO_RCE);
    const isolated = scoreChain(ISOLATED_HIGH);
    expect(chained.priorityScore).toBeGreaterThan(isolated.priorityScore);
  });

  it('連鎖シナジーは複数ステップのときだけ加点される', () => {
    expect(scoreChain(CHAINED_MEDIUMS_TO_RCE).breakdown.synergyBonus).toBeGreaterThan(0);
    expect(scoreChain(ISOLATED_HIGH).breakdown.synergyBonus).toBe(0);
  });

  it('単純な CVSS 合計にはなっていない（CVSS 最大値が低くても順位が逆転しうる）', () => {
    const chained = scoreChain(CHAINED_MEDIUMS_TO_RCE);
    const isolated = scoreChain(ISOLATED_HIGH);
    const maxCvssChained = Math.max(...CHAINED_MEDIUMS_TO_RCE.cvssScores);
    const maxCvssIsolated = Math.max(...ISOLATED_HIGH.cvssScores);
    expect(maxCvssChained).toBeLessThan(maxCvssIsolated);
    expect(chained.priorityScore).toBeGreaterThan(isolated.priorityScore);
  });

  it('単独の認証なし RCE は最上位クラスになる', () => {
    const standaloneRce = scoreChain(
      input({
        cvssScores: [9.8],
        confidences: [0.9],
        llmLikelihood: 'high',
        stepCount: 1,
        tactics: ['execution'],
      }),
    );
    expect(standaloneRce.priorityScore).toBeGreaterThan(
      scoreChain(CHAINED_MEDIUMS_TO_RCE).priorityScore,
    );
    expect(standaloneRce.priorityScore).toBeGreaterThan(90);
  });

  it('到達性が証明できていない連鎖は同条件より低くなる', () => {
    const proven = scoreChain(input({ ...CHAINED_MEDIUMS_TO_RCE, reachabilityRatio: 1 }));
    const unproven = scoreChain(input({ ...CHAINED_MEDIUMS_TO_RCE, reachabilityRatio: 0 }));
    expect(unproven.priorityScore).toBeLessThan(proven.priorityScore);
  });

  it('露出度の低い内部エントリポイントは低くなる', () => {
    const exposed = scoreChain(input({ ...CHAINED_MEDIUMS_TO_RCE, exposure: 1 }));
    const internal = scoreChain(input({ ...CHAINED_MEDIUMS_TO_RCE, exposure: 0.25 }));
    expect(internal.priorityScore).toBeLessThan(exposed.priorityScore);
  });

  it('常に 0..100 に収まる', () => {
    const extremes: ScoringInput[] = [
      input({ cvssScores: [0], confidences: [0], reachabilityRatio: 0, exposure: 0, llmLikelihood: 'low', tactics: [] }),
      input({ cvssScores: [10, 10, 10], confidences: [1, 1], reachabilityRatio: 1, exposure: 1, llmLikelihood: 'high', stepCount: 12, tactics: ['execution', 'impact'] }),
      input({ cvssScores: [Number.NaN], confidences: [Number.NaN], stepCount: 0 }),
    ];
    for (const e of extremes) {
      const s = scoreChain(e);
      expect(s.priorityScore).toBeGreaterThanOrEqual(0);
      expect(s.priorityScore).toBeLessThanOrEqual(100);
      expect(Number.isFinite(s.priorityScore)).toBe(true);
    }
  });

  it('内訳を返す', () => {
    const s = scoreChain(CHAINED_MEDIUMS_TO_RCE);
    expect(s.breakdown.terminalImpact).toBe(1.0);
    expect(s.breakdown.standaloneImpact).toBeCloseTo(0.61, 5);
    expect(['high', 'medium', 'low']).toContain(s.likelihood);
  });

  it('同じ入力なら常に同じスコア（決定的）', () => {
    const a = scoreChain(CHAINED_MEDIUMS_TO_RCE);
    const b = scoreChain(CHAINED_MEDIUMS_TO_RCE);
    expect(a.priorityScore).toBe(b.priorityScore);
  });
});

describe('チョークポイント選定', () => {
  const candidates: ChokePointCandidate[] = [
    { findingId: 'F1', order: 1, cwe: 'CWE-918', hasFixedVersion: false },
    { findingId: 'F2', order: 2, cwe: 'CWE-863', hasFixedVersion: false },
    { findingId: 'F3', order: 3, cwe: 'CWE-78', hasFixedVersion: false },
  ];

  it('上流ほど上流性スコアが高い', () => {
    const scored = scoreChokePoints(candidates, 3);
    expect(scored[0]?.upstreamness).toBe(1);
    expect(scored[2]?.upstreamness).toBe(0);
  });

  it('依存のバージョン更新で閉じるものは修正容易性が最大', () => {
    const scored = scoreChokePoints(
      [{ findingId: 'D', order: 2, cwe: 'CWE-1104', hasFixedVersion: true }],
      3,
    );
    expect(scored[0]?.ease).toBeGreaterThan(0.9);
  });

  it('最も上流かつ修正容易なものを選ぶ', () => {
    const picked = selectChokePoint(candidates, 3, null);
    expect(picked?.findingId).toBe('F1');
  });

  it('僅差なら LLM の提案を尊重する', () => {
    const close: ChokePointCandidate[] = [
      { findingId: 'A', order: 1, cwe: 'CWE-863', hasFixedVersion: false }, // 上流だが修正困難
      { findingId: 'B', order: 2, cwe: 'CWE-89', hasFixedVersion: false }, // 少し下流だが容易
    ];
    expect(selectChokePoint(close, 2, 'B')?.findingId).toBe('B');
  });

  it('LLM の提案が大きく劣るなら採用しない', () => {
    expect(selectChokePoint(candidates, 3, 'F3')?.findingId).toBe('F1');
  });

  it('候補に無い id は無視する', () => {
    expect(selectChokePoint(candidates, 3, 'NOPE')?.findingId).toBe('F1');
  });

  it('候補が無ければ null', () => {
    expect(selectChokePoint([], 3, null)).toBeNull();
  });

  it('1 ステップなら上流性は 1', () => {
    const scored = scoreChokePoints(
      [{ findingId: 'X', order: 1, cwe: null, hasFixedVersion: false }],
      1,
    );
    expect(scored[0]?.upstreamness).toBe(1);
  });
});

describe('戦術の網羅', () => {
  it('全戦術に影響係数が定義されている', () => {
    const tactics: AttackTactic[] = [
      'initial-access',
      'execution',
      'persistence',
      'privilege-escalation',
      'defense-evasion',
      'credential-access',
      'discovery',
      'lateral-movement',
      'collection',
      'exfiltration',
      'impact',
    ];
    for (const t of tactics) {
      expect(terminalImpactOf([t])).toBeGreaterThan(0);
    }
  });
});
