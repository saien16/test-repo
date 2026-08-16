/**
 * CVSS v3.0 / v3.1 計算のテスト。
 * FIRST 公式のサンプルベクタ・NVD が公表しているスコアで検証する。
 */

import { describe, expect, it } from 'vitest';
import type { ScanContext } from '../types/context.js';
import type { Cvss3Metrics, RawFinding } from '../types/finding.js';
import {
  buildCvss3Vector,
  calculateCvss3,
  cvss3RatingToSeverity,
  cvss3SeverityRating,
  inferCvss3Metrics,
  inferCvss3MetricsWithReasons,
  parseCvss3Vector,
  roundupV30,
  roundupV31,
} from './cvss.js';

/** 公式サンプル / NVD 公表値。[ベクタ, 期待スコア, 期待レーティング] */
const OFFICIAL_SAMPLES: Array<[string, number, string]> = [
  // 課題文で指定された公式サンプル
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'High'],
  ['CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0.0, 'None'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'Medium'],
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', 9.0, 'Critical'],

  // Scope Unchanged の代表例
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, 'High'],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'High'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'High'],
  ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2, 'High'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8, 'High'],
  ['CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 6.2, 'Medium'],
  ['CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 6.5, 'Medium'],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 5.5, 'Medium'],
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N', 5.3, 'Medium'],
  ['CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 6.7, 'Medium'],
  ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', 3.5, 'Low'],

  // Scope Changed の代表例
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'Critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9, 'Critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', 9.6, 'Critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N', 5.8, 'Medium'],
  ['CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H', 8.5, 'High'],
];

describe('calculateCvss3 — 公式サンプルベクタ', () => {
  for (const [vector, expected, rating] of OFFICIAL_SAMPLES) {
    it(`${vector} → ${expected} (${rating})`, () => {
      const result = calculateCvss3(parseCvss3Vector(vector), '3.1');
      expect(result.baseScore).toBe(expected);
      expect(result.baseSeverity).toBe(rating);
      // 入力ベクタがそのまま復元されること
      expect(result.vector).toBe(vector);
    });
  }
});

describe('calculateCvss3 — 計算式の性質', () => {
  it('影響が全て None ならスコアは 0.0 / None になる', () => {
    const m: Cvss3Metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
    const r = calculateCvss3(m);
    expect(r.baseScore).toBe(0);
    expect(r.baseSeverity).toBe('None');
    expect(r.breakdown.impactSubScore).toBe(0);
    // Exploitability は影響とは独立に算出される
    expect(r.breakdown.exploitabilitySubScore).toBeGreaterThan(0);
  });

  it('スコアは 0.0 〜 10.0 に収まる（全 1944 通り）', () => {
    for (const m of allMetricCombinations()) {
      const score = calculateCvss3(m).baseScore;
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(10);
      // 小数第1位までであること
      expect(Math.round(score * 10)).toBe(score * 10);
    }
  });

  it('Scope Changed は同一メトリクスの Unchanged 以上のスコアになる', () => {
    for (const m of allMetricCombinations()) {
      if (m.S !== 'U') continue;
      const unchanged = calculateCvss3(m).baseScore;
      const changed = calculateCvss3({ ...m, S: 'C' }).baseScore;
      expect(changed).toBeGreaterThanOrEqual(unchanged);
    }
  });

  it('breakdown が Impact / Exploitability を報告する', () => {
    const r = calculateCvss3(parseCvss3Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
    expect(r.breakdown.impactSubScore).toBe(5.9);
    expect(r.breakdown.exploitabilitySubScore).toBe(3.9);
  });

  it('S:C の Impact は Scope Changed の式で計算される', () => {
    const r = calculateCvss3(parseCvss3Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'));
    expect(r.breakdown.impactSubScore).toBe(6.0);
  });
});

describe('roundup', () => {
  it('v3.1 は整数演算版で浮動小数点誤差を吸収する', () => {
    // 4.0000000000000005 は本来 4.0。素朴な ceil では 4.1 になってしまう。
    expect(roundupV31(4.0000000000000005)).toBe(4.0);
    expect(roundupV30(4.0000000000000005)).toBe(4.1);
  });

  it('小数第1位への切り上げになっている', () => {
    expect(roundupV31(4.02)).toBe(4.1);
    expect(roundupV31(4.0)).toBe(4.0);
    expect(roundupV31(0.0)).toBe(0.0);
    expect(roundupV31(9.999)).toBe(10.0);
    expect(roundupV30(4.02)).toBe(4.1);
    expect(roundupV30(4.0)).toBe(4.0);
  });
});

describe('バージョンの扱い', () => {
  it('version を省略すると 3.1 として扱う', () => {
    const r = calculateCvss3(parseCvss3Vector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
    expect(r.version).toBe('3.1');
    expect(r.vector.startsWith('CVSS:3.1/')).toBe(true);
  });

  it('3.0 を指定するとベクタのプレフィクスが 3.0 になる', () => {
    const m = parseCvss3Vector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    const r = calculateCvss3(m, '3.0');
    expect(r.version).toBe('3.0');
    expect(r.vector).toBe('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(r.baseScore).toBe(9.8);
  });

  it('基本評価値では v3.0 と v3.1 の丸め差は現れない（全組合せで一致）', () => {
    // roundup の定義差は基本評価基準の範囲では表面化しないことを確認する。
    // （差が出るのは環境評価基準など、より複雑な計算を経た場合）
    for (const m of allMetricCombinations()) {
      expect(calculateCvss3(m, '3.0').baseScore).toBe(calculateCvss3(m, '3.1').baseScore);
    }
  });
});

describe('parseCvss3Vector / buildCvss3Vector', () => {
  it('ラウンドトリップ（parse → build）で元のベクタに戻る（全 1944 通り）', () => {
    for (const m of allMetricCombinations()) {
      const vector = buildCvss3Vector(m, '3.1');
      const parsed = parseCvss3Vector(vector);
      expect(parsed).toEqual(m);
      expect(buildCvss3Vector(parsed, '3.1')).toBe(vector);
    }
  });

  it('CVSS プレフィクス無しのベクタも受け付ける', () => {
    expect(parseCvss3Vector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toEqual({
      AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
    });
  });

  it('Temporal / Environmental メトリクスは無視して基本メトリクスを取り出す', () => {
    const m = parseCvss3Vector(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/MAV:L',
    );
    expect(m.AV).toBe('N');
    expect(calculateCvss3(m).baseScore).toBe(9.8);
  });

  it('メトリクスが欠けている場合はエラーになる', () => {
    expect(() => parseCvss3Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toThrow(/A/);
  });

  it('値が不正な場合はエラーになる', () => {
    expect(() => parseCvss3Vector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow();
  });

  it('未対応バージョンはエラーになる', () => {
    expect(() => parseCvss3Vector('CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(
      /バージョン/,
    );
  });

  it('空文字はエラーになる', () => {
    expect(() => parseCvss3Vector('')).toThrow();
  });

  it('buildCvss3Vector は正準順序で出力する', () => {
    const vector = buildCvss3Vector(
      { A: 'H', I: 'H', C: 'H', S: 'U', UI: 'N', PR: 'N', AC: 'L', AV: 'N' },
      '3.1',
    );
    expect(vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });
});

describe('cvss3SeverityRating', () => {
  it('境界値が仕様どおり', () => {
    expect(cvss3SeverityRating(0.0)).toBe('None');
    expect(cvss3SeverityRating(0.1)).toBe('Low');
    expect(cvss3SeverityRating(3.9)).toBe('Low');
    expect(cvss3SeverityRating(4.0)).toBe('Medium');
    expect(cvss3SeverityRating(6.9)).toBe('Medium');
    expect(cvss3SeverityRating(7.0)).toBe('High');
    expect(cvss3SeverityRating(8.9)).toBe('High');
    expect(cvss3SeverityRating(9.0)).toBe('Critical');
    expect(cvss3SeverityRating(10.0)).toBe('Critical');
  });

  it('内部 Severity へ変換できる', () => {
    expect(cvss3RatingToSeverity('Critical')).toBe('critical');
    expect(cvss3RatingToSeverity('None')).toBe('info');
  });
});

/* ------------------------------------------------------------------ *
 * inferCvss3Metrics
 * ------------------------------------------------------------------ */

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot: '/repo',
    scannedAt: '2026-01-01T00:00:00.000Z',
    readme: null,
    languages: [],
    frameworks: [],
    dependencies: [],
    files: [],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [],
    trustBoundaries: [],
    warnings: [],
    ...overrides,
  };
}

function makeRaw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    cwe: 'CWE-89',
    category: 'A03:2021-Injection',
    title: 'SQLインジェクション',
    severity: 'critical',
    confidence: 0.9,
    location: { file: 'src/api/users.ts', startLine: 10, endLine: 12 },
    evidence: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
    dataFlow: [
      {
        file: 'src/api/users.ts',
        line: 10,
        code: 'const id = req.params.id',
        role: 'source',
        description: 'HTTPパラメータ',
      },
      {
        file: 'src/api/users.ts',
        line: 12,
        code: 'db.query(...)',
        role: 'sink',
        description: 'SQL実行',
      },
    ],
    reasoning: '文字列連結でSQLを構築している',
    remediation: 'プレースホルダを使う',
    lens: 'injection',
    ...overrides,
  };
}

const HTTP_ENTRY = {
  kind: 'http-route' as const,
  identifier: 'GET /users/:id',
  file: 'src/api/users.ts',
  line: 5,
};

describe('inferCvss3Metrics', () => {
  it('公開HTTPエンドポイント上のSQLiは 9.8 相当になる', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const m = inferCvss3Metrics(makeRaw(), ctx);
    expect(buildCvss3Vector(m, '3.1')).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(calculateCvss3(m).baseScore).toBe(9.8);
  });

  it('エントリポイントから到達できない場合は AV と PR を下方修正する', () => {
    const ctx = makeContext(); // エントリポイント無し
    const m = inferCvss3Metrics(makeRaw(), ctx);
    expect(m.AV).toBe('L');
    expect(m.PR).toBe('L');
    // 到達性が無いぶんスコアも下がる
    expect(calculateCvss3(m).baseScore).toBeLessThan(9.8);
  });

  it('dataFlow が空なら AC を H に引き上げる（到達性未証明）', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const m = inferCvss3Metrics(makeRaw({ dataFlow: [] }), ctx);
    expect(m.AC).toBe('H');
  });

  it('経路上にサニタイザがあれば AC を H にする', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const raw = makeRaw();
    const m = inferCvss3Metrics(
      {
        ...raw,
        dataFlow: [
          ...raw.dataFlow,
          {
            file: 'src/api/users.ts',
            line: 11,
            code: 'escape(id)',
            role: 'sanitizer',
            description: 'エスケープ',
          },
        ],
      },
      ctx,
    );
    expect(m.AC).toBe('H');
  });

  it('認証が必要なエントリポイントでは PR を L にする', () => {
    const ctx = makeContext({
      entryPoints: [{ ...HTTP_ENTRY, metadata: { auth: 'required' } }],
    });
    const m = inferCvss3Metrics(makeRaw(), ctx);
    expect(m.PR).toBe('L');
  });

  it('CLI のみのエントリポイントなら AV は L になる', () => {
    const ctx = makeContext({
      entryPoints: [{ kind: 'cli', identifier: 'scan', file: 'src/api/users.ts', line: 1 }],
    });
    const m = inferCvss3Metrics(makeRaw(), ctx);
    expect(m.AV).toBe('L');
  });

  it('XSS はユーザ操作が必要でスコープが変わる', () => {
    const ctx = makeContext({
      entryPoints: [{ ...HTTP_ENTRY, file: 'src/web/render.ts' }],
    });
    const m = inferCvss3Metrics(
      makeRaw({
        cwe: 'CWE-79',
        severity: 'medium',
        lens: 'web-output',
        location: { file: 'src/web/render.ts', startLine: 3, endLine: 3 },
        dataFlow: [
          { file: 'src/web/render.ts', line: 1, code: 'req.query.q', role: 'source', description: '入力' },
          { file: 'src/web/render.ts', line: 3, code: 'res.send(html)', role: 'sink', description: '出力' },
        ],
      }),
      ctx,
    );
    expect(m.UI).toBe('R');
    expect(m.S).toBe('C');
    expect(calculateCvss3(m).baseScore).toBe(6.1);
  });

  it("severity='info' は影響なし（0.0 / None）として扱う", () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const m = inferCvss3Metrics(makeRaw({ severity: 'info' }), ctx);
    expect([m.C, m.I, m.A]).toEqual(['N', 'N', 'N']);
    const r = calculateCvss3(m);
    expect(r.baseScore).toBe(0);
    expect(r.baseSeverity).toBe('None');
  });

  it("severity='low' なら High の影響度が Low に降格する", () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const m = inferCvss3Metrics(makeRaw({ severity: 'low' }), ctx);
    expect(m.C).toBe('L');
    expect(m.I).toBe('L');
  });

  it('未知の CWE でも OWASP カテゴリから推定できる', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const { metrics, reasons } = inferCvss3MetricsWithReasons(
      makeRaw({ cwe: 'CWE-99999', category: 'A01:2021-Broken Access Control' }),
      ctx,
    );
    expect(metrics.AV).toBe('N');
    expect(reasons.some((r) => r.includes('A01'))).toBe(true);
  });

  it('推定根拠が日本語で説明される', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const { reasons } = inferCvss3MetricsWithReasons(makeRaw(), ctx);
    expect(reasons.length).toBeGreaterThan(0);
    expect(reasons[0]).toContain('CWE-89');
  });

  it('推定結果は常に妥当なメトリクスになる（計算が例外を投げない）', () => {
    const ctx = makeContext({ entryPoints: [HTTP_ENTRY] });
    const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const cwes = ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-798', 'CWE-918', 'CWE-327', 'CWE-0000'];
    for (const severity of severities) {
      for (const cwe of cwes) {
        const m = inferCvss3Metrics(makeRaw({ severity, cwe }), ctx);
        expect(() => calculateCvss3(m)).not.toThrow();
      }
    }
  });
});

// CWE ID 正規化のテストは `catalog.test.ts` へ移した
// （実装を catalog.ts に一元化したため）。

/** 基本メトリクスの全組合せ（4×2×3×2×2×3×3×3 = 1944 通り） */
function* allMetricCombinations(): Generator<Cvss3Metrics> {
  const AV = ['N', 'A', 'L', 'P'] as const;
  const AC = ['L', 'H'] as const;
  const PR = ['N', 'L', 'H'] as const;
  const UI = ['N', 'R'] as const;
  const S = ['U', 'C'] as const;
  const CIA = ['H', 'L', 'N'] as const;
  for (const av of AV)
    for (const ac of AC)
      for (const pr of PR)
        for (const ui of UI)
          for (const s of S)
            for (const c of CIA)
              for (const i of CIA)
                for (const a of CIA)
                  yield { AV: av, AC: ac, PR: pr, UI: ui, S: s, C: c, I: i, A: a };
}
