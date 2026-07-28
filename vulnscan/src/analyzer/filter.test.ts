import { describe, expect, it } from 'vitest';
import type { RawFinding } from '../types/finding.js';
import {
  clampConfidence,
  dedupeFindings,
  evidencePenalty,
  filterByConfidence,
  finalizeFindings,
  sortFindings,
  toRawFinding,
} from './filter.js';
import type { CandidateFinding, Verdict } from './schema.js';
import type { Chunk } from './types.js';
import { applyVerdict } from './verify.js';

const chunk: Chunk = {
  id: 'src/a.ts#getUser@5-9',
  file: 'src/a.ts',
  language: 'typescript',
  fileHash: 'hash-1',
  kind: 'symbol',
  label: 'getUser',
  startLine: 5,
  endLine: 9,
  segments: [{ startLine: 5, endLine: 9 }],
  code: '    5| ...',
  symbols: [],
};

function candidate(overrides: Partial<CandidateFinding> = {}): CandidateFinding {
  return {
    cwe: 'CWE-89',
    category: 'A03:2021-Injection',
    title: 'SQLインジェクション',
    severity: 'high',
    confidence: 0.8,
    location: { file: 'src/a.ts', startLine: 7, endLine: 7 },
    evidence: 'db.query(`SELECT * FROM u WHERE id=${id}`)',
    dataFlow: [
      {
        file: 'src/a.ts',
        line: 6,
        code: 'const id = req.params.id;',
        role: 'source',
        description: 'リクエストパラメータ',
      },
      {
        file: 'src/a.ts',
        line: 7,
        code: 'db.query(...)',
        role: 'sink',
        description: '文字列連結でクエリを組み立てている',
      },
    ],
    reasoning: '連結された値がそのままクエリに渡る',
    remediation: 'プレースホルダを使う',
    ...overrides,
  };
}

function verdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    verdict: 'confirmed',
    confidence: 0.9,
    exploitPath: 'req.params.id → db.query',
    rebuttal: '',
    missingEvidence: [],
    correctedSeverity: 'high',
    ...overrides,
  };
}

function finding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    cwe: 'CWE-89',
    category: 'A03:2021-Injection',
    title: 'SQLi',
    severity: 'high',
    confidence: 0.8,
    location: { file: 'src/a.ts', startLine: 7, endLine: 7 },
    evidence: '...',
    dataFlow: [],
    reasoning: '...',
    remediation: '...',
    lens: 'injection',
    ...overrides,
  };
}

describe('clampConfidence', () => {
  it('0..1 に収め、NaN は 0 にする', () => {
    expect(clampConfidence(1.7)).toBe(1);
    expect(clampConfidence(-0.2)).toBe(0);
    expect(clampConfidence(Number.NaN)).toBe(0);
    expect(clampConfidence(0.42)).toBe(0.42);
  });
});

describe('evidencePenalty', () => {
  it('source→sink が揃っていれば減点しない', () => {
    expect(evidencePenalty(candidate())).toBe(1);
  });

  it('dataFlow が空（到達性未証明）は大きく減点する', () => {
    expect(evidencePenalty(candidate({ dataFlow: [] }))).toBe(0.5);
  });

  it('片側しか無い経路は減点する', () => {
    const onlySink = candidate().dataFlow.filter((s) => s.role === 'sink');
    expect(evidencePenalty({ dataFlow: onlySink })).toBe(0.85);
  });

  it('source も sink も無い経路はさらに減点する', () => {
    expect(
      evidencePenalty({
        dataFlow: [
          {
            file: 'src/a.ts',
            line: 6,
            code: 'x = y',
            role: 'propagation',
            description: '伝播',
          },
        ],
      }),
    ).toBe(0.7);
  });
});

describe('applyVerdict', () => {
  it('反証されたものは破棄する', () => {
    const applied = applyVerdict(candidate(), verdict({ verdict: 'refuted', rebuttal: 'バインド済み' }));
    expect(applied.dropped).toBe(true);
  });

  it('確認できたものは検証側に重みを置いて合成する', () => {
    const applied = applyVerdict(candidate({ confidence: 0.5 }), verdict({ confidence: 1 }));
    expect(applied.dropped).toBe(false);
    expect(applied.confidence).toBeCloseTo(0.5 * 0.4 + 1 * 0.6, 5);
  });

  it('判断がつかないものは確信度を下げる', () => {
    const applied = applyVerdict(
      candidate({ confidence: 0.9 }),
      verdict({ verdict: 'uncertain', confidence: 0.6, missingEvidence: ['呼び出し元'] }),
    );
    expect(applied.confidence).toBeCloseTo(0.6 * 0.7, 5);
    expect(applied.note).toContain('呼び出し元');
  });

  it('検証できなかった場合は控えめに減衰する', () => {
    const applied = applyVerdict(candidate({ confidence: 0.9 }), null);
    expect(applied.confidence).toBeCloseTo(0.72, 5);
    expect(applied.dropped).toBe(false);
  });

  it('深刻度は下げる方向にだけ反映する', () => {
    expect(
      applyVerdict(candidate({ severity: 'high' }), verdict({ correctedSeverity: 'low' })).severity,
    ).toBe('low');
    expect(
      applyVerdict(candidate({ severity: 'low' }), verdict({ correctedSeverity: 'critical' }))
        .severity,
    ).toBe('low');
  });
});

describe('toRawFinding', () => {
  it('根拠の薄さを確信度に反映する', () => {
    const raw = toRawFinding({
      candidate: candidate({ dataFlow: [] }),
      chunk,
      lens: 'injection',
      confidence: 0.8,
      severity: 'high',
    });
    expect(raw.confidence).toBeCloseTo(0.4, 5);
    expect(raw.lens).toBe('injection');
  });

  it('位置の異常値を正す', () => {
    const raw = toRawFinding({
      candidate: candidate({ location: { file: '', startLine: 0, endLine: -3 } }),
      chunk,
      lens: 'injection',
      confidence: 0.9,
      severity: 'high',
    });
    expect(raw.location).toEqual({ file: 'src/a.ts', startLine: 1, endLine: 1 });
  });

  it('検証メモを reasoning に追記する', () => {
    const raw = toRawFinding({
      candidate: candidate(),
      chunk,
      lens: 'injection',
      confidence: 0.9,
      severity: 'high',
      note: '自己検証で成立を確認した。',
    });
    expect(raw.reasoning).toContain('[自己検証]');
  });
});

describe('filterByConfidence', () => {
  it('閾値未満を破棄する', () => {
    const kept = filterByConfidence(
      [finding({ confidence: 0.49 }), finding({ confidence: 0.5 }), finding({ confidence: 0.9 })],
      0.5,
    );
    expect(kept.map((f) => f.confidence)).toEqual([0.5, 0.9]);
  });
});

describe('dedupeFindings', () => {
  it('同じ箇所・同じCWEは確信度が高い方を残す', () => {
    const kept = dedupeFindings([
      finding({ confidence: 0.6, title: '低い方' }),
      finding({ confidence: 0.9, title: '高い方', location: { file: 'src/a.ts', startLine: 8, endLine: 8 } }),
    ]);
    expect(kept).toHaveLength(1);
    expect(kept[0]?.title).toBe('高い方');
  });

  it('CWEが違えば残す', () => {
    const kept = dedupeFindings([finding(), finding({ cwe: 'CWE-79' })]);
    expect(kept).toHaveLength(2);
  });

  it('離れた箇所は残す', () => {
    const kept = dedupeFindings([
      finding(),
      finding({ location: { file: 'src/a.ts', startLine: 200, endLine: 200 } }),
    ]);
    expect(kept).toHaveLength(2);
  });

  it('ファイルが違えば残す', () => {
    const kept = dedupeFindings([
      finding(),
      finding({ location: { file: 'src/b.ts', startLine: 7, endLine: 7 } }),
    ]);
    expect(kept).toHaveLength(2);
  });
});

describe('sortFindings', () => {
  it('深刻度→確信度の順に並べる', () => {
    const sorted = sortFindings([
      finding({ severity: 'low', confidence: 0.9, cwe: 'CWE-1' }),
      finding({ severity: 'critical', confidence: 0.5, cwe: 'CWE-2' }),
      finding({ severity: 'critical', confidence: 0.8, cwe: 'CWE-3' }),
    ]);
    expect(sorted.map((f) => f.cwe)).toEqual(['CWE-3', 'CWE-2', 'CWE-1']);
  });
});

describe('finalizeFindings', () => {
  it('閾値フィルタ→重複統合→整列をまとめて行う', () => {
    const result = finalizeFindings(
      [
        finding({ confidence: 0.2 }),
        finding({ confidence: 0.8, title: '残る' }),
        finding({ confidence: 0.7, title: '重複' }),
        finding({ cwe: 'CWE-79', severity: 'critical', confidence: 0.6, title: 'XSS' }),
      ],
      0.5,
    );
    expect(result.map((f) => f.title)).toEqual(['XSS', '残る']);
  });
});
