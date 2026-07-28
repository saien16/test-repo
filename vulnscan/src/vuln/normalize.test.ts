/**
 * 正規化・指紋・重複統合のテスト。
 */

import { describe, expect, it } from 'vitest';
import type { ScanContext } from '../types/context.js';
import type { RawFinding } from '../types/finding.js';
import {
  computeFingerprint,
  fingerprintToId,
  normalizeCodeSnippet,
  normalizeFilePath,
} from './fingerprint.js';
import { mergeFindings, normalizeFinding } from './normalize.js';
import { buildReferences, CWE_KB, cweUrl, lookupCwe, owaspUrl } from './knowledge.js';

const NOW = '2026-07-28T00:00:00.000Z';

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot: '/repo',
    scannedAt: NOW,
    languages: [],
    frameworks: [],
    dependencies: [],
    files: [],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [
      { kind: 'http-route', identifier: 'GET /users/:id', file: 'src/api/users.ts', line: 5 },
    ],
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
    severity: 'high',
    confidence: 0.8,
    location: { file: 'src/api/users.ts', startLine: 10, endLine: 12 },
    evidence: 'db.query("SELECT * FROM users WHERE id = " + id)',
    dataFlow: [],
    reasoning: '文字列連結',
    remediation: 'プレースホルダを使う',
    lens: 'injection',
    ...overrides,
  };
}

describe('normalizeCodeSnippet', () => {
  it('インデント・改行の違いを吸収する', () => {
    const a = 'if (x) {\n    doSomething(x);\n}';
    const b = 'if (x) {\n\t\tdoSomething(x);\n}';
    expect(normalizeCodeSnippet(a)).toBe(normalizeCodeSnippet(b));
  });

  it('コメントの追加では変化しない', () => {
    const a = 'db.query(sql)';
    const b = 'db.query(sql) // FIXME: 後で直す';
    const c = 'db.query(sql) /* 危険 */';
    expect(normalizeCodeSnippet(a)).toBe(normalizeCodeSnippet(b));
    expect(normalizeCodeSnippet(a)).toBe(normalizeCodeSnippet(c));
  });

  it('引用符の種類の違いを吸収する', () => {
    expect(normalizeCodeSnippet(`f('a')`)).toBe(normalizeCodeSnippet('f("a")'));
  });
});

describe('normalizeFilePath', () => {
  it('repoRoot 相対の POSIX パスに揃える', () => {
    expect(normalizeFilePath('/repo/src/a.ts', '/repo')).toBe('src/a.ts');
    expect(normalizeFilePath('./src/a.ts')).toBe('src/a.ts');
    expect(normalizeFilePath('src\\a.ts')).toBe('src/a.ts');
  });
});

describe('computeFingerprint', () => {
  it('行番号を含まないため行がずれても変化しない', () => {
    const ctx = makeContext();
    const a = normalizeFinding(makeRaw(), ctx, NOW);
    const b = normalizeFinding(
      makeRaw({ location: { file: 'src/api/users.ts', startLine: 120, endLine: 122 } }),
      ctx,
      NOW,
    );
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.id).toBe(b.id);
  });

  it('ファイル・CWE・コード片が変われば変化する', () => {
    const base = { file: 'a.ts', cwe: 'CWE-89', evidence: 'x' };
    const fp = computeFingerprint(base);
    expect(computeFingerprint({ ...base, file: 'b.ts' })).not.toBe(fp);
    expect(computeFingerprint({ ...base, cwe: 'CWE-79' })).not.toBe(fp);
    expect(computeFingerprint({ ...base, evidence: 'y' })).not.toBe(fp);
  });

  it('同じ入力からは常に同じ指紋が得られる（決定的）', () => {
    const base = { file: 'a.ts', cwe: 'CWE-89', evidence: 'x' };
    expect(computeFingerprint(base)).toBe(computeFingerprint(base));
  });

  it('ID は指紋由来の短い安定値', () => {
    const fp = computeFingerprint({ file: 'a.ts', cwe: 'CWE-89', evidence: 'x' });
    expect(fingerprintToId(fp)).toMatch(/^VS-[0-9a-f]{12}$/);
    expect(fingerprintToId(fp)).toBe(fingerprintToId(fp));
  });
});

describe('normalizeFinding', () => {
  it('CVSS を推定して付与する', () => {
    const f = normalizeFinding(makeRaw(), makeContext(), NOW);
    expect(f.cvss.vector).toMatch(/^CVSS:3\.1\//);
    expect(f.cvss.baseScore).toBeGreaterThan(0);
    expect(f.cvss.baseSeverity).toBeTruthy();
  });

  it('CVSS の推定根拠を reasoning に残す', () => {
    const f = normalizeFinding(makeRaw(), makeContext(), NOW);
    expect(f.reasoning).toContain('[CVSS推定根拠]');
    expect(f.reasoning).toContain('CWE-89');
  });

  it('CWE の表記ゆれを正規化する', () => {
    const f = normalizeFinding(makeRaw({ cwe: 'cwe-89' }), makeContext(), NOW);
    expect(f.cwe).toBe('CWE-89');
  });

  it('CWE 知識ベースからカテゴリと参照リンクを設定する', () => {
    const f = normalizeFinding(makeRaw({ category: '間違ったカテゴリ' }), makeContext(), NOW);
    expect(f.category).toBe('A03:2021-Injection');
    expect(f.references).toContain('https://cwe.mitre.org/data/definitions/89.html');
    expect(f.references).toContain('https://owasp.org/Top10/A03_2021-Injection/');
  });

  it('初期状態は open / new になる', () => {
    const f = normalizeFinding(makeRaw(), makeContext(), NOW);
    expect(f.status).toBe('open');
    expect(f.diffStatus).toBe('new');
    expect(f.firstSeen).toBe(NOW);
    expect(f.mergedFrom).toEqual([]);
  });

  it('confidence は 0..1 に丸められる', () => {
    expect(normalizeFinding(makeRaw({ confidence: 3 }), makeContext(), NOW).confidence).toBe(1);
    expect(normalizeFinding(makeRaw({ confidence: -1 }), makeContext(), NOW).confidence).toBe(0);
  });

  it('絶対パスは repoRoot 相対に変換される', () => {
    const f = normalizeFinding(
      makeRaw({ location: { file: '/repo/src/api/users.ts', startLine: 1, endLine: 2 } }),
      makeContext(),
      NOW,
    );
    expect(f.location.file).toBe('src/api/users.ts');
  });
});

describe('mergeFindings', () => {
  const ctx = makeContext();

  it('完全に同一の指摘は1件に統合される', () => {
    const a = normalizeFinding(makeRaw(), ctx, NOW);
    const b = normalizeFinding(makeRaw(), ctx, NOW);
    const merged = mergeFindings([a, b]);
    expect(merged).toHaveLength(1);
  });

  it('異なるレンズが同じ問題を検出したら confidence を上げる', () => {
    const a = normalizeFinding(makeRaw({ lens: 'injection', confidence: 0.7 }), ctx, NOW);
    const b = normalizeFinding(makeRaw({ lens: 'authz', confidence: 0.6 }), ctx, NOW);
    const merged = mergeFindings([a, b]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.confidence).toBeCloseTo(0.8, 5);
    expect(merged[0]!.reasoning).toContain('[統合]');
  });

  it('同一箇所・同一CWEなら抜粋が違っても統合し mergedFrom に記録する', () => {
    const a = normalizeFinding(makeRaw({ confidence: 0.9 }), ctx, NOW);
    const b = normalizeFinding(
      makeRaw({
        confidence: 0.5,
        lens: 'authz',
        evidence: 'db.query(`SELECT * FROM users WHERE id=${id}`)',
        location: { file: 'src/api/users.ts', startLine: 11, endLine: 13 },
      }),
      ctx,
      NOW,
    );
    expect(a.fingerprint).not.toBe(b.fingerprint);
    const merged = mergeFindings([a, b]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.fingerprint).toBe(a.fingerprint);
    expect(merged[0]!.mergedFrom).toEqual([b.fingerprint]);
  });

  it('CWE が異なれば統合しない', () => {
    const a = normalizeFinding(makeRaw(), ctx, NOW);
    const b = normalizeFinding(makeRaw({ cwe: 'CWE-79' }), ctx, NOW);
    expect(mergeFindings([a, b])).toHaveLength(2);
  });

  it('離れた行の指摘は統合しない', () => {
    const a = normalizeFinding(makeRaw(), ctx, NOW);
    const b = normalizeFinding(
      makeRaw({
        evidence: '別のクエリ',
        location: { file: 'src/api/users.ts', startLine: 300, endLine: 301 },
      }),
      ctx,
      NOW,
    );
    expect(mergeFindings([a, b])).toHaveLength(2);
  });

  it('統合後は最も高い深刻度と最も詳細なデータフローを採用する', () => {
    const flow = [
      { file: 'src/api/users.ts', line: 10, code: 'x', role: 'source' as const, description: 'in' },
      { file: 'src/api/users.ts', line: 12, code: 'y', role: 'sink' as const, description: 'out' },
    ];
    const a = normalizeFinding(makeRaw({ confidence: 0.9, severity: 'medium' }), ctx, NOW);
    const b = normalizeFinding(
      makeRaw({ confidence: 0.4, severity: 'critical', lens: 'authz', dataFlow: flow }),
      ctx,
      NOW,
    );
    const merged = mergeFindings([a, b]);
    expect(merged[0]!.severity).toBe('critical');
    expect(merged[0]!.dataFlow).toHaveLength(2);
  });

  it('深刻度の高い順に並ぶ', () => {
    const low = normalizeFinding(
      makeRaw({ severity: 'low', evidence: 'a', location: { file: 'x.ts', startLine: 1, endLine: 1 } }),
      ctx,
      NOW,
    );
    const critical = normalizeFinding(
      makeRaw({ severity: 'critical', evidence: 'b', location: { file: 'y.ts', startLine: 1, endLine: 1 } }),
      ctx,
      NOW,
    );
    const merged = mergeFindings([low, critical]);
    expect(merged[0]!.severity).toBe('critical');
  });
});

describe('知識ベース', () => {
  it('主要な CWE を網羅している', () => {
    for (const cwe of ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-798', 'CWE-918', 'CWE-502', 'CWE-327']) {
      const entry = lookupCwe(cwe);
      expect(entry, cwe).toBeDefined();
      expect(entry!.name).toBeTruthy();
      expect(entry!.owasp).toMatch(/^A\d{2}:2021-/);
    }
  });

  it('CWE と OWASP の URL を生成する', () => {
    expect(cweUrl('CWE-89')).toBe('https://cwe.mitre.org/data/definitions/89.html');
    expect(cweUrl('不正')).toBeNull();
    expect(owaspUrl('A10:2021-Server-Side Request Forgery (SSRF)')).toContain('A10_2021');
    expect(owaspUrl(undefined)).toBeNull();
  });

  it('buildReferences は重複を除去する', () => {
    const refs = buildReferences('CWE-89', 'A03:2021-Injection', [
      'https://example.com/adv',
      'https://example.com/adv',
    ]);
    expect(refs).toHaveLength(3);
    expect(new Set(refs).size).toBe(3);
  });

  it('全 CWE エントリの OWASP カテゴリが URL に解決できる', () => {
    const ids = Object.keys(CWE_KB);
    expect(ids.length).toBeGreaterThanOrEqual(30);
    for (const [id, entry] of Object.entries(CWE_KB)) {
      expect(id).toMatch(/^CWE-\d+$/);
      expect(owaspUrl(entry.owasp), id).not.toBeNull();
    }
  });
});
