import { describe, expect, it } from 'vitest';
import type { EntryPoint } from '../types/context.js';
import {
  buildCandidateGroups,
  dataFlowKeys,
  ENTRY_POINT_EXPOSURE,
  groupByDataFlow,
  isStandaloneCritical,
} from './grouping.js';
import { makeCallGraph, makeContext, makeFinding, makeFlowStep, makeSymbolTable } from './test-fixtures.js';

const route: EntryPoint = {
  kind: 'http-route',
  identifier: 'GET /api/report',
  file: 'src/api.ts',
  line: 5,
};

const cliEntry: EntryPoint = {
  kind: 'cli',
  identifier: 'vulnscan import',
  file: 'src/cli.ts',
  line: 3,
};

const symbols = makeSymbolTable([
  { name: 'reportRoute', kind: 'route', file: 'src/api.ts', startLine: 1, endLine: 20 },
  { name: 'fetchRemote', kind: 'function', file: 'src/fetch.ts', startLine: 1, endLine: 40 },
  { name: 'render', kind: 'function', file: 'src/render.ts', startLine: 1, endLine: 30 },
  { name: 'importCmd', kind: 'function', file: 'src/cli.ts', startLine: 1, endLine: 20 },
  { name: 'lonely', kind: 'function', file: 'src/lonely.ts', startLine: 1, endLine: 10 },
]);

const callGraph = makeCallGraph([
  ['src/api.ts:reportRoute', 'src/fetch.ts:fetchRemote', 0.9],
  ['src/fetch.ts:fetchRemote', 'src/render.ts:render', 0.8],
  ['src/cli.ts:importCmd', 'src/render.ts:render', 0.7],
]);

describe('isStandaloneCritical', () => {
  it('CVSS 9.0 以上は単独で致命的', () => {
    expect(isStandaloneCritical(makeFinding({ id: 'X', baseScore: 9.8 }))).toBe(true);
  });

  it('critical かつ認証不要・ネットワーク越しなら単独で致命的', () => {
    const f = makeFinding({
      id: 'X',
      severity: 'critical',
      baseScore: 8.5,
      metrics: { AV: 'N', PR: 'N', UI: 'N' },
    });
    expect(isStandaloneCritical(f)).toBe(true);
  });

  it('critical でも権限が要るなら単独扱いにしない', () => {
    const f = makeFinding({
      id: 'X',
      severity: 'critical',
      baseScore: 8.5,
      metrics: { PR: 'H' },
    });
    expect(isStandaloneCritical(f)).toBe(false);
  });

  it('medium は単独扱いにしない', () => {
    expect(isStandaloneCritical(makeFinding({ id: 'X', baseScore: 5.5 }))).toBe(false);
  });
});

describe('dataFlowKeys / groupByDataFlow', () => {
  it('データフローの file:line を重複なく抽出する', () => {
    const f = makeFinding({
      id: 'A',
      dataFlow: [
        makeFlowStep('./src/a.ts', 10, 'source'),
        makeFlowStep('src/a.ts', 10, 'propagation'),
        makeFlowStep('src/b.ts', 20, 'sink'),
      ],
    });
    expect(dataFlowKeys(f).sort()).toEqual(['src/a.ts:10', 'src/b.ts:20']);
  });

  it('同じ位置を通過する Finding を連結する', () => {
    const a = makeFinding({
      id: 'A',
      dataFlow: [makeFlowStep('src/a.ts', 1, 'source'), makeFlowStep('src/mid.ts', 7, 'sink')],
    });
    const b = makeFinding({
      id: 'B',
      dataFlow: [makeFlowStep('src/mid.ts', 7, 'source'), makeFlowStep('src/z.ts', 9, 'sink')],
    });
    const c = makeFinding({ id: 'C', dataFlow: [makeFlowStep('src/other.ts', 3, 'sink')] });

    const groups = groupByDataFlow([a, b, c], new Map());
    expect(groups).toHaveLength(1);
    expect(groups[0]?.sort()).toEqual(['A', 'B']);
  });

  it('同一シンボルに属する Finding も連結する', () => {
    const a = makeFinding({ id: 'A' });
    const b = makeFinding({ id: 'B' });
    const groups = groupByDataFlow(
      [a, b],
      new Map([
        ['A', 'src/x.ts:f'],
        ['B', 'src/x.ts:f'],
      ]),
    );
    expect(groups[0]?.sort()).toEqual(['A', 'B']);
  });

  it('多数が共有するハブ位置では連結しない', () => {
    const findings = ['A', 'B', 'C', 'D'].map((id) =>
      makeFinding({ id, dataFlow: [makeFlowStep('src/hub.ts', 1, 'propagation')] }),
    );
    expect(groupByDataFlow(findings, new Map(), { maxSharedFlowKeyFanout: 3 })).toEqual([]);
    expect(groupByDataFlow(findings, new Map(), { maxSharedFlowKeyFanout: 9 })).toHaveLength(1);
  });
});

describe('buildCandidateGroups', () => {
  const ssrf = makeFinding({
    id: 'F-ssrf',
    file: 'src/fetch.ts',
    startLine: 10,
    endLine: 12,
    cwe: 'CWE-918',
    baseScore: 6.5,
  });
  const xss = makeFinding({
    id: 'F-xss',
    file: 'src/render.ts',
    startLine: 5,
    endLine: 6,
    cwe: 'CWE-79',
    baseScore: 5.4,
  });
  const lonely = makeFinding({
    id: 'F-lonely',
    file: 'src/lonely.ts',
    startLine: 2,
    endLine: 3,
    baseScore: 7.5,
    severity: 'high',
  });

  const ctx = makeContext({
    symbols,
    callGraph,
    entryPoints: [route, cliEntry],
  });

  it('同一エントリポイントから到達可能な Finding をまとめる', () => {
    const groups = buildCandidateGroups([ssrf, xss, lonely], ctx);
    const epGroup = groups.find((g) => g.kind === 'entry-point' && g.entryPointId === route.identifier);
    expect(epGroup).toBeDefined();
    expect(epGroup?.findingIds.sort()).toEqual(['F-ssrf', 'F-xss']);
    expect(epGroup?.reachabilityRatio).toBe(1);
  });

  it('到達性の根拠に呼び出しパスと深さが入る', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx);
    const epGroup = groups.find((g) => g.entryPointId === route.identifier);
    const ev = epGroup?.evidence.find((e) => e.findingId === 'F-xss');
    expect(ev?.reachable).toBe(true);
    expect(ev?.depth).toBe(2);
    expect(ev?.path).toEqual([
      'src/api.ts:reportRoute',
      'src/fetch.ts:fetchRemote',
      'src/render.ts:render',
    ]);
    expect(ev?.minEdgeConfidence).toBeCloseTo(0.8, 5);
  });

  it('どのエントリポイントからも到達できない孤立 Finding はグループ化されない', () => {
    const groups = buildCandidateGroups([ssrf, xss, lonely], ctx);
    const containsLonely = groups.some((g) => g.findingIds.includes('F-lonely'));
    expect(containsLonely).toBe(false);
  });

  it('単独 critical は単独グループになる', () => {
    const rce = makeFinding({
      id: 'F-rce',
      file: 'src/lonely.ts',
      startLine: 2,
      endLine: 3,
      cwe: 'CWE-78',
      severity: 'critical',
      baseScore: 9.8,
    });
    const groups = buildCandidateGroups([rce], ctx);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.kind).toBe('standalone');
    expect(groups[0]?.findingIds).toEqual(['F-rce']);
  });

  it('http-route は cli より露出度が高い', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx);
    const http = groups.find((g) => g.entryPointId === route.identifier);
    const cli = groups.find((g) => g.entryPointId === cliEntry.identifier);
    expect(ENTRY_POINT_EXPOSURE['http-route']).toBeGreaterThan(ENTRY_POINT_EXPOSURE.cli);
    if (http !== undefined && cli !== undefined) {
      expect(http.exposure).toBeGreaterThan(cli.exposure);
    }
  });

  it('確信度の低い呼び出しエッジは辿らない', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx, { minEdgeConfidence: 0.85 });
    const epGroup = groups.find((g) => g.entryPointId === route.identifier);
    // fetchRemote→render (0.8) が切れるので XSS には届かない
    expect(epGroup?.findingIds ?? []).not.toContain('F-xss');
  });

  it('maxGroups でグループ数を打ち切る', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx, { maxGroups: 1 });
    expect(groups).toHaveLength(1);
  });

  it('maxFindingsPerGroup を超える分は上流優先で切り捨てる', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx, { maxFindingsPerGroup: 1 });
    const epGroup = groups.find((g) => g.entryPointId === route.identifier);
    expect(epGroup?.findingIds).toEqual(['F-ssrf']);
  });

  it('Finding が空なら空配列', () => {
    expect(buildCandidateGroups([], ctx)).toEqual([]);
  });

  it('同一メンバのグループは重複排除される', () => {
    const groups = buildCandidateGroups([ssrf, xss], ctx);
    const keys = groups.map((g) => `${g.kind}|${[...g.findingIds].sort().join(',')}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
