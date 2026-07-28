import { describe, expect, it } from 'vitest';
import { symbolId as sharedSymbolId } from '../context/symbols.js';
import type { CallGraph, SymbolTable } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import {
  bfs,
  buildAdjacency,
  computeReachability,
  findEnclosingSymbol,
  findNearestSymbol,
  normalizePath,
  pathMinConfidence,
  reconstructPath,
  resolveEntryPointSymbol,
  resolveFindingSymbol,
  symbolIdOf,
} from './reachability.js';
import { makeFinding, makeSymbolTable } from './test-fixtures.js';

function graph(edges: [string, string, number?][]): CallGraph {
  const callees: Record<string, string[]> = {};
  const callers: Record<string, string[]> = {};
  for (const [from, to] of edges) {
    (callees[from] ??= []).push(to);
    (callers[to] ??= []).push(from);
  }
  return {
    edges: edges.map(([from, to, confidence]) => ({
      from,
      to,
      file: from.split(':')[0] ?? '',
      line: 1,
      confidence: confidence ?? 1,
    })),
    callees,
    callers,
  };
}

describe('normalizePath', () => {
  it('先頭の ./ と重複スラッシュとバックスラッシュを吸収する', () => {
    expect(normalizePath('./src//a\\b.ts')).toBe('src/a/b.ts');
  });

  it('repoRoot 接頭辞を剥がす', () => {
    expect(normalizePath('/repo/src/a.ts', '/repo')).toBe('src/a.ts');
    expect(normalizePath('/other/src/a.ts', '/repo')).toBe('other/src/a.ts');
  });
});

describe('buildAdjacency', () => {
  it('確信度が閾値未満のエッジを除外する', () => {
    const adj = buildAdjacency(graph([['a:f', 'b:g', 0.2], ['a:f', 'c:h', 0.9]]), 0.5);
    expect(adj.callees.get('a:f')).toEqual(['c:h']);
  });

  it('edges が空なら callees にフォールバックする', () => {
    const g: CallGraph = { edges: [], callees: { 'a:f': ['b:g'] }, callers: {} };
    const adj = buildAdjacency(g, 0.9);
    expect(adj.callees.get('a:f')).toEqual(['b:g']);
  });

  it('同一エッジが重複したら最大の確信度を採用する', () => {
    const adj = buildAdjacency(graph([['a:f', 'b:g', 0.4], ['a:f', 'b:g', 0.95]]), 0);
    expect(adj.edgeConfidence.get('a:f b:g')).toBe(0.95);
  });
});

describe('bfs / reconstructPath', () => {
  const adj = buildAdjacency(
    graph([
      ['r:handler', 'a:parse'],
      ['a:parse', 'b:query'],
      ['b:query', 'c:exec'],
      ['r:handler', 'd:log'],
      // 循環
      ['c:exec', 'a:parse'],
    ]),
  );

  it('到達可能なノードに最短ホップ数を割り当てる', () => {
    const r = bfs(adj, 'r:handler');
    expect(r.depth.get('r:handler')).toBe(0);
    expect(r.depth.get('a:parse')).toBe(1);
    expect(r.depth.get('c:exec')).toBe(3);
    expect(r.depth.get('d:log')).toBe(1);
  });

  it('循環があっても停止する', () => {
    const r = bfs(adj, 'c:exec');
    expect(r.depth.get('a:parse')).toBe(1);
    expect(r.depth.has('r:handler')).toBe(false);
  });

  it('maxDepth を超えて辿らない', () => {
    const r = bfs(adj, 'r:handler', 2);
    expect(r.depth.has('b:query')).toBe(true);
    expect(r.depth.has('c:exec')).toBe(false);
  });

  it('呼び出しパスを復元できる', () => {
    const r = bfs(adj, 'r:handler');
    expect(reconstructPath(r, 'r:handler', 'c:exec')).toEqual([
      'r:handler',
      'a:parse',
      'b:query',
      'c:exec',
    ]);
  });

  it('未到達なら空配列を返す', () => {
    const r = bfs(adj, 'r:handler');
    expect(reconstructPath(r, 'r:handler', 'z:nope')).toEqual([]);
  });
});

describe('pathMinConfidence', () => {
  it('パス上の最弱エッジを返す', () => {
    const adj = buildAdjacency(graph([['a:f', 'b:g', 0.9], ['b:g', 'c:h', 0.6]]));
    expect(pathMinConfidence(adj, ['a:f', 'b:g', 'c:h'])).toBe(0.6);
  });

  it('単一ノードなら 1', () => {
    const adj = buildAdjacency(graph([]));
    expect(pathMinConfidence(adj, ['a:f'])).toBe(1);
  });
});

describe('シンボル解決', () => {
  const table: SymbolTable = makeSymbolTable([
    { name: 'UserController', kind: 'class', file: 'src/user.ts', startLine: 1, endLine: 100 },
    { name: 'getUser', kind: 'method', file: 'src/user.ts', startLine: 10, endLine: 30 },
    { name: 'helper', kind: 'function', file: 'src/util.ts', startLine: 5, endLine: 9 },
  ]);

  it('入れ子なら最も内側のシンボルを返す', () => {
    expect(findEnclosingSymbol(table, 'src/user.ts', 15)?.name).toBe('getUser');
    expect(findEnclosingSymbol(table, 'src/user.ts', 60)?.name).toBe('UserController');
  });

  it('パス表記が違っても一致させる', () => {
    expect(findEnclosingSymbol(table, './src/user.ts', 15)?.name).toBe('getUser');
  });

  it('【統合で改善】同じ幅なら class より内側の定義を優先する', () => {
    // SymbolLocator.locate のタイブレーク規則。再実装版には無かったため、
    // callgraph.ts が組んだノードIDと killchain が解決するIDが食い違い、
    // 到達可能性が静かに false になりうる状態だった。
    const tied = makeSymbolTable([
      { name: 'Wrapper', kind: 'class', file: 'src/tie.ts', startLine: 1, endLine: 20 },
      { name: 'handler', kind: 'function', file: 'src/tie.ts', startLine: 1, endLine: 20 },
    ]);
    expect(findEnclosingSymbol(tied, 'src/tie.ts', 10)?.name).toBe('handler');
  });

  it('【統合で改善】repoRoot 付きの絶対パス・重複スラッシュも解決できる', () => {
    expect(findEnclosingSymbol(table, '/repo/src/user.ts', 15, '/repo')?.name).toBe('getUser');
    expect(findEnclosingSymbol(table, '//src/user.ts', 15)?.name).toBe('getUser');
    expect(findEnclosingSymbol(table, 'src\\user.ts', 15)?.name).toBe('getUser');
  });

  it('解決したシンボルIDは context/symbols.ts の規約と一致する', () => {
    // `${file}:${name}` はグラフ・SymbolTable.byId・EntryPoint.symbolId を
    // 繋ぐ唯一の結合規約なので、共有実装と同じ文字列でなければならない。
    expect(symbolIdOf({ file: 'src/user.ts', name: 'getUser' })).toBe(
      sharedSymbolId('src/user.ts', 'getUser'),
    );
  });

  it('範囲外なら null、近傍探索なら最寄りを返す', () => {
    expect(findEnclosingSymbol(table, 'src/util.ts', 200)).toBeNull();
    expect(findNearestSymbol(table, 'src/util.ts', 200)?.name).toBe('helper');
  });

  it('symbolId が明記されたエントリポイントはそれを優先する', () => {
    const id = resolveEntryPointSymbol(
      {
        kind: 'http-route',
        identifier: 'GET /u',
        file: 'src/user.ts',
        line: 15,
        symbolId: 'src/user.ts:explicit',
      },
      table,
    );
    expect(id).toBe('src/user.ts:explicit');
  });

  it('symbolId が無ければ位置から解決する', () => {
    const id = resolveEntryPointSymbol(
      { kind: 'http-route', identifier: 'GET /u', file: 'src/user.ts', line: 15 },
      table,
    );
    expect(id).toBe(symbolIdOf({ file: 'src/user.ts', name: 'getUser' }));
  });

  it('Finding は開始行→終了行→近傍の順で解決する', () => {
    const f = makeFinding({ id: 'F1', file: 'src/util.ts', startLine: 7, endLine: 8 });
    expect(resolveFindingSymbol(f, table)).toBe('src/util.ts:helper');

    const outside = makeFinding({ id: 'F2', file: 'src/util.ts', startLine: 300, endLine: 301 });
    expect(resolveFindingSymbol(outside, table)).toBe('src/util.ts:helper');

    const unknown = makeFinding({ id: 'F3', file: 'src/none.ts', startLine: 1, endLine: 2 });
    expect(resolveFindingSymbol(unknown, table)).toBeNull();
  });
});

describe('computeReachability', () => {
  const table: SymbolTable = makeSymbolTable([
    { name: 'route', kind: 'route', file: 'src/api.ts', startLine: 1, endLine: 20 },
    { name: 'svc', kind: 'function', file: 'src/svc.ts', startLine: 1, endLine: 40 },
    { name: 'orphan', kind: 'function', file: 'src/orphan.ts', startLine: 1, endLine: 10 },
  ]);
  const adj = buildAdjacency(graph([['src/api.ts:route', 'src/svc.ts:svc', 0.8]]));

  const reachableFinding = makeFinding({ id: 'A', file: 'src/svc.ts', startLine: 5, endLine: 6 });
  const orphanFinding = makeFinding({ id: 'B', file: 'src/orphan.ts', startLine: 2, endLine: 3 });
  const sameFileFinding = makeFinding({ id: 'C', file: 'src/api.ts', startLine: 500, endLine: 501 });

  const symbols = new Map<string, string | null>([
    ['A', 'src/svc.ts:svc'],
    ['B', 'src/orphan.ts:orphan'],
    ['C', null],
  ]);

  it('到達可能な Finding に経路と深さを付ける', () => {
    const ev = computeReachability(
      'src/api.ts:route',
      'src/api.ts',
      [reachableFinding, orphanFinding, sameFileFinding] as Finding[],
      symbols,
      adj,
    );
    const a = ev.find((e) => e.findingId === 'A');
    expect(a?.reachable).toBe(true);
    expect(a?.depth).toBe(1);
    expect(a?.path).toEqual(['src/api.ts:route', 'src/svc.ts:svc']);
    expect(a?.minEdgeConfidence).toBe(0.8);
  });

  it('未到達な Finding は reachable=false になる', () => {
    const ev = computeReachability(
      'src/api.ts:route',
      'src/api.ts',
      [orphanFinding] as Finding[],
      symbols,
      adj,
    );
    expect(ev[0]?.reachable).toBe(false);
    expect(ev[0]?.depth).toBe(-1);
  });

  it('シンボル解決不能でも同一ファイルなら弱い根拠として記録する', () => {
    const ev = computeReachability(
      'src/api.ts:route',
      'src/api.ts',
      [sameFileFinding] as Finding[],
      symbols,
      adj,
    );
    expect(ev[0]?.reachable).toBe(false);
    expect(ev[0]?.sameFileOnly).toBe(true);
  });

  it('エントリポイントのシンボルが解決できない場合も落ちない', () => {
    const ev = computeReachability(null, null, [reachableFinding] as Finding[], symbols, adj);
    expect(ev[0]?.reachable).toBe(false);
    expect(ev[0]?.sameFileOnly).toBe(false);
  });
});
