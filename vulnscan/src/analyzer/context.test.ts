import { describe, expect, it } from 'vitest';
import type { ScanContext, SymbolInfo } from '../types/context.js';
import { chunkFile } from './chunker.js';
import {
  buildChunkContext,
  buildScanContextIndex,
  chunkSymbolIds,
  findReachability,
  symbolId,
} from './context.js';
import type { Chunk } from './types.js';

const ROUTE_FILE = 'src/routes/user.ts';
const REPO_FILE = 'src/db/repo.ts';

function symbol(
  name: string,
  file: string,
  startLine: number,
  endLine: number,
  overrides: Partial<SymbolInfo> = {},
): SymbolInfo {
  return {
    name,
    kind: 'function',
    file,
    startLine,
    endLine,
    exported: true,
    ...overrides,
  };
}

const handler = symbol('getUser', ROUTE_FILE, 5, 12);
const findUser = symbol('findUser', REPO_FILE, 3, 8);
const registerRoutes = symbol('registerRoutes', ROUTE_FILE, 1, 3);

function makeContext(): ScanContext {
  const symbols = [handler, findUser, registerRoutes];
  return {
    repoRoot: '/repo',
    scannedAt: '2026-07-28T00:00:00Z',
    readme: null,
    languages: [{ name: 'typescript', fileCount: 2, ratio: 1 }],
    frameworks: [{ name: 'express', evidence: 'package.json: express', version: '4.19.2' }],
    dependencies: [],
    files: [],
    symbols: {
      symbols,
      byId: Object.fromEntries(symbols.map((s) => [symbolId(s.file, s.name), s])),
    },
    callGraph: {
      edges: [
        {
          from: symbolId(ROUTE_FILE, 'registerRoutes'),
          to: symbolId(ROUTE_FILE, 'getUser'),
          file: ROUTE_FILE,
          line: 2,
          confidence: 0.9,
        },
        {
          from: symbolId(ROUTE_FILE, 'getUser'),
          to: symbolId(REPO_FILE, 'findUser'),
          file: ROUTE_FILE,
          line: 9,
          confidence: 0.8,
        },
      ],
      callees: {
        [symbolId(ROUTE_FILE, 'registerRoutes')]: [symbolId(ROUTE_FILE, 'getUser')],
        [symbolId(ROUTE_FILE, 'getUser')]: [symbolId(REPO_FILE, 'findUser'), 'unresolvedFn'],
      },
      callers: {
        [symbolId(ROUTE_FILE, 'getUser')]: [symbolId(ROUTE_FILE, 'registerRoutes')],
        [symbolId(REPO_FILE, 'findUser')]: [symbolId(ROUTE_FILE, 'getUser')],
      },
    },
    entryPoints: [
      {
        kind: 'http-route',
        identifier: 'GET /users/:id',
        file: ROUTE_FILE,
        line: 2,
        symbolId: symbolId(ROUTE_FILE, 'registerRoutes'),
        metadata: { method: 'GET' },
      },
    ],
    trustBoundaries: [
      {
        type: 'source',
        category: 'user-input',
        expression: 'req.params.id',
        file: ROUTE_FILE,
        line: 6,
        symbolId: symbolId(ROUTE_FILE, 'getUser'),
      },
      {
        type: 'sink',
        category: 'sql',
        expression: 'db.query(`...`)',
        file: REPO_FILE,
        line: 5,
        symbolId: symbolId(REPO_FILE, 'findUser'),
      },
      {
        type: 'sink',
        category: 'html-output',
        expression: 'res.send(html)',
        file: 'src/other.ts',
        line: 40,
        symbolId: 'src/other.ts:render',
      },
    ],
    warnings: [],
  };
}

function handlerChunk(): Chunk {
  const content = [
    'export function registerRoutes(app) {', // 1
    "  app.get('/users/:id', getUser);", // 2
    '}', // 3
    '', // 4
    'export function getUser(req, res) {', // 5
    '  const id = req.params.id;', // 6
    '  const rows = findUser(id);', // 7
    '  res.json(rows);', // 8
    '}', // 9
  ].join('\n');

  const chunks = chunkFile({
    file: { path: ROUTE_FILE, language: 'typescript', sizeBytes: 200, lines: 8, hash: 'h' },
    content,
    symbols: [
      symbol('registerRoutes', ROUTE_FILE, 1, 3),
      symbol('getUser', ROUTE_FILE, 5, 9),
    ],
  });

  const chunk = chunks.find((c) => c.label === 'getUser');
  if (!chunk) throw new Error('getUser チャンクが見つからない');
  return chunk;
}

describe('buildChunkContext', () => {
  it('呼び出し元・呼び出し先のシグネチャを添える', () => {
    const ctx = makeContext();
    const built = buildChunkContext(ctx, handlerChunk());

    expect(built.callers.map((c) => c.id)).toEqual([symbolId(ROUTE_FILE, 'registerRoutes')]);
    expect(built.callers[0]?.via).toEqual({ file: ROUTE_FILE, line: 2 });
    expect(built.text).toContain('function registerRoutes');

    expect(built.callees.map((c) => c.id)).toEqual([
      symbolId(REPO_FILE, 'findUser'),
      'unresolvedFn',
    ]);
    // 名前解決できなかった呼び出し先もその旨を添えて残す
    expect(built.callees[1]?.resolved).toBe(false);
    expect(built.text).toContain('シンボル未解決');
  });

  it('関係する信頼境界だけを添える', () => {
    const built = buildChunkContext(makeContext(), handlerChunk());

    expect(built.directBoundaries.map((b) => b.expression)).toEqual(['req.params.id']);
    // 呼び出し先の sink は「間接的に関係する」側に入る
    expect(built.relatedBoundaries.map((b) => b.expression)).toEqual(['db.query(`...`)']);
    // 無関係なファイルの sink は入らない
    expect(built.text).not.toContain('res.send(html)');
  });

  it('エントリポイントからの到達可能性を判定する', () => {
    const built = buildChunkContext(makeContext(), handlerChunk());
    expect(built.reachability.reachable).toBe(true);
    expect(built.reachability.entryPoint?.identifier).toBe('GET /users/:id');
    expect(built.text).toContain('到達しうる');
  });

  it('フレームワークを添える', () => {
    const built = buildChunkContext(makeContext(), handlerChunk());
    expect(built.text).toContain('express@4.19.2');
  });

  it('declarationOf があれば宣言行を添える', () => {
    const built = buildChunkContext(makeContext(), handlerChunk(), {
      declarationOf: (s) => (s.name === 'findUser' ? 'export function findUser(id) {' : undefined),
    });
    expect(built.text).toContain('宣言: export function findUser(id) {');
  });

  it('関連シンボルの件数を上限で打ち切る', () => {
    const built = buildChunkContext(makeContext(), handlerChunk(), { maxRelated: 1 });
    expect(built.callees).toHaveLength(1);
  });
});

describe('findReachability', () => {
  it('深さ制限を超える経路は未到達として扱う', () => {
    const ctx = makeContext();
    const reach = findReachability([symbolId(REPO_FILE, 'findUser')], ctx, 0);
    expect(reach.reachable).toBe(false);

    const deeper = findReachability([symbolId(REPO_FILE, 'findUser')], ctx, 5);
    expect(deeper.reachable).toBe(true);
    expect(deeper.path).toEqual([
      symbolId(REPO_FILE, 'findUser'),
      symbolId(ROUTE_FILE, 'getUser'),
      symbolId(ROUTE_FILE, 'registerRoutes'),
    ]);
  });

  it('循環があっても止まる', () => {
    const ctx = makeContext();
    ctx.callGraph.callers = {
      'a:x': ['a:y'],
      'a:y': ['a:x'],
    };
    expect(findReachability(['a:x'], ctx, 10).reachable).toBe(false);
  });
});

describe('buildScanContextIndex（事前構築した索引）', () => {
  it('索引を渡しても渡さなくても同じ ChunkContext になる', () => {
    const chunk = handlerChunk();
    const withoutIndex = buildChunkContext(makeContext(), chunk);

    const ctx = makeContext();
    const withIndex = buildChunkContext(ctx, chunk, { index: buildScanContextIndex(ctx) });

    expect(withIndex).toEqual(withoutIndex);
  });

  it('索引を渡すと呼び出しグラフの辺を線形走査しない', () => {
    const ctx = makeContext();
    const index = buildScanContextIndex(ctx);

    // 索引の構築が済んだ後は edges に一切触れないはず
    const guarded = new Proxy(ctx.callGraph.edges, {
      get(_target, prop) {
        throw new Error(`edges.${String(prop)} を参照した（全走査が残っている）`);
      },
    });

    const built = buildChunkContext(
      { ...ctx, callGraph: { ...ctx.callGraph, edges: guarded } },
      handlerChunk(),
      { index },
    );

    // それでも呼び出し位置（辺の情報）は従来どおり添えられる
    expect(built.callers[0]?.via).toEqual({ file: ROUTE_FILE, line: 2 });
    expect(built.callees[0]?.via).toEqual({ file: ROUTE_FILE, line: 9 });
  });

  it('無関係な信頼境界・エントリポイントが大量にあっても出力が変わらない', () => {
    const chunk = handlerChunk();
    const base = buildChunkContext(makeContext(), chunk);

    const ctx = makeContext();
    for (let i = 0; i < 2000; i++) {
      ctx.trustBoundaries.push({
        type: 'sink',
        category: 'sql',
        expression: `noise-${i}`,
        file: `src/noise/${i}.ts`,
        line: i + 1,
        symbolId: `src/noise/${i}.ts:noise`,
      });
      ctx.entryPoints.push({
        kind: 'http-route',
        identifier: `/noise/${i}`,
        file: `src/noise/${i}.ts`,
        line: i + 1,
        symbolId: `src/noise/${i}.ts:noise`,
      });
    }

    const built = buildChunkContext(ctx, chunk, { index: buildScanContextIndex(ctx) });
    expect(built.directBoundaries).toEqual(base.directBoundaries);
    expect(built.relatedBoundaries).toEqual(base.relatedBoundaries);
    expect(built.ownEntryPoints).toEqual(base.ownEntryPoints);
    expect(built.text).toBe(base.text);
  });

  it('信頼境界の並び順と上限は ScanContext の並び順どおりに効く', () => {
    const ctx = makeContext();
    // getUser（6〜9行）の範囲に入る境界を先頭側へ追加する
    ctx.trustBoundaries.unshift({
      type: 'source',
      category: 'user-input',
      expression: 'req.headers.auth',
      file: ROUTE_FILE,
      line: 7,
      symbolId: symbolId(ROUTE_FILE, 'getUser'),
    });

    const built = buildChunkContext(ctx, handlerChunk(), {
      index: buildScanContextIndex(ctx),
      maxBoundaries: 1,
    });

    // 元配列で先に現れるものが残る
    expect(built.directBoundaries.map((b) => b.expression)).toEqual(['req.headers.auth']);
  });

  it('findReachability は事前構築した entryById を使っても同じ結果を返す', () => {
    const ctx = makeContext();
    const ids = [symbolId(REPO_FILE, 'findUser')];

    const built = findReachability(ids, ctx, 5);
    const withIndex = findReachability(ids, ctx, 5, buildScanContextIndex(ctx).entryById);

    expect(withIndex).toEqual(built);
    expect(withIndex.reachable).toBe(true);
  });
});

describe('chunkSymbolIds', () => {
  it('チャンク内のシンボルIDを返す', () => {
    expect(chunkSymbolIds(handlerChunk())).toEqual([symbolId(ROUTE_FILE, 'getUser')]);
  });
});
