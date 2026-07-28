import { describe, expect, it } from 'vitest';
import type { ScanContext, SymbolInfo } from '../types/context.js';
import { chunkFile } from './chunker.js';
import { buildChunkContext, chunkSymbolIds, findReachability, symbolId } from './context.js';
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
    file: { path: ROUTE_FILE, language: 'typescript', sizeBytes: 200, hash: 'h' },
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

describe('chunkSymbolIds', () => {
  it('チャンク内のシンボルIDを返す', () => {
    expect(chunkSymbolIds(handlerChunk())).toEqual([symbolId(ROUTE_FILE, 'getUser')]);
  });
});
