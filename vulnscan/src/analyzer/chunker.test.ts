import { describe, expect, it } from 'vitest';
import type { SourceFile, SymbolInfo } from '../types/context.js';
import {
  chunkFile,
  groupSymbolsByFile,
  invertRanges,
  mergeRanges,
  splitRange,
  topLevelSymbols,
} from './chunker.js';
import type { ChunkLimits } from './types.js';

const FILE = 'src/a.ts';

function file(overrides: Partial<SourceFile> = {}): SourceFile {
  return {
    path: FILE,
    language: 'typescript',
    sizeBytes: 512,
    lines: 16,
    hash: 'hash-1',
    ...overrides,
  };
}

function sym(
  name: string,
  kind: SymbolInfo['kind'],
  startLine: number,
  endLine: number,
  overrides: Partial<SymbolInfo> = {},
): SymbolInfo {
  return { name, kind, file: FILE, startLine, endLine, exported: false, ...overrides };
}

const LOOSE: ChunkLimits = { maxLines: 320, maxChars: 12_000, overlapLines: 12 };

describe('splitRange', () => {
  it('オーバーラップ付きの行ウィンドウに分割する', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`);
    const parts = splitRange({ startLine: 1, endLine: 30 }, lines, {
      maxLines: 10,
      maxChars: 10_000,
      overlapLines: 2,
    });
    expect(parts).toEqual([
      { startLine: 1, endLine: 10 },
      { startLine: 9, endLine: 18 },
      { startLine: 17, endLine: 26 },
      { startLine: 25, endLine: 30 },
    ]);
  });

  it('1行が上限を超えても前進する（無限ループしない）', () => {
    const lines = ['x'.repeat(100), 'y'.repeat(100)];
    const parts = splitRange({ startLine: 1, endLine: 2 }, lines, {
      maxLines: 10,
      maxChars: 10,
      overlapLines: 5,
    });
    expect(parts).toEqual([
      { startLine: 1, endLine: 1 },
      { startLine: 2, endLine: 2 },
    ]);
  });
});

describe('mergeRanges / invertRanges', () => {
  it('隣接・重複する範囲をまとめる', () => {
    expect(
      mergeRanges([
        { startLine: 5, endLine: 8 },
        { startLine: 1, endLine: 3 },
        { startLine: 4, endLine: 4 },
      ]),
    ).toEqual([{ startLine: 1, endLine: 8 }]);
  });

  it('覆われていない範囲を返す', () => {
    expect(
      invertRanges(
        [
          { startLine: 3, endLine: 5 },
          { startLine: 8, endLine: 9 },
        ],
        12,
      ),
    ).toEqual([
      { startLine: 1, endLine: 2 },
      { startLine: 6, endLine: 7 },
      { startLine: 10, endLine: 12 },
    ]);
  });
});

describe('topLevelSymbols', () => {
  it('包含されているシンボルを除く', () => {
    const symbols = [
      sym('C', 'class', 1, 20),
      sym('m1', 'method', 2, 5, { container: 'C' }),
      sym('helper', 'function', 22, 30),
    ];
    expect(topLevelSymbols(symbols).map((s) => s.name)).toEqual(['C', 'helper']);
  });
});

describe('chunkFile', () => {
  const content = [
    "import { db } from './db';", // 1
    "const SECRET = 'sk-live-hardcoded';", // 2
    '', // 3
    'export function a() {', // 4
    '  return 1;', // 5
    '}', // 6
    '', // 7
    'export function b() {', // 8
    '  return 2;', // 9
    '}', // 10
  ].join('\n');

  const symbols = [
    sym('a', 'function', 4, 6, { exported: true }),
    sym('b', 'function', 8, 10, { exported: true }),
  ];

  it('関数単位で切り出し、残余をmoduleチャンクにする', () => {
    const chunks = chunkFile({ file: file(), content, symbols }, LOOSE);

    expect(chunks.map((c) => c.kind)).toEqual(['module', 'symbol', 'symbol']);
    expect(chunks.map((c) => c.label)).toEqual(['module', 'a', 'b']);

    const moduleChunk = chunks[0];
    expect(moduleChunk?.segments).toEqual([{ startLine: 1, endLine: 3 }]);
    // モジュールスコープのハードコード秘密情報を落とさない
    expect(moduleChunk?.code).toContain('sk-live-hardcoded');

    const aChunk = chunks[1];
    expect(aChunk?.startLine).toBe(4);
    expect(aChunk?.endLine).toBe(6);
    expect(aChunk?.symbols.map((s) => s.name)).toEqual(['a']);
  });

  it('コードに実ファイルの行番号を付ける', () => {
    const chunks = chunkFile({ file: file(), content, symbols }, LOOSE);
    expect(chunks[1]?.code).toBe(
      ['    4| export function a() {', '    5|   return 1;', '    6| }'].join('\n'),
    );
  });

  it('チャンクIDにファイルパスと範囲が入る（キャッシュキーとして安定）', () => {
    const chunks = chunkFile({ file: file(), content, symbols }, LOOSE);
    expect(chunks[1]?.id).toBe('src/a.ts#a@4-6');
    // 同じ入力なら同じID
    expect(chunkFile({ file: file(), content, symbols }, LOOSE)[1]?.id).toBe(chunks[1]?.id);
  });

  it('シンボル情報が無ければファイル全体を1チャンクにする（フォールバック）', () => {
    const chunks = chunkFile({ file: file(), content, symbols: [] }, LOOSE);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.kind).toBe('file');
    expect(chunks[0]?.startLine).toBe(1);
    expect(chunks[0]?.endLine).toBe(10);
  });

  it('空ファイルはチャンクを作らない', () => {
    expect(chunkFile({ file: file(), content: '   \n\n', symbols: [] }, LOOSE)).toEqual([]);
  });

  it('他ファイルのシンボルは無視する', () => {
    const chunks = chunkFile(
      {
        file: file(),
        content,
        symbols: [...symbols, sym('other', 'function', 1, 3, { file: 'src/b.ts' })],
      },
      LOOSE,
    );
    expect(chunks.every((c) => c.symbols.every((s) => s.file === FILE))).toBe(true);
  });

  it('大きすぎるクラスは内側のメソッドへ降りる', () => {
    const big = Array.from({ length: 12 }, (_, i) => `  line${i + 1}`);
    const classContent = ['class C {', ...big, '}'].join('\n');
    const classSymbols = [
      sym('C', 'class', 1, 14),
      sym('m1', 'method', 2, 7, { container: 'C' }),
      sym('m2', 'method', 8, 13, { container: 'C' }),
    ];

    const chunks = chunkFile({ file: file(), content: classContent, symbols: classSymbols }, {
      maxLines: 8,
      maxChars: 10_000,
      overlapLines: 2,
    });

    const symbolChunks = chunks.filter((c) => c.kind === 'symbol');
    expect(symbolChunks.map((c) => c.label)).toEqual(['C.m1', 'C.m2']);
  });

  it('子シンボルの無い巨大な関数は行ウィンドウで分割する', () => {
    const body = Array.from({ length: 28 }, (_, i) => `  const v${i} = ${i};`);
    const fnContent = ['function huge() {', ...body, '}'].join('\n');
    const chunks = chunkFile(
      { file: file(), content: fnContent, symbols: [sym('huge', 'function', 1, 30)] },
      { maxLines: 10, maxChars: 10_000, overlapLines: 2 },
    );

    const parts = chunks.filter((c) => c.kind === 'symbol-part');
    expect(parts.length).toBeGreaterThan(1);
    expect(parts[0]?.part).toEqual({ index: 1, total: parts.length });
    // 分割してもIDは一意
    expect(new Set(parts.map((c) => c.id)).size).toBe(parts.length);
  });
});

describe('groupSymbolsByFile', () => {
  it('ファイルごとにまとめる', () => {
    const map = groupSymbolsByFile([
      sym('a', 'function', 1, 2),
      sym('b', 'function', 3, 4),
      sym('c', 'function', 1, 2, { file: 'src/b.ts' }),
    ]);
    expect(map.get(FILE)?.map((s) => s.name)).toEqual(['a', 'b']);
    expect(map.get('src/b.ts')?.map((s) => s.name)).toEqual(['c']);
  });
});
