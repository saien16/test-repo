import { describe, expect, it } from 'vitest';
import { buildCallGraph } from './callgraph.js';
import { maskSource } from './mask.js';
import { buildSymbolTable, extractFileSymbols, type AnalyzableSource } from './symbols.js';

function source(path: string, language: string, lines: string[]): AnalyzableSource {
  const content = lines.join('\n');
  return { path, language, masked: maskSource(content, language) };
}

function find(symbols: ReturnType<typeof extractFileSymbols>, name: string) {
  return symbols.find((s) => s.name === name);
}

describe('maskSource', () => {
  it('コメントを潰しつつ文字列リテラルは残す', () => {
    const masked = maskSource(['// eval(danger)', "const p = '/users';"].join('\n'), 'typescript');
    expect(masked.noComment[0]?.trim()).toBe('');
    expect(masked.noComment[1]).toContain('/users');
    // codeOnly は文字列の中身も消える
    expect(masked.codeOnly[1]).not.toContain('/users');
  });

  it('ブロックコメントが複数行に跨っても行数を保つ', () => {
    const masked = maskSource(['/*', 'function ghost() {}', '*/', 'const x = 1;'].join('\n'), 'javascript');
    expect(masked.codeOnly).toHaveLength(4);
    expect(masked.codeOnly[1]?.trim()).toBe('');
    expect(masked.codeOnly[3]).toContain('const x');
  });

  it('Python のコメントと文字列を扱える', () => {
    const masked = maskSource(['# def ghost():', "path = '/etc/passwd'"].join('\n'), 'python');
    expect(masked.noComment[0]?.trim()).toBe('');
    expect(masked.noComment[1]).toContain('/etc/passwd');
  });
});

describe('extractFileSymbols (TypeScript)', () => {
  const src = source('src/user.ts', 'typescript', [
    'export function greet(name: string): string {', // 1
    '  return `hi ${name}`;', //                        2
    '}', //                                             3
    '', //                                              4
    'export class UserService {', //                    5
    '  async findUser(id: string) {', //                6
    '    return this.repo.query(id);', //               7
    '  }', //                                           8
    '}', //                                             9
    '', //                                             10
    'const helper = (x: number) => {', //              11
    '  return x + 1;', //                              12
    '};', //                                           13
  ]);
  const symbols = extractFileSymbols(src);

  it('ファイル全体を表す module シンボルを含む', () => {
    const mod = find(symbols, '<module>');
    expect(mod?.kind).toBe('module');
    expect(mod?.endLine).toBe(13);
  });

  it('関数の定義範囲を波括弧の対応から求める', () => {
    const greet = find(symbols, 'greet');
    expect(greet).toMatchObject({ kind: 'function', startLine: 1, endLine: 3, exported: true });
  });

  it('クラスとメソッドを所属付きで抽出する', () => {
    expect(find(symbols, 'UserService')).toMatchObject({
      kind: 'class',
      startLine: 5,
      endLine: 9,
      exported: true,
    });
    expect(find(symbols, 'findUser')).toMatchObject({
      kind: 'method',
      container: 'UserService',
      startLine: 6,
      endLine: 8,
    });
  });

  it('アロー関数の代入も関数として拾う', () => {
    expect(find(symbols, 'helper')).toMatchObject({ kind: 'function', startLine: 11, endLine: 13 });
  });

  it('制御構文をシンボルと誤認しない', () => {
    expect(find(symbols, 'if')).toBeUndefined();
    expect(find(symbols, 'for')).toBeUndefined();
  });
});

describe('extractFileSymbols (Python)', () => {
  const symbols = extractFileSymbols(
    source('app/views.py', 'python', [
      'class Foo:', //           1
      '    def bar(self):', //   2
      '        return 1', //     3
      '', //                     4
      'def top():', //           5
      '    return 2', //         6
    ]),
  );

  it('インデントでブロック範囲を決める', () => {
    expect(find(symbols, 'Foo')).toMatchObject({ kind: 'class', startLine: 1, endLine: 3 });
    expect(find(symbols, 'bar')).toMatchObject({
      kind: 'method',
      container: 'Foo',
      startLine: 2,
      endLine: 3,
    });
    expect(find(symbols, 'top')).toMatchObject({ kind: 'function', startLine: 5, endLine: 6 });
  });

  it('先頭アンダースコアは非公開として扱う', () => {
    const privateSymbols = extractFileSymbols(
      source('app/util.py', 'python', ['def _hidden():', '    pass']),
    );
    expect(find(privateSymbols, '_hidden')?.exported).toBe(false);
  });
});

describe('extractFileSymbols (Go)', () => {
  const symbols = extractFileSymbols(
    source('main.go', 'go', [
      'func main() {', //                       1
      '\trun()', //                             2
      '}', //                                   3
      '', //                                    4
      'func (s *Server) Handle(w, r) {', //     5
      '\tfmt.Println("x")', //                  6
      '}', //                                   7
    ]),
  );

  it('レシーバからメソッドの所属を決める', () => {
    expect(find(symbols, 'Handle')).toMatchObject({
      kind: 'method',
      container: 'Server',
      startLine: 5,
      endLine: 7,
      exported: true,
    });
  });

  it('小文字始まりは非公開として扱う', () => {
    expect(find(symbols, 'main')).toMatchObject({ kind: 'function', exported: false });
  });
});

describe('buildCallGraph', () => {
  const src = source('src/app.ts', 'typescript', [
    'function helper(x) {', //          1
    '  return x;', //                   2
    '}', //                             3
    'function caller(x) {', //          4
    '  const y = helper(x);', //        5
    '  return externalThing(y);', //    6
    '}', //                             7
  ]);
  const warnings: string[] = [];
  const table = buildSymbolTable([src], warnings);
  const graph = buildCallGraph([src], table, warnings);

  it('同一ファイル内で解決できた呼び出しは確度が高い', () => {
    const edge = graph.edges.find((e) => e.to === 'src/app.ts:helper');
    expect(edge).toBeDefined();
    expect(edge?.from).toBe('src/app.ts:caller');
    expect(edge?.line).toBe(5);
    expect(edge?.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it('定義が見つからない呼び出しは名前のみ・低確度で残す', () => {
    const edge = graph.edges.find((e) => e.to === 'externalThing');
    expect(edge?.confidence).toBeLessThan(0.3);
  });

  it('callees / callers の索引が張られる', () => {
    expect(graph.callees['src/app.ts:caller']).toContain('src/app.ts:helper');
    expect(graph.callers['src/app.ts:helper']).toContain('src/app.ts:caller');
  });

  it('警告を出さずに解析できる', () => {
    expect(warnings).toEqual([]);
  });

  it('Object.prototype と同名の呼び出し先でも索引が壊れない', () => {
    const tricky = source('src/tricky.ts', 'typescript', [
      'function run(x) {', //          1
      '  return x.toString();', //     2
      '}', //                          3
    ]);
    const localWarnings: string[] = [];
    const localTable = buildSymbolTable([tricky], localWarnings);
    const localGraph = buildCallGraph([tricky], localTable, localWarnings);

    expect(localWarnings).toEqual([]);
    expect(localGraph.callers['toString']).toEqual(['src/tricky.ts:run']);
  });
});

describe('buildSymbolTable', () => {
  it('byId で `${file}:${name}` を索引できる', () => {
    const table = buildSymbolTable(
      [source('src/a.ts', 'typescript', ['export function run() {', '  return 1;', '}'])],
      [],
    );
    expect(table.byId['src/a.ts:run']?.kind).toBe('function');
    expect(table.byId['src/a.ts:<module>']?.kind).toBe('module');
  });

  it('壊れたコードでも例外を投げない', () => {
    const broken = source('src/broken.ts', 'typescript', [
      'export function unterminated() {',
      '  const s = "開いたまま',
      '  if (x) {',
    ]);
    expect(() => buildSymbolTable([broken], [])).not.toThrow();
  });
});
