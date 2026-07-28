/**
 * 呼び出しグラフの構築。
 *
 * 呼び出し式を正規表現で拾い、シンボル表と突き合わせて解決する。
 * 型解決は行わないため、確度を `CallEdge.confidence` に載せて後段が
 * 重み付けできるようにする。
 *
 *   同一ファイル内に定義あり     : 高（0.75〜0.9）
 *   他ファイルに一意な定義あり   : 中（0.5〜0.6）
 *   同名定義が複数              : 低（0.3）
 *   定義が見つからない（外部API）: 最低（0.15）
 */

import type { CallEdge, CallGraph, SymbolInfo, SymbolTable } from '../types/context.js';
import { MODULE_SYMBOL_NAME, SymbolLocator, symbolId, type AnalyzableSource } from './symbols.js';

/** `receiver.name(` / `name(` を拾う */
const CALL_PATTERN = /(?:([A-Za-z_$][\w$]*)\s*(?:\.|->|::)\s*)?([A-Za-z_$][\w$]*)\s*\(/g;

/** 呼び出しに見えるが呼び出しではないキーワード */
const NOT_A_CALL = new Set([
  'if',
  'else',
  'elif',
  'for',
  'foreach',
  'while',
  'switch',
  'match',
  'catch',
  'except',
  'do',
  'try',
  'return',
  'function',
  'func',
  'def',
  'class',
  'struct',
  'interface',
  'typeof',
  'instanceof',
  'sizeof',
  'in',
  'of',
  'and',
  'or',
  'not',
  'with',
  'yield',
  'case',
  'when',
  'unless',
  'until',
  'lambda',
  'constructor',
  'super',
]);

const MAX_EDGES_PER_FILE = 3000;
const MAX_EDGES_TOTAL = 60_000;

/** 呼び出し先候補の索引を作る */
function indexByName(table: SymbolTable): Map<string, SymbolInfo[]> {
  const index = new Map<string, SymbolInfo[]>();
  for (const symbol of table.symbols) {
    if (symbol.kind === 'module') continue;
    const list = index.get(symbol.name);
    if (list) list.push(symbol);
    else index.set(symbol.name, [symbol]);
  }
  return index;
}

interface Resolution {
  to: string;
  confidence: number;
}

function resolve(
  name: string,
  file: string,
  hasReceiver: boolean,
  index: Map<string, SymbolInfo[]>,
): Resolution {
  const candidates = index.get(name);
  if (!candidates || candidates.length === 0) {
    // 外部ライブラリや組み込み API の可能性が高い
    return { to: name, confidence: 0.15 };
  }

  const sameFile = candidates.filter((c) => c.file === file);
  if (sameFile.length === 1) {
    const target = sameFile[0] as SymbolInfo;
    return { to: symbolId(target.file, target.name), confidence: hasReceiver ? 0.8 : 0.9 };
  }
  if (sameFile.length > 1) {
    const target = sameFile[0] as SymbolInfo;
    return { to: symbolId(target.file, target.name), confidence: 0.75 };
  }

  if (candidates.length === 1) {
    const target = candidates[0] as SymbolInfo;
    return { to: symbolId(target.file, target.name), confidence: hasReceiver ? 0.5 : 0.6 };
  }

  // 同名が複数ファイルに散らばる場合は名前一致のみの弱い解決
  const target = candidates[0] as SymbolInfo;
  return { to: symbolId(target.file, target.name), confidence: 0.3 };
}

/**
 * 呼び出しグラフを構築する。解析に失敗したファイルは warnings に積んでスキップする。
 */
export function buildCallGraph(
  sources: readonly AnalyzableSource[],
  table: SymbolTable,
  warnings: string[],
): CallGraph {
  const index = indexByName(table);
  const locator = new SymbolLocator(table);
  const edges: CallEdge[] = [];
  // 同一 from→to（同一行）の重複を抑える
  const seen = new Set<string>();

  // 定義行での自己言及を除外するための索引
  const definitionLines = new Map<string, Set<string>>();
  for (const symbol of table.symbols) {
    if (symbol.kind === 'module') continue;
    const key = `${symbol.file}:${symbol.startLine}`;
    const set = definitionLines.get(key);
    if (set) set.add(symbol.name);
    else definitionLines.set(key, new Set([symbol.name]));
  }

  for (const source of sources) {
    if (edges.length >= MAX_EDGES_TOTAL) {
      warnings.push(`呼び出しグラフのエッジ数が上限 ${MAX_EDGES_TOTAL} に達したため打ち切りました`);
      break;
    }

    let fileEdges = 0;
    try {
      const lines = source.masked.codeOnly;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (line.indexOf('(') < 0) continue;
        const lineNo = i + 1;
        const defined = definitionLines.get(`${source.path}:${lineNo}`);

        CALL_PATTERN.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = CALL_PATTERN.exec(line)) !== null) {
          const receiver = match[1];
          const name = match[2];
          if (!name || NOT_A_CALL.has(name)) continue;
          // 定義行のシグネチャ自体は呼び出しではない
          if (defined?.has(name)) continue;

          const from = locator.locate(source.path, lineNo);
          const { to, confidence } = resolve(name, source.path, Boolean(receiver), index);

          const key = `${from}->${to}@${source.path}:${lineNo}`;
          if (seen.has(key)) continue;
          seen.add(key);

          edges.push({ from, to, file: source.path, line: lineNo, confidence });
          fileEdges++;
          if (fileEdges >= MAX_EDGES_PER_FILE) break;
        }
        if (fileEdges >= MAX_EDGES_PER_FILE) {
          warnings.push(`呼び出しが多すぎるため途中で打ち切りました: ${source.path}`);
          break;
        }
      }
    } catch (err) {
      warnings.push(`呼び出しグラフの構築に失敗しました: ${source.path} (${String(err)})`);
    }
  }

  // 呼び出し先名には `toString` のような Object.prototype のキーが現れうるため、
  // 索引の構築には必ず Map を使う（プレーンオブジェクトだと継承プロパティを掴む）
  const calleeMap = new Map<string, Set<string>>();
  const callerMap = new Map<string, Set<string>>();
  for (const edge of edges) {
    const callee = calleeMap.get(edge.from) ?? new Set<string>();
    callee.add(edge.to);
    calleeMap.set(edge.from, callee);

    const caller = callerMap.get(edge.to) ?? new Set<string>();
    caller.add(edge.from);
    callerMap.set(edge.to, caller);
  }

  const callees: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  const callers: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  for (const [key, values] of calleeMap) callees[key] = [...values];
  for (const [key, values] of callerMap) callers[key] = [...values];

  return { edges, callees, callers };
}

/** ファイル直下（関数外）のコードを指す疑似シンボルID */
export function moduleSymbolId(file: string): string {
  return symbolId(file, MODULE_SYMBOL_NAME);
}
