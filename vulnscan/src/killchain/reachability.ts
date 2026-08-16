/**
 * 呼び出しグラフ上の到達可能性計算（純粋関数のみ）。
 *
 * LLM に総当たりの Finding 組み合わせを渡すのはコスト的に破綻するので、
 * 「そもそも攻撃者が触れる位置にあるか」をここで機械的に判定し、
 * 候補を絞り込む。到達可能性の根拠（呼び出しパス）はプロンプトにも載せる。
 */

import { SymbolLocator, symbolId } from '../context/symbols.js';
import type { CallGraph, EntryPoint, SymbolInfo, SymbolTable } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import { normalizeRepoRelPath } from '../util/path.js';

/**
 * パス表記のゆらぎ（'./a/b', 'a\\b', '//'）を吸収する。
 * 実体は `util/path.ts` の {@link normalizeRepoRelPath}（唯一の定義）。
 */
export function normalizePath(raw: string, repoRoot?: string): string {
  return normalizeRepoRelPath(raw, repoRoot);
}

/**
 * SymbolTable の索引キー `${file}:${name}` を組み立てる。
 *
 * この文字列は呼び出しグラフのノードID・`SymbolTable.byId`・
 * `EntryPoint.symbolId` を繋ぐ**唯一の結合規約**なので、
 * `context/symbols.ts` の定義をそのまま使う（自前で組み立てない）。
 */
export function symbolIdOf(symbol: Pick<SymbolInfo, 'file' | 'name'>): string {
  return symbolId(symbol.file, symbol.name);
}

/** 呼び出しグラフの隣接表 */
export interface Adjacency {
  /** シンボルID → 呼び出し先ID一覧 */
  readonly callees: ReadonlyMap<string, readonly string[]>;
  /** `${from} ${to}` → エッジ確信度 */
  readonly edgeConfidence: ReadonlyMap<string, number>;
}

/**
 * 隣接表を構築する。
 * `edges` があればそちらを使い `minEdgeConfidence` 未満のエッジを捨てる。
 * `edges` が空のグラフ（callees だけ埋めた簡易実装）では callees にフォールバックする。
 */
export function buildAdjacency(graph: CallGraph, minEdgeConfidence = 0): Adjacency {
  const callees = new Map<string, string[]>();
  const edgeConfidence = new Map<string, number>();

  const edges = graph?.edges ?? [];
  if (edges.length > 0) {
    for (const e of edges) {
      if (!e || typeof e.from !== 'string' || typeof e.to !== 'string') continue;
      const conf = typeof e.confidence === 'number' ? e.confidence : 1;
      if (conf < minEdgeConfidence) continue;
      const list = callees.get(e.from);
      if (list === undefined) callees.set(e.from, [e.to]);
      else if (!list.includes(e.to)) list.push(e.to);
      const key = `${e.from} ${e.to}`;
      const prev = edgeConfidence.get(key);
      // 同じ辺が複数回現れたら最も確信度の高いものを採用する
      if (prev === undefined || conf > prev) edgeConfidence.set(key, conf);
    }
    if (callees.size > 0) return { callees, edgeConfidence };
  }

  for (const [from, tos] of Object.entries(graph?.callees ?? {})) {
    if (!Array.isArray(tos)) continue;
    callees.set(from, [...new Set(tos)]);
    for (const to of tos) edgeConfidence.set(`${from} ${to}`, 1);
  }
  return { callees, edgeConfidence };
}

export interface BfsResult {
  /** 到達したノード → 起点からの深さ（起点自身は 0） */
  readonly depth: ReadonlyMap<string, number>;
  /** 到達したノード → 直前ノード（起点は未登録） */
  readonly prev: ReadonlyMap<string, string>;
}

/** 起点から幅優先探索する。最短パス（＝最小ホップ）が prev に記録される。 */
export function bfs(adj: Adjacency, start: string, maxDepth = 32): BfsResult {
  const depth = new Map<string, number>();
  const prev = new Map<string, string>();
  if (start === '') return { depth, prev };

  depth.set(start, 0);
  const queue: string[] = [start];
  let head = 0;

  while (head < queue.length) {
    const node = queue[head++];
    if (node === undefined) break;
    const d = depth.get(node) ?? 0;
    if (d >= maxDepth) continue;
    for (const next of adj.callees.get(node) ?? []) {
      if (depth.has(next)) continue;
      depth.set(next, d + 1);
      prev.set(next, node);
      queue.push(next);
    }
  }
  return { depth, prev };
}

/** BFS の結果から起点→対象の呼び出しパスを復元する。未到達なら空配列。 */
export function reconstructPath(result: BfsResult, start: string, target: string): string[] {
  if (!result.depth.has(target)) return [];
  const path: string[] = [target];
  let cur = target;
  // 起点に戻るまで遡る。prev は循環しないので上限はノード数。
  for (let i = 0; i < result.depth.size + 1 && cur !== start; i++) {
    const p = result.prev.get(cur);
    if (p === undefined) break;
    path.push(p);
    cur = p;
  }
  path.reverse();
  return path[0] === start ? path : [];
}

/** パス上で最も弱いエッジの確信度。パスが 1 ノード以下なら 1。 */
export function pathMinConfidence(adj: Adjacency, path: readonly string[]): number {
  if (path.length < 2) return 1;
  let min = 1;
  for (let i = 0; i + 1 < path.length; i++) {
    const from = path[i];
    const to = path[i + 1];
    if (from === undefined || to === undefined) continue;
    const c = adj.edgeConfidence.get(`${from} ${to}`) ?? 1;
    if (c < min) min = c;
  }
  return min;
}

/* ------------------------------------------------------------------ *
 * シンボル位置の解決
 *
 * 以前はここで全シンボルを線形走査していた。`grouping.ts` は Finding 1件につき
 * 3回呼ぶため O(3 × Finding数 × 全シンボル数) になり、S=6万・F=200 では
 * `normalizePath` だけで約9,600万回走っていた。
 *
 * さらに「同じ幅なら class より内側を優先」というタイブレーク規則が
 * `SymbolLocator.locate` にはあり再実装側には無かったため、`callgraph.ts` が
 * 組んだノードIDと killchain が解決するシンボルIDが食い違い、
 * 到達可能性が静かに false になりうる状態だった。
 *
 * そこで `context/symbols.ts` の {@link SymbolLocator} を唯一の判定器として使う。
 * repoRoot の剥がしだけは killchain 側の事情なので、
 * 正規化済みファイル名で張り直した索引を (SymbolTable, repoRoot) 単位で
 * キャッシュしてから locate に渡す。
 * ------------------------------------------------------------------ */

interface SymbolIndex {
  /** 正規化済みファイル名で構築した SymbolLocator */
  readonly locator: SymbolLocator;
  /** 正規化済みシンボルID → 元の SymbolInfo（呼び出しグラフのIDは元の file 表記のまま） */
  readonly original: ReadonlyMap<string, SymbolInfo>;
  /** 正規化済みファイル名 → そのファイルのシンボル一覧（近傍探索用） */
  readonly byFile: ReadonlyMap<string, SymbolInfo[]>;
}

/** SymbolTable は巨大なので、索引はテーブルの寿命に合わせて弱参照で持つ */
const indexCache = new WeakMap<SymbolTable, Map<string, SymbolIndex>>();

function buildIndex(table: SymbolTable, repoRoot: string | undefined): SymbolIndex {
  const symbols = table?.symbols ?? [];
  const normalized: SymbolInfo[] = [];
  const original = new Map<string, SymbolInfo>();
  const byFile = new Map<string, SymbolInfo[]>();

  for (const s of symbols) {
    const file = normalizeRepoRelPath(s.file, repoRoot);
    normalized.push(file === s.file ? s : { ...s, file });
    // 同名が複数あれば最初のものを採用する（線形走査版と同じく先着優先）
    const id = symbolId(file, s.name);
    if (!original.has(id)) original.set(id, s);
    const list = byFile.get(file);
    if (list) list.push(s);
    else byFile.set(file, [s]);
  }

  return {
    locator: new SymbolLocator({ symbols: normalized, byId: {} }),
    original,
    byFile,
  };
}

function symbolIndexOf(table: SymbolTable, repoRoot: string | undefined): SymbolIndex {
  const key = repoRoot ?? '';
  let byRoot = indexCache.get(table);
  if (byRoot === undefined) {
    byRoot = new Map();
    indexCache.set(table, byRoot);
  }
  let index = byRoot.get(key);
  if (index === undefined) {
    index = buildIndex(table, repoRoot);
    byRoot.set(key, index);
  }
  return index;
}

/**
 * file:line を含む最も内側のシンボルを返す。
 *
 * 判定規則は {@link SymbolLocator} に委ねる（狭い範囲＝内側、
 * 同じ幅なら class より内側の定義を優先）。該当が無ければ null。
 */
export function findEnclosingSymbol(
  table: SymbolTable,
  file: string,
  line: number,
  repoRoot?: string,
): SymbolInfo | null {
  const index = symbolIndexOf(table, repoRoot);
  const target = normalizeRepoRelPath(file, repoRoot);
  if (!index.byFile.has(target)) return null;
  // locate は該当なしのとき `${file}:<module>` を返す。
  // 実在する <module> シンボルならそれが最外周の囲みなので採用し、
  // 実在しなければ「囲むシンボル無し」として null にする。
  return index.original.get(index.locator.locate(target, line)) ?? null;
}

/** 行を含むシンボルが無い場合の近傍フォールバック（開始行が最も近いシンボル） */
export function findNearestSymbol(
  table: SymbolTable,
  file: string,
  line: number,
  repoRoot?: string,
): SymbolInfo | null {
  const index = symbolIndexOf(table, repoRoot);
  const list = index.byFile.get(normalizeRepoRelPath(file, repoRoot));
  if (list === undefined) return null;
  let best: SymbolInfo | null = null;
  let bestDelta = Number.POSITIVE_INFINITY;
  for (const s of list) {
    const delta = Math.abs(s.startLine - line);
    if (delta < bestDelta) {
      best = s;
      bestDelta = delta;
    }
  }
  return best;
}

/** エントリポイントに対応するシンボルIDを解決する */
export function resolveEntryPointSymbol(
  ep: EntryPoint,
  table: SymbolTable,
  repoRoot?: string,
): string | null {
  if (typeof ep.symbolId === 'string' && ep.symbolId !== '') return ep.symbolId;
  const sym =
    findEnclosingSymbol(table, ep.file, ep.line, repoRoot) ??
    findNearestSymbol(table, ep.file, ep.line, repoRoot);
  return sym === null ? null : symbolIdOf(sym);
}

/**
 * Finding の位置に対応するシンボルIDを解決する。
 * 開始行 → 終了行 → 近傍 の順で試す（依存脆弱性など位置が曖昧な Finding もあるため）。
 */
export function resolveFindingSymbol(
  finding: Pick<Finding, 'location'>,
  table: SymbolTable,
  repoRoot?: string,
): string | null {
  const loc = finding?.location;
  if (!loc || typeof loc.file !== 'string') return null;
  const sym =
    findEnclosingSymbol(table, loc.file, loc.startLine, repoRoot) ??
    findEnclosingSymbol(table, loc.file, loc.endLine, repoRoot) ??
    findNearestSymbol(table, loc.file, loc.startLine, repoRoot);
  return sym === null ? null : symbolIdOf(sym);
}

/** ある Finding がエントリポイントから到達可能かの根拠 */
export interface ReachabilityEvidence {
  findingId: string;
  /** 解決できたシンボルID。解決不能なら null */
  symbolId: string | null;
  reachable: boolean;
  /** エントリポイントから Finding までの呼び出しパス（シンボルID列） */
  path: string[];
  /** ホップ数。未到達なら -1 */
  depth: number;
  /** パス上の最弱エッジ確信度 */
  minEdgeConfidence: number;
  /** 呼び出しグラフでは繋がらないが同一ファイルにある（弱い根拠） */
  sameFileOnly: boolean;
}

/**
 * 1 エントリポイントから見た全 Finding の到達可能性をまとめて計算する。
 * `entrySymbolId` が null（シンボル解決できないエントリポイント）の場合は
 * 同一ファイル判定のみを行う。
 */
export function computeReachability(
  entrySymbolId: string | null,
  entryFile: string | null,
  findings: readonly Finding[],
  findingSymbols: ReadonlyMap<string, string | null>,
  adj: Adjacency,
  options: { maxDepth?: number; repoRoot?: string } = {},
): ReachabilityEvidence[] {
  const maxDepth = options.maxDepth ?? 32;
  const result = entrySymbolId === null ? null : bfs(adj, entrySymbolId, maxDepth);
  const normEntryFile = entryFile === null ? null : normalizePath(entryFile, options.repoRoot);

  return findings.map((f) => {
    const symbolId = findingSymbols.get(f.id) ?? null;
    const sameFile =
      normEntryFile !== null &&
      typeof f.location?.file === 'string' &&
      normalizePath(f.location.file, options.repoRoot) === normEntryFile;

    if (result === null || symbolId === null || !result.depth.has(symbolId)) {
      return {
        findingId: f.id,
        symbolId,
        reachable: false,
        path: [],
        depth: -1,
        minEdgeConfidence: 0,
        sameFileOnly: sameFile,
      };
    }

    const path =
      entrySymbolId === null ? [] : reconstructPath(result, entrySymbolId, symbolId);
    return {
      findingId: f.id,
      symbolId,
      reachable: true,
      path,
      depth: result.depth.get(symbolId) ?? 0,
      minEdgeConfidence: pathMinConfidence(adj, path),
      sameFileOnly: sameFile,
    };
  });
}
