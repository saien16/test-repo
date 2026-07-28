/**
 * 文脈の付与（retrieval）。
 *
 * チャンク単体のコードだけでは到達可能性もサニタイズの有無も判断できない。
 * ここで ScanContext から以下を引いてチャンクに添付する:
 *   - 呼び出しグラフ上の呼び出し元 / 呼び出し先のシグネチャ
 *   - そのチャンク（および呼び出し先）に関係する信頼境界 source/sink
 *   - エントリポイントからの到達可能性
 *   - フレームワーク一覧（そのフレームワーク特有の防御機構を考慮させる）
 *
 * 検出精度はここで決まるので、量より「判断に効く情報」を優先して詰める。
 */

import type {
  EntryPoint,
  FrameworkInfo,
  ScanContext,
  SymbolInfo,
  TrustBoundary,
} from '../types/context.js';
import type { Chunk, RelatedSymbol } from './types.js';

/** 呼び出しグラフで使われるシンボルID */
export function symbolId(file: string, name: string): string {
  return `${file}:${name}`;
}

export interface ContextBuildOptions {
  /** 呼び出し元・呼び出し先それぞれの最大件数 */
  maxRelated?: number;
  /** 添付する信頼境界の最大件数 */
  maxBoundaries?: number;
  /** 添付するエントリポイントの最大件数 */
  maxEntryPoints?: number;
  /** 到達可能性を辿る最大深さ */
  maxReachDepth?: number;
  /** 宣言行のテキストを引く（あればシグネチャに添える） */
  declarationOf?: (symbol: SymbolInfo) => string | undefined;
}

const DEFAULTS = {
  maxRelated: 12,
  maxBoundaries: 24,
  maxEntryPoints: 8,
  maxReachDepth: 6,
} as const;

export interface Reachability {
  /** エントリポイントから到達しうるか */
  reachable: boolean;
  /** 到達経路（チャンク側 → エントリポイント側）。未到達なら空 */
  path: string[];
  /** 到達の根拠となったエントリポイント */
  entryPoint: EntryPoint | null;
}

export interface ChunkContext {
  chunk: Chunk;
  frameworks: FrameworkInfo[];
  /** このチャンク自身がエントリポイントである場合の一覧 */
  ownEntryPoints: EntryPoint[];
  callers: RelatedSymbol[];
  callees: RelatedSymbol[];
  /** チャンク内に直接ある信頼境界 */
  directBoundaries: TrustBoundary[];
  /** 呼び出し先など、間接的に関係する信頼境界 */
  relatedBoundaries: TrustBoundary[];
  reachability: Reachability;
  /** プロンプトに埋め込む整形済みテキスト */
  text: string;
}

/** チャンクに含まれるシンボルのID一覧 */
export function chunkSymbolIds(chunk: Chunk): string[] {
  return chunk.symbols.map((s) => symbolId(s.file, s.name));
}

function inChunkRange(chunk: Chunk, file: string, line: number): boolean {
  if (file !== chunk.file) return false;
  return chunk.segments.some((seg) => line >= seg.startLine && line <= seg.endLine);
}

function describeSymbol(
  sym: SymbolInfo,
  declarationOf?: ContextBuildOptions['declarationOf'],
): string {
  const owner = sym.container ? `${sym.container}.` : '';
  const exported = sym.exported ? 'export ' : '';
  const decl = declarationOf?.(sym)?.trim();
  const head = `${exported}${sym.kind} ${owner}${sym.name} (${sym.file}:${sym.startLine}-${sym.endLine})`;
  return decl ? `${head}\n      宣言: ${decl}` : head;
}

function collectRelated(
  ids: string[],
  direction: 'caller' | 'callee',
  ctx: ScanContext,
  opts: Required<Pick<ContextBuildOptions, 'maxRelated'>> & ContextBuildOptions,
): RelatedSymbol[] {
  const table = direction === 'caller' ? ctx.callGraph.callers : ctx.callGraph.callees;
  const own = new Set(ids);
  const seen = new Set<string>();
  const out: RelatedSymbol[] = [];

  for (const id of ids) {
    for (const relatedId of table[id] ?? []) {
      if (own.has(relatedId) || seen.has(relatedId)) continue;
      seen.add(relatedId);

      const sym = ctx.symbols.byId[relatedId];
      // 呼び出しが書かれている位置（辺）を1つ添える。行が判るとLLMが検証しやすい
      const edge = ctx.callGraph.edges.find((e) =>
        direction === 'caller' ? e.from === relatedId && e.to === id : e.from === id && e.to === relatedId,
      );

      const related: RelatedSymbol = {
        id: relatedId,
        direction,
        signature: sym
          ? describeSymbol(sym, opts.declarationOf)
          : `${relatedId}（シンボル未解決）`,
        resolved: sym !== undefined,
      };
      if (edge) related.via = { file: edge.file, line: edge.line };
      out.push(related);

      if (out.length >= opts.maxRelated) return out;
    }
  }
  return out;
}

/**
 * 呼び出し元を遡ってエントリポイントに到達できるか調べる（幅優先・深さ制限つき）。
 * ヒューリスティックな呼び出しグラフなので「到達しうる」以上の意味は持たせない。
 */
export function findReachability(
  ids: string[],
  ctx: ScanContext,
  maxDepth = DEFAULTS.maxReachDepth,
): Reachability {
  const entryById = new Map<string, EntryPoint>();
  for (const ep of ctx.entryPoints) {
    if (ep.symbolId) entryById.set(ep.symbolId, ep);
  }

  const visited = new Set<string>(ids);
  let frontier: { id: string; path: string[] }[] = ids.map((id) => ({ id, path: [id] }));

  for (let depth = 0; depth <= maxDepth && frontier.length > 0; depth++) {
    for (const node of frontier) {
      const ep = entryById.get(node.id);
      if (ep) return { reachable: true, path: node.path, entryPoint: ep };
    }
    const next: { id: string; path: string[] }[] = [];
    for (const node of frontier) {
      for (const callerId of ctx.callGraph.callers[node.id] ?? []) {
        if (visited.has(callerId)) continue;
        visited.add(callerId);
        next.push({ id: callerId, path: [...node.path, callerId] });
      }
    }
    frontier = next;
  }

  return { reachable: false, path: [], entryPoint: null };
}

function formatBoundary(b: TrustBoundary): string {
  const kind = b.type === 'source' ? '汚染源(source)' : '危険な出力先(sink)';
  return `${kind} [${b.category}] ${b.file}:${b.line} — ${b.expression}`;
}

function formatEntryPoint(ep: EntryPoint): string {
  const meta = ep.metadata
    ? Object.entries(ep.metadata)
        .map(([k, v]) => `${k}=${v}`)
        .join(' ')
    : '';
  return `[${ep.kind}] ${ep.identifier} (${ep.file}:${ep.line})${meta ? ` ${meta}` : ''}`;
}

function formatRelated(r: RelatedSymbol): string {
  const via = r.via ? `  ← 呼び出し位置 ${r.via.file}:${r.via.line}` : '';
  return `  - ${r.signature}${via}`;
}

function section(title: string, body: string[]): string {
  if (body.length === 0) return `## ${title}\n  （該当なし）`;
  return `## ${title}\n${body.join('\n')}`;
}

/** チャンクに添付する文脈を組み立てる */
export function buildChunkContext(
  ctx: ScanContext,
  chunk: Chunk,
  opts: ContextBuildOptions = {},
): ChunkContext {
  const maxRelated = opts.maxRelated ?? DEFAULTS.maxRelated;
  const maxBoundaries = opts.maxBoundaries ?? DEFAULTS.maxBoundaries;
  const maxEntryPoints = opts.maxEntryPoints ?? DEFAULTS.maxEntryPoints;
  const maxReachDepth = opts.maxReachDepth ?? DEFAULTS.maxReachDepth;

  const ids = chunkSymbolIds(chunk);
  const idSet = new Set(ids);

  const callers = collectRelated(ids, 'caller', ctx, { ...opts, maxRelated });
  const callees = collectRelated(ids, 'callee', ctx, { ...opts, maxRelated });
  const calleeIds = new Set(callees.map((c) => c.id));

  const ownEntryPoints = ctx.entryPoints
    .filter(
      (ep) =>
        (ep.symbolId !== undefined && idSet.has(ep.symbolId)) ||
        inChunkRange(chunk, ep.file, ep.line),
    )
    .slice(0, maxEntryPoints);

  const directBoundaries: TrustBoundary[] = [];
  const relatedBoundaries: TrustBoundary[] = [];
  for (const b of ctx.trustBoundaries) {
    const isDirect =
      inChunkRange(chunk, b.file, b.line) ||
      (b.symbolId !== undefined && idSet.has(b.symbolId));
    if (isDirect) {
      if (directBoundaries.length < maxBoundaries) directBoundaries.push(b);
      continue;
    }
    if (b.symbolId !== undefined && calleeIds.has(b.symbolId)) {
      if (relatedBoundaries.length < maxBoundaries) relatedBoundaries.push(b);
    }
  }

  const reachability =
    ownEntryPoints.length > 0
      ? {
          reachable: true,
          path: ids.slice(0, 1),
          entryPoint: ownEntryPoints[0] ?? null,
        }
      : findReachability(ids, ctx, maxReachDepth);

  const frameworks = ctx.frameworks;

  const reachLines: string[] = [];
  if (reachability.reachable && reachability.entryPoint) {
    reachLines.push(`  到達しうる: ${formatEntryPoint(reachability.entryPoint)}`);
    if (reachability.path.length > 1) {
      reachLines.push(`  経路(内→外): ${reachability.path.join(' ← ')}`);
    }
  } else if (ids.length === 0) {
    reachLines.push('  シンボル情報が無いため未判定');
  } else {
    reachLines.push(
      '  呼び出しグラフ上ではエントリポイントに繋がらなかった（グラフはヒューリスティックなので、外部から呼ばれる可能性は残る）',
    );
  }

  const text = [
    `# 解析対象チャンク`,
    `  ファイル: ${chunk.file} (${chunk.language})`,
    `  範囲: ${chunk.startLine}-${chunk.endLine} 行 / 種別: ${chunk.kind} / 名前: ${chunk.label}`,
    chunk.part && chunk.part.total > 1
      ? `  分割: ${chunk.part.index}/${chunk.part.total}（前後に続きがある）`
      : null,
    '',
    section(
      '検出済みフレームワーク',
      frameworks.map((f) => `  - ${f.name}${f.version ? `@${f.version}` : ''}（根拠: ${f.evidence}）`),
    ),
    '',
    section(
      'このチャンク自身のエントリポイント',
      ownEntryPoints.map((ep) => `  - ${formatEntryPoint(ep)}`),
    ),
    '',
    section('エントリポイントからの到達可能性', reachLines),
    '',
    section('呼び出し元', callers.map(formatRelated)),
    '',
    section('呼び出し先', callees.map(formatRelated)),
    '',
    section(
      'このチャンク内の信頼境界',
      directBoundaries.map((b) => `  - ${formatBoundary(b)}`),
    ),
    '',
    section(
      '呼び出し先にある信頼境界',
      relatedBoundaries.map((b) => `  - ${formatBoundary(b)}`),
    ),
  ]
    .filter((line): line is string => line !== null)
    .join('\n');

  return {
    chunk,
    frameworks,
    ownEntryPoints,
    callers,
    callees,
    directBoundaries,
    relatedBoundaries,
    reachability,
    text,
  };
}
