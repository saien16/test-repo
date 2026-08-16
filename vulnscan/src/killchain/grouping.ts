/**
 * LLM に渡す前の候補絞り込み（純粋関数）。
 *
 * 方針:
 *   1. 各エントリポイントから呼び出しグラフを BFS し、到達可能な Finding を束ねる
 *   2. データフロー（source→sink の file:line）が繋がる Finding を Union-Find で束ねる
 *   3. 単独で致命的な Finding（認証不要 RCE など）は単独チェーン候補にする
 * これで N^2 の総当たりを避け、LLM 呼び出し回数を候補グループ数に抑える。
 */

import type { EntryPoint, ScanContext } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import {
  buildAdjacency,
  computeReachability,
  normalizePath,
  resolveEntryPointSymbol,
  resolveFindingSymbol,
  type Adjacency,
  type ReachabilityEvidence,
} from './reachability.js';

/** エントリポイント種別ごとの露出度（攻撃者がどれだけ触りやすいか） */
export const ENTRY_POINT_EXPOSURE: Record<EntryPoint['kind'], number> = {
  'http-route': 1.0,
  'message-handler': 0.8,
  'event-handler': 0.7,
  cli: 0.5,
  main: 0.45,
  export: 0.35,
};

/** エントリポイントを特定できなかったグループの露出度 */
export const UNKNOWN_EXPOSURE = 0.25;

export type CandidateGroupKind = 'entry-point' | 'data-flow' | 'standalone';

export interface CandidateGroup {
  id: string;
  kind: CandidateGroupKind;
  /** 表示用のエントリポイント識別子 */
  entryPointId: string;
  entryPoint: EntryPoint | null;
  findingIds: string[];
  /** findingId 順に対応する到達性根拠 */
  evidence: ReachabilityEvidence[];
  /** 0..1 の露出度 */
  exposure: number;
  /** 到達性が証明できた Finding の割合 0..1 */
  reachabilityRatio: number;
  /** LLM 呼び出し順・打ち切り判断に使う機械的なリスク見積り 0..1 */
  rank: number;
}

export interface GroupingOptions {
  /** LLM に投げるグループ数の上限 */
  maxGroups?: number;
  /** 1グループあたりの Finding 数上限（プロンプト肥大の抑制） */
  maxFindingsPerGroup?: number;
  /** この確信度未満の呼び出しエッジは辿らない */
  minEdgeConfidence?: number;
  /** BFS の最大ホップ数 */
  maxDepth?: number;
  /** これ以上の Finding が共有する file:line は「ハブ」とみなしデータフロー連結に使わない */
  maxSharedFlowKeyFanout?: number;
}

export const DEFAULT_GROUPING_OPTIONS: Required<GroupingOptions> = {
  maxGroups: 24,
  maxFindingsPerGroup: 8,
  minEdgeConfidence: 0.3,
  maxDepth: 24,
  maxSharedFlowKeyFanout: 5,
};

/**
 * 単独でも致命的な Finding か。
 * 「認証なし RCE」のように連鎖を待たずに終わる脆弱性は単独チェーンとして扱う。
 */
export function isStandaloneCritical(finding: Finding): boolean {
  const m = finding.cvss?.metrics;
  const score = finding.cvss?.baseScore ?? 0;
  if (score >= 9.0) return true;
  if (finding.severity !== 'critical') return false;
  if (!m) return false;
  // ネットワーク越し・権限不要・ユーザー操作不要
  return m.AV === 'N' && m.PR === 'N' && m.UI === 'N';
}

/** データフローの各ステップを `file:line` のキーに畳む */
export function dataFlowKeys(finding: Finding, repoRoot?: string): string[] {
  const steps = Array.isArray(finding.dataFlow) ? finding.dataFlow : [];
  const keys = new Set<string>();
  for (const s of steps) {
    if (!s || typeof s.file !== 'string') continue;
    keys.add(`${normalizePath(s.file, repoRoot)}:${s.line}`);
  }
  return [...keys];
}

/** 素朴な Union-Find */
class UnionFind {
  private readonly parent = new Map<string, string>();

  find(x: string): string {
    const p = this.parent.get(x);
    if (p === undefined) {
      this.parent.set(x, x);
      return x;
    }
    if (p === x) return x;
    const root = this.find(p);
    this.parent.set(x, root);
    return root;
  }

  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(ra, rb);
  }
}

/**
 * データフローが繋がる Finding をグルーピングする。
 * 同じ `file:line` を通過する Finding 同士、および同じシンボルに属する Finding 同士を連結する。
 * 多数の Finding が共有する「ハブ」的な位置は過剰連結を招くので除外する。
 */
export function groupByDataFlow(
  findings: readonly Finding[],
  findingSymbols: ReadonlyMap<string, string | null>,
  options: { repoRoot?: string; maxSharedFlowKeyFanout?: number } = {},
): string[][] {
  const fanoutLimit =
    options.maxSharedFlowKeyFanout ?? DEFAULT_GROUPING_OPTIONS.maxSharedFlowKeyFanout;

  const byKey = new Map<string, string[]>();
  const push = (key: string, id: string): void => {
    const list = byKey.get(key);
    if (list === undefined) byKey.set(key, [id]);
    else if (!list.includes(id)) list.push(id);
  };

  for (const f of findings) {
    for (const k of dataFlowKeys(f, options.repoRoot)) push(`flow:${k}`, f.id);
    const sym = findingSymbols.get(f.id);
    if (sym !== undefined && sym !== null) push(`sym:${sym}`, f.id);
  }

  const uf = new UnionFind();
  for (const f of findings) uf.find(f.id);
  for (const ids of byKey.values()) {
    if (ids.length < 2 || ids.length > fanoutLimit) continue;
    const head = ids[0];
    if (head === undefined) continue;
    for (let i = 1; i < ids.length; i++) {
      const other = ids[i];
      if (other !== undefined) uf.union(head, other);
    }
  }

  const components = new Map<string, string[]>();
  for (const f of findings) {
    const root = uf.find(f.id);
    const list = components.get(root);
    if (list === undefined) components.set(root, [f.id]);
    else list.push(f.id);
  }

  return [...components.values()].filter((ids) => ids.length >= 2);
}

function exposureOf(ep: EntryPoint | null, avgDepth: number): number {
  const base = ep === null ? UNKNOWN_EXPOSURE : (ENTRY_POINT_EXPOSURE[ep.kind] ?? UNKNOWN_EXPOSURE);
  // 深いところにある Finding は入口から遠く、前提条件が増えるため露出度を落とす
  const decayed = base * Math.pow(0.97, Math.max(0, avgDepth));
  return Math.max(0.1, Math.min(1, decayed));
}

function rankOf(group: {
  findings: readonly Finding[];
  exposure: number;
  reachabilityRatio: number;
}): number {
  let maxCvss = 0;
  for (const f of group.findings) maxCvss = Math.max(maxCvss, f.cvss?.baseScore ?? 0);
  const size = Math.min(group.findings.length, 5) / 5;
  return (
    0.45 * (maxCvss / 10) + 0.25 * group.exposure + 0.2 * size + 0.1 * group.reachabilityRatio
  );
}

function makeGroup(
  kind: CandidateGroupKind,
  entryPoint: EntryPoint | null,
  members: readonly Finding[],
  evidence: readonly ReachabilityEvidence[],
  maxFindingsPerGroup: number,
): CandidateGroup | null {
  if (members.length === 0) return null;

  const evidenceById = new Map(evidence.map((e) => [e.findingId, e]));
  // 上流（浅い）かつ深刻なものを優先して残す
  const ordered = [...members].sort((a, b) => {
    const da = evidenceById.get(a.id)?.depth ?? Number.MAX_SAFE_INTEGER;
    const db = evidenceById.get(b.id)?.depth ?? Number.MAX_SAFE_INTEGER;
    const na = da < 0 ? Number.MAX_SAFE_INTEGER : da;
    const nb = db < 0 ? Number.MAX_SAFE_INTEGER : db;
    if (na !== nb) return na - nb;
    return (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0);
  });
  const kept = ordered.slice(0, Math.max(1, maxFindingsPerGroup));

  const keptEvidence = kept.map(
    (f) =>
      evidenceById.get(f.id) ?? {
        findingId: f.id,
        symbolId: null,
        reachable: false,
        path: [],
        depth: -1,
        minEdgeConfidence: 0,
        sameFileOnly: false,
      },
  );

  const reachableDepths = keptEvidence.filter((e) => e.reachable).map((e) => e.depth);
  const avgDepth =
    reachableDepths.length === 0
      ? 4
      : reachableDepths.reduce((a, b) => a + b, 0) / reachableDepths.length;
  const reachabilityRatio = keptEvidence.filter((e) => e.reachable).length / keptEvidence.length;
  const exposure = exposureOf(entryPoint, avgDepth);

  const findingIds = kept.map((f) => f.id);
  const entryPointId = entryPoint === null ? '(エントリポイント未特定)' : entryPoint.identifier;

  return {
    id: `${kind}:${entryPointId}:${[...findingIds].sort().join(',')}`,
    kind,
    entryPointId,
    entryPoint,
    findingIds,
    evidence: keptEvidence,
    exposure,
    reachabilityRatio,
    rank: rankOf({ findings: kept, exposure, reachabilityRatio }),
  };
}

/**
 * 候補グループを構築する（この機能の前処理の中核。純粋関数）。
 */
export function buildCandidateGroups(
  findings: readonly Finding[],
  ctx: ScanContext,
  options: GroupingOptions = {},
): CandidateGroup[] {
  const opt = { ...DEFAULT_GROUPING_OPTIONS, ...options };
  if (findings.length === 0) return [];

  const repoRoot = ctx?.repoRoot;
  const symbols = ctx?.symbols ?? { symbols: [], byId: {} };
  const adj: Adjacency = buildAdjacency(
    ctx?.callGraph ?? { edges: [], callees: {}, callers: {} },
    opt.minEdgeConfidence,
  );

  const findingSymbols = new Map<string, string | null>();
  for (const f of findings) {
    findingSymbols.set(f.id, resolveFindingSymbol(f, symbols, repoRoot));
  }
  const byId = new Map(findings.map((f) => [f.id, f]));

  const groups: CandidateGroup[] = [];
  /** findingId → その Finding に最も露出度の高いエントリポイント */
  const bestEntry = new Map<string, { ep: EntryPoint; evidence: ReachabilityEvidence }>();

  // --- 1. エントリポイント起点のグループ ---
  for (const ep of ctx?.entryPoints ?? []) {
    const entrySymbol = resolveEntryPointSymbol(ep, symbols, repoRoot);
    const evidence = computeReachability(entrySymbol, ep.file, findings, findingSymbols, adj, {
      maxDepth: opt.maxDepth,
      repoRoot,
    });

    const members: Finding[] = [];
    const memberEvidence: ReachabilityEvidence[] = [];
    for (const e of evidence) {
      // 呼び出しグラフで到達可能、もしくは（グラフが不完全な場合の保険として）同一ファイル
      if (!e.reachable && !e.sameFileOnly) continue;
      const f = byId.get(e.findingId);
      if (f === undefined) continue;
      members.push(f);
      memberEvidence.push(e);

      const prev = bestEntry.get(e.findingId);
      const prevExposure = prev === undefined ? -1 : (ENTRY_POINT_EXPOSURE[prev.ep.kind] ?? 0);
      if ((ENTRY_POINT_EXPOSURE[ep.kind] ?? 0) > prevExposure) {
        bestEntry.set(e.findingId, { ep, evidence: e });
      }
    }

    if (members.length >= 2) {
      const g = makeGroup('entry-point', ep, members, memberEvidence, opt.maxFindingsPerGroup);
      if (g !== null) groups.push(g);
    }
  }

  // --- 2. データフローで繋がるグループ ---
  for (const component of groupByDataFlow(findings, findingSymbols, {
    repoRoot,
    maxSharedFlowKeyFanout: opt.maxSharedFlowKeyFanout,
  })) {
    const members = component
      .map((id) => byId.get(id))
      .filter((f): f is Finding => f !== undefined);
    if (members.length < 2) continue;

    // 構成メンバに最も強く届くエントリポイントを代表にする
    let ep: EntryPoint | null = null;
    let epExposure = -1;
    for (const f of members) {
      const cand = bestEntry.get(f.id);
      if (cand === undefined) continue;
      const e = ENTRY_POINT_EXPOSURE[cand.ep.kind] ?? 0;
      if (e > epExposure) {
        ep = cand.ep;
        epExposure = e;
      }
    }

    const evidence: ReachabilityEvidence[] = members.map(
      (f) =>
        bestEntry.get(f.id)?.evidence ?? {
          findingId: f.id,
          symbolId: findingSymbols.get(f.id) ?? null,
          reachable: false,
          path: [],
          depth: -1,
          minEdgeConfidence: 0,
          sameFileOnly: false,
        },
    );

    const g = makeGroup('data-flow', ep, members, evidence, opt.maxFindingsPerGroup);
    if (g === null) continue;
    if (groups.some((existing) => sameMembers(existing, g))) continue;
    groups.push(g);
  }

  // --- 3. 単独で致命的な Finding ---
  for (const f of findings) {
    if (!isStandaloneCritical(f)) continue;
    if (groups.some((g) => g.findingIds.length === 1 && g.findingIds[0] === f.id)) continue;
    const cand = bestEntry.get(f.id);
    const evidence: ReachabilityEvidence[] = [
      cand?.evidence ?? {
        findingId: f.id,
        symbolId: findingSymbols.get(f.id) ?? null,
        reachable: false,
        path: [],
        depth: -1,
        minEdgeConfidence: 0,
        sameFileOnly: false,
      },
    ];
    const g = makeGroup('standalone', cand?.ep ?? null, [f], evidence, opt.maxFindingsPerGroup);
    if (g !== null) groups.push(g);
  }

  // --- 重複排除 + ランク順で打ち切り ---
  const deduped: CandidateGroup[] = [];
  const seen = new Set<string>();
  for (const g of groups.sort((a, b) => b.rank - a.rank)) {
    const key = `${g.kind}|${[...g.findingIds].sort().join(',')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(g);
  }

  return deduped.slice(0, Math.max(0, opt.maxGroups));
}

function sameMembers(a: CandidateGroup, b: CandidateGroup): boolean {
  if (a.findingIds.length !== b.findingIds.length) return false;
  const sa = [...a.findingIds].sort().join(',');
  const sb = [...b.findingIds].sort().join(',');
  return sa === sb;
}
