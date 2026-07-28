/**
 * テスト用のフィクスチャ生成ヘルパー。
 * 本番コードからは参照しない（vitest 専用）。
 */

import type {
  CallGraph,
  EntryPoint,
  ScanContext,
  SymbolInfo,
  SymbolTable,
  TrustBoundary,
} from '../types/context.js';
import type { Cvss3Metrics, DataFlowStep, Finding, LensId, Severity } from '../types/finding.js';

export function makeSymbolTable(
  entries: readonly (Pick<SymbolInfo, 'name' | 'kind' | 'file' | 'startLine' | 'endLine'> &
    Partial<SymbolInfo>)[],
): SymbolTable {
  const symbols: SymbolInfo[] = entries.map((e) => ({
    exported: true,
    ...e,
  }));
  const byId: Record<string, SymbolInfo> = {};
  for (const s of symbols) byId[`${s.file}:${s.name}`] = s;
  return { symbols, byId };
}

export function makeCallGraph(edges: readonly [string, string, number?][]): CallGraph {
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

export interface FindingOverrides {
  id: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  cwe?: string;
  category?: string;
  severity?: Severity;
  baseScore?: number;
  confidence?: number;
  lens?: LensId;
  dataFlow?: DataFlowStep[];
  metrics?: Partial<Cvss3Metrics>;
  fixedVersion?: string;
  status?: Finding['status'];
  diffStatus?: Finding['diffStatus'];
}

const DEFAULT_METRICS: Cvss3Metrics = {
  AV: 'N',
  AC: 'L',
  PR: 'N',
  UI: 'N',
  S: 'U',
  C: 'H',
  I: 'H',
  A: 'H',
};

export function makeFinding(o: FindingOverrides): Finding {
  const baseScore = o.baseScore ?? 5.5;
  const metrics: Cvss3Metrics = { ...DEFAULT_METRICS, ...o.metrics };
  const finding: Finding = {
    id: o.id,
    fingerprint: `fp-${o.id}`,
    cwe: o.cwe ?? 'CWE-79',
    category: o.category ?? 'A03:2021-Injection',
    title: `テスト用 Finding ${o.id}`,
    severity: o.severity ?? 'medium',
    confidence: o.confidence ?? 0.8,
    location: {
      file: o.file ?? 'src/app.ts',
      startLine: o.startLine ?? 1,
      endLine: o.endLine ?? 2,
    },
    evidence: `const x = req.query.q; // ${o.id}`,
    dataFlow: o.dataFlow ?? [],
    reasoning: `${o.id} の理由`,
    remediation: `${o.id} の修正方針`,
    lens: o.lens ?? 'injection',
    cvss: {
      baseScore,
      baseSeverity: baseScore >= 9 ? 'Critical' : baseScore >= 7 ? 'High' : 'Medium',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      metrics,
      version: '3.1',
      breakdown: { impactSubScore: 5.9, exploitabilitySubScore: 3.9 },
    },
    status: o.status ?? 'open',
    diffStatus: o.diffStatus ?? 'new',
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    mergedFrom: [],
    references: [],
  };
  if (o.fixedVersion !== undefined) {
    finding.affectedPackage = {
      name: 'demo-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      fixedVersion: o.fixedVersion,
    };
  }
  return finding;
}

export function makeFlowStep(
  file: string,
  line: number,
  role: DataFlowStep['role'],
): DataFlowStep {
  return { file, line, code: `line ${line}`, role, description: `${role} at ${file}:${line}` };
}

export function makeContext(o: {
  symbols?: SymbolTable;
  callGraph?: CallGraph;
  entryPoints?: EntryPoint[];
  trustBoundaries?: TrustBoundary[];
  repoRoot?: string;
}): ScanContext {
  return {
    repoRoot: o.repoRoot ?? '/repo',
    scannedAt: '2026-01-01T00:00:00Z',
    languages: [{ name: 'typescript', fileCount: 10, ratio: 1 }],
    frameworks: [{ name: 'express', evidence: 'package.json' }],
    dependencies: [],
    files: [],
    symbols: o.symbols ?? makeSymbolTable([]),
    callGraph: o.callGraph ?? makeCallGraph([]),
    entryPoints: o.entryPoints ?? [],
    trustBoundaries: o.trustBoundaries ?? [],
    warnings: [],
  };
}
