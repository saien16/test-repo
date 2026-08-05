/**
 * ヒートマップのテスト用フィクスチャ。
 * 本番コードからは参照しない（vitest 専用）。
 */

import type {
  ArchitectureComponent,
  ArchitectureModel,
  ComponentDataFlow,
  ComponentKind,
  DataSensitivity,
  DeploymentStack,
  Exposure,
} from '../types/architecture.js';
import type { Claim } from '../types/evidence.js';
import { assumed, inferred, observed } from '../types/evidence.js';
import { DEFAULT_CONFIG, type VulnScanConfig } from '../types/config.js';
import type { EntryPoint, ScanContext, SourceFile } from '../types/context.js';
import type { AttackChain, ChainStep } from '../types/killchain.js';

/** 事実の Claim */
export function fact<T>(value: T, file = 'package.json'): Claim<T> {
  return observed(value, [{ file }]);
}

/** 推測の Claim */
export function guess<T>(value: T, confidence: number, reasoning = 'テスト用の推測'): Claim<T> {
  return inferred(value, { confidence, inferredBy: 'heuristic', reasoning });
}

/** 仮定の Claim */
export function assume<T>(value: T, reasoning = 'テスト用の仮定'): Claim<T> {
  return assumed(value, reasoning);
}

export interface ComponentOverrides {
  id: string;
  kind?: ComponentKind;
  name?: string;
  technology?: Claim<string>;
  exposure?: Claim<Exposure>;
  dataSensitivity?: Claim<DataSensitivity[]>;
  requiresAuthentication?: Claim<boolean>;
  sourcePaths?: string[];
  entryPointIds?: string[];
}

export function makeComponent(o: ComponentOverrides): ArchitectureComponent {
  return {
    id: o.id,
    kind: o.kind ?? 'api-service',
    name: o.name ?? `構成要素 ${o.id}`,
    technology: o.technology ?? fact('Express on Node.js 20'),
    exposure: o.exposure ?? fact<Exposure>('public-internet'),
    dataSensitivity: o.dataSensitivity ?? fact<DataSensitivity[]>(['credentials']),
    requiresAuthentication: o.requiresAuthentication ?? fact(false),
    sourcePaths: o.sourcePaths ?? [`src/${o.id}`],
    entryPointIds: o.entryPointIds ?? [],
  };
}

const DEFAULT_DEPLOYMENT: DeploymentStack = {
  runtime: observed('Node.js 20', [{ file: 'package.json' }]),
  containerization: observed('docker', [{ file: 'Dockerfile' }]),
  platform: inferred('aws-ecs', {
    confidence: 0.6,
    inferredBy: 'heuristic',
    reasoning: 'task-definition.json があるため',
  }),
  cloudProvider: inferred('aws', {
    confidence: 0.6,
    inferredBy: 'heuristic',
    reasoning: 'AWS SDK 依存があるため',
  }),
  cicd: observed('github-actions', [{ file: '.github/workflows/ci.yml' }]),
  ingress: assumed('unknown', '判定材料なし'),
  secretsManagement: assumed('unknown', '判定材料なし'),
  iac: assumed('none', '判定材料なし'),
};

export interface ArchitectureOverrides {
  components: ArchitectureComponent[];
  dataFlows?: ComponentDataFlow[];
  evidence?: ArchitectureModel['evidence'];
}

export function makeArchitecture(o: ArchitectureOverrides): ArchitectureModel {
  return {
    style: observed('microservices', [{ file: 'docker-compose.yml' }]),
    components: o.components,
    dataFlows: o.dataFlows ?? [],
    deployment: DEFAULT_DEPLOYMENT,
    evidence: o.evidence ?? {
      observed: 6,
      inferred: 2,
      assumed: 2,
      meanInferredConfidence: 0.6,
    },
    inspectedManifests: ['package.json'],
    gaps: [],
  };
}

export function makeDataFlow(
  fromId: string,
  toId: string,
  protocol: Claim<string>,
): ComponentDataFlow {
  return {
    fromId,
    toId,
    protocol,
    crossesTrustBoundary: observed(true, [{ file: 'src/db.ts' }]),
  };
}

export function makeFile(path: string, language = 'typescript'): SourceFile {
  return { path, language, sizeBytes: 1024, lines: 32, hash: `hash-${path}` };
}

export interface ContextOverrides {
  files?: SourceFile[];
  entryPoints?: EntryPoint[];
  languages?: { name: string; fileCount: number; ratio: number }[];
  frameworks?: { name: string; evidence: string }[];
}

export function makeCtx(o: ContextOverrides = {}): ScanContext {
  return {
    repoRoot: '/repo',
    scannedAt: '2026-01-01T00:00:00Z',
    readme: null,
    languages: o.languages ?? [{ name: 'typescript', fileCount: 10, ratio: 1 }],
    frameworks: o.frameworks ?? [{ name: 'express', evidence: 'package.json' }],
    dependencies: [],
    files: o.files ?? [],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: o.entryPoints ?? [],
    trustBoundaries: [],
    warnings: [],
  };
}

export function makeConfig(o: Partial<VulnScanConfig> = {}): VulnScanConfig {
  return {
    ...DEFAULT_CONFIG,
    ...o,
    llm: { ...DEFAULT_CONFIG.llm, ...(o.llm ?? {}) },
    scan: { ...DEFAULT_CONFIG.scan, ...(o.scan ?? {}) },
  };
}

export function makeEntryPoint(identifier: string, file: string): EntryPoint {
  return { kind: 'http-route', identifier, file, line: 1 };
}

export function makeChain(id: string, findingIds: (string | null)[]): AttackChain {
  const steps: ChainStep[] = findingIds.map((findingId, index) => ({
    order: index + 1,
    findingId,
    killChainPhase: 'exploitation',
    attackTactic: 'initial-access',
    description: `ステップ${index + 1}`,
    preconditions: [],
  }));
  return {
    id,
    title: `テスト用チェーン ${id}`,
    entryPoint: 'GET /',
    steps,
    impact: 'テスト',
    likelihood: 'medium',
    priorityScore: 50,
    chokePoint: null,
    reasoning: 'テスト',
  };
}
