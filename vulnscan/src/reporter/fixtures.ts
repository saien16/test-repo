/**
 * レポーターのテスト用フィクスチャ生成。
 *
 * 型が大きいため、テストごとに全フィールドを書くと本質が埋もれる。
 * ここでは「妥当な既定値 + 部分上書き」でオブジェクトを作れるようにする。
 */

import type { ArchitectureModel } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import { assumed, inferred, observed } from '../types/evidence.js';
import type { Cvss3Result, Finding } from '../types/finding.js';
import type { VulnerabilityHeatmap } from '../types/heatmap.js';
import type { AttackChain } from '../types/killchain.js';
import type { ScanResult } from '../types/report.js';
import {
  assessAnalysisHealth,
  emptyAnalysisStats,
  type AnalysisStats,
} from '../types/health.js';
import { summarize } from './summarize.js';

export function makeCvss(overrides: Partial<Cvss3Result> = {}): Cvss3Result {
  return {
    baseScore: 9.8,
    baseSeverity: 'Critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
    version: '3.1',
    breakdown: { impactSubScore: 5.9, exploitabilitySubScore: 3.9 },
    ...overrides,
  };
}

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const id = overrides.id ?? 'f-1';
  return {
    id,
    fingerprint: `fp-${id}`,
    cwe: 'CWE-89',
    category: 'A03:2021-Injection',
    title: 'SQLクエリへのユーザー入力の直接連結',
    severity: 'critical',
    confidence: 0.9,
    location: { file: 'src/api/users.ts', startLine: 42, endLine: 47 },
    evidence: "const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    dataFlow: [
      {
        file: 'src/api/users.ts',
        line: 40,
        code: 'const id = req.params.id;',
        role: 'source',
        description: 'HTTPリクエストパラメータから未検証の値を取得',
      },
      {
        file: 'src/api/users.ts',
        line: 42,
        code: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
        role: 'sink',
        description: 'SQL文字列へそのまま埋め込まれる',
      },
    ],
    reasoning: 'ユーザー制御可能な値がエスケープなしでSQLへ連結されており、任意のクエリを実行できる。',
    remediation: 'プレースホルダを用いたパラメータ化クエリに書き換える。',
    lens: 'injection',
    cvss: makeCvss(),
    status: 'open',
    diffStatus: 'new',
    firstSeen: '2026-07-01T00:00:00.000Z',
    lastSeen: '2026-07-28T00:00:00.000Z',
    mergedFrom: [],
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
    ...overrides,
  };
}

export function makeChain(overrides: Partial<AttackChain> = {}): AttackChain {
  return {
    id: 'ch-1',
    title: 'SQLインジェクション経由で認証情報を奪取し横展開',
    entryPoint: 'GET /api/users/:id',
    steps: [
      {
        order: 1,
        findingId: 'f-1',
        killChainPhase: 'exploitation',
        attackTactic: 'initial-access',
        attackTechnique: 'T1190',
        description: '公開APIのSQLインジェクションで任意クエリを実行する',
        preconditions: ['APIが認証なしで到達可能であること'],
      },
      {
        order: 2,
        findingId: 'f-2',
        killChainPhase: 'actions-on-objectives',
        attackTactic: 'credential-access',
        description: 'ハードコードされた鍵でセッショントークンを偽造する',
        preconditions: ['鍵がリポジトリに含まれていること'],
      },
    ],
    impact: '全ユーザーの個人情報の閲覧と管理者権限の奪取',
    likelihood: 'high',
    priorityScore: 92,
    chokePoint: { findingId: 'f-1', rationale: '入口を塞げば後段のステップは成立しない' },
    reasoning: 'エントリポイントから sink までのデータフローが確認できているため成立性が高い。',
    ...overrides,
  };
}

export function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot: '/home/user/app',
    scannedAt: '2026-07-28T09:00:00.000Z',
    readme: null,
    languages: [{ name: 'typescript', fileCount: 120, ratio: 0.9 }],
    frameworks: [{ name: 'express', evidence: 'package.json', version: '4.19.2' }],
    dependencies: [
      { name: 'express', version: '4.19.2', ecosystem: 'npm', dev: false, manifest: 'package.json' },
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm', dev: false, manifest: 'package.json' },
    ],
    files: [
      { path: 'src/api/users.ts', language: 'typescript', sizeBytes: 2048, lines: 64, hash: 'aaa' },
      { path: 'src/auth/token.ts', language: 'typescript', sizeBytes: 1024, lines: 32, hash: 'bbb' },
    ],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [
      {
        kind: 'http-route',
        identifier: 'GET /api/users/:id',
        file: 'src/api/users.ts',
        line: 30,
      },
    ],
    trustBoundaries: [],
    git: { branch: 'main', headSha: 'abcdef1234567890', changedFiles: ['src/api/users.ts'] },
    warnings: [],
    ...overrides,
  };
}

/**
 * アーキテクチャ推定のフィクスチャ。
 * 公開/内部/ローカルの3層と、信頼境界をまたぐフローを含む最小構成。
 */
export function makeArchitecture(overrides: Partial<ArchitectureModel> = {}): ArchitectureModel {
  return {
    style: inferred('spa-with-api', {
      confidence: 0.7,
      inferredBy: 'heuristic',
      reasoning: 'フロントエンドのビルド設定と Express のルータ定義が同居しているため。',
      alternatives: ['monolith'],
    }),
    components: [
      {
        id: 'web',
        kind: 'web-frontend',
        name: 'Web フロントエンド',
        technology: observed('React 18', [{ file: 'package.json', line: 12 }]),
        exposure: inferred('public-internet', {
          confidence: 0.8,
          inferredBy: 'heuristic',
          reasoning: 'CDN 配信の設定があるため公開されていると判断。',
        }),
        dataSensitivity: assumed(['none'], '扱うデータの判別材料がない'),
        requiresAuthentication: assumed(false, '既定値'),
        sourcePaths: ['web/'],
        entryPointIds: [],
      },
      {
        id: 'api',
        kind: 'api-service',
        name: 'API サーバ (Express)',
        technology: observed('Express 4.19.2', [{ file: 'package.json', line: 20 }]),
        exposure: observed('public-internet', [{ file: 'Dockerfile', line: 8 }]),
        dataSensitivity: inferred(['pii'], {
          confidence: 0.6,
          inferredBy: 'llm',
          reasoning: 'users テーブルを直接参照しているため。',
        }),
        requiresAuthentication: inferred(true, {
          confidence: 0.5,
          inferredBy: 'heuristic',
          reasoning: '認証ミドルウェアの登録があるため。',
        }),
        sourcePaths: ['src/api/'],
        entryPointIds: ['GET /api/users/:id'],
      },
      {
        id: 'db',
        kind: 'database',
        name: 'PostgreSQL',
        technology: observed('PostgreSQL 15', [{ file: 'docker-compose.yml', line: 14 }]),
        exposure: inferred('internal', {
          confidence: 0.9,
          inferredBy: 'heuristic',
          reasoning: 'compose のネットワークが内部のみに閉じているため。',
        }),
        dataSensitivity: inferred(['pii', 'credentials'], {
          confidence: 0.7,
          inferredBy: 'llm',
          reasoning: 'ユーザーテーブルとトークンテーブルを保持している。',
        }),
        requiresAuthentication: observed(true, [{ file: 'docker-compose.yml', line: 16 }]),
        sourcePaths: ['src/db/'],
        entryPointIds: [],
      },
      {
        id: 'worker',
        kind: 'background-worker',
        name: 'バッチワーカー',
        technology: assumed('Node.js', '実行形態の記述が無いため既定値'),
        exposure: assumed('local', '起動方法が不明なためローカル実行と仮定'),
        dataSensitivity: assumed(['unknown'], '不明'),
        requiresAuthentication: assumed(false, '既定値'),
        sourcePaths: ['src/worker/'],
        entryPointIds: [],
      },
    ],
    dataFlows: [
      {
        fromId: 'web',
        toId: 'api',
        protocol: observed('HTTP', [{ file: 'web/src/api.ts', line: 3 }]),
        crossesTrustBoundary: inferred(true, {
          confidence: 0.8,
          inferredBy: 'heuristic',
          reasoning: 'ブラウザからの入力がそのままサーバへ渡るため。',
        }),
      },
      {
        fromId: 'api',
        toId: 'db',
        protocol: observed('SQL', [{ file: 'src/db/pool.ts', line: 9 }]),
        crossesTrustBoundary: inferred(false, {
          confidence: 0.6,
          inferredBy: 'heuristic',
          reasoning: '同一 VPC 内の通信のため。',
        }),
      },
      {
        fromId: 'worker',
        toId: 'db',
        protocol: assumed('SQL', '接続方式の記述がないため既定値'),
        crossesTrustBoundary: assumed(false, '判断材料なし'),
      },
    ],
    deployment: {
      runtime: observed('Node.js 20', [{ file: 'Dockerfile', line: 1 }]),
      containerization: observed('docker', [{ file: 'Dockerfile' }]),
      platform: inferred('aws-ecs', {
        confidence: 0.4,
        inferredBy: 'heuristic',
        reasoning: 'task-definition.json があるため ECS と推測。',
        alternatives: ['aws-ec2'],
      }),
      cloudProvider: inferred('aws', {
        confidence: 0.6,
        inferredBy: 'heuristic',
        reasoning: 'AWS SDK への依存があるため。',
      }),
      cicd: observed('github-actions', [{ file: '.github/workflows/ci.yml' }]),
      ingress: assumed('unknown', 'ロードバランサ設定を発見できなかった'),
      secretsManagement: inferred('env-file', {
        confidence: 0.5,
        inferredBy: 'heuristic',
        reasoning: '.env.example が存在するため。',
      }),
      iac: assumed('none', 'IaC ファイルを発見できなかった'),
    },
    evidence: { observed: 4, inferred: 4, assumed: 2, meanInferredConfidence: 0.55 },
    inspectedManifests: ['package.json', 'Dockerfile', 'docker-compose.yml'],
    gaps: [
      'ロードバランサ／WAF の有無を判断できなかった（設定ファイルを発見できず）',
      'バッチワーカーの実行契機が不明（cron 定義なし）',
    ],
    ...overrides,
  };
}

/** ヒートマップのフィクスチャ。死角を likelyCause 別に複数含む */
export function makeHeatmap(overrides: Partial<VulnerabilityHeatmap> = {}): VulnerabilityHeatmap {
  return {
    componentIds: ['web', 'api', 'db', 'worker'],
    categories: [
      { id: 'injection', name: 'インジェクション', cweIds: ['CWE-89'], owasp: 'A03:2021' },
      { id: 'authz', name: '認可', cweIds: ['CWE-285'], owasp: 'A01:2021' },
      { id: 'crypto', name: '暗号・秘密情報', cweIds: ['CWE-798'], owasp: 'A02:2021' },
    ],
    cells: [
      {
        componentId: 'api',
        categoryId: 'injection',
        observedRisk: 92,
        findingIds: ['f-1'],
        chainIds: ['ch-1'],
        inferredRisk: inferred(85, {
          confidence: 0.7,
          inferredBy: 'catalog',
          reasoning: '公開APIかつSQL利用のため。',
        }),
        basis: 'both',
      },
      {
        componentId: 'api',
        categoryId: 'crypto',
        observedRisk: 60,
        findingIds: ['f-2'],
        chainIds: [],
        inferredRisk: inferred(40, {
          confidence: 0.5,
          inferredBy: 'catalog',
          reasoning: '署名鍵の取り扱いがあるため。',
        }),
        basis: 'observed-only',
      },
      {
        componentId: 'db',
        categoryId: 'authz',
        observedRisk: 0,
        findingIds: [],
        chainIds: [],
        inferredRisk: inferred(78, {
          confidence: 0.6,
          inferredBy: 'catalog',
          reasoning: '行レベル認可の実装が確認できないため。',
        }),
        basis: 'inferred-only',
      },
      {
        componentId: 'worker',
        categoryId: 'injection',
        observedRisk: 0,
        findingIds: [],
        chainIds: [],
        inferredRisk: assumed(0, '該当コードを走査していない'),
        basis: 'none',
      },
    ],
    blindSpots: [
      {
        componentId: 'db',
        categoryId: 'authz',
        inferredRisk: 78,
        reasoning: '認可レンズが DB 層のクエリを追跡できていない。',
        likelyCause: 'no-matching-lens',
        recommendedAction: '行レベルセキュリティの設定を手動で確認する。',
      },
      {
        componentId: 'worker',
        categoryId: 'injection',
        inferredRisk: 65,
        reasoning: 'worker ディレクトリが除外設定に含まれている。',
        likelyCause: 'not-scanned',
        recommendedAction: '除外設定を外して再スキャンする。',
      },
      {
        componentId: 'web',
        categoryId: 'crypto',
        inferredRisk: 30,
        reasoning: 'フロントエンドに暗号処理の実装が見当たらない。',
        likelyCause: 'genuinely-absent',
        recommendedAction: '暗号処理をサーバ側に集約できているか確認する。',
      },
      {
        componentId: 'web',
        categoryId: 'authz',
        inferredRisk: 20,
        reasoning: '判断材料が不足している。',
        likelyCause: 'unknown',
        recommendedAction: 'まず原因を切り分ける。',
      },
    ],
    componentTotals: {
      web: { observed: 12, inferred: 50 },
      api: { observed: 152, inferred: 125 },
      db: { observed: 0, inferred: 78 },
      worker: { observed: 0, inferred: 65 },
    },
    categoryTotals: {
      injection: { observed: 92, inferred: 150 },
      authz: { observed: 0, inferred: 98 },
      crypto: { observed: 60, inferred: 70 },
    },
    inferenceRatio: 0.68,
    ...overrides,
  };
}

/**
 * 分析タスクが全件成功した統計。
 *
 * 既定を「完走」にしてあるのは、既存の大多数のテストが
 * 「正常に走った結果をどう表示するか」を見ているため。
 * 未完走の挙動を確かめるテストは `health` を明示的に渡す。
 */
export function makeAnalysisStats(overrides: Partial<AnalysisStats> = {}): AnalysisStats {
  return { ...emptyAnalysisStats(), total: 8, succeeded: 8, ...overrides };
}

/** サマリと健全性を自動で埋めた ScanResult を作る */
export function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const base = {
    context: overrides.context ?? makeContext(),
    findings: overrides.findings ?? [],
    chains: overrides.chains ?? [],
    errors: overrides.errors ?? [],
  };
  return {
    ...base,
    health: overrides.health ?? assessAnalysisHealth(makeAnalysisStats()),
    ...(overrides.architecture ? { architecture: overrides.architecture } : {}),
    ...(overrides.heatmap ? { heatmap: overrides.heatmap } : {}),
    summary:
      overrides.summary ??
      summarize(base, {
        durationMs: 1234,
        suppressedCount: 0,
        tokenUsage: { input: 100, output: 200, cacheRead: 300, cacheWrite: 400 },
      }),
  };
}
