/**
 * レポーターのテスト用フィクスチャ生成。
 *
 * 型が大きいため、テストごとに全フィールドを書くと本質が埋もれる。
 * ここでは「妥当な既定値 + 部分上書き」でオブジェクトを作れるようにする。
 */

import type { ScanContext } from '../types/context.js';
import type { Cvss3Result, Finding } from '../types/finding.js';
import type { AttackChain } from '../types/killchain.js';
import type { ScanResult, ScanSummary } from '../types/report.js';
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
    languages: [{ name: 'typescript', fileCount: 120, ratio: 0.9 }],
    frameworks: [{ name: 'express', evidence: 'package.json', version: '4.19.2' }],
    dependencies: [
      { name: 'express', version: '4.19.2', ecosystem: 'npm', dev: false, manifest: 'package.json' },
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm', dev: false, manifest: 'package.json' },
    ],
    files: [
      { path: 'src/api/users.ts', language: 'typescript', sizeBytes: 2048, hash: 'aaa' },
      { path: 'src/auth/token.ts', language: 'typescript', sizeBytes: 1024, hash: 'bbb' },
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

export function makeSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    totalFindings: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byCategory: {},
    newCount: 0,
    fixedCount: 0,
    persistentCount: 0,
    suppressedCount: 0,
    chainCount: 0,
    maxCvssScore: 0,
    filesScanned: 0,
    durationMs: 1234,
    tokenUsage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    ...overrides,
  };
}

/** サマリを自動計算した ScanResult を作る */
export function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const base = {
    context: overrides.context ?? makeContext(),
    findings: overrides.findings ?? [],
    chains: overrides.chains ?? [],
    errors: overrides.errors ?? [],
  };
  return {
    ...base,
    summary:
      overrides.summary ??
      summarize(base, {
        durationMs: 1234,
        suppressedCount: 0,
        tokenUsage: { input: 100, output: 200, cacheRead: 300, cacheWrite: 400 },
      }),
  };
}
