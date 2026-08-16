/**
 * OSV.dev API 連携。依存パッケージの既知脆弱性を照合して Finding を生成する。
 *
 * 使用するエンドポイント:
 *   POST https://api.osv.dev/v1/querybatch  … パッケージ一括問い合わせ（ID一覧のみ返る）
 *   GET  https://api.osv.dev/v1/vulns/{id}  … 個別脆弱性の詳細
 *
 * ネットワークが使えない環境でも壊れないこと（オフライン耐性）を最優先とし、
 * 失敗はすべて errors に積んで処理を継続する。
 */

import type { Dependency } from '../types/context.js';
import type { StageProgress } from '../types/progress.js';
import type { Cvss3Metrics, Finding } from '../types/finding.js';
import { mapPool } from '../llm/pool.js';
import { extractCweId } from './catalog.js';
import { calculateCvss3, cvss3RatingToSeverity, parseCvss3Vector } from './cvss.js';
import { computeDependencyFingerprint, fingerprintToId } from './fingerprint.js';
import { buildReferences, lookupCwe } from './knowledge.js';

const OSV_BASE_URL = 'https://api.osv.dev';
/** querybatch の1リクエストあたりの問い合わせ件数 */
const BATCH_SIZE = 100;
/** 詳細取得の同時実行数（API への配慮） */
const DETAIL_CONCURRENCY = 8;
/** 1リクエストのタイムアウト(ms) */
const DEFAULT_TIMEOUT_MS = 15_000;

/** fetch 互換関数（テストでの差し替え用） */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface OsvOptions {
  /** 既定は globalThis.fetch */
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** 開発用依存も照合するか（既定 true。ただし confidence を下げる） */
  includeDevDependencies?: boolean;
  /** 生成時刻（ISO8601） */
  now?: string;
  /**
   * 進捗通知（脆弱性IDの詳細取得単位）。
   * ③で時間がかかるのはここのネットワーク往復だけなので、数えるのもここだけ。
   */
  onProgress?: (progress: StageProgress) => void;
}

/* --- OSV レスポンスの最小限の型（必要なフィールドのみ） --- */

interface OsvSeverity {
  type?: string;
  score?: string;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }>;
  severity?: OsvSeverity[];
  database_specific?: Record<string, unknown>;
}

interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: Record<string, unknown>;
}

interface OsvBatchResponse {
  results?: Array<{ vulns?: Array<{ id: string; modified?: string }> } | null>;
}

export interface OsvScanResult {
  findings: Finding[];
  errors: string[];
}

/**
 * 依存関係一覧を OSV.dev に問い合わせ、既知脆弱性の Finding を生成する。
 * ネットワーク不通・APIエラーの場合は空の findings と errors を返す。
 */
export async function scanDependencies(
  dependencies: Dependency[],
  options: OsvOptions = {},
): Promise<OsvScanResult> {
  const errors: string[] = [];
  const findings: Finding[] = [];

  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  const now = options.now ?? new Date().toISOString();
  const includeDev = options.includeDevDependencies !== false;

  const targets = (dependencies ?? []).filter(
    (d) => d && d.name && d.version && (includeDev || !d.dev),
  );
  if (targets.length === 0) return { findings, errors };

  if (typeof fetchImpl !== 'function') {
    errors.push('OSV照合をスキップ: この実行環境には fetch がありません');
    return { findings, errors };
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // --- 1. querybatch で脆弱性IDを取得 ---
  /** 依存index → 脆弱性ID一覧 */
  const idsByDep = new Map<number, string[]>();

  for (let offset = 0; offset < targets.length; offset += BATCH_SIZE) {
    const chunk = targets.slice(offset, offset + BATCH_SIZE);
    const body = {
      queries: chunk.map((d) => ({
        version: d.version,
        package: { name: d.name, ecosystem: d.ecosystem },
      })),
    };

    try {
      const res = await fetchImpl(`${OSV_BASE_URL}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        errors.push(`OSV querybatch がエラーを返しました (HTTP ${res.status})`);
        continue;
      }
      const json = (await res.json()) as OsvBatchResponse;
      const results = json.results ?? [];
      for (let i = 0; i < chunk.length; i++) {
        const vulns = results[i]?.vulns ?? [];
        if (vulns.length > 0) {
          idsByDep.set(
            offset + i,
            vulns.map((v) => v.id).filter((id): id is string => typeof id === 'string'),
          );
        }
      }
    } catch (e) {
      errors.push(`OSV querybatch に失敗しました: ${describeError(e)}`);
    }
  }

  if (idsByDep.size === 0) return { findings, errors };

  // --- 2. 脆弱性の詳細を取得（IDごとに1回だけ） ---
  const uniqueIds = Array.from(new Set(Array.from(idsByDep.values()).flat()));
  const details = new Map<string, OsvVulnerability>();

  // 同時実行数の制限は `llm/pool.ts` の mapPool に任せる
  // （以前はここに1行ずつ対応する手書きのワーカープールがあった）。
  const onProgress = options.onProgress;
  await mapPool(
    uniqueIds,
    DETAIL_CONCURRENCY,
    async (id) => {
      try {
        const res = await fetchImpl(`${OSV_BASE_URL}/v1/vulns/${encodeURIComponent(id)}`, {
          method: 'GET',
          headers: { accept: 'application/json' },
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) {
          errors.push(`OSV 詳細取得に失敗しました (${id}: HTTP ${res.status})`);
          return;
        }
        const json = (await res.json()) as OsvVulnerability;
        if (json && typeof json.id === 'string') details.set(id, json);
      } catch (e) {
        errors.push(`OSV 詳細取得に失敗しました (${id}): ${describeError(e)}`);
      }
    },
    onProgress
      ? (p) => onProgress({ completed: p.completed, total: p.total, unit: '依存脆弱性' })
      : undefined,
  );

  // --- 3. Finding を組み立てる ---
  for (const [depIndex, ids] of Array.from(idsByDep.entries()).sort((a, b) => a[0] - b[0])) {
    const dep = targets[depIndex];
    if (!dep) continue;
    for (const id of ids) {
      const vuln = details.get(id);
      // 詳細が取れなかった場合も、ID だけの最小限の Finding は残す（取りこぼし防止）
      findings.push(buildDependencyFinding(dep, id, vuln, now));
    }
  }

  return { findings, errors };
}

/** OSV の脆弱性情報から依存 Finding を組み立てる */
function buildDependencyFinding(
  dep: Dependency,
  vulnId: string,
  vuln: OsvVulnerability | undefined,
  now: string,
): Finding {
  const aliases = vuln?.aliases ?? [];
  const cve = [vulnId, ...aliases].find((a) => /^CVE-\d{4}-\d+$/i.test(a))?.toUpperCase();

  // CWE は database_specific.cwe_ids があれば利用、無ければ「脆弱な依存」を表す CWE-1395
  const cweFromDb = extractCweIds(vuln?.database_specific).find((c) => lookupCwe(c));
  const cwe = cweFromDb ?? extractCweIds(vuln?.database_specific)[0] ?? 'CWE-1395';

  // CVSS: OSV がベクタを提供していれば厳密に使い、無ければ深刻度文字列から推定する
  let metrics: Cvss3Metrics;
  let cvssSource: string;
  const vector = findCvssVector(vuln);
  let version: '3.0' | '3.1' = '3.1';
  if (vector) {
    try {
      metrics = parseCvss3Vector(vector);
      version = vector.startsWith('CVSS:3.0') ? '3.0' : '3.1';
      cvssSource = `OSV提供のCVSSベクタ (${vector})`;
    } catch {
      metrics = metricsFromQualitativeSeverity(qualitativeSeverity(vuln));
      cvssSource = `OSV提供のベクタが解釈できないため深刻度 '${qualitativeSeverity(vuln)}' から推定`;
    }
  } else {
    metrics = metricsFromQualitativeSeverity(qualitativeSeverity(vuln));
    cvssSource = `CVSSベクタ未提供のため深刻度 '${qualitativeSeverity(vuln) ?? '不明'}' から推定`;
  }
  const cvss = calculateCvss3(metrics, version);

  const fixedVersion = findFixedVersion(vuln, dep);
  const fingerprint = computeDependencyFingerprint({
    ecosystem: dep.ecosystem,
    name: dep.name,
    vulnId,
  });

  const advisoryUrls = (vuln?.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === 'string' && /^https?:\/\//.test(u))
    .slice(0, 5);
  const references = buildReferences(extractCweId(cwe), 'A06:2021-Vulnerable and Outdated Components', [
    `https://osv.dev/vulnerability/${vulnId}`,
    ...(cve ? [`https://nvd.nist.gov/vuln/detail/${cve}`] : []),
    ...advisoryUrls,
  ]);

  const summary = vuln?.summary?.trim() || `${vulnId} が ${dep.name} に影響します`;
  const label = cve ? `${cve} (${vulnId})` : vulnId;

  const remediation = fixedVersion
    ? `${dep.name} を ${fixedVersion} 以降に更新してください（現在 ${dep.version}）。`
    : `${dep.name} ${dep.version} に修正版の情報がありません。アドバイザリ(${vulnId})を確認し、回避策の適用または代替パッケージへの移行を検討してください。`;

  return {
    cwe: extractCweId(cwe) ?? 'CWE-1395',
    category: 'A06:2021-Vulnerable and Outdated Components',
    title: `${dep.name}@${dep.version}: ${label} - ${truncate(summary, 120)}`,
    severity: cvss3RatingToSeverity(cvss.baseSeverity),
    // OSV がバージョン範囲で照合しているため確信度は高い。開発時のみの依存は影響が限定的なので下げる。
    confidence: dep.dev ? 0.6 : 0.95,
    location: { file: dep.manifest || 'package.json', startLine: 1, endLine: 1 },
    evidence: `${dep.name}@${dep.version} (${dep.ecosystem}) — 宣言元: ${dep.manifest}`,
    dataFlow: [],
    reasoning: [
      `依存パッケージ ${dep.name}@${dep.version} は OSV.dev のアドバイザリ ${vulnId} の影響を受けます。`,
      vuln?.details?.trim() || summary,
      dep.dev ? '※ 開発時のみの依存であり、本番実行環境への影響は限定的です。' : '',
      `[CVSS] ${cvssSource}`,
    ]
      .filter(Boolean)
      .join('\n'),
    remediation,
    lens: 'dependency',
    id: fingerprintToId(fingerprint),
    fingerprint,
    ...(cve ? { cve } : {}),
    affectedPackage: {
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      ...(fixedVersion ? { fixedVersion } : {}),
    },
    cvss,
    status: 'open',
    diffStatus: 'new',
    firstSeen: now,
    lastSeen: now,
    mergedFrom: [],
    references,
  };
}

/** CVSS v3 系のベクタ文字列を探す（affected 側にしか無い場合もある） */
function findCvssVector(vuln: OsvVulnerability | undefined): string | null {
  const pools: OsvSeverity[] = [
    ...(vuln?.severity ?? []),
    ...(vuln?.affected ?? []).flatMap((a) => a.severity ?? []),
  ];
  for (const s of pools) {
    const score = s?.score;
    if (typeof score !== 'string') continue;
    if (/^CVSS:3\.[01]\//.test(score)) return score;
  }
  return null;
}

/** database_specific.severity 等から定性的な深刻度を取り出す */
function qualitativeSeverity(vuln: OsvVulnerability | undefined): string | null {
  const raw = vuln?.database_specific?.['severity'];
  return typeof raw === 'string' ? raw.toUpperCase() : null;
}

/** database_specific.cwe_ids から CWE ID を取り出す */
function extractCweIds(dbSpecific: Record<string, unknown> | undefined): string[] {
  const raw = dbSpecific?.['cwe_ids'];
  if (!Array.isArray(raw)) return [];
  return raw
    .map((v) => extractCweId(typeof v === 'string' ? v : null))
    .filter((v): v is string => v !== null);
}

/**
 * CVSSベクタが無い場合の代替メトリクス。
 * 「ネットワーク経由・認証不要で悪用され、深刻度に応じた影響が出る」という
 * 依存脆弱性の一般的な形を仮定する。
 */
function metricsFromQualitativeSeverity(severity: string | null): Cvss3Metrics {
  const base: Cvss3Metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L' };
  switch (severity) {
    case 'CRITICAL':
      return { ...base, C: 'H', I: 'H', A: 'H' };
    case 'HIGH':
      return { ...base, C: 'H', I: 'H', A: 'N' };
    case 'MODERATE':
    case 'MEDIUM':
      return { ...base, C: 'L', I: 'L', A: 'N' };
    case 'LOW':
      return { ...base, AC: 'H', C: 'L', I: 'N', A: 'N' };
    default:
      // 不明な場合は中程度とみなす
      return { ...base, C: 'L', I: 'L', A: 'N' };
  }
}

/** 影響範囲から修正済みバージョンを探す */
function findFixedVersion(vuln: OsvVulnerability | undefined, dep: Dependency): string | undefined {
  const affected = (vuln?.affected ?? []).filter((a) => {
    const name = a.package?.name;
    return !name || name.toLowerCase() === dep.name.toLowerCase();
  });
  const fixes: string[] = [];
  for (const a of affected) {
    for (const range of a.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (typeof event.fixed === 'string' && event.fixed !== '') fixes.push(event.fixed);
      }
    }
  }
  return fixes[0];
}

function truncate(text: string, max: number): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function describeError(e: unknown): string {
  if (e instanceof Error) {
    return e.name === 'TimeoutError' || e.name === 'AbortError' ? 'タイムアウト' : e.message;
  }
  return String(e);
}
