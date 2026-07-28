/**
 * SARIF 2.1.0 フォーマッタ。
 *
 * GitHub Code Scanning が受け付ける形を目標にしている。
 * 特に効くのは以下:
 *   - runs[].tool.driver.rules[] にCWE単位のルール定義を置き、
 *     results[].ruleId / ruleIndex で参照する
 *   - rule.properties["security-severity"] に数値文字列を入れる
 *     （GitHub はここを見て Critical/High/Medium/Low を決める）
 *   - partialFingerprints に安定した指紋を入れてアラートの重複を防ぐ
 */

import type { Finding } from '../../types/finding.js';
import type { AnalyzedReport, ScanResult } from '../../types/report.js';
import { securitySeverityValue, toSarifLevel } from '../severity.js';
import { truncate } from '../text.js';

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

const TOOL_NAME = 'grimoire';
const TOOL_VERSION = '0.1.0';
const TOOL_URI = 'https://github.com/grimoire-scanner/grimoire';

/** SARIFの最小限の型（外部依存を増やさないため自前で定義） */
export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
  invocations: SarifInvocation[];
  originalUriBaseIds?: Record<string, { uri: string }>;
  automationDetails?: { id: string; description?: { text: string } };
  columnKind: string;
  properties?: Record<string, unknown>;
}

export interface SarifDriver {
  name: string;
  version: string;
  semanticVersion: string;
  informationUri: string;
  rules: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri?: string;
  defaultConfiguration: { level: 'error' | 'warning' | 'note' | 'none' };
  properties: Record<string, unknown>;
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: SarifArtifactLocation;
    region: {
      startLine: number;
      endLine?: number;
      snippet?: { text: string };
    };
  };
  message?: { text: string };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints: Record<string, string>;
  properties: Record<string, unknown>;
  baselineState?: 'new' | 'unchanged' | 'updated' | 'absent';
  codeFlows?: SarifCodeFlow[];
  fixes?: { description: { text: string } }[];
  suppressions?: { kind: 'inSource' | 'external'; justification?: string; status?: string }[];
  relatedLocations?: SarifLocation[];
}

export interface SarifCodeFlow {
  message?: { text: string };
  threadFlows: {
    locations: {
      location: SarifLocation;
      importance?: 'essential' | 'important' | 'unimportant';
      nestingLevel?: number;
    }[];
  }[];
}

export interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  toolExecutionNotifications?: {
    level: 'error' | 'warning' | 'note';
    message: { text: string };
  }[];
}

/** CWE番号（数値部分）を取り出す */
function cweNumber(cwe: string): string | null {
  const match = /(\d+)/.exec(cwe);
  return match?.[1] ?? null;
}

/** SARIFのルールIDに使える形へ正規化 */
function normalizeRuleId(cwe: string): string {
  const trimmed = (cwe ?? '').trim();
  if (trimmed === '') return 'CWE-UNKNOWN';
  return /^cwe-/i.test(trimmed) ? trimmed.toUpperCase() : `CWE-${trimmed.replace(/^-+/, '')}`;
}

/** rule.name は識別子的な文字列が期待されるので英数字に落とす */
function ruleName(ruleId: string): string {
  const sanitized = ruleId.replace(/[^A-Za-z0-9]/g, '');
  return sanitized === '' ? 'VulnScanRule' : sanitized;
}

/** ファイルパスをSARIFのURI（相対・スラッシュ区切り）へ */
function toUri(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

/** ローカルパスを file:// URIへ（originalUriBaseIds用） */
function toFileUri(absolutePath: string): string {
  const normalized = absolutePath.replace(/\\/g, '/');
  const withSlash = normalized.endsWith('/') ? normalized : `${normalized}/`;
  return withSlash.startsWith('/') ? `file://${withSlash}` : `file:///${withSlash}`;
}

function clampLine(line: number): number {
  return Number.isFinite(line) && line >= 1 ? Math.trunc(line) : 1;
}

function buildLocation(
  file: string,
  startLine: number,
  endLine: number,
  snippet: string | undefined,
  message?: string,
): SarifLocation {
  const start = clampLine(startLine);
  const end = Math.max(start, clampLine(endLine));
  const location: SarifLocation = {
    physicalLocation: {
      artifactLocation: { uri: toUri(file), uriBaseId: 'SRCROOT' },
      region: { startLine: start, endLine: end },
    },
  };
  if (snippet && snippet.trim() !== '') {
    location.physicalLocation.region.snippet = { text: truncate(snippet, 2000) };
  }
  if (message) location.message = { text: message };
  return location;
}

function baselineState(finding: Finding): SarifResult['baselineState'] {
  switch (finding.diffStatus) {
    case 'new':
      return 'new';
    case 'persistent':
      return 'unchanged';
    case 'fixed':
      return 'absent';
    default:
      return undefined;
  }
}

function buildCodeFlow(finding: Finding): SarifCodeFlow | null {
  if (finding.dataFlow.length === 0) return null;
  return {
    message: { text: `${finding.cwe} のデータフロー（source から sink まで）` },
    threadFlows: [
      {
        locations: finding.dataFlow.map((step, index) => ({
          location: buildLocation(
            step.file,
            step.line,
            step.line,
            step.code,
            `[${step.role}] ${step.description}`,
          ),
          importance:
            step.role === 'source' || step.role === 'sink'
              ? ('essential' as const)
              : ('important' as const),
          nestingLevel: index,
        })),
      },
    ],
  };
}

/** ルール定義（CWE単位）を組み立てる */
function buildRules(findings: readonly Finding[]): { rules: SarifRule[]; index: Map<string, number> } {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const id = normalizeRuleId(finding.cwe);
    const list = grouped.get(id);
    if (list) list.push(finding);
    else grouped.set(id, [finding]);
  }

  const rules: SarifRule[] = [];
  const index = new Map<string, number>();

  for (const [ruleId, group] of [...grouped.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const representative = group.reduce((best, f) =>
      securitySeverityValue(f) > securitySeverityValue(best) ? f : best,
    );
    const maxSeverity = securitySeverityValue(representative);
    const num = cweNumber(ruleId);
    const categories = [...new Set(group.map((f) => f.category).filter((c) => c !== ''))];

    const tags = ['security', 'grimoire'];
    if (num) tags.push(`external/cwe/cwe-${num}`);
    for (const category of categories) {
      tags.push(category.replace(/\s+/g, '-'));
    }

    const helpMarkdown = [
      `## ${ruleId}`,
      '',
      `**代表例**: ${representative.title}`,
      '',
      '### なぜ問題か',
      representative.reasoning || '（説明なし）',
      '',
      '### 修正方針',
      representative.remediation || '（修正方針の記載なし）',
      '',
      ...(representative.references.length > 0
        ? ['### 参考', ...representative.references.map((r) => `- ${r}`)]
        : []),
    ].join('\n');

    index.set(ruleId, rules.length);
    rules.push({
      id: ruleId,
      name: ruleName(ruleId),
      shortDescription: { text: truncate(representative.title, 120) },
      fullDescription: {
        text: truncate(representative.reasoning || representative.title, 900),
      },
      help: {
        text: truncate(representative.remediation || representative.reasoning, 900),
        markdown: helpMarkdown,
      },
      ...(num ? { helpUri: `https://cwe.mitre.org/data/definitions/${num}.html` } : {}),
      defaultConfiguration: { level: toSarifLevel(representative.severity) },
      properties: {
        tags,
        // GitHub Code Scanning はこの文字列を読んで深刻度を決める
        'security-severity': maxSeverity.toFixed(1),
        precision: representative.confidence >= 0.8 ? 'high' : representative.confidence >= 0.5 ? 'medium' : 'low',
        cwe: ruleId,
        ...(categories.length > 0 ? { owaspCategories: categories } : {}),
      },
    });
  }

  return { rules, index };
}

function buildResult(finding: Finding, ruleIndex: Map<string, number>): SarifResult {
  const ruleId = normalizeRuleId(finding.cwe);
  const cvss = finding.cvss;

  const message = [
    finding.title,
    finding.reasoning ? `\n\n${truncate(finding.reasoning, 700)}` : '',
    finding.remediation ? `\n\n修正方針: ${truncate(finding.remediation, 500)}` : '',
  ].join('');

  const result: SarifResult = {
    ruleId,
    ruleIndex: ruleIndex.get(ruleId) ?? 0,
    level: toSarifLevel(finding.severity),
    message: { text: message },
    locations: [
      buildLocation(
        finding.location.file,
        finding.location.startLine,
        finding.location.endLine,
        finding.evidence,
      ),
    ],
    // 指紋はベースライン照合と同じ値を使う。値は必ず文字列。
    //
    // キー名が旧称 (vulnscan*) のままなのは意図的。GRIMOIRE へ改称しても
    // ここは GitHub code scanning などが既存アラートと同一視するための
    // 安定キーであり、変えると過去のアラート履歴・トリアージ状態が
    // 全て切れて重複計上される。表示名だけを変え、識別子は据え置く。
    partialFingerprints: {
      vulnscanFingerprint: String(finding.fingerprint),
      vulnscanFindingId: String(finding.id),
    },
    properties: {
      cwe: ruleId,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      lens: finding.lens,
      diffStatus: finding.diffStatus,
      triageStatus: finding.status,
      firstSeen: finding.firstSeen,
      lastSeen: finding.lastSeen,
      // GitHub は result 側の properties も参照しうるので両方に入れる
      'security-severity': securitySeverityValue(finding).toFixed(1),
      cvssScore: cvss?.baseScore ?? 0,
      cvssVector: cvss?.vector ?? '',
      cvssVersion: cvss?.version ?? '',
      cvssBaseSeverity: cvss?.baseSeverity ?? 'None',
      ...(cvss?.breakdown
        ? {
            cvssImpactSubScore: cvss.breakdown.impactSubScore,
            cvssExploitabilitySubScore: cvss.breakdown.exploitabilitySubScore,
          }
        : {}),
      ...(finding.cve ? { cve: finding.cve } : {}),
      ...(finding.affectedPackage
        ? {
            affectedPackage: `${finding.affectedPackage.name}@${finding.affectedPackage.version}`,
            packageEcosystem: finding.affectedPackage.ecosystem,
            ...(finding.affectedPackage.fixedVersion
              ? { fixedVersion: finding.affectedPackage.fixedVersion }
              : {}),
          }
        : {}),
      ...(finding.mergedFrom.length > 0 ? { mergedFrom: finding.mergedFrom } : {}),
      ...(finding.references.length > 0 ? { references: finding.references } : {}),
    },
  };

  const state = baselineState(finding);
  if (state) result.baselineState = state;

  const codeFlow = buildCodeFlow(finding);
  if (codeFlow) result.codeFlows = [codeFlow];

  if (finding.remediation && finding.remediation.trim() !== '') {
    result.fixes = [{ description: { text: truncate(finding.remediation, 900) } }];
  }

  // トリアージ済みのものは抑制として表現する（GitHubでdismissed相当に見せる）
  if (finding.status === 'false-positive' || finding.status === 'accepted') {
    result.suppressions = [
      {
        kind: 'external',
        justification:
          finding.status === 'false-positive'
            ? '誤検知としてトリアージ済み'
            : 'リスク受容としてトリアージ済み',
        status: 'accepted',
      },
    ];
  }

  return result;
}

/** SARIFログのオブジェクトを組み立てる（テストから直接検証できるよう分離） */
export function buildSarifLog(result: ScanResult, analyzed?: AnalyzedReport): SarifLog {
  const findings = result.findings;
  const { rules, index } = buildRules(findings);

  const invocation: SarifInvocation = {
    executionSuccessful: result.errors.length === 0,
    startTimeUtc: normalizeIso(result.context.scannedAt),
  };
  const notifications = [
    ...result.errors.map((message) => ({ level: 'error' as const, message: { text: message } })),
    ...result.context.warnings.map((message) => ({
      level: 'warning' as const,
      message: { text: message },
    })),
  ];
  if (notifications.length > 0) invocation.toolExecutionNotifications = notifications;

  const run: SarifRun = {
    tool: {
      driver: {
        name: TOOL_NAME,
        version: TOOL_VERSION,
        semanticVersion: TOOL_VERSION,
        informationUri: TOOL_URI,
        rules,
      },
    },
    results: findings.map((finding) => buildResult(finding, index)),
    invocations: [invocation],
    originalUriBaseIds: { SRCROOT: { uri: toFileUri(result.context.repoRoot) } },
    automationDetails: {
      id: `grimoire/${result.context.git?.branch ?? 'scan'}/`,
      description: {
        text: analyzed
          ? truncate(analyzed.executiveSummary, 900)
          : `GRIMOIRE による ${findings.length} 件の検出結果`,
      },
    },
    columnKind: 'utf16CodeUnits',
    properties: {
      summary: result.summary,
      chainCount: result.chains.length,
      ...(analyzed
        ? {
            prioritizedActions: analyzed.prioritizedActions.map((a) => ({
              order: a.order,
              action: a.action,
              effort: a.effort,
              resolvesFindings: a.resolves.findings,
              resolvesChains: a.resolves.chains,
            })),
          }
        : {}),
      attackChains: result.chains.map((chain) => ({
        id: chain.id,
        title: chain.title,
        entryPoint: chain.entryPoint,
        likelihood: chain.likelihood,
        priorityScore: chain.priorityScore,
        findingIds: chain.steps.map((s) => s.findingId).filter((id): id is string => id !== null),
        chokePointFindingId: chain.chokePoint?.findingId ?? null,
      })),
    },
  };

  return { $schema: SARIF_SCHEMA, version: SARIF_VERSION, runs: [run] };
}

function normalizeIso(value: string): string | undefined {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** SARIF文字列を生成する */
export function renderSarif(result: ScanResult, analyzed: AnalyzedReport): string {
  return `${JSON.stringify(buildSarifLog(result, analyzed), null, 2)}\n`;
}
