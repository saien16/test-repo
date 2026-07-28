/**
 * Markdownフォーマッタ。人間向けの詳細レポート。
 *
 * 構成:
 *   エグゼクティブサマリ → リスク全体像 → 優先対応アクション
 *   → 攻撃チェーン詳細 → 個別Finding詳細 → 依存関係SBOM
 *
 * 「読み物として成立させる」ことを優先し、表と散文を織り交ぜる。
 */

import type { Dependency } from '../../types/context.js';
import type { Finding } from '../../types/finding.js';
import type { AttackChain } from '../../types/killchain.js';
import type { AnalyzedReport, ReportOptions, ScanResult } from '../../types/report.js';
import { effortJa, likelihoodJa } from '../priority.js';
import {
  SEVERITY_LABEL_JA,
  SEVERITY_ORDER,
  isActiveFinding,
  severityRank,
} from '../severity.js';
import {
  escapeMdCell,
  formatDateTime,
  formatDuration,
  formatNumber,
  truncate,
} from '../text.js';

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

/** キルチェーン段階の日本語表記 */
const PHASE_JA: Record<string, string> = {
  reconnaissance: '偵察',
  weaponization: '武器化',
  delivery: '配送',
  exploitation: '攻撃実行',
  installation: '居座り',
  'command-and-control': '遠隔操作',
  'actions-on-objectives': '目的の実行',
};

/** ATT&CK戦術の日本語表記 */
const TACTIC_JA: Record<string, string> = {
  'initial-access': '初期侵入',
  execution: '実行',
  persistence: '永続化',
  'privilege-escalation': '権限昇格',
  'defense-evasion': '防御回避',
  'credential-access': '資格情報アクセス',
  discovery: '探索',
  'lateral-movement': '横展開',
  collection: '収集',
  exfiltration: '持ち出し',
  impact: '影響',
};

const ROLE_JA: Record<string, string> = {
  source: '汚染源',
  propagation: '伝播',
  sanitizer: '無害化',
  sink: '危険な出力先',
};

function fence(code: string, lang = ''): string {
  // コード片にバッククォートが含まれても壊れないようフェンスを伸ばす
  const longest = /(`{3,})/.exec(code)?.[1]?.length ?? 0;
  const marker = '`'.repeat(Math.max(3, longest + 1));
  return `${marker}${lang}\n${code.replace(/\s+$/u, '')}\n${marker}`;
}

function anchor(text: string): string {
  return text.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s+/g, '-');
}

function renderHeader(result: ScanResult, analyzed: AnalyzedReport): string[] {
  const s = analyzed.summary;
  const git = result.context.git;
  const lines: string[] = [];

  lines.push('# セキュリティスキャンレポート');
  lines.push('');
  lines.push(
    `> **対象**: \`${result.context.repoRoot}\`` +
      (git ? ` / **ブランチ**: \`${git.branch}\` (\`${truncate(git.headSha, 12, '')}\`)` : ''),
  );
  lines.push(`> **実施日時**: ${formatDateTime(result.context.scannedAt)} / **所要**: ${formatDuration(s.durationMs)}`);
  lines.push(
    `> **走査対象**: ${formatNumber(s.filesScanned)} ファイル / 依存 ${formatNumber(result.context.dependencies.length)} 件 / 入口 ${formatNumber(result.context.entryPoints.length)} 箇所`,
  );
  lines.push('');

  // 数字のダッシュボード
  lines.push('| 指標 | 値 |');
  lines.push('| --- | --- |');
  lines.push(`| 検出件数 | **${formatNumber(s.totalFindings)}** |`);
  for (const severity of SEVERITY_ORDER) {
    const count = s.bySeverity[severity] ?? 0;
    if (count === 0 && (severity === 'info' || severity === 'low')) continue;
    lines.push(`| ${SEVERITY_EMOJI[severity] ?? ''} ${SEVERITY_LABEL_JA[severity]} (${severity}) | ${count} |`);
  }
  lines.push(`| 最大CVSS | ${s.maxCvssScore.toFixed(1)} |`);
  lines.push(`| 攻撃チェーン | ${formatNumber(s.chainCount)} 本 |`);
  lines.push(`| 差分 | 新規 ${s.newCount} / 継続 ${s.persistentCount} / 解消 ${s.fixedCount} |`);
  lines.push(`| 抑制済み | ${formatNumber(s.suppressedCount)} |`);
  lines.push('');
  return lines;
}

function renderToc(hasChains: boolean, hasFindings: boolean, hasDeps: boolean): string[] {
  const items = [
    '- [エグゼクティブサマリ](#エグゼクティブサマリ)',
    '- [リスクの全体像](#リスクの全体像)',
    '- [優先対応アクション](#優先対応アクション)',
  ];
  if (hasChains) items.push('- [攻撃チェーン詳細](#攻撃チェーン詳細)');
  if (hasFindings) items.push('- [個別Finding詳細](#個別finding詳細)');
  if (hasDeps) items.push('- [依存関係SBOM](#依存関係sbom)');
  return ['## 目次', '', ...items, ''];
}

function renderExecutive(analyzed: AnalyzedReport): string[] {
  const lines = ['## エグゼクティブサマリ', '', analyzed.executiveSummary, ''];
  if (analyzed.keyFindings.length > 0) {
    lines.push('### 今回の重要な所見', '');
    for (const item of analyzed.keyFindings) lines.push(`- ${item}`);
    lines.push('');
  }
  if (analyzed.trendNarrative) {
    lines.push('### 前回スキャンとの比較', '', analyzed.trendNarrative, '');
  }
  return lines;
}

function renderRisk(analyzed: AnalyzedReport): string[] {
  return ['## リスクの全体像', '', analyzed.riskNarrative, ''];
}

function renderActions(analyzed: AnalyzedReport): string[] {
  const lines = ['## 優先対応アクション', ''];
  if (analyzed.prioritizedActions.length === 0) {
    lines.push('現時点で対応が必要なアクションはありません。', '');
    return lines;
  }

  lines.push(
    '対応順序は「攻撃チェーンのチョークポイントか」「複数の攻撃経路に登場するか」' +
      '「CVSSスコア」の順で機械的に決定しています。同じ修正で解決するFindingは1件にまとめています。',
    '',
  );
  lines.push('| # | 対応内容 | 工数 | 解消Finding | 遮断チェーン |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const action of analyzed.prioritizedActions) {
    lines.push(
      `| ${action.order} | ${escapeMdCell(action.action)} | ${effortJa(action.effort)} | ` +
        `${action.resolves.findings.length} 件 | ${action.resolves.chains.length} 本 |`,
    );
  }
  lines.push('');

  for (const action of analyzed.prioritizedActions) {
    lines.push(`### ${action.order}. ${action.action}`);
    lines.push('');
    lines.push(`**見積もり工数**: ${effortJa(action.effort)} (\`${action.effort}\`)`);
    lines.push('');
    lines.push(action.rationale);
    lines.push('');
    if (action.resolves.findings.length > 0) {
      lines.push(
        `- 解消されるFinding: ${action.resolves.findings.map((id) => `\`${id}\``).join(', ')}`,
      );
    }
    if (action.resolves.chains.length > 0) {
      lines.push(`- 遮断される攻撃チェーン: ${action.resolves.chains.map((id) => `\`${id}\``).join(', ')}`);
    }
    lines.push('');
  }
  return lines;
}

function renderChains(chains: readonly AttackChain[]): string[] {
  if (chains.length === 0) return [];
  const sorted = [...chains].sort((a, b) => b.priorityScore - a.priorityScore);
  const lines = ['## 攻撃チェーン詳細', ''];
  lines.push(
    '個々の指摘は単独では中程度でも、連鎖すると深刻な結果に至ります。' +
      '以下は本コードベースで成立しうる攻撃の筋書きです。',
    '',
  );

  for (const chain of sorted) {
    lines.push(`### ${chain.title}`);
    lines.push('');
    lines.push(
      `\`${chain.id}\` / **優先度** ${chain.priorityScore} / ` +
        `**成立可能性** ${likelihoodJa(chain.likelihood)} / **起点** \`${chain.entryPoint}\``,
    );
    lines.push('');
    lines.push(`**最終的な影響**: ${chain.impact}`);
    lines.push('');

    lines.push('| # | 段階 | 戦術 | 技術 | 攻撃者の行動 | Finding |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const step of [...chain.steps].sort((a, b) => a.order - b.order)) {
      lines.push(
        `| ${step.order} | ${PHASE_JA[step.killChainPhase] ?? step.killChainPhase} | ` +
          `${TACTIC_JA[step.attackTactic] ?? step.attackTactic} | ${step.attackTechnique ?? '-'} | ` +
          `${escapeMdCell(step.description)} | ${step.findingId ? `\`${step.findingId}\`` : '-'} |`,
      );
    }
    lines.push('');

    const preconditions = chain.steps.flatMap((s) => s.preconditions);
    if (preconditions.length > 0) {
      lines.push('**成立の前提条件**', '');
      for (const pre of [...new Set(preconditions)]) lines.push(`- ${pre}`);
      lines.push('');
    }

    if (chain.chokePoint) {
      lines.push(
        `> **✂ チョークポイント**: \`${chain.chokePoint.findingId}\`  `,
        `> ${chain.chokePoint.rationale}`,
        '',
      );
    }
    if (chain.reasoning) {
      lines.push('<details><summary>推論の根拠</summary>', '', chain.reasoning, '', '</details>', '');
    }
  }
  return lines;
}

function renderFindingDetail(finding: Finding): string[] {
  const lines: string[] = [];
  const emoji = SEVERITY_EMOJI[finding.severity] ?? '';
  lines.push(`### ${emoji} ${finding.title}`);
  lines.push('');
  lines.push(
    `\`${finding.id}\` / **${finding.cwe}** / ${finding.category} / ` +
      `**深刻度** ${SEVERITY_LABEL_JA[finding.severity]} / **CVSS** ${(finding.cvss?.baseScore ?? 0).toFixed(1)} ` +
      `(${finding.cvss?.baseSeverity ?? 'None'}) / **確信度** ${(finding.confidence * 100).toFixed(0)}%`,
  );
  lines.push('');
  lines.push(
    `**該当箇所**: \`${finding.location.file}:${finding.location.startLine}-${finding.location.endLine}\`` +
      ` / 検出レンズ: \`${finding.lens}\` / 状態: \`${finding.status}\` (\`${finding.diffStatus}\`)`,
  );
  if (finding.cvss?.vector) {
    lines.push('');
    lines.push(`**CVSSベクタ**: \`${finding.cvss.vector}\``);
  }
  if (finding.cve) {
    lines.push('');
    lines.push(`**CVE**: ${finding.cve}`);
  }
  if (finding.affectedPackage) {
    const p = finding.affectedPackage;
    lines.push('');
    lines.push(
      `**該当パッケージ**: \`${p.name}@${p.version}\` (${p.ecosystem})` +
        (p.fixedVersion ? ` → 修正版 \`${p.fixedVersion}\`` : ' → 修正版なし'),
    );
  }
  lines.push('');

  if (finding.evidence && finding.evidence.trim() !== '') {
    lines.push('**該当コード**', '');
    lines.push(fence(finding.evidence));
    lines.push('');
  }

  lines.push('**なぜ問題か**', '', finding.reasoning || '（説明なし）', '');

  if (finding.dataFlow.length > 0) {
    lines.push('**データフロー（source → sink）**', '');
    lines.push('| # | 役割 | 位置 | 説明 |');
    lines.push('| --- | --- | --- | --- |');
    finding.dataFlow.forEach((step, index) => {
      lines.push(
        `| ${index + 1} | ${ROLE_JA[step.role] ?? step.role} | \`${step.file}:${step.line}\` | ` +
          `${escapeMdCell(step.description)} |`,
      );
    });
    lines.push('');
    lines.push('<details><summary>各ステップのコード</summary>', '');
    finding.dataFlow.forEach((step, index) => {
      lines.push(`${index + 1}. \`${step.file}:${step.line}\` — ${ROLE_JA[step.role] ?? step.role}`);
      lines.push('');
      lines.push(fence(step.code));
      lines.push('');
    });
    lines.push('</details>', '');
  } else {
    lines.push(
      '> データフローの根拠が提示されていません。外部入力からの到達性は未証明です。',
      '',
    );
  }

  lines.push('**修正方針**', '', finding.remediation || '（修正方針の記載なし）', '');

  if (finding.mergedFrom.length > 0) {
    lines.push(`統合された重複: ${finding.mergedFrom.map((f) => `\`${f}\``).join(', ')}`, '');
  }
  if (finding.references.length > 0) {
    lines.push('**参考リンク**', '');
    for (const ref of finding.references) lines.push(`- ${ref}`);
    lines.push('');
  }
  lines.push(`<sub>指紋: \`${finding.fingerprint}\` / 初回検出 ${finding.firstSeen} / 最終検出 ${finding.lastSeen}</sub>`);
  lines.push('');
  return lines;
}

function renderFindings(result: ScanResult, verbose: boolean): string[] {
  const findings = result.findings
    .filter(isActiveFinding)
    .filter((f) => verbose || f.severity !== 'info')
    .sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0) ||
        a.id.localeCompare(b.id),
    );

  const lines = ['## 個別Finding詳細', ''];
  if (findings.length === 0) {
    lines.push('報告対象のFindingはありません。', '');
    return lines;
  }

  lines.push('| 深刻度 | CVSS | CWE | 概要 | 位置 |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const f of findings) {
    lines.push(
      `| ${SEVERITY_EMOJI[f.severity] ?? ''} ${SEVERITY_LABEL_JA[f.severity]} | ${(f.cvss?.baseScore ?? 0).toFixed(1)} | ` +
        `${f.cwe} | [${escapeMdCell(truncate(f.title, 60))}](#${anchor(f.title)}) | \`${f.location.file}:${f.location.startLine}\` |`,
    );
  }
  lines.push('');

  for (const finding of findings) lines.push(...renderFindingDetail(finding));

  const fixed = result.findings.filter((f) => f.diffStatus === 'fixed');
  if (fixed.length > 0) {
    lines.push('### 前回から解消されたFinding', '');
    for (const f of fixed) {
      lines.push(`- ~~${escapeMdCell(f.title)}~~ (\`${f.cwe}\` / \`${f.location.file}\`)`);
    }
    lines.push('');
  }
  return lines;
}

function renderSbom(dependencies: readonly Dependency[], findings: readonly Finding[]): string[] {
  if (dependencies.length === 0) return [];

  // 脆弱性が紐づくパッケージを索引化
  const vulnerable = new Map<string, Finding[]>();
  for (const finding of findings) {
    const pkg = finding.affectedPackage;
    if (!pkg) continue;
    const key = `${pkg.ecosystem}:${pkg.name}`;
    const list = vulnerable.get(key);
    if (list) list.push(finding);
    else vulnerable.set(key, [finding]);
  }

  const lines = ['## 依存関係SBOM', ''];
  lines.push(
    `宣言されている依存は ${formatNumber(dependencies.length)} 件` +
      `（うち脆弱性が紐づくもの ${vulnerable.size} 件）。`,
    '',
  );

  const sorted = [...dependencies].sort((a, b) => {
    const av = vulnerable.has(`${a.ecosystem}:${a.name}`) ? 0 : 1;
    const bv = vulnerable.has(`${b.ecosystem}:${b.name}`) ? 0 : 1;
    return av - bv || a.name.localeCompare(b.name);
  });

  lines.push('| パッケージ | バージョン | エコシステム | 用途 | 宣言元 | 脆弱性 |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const dep of sorted) {
    const hits = vulnerable.get(`${dep.ecosystem}:${dep.name}`) ?? [];
    const vulnCell =
      hits.length === 0
        ? '-'
        : hits
            .map((f) => f.cve ?? f.cwe)
            .slice(0, 4)
            .join(', ');
    lines.push(
      `| \`${escapeMdCell(dep.name)}\` | ${escapeMdCell(dep.version)} | ${dep.ecosystem} | ` +
        `${dep.dev ? 'dev' : 'prod'} | \`${escapeMdCell(dep.manifest)}\` | ${vulnCell} |`,
    );
  }
  lines.push('');
  return lines;
}

function renderIssues(result: ScanResult): string[] {
  if (result.errors.length === 0 && result.context.warnings.length === 0) return [];
  const lines = ['## 実行時の問題', ''];
  if (result.errors.length > 0) {
    lines.push('本レポートは部分的な結果を含んでいる可能性があります。', '');
    lines.push('**エラー**', '');
    for (const err of result.errors) lines.push(`- ${err}`);
    lines.push('');
  }
  if (result.context.warnings.length > 0) {
    lines.push('**警告**', '');
    for (const warn of result.context.warnings) lines.push(`- ${warn}`);
    lines.push('');
  }
  return lines;
}

export function renderMarkdown(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: Pick<ReportOptions, 'verbose'>,
): string {
  const verbose = options.verbose === true;
  const hasChains = result.chains.length > 0;
  const hasFindings = result.findings.some(isActiveFinding);
  const hasDeps = result.context.dependencies.length > 0;

  const lines: string[] = [
    ...renderHeader(result, analyzed),
    '---',
    '',
    ...renderToc(hasChains, hasFindings, hasDeps),
    '---',
    '',
    ...renderExecutive(analyzed),
    ...renderRisk(analyzed),
    ...renderActions(analyzed),
    ...renderChains(result.chains),
    ...renderFindings(result, verbose),
    ...renderSbom(result.context.dependencies, result.findings),
    ...renderIssues(result),
    '---',
    '',
    `<sub>vulnscan 0.1.0 が生成 — トークン使用量: 入力 ${formatNumber(analyzed.summary.tokenUsage.input)} / ` +
      `出力 ${formatNumber(analyzed.summary.tokenUsage.output)} / ` +
      `キャッシュ読 ${formatNumber(analyzed.summary.tokenUsage.cacheRead)}</sub>`,
    '',
  ];

  return `${lines.join('\n')}`;
}
