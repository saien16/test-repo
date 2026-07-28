/**
 * Markdownフォーマッタ。人間向けの詳細レポート。
 *
 * 構成:
 *   エグゼクティブサマリ → リスク全体像 → 優先対応アクション
 *   → 攻撃チェーン詳細 → 個別Finding詳細 → 依存関係SBOM
 *
 * 「読み物として成立させる」ことを優先し、表と散文を織り交ぜる。
 *
 * セキュリティ上の前提:
 *   ここに流れ込む文字列（Findingのタイトル・ファイルパス・依存パッケージ名・
 *   LLMの生成文など）はスキャン対象リポジトリ由来の未信頼入力である。
 *   本フォーマッタは `<details>` などの生HTMLを出力しており、HTMLを有効にした
 *   レンダラで表示される前提なので、埋め込む値は必ずエスケープする。
 *     - 本文        : escapeMdText（`< > &` を実体参照へ）
 *     - 表のセル    : escapeMdCell（加えて改行と `|`）
 *     - コードスパン: escapeMdCode / escapeMdCodeCell（加えてバッククォート）
 *     - URL         : isSafeUrl で `^https?://` を検証してから出す
 *   フェンス付きコードブロック(fence)はレンダラがHTMLとして解釈しないため、
 *   フェンス記号が壊されないことだけを担保する。
 */

import type { Dependency } from '../../types/context.js';
import type { Finding } from '../../types/finding.js';
import type { AttackChain } from '../../types/killchain.js';
import type { AnalyzedReport, ReportOptions, ScanResult } from '../../types/report.js';
import { buildSbomIndex, reportableFindings, sbomPackageKey } from '../collect.js';
import { PHASE_JA, ROLE_JA, TACTIC_JA, effortJa, likelihoodJa } from '../labels.js';
import { SEVERITY_LABEL_JA, SEVERITY_ORDER, isActiveFinding } from '../severity.js';
import {
  escapeMdCell,
  escapeMdCode,
  escapeMdCodeCell,
  escapeMdInline,
  escapeMdText,
  formatDateTime,
  formatDuration,
  formatNumber,
  isSafeUrl,
  truncate,
} from '../text.js';

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
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
    `> **対象**: \`${escapeMdCode(result.context.repoRoot)}\`` +
      (git
        ? ` / **ブランチ**: \`${escapeMdCode(git.branch)}\` ` +
          `(\`${escapeMdCode(truncate(git.headSha, 12, ''))}\`)`
        : ''),
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
  // 文章にはFindingのタイトルなど未信頼の文字列が織り込まれている
  const lines = ['## エグゼクティブサマリ', '', escapeMdText(analyzed.executiveSummary), ''];
  if (analyzed.keyFindings.length > 0) {
    lines.push('### 今回の重要な所見', '');
    for (const item of analyzed.keyFindings) lines.push(`- ${escapeMdText(item)}`);
    lines.push('');
  }
  if (analyzed.trendNarrative) {
    lines.push('### 前回スキャンとの比較', '', escapeMdText(analyzed.trendNarrative), '');
  }
  return lines;
}

function renderRisk(analyzed: AnalyzedReport): string[] {
  return ['## リスクの全体像', '', escapeMdText(analyzed.riskNarrative), ''];
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
    lines.push(`### ${action.order}. ${escapeMdText(action.action)}`);
    lines.push('');
    lines.push(`**見積もり工数**: ${effortJa(action.effort)} (\`${escapeMdCode(action.effort)}\`)`);
    lines.push('');
    lines.push(escapeMdText(action.rationale));
    lines.push('');
    if (action.resolves.findings.length > 0) {
      lines.push(
        `- 解消されるFinding: ${action.resolves.findings
          .map((id) => `\`${escapeMdCode(id)}\``)
          .join(', ')}`,
      );
    }
    if (action.resolves.chains.length > 0) {
      lines.push(
        `- 遮断される攻撃チェーン: ${action.resolves.chains
          .map((id) => `\`${escapeMdCode(id)}\``)
          .join(', ')}`,
      );
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
    lines.push(`### ${escapeMdText(chain.title)}`);
    lines.push('');
    lines.push(
      `\`${escapeMdCode(chain.id)}\` / **優先度** ${chain.priorityScore} / ` +
        `**成立可能性** ${likelihoodJa(chain.likelihood)} / ` +
        `**起点** \`${escapeMdCode(chain.entryPoint)}\``,
    );
    lines.push('');
    lines.push(`**最終的な影響**: ${escapeMdText(chain.impact)}`);
    lines.push('');

    lines.push('| # | 段階 | 戦術 | 技術 | 攻撃者の行動 | Finding |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const step of [...chain.steps].sort((a, b) => a.order - b.order)) {
      lines.push(
        `| ${step.order} | ${escapeMdCell(PHASE_JA[step.killChainPhase] ?? step.killChainPhase)} | ` +
          `${escapeMdCell(TACTIC_JA[step.attackTactic] ?? step.attackTactic)} | ` +
          `${escapeMdCell(step.attackTechnique ?? '-')} | ` +
          `${escapeMdCell(step.description)} | ` +
          `${step.findingId ? `\`${escapeMdCodeCell(step.findingId)}\`` : '-'} |`,
      );
    }
    lines.push('');

    const preconditions = chain.steps.flatMap((s) => s.preconditions);
    if (preconditions.length > 0) {
      lines.push('**成立の前提条件**', '');
      for (const pre of [...new Set(preconditions)]) lines.push(`- ${escapeMdText(pre)}`);
      lines.push('');
    }

    if (chain.chokePoint) {
      lines.push(
        `> **✂ チョークポイント**: \`${escapeMdCode(chain.chokePoint.findingId)}\`  `,
        // 引用ブロックから抜け出させないため改行は潰す
        `> ${escapeMdText(chain.chokePoint.rationale).replace(/\r?\n/g, ' ')}`,
        '',
      );
    }
    if (chain.reasoning) {
      lines.push(
        '<details><summary>推論の根拠</summary>',
        '',
        escapeMdText(chain.reasoning),
        '',
        '</details>',
        '',
      );
    }
  }
  return lines;
}

function renderFindingDetail(finding: Finding): string[] {
  const lines: string[] = [];
  const emoji = SEVERITY_EMOJI[finding.severity] ?? '';
  lines.push(`### ${emoji} ${escapeMdText(finding.title)}`);
  lines.push('');
  lines.push(
    `\`${escapeMdCode(finding.id)}\` / **${escapeMdText(finding.cwe)}** / ` +
      `${escapeMdText(finding.category)} / ` +
      `**深刻度** ${SEVERITY_LABEL_JA[finding.severity]} / **CVSS** ${(finding.cvss?.baseScore ?? 0).toFixed(1)} ` +
      `(${escapeMdText(finding.cvss?.baseSeverity ?? 'None')}) / **確信度** ${(finding.confidence * 100).toFixed(0)}%`,
  );
  lines.push('');
  lines.push(
    `**該当箇所**: \`${escapeMdCode(finding.location.file)}:${finding.location.startLine}-${finding.location.endLine}\`` +
      ` / 検出レンズ: \`${escapeMdCode(finding.lens)}\`` +
      ` / 状態: \`${escapeMdCode(finding.status)}\` (\`${escapeMdCode(finding.diffStatus)}\`)`,
  );
  if (finding.cvss?.vector) {
    lines.push('');
    lines.push(`**CVSSベクタ**: \`${escapeMdCode(finding.cvss.vector)}\``);
  }
  if (finding.cve) {
    lines.push('');
    lines.push(`**CVE**: ${escapeMdText(finding.cve)}`);
  }
  if (finding.affectedPackage) {
    const p = finding.affectedPackage;
    lines.push('');
    lines.push(
      `**該当パッケージ**: \`${escapeMdCode(p.name)}@${escapeMdCode(p.version)}\` ` +
        `(${escapeMdText(p.ecosystem)})` +
        (p.fixedVersion ? ` → 修正版 \`${escapeMdCode(p.fixedVersion)}\`` : ' → 修正版なし'),
    );
  }
  lines.push('');

  if (finding.evidence && finding.evidence.trim() !== '') {
    lines.push('**該当コード**', '');
    lines.push(fence(finding.evidence));
    lines.push('');
  }

  lines.push('**なぜ問題か**', '', escapeMdText(finding.reasoning || '（説明なし）'), '');

  if (finding.dataFlow.length > 0) {
    lines.push('**データフロー（source → sink）**', '');
    lines.push('| # | 役割 | 位置 | 説明 |');
    lines.push('| --- | --- | --- | --- |');
    finding.dataFlow.forEach((step, index) => {
      lines.push(
        `| ${index + 1} | ${escapeMdCell(ROLE_JA[step.role] ?? step.role)} | ` +
          `\`${escapeMdCodeCell(step.file)}:${step.line}\` | ` +
          `${escapeMdCell(step.description)} |`,
      );
    });
    lines.push('');
    lines.push('<details><summary>各ステップのコード</summary>', '');
    finding.dataFlow.forEach((step, index) => {
      lines.push(
        `${index + 1}. \`${escapeMdCode(step.file)}:${step.line}\` — ` +
          `${escapeMdText(ROLE_JA[step.role] ?? step.role)}`,
      );
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

  lines.push('**修正方針**', '', escapeMdText(finding.remediation || '（修正方針の記載なし）'), '');

  if (finding.mergedFrom.length > 0) {
    lines.push(
      `統合された重複: ${finding.mergedFrom.map((f) => `\`${escapeMdCode(f)}\``).join(', ')}`,
      '',
    );
  }
  if (finding.references.length > 0) {
    lines.push('**参考リンク**', '');
    for (const ref of finding.references) {
      // http(s) 以外（javascript: など）はリンクにせず、素のテキストとして出す
      lines.push(isSafeUrl(ref) ? `- <${escapeMdText(ref)}>` : `- ${escapeMdText(ref)}`);
    }
    lines.push('');
  }
  lines.push(
    `<sub>指紋: \`${escapeMdCode(finding.fingerprint)}\` / ` +
      `初回検出 ${escapeMdText(finding.firstSeen)} / 最終検出 ${escapeMdText(finding.lastSeen)}</sub>`,
  );
  lines.push('');
  return lines;
}

function renderFindings(result: ScanResult, verbose: boolean): string[] {
  const findings = reportableFindings(result.findings, verbose);

  const lines = ['## 個別Finding詳細', ''];
  if (findings.length === 0) {
    lines.push('報告対象のFindingはありません。', '');
    return lines;
  }

  lines.push('| 深刻度 | CVSS | CWE | 概要 | 位置 |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const f of findings) {
    // リンクテキストは `[` `]` も無効化しないとリンク記法を抜け出せる
    const label = escapeMdCell(escapeMdInline(truncate(f.title, 60)));
    lines.push(
      `| ${SEVERITY_EMOJI[f.severity] ?? ''} ${SEVERITY_LABEL_JA[f.severity]} | ${(f.cvss?.baseScore ?? 0).toFixed(1)} | ` +
        `${escapeMdCell(f.cwe)} | [${label}](#${anchor(f.title)}) | ` +
        `\`${escapeMdCodeCell(f.location.file)}:${f.location.startLine}\` |`,
    );
  }
  lines.push('');

  for (const finding of findings) lines.push(...renderFindingDetail(finding));

  const fixed = result.findings.filter((f) => f.diffStatus === 'fixed');
  if (fixed.length > 0) {
    lines.push('### 前回から解消されたFinding', '');
    for (const f of fixed) {
      lines.push(
        `- ~~${escapeMdCell(f.title)}~~ ` +
          `(\`${escapeMdCode(f.cwe)}\` / \`${escapeMdCode(f.location.file)}\`)`,
      );
    }
    lines.push('');
  }
  return lines;
}

function renderSbom(dependencies: readonly Dependency[], findings: readonly Finding[]): string[] {
  if (dependencies.length === 0) return [];

  // 脆弱性が紐づくパッケージの索引と並び順（html.ts と共有）
  const { vulnerable, sorted } = buildSbomIndex(dependencies, findings);

  const lines = ['## 依存関係SBOM', ''];
  lines.push(
    `宣言されている依存は ${formatNumber(dependencies.length)} 件` +
      `（うち脆弱性が紐づくもの ${vulnerable.size} 件）。`,
    '',
  );

  lines.push('| パッケージ | バージョン | エコシステム | 用途 | 宣言元 | 脆弱性 |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const dep of sorted) {
    const hits = vulnerable.get(sbomPackageKey(dep)) ?? [];
    const vulnCell =
      hits.length === 0
        ? '-'
        : hits
            .map((f) => escapeMdCell(f.cve ?? f.cwe))
            .slice(0, 4)
            .join(', ');
    // 依存パッケージ名・バージョンは package.json 由来（＝攻撃者が制御しうる）
    lines.push(
      `| \`${escapeMdCodeCell(dep.name)}\` | ${escapeMdCell(dep.version)} | ` +
        `${escapeMdCell(dep.ecosystem)} | ` +
        `${dep.dev ? 'dev' : 'prod'} | \`${escapeMdCodeCell(dep.manifest)}\` | ${vulnCell} |`,
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
    // エラー文にはファイルパスなど未信頼の文字列が混ざる
    for (const err of result.errors) lines.push(`- ${escapeMdText(err)}`);
    lines.push('');
  }
  if (result.context.warnings.length > 0) {
    lines.push('**警告**', '');
    for (const warn of result.context.warnings) lines.push(`- ${escapeMdText(warn)}`);
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
    `<sub>GRIMOIRE 0.1.0 が生成 — トークン使用量: 入力 ${formatNumber(analyzed.summary.tokenUsage.input)} / ` +
      `出力 ${formatNumber(analyzed.summary.tokenUsage.output)} / ` +
      `キャッシュ読 ${formatNumber(analyzed.summary.tokenUsage.cacheRead)}</sub>`,
    '',
  ];

  return `${lines.join('\n')}`;
}
