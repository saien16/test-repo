/**
 * CLIフォーマッタ。端末に直接出す簡潔なサマリ。
 *
 * 方針:
 *   - 色付けは自前のANSI（options.color=false なら一切出さない）
 *   - 端末幅を見て折り返す。全角文字の幅も数える。
 *   - 全部は出さない。「今すぐ何をすべきか」に必要なものだけ。
 */

import type { Severity } from '../../types/context.js';
import type { AnalyzedReport, ReportOptions, ScanResult } from '../../types/report.js';
import { createStyler, type Styler } from '../ansi.js';
import { effortJa, likelihoodJa } from '../priority.js';
import {
  SEVERITY_LABEL_JA,
  SEVERITY_ORDER,
  isActiveFinding,
  severityRank,
} from '../severity.js';
import {
  displayWidth,
  formatDuration,
  formatNumber,
  padEnd,
  padStart,
  truncate,
  wrapIndented,
  wrapText,
} from '../text.js';

const MIN_WIDTH = 60;
const MAX_WIDTH = 110;

/** 端末幅を決める（取得できなければ80桁） */
export function resolveWidth(explicit?: number): number {
  const raw = explicit ?? (typeof process !== 'undefined' ? process.stdout?.columns : undefined);
  const width = typeof raw === 'number' && Number.isFinite(raw) && raw > 0 ? raw : 80;
  return Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Math.floor(width)));
}

interface Ctx {
  out: string[];
  style: Styler;
  width: number;
}

function rule(ctx: Ctx, char = '─'): void {
  ctx.out.push(ctx.style.dim(char.repeat(ctx.width)));
}

function heading(ctx: Ctx, title: string): void {
  ctx.out.push('');
  ctx.out.push(ctx.style.bold(`▍${title}`));
}

function paragraph(ctx: Ctx, text: string, indent = '  '): void {
  for (const line of wrapIndented(text, ctx.width, indent)) ctx.out.push(line);
}

/**
 * 1行目だけ prefix を付け、2行目以降は同じ幅で字下げして折り返す。
 * prefix に色が付いていても、折り返し幅の計算はANSIを除いた表示幅で行う。
 */
function pushWithPrefix(ctx: Ctx, prefix: string, text: string): void {
  const indent = ' '.repeat(displayWidth(prefix));
  const lines = wrapText(text, Math.max(8, ctx.width - displayWidth(prefix)));
  ctx.out.push(prefix + (lines[0] ?? ''));
  for (const rest of lines.slice(1)) {
    if (rest !== '') ctx.out.push(indent + rest);
  }
}

/** 深刻度別の横棒グラフ */
function severityBars(ctx: Ctx, counts: Record<Severity, number>): void {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  const max = SEVERITY_ORDER.reduce((m, s) => Math.max(m, counts[s] ?? 0), 0);
  const labelWidth = 12;
  const countWidth = 5;
  const barWidth = Math.max(10, ctx.width - labelWidth - countWidth - 6);

  for (const severity of SEVERITY_ORDER) {
    const count = counts[severity] ?? 0;
    if (count === 0 && (severity === 'info' || severity === 'low') && total > 0) continue;
    const label = padEnd(`${SEVERITY_LABEL_JA[severity]} ${severity}`, labelWidth);
    const filled = max > 0 ? Math.round((count / max) * barWidth) : 0;
    const bar = '█'.repeat(filled);
    ctx.out.push(
      `  ${ctx.style.severity(label, severity)}${padStart(String(count), countWidth)}  ` +
        ctx.style.severity(bar, severity),
    );
  }
}

function renderHeader(ctx: Ctx, result: ScanResult): void {
  const { style } = ctx;
  const title = ' vulnscan スキャン結果 ';
  const sideWidth = Math.max(0, ctx.width - displayWidth(title));
  const left = '━'.repeat(Math.floor(sideWidth / 2));
  const right = '━'.repeat(sideWidth - Math.floor(sideWidth / 2));
  ctx.out.push(style.apply(`${left}${title}${right}`, 'cyan', 'bold'));

  const git = result.context.git;
  const meta: string[] = [`対象: ${result.context.repoRoot}`];
  if (git) meta.push(`ブランチ: ${git.branch}@${truncate(git.headSha, 8, '')}`);
  ctx.out.push(style.dim(truncate(meta.join('  '), ctx.width)));

  const s = result.summary;
  ctx.out.push(
    style.dim(
      truncate(
        `ファイル ${formatNumber(s.filesScanned)} / 所要 ${formatDuration(s.durationMs)} / ` +
          `依存 ${formatNumber(result.context.dependencies.length)} / 入口 ${formatNumber(result.context.entryPoints.length)}`,
        ctx.width,
      ),
    ),
  );
}

function renderSummary(ctx: Ctx, result: ScanResult): void {
  const s = result.summary;
  heading(ctx, '深刻度別の検出状況');

  if (s.totalFindings === 0) {
    ctx.out.push(`  ${ctx.style.green('✔ 対応を要する脆弱性は検出されませんでした')}`);
  } else {
    severityBars(ctx, s.bySeverity);
  }

  const bits = [
    `合計 ${formatNumber(s.totalFindings)} 件`,
    `攻撃チェーン ${formatNumber(s.chainCount)} 本`,
    `最大CVSS ${s.maxCvssScore.toFixed(1)}`,
  ];
  if (s.suppressedCount > 0) bits.push(`抑制 ${formatNumber(s.suppressedCount)} 件`);
  ctx.out.push(`  ${ctx.style.dim(truncate(bits.join('  |  '), ctx.width - 2))}`);

  if (s.newCount > 0 || s.fixedCount > 0 || s.persistentCount > 0) {
    const diff = [
      ctx.style.yellow(`新規 ${s.newCount}`),
      ctx.style.dim(`継続 ${s.persistentCount}`),
      ctx.style.green(`解消 ${s.fixedCount}`),
    ].join('  |  ');
    ctx.out.push(`  ${diff}`);
  }
}

function renderNarrative(ctx: Ctx, analyzed: AnalyzedReport): void {
  heading(ctx, 'エグゼクティブサマリ');
  paragraph(ctx, analyzed.executiveSummary);

  if (analyzed.keyFindings.length > 0) {
    heading(ctx, '主な所見');
    for (const item of analyzed.keyFindings) {
      pushWithPrefix(ctx, `  ${ctx.style.cyan('•')} `, item);
    }
  }

  if (analyzed.trendNarrative) {
    heading(ctx, '前回との比較');
    paragraph(ctx, analyzed.trendNarrative);
  }
}

function renderChains(ctx: Ctx, result: ScanResult, limit: number): void {
  if (result.chains.length === 0) return;
  const chains = [...result.chains].sort((a, b) => b.priorityScore - a.priorityScore);
  heading(ctx, `上位の攻撃チェーン（全 ${chains.length} 本）`);

  for (const chain of chains.slice(0, limit)) {
    const score = padStart(String(chain.priorityScore), 3);
    const severity: Severity =
      chain.priorityScore >= 80 ? 'critical' : chain.priorityScore >= 60 ? 'high' : 'medium';
    ctx.out.push(
      `  ${ctx.style.severity(`[${score}]`, severity)} ${ctx.style.bold(truncate(chain.title, ctx.width - 12))}`,
    );
    ctx.out.push(
      ctx.style.dim(
        truncate(
          `        起点 ${chain.entryPoint} / 成立可能性 ${likelihoodJa(chain.likelihood)} / ${chain.steps.length} ステップ`,
          ctx.width,
        ),
      ),
    );
    for (const line of wrapIndented(`影響: ${chain.impact}`, ctx.width, '        ')) {
      ctx.out.push(line);
    }
    if (chain.chokePoint) {
      ctx.out.push(
        ctx.style.yellow(
          truncate(`        ✂ チョークポイント: ${chain.chokePoint.findingId}`, ctx.width),
        ),
      );
    }
  }
  if (chains.length > limit) {
    ctx.out.push(ctx.style.dim(`  … 他 ${chains.length - limit} 本（詳細は markdown/html 出力を参照）`));
  }
}

function renderActions(ctx: Ctx, analyzed: AnalyzedReport, limit: number): void {
  const actions = analyzed.prioritizedActions;
  if (actions.length === 0) return;
  heading(ctx, '優先対応アクション');

  for (const action of actions.slice(0, limit)) {
    const effortColor: Severity =
      action.effort === 'low' ? 'low' : action.effort === 'medium' ? 'medium' : 'high';
    const head = `  ${ctx.style.bold(`${action.order}.`)} ${ctx.style.severity(`[工数:${effortJa(action.effort)}]`, effortColor)} `;
    pushWithPrefix(ctx, head, action.action);

    const resolves: string[] = [`Finding ${action.resolves.findings.length} 件`];
    if (action.resolves.chains.length > 0) {
      resolves.push(`チェーン ${action.resolves.chains.length} 本を遮断`);
    }
    ctx.out.push(ctx.style.dim(truncate(`     └ 解消: ${resolves.join(' / ')}`, ctx.width)));
  }
  if (actions.length > limit) {
    ctx.out.push(ctx.style.dim(`  … 他 ${actions.length - limit} 件`));
  }
}

function renderFindings(ctx: Ctx, result: ScanResult, verbose: boolean): void {
  const findings = result.findings
    .filter(isActiveFinding)
    .filter((f) => verbose || f.severity !== 'info')
    .sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0) ||
        a.id.localeCompare(b.id),
    );
  if (findings.length === 0) return;

  const limit = verbose ? findings.length : 10;
  heading(ctx, `検出一覧${verbose ? '' : `（上位 ${Math.min(limit, findings.length)} 件）`}`);

  for (const finding of findings.slice(0, limit)) {
    const badge = ctx.style.badge(` ${padEnd(SEVERITY_LABEL_JA[finding.severity], 4)}`, finding.severity);
    const loc = `${finding.location.file}:${finding.location.startLine}`;
    const score = (finding.cvss?.baseScore ?? 0).toFixed(1);
    const prefix = `  ${badge} ${ctx.style.dim(padStart(score, 4))} `;
    const budget = ctx.width - displayWidth(prefix) - 1;
    ctx.out.push(prefix + truncate(finding.title, Math.max(20, budget)));
    ctx.out.push(
      ctx.style.dim(truncate(`        ${finding.cwe}  ${loc}  [${finding.id}] ${finding.diffStatus}`, ctx.width)),
    );
  }
  if (findings.length > limit) {
    ctx.out.push(ctx.style.dim(`  … 他 ${findings.length - limit} 件（--verbose で全件表示）`));
  }
}

function renderErrors(ctx: Ctx, result: ScanResult): void {
  const warnings = result.context.warnings;
  if (result.errors.length === 0 && warnings.length === 0) return;

  heading(ctx, '実行時の問題（結果が部分的な可能性）');
  for (const err of result.errors.slice(0, 10)) {
    for (const line of wrapIndented(`✖ ${err}`, ctx.width, '  ')) ctx.out.push(ctx.style.red(line));
  }
  for (const warn of warnings.slice(0, 5)) {
    for (const line of wrapIndented(`! ${warn}`, ctx.width, '  ')) ctx.out.push(ctx.style.yellow(line));
  }
}

function renderFooter(ctx: Ctx, result: ScanResult): void {
  const t = result.summary.tokenUsage;
  ctx.out.push('');
  rule(ctx);
  ctx.out.push(
    ctx.style.dim(
      truncate(
        `トークン: 入力 ${formatNumber(t.input)} / 出力 ${formatNumber(t.output)} / ` +
          `キャッシュ読 ${formatNumber(t.cacheRead)} 書 ${formatNumber(t.cacheWrite)}`,
        ctx.width,
      ),
    ),
  );
}

export interface CliRenderOptions extends Pick<ReportOptions, 'color' | 'verbose'> {
  /** テストから幅を固定するための上書き */
  width?: number;
}

export function renderCli(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: CliRenderOptions,
): string {
  const ctx: Ctx = {
    out: [],
    style: createStyler(options.color === true),
    width: resolveWidth(options.width),
  };

  renderHeader(ctx, result);
  renderSummary(ctx, result);
  renderNarrative(ctx, analyzed);
  renderChains(ctx, result, options.verbose ? 10 : 3);
  renderActions(ctx, analyzed, options.verbose ? 25 : 5);
  renderFindings(ctx, result, options.verbose === true);
  renderErrors(ctx, result);
  renderFooter(ctx, result);

  return `${ctx.out.join('\n')}\n`;
}
