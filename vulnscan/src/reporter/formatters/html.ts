/**
 * HTMLフォーマッタ。1ファイルで完結する詳細レポート。
 *
 * 制約:
 *   - 外部CSS/JS/フォント/画像に一切依存しない（すべてインライン）
 *   - `prefers-color-scheme` でダーク／ライト両対応
 *   - テーブルは横スクロール可能なコンテナに入れ、ページ本体は横スクロールしない
 *   - 詳細は <details> で折りたたむ（JSなしで動く）
 */

import type { Dependency } from '../../types/context.js';
import type { Finding } from '../../types/finding.js';
import type { AttackChain } from '../../types/killchain.js';
import type { AnalyzedReport, ReportOptions, ScanResult } from '../../types/report.js';
import { buildSbomIndex, reportableFindings, sbomPackageKey } from '../collect.js';
import { PHASE_JA, ROLE_JA, TACTIC_JA, effortJa, likelihoodJa } from '../labels.js';
import {
  SEVERITY_HEX,
  SEVERITY_HEX_DARK,
  SEVERITY_LABEL_JA,
  SEVERITY_ORDER,
} from '../severity.js';
import {
  escapeHtml,
  formatDateTime,
  formatDuration,
  formatNumber,
  isSafeUrl,
  truncate,
} from '../text.js';
import { ARCHITECTURE_MAP_STYLE, renderArchitectureMap } from './architecture-map.js';
import { scrollTable } from '../html-util.js';
import { buildTargetSummary, formatBytes, formatTimestamp } from '../target.js';

/** 段落分割（空行区切りを <p> にする） */
function paragraphs(text: string): string {
  const blocks = text
    .split(/\n\s*\n/)
    .map((b) => b.trim())
    .filter((b) => b !== '');
  if (blocks.length === 0) return '';
  return blocks.map((b) => `<p>${escapeHtml(b).replace(/\n/g, '<br>')}</p>`).join('\n');
}

function badge(severity: Finding['severity']): string {
  return `<span class="badge sev-${severity}">${escapeHtml(SEVERITY_LABEL_JA[severity])}</span>`;
}

function code(text: string): string {
  return `<pre class="code"><code>${escapeHtml(text.replace(/\s+$/u, ''))}</code></pre>`;
}

/** 見出しに使う安定したID */
function idFor(prefix: string, key: string): string {
  const safe = key.replace(/[^A-Za-z0-9_-]/g, '-').replace(/-+/g, '-');
  return `${prefix}-${safe}`;
}

/**
 * Finding へのリンク。
 * verbose でない場合など、詳細を描画していないFindingへはリンクを張らない
 * （リンク切れのアンカーを作らないため）。
 */
function linkFinding(id: string, rendered: ReadonlySet<string>, label?: string): string {
  const text = `<code>${escapeHtml(label ?? id)}</code>`;
  return rendered.has(id) ? `<a href="#${idFor('finding', id)}">${text}</a>` : text;
}

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-2: #f0f2f5;
  --text: #1b1f24;
  --text-dim: #5b6470;
  --border: #d8dde3;
  --accent: #1d4ed8;
  --ok: #167a4a;
  --sev-critical: ${SEVERITY_HEX.critical};
  --sev-high: ${SEVERITY_HEX.high};
  --sev-medium: ${SEVERITY_HEX.medium};
  --sev-low: ${SEVERITY_HEX.low};
  --sev-info: ${SEVERITY_HEX.info};
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1319;
    --surface: #161b22;
    --surface-2: #1d242e;
    --text: #e5e9ef;
    --text-dim: #9aa4b2;
    --border: #2b333f;
    --accent: #7aa2ff;
    --ok: #4ec98a;
    --sev-critical: ${SEVERITY_HEX_DARK.critical};
    --sev-high: ${SEVERITY_HEX_DARK.high};
    --sev-medium: ${SEVERITY_HEX_DARK.medium};
    --sev-low: ${SEVERITY_HEX_DARK.low};
    --sev-info: ${SEVERITY_HEX_DARK.info};
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: "Hiragino Kaku Gothic ProN", "Yu Gothic", Meiryo, system-ui, -apple-system,
    "Segoe UI", Roboto, sans-serif;
  line-height: 1.8;
  font-size: 16px;
  overflow-x: hidden;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 24px 16px 96px; }
h1, h2, h3, h4 { line-height: 1.4; }
h1 { font-size: 1.9rem; margin: 0 0 8px; }
h2 {
  font-size: 1.4rem; margin: 48px 0 12px; padding-bottom: 8px;
  border-bottom: 2px solid var(--border);
}
h3 { font-size: 1.12rem; margin: 32px 0 8px; }
h4 { font-size: 1rem; margin: 20px 0 6px; color: var(--text-dim); }
p { margin: 0 0 12px; }
a { color: var(--accent); }
.meta { color: var(--text-dim); font-size: 0.85rem; margin: 0 0 4px; word-break: break-word; }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 18px; margin: 16px 0;
}
.target-facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 18px; margin: 0; font-size: 0.9rem; }
.target-facts dt { color: var(--text-dim); white-space: nowrap; }
.target-facts dd { margin: 0; word-break: break-word; }
@media (max-width: 520px) { .target-facts { grid-template-columns: 1fr; gap: 0 0; } .target-facts dd { margin: 0 0 8px; } }
.readme-quote {
  margin: 12px 0; padding: 14px 18px; border-left: 4px solid var(--teal, #0E9E78);
  background: var(--surface); border-radius: 0 8px 8px 0;
}
.readme-quote p { margin: 0 0 8px; }
/* ページ末尾の footer 用スタイル（余白64px＋上罫線）を引用内で打ち消す */
.readme-quote footer { font-size: 0.8rem; color: var(--text-dim); margin-top: 0; padding-top: 0; border-top: 0; }
.inferred-note { font-size: 0.88rem; color: var(--text-dim); margin: 8px 0 0; }
.file-list { font-size: 0.88rem; }
.dir-child { padding-left: 1.6em; color: var(--text-dim); display: inline-block; }
.dir-table td:not(:first-child), .dir-table th:not(:first-child) { text-align: right; font-variant-numeric: tabular-nums; }

.stat-grid {
  display: grid; gap: 10px; margin: 20px 0;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
}
.stat {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
}
.stat .label { font-size: 0.75rem; color: var(--text-dim); display: block; }
.stat .value { font-size: 1.5rem; font-weight: 700; font-variant-numeric: tabular-nums; }
/* 走査が完走しなかったことの注記。統計グリッドと同じ視野に入る位置に置く。
   罫線の太い左枠で「読み飛ばせない」見た目にしてある。 */
.health-notice {
  border: 1px solid var(--border); border-left: 5px solid var(--sev-high);
  background: var(--surface); border-radius: 10px;
  padding: 12px 16px; margin: 20px 0;
}
.health-notice.health-failed { border-left-color: var(--sev-critical); }
.health-notice h3 { margin: 0 0 6px; font-size: 1.05rem; color: var(--sev-high); }
.health-notice.health-failed h3 { color: var(--sev-critical); }
.health-notice p:last-child { margin-bottom: 0; }
.bars { margin: 12px 0; }
.bar-row { display: grid; grid-template-columns: 108px 44px 1fr; align-items: center; gap: 8px; margin: 4px 0; }
.bar-row .name { font-size: 0.85rem; }
.bar-row .num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
.bar { height: 10px; border-radius: 5px; background: var(--surface-2); overflow: hidden; }
.bar > span { display: block; height: 100%; border-radius: 5px; }
.badge {
  display: inline-block; padding: 1px 8px; border-radius: 999px;
  font-size: 0.75rem; font-weight: 700; color: #fff; white-space: nowrap;
}
.sev-critical { background: var(--sev-critical); }
.sev-high { background: var(--sev-high); }
.sev-medium { background: var(--sev-medium); }
.sev-low { background: var(--sev-low); }
.sev-info { background: var(--sev-info); }
.table-scroll {
  overflow-x: auto; -webkit-overflow-scrolling: touch;
  border: 1px solid var(--border); border-radius: 10px; margin: 12px 0;
  max-width: 100%;
}
table { border-collapse: collapse; width: 100%; min-width: 520px; font-size: 0.88rem; background: var(--surface); }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--surface-2); font-size: 0.8rem; color: var(--text-dim); white-space: nowrap; }
tr:last-child td { border-bottom: none; }
td code, th code { white-space: nowrap; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85em; background: var(--surface-2);
  padding: 1px 5px; border-radius: 4px;
}
pre.code {
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; overflow-x: auto; max-width: 100%; margin: 8px 0;
}
pre.code code { background: none; padding: 0; font-size: 0.82rem; line-height: 1.6; }
details {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 10px 14px; margin: 12px 0;
}
details > summary { cursor: pointer; font-weight: 600; list-style: revert; }
details[open] > summary { margin-bottom: 10px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
blockquote {
  margin: 12px 0; padding: 10px 16px; border-left: 4px solid var(--accent);
  background: var(--surface-2); border-radius: 0 8px 8px 0;
}
ul.toc { list-style: none; padding: 0; margin: 0; }
ul.toc li { margin: 4px 0; }
ul.toc li.sub { padding-left: 20px; font-size: 0.9rem; color: var(--text-dim); }
.finding { border-left: 4px solid var(--border); padding-left: 14px; margin: 28px 0; }
.finding.sev-l-critical { border-left-color: var(--sev-critical); }
.finding.sev-l-high { border-left-color: var(--sev-high); }
.finding.sev-l-medium { border-left-color: var(--sev-medium); }
.finding.sev-l-low { border-left-color: var(--sev-low); }
.finding.sev-l-info { border-left-color: var(--sev-info); }
.tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 12px; }
.tag {
  font-size: 0.75rem; background: var(--surface-2); border: 1px solid var(--border);
  border-radius: 6px; padding: 1px 8px; color: var(--text-dim); word-break: break-all;
}
.ok { color: var(--ok); font-weight: 700; }
.action-order {
  display: inline-flex; align-items: center; justify-content: center;
  width: 26px; height: 26px; border-radius: 50%;
  background: var(--accent); color: #fff; font-size: 0.85rem; font-weight: 700; margin-right: 8px;
}
footer { margin-top: 64px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.8rem; }
@media (max-width: 600px) {
  body { font-size: 15px; }
  .wrap { padding: 16px 12px 64px; }
  .bar-row { grid-template-columns: 88px 36px 1fr; }
}
`;

function renderHeader(result: ScanResult, analyzed: AnalyzedReport): string {
  const s = analyzed.summary;
  const git = result.context.git;
  const out: string[] = [];

  out.push('<header>');
  out.push('<h1>セキュリティスキャンレポート</h1>');
  out.push(`<p class="meta">対象: <code>${escapeHtml(result.context.repoRoot)}</code>${
    git ? ` / ブランチ: <code>${escapeHtml(git.branch)}</code> (<code>${escapeHtml(truncate(git.headSha, 12, ''))}</code>)` : ''
  }</p>`);
  out.push(
    `<p class="meta">実施日時: ${escapeHtml(formatDateTime(result.context.scannedAt))} / 所要: ${escapeHtml(formatDuration(s.durationMs))} / ` +
      `走査 ${formatNumber(s.filesScanned)} ファイル / 依存 ${formatNumber(result.context.dependencies.length)} 件 / 入口 ${formatNumber(result.context.entryPoints.length)} 箇所</p>`,
  );
  out.push('</header>');

  out.push('<div class="stat-grid">');
  out.push(`<div class="stat"><span class="label">検出件数</span><span class="value">${formatNumber(s.totalFindings)}</span></div>`);
  out.push(`<div class="stat"><span class="label">最大CVSS</span><span class="value">${s.maxCvssScore.toFixed(1)}</span></div>`);
  out.push(`<div class="stat"><span class="label">攻撃チェーン</span><span class="value">${formatNumber(s.chainCount)}</span></div>`);
  out.push(`<div class="stat"><span class="label">新規</span><span class="value">${formatNumber(s.newCount)}</span></div>`);
  out.push(`<div class="stat"><span class="label">解消</span><span class="value">${formatNumber(s.fixedCount)}</span></div>`);
  out.push(`<div class="stat"><span class="label">抑制</span><span class="value">${formatNumber(s.suppressedCount)}</span></div>`);
  out.push('</div>');

  const max = SEVERITY_ORDER.reduce((m, sev) => Math.max(m, s.bySeverity[sev] ?? 0), 0);
  out.push('<div class="bars">');
  for (const severity of SEVERITY_ORDER) {
    const count = s.bySeverity[severity] ?? 0;
    const pct = max > 0 ? Math.round((count / max) * 100) : 0;
    out.push(
      '<div class="bar-row">' +
        `<span class="name">${badge(severity)}</span>` +
        `<span class="num">${count}</span>` +
        `<span class="bar"><span class="sev-${severity}" style="width:${pct}%"></span></span>` +
        '</div>',
    );
  }
  out.push('</div>');
  return out.join('\n');
}

/**
 * 走査が完走しなかったことを、統計グリッドの直後・目次より前に出す。
 *
 * HTMLレポートは「検出件数 0」の大きな数字が最初に目に入る構成なので、
 * その意味を確定させる注記を同じスクロール位置に置く必要がある。
 */
function renderHealthNotice(result: ScanResult): string {
  const health = result.health;
  if (health.zeroFindingsIsMeaningful) return '';

  const a = health.analysis;
  const cls = health.level === 'failed' ? 'health-failed' : 'health-degraded';
  const title =
    health.level === 'failed' ? 'このスキャンは完走していません' : 'このスキャンは部分的です';

  return [
    `<div class="health-notice ${cls}">`,
    `<h3>⚠ ${escapeHtml(title)}</h3>`,
    `<p>${escapeHtml(health.reason)}</p>`,
    `<p class="meta">分析タスク: 成功 ${a.succeeded} / 失敗 ${a.failed} / 拒否 ${a.refused} / 全 ${a.total}</p>`,
    '<p>検出件数の多寡にかかわらず、この結果を「脆弱性が無い」ことの根拠には使えません。</p>',
    '</div>',
  ].join('\n');
}

/**
 * 何を走査したのかの節。検出内容より前に置く。
 *
 * README からの引用（事実）と様式の推測を、別々の見た目で示す。
 * 引用は出所つき、推測は確信度つきで、混ぜない。
 *
 * 事実の一覧は表ではなく dl で組む。表にすると全テーブル共通の
 * 横スクロール容器（scrollTable）に載せる必要があり、
 * 見出し1列＋値1列の短い並びには過剰なため。
 */
function renderTarget(result: ScanResult): string {
  const t = buildTargetSummary(result.context, result.summary.durationMs, result.architecture);
  const out: string[] = [];
  out.push('<section id="target">');
  out.push('<h2>走査対象</h2>');

  out.push('<div class="card">');
  out.push('<dl class="target-facts">');
  const row = (k: string, v: string): void => {
    out.push(`<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`);
  };
  row('対象ディレクトリ', `<code>${escapeHtml(t.root)}</code>`);
  row(
    '実施日時',
    `${escapeHtml(formatTimestamp(t.scannedAt))}<span class="dim">（所要 ${escapeHtml(formatDuration(t.durationMs))}）</span>`,
  );
  if (t.git) {
    row(
      'Git',
      `<code>${escapeHtml(t.git.branch)}</code> @ <code>${escapeHtml(truncate(t.git.headSha, 12, ''))}</code>`,
    );
  }
  row(
    '規模',
    `${formatNumber(t.fileCount)} ファイル / ${formatNumber(t.linesScanned)} 行` +
      `<span class="dim"> / ${escapeHtml(formatBytes(t.totalBytes))}</span>`,
  );
  if (t.languages.length > 0) {
    row(
      '言語構成',
      escapeHtml(
        t.languages
          .map((l: { name: string; ratio: number }) => `${l.name} ${Math.round(l.ratio * 100)}%`)
          .join(' / '),
      ),
    );
  }
  if (t.frameworks.length > 0) row('検出フレームワーク', escapeHtml(t.frameworks.join(', ')));
  out.push('</dl>');
  out.push('</div>');

  // ---- これは何か ----
  out.push('<h3>これは何か</h3>');
  if (t.readme !== null) {
    const text = [t.readme.title, t.readme.lead].filter((x) => x !== '').join(' — ');
    out.push('<blockquote class="readme-quote">');
    out.push(`<p>${escapeHtml(text)}</p>`);
    out.push(`<footer><code>${escapeHtml(t.readme.path)}</code> からの引用 — <b>事実</b></footer>`);
    out.push('</blockquote>');
  } else {
    out.push(
      '<p class="meta">README が見つからなかったため、対象が何であるかの説明は取得できていません。</p>',
    );
  }
  if (t.style !== null) {
    const conf = t.style.confidence === null ? '' : `（確信度 ${t.style.confidence.toFixed(2)}）`;
    out.push(
      `<p class="inferred-note">アーキテクチャ様式の<b>推測</b>: ${escapeHtml(t.style.value)}${escapeHtml(conf)}</p>`,
    );
  }

  // ---- 範囲 ----
  if (t.files !== null) {
    out.push('<h3>対象ファイル</h3>');
    out.push('<ul class="file-list">');
    for (const f of t.files) out.push(`<li><code>${escapeHtml(f)}</code></li>`);
    out.push('</ul>');
  } else if (t.directories !== null) {
    out.push('<h3>構成（上位2階層）</h3>');
    const rows: string[][] = [];
    for (const dir of t.directories) {
      const name = dir.path === '.' ? '(ルート直下)' : `${dir.path}/`;
      rows.push([
        `<b>${escapeHtml(name)}</b>`,
        formatNumber(dir.fileCount),
        formatNumber(dir.lines),
        escapeHtml(formatBytes(dir.bytes)),
      ]);
      for (const child of dir.children) {
        rows.push([
          `<span class="dir-child">${escapeHtml(`${child.path}/`)}</span>`,
          formatNumber(child.fileCount),
          formatNumber(child.lines),
          escapeHtml(formatBytes(child.bytes)),
        ]);
      }
    }
    out.push(scrollTable(['ディレクトリ', 'ファイル数', '行数', 'サイズ'], rows, 'dir-table'));
    const omitted: string[] = [];
    if (t.truncatedDirectories > 0) omitted.push(`上位 ${formatNumber(t.truncatedDirectories)} 個`);
    if (t.truncatedChildren > 0) omitted.push(`2階層目 ${formatNumber(t.truncatedChildren)} 個`);
    if (omitted.length > 0) {
      out.push(`<p class="meta">表示を省略したディレクトリ: ${escapeHtml(omitted.join(' / '))}</p>`);
    }
  }

  out.push('</section>');
  return out.join('\n');
}

function renderToc(
  chains: readonly AttackChain[],
  findings: readonly Finding[],
  hasDeps: boolean,
  hasArchitectureMap: boolean,
): string {
  const items: string[] = [
    '<li><a href="#target">走査対象</a></li>',
    '<li><a href="#executive">エグゼクティブサマリ</a></li>',
    '<li><a href="#risk">リスクの全体像</a></li>',
  ];
  if (hasArchitectureMap) {
    items.push('<li><a href="#archmap">アーキテクチャ × リスクヒートマップ</a></li>');
  }
  items.push('<li><a href="#actions">優先対応アクション</a></li>');
  if (chains.length > 0) {
    items.push('<li><a href="#chains">攻撃チェーン詳細</a></li>');
    for (const chain of chains.slice(0, 8)) {
      items.push(
        `<li class="sub"><a href="#${idFor('chain', chain.id)}">${escapeHtml(truncate(chain.title, 60))}</a></li>`,
      );
    }
  }
  if (findings.length > 0) {
    items.push('<li><a href="#findings">個別Finding詳細</a></li>');
  }
  if (hasDeps) items.push('<li><a href="#sbom">依存関係SBOM</a></li>');

  return `<nav class="card"><h4>目次</h4><ul class="toc">${items.join('')}</ul></nav>`;
}

function renderExecutive(analyzed: AnalyzedReport): string {
  const out = ['<h2 id="executive">エグゼクティブサマリ</h2>'];
  out.push(`<div class="card">${paragraphs(analyzed.executiveSummary)}</div>`);
  if (analyzed.keyFindings.length > 0) {
    out.push('<h3>今回の重要な所見</h3>');
    out.push(`<ul>${analyzed.keyFindings.map((k) => `<li>${escapeHtml(k)}</li>`).join('')}</ul>`);
  }
  if (analyzed.trendNarrative) {
    out.push('<h3>前回スキャンとの比較</h3>');
    out.push(paragraphs(analyzed.trendNarrative));
  }
  return out.join('\n');
}

function renderRisk(analyzed: AnalyzedReport): string {
  return ['<h2 id="risk">リスクの全体像</h2>', paragraphs(analyzed.riskNarrative)].join('\n');
}

function renderActions(analyzed: AnalyzedReport, rendered: ReadonlySet<string>): string {
  const out = ['<h2 id="actions">優先対応アクション</h2>'];
  if (analyzed.prioritizedActions.length === 0) {
    out.push('<p class="ok">対応が必要なアクションはありません。</p>');
    return out.join('\n');
  }
  out.push(
    '<p>対応順序は「攻撃チェーンのチョークポイントか」「複数の攻撃経路に登場するか」' +
      '「CVSSスコア」の順で機械的に決定しています。同じ修正で解決するFindingは1件にまとめています。</p>',
  );
  out.push(
    scrollTable(
      ['#', '対応内容', '工数', '解消Finding', '遮断チェーン'],
      analyzed.prioritizedActions.map((a) => [
        String(a.order),
        escapeHtml(a.action),
        escapeHtml(effortJa(a.effort)),
        `${a.resolves.findings.length} 件`,
        `${a.resolves.chains.length} 本`,
      ]),
    ),
  );
  for (const action of analyzed.prioritizedActions) {
    out.push(
      `<details${action.order <= 3 ? ' open' : ''}>` +
        `<summary><span class="action-order">${action.order}</span>${escapeHtml(action.action)}</summary>` +
        `<p class="meta">見積もり工数: ${escapeHtml(effortJa(action.effort))} (<code>${escapeHtml(action.effort)}</code>)</p>` +
        paragraphs(action.rationale) +
        (action.resolves.findings.length > 0
          ? `<p class="meta">解消されるFinding: ${action.resolves.findings
              .map((id) => linkFinding(id, rendered))
              .join(', ')}</p>`
          : '') +
        (action.resolves.chains.length > 0
          ? `<p class="meta">遮断される攻撃チェーン: ${action.resolves.chains
              .map((id) => `<a href="#${idFor('chain', id)}"><code>${escapeHtml(id)}</code></a>`)
              .join(', ')}</p>`
          : '') +
        '</details>',
    );
  }
  return out.join('\n');
}

function renderChains(chains: readonly AttackChain[], rendered: ReadonlySet<string>): string {
  if (chains.length === 0) return '';
  const out = ['<h2 id="chains">攻撃チェーン詳細</h2>'];
  out.push(
    '<p>個々の指摘は単独では中程度でも、連鎖すると深刻な結果に至ります。' +
      '以下は本コードベースで成立しうる攻撃の筋書きです。</p>',
  );

  for (const chain of chains) {
    out.push(`<div class="card" id="${idFor('chain', chain.id)}">`);
    out.push(`<h3>${escapeHtml(chain.title)}</h3>`);
    out.push(
      '<div class="tags">' +
        `<span class="tag">${escapeHtml(chain.id)}</span>` +
        `<span class="tag">優先度 ${chain.priorityScore}</span>` +
        `<span class="tag">成立可能性 ${escapeHtml(likelihoodJa(chain.likelihood))}</span>` +
        `<span class="tag">起点 ${escapeHtml(chain.entryPoint)}</span>` +
        '</div>',
    );
    out.push(`<p><strong>最終的な影響</strong>: ${escapeHtml(chain.impact)}</p>`);
    out.push(
      scrollTable(
        ['#', '段階', '戦術', '技術', '攻撃者の行動', 'Finding'],
        [...chain.steps]
          .sort((a, b) => a.order - b.order)
          .map((step) => [
            String(step.order),
            escapeHtml(PHASE_JA[step.killChainPhase] ?? step.killChainPhase),
            escapeHtml(TACTIC_JA[step.attackTactic] ?? step.attackTactic),
            escapeHtml(step.attackTechnique ?? '-'),
            escapeHtml(step.description),
            step.findingId
              ? linkFinding(step.findingId, rendered)
              : '-',
          ]),
      ),
    );

    const preconditions = [...new Set(chain.steps.flatMap((s) => s.preconditions))];
    if (preconditions.length > 0) {
      out.push('<h4>成立の前提条件</h4>');
      out.push(`<ul>${preconditions.map((p) => `<li>${escapeHtml(p)}</li>`).join('')}</ul>`);
    }
    if (chain.chokePoint) {
      out.push(
        `<blockquote><strong>✂ チョークポイント: ${linkFinding(chain.chokePoint.findingId, rendered)}</strong><br>` +
          `${escapeHtml(chain.chokePoint.rationale)}</blockquote>`,
      );
    }
    if (chain.reasoning) {
      out.push(`<details><summary>推論の根拠</summary>${paragraphs(chain.reasoning)}</details>`);
    }
    out.push('</div>');
  }
  return out.join('\n');
}

function renderFindingDetail(finding: Finding): string {
  const out: string[] = [];
  out.push(`<div class="finding sev-l-${finding.severity}" id="${idFor('finding', finding.id)}">`);
  out.push(`<h3>${badge(finding.severity)} ${escapeHtml(finding.title)}</h3>`);

  const tags = [
    `<span class="tag">${escapeHtml(finding.id)}</span>`,
    `<span class="tag">${escapeHtml(finding.cwe)}</span>`,
    `<span class="tag">${escapeHtml(finding.category)}</span>`,
    `<span class="tag">CVSS ${(finding.cvss?.baseScore ?? 0).toFixed(1)} (${escapeHtml(finding.cvss?.baseSeverity ?? 'None')})</span>`,
    `<span class="tag">確信度 ${(finding.confidence * 100).toFixed(0)}%</span>`,
    `<span class="tag">レンズ ${escapeHtml(finding.lens)}</span>`,
    `<span class="tag">${escapeHtml(finding.diffStatus)} / ${escapeHtml(finding.status)}</span>`,
  ];
  if (finding.cve) tags.push(`<span class="tag">${escapeHtml(finding.cve)}</span>`);
  out.push(`<div class="tags">${tags.join('')}</div>`);

  out.push(
    `<p class="meta">該当箇所: <code>${escapeHtml(finding.location.file)}:${finding.location.startLine}-${finding.location.endLine}</code></p>`,
  );
  if (finding.cvss?.vector) {
    out.push(`<p class="meta">CVSSベクタ: <code>${escapeHtml(finding.cvss.vector)}</code></p>`);
  }
  if (finding.affectedPackage) {
    const p = finding.affectedPackage;
    out.push(
      `<p class="meta">該当パッケージ: <code>${escapeHtml(p.name)}@${escapeHtml(p.version)}</code> (${escapeHtml(p.ecosystem)})` +
        (p.fixedVersion ? ` → 修正版 <code>${escapeHtml(p.fixedVersion)}</code>` : ' → 修正版なし') +
        '</p>',
    );
  }

  if (finding.evidence && finding.evidence.trim() !== '') {
    out.push('<h4>該当コード</h4>');
    out.push(code(finding.evidence));
  }

  out.push('<h4>なぜ問題か</h4>');
  out.push(paragraphs(finding.reasoning || '（説明なし）'));

  if (finding.dataFlow.length > 0) {
    out.push('<h4>データフロー（source → sink）</h4>');
    out.push(
      scrollTable(
        ['#', '役割', '位置', '説明'],
        finding.dataFlow.map((step, index) => [
          String(index + 1),
          escapeHtml(ROLE_JA[step.role] ?? step.role),
          `<code>${escapeHtml(step.file)}:${step.line}</code>`,
          escapeHtml(step.description),
        ]),
      ),
    );
    out.push(
      '<details><summary>各ステップのコード</summary>' +
        finding.dataFlow
          .map(
            (step, index) =>
              `<p class="meta">${index + 1}. <code>${escapeHtml(step.file)}:${step.line}</code> — ${escapeHtml(ROLE_JA[step.role] ?? step.role)}</p>` +
              code(step.code),
          )
          .join('') +
        '</details>',
    );
  } else {
    out.push(
      '<blockquote>データフローの根拠が提示されていません。外部入力からの到達性は未証明です。</blockquote>',
    );
  }

  out.push('<h4>修正方針</h4>');
  out.push(paragraphs(finding.remediation || '（修正方針の記載なし）'));

  if (finding.references.length > 0) {
    out.push('<h4>参考リンク</h4>');
    out.push(
      // http(s) 以外（javascript: など）や空白・引用符を含むURLはリンクにしない
      `<ul>${finding.references
        .map((r) =>
          isSafeUrl(r)
            ? `<li><a href="${escapeHtml(r)}" rel="noreferrer noopener">${escapeHtml(r)}</a></li>`
            : `<li>${escapeHtml(r)}</li>`,
        )
        .join('')}</ul>`,
    );
  }
  out.push(
    `<p class="meta">指紋: <code>${escapeHtml(finding.fingerprint)}</code> / 初回検出 ${escapeHtml(finding.firstSeen)} / 最終検出 ${escapeHtml(finding.lastSeen)}</p>`,
  );
  out.push('</div>');
  return out.join('\n');
}

function renderFindings(findings: readonly Finding[], fixed: readonly Finding[]): string {
  const out = ['<h2 id="findings">個別Finding詳細</h2>'];
  if (findings.length === 0) {
    out.push('<p class="ok">報告対象のFindingはありません。</p>');
    return out.join('\n');
  }
  out.push(
    scrollTable(
      ['深刻度', 'CVSS', 'CWE', '概要', '位置'],
      findings.map((f) => [
        badge(f.severity),
        (f.cvss?.baseScore ?? 0).toFixed(1),
        escapeHtml(f.cwe),
        `<a href="#${idFor('finding', f.id)}">${escapeHtml(truncate(f.title, 70))}</a>`,
        `<code>${escapeHtml(f.location.file)}:${f.location.startLine}</code>`,
      ]),
    ),
  );
  for (const finding of findings) out.push(renderFindingDetail(finding));

  if (fixed.length > 0) {
    out.push('<h3>前回から解消されたFinding</h3>');
    out.push(
      `<ul>${fixed
        .map(
          (f) =>
            `<li><del>${escapeHtml(f.title)}</del> <code>${escapeHtml(f.cwe)}</code> <code>${escapeHtml(f.location.file)}</code></li>`,
        )
        .join('')}</ul>`,
    );
  }
  return out.join('\n');
}

function renderSbom(dependencies: readonly Dependency[], findings: readonly Finding[], rendered: ReadonlySet<string>): string {
  if (dependencies.length === 0) return '';
  const { vulnerable, sorted } = buildSbomIndex(dependencies, findings);

  return [
    '<h2 id="sbom">依存関係SBOM</h2>',
    `<p>宣言されている依存は ${formatNumber(dependencies.length)} 件（うち脆弱性が紐づくもの ${vulnerable.size} 件）。</p>`,
    scrollTable(
      ['パッケージ', 'バージョン', 'エコシステム', '用途', '宣言元', '脆弱性'],
      sorted.map((dep) => {
        const hits = vulnerable.get(sbomPackageKey(dep)) ?? [];
        return [
          `<code>${escapeHtml(dep.name)}</code>`,
          escapeHtml(dep.version),
          escapeHtml(dep.ecosystem),
          dep.dev ? 'dev' : 'prod',
          `<code>${escapeHtml(dep.manifest)}</code>`,
          hits.length === 0
            ? '-'
            : hits
                .slice(0, 4)
                .map((f) => linkFinding(f.id, rendered, f.cve ?? f.cwe))
                .join(', '),
        ];
      }),
    ),
  ].join('\n');
}

function renderIssues(result: ScanResult): string {
  if (result.errors.length === 0 && result.context.warnings.length === 0) return '';
  const out = ['<h2 id="issues">実行時の問題</h2>'];
  if (result.errors.length > 0) {
    out.push('<p>本レポートは部分的な結果を含んでいる可能性があります。</p>');
    out.push(`<ul>${result.errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul>`);
  }
  if (result.context.warnings.length > 0) {
    out.push('<h4>警告</h4>');
    out.push(`<ul>${result.context.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}</ul>`);
  }
  return out.join('\n');
}

export function renderHtml(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: Pick<ReportOptions, 'verbose'>,
): string {
  const verbose = options.verbose === true;
  const active = reportableFindings(result.findings, verbose);
  const fixed = result.findings.filter((f) => f.diffStatus === 'fixed');
  const chains = [...result.chains].sort((a, b) => b.priorityScore - a.priorityScore);
  // 詳細を描画するFindingのID。ここに無いIDへはリンクを張らない（リンク切れ防止）
  const renderedIds: ReadonlySet<string> = new Set(active.map((f) => f.id));
  // アーキテクチャ推定とヒートマップが両方揃っている場合だけ描く。
  // 片方でも欠けていれば空文字が返り、既存のレポート構成は一切変わらない。
  const architectureMap = renderArchitectureMap(result.architecture, result.heatmap, result.chains);

  const body = [
    renderHeader(result, analyzed),
    renderHealthNotice(result),
    renderTarget(result),
    renderToc(chains, active, result.context.dependencies.length > 0, architectureMap !== ''),
    renderExecutive(analyzed),
    renderRisk(analyzed),
    architectureMap,
    renderActions(analyzed, renderedIds),
    renderChains(chains, renderedIds),
    renderFindings(active, fixed),
    renderSbom(result.context.dependencies, result.findings, renderedIds),
    renderIssues(result),
    `<footer>GRIMOIRE 0.1.0 が生成 — 処理 ${formatNumber(analyzed.summary.filesScanned)} ファイル / ` +
      `${formatNumber(analyzed.summary.linesScanned)} 行 — トークン使用量: 入力 ${formatNumber(analyzed.summary.tokenUsage.input)} / ` +
      `出力 ${formatNumber(analyzed.summary.tokenUsage.output)} / ` +
      `キャッシュ読 ${formatNumber(analyzed.summary.tokenUsage.cacheRead)} / ` +
      `書 ${formatNumber(analyzed.summary.tokenUsage.cacheWrite)}</footer>`,
  ]
    .filter((s) => s !== '')
    .join('\n');

  return [
    '<!DOCTYPE html>',
    '<html lang="ja">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="color-scheme" content="light dark">',
    `<meta name="generator" content="grimoire 0.1.0">`,
    `<title>セキュリティスキャンレポート — ${escapeHtml(result.context.repoRoot)}</title>`,
    `<style>${STYLE}${ARCHITECTURE_MAP_STYLE}</style>`,
    '</head>',
    '<body>',
    '<div class="wrap">',
    body,
    '</div>',
    '</body>',
    '</html>',
    '',
  ].join('\n');
}
