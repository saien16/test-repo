import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AnalyzedReport, ScanResult } from '../types/report.js';
import { analyzeMechanically } from './analyze.js';
import { makeChain, makeContext, makeCvss, makeFinding, makeResult } from './fixtures.js';
import { generateReport, renderToString } from './index.js';
import { buildFallbackNarrative } from './narrative.js';
import { renderCli } from './formatters/cli.js';
import { renderHtml } from './formatters/html.js';
import { renderJson } from './formatters/json.js';
import { renderMarkdown } from './formatters/markdown.js';
import { displayWidth, stripAnsi, wrapText } from './text.js';

function analyzedOf(result: ScanResult): AnalyzedReport {
  const m = analyzeMechanically(result);
  const n = buildFallbackNarrative(
    {
      context: result.context,
      summary: result.summary,
      ranked: m.ranked,
      chains: result.chains,
      actions: m.actions,
      hasBaseline: m.hasBaseline,
      errors: result.errors,
    },
    m.keyFindings,
  );
  const report: AnalyzedReport = {
    executiveSummary: n.executiveSummary,
    keyFindings: n.keyFindings,
    prioritizedActions: m.actions,
    riskNarrative: n.riskNarrative,
    summary: result.summary,
  };
  if (n.trendNarrative) report.trendNarrative = n.trendNarrative;
  return report;
}

const richResult = (): ScanResult =>
  makeResult({
    context: makeContext(),
    findings: [
      makeFinding({ id: 'f-1' }),
      makeFinding({
        id: 'f-2',
        cwe: 'CWE-798',
        severity: 'high',
        title: 'ハードコードされた署名鍵 <script>alert(1)</script>',
        location: { file: 'src/auth/token.ts', startLine: 12, endLine: 12 },
        cvss: makeCvss({ baseScore: 7.5, baseSeverity: 'High' }),
        diffStatus: 'persistent',
        remediation: '鍵を環境変数へ移し、リポジトリからは削除する。',
        dataFlow: [],
      }),
      makeFinding({
        id: 'f-3',
        cwe: 'CWE-1035',
        severity: 'medium',
        title: '既知の脆弱性を含む依存',
        cve: 'CVE-2021-23337',
        affectedPackage: {
          name: 'lodash',
          version: '4.17.20',
          ecosystem: 'npm',
          fixedVersion: '4.17.21',
        },
        cvss: makeCvss({ baseScore: 5.3, baseSeverity: 'Medium' }),
        lens: 'dependency',
        remediation: 'lodash を 4.17.21 へ更新する。',
        dataFlow: [],
      }),
      makeFinding({ id: 'f-4', severity: 'info', cwe: 'CWE-200', title: '情報レベルの指摘', dataFlow: [] }),
    ],
    chains: [makeChain()],
    errors: ['一部チャンクの解析に失敗しました'],
  });

describe('CLIフォーマッタ', () => {
  const result = richResult();
  const analyzed = analyzedOf(result);

  it('color: false ならANSIエスケープを一切出さない', () => {
    const text = renderCli(result, analyzed, { color: false, verbose: false, width: 80 });
    expect(text).not.toMatch(/\[/);
    expect(stripAnsi(text)).toBe(text);
  });

  it('color: true ならANSIエスケープを出す', () => {
    const text = renderCli(result, analyzed, { color: true, verbose: false, width: 80 });
    expect(text).toMatch(/\[/);
    // 色を剥がせば無色版と同じ情報が残る
    expect(stripAnsi(text)).toContain('vulnscan スキャン結果');
  });

  it('指定幅を超える行を作らない（全角幅を考慮）', () => {
    const width = 72;
    const text = renderCli(result, analyzed, { color: false, verbose: true, width });
    for (const line of text.split('\n')) {
      expect(displayWidth(line)).toBeLessThanOrEqual(width);
    }
  });

  it('サマリ・チェーン・アクションの見出しを含む', () => {
    const text = stripAnsi(renderCli(result, analyzed, { color: false, verbose: false, width: 80 }));
    expect(text).toContain('深刻度別の検出状況');
    expect(text).toContain('エグゼクティブサマリ');
    expect(text).toContain('上位の攻撃チェーン');
    expect(text).toContain('優先対応アクション');
    expect(text).toContain('実行時の問題');
  });

  it('verbose でなければ info レベルを出さない', () => {
    const quiet = stripAnsi(renderCli(result, analyzed, { color: false, verbose: false, width: 100 }));
    const loud = stripAnsi(renderCli(result, analyzed, { color: false, verbose: true, width: 100 }));
    expect(quiet).not.toContain('情報レベルの指摘');
    expect(loud).toContain('情報レベルの指摘');
  });

  it('Finding 0件でもクラッシュせず、その旨を表示する', () => {
    const empty = makeResult();
    const text = stripAnsi(renderCli(empty, analyzedOf(empty), { color: false, verbose: false, width: 80 }));
    expect(text).toContain('検出されませんでした');
  });
});

describe('JSONフォーマッタ', () => {
  it('ScanResult と AnalyzedReport の両方を含む', () => {
    const result = richResult();
    const parsed = JSON.parse(renderJson(result, analyzedOf(result), { verbose: true })) as {
      schemaVersion: string;
      analysis: AnalyzedReport;
      result: ScanResult;
    };
    expect(parsed.schemaVersion).toBe('1.0');
    expect(parsed.result.findings).toHaveLength(4);
    expect(parsed.result.chains).toHaveLength(1);
    expect(parsed.analysis.prioritizedActions.length).toBeGreaterThan(0);
    expect(parsed.analysis.summary.totalFindings).toBe(4);
  });

  it('verbose でなければ info レベルを落とす', () => {
    const result = richResult();
    const parsed = JSON.parse(renderJson(result, analyzedOf(result), { verbose: false })) as {
      result: ScanResult;
    };
    expect(parsed.result.findings.map((f) => f.id)).not.toContain('f-4');
  });
});

describe('Markdownフォーマッタ', () => {
  const result = richResult();
  const text = renderMarkdown(result, analyzedOf(result), { verbose: false });

  it('要求された章立てを順番どおりに含む', () => {
    const sections = [
      '## エグゼクティブサマリ',
      '## リスクの全体像',
      '## 優先対応アクション',
      '## 攻撃チェーン詳細',
      '## 個別Finding詳細',
      '## 依存関係SBOM',
    ];
    let cursor = -1;
    for (const section of sections) {
      const index = text.indexOf(section);
      expect(index, `${section} が見つからない`).toBeGreaterThan(-1);
      expect(index).toBeGreaterThan(cursor);
      cursor = index;
    }
  });

  it('コード片・データフロー・修正方針を含む', () => {
    expect(text).toContain('**該当コード**');
    expect(text).toContain('**データフロー（source → sink）**');
    expect(text).toContain('**修正方針**');
    expect(text).toContain('SELECT * FROM users');
  });

  it('SBOMに依存パッケージとCVEを載せる', () => {
    expect(text).toContain('| `lodash` | 4.17.20 | npm |');
    expect(text).toContain('CVE-2021-23337');
  });

  it('コードフェンスの数が釣り合っている', () => {
    const fences = text.match(/^`{3,}/gm) ?? [];
    expect(fences.length % 2).toBe(0);
  });
});

describe('HTMLフォーマッタ', () => {
  const result = richResult();
  const html = renderHtml(result, analyzedOf(result), { verbose: false });

  it('自己完結している（外部リソースを読み込まない）', () => {
    expect(html).not.toMatch(/<link[^>]+rel=["']?stylesheet/i);
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/https?:\/\/[^"']*\.(?:css|js|woff2?|ttf|png|jpg|svg)/i);
    expect(html).toContain('<style>');
  });

  it('ダーク/ライト両対応の指定がある', () => {
    expect(html).toContain('prefers-color-scheme: dark');
    expect(html).toContain('color-scheme: light dark');
  });

  it('テーブルは横スクロールコンテナに入り、body は横スクロールしない', () => {
    expect(html).toContain('<div class="table-scroll"');
    expect(html).toContain('overflow-x: hidden');
    // すべての <table> が table-scroll に包まれている
    const tables = html.match(/<table/g) ?? [];
    const wrappers = html.match(/<div class="table-scroll"/g) ?? [];
    expect(wrappers.length).toBe(tables.length);
  });

  it('目次と折りたたみ詳細を持つ', () => {
    expect(html).toContain('<ul class="toc">');
    expect(html).toContain('<details');
    expect(html).toContain('</details>');
  });

  it('深刻度ごとに色分けクラスが付く', () => {
    expect(html).toContain('sev-critical');
    expect(html).toContain('sev-high');
    expect(html).toContain('sev-medium');
  });

  it('ユーザー由来の文字列をエスケープする', () => {
    // タイトルに含まれる <script> がそのまま出ていないこと
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('目次リンクの参照先IDが存在する', () => {
    const hrefs = [...html.matchAll(/href="#([^"]+)"/g)].map((m) => m[1]!);
    for (const href of new Set(hrefs)) {
      expect(html, `#${href} の参照先がない`).toContain(`id="${href}"`);
    }
  });
});

describe('generateReport', () => {
  const result = richResult();
  const analyzed = analyzedOf(result);

  it('全フォーマットで空でない文字列を返す', async () => {
    for (const format of ['cli', 'json', 'sarif', 'markdown', 'html'] as const) {
      const text = await generateReport(result, analyzed, { format, color: false, verbose: false });
      expect(text.length, format).toBeGreaterThan(100);
    }
  });

  it('outputPath を指定するとファイルにも書き出す', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vulnscan-report-'));
    try {
      const outputPath = join(dir, 'nested', 'report.sarif');
      const text = await generateReport(result, analyzed, {
        format: 'sarif',
        outputPath,
        color: false,
        verbose: false,
      });
      const written = await readFile(outputPath, 'utf8');
      expect(written).toBe(text);
      expect(JSON.parse(written).version).toBe('2.1.0');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('未対応フォーマットは明示的にエラーにする', () => {
    expect(() =>
      renderToString(result, analyzed, {
        format: 'xml' as never,
        color: false,
        verbose: false,
      }),
    ).toThrow(/未対応のレポート形式/);
  });
});

describe('折り返しユーティリティ', () => {
  it('全角文字を2桁として折り返す', () => {
    const lines = wrapText('あいうえおかきくけこ', 10);
    for (const line of lines) expect(displayWidth(line)).toBeLessThanOrEqual(10);
    expect(lines.join('')).toBe('あいうえおかきくけこ');
  });

  it('英単語を途中で切らない', () => {
    const lines = wrapText('this sentence has averylongwordhere inside', 20);
    for (const line of lines) expect(displayWidth(line)).toBeLessThanOrEqual(20);
    expect(lines.some((l) => l.includes('averylongwordhere'))).toBe(true);
  });

  it('行頭禁則文字を行頭に置かない', () => {
    const lines = wrapText('これはテストです。次の文もテストです。', 12);
    for (const line of lines) {
      expect(line.startsWith('。')).toBe(false);
      expect(line.startsWith('、')).toBe(false);
    }
  });
});
