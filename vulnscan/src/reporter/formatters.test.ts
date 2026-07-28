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
import {
  displayWidth,
  escapeMdCell,
  escapeMdCode,
  escapeMdCodeCell,
  escapeMdText,
  isSafeUrl,
  stripAnsi,
  wrapText,
} from './text.js';

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
    expect(stripAnsi(text)).toContain('GRIMOIRE スキャン結果');
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

describe('Markdownフォーマッタのエスケープ', () => {
  /**
   * スキャン対象リポジトリ由来の文字列はすべて未信頼入力。
   * Markdownレポートは生HTML(<details>)を含むためHTMLが有効なレンダラで
   * 表示される前提であり、タグ・バッククォート・パイプを無害化する必要がある。
   */
  const hostile = (): ScanResult =>
    makeResult({
      context: makeContext({
        repoRoot: '/home/user/`whoami`',
        git: {
          branch: '<script>alert("branch")</script>',
          headSha: 'abcdef1234567890',
          changedFiles: [],
        },
        dependencies: [
          {
            name: '<img src=x onerror=alert(1)>',
            version: '1.0.0 | 差し込み',
            ecosystem: 'npm',
            dev: false,
            manifest: 'pkg/`evil`/package.json',
          },
        ],
        warnings: ['<script>alert("warn")</script> という警告'],
      }),
      findings: [
        makeFinding({
          id: 'f-x',
          title: '<script>alert("title")</script>',
          location: { file: 'src/`inj`/<img src=x onerror=alert(2)>.ts', startLine: 1, endLine: 2 },
          reasoning: '<img src=x onerror=alert(3)>',
          remediation: '</details><script>alert(4)</script>',
          references: ['javascript:alert(5)', 'https://example.com/ok', 'https://ex.com/<script>'],
          dataFlow: [
            {
              file: 'src/`flow`.ts',
              line: 3,
              code: 'const a = 1;',
              role: 'source',
              description: '説明 | パイプ入り <b>tag</b>',
            },
          ],
          mergedFrom: ['<script>alert(6)</script>'],
          affectedPackage: {
            name: '<img src=x>',
            version: '1.0.0',
            ecosystem: 'npm',
            fixedVersion: '2.0.0',
          },
        }),
      ],
      chains: [
        makeChain({
          title: '<script>alert("chain")</script>',
          entryPoint: 'GET /`x`',
          impact: '<img src=x onerror=alert(7)>',
          reasoning: '</details><script>alert(8)</script>',
          chokePoint: { findingId: 'f-x', rationale: '<b>choke</b>\n改行あり' },
          steps: [
            {
              order: 1,
              findingId: 'f-x',
              killChainPhase: 'exploitation',
              attackTactic: 'initial-access',
              attackTechnique: 'T1190<script>alert(9)</script>',
              description: '説明 | パイプ',
              preconditions: ['<script>alert(10)</script>'],
            },
          ],
        }),
      ],
      errors: ['<script>alert("err")</script> が起きました'],
    });

  const md = renderMarkdown(hostile(), analyzedOf(hostile()), { verbose: true });

  it('HTMLタグをそのまま出力しない', () => {
    expect(md).not.toContain('<script>');
    expect(md).not.toContain('</script>');
    expect(md).not.toContain('<img ');
    expect(md).not.toContain('<b>');
    // エスケープ済みの形では現れる
    expect(md).toContain('&lt;script&gt;');
    expect(md).toContain('&lt;img src=x onerror=alert(3)&gt;');
  });

  it('自前で出す <details> だけがHTMLとして残る', () => {
    const opens = md.match(/<details>/g) ?? [];
    const closes = md.match(/<\/details>/g) ?? [];
    expect(opens.length).toBe(closes.length);
    // remediation / chain.reasoning に仕込んだ </details> は閉じタグとして数えられない
    expect(closes.length).toBeLessThanOrEqual(2);
  });

  it('コードスパンに入る値のバッククォートを無害化する', () => {
    // 該当箇所・SBOM・対象パスはいずれもコードスパンなので閉じられてはいけない
    expect(md).toContain("`src/'inj'/&lt;img src=x onerror=alert(2)&gt;.ts:1-2`");
    expect(md).toContain("`pkg/'evil'/package.json`");
    expect(md).toContain("`/home/user/'whoami'`");
    expect(md).not.toContain('`evil`');
    expect(md).not.toContain('`whoami`');
    // コードスパンの開閉が釣り合っている（単独のバッククォートの総数が偶数）
    const singles = (md.match(/(?<!`)`(?!`)/g) ?? []).length;
    expect(singles % 2).toBe(0);
  });

  it('テーブルセルのパイプをエスケープする', () => {
    expect(md).toContain('1.0.0 \\| 差し込み');
    expect(md).toContain('説明 \\| パイプ');
  });

  it('参考リンクは http(s) のみリンクにする', () => {
    expect(md).toContain('- <https://example.com/ok>');
    // javascript: スキームはリンクにしない
    expect(md).not.toContain('<javascript:');
    expect(md).toContain('- javascript:alert(5)');
    // URL内のタグもエスケープする
    expect(md).toContain('https://ex.com/&lt;script&gt;');
  });

  it('実行時のエラー・警告もエスケープする', () => {
    expect(md).toContain('&lt;script&gt;alert(&quot;err&quot;)&lt;/script&gt;'.replace(/&quot;/g, '"'));
    expect(md).toContain('&lt;script&gt;alert("warn")&lt;/script&gt;');
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

describe('Markdownエスケープユーティリティ', () => {
  it('escapeMdText はHTML特殊文字を実体参照にする', () => {
    expect(escapeMdText('<script>alert(1)</script>')).toBe(
      '&lt;script&gt;alert(1)&lt;/script&gt;',
    );
    expect(escapeMdText('a & b')).toBe('a &amp; b');
    // 二重エスケープにならない順序であること
    expect(escapeMdText('&lt;')).toBe('&amp;lt;');
  });

  it('escapeMdCode はバッククォートと改行を無害化する', () => {
    expect(escapeMdCode('a`b`c')).toBe("a'b'c");
    expect(escapeMdCode('a\nb')).toBe('a b');
    expect(escapeMdCode('<img src=x>')).toBe('&lt;img src=x&gt;');
  });

  it('escapeMdCell はパイプと改行を潰す', () => {
    expect(escapeMdCell('a|b\nc')).toBe('a\\|b c');
    expect(escapeMdCell('<b>x</b>')).toBe('&lt;b&gt;x&lt;/b&gt;');
  });

  it('escapeMdCodeCell はバッククォートとパイプの両方を処理する', () => {
    expect(escapeMdCodeCell('a`b|c')).toBe("a'b\\|c");
  });

  it('isSafeUrl は http(s) のみ許可する', () => {
    expect(isSafeUrl('https://example.com/a')).toBe(true);
    expect(isSafeUrl('http://example.com')).toBe(true);
    expect(isSafeUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeUrl('data:text/html,<script>')).toBe(false);
    expect(isSafeUrl('https://example.com/ <script>')).toBe(false);
    expect(isSafeUrl('https://example.com/`x`')).toBe(false);
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
