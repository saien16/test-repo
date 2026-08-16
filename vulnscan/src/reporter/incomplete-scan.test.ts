/**
 * 走査が完走しなかったときのレポート文言の検証。
 *
 * 終了コードを直すだけでは足りない。人間が読む本文が
 * 「対応を要する脆弱性は検出されませんでした」のままだと、
 * CIが赤くても読み手は「安全だが何かのエラーが出ている」と解釈する。
 * 全フォーマットで、件数より先に「判定できていない」ことを言わせる。
 *
 * 実際に踏んだ不具合:
 *   APIキー未設定で12タスク全滅・検出0件のとき、
 *   終了コード0 かつ「✔ 対応を要する脆弱性は検出されませんでした」だった。
 */

import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../types/config.js';
import { assessAnalysisHealth, emptyAnalysisStats } from '../types/health.js';
import type { AnalyzedReport, ScanResult } from '../types/report.js';
import { analyzeMechanically } from './analyze.js';
import { makeFinding, makeResult } from './fixtures.js';
import { renderCli } from './formatters/cli.js';
import { renderHtml } from './formatters/html.js';
import { renderJson } from './formatters/json.js';
import { renderMarkdown } from './formatters/markdown.js';
import { buildSarifLog } from './formatters/sarif.js';
import { buildFallbackNarrative } from './narrative.js';
import { buildKeyFindings } from './priority.js';
import { stripAnsi } from './text.js';

/** 全タスクが失敗し、検出0件になった走査 */
function allFailedResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return makeResult({
    findings: [],
    errors: Array.from(
      { length: 12 },
      (_v, i) => `[injection] src/a${i}.ts: 分析に失敗しました: APIエラー 401: 認証エラー`,
    ),
    health: assessAnalysisHealth({ ...emptyAnalysisStats(), total: 12, failed: 12 }),
    ...overrides,
  });
}

/** 完走した走査（対照群） */
function completeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return makeResult({
    findings: [],
    health: assessAnalysisHealth({ ...emptyAnalysisStats(), total: 12, succeeded: 12 }),
    ...overrides,
  });
}

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
      health: result.health,
    },
    m.keyFindings,
  );
  return {
    executiveSummary: n.executiveSummary,
    keyFindings: n.keyFindings,
    prioritizedActions: m.actions,
    riskNarrative: n.riskNarrative,
    summary: result.summary,
  };
}

describe('エグゼクティブサマリ（機械生成）', () => {
  it('未完走なら「検出されませんでした」と書かない', () => {
    const text = analyzedOf(allFailedResult()).executiveSummary;
    expect(text).not.toContain('検出されませんでした');
    expect(text).toContain('完走していません');
    expect(text).toContain('調べられなかった');
  });

  it('未完走なら最初にすべきことが「走査の復旧」だと書く', () => {
    const text = analyzedOf(allFailedResult()).executiveSummary;
    expect(text).toContain('走査の復旧');
    expect(text).toMatch(/APIキー|ネットワーク|予算/u);
  });

  it('分析対象が0件のときは走査対象の見直しを促す（APIキーの話をしない）', () => {
    // 原因に合った指示を出す。除外設定の問題を認証の問題として案内しない
    const result = makeResult({
      health: assessAnalysisHealth(emptyAnalysisStats()),
    });
    const text = analyzedOf(result).executiveSummary;
    expect(text).toContain('走査対象の見直し');
    expect(text).toContain('scan.include');
    expect(text).not.toContain('APIキー');
  });

  it('未完走で検出がある場合は「下限」だと断る', () => {
    const result = allFailedResult({ findings: [makeFinding({ id: 'f-1', severity: 'high' })] });
    const text = analyzedOf(result).executiveSummary;
    expect(text).toContain('下限');
    expect(text).toContain('これ以上');
  });

  it('完走していれば従来どおり「検出されませんでした」と書く', () => {
    // 完走した0件は正当に「見たが無かった」と言ってよい
    const text = analyzedOf(completeResult()).executiveSummary;
    expect(text).toContain('検出されませんでした');
    expect(text).not.toContain('完走していません');
  });

  it('リスク全体像も「経路は確認できませんでした」と言い切らない', () => {
    const text = analyzedOf(allFailedResult()).riskNarrative;
    expect(text).not.toContain('確認できませんでした');
    expect(text).toContain('描けません');
  });

  it('主な所見も「検出されませんでした」と書かない', () => {
    const keyFindings = buildKeyFindings([], [], [], {
      health: allFailedResult().health,
    });
    expect(keyFindings).toHaveLength(1);
    expect(keyFindings[0]).not.toContain('検出されませんでした');
    expect(keyFindings[0]).toContain('完走しなかった');
  });

  it('完走していれば主な所見は従来どおり', () => {
    const keyFindings = buildKeyFindings([], [], [], {
      health: completeResult().health,
    });
    expect(keyFindings[0]).toContain('検出されませんでした');
  });

  it('文章に Markdown の強調記法を混ぜない（CLIで生の ** が見える）', () => {
    const analyzed = analyzedOf(allFailedResult());
    expect(analyzed.executiveSummary).not.toContain('**');
    expect(analyzed.riskNarrative).not.toContain('**');
  });
});

describe('CLIフォーマッタ', () => {
  const render = (result: ScanResult): string =>
    stripAnsi(renderCli(result, analyzedOf(result), { color: false, verbose: false, width: 100 }));

  it('未完走なら緑のチェックマークを出さない', () => {
    const text = render(allFailedResult());
    expect(text).not.toContain('✔ 対応を要する脆弱性は検出されませんでした');
    expect(text).toContain('判定できません');
  });

  it('未完走の警告はサマリより前に出る', () => {
    const text = render(allFailedResult());
    const notice = text.indexOf('走査は完走しませんでした');
    const summary = text.indexOf('深刻度別の検出状況');
    expect(notice).toBeGreaterThanOrEqual(0);
    expect(notice).toBeLessThan(summary);
  });

  it('タスクの内訳を出す（何件見られなかったのかが分かるように）', () => {
    const text = render(allFailedResult());
    expect(text).toContain('成功 0');
    expect(text).toContain('失敗 12');
    expect(text).toContain('全 12');
  });

  it('完走していれば警告は出ない', () => {
    const text = render(completeResult());
    expect(text).not.toContain('走査は完走しませんでした');
    expect(text).toContain('✔ 対応を要する脆弱性は検出されませんでした');
  });
});

describe('Markdownフォーマッタ', () => {
  const render = (result: ScanResult): string =>
    renderMarkdown(result, analyzedOf(result), { verbose: false });

  it('未完走なら警告ブロックを出し、完走状況を表に載せる', () => {
    const text = render(allFailedResult());
    expect(text).toContain('[!CAUTION]');
    expect(text).toContain('このスキャンは完走していません');
    expect(text).toContain('| 走査の完走 | ❌ 未完走 |');
  });

  it('警告はエグゼクティブサマリより前に出る', () => {
    const text = render(allFailedResult());
    expect(text.indexOf('完走していません')).toBeLessThan(text.indexOf('## エグゼクティブサマリ'));
  });

  it('部分的失敗は CAUTION ではなく WARNING', () => {
    const result = makeResult({
      health: assessAnalysisHealth({
        ...emptyAnalysisStats(),
        total: 10,
        succeeded: 9,
        failed: 1,
      }),
    });
    const text = render(result);
    expect(text).toContain('[!WARNING]');
    expect(text).toContain('| 走査の完走 | ⚠️ 部分的 |');
  });

  it('完走していれば警告ブロックは出ない', () => {
    const text = render(completeResult());
    expect(text).not.toContain('[!CAUTION]');
    expect(text).not.toContain('[!WARNING]');
    expect(text).toContain('| 走査の完走 | ✅ 完走 |');
  });
});

describe('HTMLフォーマッタ', () => {
  const render = (result: ScanResult): string =>
    renderHtml(result, analyzedOf(result), { verbose: false });

  it('未完走なら注記ブロックを出す', () => {
    const html = render(allFailedResult());
    expect(html).toContain('health-notice health-failed');
    expect(html).toContain('このスキャンは完走していません');
    // 対応するスタイルも入っていること（枠線が付かないと読み飛ばされる）
    expect(html).toContain('.health-notice');
  });

  it('注記は目次より前に置かれる', () => {
    const html = render(allFailedResult());
    expect(html.indexOf('health-notice')).toBeLessThan(html.indexOf('class="toc"'));
  });

  it('完走していれば注記は出ない', () => {
    expect(render(completeResult())).not.toContain('health-notice health-failed');
  });
});

describe('機械可読フォーマット', () => {
  it('JSONは health をそのまま含む（CI側で判定できるように）', () => {
    const result = allFailedResult();
    const parsed = JSON.parse(renderJson(result, analyzedOf(result), { verbose: true })) as {
      result: ScanResult;
    };
    expect(parsed.result.health.level).toBe('failed');
    expect(parsed.result.health.zeroFindingsIsMeaningful).toBe(false);
    expect(parsed.result.health.analysis.failed).toBe(12);
  });

  it('SARIFは executionSuccessful を false にする', () => {
    const log = buildSarifLog(allFailedResult());
    expect(log.runs[0]?.invocations?.[0]?.executionSuccessful).toBe(false);
  });

  it('SARIFの通知の先頭が未完走の理由になる', () => {
    // GitHub Code Scanning は「アラート0件」を成功として見せるため、
    // 理由が他のエラーに埋もれないよう先頭に置く
    const notifications = buildSarifLog(allFailedResult()).runs[0]?.invocations?.[0]
      ?.toolExecutionNotifications;
    expect(notifications?.[0]?.level).toBe('error');
    expect(notifications?.[0]?.message.text).toContain('完走しませんでした');
    expect(notifications?.[0]?.message.text).toContain('安全');
  });

  it('完走した走査は executionSuccessful が true', () => {
    const log = buildSarifLog(completeResult());
    expect(log.runs[0]?.invocations?.[0]?.executionSuccessful).toBe(true);
    expect(log.runs[0]?.invocations?.[0]?.toolExecutionNotifications).toBeUndefined();
  });
});

describe('DEFAULT_CONFIG', () => {
  it('未完走のゲートは既定で有効（安全側に倒す）', () => {
    expect(DEFAULT_CONFIG.failOnIncompleteScan).toBe(true);
  });
});
