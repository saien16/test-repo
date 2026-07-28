import { describe, expect, it, vi } from 'vitest';
import type { LlmClient, LlmResult } from '../llm/client.js';
import { DEFAULT_CONFIG } from '../types/config.js';
import { analyzeMechanically, analyzeResult } from './analyze.js';
import { makeChain, makeCvss, makeFinding, makeResult } from './fixtures.js';
import type { Narrative } from './narrative.js';

/** LLMクライアントのモック。実APIは一切叩かない。 */
function mockLlm(result: LlmResult<unknown>): { llm: LlmClient; structured: ReturnType<typeof vi.fn> } {
  const structured = vi.fn().mockResolvedValue(result);
  return { llm: { structured } as unknown as LlmClient, structured };
}

const okNarrative: Narrative = {
  executiveSummary: 'LLMが書いた要約です。',
  keyFindings: ['LLMが書いた所見1', 'LLMが書いた所見2'],
  riskNarrative: 'LLMが書いたリスクの全体像です。',
  trendNarrative: 'LLMが書いた前回比較です。',
};

describe('analyzeMechanically（機械的導出）', () => {
  it('チョークポイントに指定されたFindingを最優先にする', () => {
    const result = makeResult({
      findings: [
        // CVSSは最高だがチェーンに関与しない
        makeFinding({
          id: 'f-lonely',
          cwe: 'CWE-22',
          cvss: makeCvss({ baseScore: 10 }),
          remediation: 'パス正規化を行う。',
          location: { file: 'src/files.ts', startLine: 5, endLine: 6 },
        }),
        // CVSSは低いがチョークポイント
        makeFinding({
          id: 'f-1',
          cwe: 'CWE-89',
          severity: 'medium',
          cvss: makeCvss({ baseScore: 5.0, baseSeverity: 'Medium' }),
        }),
        makeFinding({
          id: 'f-2',
          cwe: 'CWE-798',
          severity: 'high',
          cvss: makeCvss({ baseScore: 7.5, baseSeverity: 'High' }),
          remediation: '鍵を環境変数へ移す。',
          location: { file: 'src/auth/token.ts', startLine: 12, endLine: 12 },
        }),
      ],
      chains: [makeChain()],
    });

    const { ranked, actions } = analyzeMechanically(result);
    expect(ranked[0]!.finding.id).toBe('f-1');
    expect(ranked[0]!.chokePointChainIds).toEqual(['ch-1']);
    expect(actions[0]!.resolves.findings).toContain('f-1');
    // チョークポイントを潰せばチェーンが遮断される
    expect(actions[0]!.resolves.chains).toContain('ch-1');
  });

  it('複数チェーンに登場するFindingを上位にする', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-shared', severity: 'medium', cvss: makeCvss({ baseScore: 5.0 }) }),
        makeFinding({
          id: 'f-solo',
          cwe: 'CWE-22',
          severity: 'high',
          cvss: makeCvss({ baseScore: 8.0 }),
          remediation: 'パス正規化を行う。',
          location: { file: 'src/files.ts', startLine: 5, endLine: 6 },
        }),
      ],
      chains: [
        makeChain({
          id: 'ch-a',
          chokePoint: null,
          steps: [
            {
              order: 1,
              findingId: 'f-shared',
              killChainPhase: 'exploitation',
              attackTactic: 'initial-access',
              description: 'A',
              preconditions: [],
            },
          ],
        }),
        makeChain({
          id: 'ch-b',
          chokePoint: null,
          steps: [
            {
              order: 1,
              findingId: 'f-shared',
              killChainPhase: 'exploitation',
              attackTactic: 'execution',
              description: 'B',
              preconditions: [],
            },
          ],
        }),
      ],
    });

    const { ranked, signals } = analyzeMechanically(result);
    expect(signals.get('f-shared')!.chainIds).toEqual(['ch-a', 'ch-b']);
    expect(ranked[0]!.finding.id).toBe('f-shared');
  });

  it('同じパッケージの依存脆弱性を1つのアクションに集約する', () => {
    const pkg = { name: 'lodash', version: '4.17.20', ecosystem: 'npm', fixedVersion: '4.17.21' };
    const result = makeResult({
      findings: [
        makeFinding({
          id: 'd-1',
          cwe: 'CWE-1321',
          cve: 'CVE-2020-8203',
          affectedPackage: pkg,
          remediation: 'lodash を更新する。',
          dataFlow: [],
        }),
        makeFinding({
          id: 'd-2',
          cwe: 'CWE-400',
          cve: 'CVE-2021-23337',
          affectedPackage: pkg,
          remediation: 'lodash を更新する。',
          dataFlow: [],
        }),
      ],
    });

    const { actions } = analyzeMechanically(result);
    expect(actions).toHaveLength(1);
    expect(actions[0]!.resolves.findings.sort()).toEqual(['d-1', 'd-2']);
    expect(actions[0]!.action).toContain('4.17.21');
    // 修正版が出ているので工数は小
    expect(actions[0]!.effort).toBe('low');
  });

  it('修正版が無い依存は工数を大に見積もる', () => {
    const result = makeResult({
      findings: [
        makeFinding({
          id: 'd-1',
          affectedPackage: { name: 'oldpkg', version: '1.0.0', ecosystem: 'npm' },
          dataFlow: [],
        }),
      ],
    });
    expect(analyzeMechanically(result).actions[0]!.effort).toBe('high');
  });

  it('同じ修正方針のコード上の問題をまとめる', () => {
    const result = makeResult({
      findings: [
        makeFinding({
          id: 'f-1',
          location: { file: 'src/a.ts', startLine: 1, endLine: 2 },
          remediation: 'プレースホルダを用いたパラメータ化クエリに書き換える。',
        }),
        makeFinding({
          id: 'f-2',
          location: { file: 'src/b.ts', startLine: 1, endLine: 2 },
          remediation: 'プレースホルダを用いたパラメータ化クエリに書き換える。',
        }),
      ],
    });
    const { actions } = analyzeMechanically(result);
    expect(actions).toHaveLength(1);
    expect(actions[0]!.resolves.findings).toHaveLength(2);
    // 2ファイルにまたがるので工数は中
    expect(actions[0]!.effort).toBe('medium');
  });

  it('修正済み・受容済みはアクションに含めない', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-1', diffStatus: 'fixed' }),
        makeFinding({ id: 'f-2', cwe: 'CWE-22', status: 'accepted', remediation: 'a'.repeat(20) }),
        makeFinding({ id: 'f-3', cwe: 'CWE-79', status: 'false-positive', remediation: 'b'.repeat(20) }),
      ],
    });
    expect(analyzeMechanically(result).actions).toHaveLength(0);
  });

  it('order は 1 から連番で振られる', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-1', cwe: 'CWE-89', remediation: 'aaaaaaaaaaaaaaaa' }),
        makeFinding({ id: 'f-2', cwe: 'CWE-22', remediation: 'bbbbbbbbbbbbbbbb' }),
        makeFinding({ id: 'f-3', cwe: 'CWE-79', remediation: 'cccccccccccccccc' }),
      ],
    });
    const { actions } = analyzeMechanically(result);
    expect(actions.map((a) => a.order)).toEqual([1, 2, 3]);
  });

  it('全件 new なら初回スキャンとみなす', () => {
    const first = makeResult({ findings: [makeFinding({ id: 'f-1', diffStatus: 'new' })] });
    expect(analyzeMechanically(first).hasBaseline).toBe(false);

    const second = makeResult({
      findings: [
        makeFinding({ id: 'f-1', diffStatus: 'new' }),
        makeFinding({ id: 'f-2', diffStatus: 'persistent' }),
      ],
    });
    expect(analyzeMechanically(second).hasBaseline).toBe(true);
  });
});

describe('analyzeResult（LLM連携）', () => {
  const result = makeResult({
    findings: [makeFinding({ id: 'f-1' }), makeFinding({ id: 'f-2', diffStatus: 'persistent' })],
    chains: [makeChain()],
  });

  it('LLMが成功したらその文章を使う', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: okNarrative,
      fromCache: false,
      model: 'claude-opus-5',
    });

    const analyzed = await analyzeResult(result, llm, DEFAULT_CONFIG);

    expect(structured).toHaveBeenCalledTimes(1);
    expect(analyzed.executiveSummary).toBe('LLMが書いた要約です。');
    expect(analyzed.riskNarrative).toBe('LLMが書いたリスクの全体像です。');
    expect(analyzed.trendNarrative).toBe('LLMが書いた前回比較です。');
    expect(analyzed.keyFindings).toEqual(['LLMが書いた所見1', 'LLMが書いた所見2']);
    // 順序と集約は機械側の結果がそのまま使われる
    expect(analyzed.prioritizedActions.length).toBeGreaterThan(0);
    expect(analyzed.summary).toBe(result.summary);
  });

  it('LLMに渡すスキーマ名とキャッシュキーを指定する', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: okNarrative,
      fromCache: false,
      model: 'claude-opus-5',
    });
    await analyzeResult(result, llm, DEFAULT_CONFIG);
    const call = structured.mock.calls[0]![0] as { schemaName: string; cacheKey: string };
    expect(call.schemaName).toBe('VulnScanNarrative');
    expect(call.cacheKey).toMatch(/^reporter-narrative:[0-9a-f]{64}$/);
  });

  it.each([
    ['refusal', { ok: false, reason: 'refusal', category: 'cyber' } as LlmResult<unknown>],
    ['budget-exhausted', { ok: false, reason: 'budget-exhausted' } as LlmResult<unknown>],
    ['error', { ok: false, reason: 'error', error: '接続エラー' } as LlmResult<unknown>],
  ])('LLMが %s で失敗しても機械生成でレポートが成立する', async (_label, failure) => {
    const { llm } = mockLlm(failure);
    const analyzed = await analyzeResult(result, llm, DEFAULT_CONFIG);

    expect(analyzed.executiveSummary.length).toBeGreaterThan(20);
    expect(analyzed.riskNarrative.length).toBeGreaterThan(20);
    expect(analyzed.prioritizedActions.length).toBeGreaterThan(0);
    expect(analyzed.summary.totalFindings).toBe(2);
    // フォールバックした事実を読み手に伝える注記が入る
    expect(analyzed.keyFindings.some((k) => k.startsWith('※'))).toBe(true);
  });

  it('LLMが例外を投げてもレポート生成は落ちない', async () => {
    const llm = {
      structured: vi.fn().mockRejectedValue(new Error('想定外の例外')),
    } as unknown as LlmClient;

    const analyzed = await analyzeResult(result, llm, DEFAULT_CONFIG);
    expect(analyzed.executiveSummary.length).toBeGreaterThan(20);
    expect(analyzed.keyFindings.some((k) => k.includes('想定外の例外'))).toBe(true);
  });

  it('Findingが0件ならLLMを呼ばずに定型文で成立させる', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: okNarrative,
      fromCache: false,
      model: 'claude-opus-5',
    });

    const analyzed = await analyzeResult(makeResult(), llm, DEFAULT_CONFIG);

    expect(structured).not.toHaveBeenCalled();
    expect(analyzed.executiveSummary).toContain('検出されませんでした');
    expect(analyzed.prioritizedActions).toEqual([]);
    expect(analyzed.riskNarrative.length).toBeGreaterThan(20);
  });

  it('LLMが空文字を返したフィールドは機械生成で埋める', async () => {
    const { llm } = mockLlm({
      ok: true,
      value: { executiveSummary: '   ', keyFindings: [], riskNarrative: '', trendNarrative: null },
      fromCache: false,
      model: 'claude-opus-5',
    });

    const analyzed = await analyzeResult(result, llm, DEFAULT_CONFIG);
    expect(analyzed.executiveSummary.trim().length).toBeGreaterThan(20);
    expect(analyzed.riskNarrative.trim().length).toBeGreaterThan(20);
    expect(analyzed.keyFindings.length).toBeGreaterThan(0);
  });

  it('ベースラインが無ければ trendNarrative を出さない', async () => {
    const firstScan = makeResult({
      findings: [makeFinding({ id: 'f-1', diffStatus: 'new' })],
    });
    const { llm } = mockLlm({
      ok: true,
      value: okNarrative,
      fromCache: false,
      model: 'claude-opus-5',
    });

    const analyzed = await analyzeResult(firstScan, llm, DEFAULT_CONFIG);
    expect(analyzed.trendNarrative).toBeUndefined();
  });
});
