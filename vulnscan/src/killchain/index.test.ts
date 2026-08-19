import { describe, expect, it, vi } from 'vitest';
import type { EntryPoint } from '../types/context.js';
import type { VulnScanConfig } from '../types/config.js';
import type { LlmClient, LlmResult } from '../llm/client.js';
import { analyzeKillChains } from './index.js';
import type { KillChainResponse } from './schema.js';
import { makeCallGraph, makeContext, makeFinding, makeSymbolTable } from './test-fixtures.js';

// --- 共通フィクスチャ -----------------------------------------------------

const route: EntryPoint = {
  kind: 'http-route',
  identifier: 'GET /api/report',
  file: 'src/api.ts',
  line: 5,
};

const ctx = makeContext({
  entryPoints: [route],
  symbols: makeSymbolTable([
    { name: 'reportRoute', kind: 'route', file: 'src/api.ts', startLine: 1, endLine: 20 },
    { name: 'fetchRemote', kind: 'function', file: 'src/fetch.ts', startLine: 1, endLine: 40 },
    { name: 'runShell', kind: 'function', file: 'src/shell.ts', startLine: 1, endLine: 30 },
  ]),
  callGraph: makeCallGraph([
    ['src/api.ts:reportRoute', 'src/fetch.ts:fetchRemote', 0.9],
    ['src/fetch.ts:fetchRemote', 'src/shell.ts:runShell', 0.9],
  ]),
});

const ssrf = makeFinding({
  id: 'F-ssrf',
  file: 'src/fetch.ts',
  startLine: 10,
  endLine: 12,
  cwe: 'CWE-918',
  baseScore: 6.5,
  severity: 'medium',
});

const cmd = makeFinding({
  id: 'F-cmd',
  file: 'src/shell.ts',
  startLine: 8,
  endLine: 9,
  cwe: 'CWE-78',
  baseScore: 5.9,
  severity: 'medium',
});

const config: VulnScanConfig = {
  llm: {
    model: 'claude-opus-5',
    effort: 'high',
    maxTokens: 16000,
    concurrency: 2,
    tokenBudget: null,
    fallbackModel: null,
    cache: false,
  },
  scan: {
    exclude: [],
    include: [],
    lenses: ['injection'],
    selfVerify: false,
    minConfidence: 0.5,
    maxFileBytes: 512_000,
  },
  failOn: 'high',
  failOnNewOnly: false,
  baselinePath: '.vulnscan/baseline.json',
  ignorePath: '.vulnignore',
  reportDir: 'reports',
  archiveReport: false,
  kev: false,
  kevPath: '.grimoire/kev.json',
  killChain: true,
  failOnIncompleteScan: true,
  architecture: false,
  heatmap: false,
  minInferenceConfidence: 0.5,
};

const goodResponse: KillChainResponse = {
  chains: [
    {
      title: 'SSRF から OS コマンド実行への連鎖',
      chainViable: true,
      entryPoint: 'GET /api/report',
      steps: [
        {
          findingId: 'F-ssrf',
          killChainPhase: 'exploitation',
          attackTactic: 'credential-access',
          attackTechnique: 'T1552.005',
          description: '内部メタデータAPIへリクエストを飛ばして資格情報を得る',
          preconditions: ['宛先ホストの検証がない'],
        },
        {
          findingId: null,
          killChainPhase: 'exploitation',
          attackTactic: 'discovery',
          attackTechnique: 'T1082',
          description: '取得した情報で内部構成を把握する',
          preconditions: [],
        },
        {
          findingId: 'F-cmd',
          killChainPhase: 'exploitation',
          attackTactic: 'execution',
          attackTechnique: 'T1059.004',
          description: 'シェル経由で任意コマンドを実行する',
          preconditions: ['引数がエスケープされていない'],
        },
      ],
      impact: 'アプリケーションサーバの完全掌握',
      likelihood: 'medium',
      chokePointFindingId: 'F-ssrf',
      chokePointRationale: '最上流の入口であり宛先 allowlist で塞げる',
      reasoning: '呼び出しパスが route→fetchRemote→runShell で繋がっている',
    },
  ],
};

/** LlmClient のスタブ。structured() だけを差し替える。 */
function stubLlm(
  impl: (opts: { system: string; user: string }) => Promise<LlmResult<unknown>>,
): { llm: LlmClient; calls: { system: string; user: string }[] } {
  const calls: { system: string; user: string }[] = [];
  const structured = vi.fn(async (opts: { system: string; user: string }) => {
    calls.push({ system: opts.system, user: opts.user });
    return impl(opts);
  });
  return { llm: { structured } as unknown as LlmClient, calls };
}

function ok<T>(value: T): LlmResult<T> {
  return { ok: true, value, fromCache: false, model: 'claude-opus-5' };
}

// --- テスト ---------------------------------------------------------------

describe('analyzeKillChains', () => {
  it('killChain が false なら LLM を呼ばずに空を返す', async () => {
    const { llm, calls } = stubLlm(async () => ok(goodResponse));
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, { ...config, killChain: false });
    expect(r.chains).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it('Finding が無ければ LLM を呼ばない', async () => {
    const { llm, calls } = stubLlm(async () => ok(goodResponse));
    const r = await analyzeKillChains([], ctx, llm, config);
    expect(r.chains).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it('false-positive / fixed の Finding は材料にしない', async () => {
    const { llm, calls } = stubLlm(async () => ok(goodResponse));
    const r = await analyzeKillChains(
      [
        { ...ssrf, status: 'false-positive' },
        { ...cmd, status: 'fixed' },
      ],
      ctx,
      llm,
      config,
    );
    expect(r.chains).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it('連鎖を組み立ててスコアとチョークポイントを付ける', async () => {
    const { llm } = stubLlm(async () => ok(goodResponse));
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);

    expect(r.chains).toHaveLength(1);
    const chain = r.chains[0];
    expect(chain?.title).toBe('SSRF から OS コマンド実行への連鎖');
    expect(chain?.entryPoint).toBe('GET /api/report');
    expect(chain?.steps.map((s) => s.order)).toEqual([1, 2, 3]);
    expect(chain?.steps[0]?.attackTechnique).toBe('T1552.005');
    expect(chain?.steps[1]?.findingId).toBeNull();
    expect(chain?.chokePoint?.findingId).toBe('F-ssrf');
    expect(chain?.priorityScore).toBeGreaterThan(0);
    expect(chain?.priorityScore).toBeLessThanOrEqual(100);
    expect(['high', 'medium', 'low']).toContain(chain?.likelihood);
    expect(chain?.reasoning).toContain('スコア内訳');
  });

  it('プロンプトに到達可能性の根拠（呼び出しパス）が含まれる', async () => {
    const { llm, calls } = stubLlm(async () => ok(goodResponse));
    await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(calls).toHaveLength(1);
    const user = calls[0]?.user ?? '';
    expect(user).toContain('到達可能性の根拠');
    expect(user).toContain('src/api.ts:reportRoute → src/fetch.ts:fetchRemote');
    expect(user).toContain('F-ssrf');
    expect(user).toContain('GET /api/report');
    // system は不変（キャッシュ対象）
    expect(calls[0]?.system).toContain('ATT&CK 戦術');
    expect(calls[0]?.system).toContain('ATT&CK テクニック');
    expect(calls[0]?.system).not.toContain('F-ssrf');
  });

  it('存在しない findingId は null に落とし、エラーに記録する', async () => {
    const { llm } = stubLlm(async () =>
      ok({
        chains: [
          {
            ...goodResponse.chains[0]!,
            steps: [
              { ...goodResponse.chains[0]!.steps[0]!, findingId: 'F-ssrf' },
              { ...goodResponse.chains[0]!.steps[2]!, findingId: 'F-GHOST' },
            ],
          },
        ],
      } satisfies KillChainResponse),
    );
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains[0]?.steps[1]?.findingId).toBeNull();
    expect(r.errors.join()).toContain('F-GHOST');
  });

  it('カタログ外のテクニックIDを CWE 対応表で補正する', async () => {
    const { llm } = stubLlm(async () =>
      ok({
        chains: [
          {
            ...goodResponse.chains[0]!,
            steps: [{ ...goodResponse.chains[0]!.steps[0]!, attackTechnique: 'T4242' }],
          },
        ],
      } satisfies KillChainResponse),
    );
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains[0]?.steps[0]?.attackTechnique).toBe('T1552.005');
    expect(r.errors.join()).toContain('T4242');
  });

  it('chainViable=false の連鎖は採用しない', async () => {
    const { llm } = stubLlm(async () =>
      ok({ chains: [{ ...goodResponse.chains[0]!, chainViable: false }] } satisfies KillChainResponse),
    );
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toEqual([]);
  });

  it('Finding に一切紐づかない連鎖は採用しない', async () => {
    const { llm } = stubLlm(async () =>
      ok({
        chains: [
          {
            ...goodResponse.chains[0]!,
            steps: [{ ...goodResponse.chains[0]!.steps[1]! }],
          },
        ],
      } satisfies KillChainResponse),
    );
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toEqual([]);
  });

  it('refusal は errors に積んで全体を止めない', async () => {
    const { llm } = stubLlm(async () => ({ ok: false, reason: 'refusal', category: 'cyber' }));
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toEqual([]);
    expect(r.errors.join()).toContain('拒否');
    expect(r.errors.join()).toContain('cyber');
  });

  it('error も errors に積んで全体を止めない', async () => {
    const { llm } = stubLlm(async () => ({ ok: false, reason: 'error', error: 'レート制限' }));
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toEqual([]);
    expect(r.errors.join()).toContain('レート制限');
  });

  it('個別グループの失敗があっても成功したグループの結果は返る', async () => {
    let n = 0;
    const { llm } = stubLlm(async () => {
      n += 1;
      return n === 1 ? { ok: false, reason: 'error', error: '一時障害' } : ok(goodResponse);
    });
    const rce = makeFinding({
      id: 'F-rce',
      file: 'src/shell.ts',
      startLine: 20,
      endLine: 21,
      cwe: 'CWE-78',
      severity: 'critical',
      baseScore: 9.8,
    });
    const r = await analyzeKillChains([ssrf, cmd, rce], ctx, llm, { ...config, llm: { ...config.llm, concurrency: 1 } });
    expect(r.errors.join()).toContain('一時障害');
    expect(r.chains.length).toBeGreaterThan(0);
  });

  it('budget-exhausted なら以降の呼び出しを打ち切る', async () => {
    const { llm, calls } = stubLlm(async () => ({ ok: false, reason: 'budget-exhausted' }));
    const rce = makeFinding({
      id: 'F-rce',
      file: 'src/shell.ts',
      startLine: 20,
      endLine: 21,
      severity: 'critical',
      baseScore: 9.8,
    });
    const r = await analyzeKillChains([ssrf, cmd, rce], ctx, llm, {
      ...config,
      llm: { ...config.llm, concurrency: 1 },
    });
    expect(calls).toHaveLength(1);
    expect(r.errors.filter((e) => e.includes('予算'))).toHaveLength(1);
  });

  it('連鎖は priorityScore の降順に並ぶ', async () => {
    const { llm } = stubLlm(async () => ok(goodResponse));
    const rce = makeFinding({
      id: 'F-rce',
      file: 'src/shell.ts',
      startLine: 20,
      endLine: 21,
      cwe: 'CWE-78',
      severity: 'critical',
      baseScore: 9.8,
    });
    const r = await analyzeKillChains([ssrf, cmd, rce], ctx, llm, config);
    const scores = r.chains.map((c) => c.priorityScore);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  });

  it('同一内容の連鎖は重複排除される', async () => {
    const { llm } = stubLlm(async () =>
      ok({ chains: [goodResponse.chains[0]!, { ...goodResponse.chains[0]! }] } satisfies KillChainResponse),
    );
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toHaveLength(1);
  });

  it('chain id は決定的（同じ入力なら同じ id）', async () => {
    const { llm } = stubLlm(async () => ok(goodResponse));
    const a = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    const b = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(a.chains[0]?.id).toBe(b.chains[0]?.id);
    expect(a.chains[0]?.id).toMatch(/^chain-[0-9a-f]{12}$/);
  });

  it('LLM が空配列を返しても落ちない', async () => {
    const { llm } = stubLlm(async () => ok({ chains: [] } satisfies KillChainResponse));
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config);
    expect(r.chains).toEqual([]);
    expect(r.errors).toEqual([]);
  });

  it('候補グループ単位で進捗を報告する', async () => {
    // 1グループ = LLM 1回。④で唯一観測できる刻み。
    const { llm } = stubLlm(async () => ok(goodResponse));
    const seen: { completed: number; total: number; unit: string }[] = [];
    const r = await analyzeKillChains([ssrf, cmd], ctx, llm, config, {
      onProgress: (p) => seen.push(p),
    });

    expect(r.chains.length).toBeGreaterThan(0);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((p) => p.unit === 'グループ')).toBe(true);
    const last = seen[seen.length - 1];
    expect(last?.completed).toBe(last?.total);
  });

  it('候補グループが作れなければ LLM を呼ばない', async () => {
    const { llm, calls } = stubLlm(async () => ok(goodResponse));
    const lonely = makeFinding({ id: 'F-lonely', file: 'src/nowhere.ts', baseScore: 5.0 });
    const r = await analyzeKillChains([lonely], ctx, llm, config);
    expect(r.chains).toEqual([]);
    expect(calls).toHaveLength(0);
  });
});
