import { describe, expect, it } from 'vitest';
import type { LlmClient, LlmResult } from '../llm/client.js';
import { DEFAULT_CONFIG } from '../types/config.js';
import type { VulnScanConfig } from '../types/config.js';
import type { ScanContext, SymbolInfo } from '../types/context.js';
import { assessAnalysisHealth, skippedTasks } from '../types/health.js';
import { analyze } from './index.js';
import type { CandidateFinding, Verdict } from './schema.js';

const FILE = 'src/a.ts';
const CONTENT = [
  'export function getUser(req, res) {', // 1
  '  const id = req.params.id;', // 2
  '  const rows = db.query(`SELECT * FROM u WHERE id=${id}`);', // 3
  '  res.json(rows);', // 4
  '}', // 5
].join('\n');

const SYMBOL: SymbolInfo = {
  name: 'getUser',
  kind: 'function',
  file: FILE,
  startLine: 1,
  endLine: 5,
  exported: true,
};

function makeContext(): ScanContext {
  return {
    repoRoot: '/repo',
    scannedAt: '2026-07-28T00:00:00Z',
    readme: null,
    languages: [{ name: 'typescript', fileCount: 1, ratio: 1 }],
    frameworks: [{ name: 'express', evidence: 'package.json' }],
    dependencies: [],
    files: [{ path: FILE, language: 'typescript', sizeBytes: CONTENT.length, lines: CONTENT.split('\n').length, hash: 'hash-1' }],
    symbols: { symbols: [SYMBOL], byId: { [`${FILE}:getUser`]: SYMBOL } },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [],
    trustBoundaries: [],
    warnings: [],
  };
}

function makeConfig(overrides: Partial<VulnScanConfig['scan']> = {}): VulnScanConfig {
  return {
    ...DEFAULT_CONFIG,
    llm: { ...DEFAULT_CONFIG.llm, concurrency: 1 },
    scan: { ...DEFAULT_CONFIG.scan, lenses: ['injection'], ...overrides },
  };
}

const CANDIDATE: CandidateFinding = {
  cwe: 'CWE-89',
  category: 'A03:2021-Injection',
  title: 'SQLインジェクション',
  severity: 'high',
  confidence: 0.9,
  location: { file: FILE, startLine: 3, endLine: 3 },
  evidence: 'db.query(`SELECT * FROM u WHERE id=${id}`)',
  dataFlow: [
    {
      file: FILE,
      line: 2,
      code: 'const id = req.params.id;',
      role: 'source',
      description: 'リクエストパラメータ',
    },
    {
      file: FILE,
      line: 3,
      code: 'db.query(...)',
      role: 'sink',
      description: '文字列連結',
    },
  ],
  reasoning: '連結された値がそのままクエリに渡る',
  remediation: 'プレースホルダを使う',
};

const CONFIRMED: Verdict = {
  verdict: 'confirmed',
  confidence: 0.9,
  exploitPath: 'req.params.id → db.query',
  rebuttal: '',
  missingEvidence: [],
  correctedSeverity: 'high',
};

interface RecordedCall {
  system: string;
  user: string;
  schemaName: string;
  cacheKey: string | undefined;
}

type Handler = (call: RecordedCall) => LlmResult<unknown>;

function makeLlm(handler: Handler): { llm: LlmClient; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const llm = {
    structured: async (opts: {
      system: string;
      user: string;
      schemaName: string;
      cacheKey?: string;
    }) => {
      const call: RecordedCall = {
        system: opts.system,
        user: opts.user,
        schemaName: opts.schemaName,
        cacheKey: opts.cacheKey,
      };
      calls.push(call);
      return handler(call);
    },
  } as unknown as LlmClient;
  return { llm, calls };
}

function ok(value: unknown): LlmResult<unknown> {
  return { ok: true, value, fromCache: false, model: 'test-model' };
}

const readFile = async (_root: string, path: string): Promise<string | null> =>
  path === FILE ? CONTENT : null;

describe('analyze', () => {
  it('分析パスと自己検証パスを通して RawFinding を返す', async () => {
    const { llm, calls } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis' ? ok({ findings: [CANDIDATE] }) : ok(CONFIRMED),
    );

    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.errors).toEqual([]);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding?.cwe).toBe('CWE-89');
    expect(finding?.lens).toBe('injection');
    expect(finding?.confidence).toBeCloseTo(0.9, 5);
    expect(finding?.reasoning).toContain('[自己検証]');

    expect(calls.map((c) => c.schemaName)).toEqual(['VulnScanAnalysis', 'VulnScanVerdict']);
  });

  it('キャッシュキーにファイルハッシュ・レンズID・チャンク識別子を含める', async () => {
    const { llm, calls } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis' ? ok({ findings: [CANDIDATE] }) : ok(CONFIRMED),
    );
    await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(calls[0]?.cacheKey).toBe('hash-1|injection|src/a.ts#getUser@1-5');
    // 検証パスは同じチャンクでも別キー（候補ごとに分かれる）
    expect(calls[1]?.cacheKey).toContain('hash-1|injection|src/a.ts#getUser@1-5|verify|');
    expect(calls[1]?.cacheKey).not.toBe(calls[0]?.cacheKey);
  });

  it('プロンプトに文脈とコードを載せる', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    await analyze(makeContext(), llm, makeConfig({ selfVerify: false }), { readFile });

    const user = calls[0]?.user ?? '';
    expect(user).toContain('検出済みフレームワーク');
    expect(user).toContain('エントリポイントからの到達可能性');
    expect(user).toContain('    3|   const rows = db.query');
    expect(calls[0]?.system).toContain('インジェクション');
  });

  it('有効なレンズごとに走査する', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    await analyze(
      makeContext(),
      llm,
      makeConfig({ lenses: ['injection', 'crypto-secrets'], selfVerify: false }),
      { readFile },
    );
    expect(calls).toHaveLength(2);
    expect(new Set(calls.map((c) => c.system)).size).toBe(2);
  });

  it("②で扱えないレンズ（dependency）はスキップして記録する", async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    const result = await analyze(
      makeContext(),
      llm,
      makeConfig({ lenses: ['dependency'], selfVerify: false }),
      { readFile },
    );
    expect(calls).toHaveLength(0);
    expect(result.errors.some((e) => e.includes('dependency'))).toBe(true);
  });

  it('自己検証が無効なら2nd passを呼ばない', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [CANDIDATE] }));
    const result = await analyze(makeContext(), llm, makeConfig({ selfVerify: false }), {
      readFile,
    });
    expect(calls.map((c) => c.schemaName)).toEqual(['VulnScanAnalysis']);
    expect(result.findings).toHaveLength(1);
  });

  it('反証された指摘は破棄する', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis'
        ? ok({ findings: [CANDIDATE] })
        : ok({
            ...CONFIRMED,
            verdict: 'refuted',
            rebuttal: 'プレースホルダにバインドされている',
          } satisfies Verdict),
    );

    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });
    expect(result.findings).toEqual([]);
  });

  it('minConfidence 未満は破棄する', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis'
        ? ok({ findings: [CANDIDATE] })
        : ok({ ...CONFIRMED, verdict: 'uncertain', confidence: 0.5 } satisfies Verdict),
    );

    const result = await analyze(makeContext(), llm, makeConfig({ minConfidence: 0.8 }), {
      readFile,
    });
    expect(result.findings).toEqual([]);
  });

  it('refusal はエラーに積んで該当チャンクだけスキップする', async () => {
    const { llm } = makeLlm(() => ({ ok: false, reason: 'refusal', category: 'cyber' }));
    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.findings).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('拒否');
    expect(result.errors[0]).toContain('cyber');
  });

  it('個々の失敗で全体を止めない', async () => {
    let first = true;
    const { llm } = makeLlm((call) => {
      if (call.schemaName === 'VulnScanAnalysis' && first) {
        first = false;
        return { ok: false, reason: 'error', error: 'レート制限' };
      }
      return call.schemaName === 'VulnScanAnalysis' ? ok({ findings: [CANDIDATE] }) : ok(CONFIRMED);
    });

    const ctx = makeContext();
    ctx.files.push({
      path: 'src/b.ts',
      language: 'typescript',
      sizeBytes: CONTENT.length,
      lines: CONTENT.split('\n').length,
      hash: 'hash-2',
    });

    const result = await analyze(ctx, llm, makeConfig(), {
      readFile: async () => CONTENT,
    });

    expect(result.errors.some((e) => e.includes('レート制限'))).toBe(true);
    expect(result.findings).toHaveLength(1);
  });

  it('予算切れなら以降の分析を打ち切る', async () => {
    const { llm, calls } = makeLlm(() => ({ ok: false, reason: 'budget-exhausted' }));

    const ctx = makeContext();
    ctx.files.push({
      path: 'src/b.ts',
      language: 'typescript',
      sizeBytes: CONTENT.length,
      lines: CONTENT.split('\n').length,
      hash: 'hash-2',
    });

    const result = await analyze(ctx, llm, makeConfig(), { readFile: async () => CONTENT });

    // 1回目で打ち切られ、2つ目のチャンクは呼ばれない
    expect(calls).toHaveLength(1);
    expect(result.errors).toEqual([
      'トークン予算を使い切ったため、以降の分析を打ち切りました（それまでの結果のみ返します）',
    ]);
  });

  it('サイズ上限を超えるファイルはスキップして記録する', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    const result = await analyze(makeContext(), llm, makeConfig({ maxFileBytes: 10 }), {
      readFile,
    });

    expect(calls).toHaveLength(0);
    expect(result.errors[0]).toContain('上限');
  });

  it('読み込めないファイルはスキップして記録する', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    const result = await analyze(makeContext(), llm, makeConfig(), {
      readFile: async () => null,
    });

    expect(calls).toHaveLength(0);
    expect(result.errors[0]).toContain('読み込めなかった');
  });

  it('user プロンプトはレンズ間で同一（チャンクごとに1回だけ組み立てる）', async () => {
    const { llm, calls } = makeLlm(() => ok({ findings: [] }));
    await analyze(
      makeContext(),
      llm,
      makeConfig({ lenses: ['injection', 'crypto-secrets', 'authz'], selfVerify: false }),
      { readFile },
    );

    expect(calls).toHaveLength(3);
    // system はレンズごとに変わるが、user はレンズに依存しない
    expect(new Set(calls.map((c) => c.system)).size).toBe(3);
    expect(new Set(calls.map((c) => c.user)).size).toBe(1);
    // 同じチャンクのタスクは文字列インスタンスまで共有している
    expect(calls[1]?.user).toBe(calls[0]?.user);
    expect(calls[2]?.user).toBe(calls[0]?.user);
  });

  it('自己検証の refusal は警告だけ積んで未検証として続行する', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis'
        ? ok({ findings: [CANDIDATE] })
        : { ok: false, reason: 'refusal', category: 'cyber' },
    );

    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    // 検証できなかった候補は破棄せず残る
    expect(result.findings).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('自己検証が拒否されました');
    expect(result.errors[0]).toContain('category=cyber');
    expect(result.errors[0]).toContain('未検証として扱います');
  });

  it('自己検証パスの予算切れも同じメッセージで打ち切る', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis'
        ? ok({ findings: [CANDIDATE] })
        : { ok: false, reason: 'budget-exhausted' },
    );

    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.errors).toEqual([
      'トークン予算を使い切ったため、以降の分析を打ち切りました（それまでの結果のみ返します）',
    ]);
  });

  it('進捗を通知する', async () => {
    const phases: string[] = [];
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis' ? ok({ findings: [CANDIDATE] }) : ok(CONFIRMED),
    );

    await analyze(makeContext(), llm, makeConfig(), {
      readFile,
      onProgress: (p) => phases.push(p.phase),
    });

    expect(phases).toEqual(['analyze', 'verify']);
  });
});

/*
 * 実行統計。これが無いと下流（CIゲート・レポート文言）が
 * 「検出0件」を「見たが無かった」と「見られなかった」に区別できず、
 * 全滅した走査が緑のCIと「脆弱性なし」のレポートになる。
 */
describe('analyze の実行統計', () => {
  /** チャンクを2つにするための2ファイル構成 */
  function twoFileContext(): ScanContext {
    const ctx = makeContext();
    ctx.files.push({
      path: 'src/b.ts',
      language: 'typescript',
      sizeBytes: CONTENT.length,
      lines: CONTENT.split('\n').length,
      hash: 'hash-2',
    });
    return ctx;
  }

  const readAny = async (): Promise<string> => CONTENT;

  it('全件成功なら complete と判定される統計を返す', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis' ? ok({ findings: [] }) : ok(CONFIRMED),
    );
    const result = await analyze(twoFileContext(), llm, makeConfig(), { readFile: readAny });

    expect(result.stats).toEqual({
      total: 2,
      succeeded: 2,
      failed: 0,
      refused: 0,
      budgetExhausted: false,
      fromCache: 0,
    });
    expect(assessAnalysisHealth(result.stats).zeroFindingsIsMeaningful).toBe(true);
  });

  it('全滅した場合は failed と判定される統計を返す（検出0件でも0件に意味は無い）', async () => {
    const { llm } = makeLlm(() => ({
      ok: false,
      reason: 'error',
      error: '認証エラー: APIキーが設定されていません',
    }));
    const result = await analyze(twoFileContext(), llm, makeConfig(), { readFile: readAny });

    expect(result.findings).toEqual([]);
    expect(result.stats.total).toBe(2);
    expect(result.stats.succeeded).toBe(0);
    expect(result.stats.failed).toBe(2);

    const health = assessAnalysisHealth(result.stats);
    expect(health.level).toBe('failed');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
  });

  it('refusal は failed ではなく refused に数える', async () => {
    const { llm } = makeLlm(() => ({ ok: false, reason: 'refusal', category: 'cyber' }));
    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.stats.refused).toBe(1);
    expect(result.stats.failed).toBe(0);
  });

  it('キャッシュ由来は成功かつ fromCache に数える', async () => {
    const llm = {
      structured: async () => ({
        ok: true as const,
        value: { findings: [] },
        fromCache: true,
        model: 'test-model',
      }),
    } as unknown as LlmClient;
    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.stats.succeeded).toBe(1);
    expect(result.stats.fromCache).toBe(1);
    expect(assessAnalysisHealth(result.stats).level).toBe('complete');
  });

  it('予算切れで打ち切られた分は失敗ではなく「未実行」として現れる', async () => {
    const { llm } = makeLlm(() => ({ ok: false, reason: 'budget-exhausted' }));
    const result = await analyze(twoFileContext(), llm, makeConfig(), { readFile: readAny });

    // 打ち切りは「失敗」ではないので failed/refused には入らない。
    // total との差（=2）が未走査であることを示す。
    expect(result.stats.total).toBe(2);
    expect(result.stats.failed).toBe(0);
    expect(result.stats.refused).toBe(0);
    expect(result.stats.budgetExhausted).toBe(true);
    expect(skippedTasks(result.stats)).toBe(2);
    expect(assessAnalysisHealth(result.stats).level).toBe('failed');
  });

  it('検証パスだけ予算切れなら未走査は0件（検出パスは完走している）', async () => {
    const { llm } = makeLlm((call) =>
      call.schemaName === 'VulnScanAnalysis'
        ? ok({ findings: [CANDIDATE] })
        : { ok: false, reason: 'budget-exhausted' },
    );
    const result = await analyze(makeContext(), llm, makeConfig(), { readFile });

    expect(result.stats.succeeded).toBe(1);
    expect(result.stats.total).toBe(1);
    expect(skippedTasks(result.stats)).toBe(0);
    expect(result.stats.budgetExhausted).toBe(true);
    // 走査範囲は欠けていないので degraded 止まり
    expect(assessAnalysisHealth(result.stats).level).toBe('degraded');
  });

  it('レンズが無い場合は total 0（「見た結果0件」と区別できる）', async () => {
    const { llm } = makeLlm(() => ok({ findings: [] }));
    const result = await analyze(makeContext(), llm, makeConfig({ lenses: [] }), { readFile });

    expect(result.stats.total).toBe(0);
    expect(assessAnalysisHealth(result.stats).zeroFindingsIsMeaningful).toBe(false);
  });

  it('走査対象ファイルが無い場合も total 0', async () => {
    const { llm } = makeLlm(() => ok({ findings: [] }));
    const ctx = makeContext();
    ctx.files = [];
    const result = await analyze(ctx, llm, makeConfig(), { readFile });

    expect(result.stats.total).toBe(0);
    expect(assessAnalysisHealth(result.stats).level).toBe('degraded');
  });

  it('レンズ数×チャンク数がタスク総数になる', async () => {
    const { llm } = makeLlm(() => ok({ findings: [] }));
    const result = await analyze(
      twoFileContext(),
      llm,
      makeConfig({ lenses: ['injection', 'crypto-secrets'], selfVerify: false }),
      { readFile: readAny },
    );

    expect(result.stats.total).toBe(4);
    expect(result.stats.succeeded).toBe(4);
  });
});
