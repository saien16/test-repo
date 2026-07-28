/**
 * ② ソースコード分析（LLM中心）。
 *
 * ScanContext を入力に、以下のパイプラインで RawFinding[] を作る:
 *
 *   1. チャンク分割      : ctx.symbols を使って構文単位で切る（chunker.ts）
 *   2. 文脈の付与        : 呼び出しグラフ・信頼境界・到達可能性を添える（context.ts）
 *   3. 多視点レンズ走査  : レンズごとの system プロンプトで構造化出力を得る（lenses/）
 *   4. 自己検証パス      : 別プロンプトで反証を試み、確信度を補正する（verify.ts）
 *   5. 正規化と絞り込み  : 減点・閾値・重複統合（filter.ts）
 *
 * 個々のチャンクの失敗は errors に積んで全体は止めない。
 * トークン予算が尽きた場合はそこで打ち切り、それまでの結果を返す。
 */

import type { LlmClient } from '../llm/client.js';
import { mapPool } from '../llm/pool.js';
import type { ScanContext, SymbolInfo } from '../types/context.js';
import type { VulnScanConfig } from '../types/config.js';
import type { RawFinding } from '../types/finding.js';
import { chunkFile, groupSymbolsByFile, splitLines } from './chunker.js';
import {
  buildChunkContext,
  type ChunkContext,
  type ContextBuildOptions,
} from './context.js';
import { finalizeFindings, toRawFinding } from './filter.js';
import { selectLenses, type Lens } from './lenses/index.js';
import { buildAnalysisPrompt } from './prompt.js';
import {
  analysisResultSchema,
  verdictSchema,
  type CandidateFinding,
  type Verdict,
} from './schema.js';
import { defaultSourceReader, type SourceReader } from './source.js';
import { DEFAULT_CHUNK_LIMITS, type Chunk, type ChunkLimits } from './types.js';
import { applyVerdict, buildVerificationPrompt, VERIFY_SYSTEM_PROMPT } from './verify.js';

export type { Chunk, ChunkLimits, LineRange, RelatedSymbol } from './types.js';
export type { ChunkContext } from './context.js';
export type { CandidateFinding, Verdict } from './schema.js';
export { chunkFile, groupSymbolsByFile } from './chunker.js';
export { buildChunkContext } from './context.js';
export { LENSES, getLens, selectLenses } from './lenses/index.js';
export {
  dedupeFindings,
  evidencePenalty,
  filterByConfidence,
  finalizeFindings,
  sortFindings,
  toRawFinding,
} from './filter.js';
export { applyVerdict } from './verify.js';

export interface AnalyzeProgress {
  phase: 'analyze' | 'verify';
  completed: number;
  total: number;
}

/** テストや呼び出し側からの差し替え用 */
export interface AnalyzeDeps {
  readFile?: SourceReader;
  chunkLimits?: ChunkLimits;
  contextOptions?: ContextBuildOptions;
  onProgress?: (progress: AnalyzeProgress) => void;
}

export interface AnalyzeResult {
  findings: RawFinding[];
  errors: string[];
}

interface AnalysisTask {
  chunk: Chunk;
  chunkContext: ChunkContext;
  lens: Lens;
}

interface Candidate {
  task: AnalysisTask;
  candidate: CandidateFinding;
}

interface BudgetState {
  exhausted: boolean;
}

const SCHEMA_NAME_ANALYSIS = 'VulnScanAnalysis';
const SCHEMA_NAME_VERDICT = 'VulnScanVerdict';

function taskLabel(task: AnalysisTask): string {
  return `[${task.lens.id}] ${task.chunk.id}`;
}

/** 候補ごとに安定したキャッシュキー断片を作る（同じ指摘なら同じ検証結果を再利用） */
function candidateKey(candidate: CandidateFinding): string {
  return [
    candidate.cwe.trim().toUpperCase(),
    candidate.location.file,
    candidate.location.startLine,
    candidate.location.endLine,
    candidate.title.trim(),
  ].join('|');
}

/**
 * 予算切れを記録する。最初の1回だけ errors に積む。
 * 以降のタスクは呼び出す前に打ち切られる。
 */
function markBudgetExhausted(state: BudgetState, errors: string[]): void {
  if (state.exhausted) return;
  state.exhausted = true;
  errors.push(
    'トークン予算を使い切ったため、以降の分析を打ち切りました（それまでの結果のみ返します）',
  );
}

/** ファイルを読んでチャンクに分割する */
async function collectChunks(
  ctx: ScanContext,
  config: VulnScanConfig,
  read: SourceReader,
  limits: ChunkLimits,
  errors: string[],
): Promise<{ chunks: Chunk[]; sourceLines: Map<string, string[]> }> {
  const symbolsByFile = groupSymbolsByFile(ctx.symbols.symbols);
  const sourceLines = new Map<string, string[]>();
  const chunks: Chunk[] = [];

  for (const file of ctx.files) {
    if (file.sizeBytes > config.scan.maxFileBytes) {
      errors.push(
        `${file.path}: ${file.sizeBytes} バイトで上限 ${config.scan.maxFileBytes} を超えるためスキップしました`,
      );
      continue;
    }

    let content: string | null;
    try {
      content = await read(ctx.repoRoot, file.path);
    } catch (err) {
      errors.push(`${file.path}: 読み込みに失敗しました: ${String(err)}`);
      continue;
    }
    if (content === null) {
      errors.push(`${file.path}: 読み込めなかったためスキップしました`);
      continue;
    }

    sourceLines.set(file.path, splitLines(content));
    const symbols: SymbolInfo[] = symbolsByFile.get(file.path) ?? [];
    chunks.push(...chunkFile({ file, content, symbols }, limits));
  }

  return { chunks, sourceLines };
}

/** 1st pass: レンズ × チャンクを並列に走らせる */
async function runAnalysisPass(
  tasks: readonly AnalysisTask[],
  llm: LlmClient,
  config: VulnScanConfig,
  state: BudgetState,
  errors: string[],
  onProgress?: (p: AnalyzeProgress) => void,
): Promise<Candidate[]> {
  const concurrency = Math.max(1, config.llm.concurrency);

  const results = await mapPool(
    tasks,
    concurrency,
    async (task) => {
      if (state.exhausted) return null;

      const result = await llm.structured({
        system: task.lens.systemPrompt,
        user: buildAnalysisPrompt(task.chunkContext),
        schema: analysisResultSchema,
        schemaName: SCHEMA_NAME_ANALYSIS,
        // ファイル内容ハッシュ + レンズID + チャンク識別子。
        // 変更のないコードは再分析されない。
        cacheKey: `${task.chunk.fileHash}|${task.lens.id}|${task.chunk.id}`,
      });

      if (!result.ok) {
        if (result.reason === 'budget-exhausted') {
          markBudgetExhausted(state, errors);
          return null;
        }
        if (result.reason === 'refusal') {
          // 脆弱性解析は正当な用途だが、稀に安全分類器に拒否される。
          // 該当チャンクだけ落として続行する。
          errors.push(
            `${taskLabel(task)}: 安全分類器に拒否されたためスキップしました（category=${
              result.category ?? '不明'
            }）`,
          );
          return null;
        }
        errors.push(`${taskLabel(task)}: 分析に失敗しました: ${result.error}`);
        return null;
      }

      return result.value.findings.map((candidate) => ({ task, candidate }));
    },
    onProgress
      ? (p) => onProgress({ phase: 'analyze', completed: p.completed, total: p.total })
      : undefined,
  );

  const candidates: Candidate[] = [];
  for (const group of results) {
    if (group === null) continue;
    candidates.push(...group);
  }
  return candidates;
}

/** 2nd pass: 候補ごとに反証を試みる */
async function runVerifyPass(
  candidates: readonly Candidate[],
  llm: LlmClient,
  config: VulnScanConfig,
  state: BudgetState,
  errors: string[],
  onProgress?: (p: AnalyzeProgress) => void,
): Promise<(Verdict | null)[]> {
  const concurrency = Math.max(1, config.llm.concurrency);

  return mapPool(
    candidates,
    concurrency,
    async (item) => {
      if (state.exhausted) return null;

      const { task, candidate } = item;
      const result = await llm.structured({
        system: VERIFY_SYSTEM_PROMPT,
        user: buildVerificationPrompt(candidate, task.chunkContext, task.lens.title),
        schema: verdictSchema,
        schemaName: SCHEMA_NAME_VERDICT,
        cacheKey: `${task.chunk.fileHash}|${task.lens.id}|${task.chunk.id}|verify|${candidateKey(
          candidate,
        )}`,
      });

      if (!result.ok) {
        if (result.reason === 'budget-exhausted') {
          markBudgetExhausted(state, errors);
          return null;
        }
        if (result.reason === 'refusal') {
          errors.push(
            `${taskLabel(task)}: 自己検証が拒否されました（category=${
              result.category ?? '不明'
            }）。未検証として扱います`,
          );
          return null;
        }
        errors.push(`${taskLabel(task)}: 自己検証に失敗しました: ${result.error}`);
        return null;
      }

      return result.value;
    },
    onProgress
      ? (p) => onProgress({ phase: 'verify', completed: p.completed, total: p.total })
      : undefined,
  );
}

/**
 * ソースコード分析のエントリポイント。
 *
 * 例外は投げない。部分的な失敗はすべて errors に積んで、
 * 得られた分だけの findings を返す。
 */
export async function analyze(
  ctx: ScanContext,
  llm: LlmClient,
  config: VulnScanConfig,
  deps: AnalyzeDeps = {},
): Promise<AnalyzeResult> {
  const errors: string[] = [];

  const { lenses, skipped } = selectLenses(config.scan.lenses);
  for (const id of skipped) {
    errors.push(
      `レンズ '${id}' はソースコード分析の対象外のためスキップしました（依存脆弱性は③が担当）`,
    );
  }
  if (lenses.length === 0) {
    errors.push('有効な分析レンズが無いため、ソースコード分析を実行しませんでした');
    return { findings: [], errors };
  }

  const read = deps.readFile ?? defaultSourceReader;
  const limits = deps.chunkLimits ?? DEFAULT_CHUNK_LIMITS;

  const { chunks, sourceLines } = await collectChunks(ctx, config, read, limits, errors);
  if (chunks.length === 0) {
    return { findings: [], errors };
  }

  // 関連シンボルのシグネチャに宣言行を添えるためのアクセサ
  const declarationOf = (symbol: SymbolInfo): string | undefined =>
    sourceLines.get(symbol.file)?.[symbol.startLine - 1];

  const contextOptions: ContextBuildOptions = {
    declarationOf,
    ...deps.contextOptions,
  };

  const contextByChunkId = new Map<string, ChunkContext>();
  for (const chunk of chunks) {
    contextByChunkId.set(chunk.id, buildChunkContext(ctx, chunk, contextOptions));
  }

  // レンズ単位でまとめる: 同じ system プロンプトが連続し、プロンプトキャッシュが効く
  const tasks: AnalysisTask[] = [];
  for (const lens of lenses) {
    for (const chunk of chunks) {
      const chunkContext = contextByChunkId.get(chunk.id);
      if (!chunkContext) continue;
      tasks.push({ chunk, chunkContext, lens });
    }
  }

  const state: BudgetState = { exhausted: false };
  const candidates = await runAnalysisPass(
    tasks,
    llm,
    config,
    state,
    errors,
    deps.onProgress,
  );

  const verdicts: (Verdict | null)[] =
    config.scan.selfVerify && !state.exhausted
      ? await runVerifyPass(candidates, llm, config, state, errors, deps.onProgress)
      : candidates.map(() => null);

  const raw: RawFinding[] = [];
  candidates.forEach((item, index) => {
    const verdict = verdicts[index] ?? null;
    // 自己検証が無効なときは検証メモも減点も付けない
    if (!config.scan.selfVerify) {
      raw.push(
        toRawFinding({
          candidate: item.candidate,
          chunk: item.task.chunk,
          lens: item.task.lens.id,
          confidence: item.candidate.confidence,
          severity: item.candidate.severity,
        }),
      );
      return;
    }

    const applied = applyVerdict(item.candidate, verdict);
    if (applied.dropped) return;

    raw.push(
      toRawFinding({
        candidate: item.candidate,
        chunk: item.task.chunk,
        lens: item.task.lens.id,
        confidence: applied.confidence,
        severity: applied.severity,
        note: applied.note,
      }),
    );
  });

  return { findings: finalizeFindings(raw, config.scan.minConfidence), errors };
}
