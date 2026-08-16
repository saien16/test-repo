/**
 * Anthropic SDK のラッパー。
 *
 * 全ステージ（分析・キルチェーン・レポーター）はこのアダプタ経由でのみ
 * LLMを呼ぶ。ここに以下の横断的関心事を集約している:
 *   - zod スキーマによる構造化出力の強制
 *   - プロンプトキャッシュ（安定した system プロンプトを前方に配置）
 *   - トークン予算の上限
 *   - チャンク単位の結果キャッシュ
 *   - 安全分類器による拒否(refusal)時のフォールバック
 *
 * refusal の扱いが特に重要: 脆弱性スキャナーはまさにサイバーセキュリティ
 * 領域の入力を送るため、Claude Opus 5 の安全分類器が正当な解析を稀に
 * 拒否しうる。拒否は HTTP 200 + stop_reason:'refusal' で返るので、
 * content を読む前に必ず stop_reason を確認する。
 */

import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
// SDK の zodOutputFormat は zod/v4 のスキーマを要求する。
// 各ステージのスキーマも必ず 'zod/v4' から import すること。
import type * as z from 'zod/v4';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { LlmConfig } from '../types/config.js';

export interface TokenUsage {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

export interface LlmCallOptions<T> {
  /** キャッシュされる安定プロンプト。レンズ定義など */
  system: string;
  /** 可変部分。解析対象のコードなど */
  user: string;
  /** 出力を強制する zod スキーマ（必ず 'zod/v4' から作ること） */
  schema: z.ZodType<T>;
  /** ログ・デバッグ用のスキーマ名 */
  schemaName: string;
  /**
   * 結果キャッシュのキー。同一キーなら再呼び出しをスキップする。
   * 通常はファイル内容ハッシュ + レンズID を渡す。
   */
  cacheKey?: string;
  maxTokens?: number;
  /** このコール個別の effort 上書き */
  effort?: LlmConfig['effort'];
}

export type LlmResult<T> =
  | { ok: true; value: T; fromCache: boolean; model: string }
  | { ok: false; reason: 'refusal'; category: string | null }
  | { ok: false; reason: 'budget-exhausted' }
  | { ok: false; reason: 'error'; error: string };

/** トークン予算を超過した際に投げられる */
export class TokenBudgetExhausted extends Error {
  constructor(spent: number, budget: number) {
    super(`トークン予算を超過しました (${spent} / ${budget})`);
    this.name = 'TokenBudgetExhausted';
  }
}

export class LlmClient {
  private readonly client: Anthropic;
  private readonly usage: TokenUsage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  private readonly cacheDir: string;

  constructor(
    private readonly config: LlmConfig,
    cacheDir = '.grimoire/cache',
  ) {
    // APIキーは環境変数 or `ant auth login` プロファイルから解決される。
    // ハードコードしない。
    this.client = new Anthropic({ maxRetries: 3 });
    this.cacheDir = cacheDir;
  }

  getUsage(): TokenUsage {
    return { ...this.usage };
  }

  /** 予算を使い切っているか */
  isBudgetExhausted(): boolean {
    if (this.config.tokenBudget === null) return false;
    return this.usage.output >= this.config.tokenBudget;
  }

  /**
   * 構造化出力でLLMを1回呼ぶ。
   * 失敗は例外ではなく判別可能な結果型で返す（部分的失敗を許容するため）。
   */
  async structured<T>(opts: LlmCallOptions<T>): Promise<LlmResult<T>> {
    if (this.isBudgetExhausted()) {
      return { ok: false, reason: 'budget-exhausted' };
    }

    const cached = await this.readCache<T>(opts);
    if (cached !== null) {
      return { ok: true, value: cached, fromCache: true, model: this.config.model };
    }

    const primary = await this.call(opts, this.config.model);

    // 安全分類器に拒否された場合はフォールバックモデルで再試行する。
    // 脆弱性解析は正当な用途だが、稀に cyber カテゴリで拒否されうる。
    if (!primary.ok && primary.reason === 'refusal' && this.config.fallbackModel) {
      const fallback = await this.call(opts, this.config.fallbackModel);
      if (fallback.ok) await this.writeCache(opts, fallback.value);
      return fallback;
    }

    if (primary.ok) await this.writeCache(opts, primary.value);
    return primary;
  }

  private async call<T>(opts: LlmCallOptions<T>, model: string): Promise<LlmResult<T>> {
    try {
      const response = await this.client.messages.parse({
        model,
        max_tokens: opts.maxTokens ?? this.config.maxTokens,
        // Opus 5 は思考が既定でON。effort が思考の深さとトークン消費を制御する。
        output_config: {
          effort: opts.effort ?? this.config.effort,
          format: zodOutputFormat(opts.schema),
        },
        system: [
          {
            type: 'text',
            text: opts.system,
            // 安定プロンプトをキャッシュ。可変部分は user 側に置く。
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: opts.user }],
      });

      this.recordUsage(response.usage);

      // content を読む前に必ず stop_reason を確認する
      if (response.stop_reason === 'refusal') {
        return {
          ok: false,
          reason: 'refusal',
          category: response.stop_details?.category ?? null,
        };
      }

      if (response.stop_reason === 'max_tokens') {
        return { ok: false, reason: 'error', error: 'max_tokens に達し出力が切り詰められました' };
      }

      const parsed = response.parsed_output;
      if (parsed === null || parsed === undefined) {
        return { ok: false, reason: 'error', error: 'スキーマに適合する出力が得られませんでした' };
      }

      return { ok: true, value: parsed as T, fromCache: false, model };
    } catch (err) {
      if (err instanceof Anthropic.RateLimitError) {
        return { ok: false, reason: 'error', error: `レート制限: ${err.message}` };
      }
      if (err instanceof Anthropic.APIConnectionError) {
        return { ok: false, reason: 'error', error: `接続エラー: ${err.message}` };
      }
      if (err instanceof Anthropic.APIError) {
        return { ok: false, reason: 'error', error: `APIエラー ${err.status}: ${err.message}` };
      }
      return { ok: false, reason: 'error', error: String(err) };
    }
  }

  private recordUsage(usage: Anthropic.Usage | null | undefined): void {
    if (!usage) return;
    this.usage.input += usage.input_tokens ?? 0;
    this.usage.output += usage.output_tokens ?? 0;
    this.usage.cacheRead += usage.cache_read_input_tokens ?? 0;
    this.usage.cacheWrite += usage.cache_creation_input_tokens ?? 0;
  }

  private cachePath(opts: LlmCallOptions<unknown>): string | null {
    if (!this.config.cache || !opts.cacheKey) return null;
    // プロンプト内容も鍵に含める。プロンプトを変えたら古い結果を使わない。
    const digest = createHash('sha256')
      .update(opts.cacheKey)
      .update('\0')
      .update(opts.system)
      .update('\0')
      .update(this.config.model)
      .digest('hex');
    return join(this.cacheDir, `${digest}.json`);
  }

  private async readCache<T>(opts: LlmCallOptions<T>): Promise<T | null> {
    const path = this.cachePath(opts);
    if (!path) return null;
    try {
      const raw = await readFile(path, 'utf8');
      // キャッシュ内容もスキーマ検証する。スキーマ変更後の古い結果を弾くため。
      const result = opts.schema.safeParse(JSON.parse(raw));
      return result.success ? result.data : null;
    } catch {
      return null;
    }
  }

  private async writeCache<T>(opts: LlmCallOptions<T>, value: T): Promise<void> {
    const path = this.cachePath(opts);
    if (!path) return;
    try {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify(value), 'utf8');
    } catch {
      // キャッシュ書き込み失敗はスキャンを止める理由にならない
    }
  }
}
