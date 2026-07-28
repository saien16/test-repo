/**
 * LLM 推測の構造化出力スキーマ。
 *
 * 注意: SDK の `zodOutputFormat` は zod/v4 のスキーマを要求するため、
 * ここでは必ず 'zod/v4' から import する（'zod' からだと型エラーになる）。
 *
 * すべての判断に confidence / reasoning / alternatives / basis を必須で付けさせる。
 * 「根拠なしの断定」を構造的に作れないようにするのが狙い。
 */

import * as z from 'zod/v4';

export const ARCHITECTURE_STYLES = [
  'monolith',
  'microservices',
  'serverless',
  'spa-with-api',
  'static-site',
  'cli-tool',
  'library',
  'batch-job',
  'unknown',
] as const;

export const EXPOSURES = ['public-internet', 'internal', 'local', 'unknown'] as const;

export const DATA_SENSITIVITIES = [
  'pii',
  'credentials',
  'financial',
  'business',
  'none',
  'unknown',
] as const;

export const LlmCitationSchema = z.object({
  file: z
    .string()
    .describe('根拠となるファイルの相対パス。提示された「事実」に出てきたパスのみを使うこと'),
  line: z.number().int().nullable().describe('1始まりの行番号。判らなければ null'),
  excerpt: z.string().nullable().describe('該当箇所の短い抜粋。無ければ null'),
});

/** 判断 1 件。値そのものと、その値をどれだけ信じてよいかをセットで返させる */
function judgement<T extends z.ZodType>(value: T) {
  return z.object({
    value,
    confidence: z
      .number()
      .describe('0..1。この判断が正しい確率の見積もり。根拠が薄いときは低くすること'),
    reasoning: z.string().describe('そう判断した理由（日本語）。読み手が反証できる粒度で書く'),
    alternatives: z
      .array(z.string())
      .describe('検討したが採らなかった対立仮説（日本語）。1つ以上書くこと'),
    basis: z
      .array(LlmCitationSchema)
      .describe('土台にした観測事実の引用。提示されていないファイルを書かないこと'),
  });
}

export const ComponentJudgementSchema = z.object({
  componentId: z.string().describe('提示された構成要素の id。存在しない id を作らないこと'),
  exposure: judgement(z.enum(EXPOSURES)).describe('ネットワーク露出度。判断できなければ unknown'),
  dataSensitivity: judgement(z.array(z.enum(DATA_SENSITIVITIES))).describe(
    '扱うデータの機微度。判断できなければ ["unknown"]',
  ),
  requiresAuthentication: judgement(z.boolean()).describe('この構成要素が認証を要求するか'),
});

export const DataFlowJudgementSchema = z.object({
  fromId: z.string().describe('提示された構成要素の id'),
  toId: z.string().describe('提示された構成要素の id'),
  protocol: judgement(z.string()).describe("プロトコル。例: 'HTTP', 'SQL', 'AMQP'"),
  crossesTrustBoundary: judgement(z.boolean()).describe('この通信が信頼境界をまたぐか'),
});

export const ArchitectureResponseSchema = z.object({
  style: judgement(z.enum(ARCHITECTURE_STYLES)).describe('アーキテクチャ様式'),
  components: z
    .array(ComponentJudgementSchema)
    .describe('提示された構成要素それぞれについての判断。判断できないものは省いてよい'),
  dataFlows: z
    .array(DataFlowJudgementSchema)
    .describe('構成要素間のデータフロー。根拠のないフローを作らないこと'),
  unknowns: z
    .array(z.string())
    .describe('提示された事実からは判断できなかった事項とその理由（日本語）'),
});

export type ArchitectureResponse = z.infer<typeof ArchitectureResponseSchema>;
export type LlmComponentJudgement = z.infer<typeof ComponentJudgementSchema>;
export type LlmDataFlowJudgement = z.infer<typeof DataFlowJudgementSchema>;
export type LlmCitation = z.infer<typeof LlmCitationSchema>;
