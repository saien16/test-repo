/**
 * 構造化出力のスキーマ定義。
 *
 * SDK の zodOutputFormat は zod/v4 のスキーマを要求するため、
 * 必ず 'zod/v4' から import する（'zod' からだと型が合わない）。
 *
 * 誤検知抑制の要は「根拠を構造として要求する」こと。
 * dataFlow（source→sinkの経路）と reasoning は必須フィールドにしてあり、
 * 根拠を書けない指摘はそもそもスキーマに適合しない。
 * さらに dataFlow が空、sink ステップが無い場合は
 * `filter.ts` の evidencePenalty で confidence を下げる。
 *
 * 注意: 構造化出力は数値の min/max や配列の minItems といった制約を
 * サポートしないため、範囲チェックはスキーマに書かずコード側で正規化する。
 */

import * as z from 'zod/v4';

export const severitySchema = z
  .enum(['critical', 'high', 'medium', 'low', 'info'])
  .describe('影響の大きさ。悪用の容易さではなく、成立した場合の被害で決める');

export const dataFlowStepSchema = z.object({
  file: z.string().describe('このステップが存在するファイルパス'),
  line: z.number().int().describe('このステップの行番号（提示された行番号をそのまま使う）'),
  code: z.string().describe('該当行のコード片'),
  role: z
    .enum(['source', 'propagation', 'sanitizer', 'sink'])
    .describe(
      'source=攻撃者が制御しうる入力の入口 / propagation=値の伝播 / sanitizer=無害化処理 / sink=危険な操作',
    ),
  description: z.string().describe('このステップで値がどう扱われるか'),
});

export const candidateFindingSchema = z.object({
  cwe: z.string().describe("CWE識別子。例: 'CWE-89'"),
  category: z.string().describe("OWASP Top 10 カテゴリ。例: 'A03:2021-Injection'"),
  title: z.string().describe('何がどこで問題なのかを1行で'),
  severity: severitySchema,
  confidence: z
    .number()
    .describe(
      '0.0〜1.0。到達経路とサニタイズ不在をコード上で確認できた度合い。推測が混じるほど低くする',
    ),
  location: z
    .object({
      file: z.string(),
      startLine: z.number().int(),
      endLine: z.number().int(),
    })
    .describe('脆弱性の中心（通常は sink）の位置'),
  evidence: z.string().describe('判断の根拠となった実際のコード抜粋'),
  dataFlow: z
    .array(dataFlowStepSchema)
    .describe(
      'source から sink までの経路。中間にサニタイズがあればそれも sanitizer として書く。' +
        '経路をコード上で辿れない場合は空配列にし、confidence も下げる',
    ),
  reasoning: z
    .string()
    .describe('なぜ悪用可能と判断したか。前提条件や不明点があればそれも書く'),
  remediation: z.string().describe('このコードに対する具体的な修正方針'),
});

export const analysisResultSchema = z.object({
  findings: z
    .array(candidateFindingSchema)
    .describe('見つかった脆弱性。該当が無ければ空配列'),
});

export type CandidateFinding = z.infer<typeof candidateFindingSchema>;

/** 自己検証（反証）パスの出力 */
export const verdictSchema = z.object({
  verdict: z
    .enum(['confirmed', 'uncertain', 'refuted'])
    .describe(
      'confirmed=提示コードの範囲で悪用可能と確認できた / uncertain=判断材料が足りない / refuted=悪用できない根拠がある',
    ),
  confidence: z.number().describe('0.0〜1.0。この判定自体の確からしさ'),
  exploitPath: z
    .string()
    .describe('悪用が成立する場合の具体的な経路。成立しないと判断したなら空文字'),
  rebuttal: z
    .string()
    .describe(
      '成立しない・疑わしいと考える理由（サニタイズ済み、到達不能、テストコード、意図的な設計など）。無ければ空文字',
    ),
  missingEvidence: z
    .array(z.string())
    .describe('判断に必要だが提示されていない情報。無ければ空配列'),
  correctedSeverity: severitySchema.describe(
    '再評価した深刻度。変更が無ければ元と同じ値を入れる',
  ),
});

export type Verdict = z.infer<typeof verdictSchema>;
