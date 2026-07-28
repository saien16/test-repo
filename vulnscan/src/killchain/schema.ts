/**
 * LLM の構造化出力スキーマ。
 *
 * 注意: SDK の `zodOutputFormat` は zod/v4 のスキーマを要求するため、
 * ここでは必ず 'zod/v4' から import する（'zod' からだと型エラーになる）。
 */

import * as z from 'zod/v4';
import { ATTACK_TACTICS, KILL_CHAIN_PHASES } from './attack-mapping.js';

const PHASE_VALUES = KILL_CHAIN_PHASES as readonly [string, ...string[]];
const TACTIC_VALUES = ATTACK_TACTICS as readonly [string, ...string[]];

export const ChainStepSchema = z.object({
  findingId: z
    .string()
    .nullable()
    .describe('このステップの根拠となる Finding の id。提示された id 以外は使わない。推論だけのステップなら null'),
  killChainPhase: z.enum(PHASE_VALUES).describe('サイバーキルチェーン段階'),
  attackTactic: z.enum(TACTIC_VALUES).describe('MITRE ATT&CK 戦術'),
  attackTechnique: z
    .string()
    .nullable()
    .describe("MITRE ATT&CK テクニックID。'T1190' や 'T1552.005' の形式。判らなければ null"),
  description: z.string().describe('このステップで攻撃者が何を達成するか（日本語・1〜2文）'),
  preconditions: z.array(z.string()).describe('このステップが成立する前提条件（日本語）'),
});

export const AttackChainSchema = z.object({
  title: z.string().describe('攻撃シナリオの見出し（日本語・40字以内）'),
  chainViable: z
    .boolean()
    .describe('提示された Finding が実際に連鎖しうるか。無理筋なら false にする'),
  entryPoint: z.string().describe('攻撃の起点となるエントリポイント識別子'),
  steps: z.array(ChainStepSchema).describe('source → 中間ステップ → sink の順に並べる'),
  impact: z.string().describe('最終的なビジネス影響（日本語）'),
  likelihood: z.enum(['high', 'medium', 'low']).describe('連鎖が成立する可能性'),
  chokePointFindingId: z
    .string()
    .nullable()
    .describe('連鎖を断つのに最も効果的な Finding の id。無ければ null'),
  chokePointRationale: z.string().describe('その Finding を選んだ理由（日本語）'),
  reasoning: z.string().describe('連鎖が成立すると判断した根拠（日本語）'),
});

export const KillChainResponseSchema = z.object({
  chains: z
    .array(AttackChainSchema)
    .describe('成立しうる攻撃シナリオ。無理筋なら空配列を返す（最大3件）'),
});

export type KillChainResponse = z.infer<typeof KillChainResponseSchema>;
export type LlmAttackChain = z.infer<typeof AttackChainSchema>;
