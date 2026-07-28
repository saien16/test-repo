/**
 * レポート表示用の日本語ラベル表。
 *
 * markdown / html / cli の各フォーマッタは同じ攻撃チェーンを別の形式で描く。
 * ラベル表がフォーマッタごとに複製されていると、片方だけ更新されたときに
 * 「同じ攻撃チェーンなのにレポート形式によって表記が違う」という
 * 読み手からは原因の分からない不整合になる。定義元はこのファイルだけにする。
 *
 * すべて `Record<ユニオン型, string>` として型付けしてある。
 * 元のユニオン（KillChainPhase など）に値が増えた場合、
 * ここを更新し忘れるとコンパイルエラーになる。
 */

import type { DataFlowStep } from '../types/finding.js';
import type { AttackChain, AttackTactic, KillChainPhase } from '../types/killchain.js';
import type { Effort } from './priority.js';

/** キルチェーン段階の日本語表記 */
export const PHASE_JA: Record<KillChainPhase, string> = {
  reconnaissance: '偵察',
  weaponization: '武器化',
  delivery: '配送',
  exploitation: '攻撃実行',
  installation: '居座り',
  'command-and-control': '遠隔操作',
  'actions-on-objectives': '目的の実行',
};

/** ATT&CK戦術の日本語表記 */
export const TACTIC_JA: Record<AttackTactic, string> = {
  'initial-access': '初期侵入',
  execution: '実行',
  persistence: '永続化',
  'privilege-escalation': '権限昇格',
  'defense-evasion': '防御回避',
  'credential-access': '資格情報アクセス',
  discovery: '探索',
  'lateral-movement': '横展開',
  collection: '収集',
  exfiltration: '持ち出し',
  impact: '影響',
};

/** データフロー各ステップの役割の日本語表記 */
export const ROLE_JA: Record<DataFlowStep['role'], string> = {
  source: '汚染源',
  propagation: '伝播',
  sanitizer: '無害化',
  sink: '危険な出力先',
};

/** 攻撃チェーンの成立可能性 */
export const LIKELIHOOD_JA: Record<AttackChain['likelihood'], string> = {
  high: '高',
  medium: '中',
  low: '低',
};

/** 対応工数の見積もり */
export const EFFORT_JA: Record<Effort, string> = {
  low: '小',
  medium: '中',
  high: '大',
};

/**
 * 成立可能性の日本語表記。
 * 型の外の値（LLM由来の想定外文字列）が来た場合は従来どおり「低」に倒す。
 */
export function likelihoodJa(likelihood: AttackChain['likelihood']): string {
  return LIKELIHOOD_JA[likelihood] ?? LIKELIHOOD_JA.low;
}

/**
 * 工数の日本語表記。
 * 型の外の値が来た場合は従来どおり「大」に倒す（過小評価しない側へ倒す）。
 */
export function effortJa(effort: Effort): string {
  return EFFORT_JA[effort] ?? EFFORT_JA.high;
}
