/**
 * 実測層 (observed) の算出。
 *
 * 入力は実際に検出された Finding とその CVSS。事実なので Claim では包まない
 * （引用の役割は findingIds が兼ねる、と heatmap.ts の型コメントにある）。
 *
 * ■ 式の設計判断
 *
 * 単純合計は使わない。合計だと「CVSS 3.1 の軽微な指摘が20件あるセル」が
 * 「CVSS 9.8 が1件のセル」を上回ってしまい、色の濃さが危険度ではなく
 * 「そのファイルがどれだけ丁寧に見られたか」を表すようになる。
 *
 * そこで「最大値を主、件数を従」とする:
 *
 *   observed = min(100, max(CVSS)*10
 *                       + COUNT_WEIGHT * log2(件数)
 *                       + CHAIN_WEIGHT * log2(1 + チェーン登場Finding数))
 *
 *   - max(CVSS)*10 … 0..100 への正規化。最悪の1件がそのセルの下限を決める
 *   - log2(件数)   … 件数は緩やかにしか効かない（1件:+0, 2件:+8, 8件:+24）
 *   - チェーン項   … 攻撃チェーンに現れる Finding は単独より危険なので加算する
 */

import type { AttackChain } from '../types/killchain.js';
import type { Finding } from '../types/finding.js';

/** 件数による加点の強さ */
export const COUNT_WEIGHT = 8;
/** 攻撃チェーン登場による加点の強さ */
export const CHAIN_WEIGHT = 6;

export interface ObservedResult {
  risk: number;
  findingIds: string[];
  chainIds: string[];
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

/** Finding ID → その Finding が登場する攻撃チェーンID一覧 */
export function chainIndexByFinding(chains: readonly AttackChain[]): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const chain of chains) {
    for (const step of chain.steps) {
      if (step.findingId === null) continue;
      const list = index.get(step.findingId) ?? [];
      if (!list.includes(chain.id)) list.push(chain.id);
      index.set(step.findingId, list);
    }
    // chokePoint だけが Finding を指しているチェーンも拾う
    const choke = chain.chokePoint?.findingId;
    if (choke) {
      const list = index.get(choke) ?? [];
      if (!list.includes(chain.id)) list.push(chain.id);
      index.set(choke, list);
    }
  }
  return index;
}

/**
 * 1セル分の実測リスクを算出する。
 * `findings` は既にそのセルへ割り当て済みのもの。
 */
export function computeObserved(
  findings: readonly Finding[],
  chainsByFinding: ReadonlyMap<string, string[]>,
): ObservedResult {
  if (findings.length === 0) {
    return { risk: 0, findingIds: [], chainIds: [] };
  }

  let maxScore = 0;
  const findingIds: string[] = [];
  const chainIds: string[] = [];
  let chainedFindings = 0;

  for (const finding of findings) {
    findingIds.push(finding.id);
    const score = Number.isFinite(finding.cvss.baseScore) ? finding.cvss.baseScore : 0;
    if (score > maxScore) maxScore = Math.min(10, Math.max(0, score));
    const related = chainsByFinding.get(finding.id);
    if (related && related.length > 0) {
      chainedFindings++;
      for (const chainId of related) {
        if (!chainIds.includes(chainId)) chainIds.push(chainId);
      }
    }
  }

  const base = maxScore * 10;
  const countBonus = COUNT_WEIGHT * Math.log2(findings.length);
  const chainBonus = chainedFindings > 0 ? CHAIN_WEIGHT * Math.log2(1 + chainedFindings) : 0;
  const risk = Math.min(100, base + countBonus + chainBonus);

  // ID は決定性のためソートしておく（Finding の配列順に依存させない）
  findingIds.sort();
  chainIds.sort();

  return { risk: round1(risk), findingIds, chainIds };
}
