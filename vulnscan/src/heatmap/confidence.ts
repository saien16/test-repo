/**
 * 推測の確信度の伝播ルール。
 *
 * 想定層(inferred)は「推測に基づく推測」になりがちである。
 * 例: 「この構成要素はインターネット公開されている（推測・確信度0.7）」を
 * 根拠に「ここは SSRF のリスクが高い（推測）」と言うとき、
 * 後者の確信度は前者を超えてはならない。
 *
 * そこで、想定リスクを組み立てる際に使った各 Claim から「減衰係数」を取り、
 * それらを掛け合わせてセルの確信度とする。
 */

import type { Claim } from '../types/evidence.js';

/**
 * `assumed` に対する一律の減衰係数。
 *
 * evidence.ts の約束どおり `assumed` は確信度を持たない。よってこれは
 * 「確信度の集計値」ではなく、根拠のない仮定を土台にしたことへの
 * 固定ペナルティである（集計には加えず、常にこの定数を掛けるだけ）。
 */
export const ASSUMED_FACTOR = 0.5;

/** 根拠1件分の減衰係数と、その説明ラベル */
export interface ConfidenceFactor {
  /** 何についての根拠か。例: '露出度' */
  label: string;
  /** 0..1 */
  factor: number;
  /** reasoning に埋め込むための、出所の種類を表す短い語 */
  kind: 'observed' | 'inferred' | 'assumed' | 'catalog';
  /** reasoning 用の説明。例: 'public-internet(推測 確信度70%)' */
  detail: string;
}

function clamp01(x: number): number {
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
}

/**
 * Claim から減衰係数を取り出す。
 *   observed → 1.0（事実なので減衰しない）
 *   inferred → provenance.confidence
 *   assumed  → ASSUMED_FACTOR
 */
export function claimFactor<T>(
  label: string,
  claim: Claim<T>,
  render: (value: T) => string = (v) => String(v),
): ConfidenceFactor {
  const shown = render(claim.value);
  switch (claim.provenance.kind) {
    case 'observed':
      return { label, factor: 1, kind: 'observed', detail: `${shown}(事実)` };
    case 'inferred': {
      const confidence = clamp01(claim.provenance.confidence);
      return {
        label,
        factor: confidence,
        kind: 'inferred',
        detail: `${shown}(推測 確信度${Math.round(confidence * 100)}%)`,
      };
    }
    case 'assumed':
      return {
        label,
        factor: ASSUMED_FACTOR,
        kind: 'assumed',
        detail: `${shown}(仮定・根拠なし)`,
      };
  }
}

/** カタログ知識そのものの確信度（悪用可能性が既知かどうかで変える） */
export function catalogFactor(label: string, factor: number, detail: string): ConfidenceFactor {
  return { label, factor: clamp01(factor), kind: 'catalog', detail };
}

/**
 * 減衰係数を掛け合わせる。
 *
 * 積を採るのは「どれか1つでも怪しければ全体が怪しい」を表すため。
 * ただし同種の根拠が複数ある場合（例: 複数のデータフロー）に積を採ると
 * 根拠が増えるほど確信度が下がるという不合理が起きるため、
 * その場合は呼び出し側で `weakestOf()` により1件へ畳んでから渡すこと。
 */
export function combineFactors(factors: readonly ConfidenceFactor[]): number {
  let product = 1;
  for (const f of factors) product *= clamp01(f.factor);
  return clamp01(product);
}

/** 同種の根拠を1件へ畳む（最も弱いものを代表とする） */
export function weakestOf(factors: readonly ConfidenceFactor[]): ConfidenceFactor | null {
  let weakest: ConfidenceFactor | null = null;
  for (const f of factors) {
    if (weakest === null || f.factor < weakest.factor) weakest = f;
  }
  return weakest;
}

/** reasoning 末尾に付ける「確信度の内訳」文字列を作る */
export function describeFactors(factors: readonly ConfidenceFactor[]): string {
  if (factors.length === 0) return '（確信度の根拠なし）';
  return factors.map((f) => `${f.label} ${f.factor.toFixed(2)}`).join(' × ');
}
