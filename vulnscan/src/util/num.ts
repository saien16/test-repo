/**
 * 数値まわりの共有ユーティリティ。
 *
 * 以前は `clamp01` / `round1` が各機能（heatmap / killchain / vuln）に
 * 分散していた。特に `clamp01` は非有限値のフォールバックが実装ごとに
 * 食い違っており（0 と 0.5）、同名の関数が別の挙動をするという危険な状態
 * だったため、ここへ一元化する。
 *
 * 「非有限値を 0.5（＝どちらとも言えない）に倒す」意図がある箇所は
 * {@link clampConfidence} という別名で明示する。名前で挙動の違いが判るようにし、
 * うっかり取り違えないようにするため。
 */

/** 0..1 に丸める。非有限値は 0 とみなす（＝根拠が無いなら最低値） */
export function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/**
 * 確信度を 0..1 に丸める。
 * 非有限値は `fallback`（既定 0.5＝「判断材料が無い」）に倒す。
 * 確信度は「低いほど安全」ではなく「低いほど当てにならない」という別の軸なので、
 * 0 に落とすと Finding が不当に切り捨てられる。そのため {@link clamp01} と分けている。
 */
export function clampConfidence(value: number, fallback = 0.5): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(1, Math.max(0, value));
}

/** 小数第1位へ四捨五入する */
export function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

/** 小数第2位へ四捨五入する */
export function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
