/**
 * CWEカタログ (`src/vuln/catalog.ts`) への唯一の接続点。
 *
 * ヒートマップ本体（observed.ts / inferred.ts / blindspots.ts / index.ts）は
 * カタログを直接 import してはならない。必ずこのアダプタ経由で参照する。
 * カタログ側の関数シグネチャが変わっても、直す場所をこのファイル1つに閉じるため。
 *
 * カタログから借りるもの:
 *   - `cweCategory()`      … CWEを人が扱える粒度のカテゴリへ畳む（＝ヒートマップの列）
 *   - `cwesForPlatform()`  … 言語・技術スタックから、そこで起こりうるCWEを逆引きする
 *   - `lensForCwe()`       … そのCWEを担当する分析レンズ（死角の原因切り分けに使う）
 *   - `likelihoodOf()` / `lookupCwe().cia` … 想定リスクの素点の材料
 *
 * これらはいずれも「事実（MITRE由来）」と「本ツールの解釈（カテゴリ定義・
 * レンズ振り分け）」が混ざっている。どちらであるかはカタログ側の
 * コメントに明記されているので、想定層の reasoning でもその区別を保つ。
 */

import type { LensId } from '../types/finding.js';
import type { WeaknessCategory } from '../types/heatmap.js';
import {
  allCweCategories,
  allCwes,
  cweCategory,
  cwesForPlatform,
  lensForCwe,
  likelihoodOf,
  lookupCwe,
  type CweLikelihood,
} from '../vuln/catalog.js';

export type { CweLikelihood } from '../vuln/catalog.js';
export { lensForCwe } from '../vuln/catalog.js';

/** CIA（機密性・完全性・可用性）への影響有無 */
export interface CweCia {
  c: boolean;
  i: boolean;
  a: boolean;
}

/** 想定層の算出に必要な、CWE1件分の情報 */
export interface PlatformCwe {
  /** 'CWE-89' 形式 */
  id: string;
  likelihood: CweLikelihood;
  cia: CweCia;
  /** 担当レンズ。null なら「このスキャナはこのCWEを見ていない」 */
  lens: LensId | null;
  /**
   * 構成要素の言語・技術に**明示的に**該当するか。
   *
   * false は「言語非依存・技術非依存のCWE」を意味する。
   * どのスタックにも当てはまるということは、
   * 「この構成要素で起きうる」という主張の根拠としては弱い。
   * inferred.ts はこの区別を使って素点を割り引く。
   */
  specific: boolean;
}

/** 構成要素の技術スタック */
export interface PlatformQuery {
  languages: string[];
  technologies: string[];
}

/** どのカテゴリにも畳めなかったCWEの受け皿（カタログ側の既定カテゴリ） */
export const OTHER_CATEGORY_ID = 'other';

/** CWE ID 表記を 'CWE-89' 形式へ正規化する。'89' や 'cwe_89' も受け付ける */
export function normalizeCweId(raw: string): string | null {
  const m = /^(?:cwe[-_\s]?)?(\d+)$/i.exec(raw.trim());
  return m ? `CWE-${m[1]}` : null;
}

/** 悪用可能性の並び順（代表CWEを選ぶときに使う） */
const LIKELIHOOD_RANK: Record<CweLikelihood, number> = {
  High: 0,
  Medium: 1,
  Low: 2,
  Unknown: 3,
};

function numericId(cweId: string): number {
  const m = /(\d+)/.exec(cweId);
  return m ? Number(m[1]) : Number.MAX_SAFE_INTEGER;
}

/** カテゴリID → 所属CWE（カタログ全件を畳んだ結果）。1回だけ計算して使い回す */
let membershipCache: Map<string, string[]> | null = null;

function categoryMembership(): Map<string, string[]> {
  if (membershipCache) return membershipCache;
  const membership = new Map<string, string[]>();
  for (const entry of allCwes()) {
    const categoryId = cweCategory(entry.id).id;
    const list = membership.get(categoryId);
    if (list) list.push(entry.id);
    else membership.set(categoryId, [entry.id]);
  }
  for (const list of membership.values()) {
    // 悪用可能性が高いもの→ID順。代表CWEの選択を決定的にする
    list.sort(
      (a, b) =>
        LIKELIHOOD_RANK[likelihoodOf(a)] - LIKELIHOOD_RANK[likelihoodOf(b)] ||
        numericId(a) - numericId(b),
    );
  }
  membershipCache = membership;
  return membership;
}

/** 列に載せる「代表的なCWE ID」の上限。全件載せると読めないため */
const MAX_REPRESENTATIVE_CWES = 12;

/**
 * ヒートマップの列（弱点カテゴリ）。
 *
 * カタログ側のカテゴリ定義をそのまま使う。列を独自に定義し直すと、
 * Finding の分類（`cweCategoryId()`）と想定層の分類がずれるため。
 * 呼び出し側が書き換えても内部状態が壊れないよう、毎回複製して返す。
 */
export function weaknessCategories(): WeaknessCategory[] {
  const membership = categoryMembership();
  return allCweCategories().map((category) => {
    const members = membership.get(category.id) ?? [];
    const weakness: WeaknessCategory = {
      id: category.id,
      name: category.name,
      cweIds: members.slice(0, MAX_REPRESENTATIVE_CWES),
    };
    if (category.owasp !== undefined) weakness.owasp = category.owasp;
    return weakness;
  });
}

/** CWE が属するカテゴリのID。未知のCWEは 'other' に落ちる（捨てない） */
export function cweCategoryId(cweId: string): string {
  const normalized = normalizeCweId(cweId);
  if (normalized === null) return OTHER_CATEGORY_ID;
  return cweCategory(normalized).id;
}

function toPlatformCwe(id: string, specific: boolean): PlatformCwe {
  const entry = lookupCwe(id);
  return {
    id,
    likelihood: likelihoodOf(id),
    cia: entry ? { ...entry.cia } : { c: false, i: false, a: false },
    lens: lensForCwe(id),
    specific,
  };
}

/**
 * 構成要素の技術スタックで起こりうるCWEを、カテゴリごとに引く。
 *
 * カタログの `cwesForPlatform()` を2回呼び、
 *   - `includeGeneric: false` … 言語・技術に明示的に該当するCWE（強い根拠）
 *   - `includeGeneric: true`  … 上記に加えて言語非依存・技術非依存のCWE（弱い根拠）
 * の差分を取って `specific` フラグを立てている。
 *
 * 「どのスタックにも当てはまるCWE」を同じ重みで数えると、
 * ヒートマップの全セルが同じ濃さになり、構成要素ごとの差が消えてしまう。
 * かといって捨てると、認証不備のように言語非依存だが重大な弱点が
 * 想定層から丸ごと抜け落ちる。そこで両方採った上で重みを変える。
 */
export function cwesForComponent(platform: PlatformQuery): Map<string, PlatformCwe[]> {
  const specificIds = new Set(
    cwesForPlatform({
      languages: platform.languages,
      technologies: platform.technologies,
      includeGeneric: false,
    }).map((e) => e.id),
  );
  const allIds = cwesForPlatform({
    languages: platform.languages,
    technologies: platform.technologies,
    includeGeneric: true,
  }).map((e) => e.id);

  const byCategory = new Map<string, PlatformCwe[]>();
  for (const id of allIds) {
    const categoryId = cweCategory(id).id;
    const list = byCategory.get(categoryId);
    const value = toPlatformCwe(id, specificIds.has(id));
    if (list) list.push(value);
    else byCategory.set(categoryId, [value]);
  }
  // 出力順を決定的にする（カタログの走査順に依存させない）
  for (const list of byCategory.values()) list.sort((a, b) => numericId(a.id) - numericId(b.id));
  return byCategory;
}
