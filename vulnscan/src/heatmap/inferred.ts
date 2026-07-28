/**
 * 想定層 (inferred) の算出。
 *
 * 「そこで何が検出されたか」ではなく「そこで何が起きうるか」を、
 * CWEカタログと構成要素の性質だけから機械的に導く。LLMは使わない
 * （決定的であること・テストできることを優先する）。
 *
 * ■ 式の設計判断
 *
 *   cweWeight = 悪用可能性重み × CIA影響重み × (スタック固有か? 1 : GENERIC_DISCOUNT)
 *   base      = BASE_SCALE × max(cweWeight)                 … 最悪のCWEが下限を決める
 *   diversity = 1 + DIVERSITY_WEIGHT × log2(1 + スタック固有CWE数)  … 面の広さは緩やかに効く
 *   inferred  = clamp(0..100, base × diversity × 露出度 × データ機微度 × 認証)
 *
 * 該当CWE数を「加算」ではなく「倍率」にしているのは、加算にすると
 * ローカル実行で機微データも扱わない構成要素が、
 * 「理屈の上では当てはまるCWEが多い」というだけで下駄を履いてしまうため。
 * 面の広さは、その構成要素の置かれた状況で割り引かれるべきものである。
 * また面の広さに数えるのはスタック固有のCWEだけにする。
 * 言語非依存のCWEは全構成要素に等しく当てはまるので、行間の差を作らない。
 *
 * 露出度・機微度・認証は「同じ弱点でも、そこにあると何が起きるか」を
 * 変える係数なので乗算にする。加算にすると、公開APIでもローカルCLIでも
 * 素点が同じという不合理が起きる。
 *
 * BASE_SCALE を 100 ではなく 60 に抑えているのは、上振れ要因（未認証の公開面など）
 * のための余地を残すため。100 から始めると、悪用可能性 High かつ CIA 全影響の
 * CWE を含むカテゴリ（インジェクション、アクセス制御など）が公開構成要素で
 * 軒並み 100 に張り付き、行列の濃淡が潰れて比較できなくなる。
 *
 * ■ 値と確信度は分けて扱う
 *
 * 減衰係数（confidence.ts）は **値を小さくするのではなく確信度を下げる**。
 * 「露出度が推測でしかないから危険度が下がる」わけではない。
 * 危険度の大きさと、その主張をどれだけ信じてよいかは別の軸である。
 */

import type {
  ArchitectureComponent,
  DataSensitivity,
  Exposure,
} from '../types/architecture.js';
import type { Citation, Claim } from '../types/evidence.js';
import { assumed, inferred } from '../types/evidence.js';
import type { LensId } from '../types/finding.js';
import type { WeaknessCategory } from '../types/heatmap.js';
import type { CweLikelihood, PlatformCwe } from './catalog-adapter.js';
import {
  catalogFactor,
  claimFactor,
  combineFactors,
  type ConfidenceFactor,
  describeFactors,
} from './confidence.js';
import type { ComponentPlatform } from './platform.js';

/** 素点の基準スケール。上振れ要因のための余地(headroom)を残して 100 未満に置く */
export const BASE_SCALE = 60;

/** スタック固有CWE数による増幅の強さ（該当数が倍になるごとにこの割合だけ増える） */
export const DIVERSITY_WEIGHT = 0.05;

/**
 * 言語非依存・技術非依存のCWEに掛ける割引。
 *
 * 「どのスタックにも当てはまる」ということは
 * 「この構成要素で起きうる」という主張の根拠としては弱い、という意味の割引。
 * 0 にして切り捨てないのは、認証不備(CWE-287)のように
 * 言語非依存だが重大な弱点が想定層から丸ごと消えてしまうため。
 */
export const GENERIC_DISCOUNT = 0.6;

/** 悪用可能性の重み */
const LIKELIHOOD_WEIGHT: Record<CweLikelihood, number> = {
  High: 1.0,
  Medium: 0.65,
  Low: 0.35,
  // 判っていないものを High 扱いすると想定層が飽和するため中庸に置く
  Unknown: 0.5,
};

/** CIA影響の数による重み */
const IMPACT_WEIGHT = [0.4, 0.65, 0.85, 1.0];

/** 露出度の重み。攻撃者からの到達しやすさ */
const EXPOSURE_MULTIPLIER: Record<Exposure, number> = {
  'public-internet': 1.0,
  internal: 0.7,
  local: 0.45,
  unknown: 0.6,
};

/** データ機微度の重み。配列のうち最も高いものを採る */
const SENSITIVITY_MULTIPLIER: Record<DataSensitivity, number> = {
  credentials: 1.0,
  financial: 0.95,
  pii: 0.9,
  business: 0.7,
  none: 0.5,
  unknown: 0.65,
};

/** 未認証かつインターネット公開のときの加算（「大幅加算」の実体） */
const UNAUTHENTICATED_PUBLIC_MULTIPLIER = 1.35;
/** 未認証だがインターネット公開ではないときの加算 */
const UNAUTHENTICATED_OTHER_MULTIPLIER = 1.1;

/** 悪用可能性が既知のCWEを主根拠にできたときのカタログ確信度 */
const CATALOG_CONFIDENCE_KNOWN = 0.8;
/** 悪用可能性が Unknown のCWEしか無いときのカタログ確信度 */
const CATALOG_CONFIDENCE_UNKNOWN = 0.55;

const EXPOSURE_LABEL: Record<Exposure, string> = {
  'public-internet': 'インターネット公開',
  internal: '内部ネットワークのみ',
  local: 'ローカルのみ',
  unknown: '露出度不明',
};

const SENSITIVITY_LABEL: Record<DataSensitivity, string> = {
  credentials: '資格情報',
  pii: '個人情報',
  financial: '金融情報',
  business: '業務データ',
  none: '機微データなし',
  unknown: '機微度不明',
};

export interface InferredResult {
  claim: Claim<number>;
  /** 確信度が minInferenceConfidence 未満で除外されたか */
  suppressed: boolean;
  /** 減衰後の確信度 0..1（除外された場合もその値を保持する） */
  confidence: number;
  /** 想定の根拠になったCWE（CWE番号順） */
  matchedCweIds: string[];
  /** うち、技術スタックに明示的に該当したもの */
  specificCweIds: string[];
  /** 素点を決めた主根拠のCWE。該当なしなら null */
  dominantCweId: string | null;
  /**
   * 想定の根拠になったCWEを担当するレンズの集合。
   * 空なら「このカテゴリの弱点を見るレンズがそもそも無い」＝構造的な死角。
   * 死角の原因切り分け（blindspots.ts）が使う。
   */
  lenses: LensId[];
  /** 除外されなかった場合の素の想定リスク（テスト・説明用） */
  rawRisk: number;
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

/** データ機微度配列のうち最も重いものを選ぶ */
function dominantSensitivity(values: readonly DataSensitivity[]): DataSensitivity {
  let best: DataSensitivity = 'unknown';
  let bestWeight = -1;
  for (const value of values) {
    const weight = SENSITIVITY_MULTIPLIER[value] ?? SENSITIVITY_MULTIPLIER.unknown;
    if (weight > bestWeight) {
      bestWeight = weight;
      best = value;
    }
  }
  return best;
}

function ciaCount(cia: { c: boolean; i: boolean; a: boolean }): number {
  return (cia.c ? 1 : 0) + (cia.i ? 1 : 0) + (cia.a ? 1 : 0);
}

/**
 * 1セル分の想定リスクを算出する。
 *
 * @param minInferenceConfidence これ未満の推測はセルに反映しない（値0にする）
 */
export function computeInferred(
  component: ArchitectureComponent,
  category: WeaknessCategory,
  platform: ComponentPlatform,
  /** このカテゴリで、構成要素の技術スタックに該当したCWE（catalog-adapter が引いたもの） */
  candidates: readonly PlatformCwe[],
  minInferenceConfidence: number,
  basisCitations: Citation[] = [],
): InferredResult {
  const matchedCweIds = candidates.map((c) => c.id);
  const specificCweIds = candidates.filter((c) => c.specific).map((c) => c.id);
  const lenses: LensId[] = [];
  for (const candidate of candidates) {
    if (candidate.lens !== null && !lenses.includes(candidate.lens)) lenses.push(candidate.lens);
  }
  lenses.sort();

  if (candidates.length === 0) {
    return {
      claim: assumed(
        0,
        `カテゴリ「${category.name}」に属するCWEのうち、この構成要素の技術スタック` +
          `（${platform.description}）に適合するものが無かったため、想定リスクを0と置いた。` +
          `根拠を持つ推測ではなく既定値であることに注意。`,
      ),
      suppressed: false,
      confidence: 0,
      matchedCweIds: [],
      specificCweIds: [],
      dominantCweId: null,
      lenses: [],
      rawRisk: 0,
    };
  }

  // --- 素点: 最悪のCWEを主、スタック固有CWEの多さを従とする ---
  let dominantCweId = candidates[0]!.id;
  let dominantWeight = -1;
  let dominantLikelihood: CweLikelihood = 'Unknown';
  let dominantSpecific = false;
  for (const candidate of candidates) {
    const likelihoodWeight = LIKELIHOOD_WEIGHT[candidate.likelihood];
    const impactWeight = IMPACT_WEIGHT[ciaCount(candidate.cia)] ?? IMPACT_WEIGHT[0] ?? 0.4;
    // 言語・技術非依存のCWEは「この構成要素で起きうる」根拠としては弱いので割り引く
    const specificity = candidate.specific ? 1 : GENERIC_DISCOUNT;
    const weight = likelihoodWeight * impactWeight * specificity;
    if (weight > dominantWeight) {
      dominantWeight = weight;
      dominantCweId = candidate.id;
      dominantLikelihood = candidate.likelihood;
      dominantSpecific = candidate.specific;
    }
  }
  if (dominantWeight < 0) dominantWeight = 0;

  const base = BASE_SCALE * dominantWeight;
  const diversity = 1 + DIVERSITY_WEIGHT * Math.log2(1 + specificCweIds.length);

  // --- 構成要素の性質による重み付け（各項は Claim なので確信度も取り出す） ---
  const exposure = component.exposure.value;
  const exposureMultiplier = EXPOSURE_MULTIPLIER[exposure] ?? EXPOSURE_MULTIPLIER.unknown;
  const exposureFactor = claimFactor(
    '露出度',
    component.exposure,
    (v) => EXPOSURE_LABEL[v] ?? String(v),
  );

  const sensitivity = dominantSensitivity(component.dataSensitivity.value);
  const sensitivityMultiplier =
    SENSITIVITY_MULTIPLIER[sensitivity] ?? SENSITIVITY_MULTIPLIER.unknown;
  const sensitivityFactor = claimFactor(
    'データ機微度',
    component.dataSensitivity,
    () => SENSITIVITY_LABEL[sensitivity] ?? String(sensitivity),
  );

  const requiresAuth = component.requiresAuthentication.value;
  const authMultiplier = requiresAuth
    ? 1
    : exposure === 'public-internet'
      ? UNAUTHENTICATED_PUBLIC_MULTIPLIER
      : UNAUTHENTICATED_OTHER_MULTIPLIER;
  const authFactor = claimFactor('認証要否', component.requiresAuthentication, (v) =>
    v ? '認証あり' : '認証なし',
  );

  const rawRisk = round1(
    Math.max(
      0,
      Math.min(
        100,
        base * diversity * exposureMultiplier * sensitivityMultiplier * authMultiplier,
      ),
    ),
  );

  // --- 確信度の伝播 ---
  // カタログ知識そのものの確からしさに、推測に基づく入力の確信度を掛け合わせる。
  const catalogBase =
    dominantLikelihood === 'Unknown' ? CATALOG_CONFIDENCE_UNKNOWN : CATALOG_CONFIDENCE_KNOWN;
  const factors: ConfidenceFactor[] = [
    catalogFactor(
      'カタログ',
      catalogBase,
      `${dominantCweId} 悪用可能性 ${dominantLikelihood}`,
    ),
    exposureFactor,
    sensitivityFactor,
    authFactor,
    ...platform.factors,
  ];
  const confidence = combineFactors(factors);

  const cweSummary =
    matchedCweIds.length === 1
      ? dominantCweId
      : `${dominantCweId} ほか計${matchedCweIds.length}件` +
        `（うちスタック固有 ${specificCweIds.length}件）`;

  const commonReasoning =
    `構成要素「${component.name}」の技術スタック（${platform.description}）に該当するCWEは ${cweSummary}。` +
    `最も影響が大きい ${dominantCweId}（悪用可能性 ${dominantLikelihood}` +
    (dominantSpecific
      ? '・スタック固有'
      : `・言語/技術非依存のため素点を ${GENERIC_DISCOUNT} 倍に割引`) +
    `）を主根拠とし、` +
    `露出度 ${exposureFactor.detail}、データ機微度 ${sensitivityFactor.detail}、` +
    `認証 ${authFactor.detail} で重み付けした` +
    (!requiresAuth && exposure === 'public-internet'
      ? '（未認証かつインターネット公開のため大幅加算）'
      : '') +
    `。確信度の内訳: ${describeFactors(factors)} = ${confidence.toFixed(2)}`;

  const alternatives = [
    '該当する実装自体がこの構成要素に無い可能性（カタログは「技術スタック上ありうる」としか言えない）',
    '既に共通ミドルウェアやフレームワーク側で緩和されている可能性',
  ];

  if (confidence < minInferenceConfidence) {
    // 閾値未満の推測はセルに反映しない。値を0にした上で、
    // 「なぜ0なのか」が読み手に判るよう理由は残す（黙って消さない）。
    return {
      claim: inferred(0, {
        confidence,
        inferredBy: 'catalog',
        basis: basisCitations,
        reasoning:
          `確信度 ${confidence.toFixed(2)} が設定値 minInferenceConfidence=` +
          `${minInferenceConfidence} 未満のため、想定リスク ${rawRisk} をセルに反映せず0として扱った。` +
          `（算出過程: ${commonReasoning}）`,
        alternatives,
      }),
      suppressed: true,
      confidence,
      matchedCweIds,
      specificCweIds,
      dominantCweId,
      lenses,
      rawRisk,
    };
  }

  return {
    claim: inferred(rawRisk, {
      confidence,
      inferredBy: 'catalog',
      basis: basisCitations,
      reasoning: `想定リスク ${rawRisk}。${commonReasoning}`,
      alternatives,
    }),
    suppressed: false,
    confidence,
    matchedCweIds,
    specificCweIds,
    dominantCweId,
    lenses,
    rawRisk,
  };
}
