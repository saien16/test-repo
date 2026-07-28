/**
 * 連鎖を考慮した再優先度付け（純粋関数）。
 *
 * 設計意図:
 *   個別 CVSS の単純合計・最大値では「単独では medium が2つでも、
 *   連鎖すると RCE に至る」ケースを拾えない。そこで
 *     priorityScore = f(最終影響, 成立可能性) + 連鎖シナジー
 *   という形にし、
 *     - 最終影響 は「連鎖の到達点で得られる戦術」を主、個別 CVSS を従とする
 *     - 成立可能性 は 到達性・確信度・露出度・LLM 判断 の加重和に鎖長減衰を掛ける
 *     - シナジー は 「最終影響 − 単体で出せる最大影響」× 鎖の長さ で加点する
 *   としている。孤立した high（単体で終わる）はシナジーが 0 になるため、
 *   RCE に至る medium 連鎖に追い越される。
 */

import type { AttackTactic } from '../types/killchain.js';

/** 戦術ごとの「攻撃者にとっての到達価値」= 影響係数 0..1 */
export const TACTIC_IMPACT: Record<AttackTactic, number> = {
  execution: 1.0,
  impact: 0.95,
  exfiltration: 0.9,
  'privilege-escalation': 0.88,
  'lateral-movement': 0.82,
  persistence: 0.8,
  'credential-access': 0.8,
  collection: 0.7,
  'defense-evasion': 0.55,
  'initial-access': 0.5,
  discovery: 0.35,
};

export const LIKELIHOOD_HINT: Record<'high' | 'medium' | 'low', number> = {
  high: 1.0,
  medium: 0.65,
  low: 0.35,
};

/** スコアリングの重み。テストから参照できるよう公開する。 */
export const SCORING_WEIGHTS = {
  /** 影響 = CVSS 寄与 + 到達戦術寄与 */
  impactFromCvss: 0.35,
  impactFromTactic: 0.65,
  /** 成立可能性の加重和 */
  likelihoodReachability: 0.4,
  likelihoodConfidence: 0.25,
  likelihoodExposure: 0.2,
  likelihoodLlmHint: 0.15,
  /** ステップが増えるごとに掛かる減衰（前提条件が積み重なるため） */
  lengthDecay: 0.95,
  /** 影響と成立可能性の合成（影響重視の幾何平均） */
  impactExponent: 0.7,
  likelihoodExponent: 0.3,
  /** 連鎖シナジーの最大加点係数 */
  synergyCoefficient: 25,
} as const;

export interface ScoringInput {
  /** 連鎖に含まれる Finding の CVSS 基本値（0..10） */
  cvssScores: readonly number[];
  /** 連鎖に含まれる Finding の確信度（0..1） */
  confidences: readonly number[];
  /** 到達性を証明できた Finding の割合（0..1） */
  reachabilityRatio: number;
  /** エントリポイント露出度（0..1） */
  exposure: number;
  /** LLM が申告した成立可能性 */
  llmLikelihood: 'high' | 'medium' | 'low';
  /** 連鎖のステップ数 */
  stepCount: number;
  /** 連鎖の中で達成される戦術（最も価値の高いものが最終影響になる） */
  tactics: readonly AttackTactic[];
}

export interface ScoringResult {
  /** 0..100 */
  priorityScore: number;
  /** 再計算後の成立可能性ラベル */
  likelihood: 'high' | 'medium' | 'low';
  /** 内訳（レポート・デバッグ用） */
  breakdown: {
    impactScore: number;
    likelihoodScore: number;
    baseScore: number;
    synergyBonus: number;
    /** 単体で出せる最大影響（CVSS 由来）。シナジー算出の基準 */
    standaloneImpact: number;
    terminalImpact: number;
  };
}

function clamp01(x: number): number {
  if (!Number.isFinite(x)) return 0;
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

function mean(values: readonly number[], fallback: number): number {
  const nums = values.filter((v) => Number.isFinite(v));
  if (nums.length === 0) return fallback;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

/** 連鎖の中で最も価値の高い戦術の影響係数 */
export function terminalImpactOf(tactics: readonly AttackTactic[]): number {
  let max = 0;
  for (const t of tactics) max = Math.max(max, TACTIC_IMPACT[t] ?? 0);
  return max === 0 ? TACTIC_IMPACT['initial-access'] : max;
}

/** 成立可能性スコア（0..1）。鎖が長いほど前提が増えるので減衰させる。 */
export function computeLikelihoodScore(input: ScoringInput): number {
  const w = SCORING_WEIGHTS;
  const avgConfidence = clamp01(mean(input.confidences, 0.5));
  const raw =
    w.likelihoodReachability * clamp01(input.reachabilityRatio) +
    w.likelihoodConfidence * avgConfidence +
    w.likelihoodExposure * clamp01(input.exposure) +
    w.likelihoodLlmHint * (LIKELIHOOD_HINT[input.llmLikelihood] ?? 0.5);
  const steps = Math.max(1, Math.floor(input.stepCount));
  return clamp01(raw * Math.pow(w.lengthDecay, steps - 1));
}

/** 最終影響スコア（0..1） */
export function computeImpactScore(input: ScoringInput): number {
  const w = SCORING_WEIGHTS;
  const maxCvss = input.cvssScores.reduce((a, b) => Math.max(a, Number.isFinite(b) ? b : 0), 0);
  const standalone = clamp01(maxCvss / 10);
  const terminal = terminalImpactOf(input.tactics);
  return clamp01(w.impactFromCvss * standalone + w.impactFromTactic * terminal);
}

export function likelihoodLabel(score: number): 'high' | 'medium' | 'low' {
  if (score >= 0.7) return 'high';
  if (score >= 0.45) return 'medium';
  return 'low';
}

/**
 * 連鎖の優先度スコアを算出する。
 *
 * シナジー加点が本機能の核心:
 *   escalation = 最終影響 − 単体 CVSS で説明できる影響
 *   bonus      = escalation × (1 − 1/ステップ数) × 係数
 * 1 ステップ（＝孤立した Finding）では (1 − 1/1) = 0 となり加点されない。
 */
export function scoreChain(input: ScoringInput): ScoringResult {
  const w = SCORING_WEIGHTS;
  const impactScore = computeImpactScore(input);
  const likelihoodScore = computeLikelihoodScore(input);

  const base =
    Math.pow(Math.max(impactScore, 1e-6), w.impactExponent) *
    Math.pow(Math.max(likelihoodScore, 1e-6), w.likelihoodExponent);

  const maxCvss = input.cvssScores.reduce((a, b) => Math.max(a, Number.isFinite(b) ? b : 0), 0);
  const standaloneImpact = clamp01(maxCvss / 10);
  const terminalImpact = terminalImpactOf(input.tactics);
  const steps = Math.max(1, Math.floor(input.stepCount));
  const escalation = clamp01(terminalImpact - standaloneImpact);
  const synergyBonus = escalation * (1 - 1 / steps) * w.synergyCoefficient;

  const raw = base * 100 + synergyBonus;
  const priorityScore = Math.round(Math.max(0, Math.min(100, raw)) * 10) / 10;

  return {
    priorityScore,
    likelihood: likelihoodLabel(likelihoodScore),
    breakdown: {
      impactScore: Math.round(impactScore * 1000) / 1000,
      likelihoodScore: Math.round(likelihoodScore * 1000) / 1000,
      baseScore: Math.round(base * 1000) / 1000,
      synergyBonus: Math.round(synergyBonus * 100) / 100,
      standaloneImpact,
      terminalImpact,
    },
  };
}

// --- チョークポイント選定 -------------------------------------------------

/**
 * CWE ごとの修正容易さ 0..1（1 が最も容易）。
 * 入力検証・エスケープ・設定変更で閉じるものは高く、
 * 設計変更や認可モデルの作り直しが要るものは低い。
 */
export const REMEDIATION_EASE: Record<string, number> = {
  'CWE-798': 0.9, // ハードコード資格情報 → 環境変数へ退避
  'CWE-259': 0.9,
  'CWE-321': 0.85,
  'CWE-312': 0.8,
  'CWE-532': 0.9, // ログ出力の抑制
  'CWE-327': 0.8, // アルゴリズム差し替え
  'CWE-328': 0.8,
  'CWE-330': 0.8,
  'CWE-338': 0.8,
  'CWE-89': 0.85, // プレースホルダ化
  'CWE-79': 0.8, // 出力エスケープ
  'CWE-78': 0.75, // shell を介さない API へ
  'CWE-77': 0.75,
  'CWE-94': 0.6,
  'CWE-22': 0.75, // パス正規化 + allowlist
  'CWE-918': 0.7, // 宛先 allowlist
  'CWE-611': 0.85, // 外部実体の無効化
  'CWE-502': 0.55, // シリアライズ方式の見直し
  'CWE-434': 0.6,
  'CWE-352': 0.7, // トークン導入
  'CWE-601': 0.8,
  'CWE-306': 0.6, // 認証の追加
  'CWE-287': 0.45,
  'CWE-862': 0.45, // 認可設計
  'CWE-863': 0.4,
  'CWE-639': 0.45,
  'CWE-269': 0.35,
  'CWE-284': 0.45,
  'CWE-1321': 0.6,
  'CWE-400': 0.5,
  'CWE-770': 0.55,
  'CWE-200': 0.65,
  'CWE-209': 0.85,
};

export const DEFAULT_REMEDIATION_EASE = 0.5;
/** 依存の更新だけで閉じる Finding は最も容易 */
export const DEPENDENCY_BUMP_EASE = 0.95;

export interface ChokePointCandidate {
  findingId: string;
  /** 連鎖内での位置（1 始まり） */
  order: number;
  /** 正規化済み CWE 'CWE-89' */
  cwe: string | null;
  /** 依存のバージョン更新だけで解消できるか */
  hasFixedVersion: boolean;
}

export interface ChokePointScore {
  findingId: string;
  score: number;
  upstreamness: number;
  ease: number;
}

/** 個々の候補のチョークポイント適性を採点する（純粋関数） */
export function scoreChokePoints(
  candidates: readonly ChokePointCandidate[],
  totalSteps: number,
): ChokePointScore[] {
  const n = Math.max(1, totalSteps);
  return candidates.map((c) => {
    // 最も上流を 1、最下流を 0 とする
    const upstreamness = n <= 1 ? 1 : 1 - (Math.max(1, c.order) - 1) / (n - 1);
    const ease = c.hasFixedVersion
      ? DEPENDENCY_BUMP_EASE
      : (REMEDIATION_EASE[c.cwe ?? ''] ?? DEFAULT_REMEDIATION_EASE);
    return {
      findingId: c.findingId,
      // 上流を断つ方が下流を全部潰すより効くので上流性を重く見る
      score: 0.6 * upstreamness + 0.4 * ease,
      upstreamness,
      ease,
    };
  });
}

/** LLM の提案を採用する許容差。これ以内なら「僅差」とみなす */
export const CHOKE_POINT_LLM_TOLERANCE = 0.15;

/**
 * チョークポイントを選ぶ。
 * LLM の提案が候補に含まれ、最良候補と僅差なら LLM の判断（文脈理解）を尊重する。
 */
export function selectChokePoint(
  candidates: readonly ChokePointCandidate[],
  totalSteps: number,
  llmSuggestion: string | null,
): { findingId: string; score: ChokePointScore } | null {
  if (candidates.length === 0) return null;
  const scored = scoreChokePoints(candidates, totalSteps);
  let best = scored[0];
  if (best === undefined) return null;
  for (const s of scored) {
    if (s.score > best.score) best = s;
  }
  if (llmSuggestion !== null) {
    const suggested = scored.find((s) => s.findingId === llmSuggestion);
    if (suggested !== undefined && suggested.score >= best.score - CHOKE_POINT_LLM_TOLERANCE) {
      return { findingId: suggested.findingId, score: suggested };
    }
  }
  return { findingId: best.findingId, score: best };
}
