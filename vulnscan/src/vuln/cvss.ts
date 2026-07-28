/**
 * CVSS v3.0 / v3.1 基本評価基準（Base Metrics）の計算・パース・生成。
 *
 * 実装は FIRST の公式仕様書
 * 「Common Vulnerability Scoring System v3.1: Specification Document」
 * および v3.0 仕様の計算式に厳密に従う。
 */

import type { EntryPoint, ScanContext } from '../types/context.js';
import type { Cvss3Metrics, Cvss3Result, RawFinding, Severity } from '../types/finding.js';
import {
  ciaFromCatalog,
  extractCweId,
  likelihoodOf,
  lookupCwe as lookupCatalogCwe,
} from './catalog.js';
import { round1 } from '../util/num.js';
import { normalizeRelPath } from '../util/path.js';
import { owaspForCwe } from './knowledge.js';

/* ------------------------------------------------------------------ *
 * メトリクスの重み（公式仕様 Table 14 - 19）
 * ------------------------------------------------------------------ */

/** Attack Vector の重み */
const W_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
/** Attack Complexity の重み */
const W_AC = { L: 0.77, H: 0.44 } as const;
/** User Interaction の重み */
const W_UI = { N: 0.85, R: 0.62 } as const;
/** Confidentiality / Integrity / Availability の重み */
const W_CIA = { H: 0.56, L: 0.22, N: 0 } as const;
/** Privileges Required は Scope に依存する（S:U のとき） */
const W_PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 } as const;
/** Privileges Required（S:C のとき。権限昇格の価値が上がるため重みが大きい） */
const W_PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 } as const;

/** ベクタ文字列に現れる基本メトリクスの順序（公式の正準順序） */
const BASE_METRIC_ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;

/** 各基本メトリクスで許される値 */
const ALLOWED_VALUES: Record<(typeof BASE_METRIC_ORDER)[number], readonly string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};

/* ------------------------------------------------------------------ *
 * roundup
 * ------------------------------------------------------------------ */

/**
 * CVSS v3.1 の Roundup（公式仕様 Appendix A）。
 *
 * 浮動小数点の丸め誤差により「本来ちょうど 4.0 の値が 4.000000000000001 となり
 * 4.1 に切り上がる」事故を防ぐため、仕様は整数演算による定義を与えている。
 *   int_input = round(input * 100000)
 *   if (int_input % 10000 == 0) return int_input / 100000
 *   else return (floor(int_input / 10000) + 1) / 10.0
 */
export function roundupV31(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10.0;
}

/**
 * CVSS v3.0 の Roundup。
 * v3.0 仕様は「小数第1位への単純な切り上げ」しか規定していないため
 * `ceil(x * 10) / 10` で実装する。v3.1 との差はここだけであり、
 * 浮動小数点誤差が乗るケースでは v3.0 のほうが 0.1 高く出ることがある。
 */
export function roundupV30(input: number): number {
  return Math.ceil(input * 10) / 10;
}

function roundup(input: number, version: '3.0' | '3.1'): number {
  return version === '3.1' ? roundupV31(input) : roundupV30(input);
}


/* ------------------------------------------------------------------ *
 * 深刻度レーティング
 * ------------------------------------------------------------------ */

/** スコア → 深刻度レーティング（公式仕様 Table 14: Qualitative Severity Rating Scale） */
export function cvss3SeverityRating(score: number): Cvss3Result['baseSeverity'] {
  if (score <= 0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

/** CVSS の深刻度レーティング → 本ツール内部の Severity */
export function cvss3RatingToSeverity(rating: Cvss3Result['baseSeverity']): Severity {
  switch (rating) {
    case 'Critical':
      return 'critical';
    case 'High':
      return 'high';
    case 'Medium':
      return 'medium';
    case 'Low':
      return 'low';
    default:
      return 'info';
  }
}

/* ------------------------------------------------------------------ *
 * 計算本体
 * ------------------------------------------------------------------ */

/**
 * 基本評価基準（Base Score）を計算する。
 *
 * ISS            = 1 - ((1 - C) × (1 - I) × (1 - A))
 * Impact(S:U)    = 6.42 × ISS
 * Impact(S:C)    = 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
 * Exploitability = 8.22 × AV × AC × PR × UI
 * BaseScore      = Impact <= 0                 → 0.0
 *                  S:U → Roundup(min(Impact + Exploitability, 10))
 *                  S:C → Roundup(min(1.08 × (Impact + Exploitability), 10))
 */
export function calculateCvss3(metrics: Cvss3Metrics, version: '3.0' | '3.1' = '3.1'): Cvss3Result {
  const m = validateMetrics(metrics);

  const wC = W_CIA[m.C];
  const wI = W_CIA[m.I];
  const wA = W_CIA[m.A];

  // Impact Sub Score (ISS)
  const iss = 1 - (1 - wC) * (1 - wI) * (1 - wA);

  // Impact。Scope が Changed の場合は影響が別のセキュリティ権限範囲に及ぶため式が変わる。
  const impact =
    m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  // Exploitability。PR の重みは Scope に依存する。
  const wPR = (m.S === 'C' ? W_PR_CHANGED : W_PR_UNCHANGED)[m.PR];
  const exploitability = 8.22 * W_AV[m.AV] * W_AC[m.AC] * wPR * W_UI[m.UI];

  let baseScore: number;
  if (impact <= 0) {
    // 影響が全く無い（C:N/I:N/A:N）場合はスコア 0.0
    baseScore = 0.0;
  } else if (m.S === 'U') {
    baseScore = roundup(Math.min(impact + exploitability, 10), version);
  } else {
    baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10), version);
  }

  return {
    baseScore,
    baseSeverity: cvss3SeverityRating(baseScore),
    vector: buildCvss3Vector(m, version),
    metrics: m,
    version,
    breakdown: {
      // 説明用に小数第1位へ丸めた値（公式計算機の表示と同じ粒度）
      impactSubScore: round1(Math.max(impact, 0)),
      exploitabilitySubScore: round1(exploitability),
    },
  };
}

/* ------------------------------------------------------------------ *
 * ベクタ文字列のパース / 生成
 * ------------------------------------------------------------------ */

/**
 * CVSS ベクタ文字列をパースして基本メトリクスを返す。
 *
 * - `CVSS:3.1/AV:N/AC:L/...` および `CVSS:3.0/...` のプレフィクス付きを受け付ける。
 * - プレフィクスが無い `AV:N/AC:L/...` 形式も受け付ける（寛容にパースする）。
 * - Temporal / Environmental（E, RL, RC, CR, MAV ...）は基本評価に無関係なので無視する。
 *   OSV や NVD が返すベクタに付随することがあるため、エラーにしない。
 */
export function parseCvss3Vector(vector: string): Cvss3Metrics {
  if (typeof vector !== 'string' || vector.trim() === '') {
    throw new Error('CVSSベクタが空です');
  }

  const parts = vector.trim().split('/').filter((p) => p !== '');
  const collected: Record<string, string> = {};

  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx < 0) {
      throw new Error(`CVSSベクタの要素が不正です: '${part}'`);
    }
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim().toUpperCase();

    if (key.toUpperCase() === 'CVSS') {
      if (value !== '3.0' && value !== '3.1') {
        throw new Error(`未対応のCVSSバージョンです: '${value}'（3.0 / 3.1 のみ対応）`);
      }
      continue;
    }
    // 基本メトリクス以外（Temporal/Environmental）は読み飛ばす
    if (!(key in ALLOWED_VALUES)) continue;
    collected[key] = value;
  }

  const result: Record<string, string> = {};
  for (const key of BASE_METRIC_ORDER) {
    const value = collected[key];
    if (value === undefined) {
      throw new Error(`CVSSベクタに必須メトリクス '${key}' がありません: '${vector}'`);
    }
    if (!ALLOWED_VALUES[key].includes(value)) {
      throw new Error(`メトリクス '${key}' の値が不正です: '${value}'`);
    }
    result[key] = value;
  }

  return result as unknown as Cvss3Metrics;
}

/** 基本メトリクスから正準順序のベクタ文字列を生成する */
export function buildCvss3Vector(m: Cvss3Metrics, version: '3.0' | '3.1' = '3.1'): string {
  const v = validateMetrics(m);
  const body = BASE_METRIC_ORDER.map((key) => `${key}:${v[key]}`).join('/');
  return `CVSS:${version}/${body}`;
}

/** メトリクスの値を検証し、余計なプロパティを落とした正規形を返す */
function validateMetrics(m: Cvss3Metrics): Cvss3Metrics {
  if (m === null || typeof m !== 'object') {
    throw new Error('CVSSメトリクスがオブジェクトではありません');
  }
  const out: Record<string, string> = {};
  for (const key of BASE_METRIC_ORDER) {
    const value = (m as unknown as Record<string, unknown>)[key];
    if (typeof value !== 'string' || !ALLOWED_VALUES[key].includes(value)) {
      throw new Error(`メトリクス '${key}' の値が不正です: '${String(value)}'`);
    }
    out[key] = value;
  }
  return out as unknown as Cvss3Metrics;
}

/* ------------------------------------------------------------------ *
 * RawFinding からのメトリクス推定
 * ------------------------------------------------------------------ */

/**
 * CWE ごとの典型的な基本メトリクス（推定の出発点）。
 * 「その脆弱性クラスが最も一般的な形で悪用された場合」を表す。
 * NVD が同種の CVE に付与しているベクタの中央値的な値を採用している。
 *
 * MITRE CWE カタログ（{@link ciaFromCatalog}）との関係:
 *   カタログが与えるのは C/I/A の影響だけで、AV/AC/PR/UI/S は与えない。
 *   一方この表は8メトリクス全てを NVD の実績値に合わせて調整してあり、
 *   実スコアとの整合が検証済みなので、**この表にある CWE ではこちらを優先する**。
 *   表に無い CWE（カタログ959件のうち約890件）ではカタログの C/I/A を使う。
 *   どちらを使ったかは推定根拠（reasons）に必ず明記される。
 */
const CWE_BASELINE: Record<string, Cvss3Metrics> = {
  // --- インジェクション系: 認証不要でネットワーク越しに完全な情報/完全性侵害 ---
  'CWE-89': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // SQLi
  'CWE-78': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // OSコマンド
  'CWE-77': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'CWE-94': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // コード注入
  'CWE-95': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // eval
  'CWE-502': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // 安全でない逆シリアル化
  'CWE-90': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }, // LDAP注入
  'CWE-91': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }, // XML注入
  'CWE-943': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }, // NoSQL等
  'CWE-917': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // 式言語注入
  'CWE-20': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L' }, // 入力検証不備
  'CWE-74': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'CWE-88': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 引数注入
  'CWE-113': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' }, // HTTPヘッダ注入
  'CWE-643': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // XPath注入

  // --- 出力エンコーディング系: 被害者の操作(UI:R)が必要、ブラウザ側へ影響が波及(S:C) ---
  'CWE-79': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' }, // XSS
  'CWE-80': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  'CWE-116': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  'CWE-1021': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'N', I: 'L', A: 'N' }, // クリックジャッキング
  'CWE-352': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'H', A: 'N' }, // CSRF
  'CWE-601': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' }, // オープンリダイレクト

  // --- アクセス制御系: 何らかの権限を持つ攻撃者を想定 ---
  'CWE-22': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // パストラバーサル
  'CWE-23': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'CWE-862': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 認可の欠落
  'CWE-863': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 不正な認可
  'CWE-639': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // IDOR
  'CWE-284': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  'CWE-285': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  'CWE-732': { AV: 'L', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // 不適切な権限設定
  'CWE-269': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' }, // 権限管理不備
  'CWE-200': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // 情報漏えい
  'CWE-359': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'CWE-209': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' }, // エラーでの情報漏えい

  // --- 認証・資格情報系 ---
  'CWE-287': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 不適切な認証
  'CWE-306': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 認証の欠如
  'CWE-798': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // ハードコード資格情報
  'CWE-259': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'CWE-522': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // 資格情報の保護不備
  'CWE-521': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 脆弱なパスワード要件
  'CWE-307': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 総当たり対策不備
  'CWE-384': { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'H', A: 'N' }, // セッション固定
  'CWE-613': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // セッション期限不備

  // --- 暗号 ---
  'CWE-327': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // 脆弱な暗号アルゴリズム
  'CWE-328': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // 脆弱なハッシュ
  'CWE-326': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'CWE-330': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }, // 不十分なランダム性
  'CWE-338': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  'CWE-331': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  'CWE-319': { AV: 'A', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 平文通信（中間者が必要）
  'CWE-311': { AV: 'A', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'CWE-295': { AV: 'A', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 証明書検証不備
  'CWE-347': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }, // 署名検証不備
  'CWE-614': { AV: 'A', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // Secure属性なしCookie

  // --- SSRF / 外部リソース ---
  'CWE-918': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'N' }, // SSRF
  'CWE-611': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'L' }, // XXE
  'CWE-434': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // 危険なファイルアップロード
  'CWE-829': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // 信頼できない機能の取込
  'CWE-494': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'CWE-915': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'H', A: 'N' }, // マスアサインメント
  'CWE-345': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'H', A: 'N' },

  // --- 可用性・ログ・設定 ---
  'CWE-400': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' }, // リソース枯渇
  'CWE-1333': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' }, // ReDoS
  'CWE-532': { AV: 'L', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, // ログへの機密出力
  'CWE-117': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' }, // ログ注入
  'CWE-778': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' }, // ログ不足
  'CWE-16': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' }, // 設定不備
  'CWE-1004': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'N', A: 'N' }, // HttpOnlyなしCookie
  'CWE-1395': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }, // 脆弱な依存
  'CWE-937': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
};

/** OWASP カテゴリ単位のフォールバック（CWE が未知のとき） */
const CATEGORY_BASELINE: Record<string, Cvss3Metrics> = {
  A01: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
  A02: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  A03: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  A04: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
  A05: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
  A06: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  A07: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  A08: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  A09: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' },
  A10: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'N', A: 'N' },
};

/** severity 単位の最終フォールバック */
const SEVERITY_BASELINE: Record<Severity, Cvss3Metrics> = {
  critical: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  high: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  medium: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
  low: { AV: 'N', AC: 'H', PR: 'L', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
  info: { AV: 'L', AC: 'H', PR: 'H', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N' },
};

/** 影響度の順位（比較用） */
const IMPACT_RANK = { N: 0, L: 1, H: 2 } as const;
type ImpactValue = 'N' | 'L' | 'H';

/** 推定結果と、その根拠（説明可能性のため） */
export interface Cvss3Inference {
  metrics: Cvss3Metrics;
  /** どの根拠でどのメトリクスをどう決めたか（日本語の説明文） */
  reasons: string[];
}

/**
 * LLM が返した RawFinding（CVSSベクタを持たない）から基本メトリクスを推定する。
 *
 * 推定は次の順に「根拠が強いものほど後で上書きする」形で行う:
 *   1. CWE 別の典型ベースライン
 *      → 無ければ MITRE CWE カタログの consequences から C/I/A を導出
 *      → それも無ければ OWASP カテゴリ → severity の順にフォールバック
 *   2. エントリポイントへの到達性（ctx.entryPoints）で AV / PR を補正
 *   3. dataFlow の有無・サニタイザの有無で AC を補正
 *   4. LLM が申告した severity で影響度(C/I/A)の上下限を補正
 *
 * すべての補正理由は reasons に日本語で記録され、レポートで開示できる。
 * MITRE 由来（事実）と本ツールの調整（推測）が区別できるよう、
 * カタログを使った場合はその旨を明記する。
 */
export function inferCvss3MetricsWithReasons(
  finding: RawFinding,
  ctx: ScanContext,
): Cvss3Inference {
  const reasons: string[] = [];
  const cwe = extractCweId(finding.cwe);

  // --- 1. ベースラインの選択 ---------------------------------------
  let metrics: Cvss3Metrics;
  const byCwe = cwe ? CWE_BASELINE[cwe] : undefined;
  const catalogCia = cwe ? ciaFromCatalog(cwe) : null;

  if (byCwe) {
    metrics = { ...byCwe };
    reasons.push(`${cwe} の典型的な攻撃シナリオを基準値として採用（NVDの実績値に合わせた手調整ベースライン）`);
    // カタログにも根拠がある場合、食い違いを黙って捨てずに開示する。
    if (catalogCia && (catalogCia.C !== byCwe.C || catalogCia.I !== byCwe.I || catalogCia.A !== byCwe.A)) {
      reasons.push(
        `参考: MITRE CWE カタログの Common_Consequences からは ` +
          `C:${catalogCia.C}/I:${catalogCia.I}/A:${catalogCia.A} が導かれるが、` +
          `8メトリクス全体の整合が取れている手調整ベースラインを優先した`,
      );
    }
  } else if (catalogCia) {
    // カタログは C/I/A しか与えないので、攻撃容易性側(AV/AC/PR/UI/S)は
    // OWASP カテゴリ（祖先からの継承を含む）→ severity の順に補う。
    const skeleton = pickExploitabilitySkeleton(cwe, finding);
    metrics = { ...skeleton.metrics, C: catalogCia.C, I: catalogCia.I, A: catalogCia.A };
    reasons.push(
      `${cwe} の影響度は MITRE CWE カタログ（Common_Consequences）由来: ` +
        `C:${catalogCia.C}/I:${catalogCia.I}/A:${catalogCia.A}`,
    );
    reasons.push(`攻撃容易性(AV/AC/PR/UI/S)はカタログに情報が無いため${skeleton.label}で補完`);

    // Likelihood_Of_Exploit も MITRE 由来の事実なので AC の推定に使う。
    const likelihood = likelihoodOf(cwe ?? '');
    if (likelihood === 'High' && metrics.AC === 'H') {
      metrics.AC = 'L';
      reasons.push('カタログの Likelihood_Of_Exploit が High のため AC を H → L に降格');
    } else if (likelihood === 'Low' && metrics.AC === 'L') {
      metrics.AC = 'H';
      reasons.push('カタログの Likelihood_Of_Exploit が Low のため AC を L → H に引き上げ');
    }
  } else {
    const categoryKey = owaspKeyFor(cwe, finding);
    const byCategory = categoryKey ? CATEGORY_BASELINE[categoryKey] : undefined;
    if (byCategory) {
      metrics = { ...byCategory };
      const known = cwe !== null && lookupCatalogCwe(cwe) !== null;
      reasons.push(
        known
          ? `CWE '${finding.cwe}' はカタログにあるが影響度を導ける consequences が無いため OWASP カテゴリ ${categoryKey} の代表値を採用`
          : `CWE '${finding.cwe}' は未知のため OWASP カテゴリ ${categoryKey} の代表値を採用`,
      );
    } else {
      metrics = { ...(SEVERITY_BASELINE[finding.severity] ?? SEVERITY_BASELINE.medium) };
      reasons.push(`CWE・カテゴリとも未知のため severity='${finding.severity}' の代表値を採用`);
    }
  }

  // --- 2. エントリポイントへの到達性 -------------------------------
  const reach = analyzeReachability(finding, ctx);
  if (reach.remoteEntryPoint) {
    if (metrics.AV !== 'N') {
      metrics.AV = 'N';
      reasons.push(
        `外部公開のエントリポイント(${reach.entryPointLabel})から到達可能なため AV を N に引き上げ`,
      );
    } else {
      reasons.push(`外部公開のエントリポイント(${reach.entryPointLabel})から到達可能（AV:N を維持）`);
    }
    if (reach.authenticatedEntryPoint && metrics.PR === 'N') {
      metrics.PR = 'L';
      reasons.push('該当エントリポイントは認証を要求しているため PR を L に引き上げ');
    }
  } else if (reach.localEntryPoint) {
    if (metrics.AV === 'N') {
      metrics.AV = 'L';
      reasons.push('到達経路が CLI / ローカル実行のエントリポイントのみのため AV を L に降格');
    }
  } else {
    // 外部からの入口が特定できない = 攻撃者が直接触れる根拠が無い
    if (metrics.AV === 'N') {
      metrics.AV = 'L';
      reasons.push('エントリポイントからの到達性が確認できないため AV を N → L に降格');
    }
    if (metrics.PR === 'N') {
      metrics.PR = 'L';
      reasons.push('到達性が未確認のため、何らかの権限が必要とみなし PR を N → L に引き上げ');
    }
  }

  // --- 3. dataFlow による攻撃複雑度の補正 --------------------------
  const flow = finding.dataFlow ?? [];
  const hasSource = flow.some((s) => s.role === 'source');
  const hasSink = flow.some((s) => s.role === 'sink');
  const hasSanitizer = flow.some((s) => s.role === 'sanitizer');

  if (flow.length === 0) {
    if (metrics.AC === 'L') {
      metrics.AC = 'H';
      reasons.push('source→sink のデータフローが未証明のため AC を L → H に引き上げ');
    }
  } else if (hasSanitizer) {
    if (metrics.AC === 'L') {
      metrics.AC = 'H';
      reasons.push('経路上にサニタイザが存在し回避条件が必要なため AC を L → H に引き上げ');
    }
  } else if (hasSource && hasSink) {
    if (metrics.AC === 'H') {
      metrics.AC = 'L';
      reasons.push('source から sink までの経路が提示されており再現条件が単純なため AC を H → L に降格');
    } else {
      reasons.push('source から sink までの経路が提示されている（AC:L を維持）');
    }
  }

  // --- 4. severity による影響度の整合 ------------------------------
  applySeverityAdjustment(metrics, finding.severity, reasons);

  return { metrics, reasons };
}

/**
 * OWASP Top 10 2021 のカテゴリ記号(A01..A10)を決める。
 * LLM の申告 → 知識ベース（手作り、または CWE の祖先からの継承）の順に見る。
 */
function owaspKeyFor(cwe: string | null, finding: RawFinding): string | null {
  const declared = /^(A\d{2})/.exec(finding.category ?? '')?.[1];
  if (declared && CATEGORY_BASELINE[declared]) return declared;
  const inherited = cwe ? owaspForCwe(cwe) : null;
  const key = inherited ? /^(A\d{2})/.exec(inherited.category)?.[1] : undefined;
  return key ?? null;
}

/**
 * 攻撃容易性側のメトリクス（AV/AC/PR/UI/S）の出発点を選ぶ。
 * カタログは影響度しか与えないため、この部分は別の根拠で埋める必要がある。
 */
function pickExploitabilitySkeleton(
  cwe: string | null,
  finding: RawFinding,
): { metrics: Cvss3Metrics; label: string } {
  const categoryKey = owaspKeyFor(cwe, finding);
  const byCategory = categoryKey ? CATEGORY_BASELINE[categoryKey] : undefined;
  if (byCategory) {
    return { metrics: { ...byCategory }, label: `OWASP カテゴリ ${categoryKey} の代表値` };
  }
  const bySeverity = SEVERITY_BASELINE[finding.severity] ?? SEVERITY_BASELINE.medium;
  return { metrics: { ...bySeverity }, label: `severity='${finding.severity}' の代表値` };
}

/** {@link inferCvss3MetricsWithReasons} のメトリクスのみを返す版 */
export function inferCvss3Metrics(finding: RawFinding, ctx: ScanContext): Cvss3Metrics {
  return inferCvss3MetricsWithReasons(finding, ctx).metrics;
}

/** LLM 申告の severity と推定影響度の整合を取る */
function applySeverityAdjustment(
  metrics: Cvss3Metrics,
  severity: Severity,
  reasons: string[],
): void {
  const axes: Array<'C' | 'I' | 'A'> = ['C', 'I', 'A'];
  const maxRank = Math.max(...axes.map((a) => IMPACT_RANK[metrics[a] as ImpactValue]));

  if (severity === 'critical') {
    if (maxRank < IMPACT_RANK.H) {
      // 最も高い影響軸を H に引き上げる（全て N なら C を採用）
      const target = axes.reduce((best, a) =>
        IMPACT_RANK[metrics[a] as ImpactValue] > IMPACT_RANK[metrics[best] as ImpactValue] ? a : best,
      );
      const axis = maxRank === 0 ? 'C' : target;
      metrics[axis] = 'H';
      reasons.push(`severity='critical' のため影響度 ${axis} を H に引き上げ`);
    }
  } else if (severity === 'low') {
    let changed = false;
    for (const a of axes) {
      if (metrics[a] === 'H') {
        metrics[a] = 'L';
        changed = true;
      }
    }
    if (changed) reasons.push("severity='low' のため High の影響度を Low に降格");
  } else if (severity === 'info') {
    // 情報提供レベル = セキュリティ影響が実証されていない。
    // CVSS ではこれを「影響なし（スコア 0.0 / None）」として表現するのが正しい。
    let changed = false;
    for (const a of axes) {
      if (metrics[a] !== 'N') {
        metrics[a] = 'N';
        changed = true;
      }
    }
    if (changed) reasons.push("severity='info'（影響未実証）のため影響度を全て None とし 0.0 とする");
  }
}

/** 到達性の解析結果 */
interface ReachabilityInfo {
  /** ネットワーク越しに到達しうるエントリポイントがあるか */
  remoteEntryPoint: boolean;
  /** ローカル実行のエントリポイント（CLI / main）だけがあるか */
  localEntryPoint: boolean;
  /** そのエントリポイントが認証を要求しているか */
  authenticatedEntryPoint: boolean;
  entryPointLabel: string;
}

/** ネットワーク経由で外部から叩かれうるエントリポイント種別 */
const REMOTE_ENTRY_KINDS = new Set<EntryPoint['kind']>([
  'http-route',
  'message-handler',
  'event-handler',
]);

/**
 * Finding が外部からのエントリポイントに紐づくかを判定する。
 * 判定は「Finding もしくはそのデータフローが通過するファイルに
 * エントリポイントが定義されているか」という保守的なファイル単位の近似で行う。
 */
function analyzeReachability(finding: RawFinding, ctx: ScanContext): ReachabilityInfo {
  const files = new Set<string>();
  if (finding.location?.file) files.add(normalizeRelPath(finding.location.file));
  for (const step of finding.dataFlow ?? []) {
    if (step.file) files.add(normalizeRelPath(step.file));
  }

  const matched = (ctx.entryPoints ?? []).filter((ep) =>
    files.has(normalizeRelPath(ep.file)),
  );

  const remote = matched.filter((ep) => REMOTE_ENTRY_KINDS.has(ep.kind));
  const chosen = remote[0] ?? matched[0];

  return {
    remoteEntryPoint: remote.length > 0,
    localEntryPoint: remote.length === 0 && matched.length > 0,
    authenticatedEntryPoint: matched.some((ep) => isAuthenticatedEntryPoint(ep)),
    entryPointLabel: chosen ? `${chosen.kind} ${chosen.identifier}` : 'なし',
  };
}

/** エントリポイントのメタデータから認証必須かどうかを読む */
function isAuthenticatedEntryPoint(ep: EntryPoint): boolean {
  const meta = ep.metadata ?? {};
  for (const key of ['auth', 'authentication', 'authenticated', 'requiresAuth']) {
    const value = meta[key];
    if (value === undefined) continue;
    const v = value.toLowerCase();
    if (v === 'true' || v === 'required' || v === 'yes' || v === 'authenticated') return true;
  }
  return false;
}

