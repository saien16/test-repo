/**
 * 設定モデル（.grimoire.yml、旧 .vulnscan.yml）。
 *
 * フィールドの定義元は {@link CONFIG_SPEC}（`types/config-spec.ts`）。
 * 既定値・封じ込め対象キー・サンプル設定はすべてそこから派生する。
 * ここでは利用者から見た**型**としての `VulnScanConfig` を定義し、
 * 末尾で spec との網羅性を片方向に検査する。
 */

import type { Severity } from './context.js';
import type { LensId } from './finding.js';
import {
  CONFIG_SPEC,
  defaultPathSources,
  type ConfigKey,
  type PathKey,
  type PathSources,
} from './config-spec.js';

export {
  CONFIG_SPEC,
  PATH_KEYS,
  defaultPathSources,
  type ConfigKey,
  type ConfigSource,
  type FieldKind,
  type FieldSpec,
  type PathKey,
  type PathSources,
} from './config-spec.js';

export interface LlmConfig {
  /** 既定は claude-opus-5 */
  model: string;
  /** 思考の深さ。低いほど高速・安価 */
  effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
  maxTokens: number;
  /** 同時実行数 */
  concurrency: number;
  /** このスキャン全体の出力トークン上限。超えたら打ち切る */
  tokenBudget: number | null;
  /** 安全分類器に拒否された際のフォールバックモデル */
  fallbackModel: string | null;
  /** チャンク単位の結果キャッシュを使うか */
  cache: boolean;
}

export interface ScanConfig {
  /** 走査から除外する glob */
  exclude: string[];
  /** 明示的に含める glob（未指定なら全て） */
  include: string[];
  /** 有効にする分析レンズ */
  lenses: LensId[];
  /** 自己検証パスを実行するか（誤検知抑制） */
  selfVerify: boolean;
  /** この確信度未満のFindingは破棄 */
  minConfidence: number;
  /** 1ファイルあたりの最大バイト数。超過分はスキップ */
  maxFileBytes: number;
}

/** 出所が信頼境界の内側（オペレータ由来）かどうか */
export function isOperatorProvidedPath(
  config: { pathSources?: PathSources } | undefined,
  key: keyof PathSources,
): boolean {
  return config?.pathSources?.[key] === 'cli';
}

export interface VulnScanConfig {
  llm: LlmConfig;
  scan: ScanConfig;
  /** この深刻度以上が存在すれば非ゼロ終了 */
  failOn: Severity | 'never';
  /** 新規Findingのみでゲートするか */
  failOnNewOnly: boolean;
  /**
   * 走査が完走しなかった場合に非ゼロ終了するか（終了コード3）。
   * `failOn` とは独立した軸なので、`failOn: 'never'` でも効く。
   */
  failOnIncompleteScan: boolean;
  /** ベースラインJSONの保存先 */
  baselinePath: string;
  /** 抑制リスト */
  ignorePath: string;
  /** CISA KEV と照合するか */
  kev: boolean;
  /** ローカルの KEV カタログJSON。空ならネットワークから取得 */
  kevPath: string;
  /** HTML控えの保存先ディレクトリ */
  reportDir: string;
  /** HTML控えを残すか */
  archiveReport: boolean;
  /** キルチェーン分析を実行するか */
  killChain: boolean;
  /** アーキテクチャ・デプロイスタックの推定を行うか */
  architecture: boolean;
  /** 脆弱性ヒートマップを生成するか（architecture が必要） */
  heatmap: boolean;
  /**
   * ヒートマップの想定リスク層に採用する最低確信度。
   * これ未満の推測はセルに反映せず、死角判定にも使わない。
   */
  minInferenceConfidence: number;
  /**
   * パス系設定の出所。loadConfig が必ず算出して上書きするため、
   * `.grimoire.yml` から指定しても採用されない（信頼の詐称を防ぐ）。
   */
  pathSources?: PathSources;
}

/**
 * vulnscan 時代の既定パス。
 *
 * 明示指定が無く、かつ新しい既定パスが存在せず旧パスだけが存在する場合に、
 * loadConfig がこちらへフォールバックする（既存リポジトリを壊さないため）。
 *
 * キーは spec から導出した {@link PathKey} なので、パス設定を足したのに
 * ここへ書き忘れるとコンパイルエラーになる（旧名が無い場合は現在値と同じ値を書く）。
 */
export const LEGACY_DEFAULT_PATHS: Readonly<Record<PathKey, string>> = {
  baselinePath: '.vulnscan/baseline.json',
  ignorePath: '.vulnignore',
  // vulnscan 時代に相当するものが無いため、現在値と同じ値を置く（旧名フォールバックは働かない）
  reportDir: 'reports',
  kevPath: '.grimoire/kev.json',
};

/** spec の `default` をそのまま並べた型。リテラル型が保たれる */
type SpecDefaults = { -readonly [K in ConfigKey]: (typeof CONFIG_SPEC)[K]['default'] };

/**
 * spec から既定値のオブジェクトを組み立てる。
 *
 * `Object.entries` はキーを string へ落としてしまうため、戻り値でだけ型を戻す。
 * 値の側は {@link SpecDefaults} が spec のリテラル型を保持しているので、
 * 下の `DEFAULT_CONFIG` への代入で `VulnScanConfig` との整合が検査される。
 */
function specDefaults(): SpecDefaults {
  const defaults: Record<string, unknown> = {};
  for (const [key, spec] of Object.entries(CONFIG_SPEC)) defaults[key] = spec.default;
  return defaults as SpecDefaults;
}

export const DEFAULT_CONFIG: VulnScanConfig = {
  ...specDefaults(),
  pathSources: defaultPathSources(),
};

/* ------------------------------------------------------------------ *
 * spec と設定型の網羅性検査
 *
 * `VulnScanConfig` にフィールドを足したら {@link CONFIG_SPEC} にも書くまで
 * コンパイルが通らない（`DEFAULT_CONFIG` の代入と下の `_SpecCoversConfig` の
 * 両方が落ちる）。逆に spec にだけ足した場合も `_SpecCoversConfig` が落ちる。
 *
 * ここで `satisfies Record<keyof VulnScanConfig, FieldSpec>` を使わないのは、
 * `VulnScanConfig → PathSources → PathKey → CONFIG_SPEC` と型が循環するため。
 * 双方向に縛らず、**両方が定義され終わったこの位置で片方向に**検査する。
 * これらの型はどこからも参照しない（参照すると循環が復活する）。
 * ------------------------------------------------------------------ */

type _Assert<T extends true> = T;
type _Eq<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/** spec のキー集合＝設定型のキー集合（`pathSources` は loadConfig の算出値なので除く） */
type _SpecCoversConfig = _Assert<_Eq<ConfigKey, Exclude<keyof VulnScanConfig, 'pathSources'>>>;

/**
 * 逆向きの確認。架空のフィールドを足した型では網羅性検査が false になり、
 * `_Assert` が受け付けない（＝コンパイルエラーになる）ことを固定する。
 * `@ts-expect-error` なので、もし検査が素通りするようになれば
 * 「未使用の @ts-expect-error」として tsc が落ちる。
 */
interface _ConfigWithGhostField extends VulnScanConfig {
  ghostPath: string;
}
type _GhostKeys = Exclude<keyof _ConfigWithGhostField, 'pathSources'>;
// prettier-ignore
// @ts-expect-error 架空フィールド ghostPath は CONFIG_SPEC に無いため網羅性検査は false になる
type _GhostFieldIsDetected = _Assert<_Eq<ConfigKey, _GhostKeys>>;
