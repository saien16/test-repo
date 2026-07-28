/**
 * 設定モデル（.vulnscan.yml）。
 */

import type { Severity } from './context.js';
import type { LensId } from './finding.js';

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

/**
 * 設定値の出所。信頼境界の判定に使う。
 *   - 'default'     : 組み込みの既定値
 *   - 'config-file' : スキャン対象リポジトリの `.vulnscan.yml`（**未信頼**）
 *   - 'cli'         : CLIフラグ（オペレータが明示指定した値＝信頼できる）
 */
export type ConfigSource = 'default' | 'config-file' | 'cli';

/** パス系設定の出所。リポジトリ外を指すことを許すかの判断に使う */
export interface PathSources {
  baselinePath: ConfigSource;
  ignorePath: ConfigSource;
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
  /** ベースラインJSONの保存先 */
  baselinePath: string;
  /** 抑制リスト */
  ignorePath: string;
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
   * `.vulnscan.yml` から指定しても採用されない（信頼の詐称を防ぐ）。
   */
  pathSources?: PathSources;
}

export const DEFAULT_CONFIG: VulnScanConfig = {
  llm: {
    model: 'claude-opus-5',
    effort: 'high',
    maxTokens: 16000,
    concurrency: 4,
    tokenBudget: null,
    fallbackModel: 'claude-opus-4-8',
    cache: true,
  },
  scan: {
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      '**/vendor/**',
      '**/*.min.js',
      '**/*.lock',
    ],
    include: [],
    lenses: [
      'injection',
      'authz',
      'crypto-secrets',
      'deserialization-ssrf',
      'web-output',
    ],
    selfVerify: true,
    minConfidence: 0.5,
    maxFileBytes: 512_000,
  },
  failOn: 'high',
  failOnNewOnly: false,
  baselinePath: '.vulnscan/baseline.json',
  ignorePath: '.vulnignore',
  killChain: true,
  architecture: true,
  heatmap: true,
  minInferenceConfidence: 0.3,
  pathSources: { baselinePath: 'default', ignorePath: 'default' },
};
