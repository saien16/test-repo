/**
 * 設定フィールドの**単一の定義元**（spec）。
 *
 * ここに1回だけ書けば、以下がすべて自動的に派生する:
 *   - {@link PATH_KEYS}   … リポジトリ内へ封じ込めるキーの一覧（サニタイズ・出所記録・旧名フォールバックの駆動）
 *   - {@link PathSources} … パス系設定の出所の型
 *   - `DEFAULT_CONFIG`    … 既定値（`types/config.ts` が spec から組み立てる）
 *   - `.grimoire.yml.example` … サンプル設定（`config/example.ts` が生成する）
 *
 * 以前は `config/index.ts` に手書きの allowlist（`PATH_KEYS`）があり、
 * 新しいパス設定を足したのにそちらへ足し忘れると、
 * **サニタイズもされず CLI 由来との区別もされない値が下流へ流れる**構造だった。
 * 「足し忘れ＝デフォルト許可」を「足し忘れ＝コンパイルエラー」に変えるのがこのファイルの目的。
 *
 * 循環参照について:
 *   このファイルは `VulnScanConfig` を**型として参照しない**。参照すると
 *   `VulnScanConfig → PathSources → PathKey → CONFIG_SPEC → VulnScanConfig` で
 *   型が循環するため。網羅性の検査は、両方が定義され終わったあとに
 *   `types/config.ts` の末尾で片方向に行う。
 *
 * 対象範囲:
 *   spec 化するのは**トップレベルのフィールドのみ**。`llm.*` / `scan.*` の入れ子は
 *   `kind: 'nested'` として既存のオブジェクト既定値をそのまま持たせる。
 */

import type { LlmConfig, ScanConfig } from './config.js';

/**
 * 設定値の出所。信頼境界の判定に使う。
 *   - 'default'     : 組み込みの既定値
 *   - 'config-file' : スキャン対象リポジトリの `.grimoire.yml`（**未信頼**）
 *   - 'cli'         : CLIフラグ（オペレータが明示指定した値＝信頼できる）
 */
export type ConfigSource = 'default' | 'config-file' | 'cli';

/** 設定フィールドの種別 */
export type FieldKind =
  | 'path' // リポジトリ内へ封じ込める必要があるパス
  | 'plain' // 通常の値
  | 'nested'; // llm / scan のような入れ子オブジェクト

export interface FieldSpec {
  kind: FieldKind;
  /** 既定値。DEFAULT_CONFIG はこれから導出する */
  default: unknown;
  /** 説明。`.grimoire.yml.example` の生成にも使う（複数行は `\n` で区切る） */
  doc: string;
  /** 対応する CLI フラグ（無ければ undefined） */
  cli?: string;
  /**
   * `kind: 'nested'` のときの子キーの説明。サンプル生成にのみ使う。
   * 入れ子の中身までは spec 化しないが、サンプルのコメントは失いたくないため。
   */
  fieldDocs?: Readonly<Record<string, string>>;
}

/** llm セクションの既定値（入れ子はまとめて1つの既定値として扱う） */
const DEFAULT_LLM: LlmConfig = {
  model: 'claude-opus-5',
  effort: 'high',
  maxTokens: 16000,
  concurrency: 4,
  tokenBudget: null,
  fallbackModel: 'claude-opus-4-8',
  cache: true,
};

/** scan セクションの既定値 */
const DEFAULT_SCAN: ScanConfig = {
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
  lenses: ['injection', 'authz', 'crypto-secrets', 'deserialization-ssrf', 'web-output'],
  selfVerify: true,
  minConfidence: 0.5,
  maxFileBytes: 512_000,
};

/**
 * 設定フィールドの定義。**新しい設定はここに足す**。
 *
 * 並び順はそのまま `.grimoire.yml.example` の並び順になる。
 */
export const CONFIG_SPEC = {
  llm: {
    kind: 'nested',
    default: DEFAULT_LLM,
    doc: 'LLM（分析エンジン）の設定',
    fieldDocs: {
      model: '使用するモデル。既定は claude-opus-5',
      effort:
        '思考の深さ。low / medium / high / xhigh / max\n' +
        '低いほど高速・安価。まず high から始めて評価しながら下げるのが推奨',
      concurrency: 'LLMの同時実行数',
      tokenBudget: 'このスキャン全体の出力トークン上限。null なら無制限',
      fallbackModel: '安全分類器に解析を拒否された場合のフォールバックモデル',
      cache: 'チャンク単位の結果キャッシュ（変更のないコードを再分析しない）',
    },
  },
  scan: {
    kind: 'nested',
    default: DEFAULT_SCAN,
    doc: '走査対象の絞り込みと分析の設定',
    fieldDocs: {
      lenses: '実行する分析レンズ',
      selfVerify: '自己検証パス。誤検知を大きく減らすので原則有効のまま',
      minConfidence: 'この確信度未満の検出は破棄する',
      maxFileBytes: '1ファイルあたりの最大バイト数。超過分はスキップ',
    },
  },
  failOn: {
    kind: 'plain',
    default: 'high',
    doc: "この深刻度以上が存在すれば非ゼロ終了（CIゲート）。'never' で無効化",
    cli: '--fail-on',
  },
  failOnNewOnly: {
    kind: 'plain',
    default: false,
    doc: '新規検出のみでゲートする（既存の負債でCIを落とさない）',
    cli: '--fail-on-new-only',
  },
  failOnIncompleteScan: {
    kind: 'plain',
    default: true,
    doc:
      '走査が完走しなかった場合に非ゼロ終了する（終了コード 3）。\n' +
      '分析タスクの多くが失敗した（APIキー未設定・通信障害・予算切れなど）とき、\n' +
      '検出0件は「安全」ではなく「判定できなかった」ことを意味します。\n' +
      'これを 0 で通すとCIが偽の緑になるため既定で有効。\n' +
      "failOn: 'never' でもこの判定は独立に効きます（軸が違うため）。",
    cli: '--no-fail-on-incomplete',
  },
  baselinePath: {
    kind: 'path',
    default: '.grimoire/baseline.json',
    doc:
      'ベースラインJSONの保存先。\n' +
      'パス系設定はスキャン対象リポジトリの中だけを指せます。\n' +
      '絶対パスや `..` でリポジトリ外へ出る指定は拒否され、既定値が使われます\n' +
      '（設定ファイルは解析対象リポジトリの一部であり、未信頼入力として扱うため）。\n' +
      '旧名（.vulnscan/baseline.json）しか存在しない場合は、\n' +
      '明示指定が無い限り自動で旧名へフォールバックします（警告が1行出ます）。',
    cli: '--baseline',
  },
  kev: {
    kind: 'plain',
    default: true,
    doc:
      'CISA KEV（実際に悪用が確認された脆弱性の一覧）と照合するか。\n' +
      'ネットワーク取得を伴います。取得できなくても走査は続行し、注記が付かないだけです。\n' +
      '多数のリポジトリを続けて走査する場合は kevPath に落としたファイルを指すと確実です。',
    cli: '--no-kev',
  },
  kevPath: {
    kind: 'path',
    default: '.grimoire/kev.json',
    doc:
      'ローカルの KEV カタログJSON。\n' +
      'このファイルがあればネットワークを使わず、無ければ CISA から取得します。\n' +
      '閉域網や大量走査では、1度落として置いておくのが確実です:\n' +
      '  curl -o .grimoire/kev.json \\\n' +
      '    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\n' +
      '--kev-file で明示した場合、そのファイルが読めなければ取得へは進まずエラーにします\n' +
      '（指定したのに黙って別経路へ流れるほうが危険なため）。',
    cli: '--kev-file',
  },
  reportDir: {
    kind: 'path',
    default: 'reports',
    doc:
      'HTML控えの保存先ディレクトリ。走査のたびに\n' +
      '`grimoire-<対象名>-YYYYMMDD-HHMMSS.html` を1つ残し、\n' +
      '同じ内容を `latest.html` にも置きます（URLを固定して開きっぱなしにできます）。\n' +
      '-f / -o で何を指定していても、この控えは必ず作られます。\n' +
      'baselinePath と同じくリポジトリ内へ封じ込められます。\n' +
      'リポジトリ外へ出したい場合は --report-dir で明示指定してください。',
    cli: '--report-dir',
  },
  archiveReport: {
    kind: 'plain',
    default: true,
    doc:
      'HTML控えを残すか。false にすると reportDir へは何も書きません。\n' +
      'CIなど、成果物を別途回収する仕組みがある場合だけ切ってください。',
    cli: '--no-archive',
  },
  ignorePath: {
    kind: 'path',
    default: '.grimoireignore',
    doc:
      '抑制リストのパス。baselinePath と同じくリポジトリ内へ封じ込められます。\n' +
      '旧名（.vulnignore）しか存在しない場合は自動でフォールバックします。',
    cli: '--ignore-file',
  },
  killChain: {
    kind: 'plain',
    default: true,
    doc: 'キルチェーン分析（個別の検出を攻撃経路として連鎖させる）',
    cli: '--no-kill-chain',
  },
  architecture: {
    kind: 'plain',
    default: true,
    doc:
      'アーキテクチャ・デプロイスタックの推定を行うか\n' +
      '（マニフェストから読み取れる「事実」とLLMによる「推測」を分けて収集する）',
    cli: '--no-architecture',
  },
  heatmap: {
    kind: 'plain',
    default: true,
    doc:
      '脆弱性ヒートマップを生成するか（architecture が true である必要がある）\n' +
      '実測層（検出された脆弱性＝事実）と想定層（スタックから導かれる想定リスク＝推測）を\n' +
      '重ね合わせ、「検出は無いが想定リスクが高い」死角を洗い出す',
    cli: '--no-heatmap',
  },
  minInferenceConfidence: {
    kind: 'plain',
    default: 0.3,
    doc:
      'ヒートマップの想定リスク層に採用する最低確信度。\n' +
      'これ未満の推測はセルに反映せず、死角判定にも使わない',
  },
} as const satisfies Record<string, FieldSpec>;

/** 利用者が `.grimoire.yml` に書ける設定キー（`pathSources` は算出値なので含まない） */
export type ConfigKey = keyof typeof CONFIG_SPEC;

/** リポジトリ内への封じ込めを必須とする設定キー（spec の `kind: 'path'` から導出） */
export type PathKey = {
  [K in ConfigKey]: (typeof CONFIG_SPEC)[K]['kind'] extends 'path' ? K : never;
}[ConfigKey];

/**
 * 封じ込め対象のキー一覧。手書きの allowlist ではなく spec から導出するので、
 * `kind: 'path'` で足した設定は**自動的に**サニタイズ・出所記録・旧名フォールバックの対象になる。
 */
export const PATH_KEYS: readonly PathKey[] = Object.entries(CONFIG_SPEC)
  .filter(([, spec]) => spec.kind === 'path')
  .map(([key]) => key as PathKey);

/** パス系設定の出所。リポジトリ外を指すことを許すかの判断に使う */
export type PathSources = Record<PathKey, ConfigSource>;

/** すべてのパス系設定が既定値である状態の出所表 */
export function defaultPathSources(): PathSources {
  const sources = {} as PathSources;
  for (const key of PATH_KEYS) sources[key] = 'default';
  return sources;
}
