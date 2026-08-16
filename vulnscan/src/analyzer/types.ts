/**
 * ② ソースコード分析の内部データモデル。
 *
 * ここで定義するのは analyzer 内部だけで使う型で、外部に公開する契約は
 * `src/types/` 側（ScanContext / RawFinding / VulnScanConfig）のみ。
 */

import type { SourceFile, SymbolInfo } from '../types/context.js';

/** 1始まり・両端を含む行範囲 */
export interface LineRange {
  startLine: number;
  endLine: number;
}

/** チャンクの種別 */
export type ChunkKind =
  /** 関数・メソッド・クラスなどの構文単位まるごと */
  | 'symbol'
  /** 巨大な構文単位を行ウィンドウで分割したもの */
  | 'symbol-part'
  /** どのシンボルにも属さない部分（import・モジュールスコープの定数など） */
  | 'module'
  /** シンボル情報が無いファイルのフォールバック（ファイル全体） */
  | 'file'
  /** 上記が大きすぎて分割されたもの */
  | 'file-part';

/** LLM に渡す解析単位 */
export interface Chunk {
  /** `path#label@start-end` 形式の安定した識別子。キャッシュキーに使う */
  id: string;
  file: string;
  language: string;
  /** ファイル内容の sha256（ScanContext 由来）。キャッシュキーに使う */
  fileHash: string;
  kind: ChunkKind;
  /** 表示用の名前（シンボル名など） */
  label: string;
  /** segments 全体の外接範囲 */
  startLine: number;
  endLine: number;
  /** 実際に含めた行範囲。module チャンクは非連続になりうる */
  segments: LineRange[];
  /** 行番号付きに整形したコード */
  code: string;
  /** このチャンクに含まれるシンボル */
  symbols: SymbolInfo[];
  /** 分割された場合の位置 */
  part?: { index: number; total: number };
}

/** チャンク分割のサイズ上限 */
export interface ChunkLimits {
  /** 1チャンクの最大行数 */
  maxLines: number;
  /** 1チャンクの最大文字数 */
  maxChars: number;
  /** 分割時に前チャンクと重ねる行数（文脈の途切れを防ぐ） */
  overlapLines: number;
}

/**
 * 既定値。Opus 5 の 1M コンテキストからすれば小さいが、
 * チャンクは「1つの脆弱性判断に必要な範囲」であるほど精度が出るため
 * 意図的に絞っている。
 */
export const DEFAULT_CHUNK_LIMITS: ChunkLimits = {
  maxLines: 320,
  maxChars: 12_000,
  overlapLines: 12,
};

export interface ChunkFileInput {
  file: SourceFile;
  /** ファイルの生内容 */
  content: string;
  /** このファイルに属するシンボル */
  symbols: SymbolInfo[];
}

/** 呼び出し元／呼び出し先として添付する関連シンボル */
export interface RelatedSymbol {
  /** `${file}:${name}` */
  id: string;
  direction: 'caller' | 'callee';
  /** 表示用シグネチャ */
  signature: string;
  /** 呼び出しが書かれている位置 */
  via?: { file: string; line: number };
  /** 名前解決できたか（ヒューリスティック解析なので未解決がありうる） */
  resolved: boolean;
}
