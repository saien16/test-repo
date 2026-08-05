/**
 * ① コンテキスト収集の出力モデル。
 * 後続の全ステージ（分析・キルチェーン）がこの型のみに依存する。
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface LanguageInfo {
  /** 'typescript' | 'javascript' | 'python' | 'go' | ... */
  name: string;
  fileCount: number;
  /** 全体に占める割合 0..1 */
  ratio: number;
}

export interface FrameworkInfo {
  name: string;
  /** 検出根拠（依存名・設定ファイルなど） */
  evidence: string;
  version?: string;
}

export interface Dependency {
  name: string;
  version: string;
  /** OSV.dev の ecosystem 名: 'npm' | 'PyPI' | 'Go' | 'crates.io' ... */
  ecosystem: string;
  /** 開発時のみの依存か */
  dev: boolean;
  /** 宣言元ファイル */
  manifest: string;
}

export interface SourceFile {
  /** リポジトリルートからの相対パス */
  path: string;
  language: string;
  sizeBytes: number;
  /** 内容の sha256（キャッシュキーに使う） */
  hash: string;
}

/** 関数・メソッド・クラスなどの構文単位 */
export interface SymbolInfo {
  name: string;
  kind: 'function' | 'method' | 'class' | 'module' | 'route' | 'unknown';
  file: string;
  startLine: number;
  endLine: number;
  /** 所属クラス・モジュール名 */
  container?: string;
  /** エクスポートされているか */
  exported: boolean;
}

export interface SymbolTable {
  symbols: SymbolInfo[];
  /** `${file}:${name}` → SymbolInfo の索引 */
  byId: Record<string, SymbolInfo>;
}

export interface CallEdge {
  /** 呼び出し元シンボルID `${file}:${name}` */
  from: string;
  /** 呼び出し先シンボルID（解決できなければ名前のみ） */
  to: string;
  file: string;
  line: number;
  /** 名前解決の確度 0..1（ヒューリスティック解析のため） */
  confidence: number;
}

export interface CallGraph {
  edges: CallEdge[];
  /** シンボルID → 呼び出し先ID一覧 */
  callees: Record<string, string[]>;
  /** シンボルID → 呼び出し元ID一覧 */
  callers: Record<string, string[]>;
}

/** 外部からの入口。攻撃者が到達しうる地点 */
export interface EntryPoint {
  kind: 'http-route' | 'cli' | 'message-handler' | 'main' | 'event-handler' | 'export';
  /** ルートパスやコマンド名など */
  identifier: string;
  file: string;
  line: number;
  /** 対応するシンボルID（判れば） */
  symbolId?: string;
  /** HTTP メソッドなど補足 */
  metadata?: Record<string, string>;
}

/** 信頼境界: 汚染源(source) と 危険な出力先(sink) */
export interface TrustBoundary {
  type: 'source' | 'sink';
  /** 'user-input' | 'sql' | 'command-exec' | 'file-path' | 'html-output' | 'network' | ... */
  category: string;
  /** マッチした式・API名 */
  expression: string;
  file: string;
  line: number;
  symbolId?: string;
}

/** README から引用した「この対象は何か」。要約はせず引用のみ */
export interface ReadmeInfo {
  /** リポジトリルートからの相対パス */
  path: string;
  /** 先頭の見出し。無ければ空文字 */
  title: string;
  /** 見出し直後の導入段落。無ければ空文字 */
  lead: string;
}

export interface GitContext {
  branch: string;
  headSha: string;
  /** 差分スキャン時: ベースとの間で変更されたファイル */
  changedFiles: string[];
  baseRef?: string;
}

export interface ScanContext {
  repoRoot: string;
  scannedAt: string;
  /** README から引用した対象の説明。無ければ null */
  readme: ReadmeInfo | null;
  languages: LanguageInfo[];
  frameworks: FrameworkInfo[];
  dependencies: Dependency[];
  files: SourceFile[];
  symbols: SymbolTable;
  callGraph: CallGraph;
  entryPoints: EntryPoint[];
  trustBoundaries: TrustBoundary[];
  git?: GitContext;
  /** 収集時に発生した非致命的な警告 */
  warnings: string[];
}
