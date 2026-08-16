/**
 * MITRE CWE カタログ（959件）へのアクセス層。
 *
 * データの出典は `src/vuln/data/cwe-catalog.json`。
 * これは OWASP/cwe-sdk-javascript（MITRE CWE 公式データ cwec_latest.xml の JSON 化）を
 * `scripts/build-cwe-catalog.mjs` で圧縮したもので、実行時にネットワークへ出ない。
 *
 * このモジュールが提供するもの:
 *   - CWE の素引き（{@link lookupCwe}）
 *   - 親を辿った上位概念への畳み込み（{@link cweAncestors} / {@link cweCategory}）
 *   - MITRE の Common_Consequences から CVSS の C/I/A を導く（{@link ciaFromCatalog}）
 *   - Likelihood_Of_Exploit の参照（{@link likelihoodOf}）
 *   - 言語・技術スタックからの逆引き（{@link cwesForPlatform}）
 *   - 分析レンズへの振り分け（{@link lensForCwe}）
 *
 * 事実と推測の区別について:
 *   `description` / `consequences` / `likelihood` / `parents` は MITRE 由来の「事実」。
 *   カテゴリ定義・レンズ振り分け・C/I/A への変換規則は本ツール側の「解釈」であり、
 *   この違いは各関数の戻り値・説明文で明示している。
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { LensId } from '../types/finding.js';

/* ------------------------------------------------------------------ *
 * 型定義
 * ------------------------------------------------------------------ */

/** Common_Consequences の1件（MITRE 由来） */
export interface CweConsequence {
  /** 影響範囲。'Confidentiality' | 'Integrity' | 'Availability' | 'Access Control' 等 */
  scope: string[];
  /** 具体的な影響。'Read Application Data' | 'Execute Unauthorized Code or Commands' 等 */
  impact: string[];
}

/** Potential_Mitigations の1件（MITRE 由来） */
export interface CweMitigation {
  /** 'Architecture and Design' | 'Implementation' 等の開発フェーズ */
  phase: string[];
  description: string;
}

/** consequences から機械的に導いた C/I/A の影響有無（生成スクリプトが付与） */
export interface CweCiaFlags {
  c: boolean;
  i: boolean;
  a: boolean;
}

/** カタログ1エントリ。フィールドは全て MITRE の CWE 辞書に由来する。 */
export interface CweEntry {
  /** 'CWE-89' 形式に正規化した ID（JSON 上は '89'） */
  id: string;
  /** 英語の正式名称 */
  name: string;
  /** 抽象度。Pillar > Class > Base > Variant の順に具体的になる */
  abstraction: 'Pillar' | 'Class' | 'Base' | 'Variant' | 'Compound' | string;
  structure: string;
  status: string;
  description: string;
  extendedDescription: string;
  /** 'High' | 'Medium' | 'Low' | 'Unknown' */
  likelihood: string;
  /** 該当する言語。'Not Language-Specific' を含みうる */
  languages: string[];
  /** 該当する技術。'Web Based' | 'Database Server' 等 */
  technologies: string[];
  consequences: CweConsequence[];
  cia: CweCiaFlags;
  mitigations: CweMitigation[];
  /** ChildOf 関係の親 CWE。'CWE-74' 形式に正規化済み */
  parents: string[];
  capec: string[];
  taxonomies: Record<string, string[]>;
  detectionMethods: string[];
}

/** CVSS の影響度メトリクス（C/I/A） */
export interface CweCiaMetrics {
  C: 'H' | 'L' | 'N';
  I: 'H' | 'L' | 'N';
  A: 'H' | 'L' | 'N';
}

/** 攻撃実現可能性（MITRE の Likelihood_Of_Exploit） */
export type CweLikelihood = 'High' | 'Medium' | 'Low' | 'Unknown';

/** CWE を人が扱える粒度に畳んだカテゴリ */
export interface CweCategory {
  /** カテゴリ識別子。例: 'injection' */
  id: string;
  /** 日本語の表示名 */
  name: string;
  /** 対応する OWASP Top 10 2021 カテゴリ（あれば） */
  owasp?: string;
}

/* ------------------------------------------------------------------ *
 * JSON の読み込みと索引化（プロセス内で1回だけ）
 * ------------------------------------------------------------------ */

/** JSON 上の生エントリ（id/parents が数値文字列のまま） */
interface RawCweEntry extends Omit<CweEntry, 'id' | 'parents'> {
  id: string;
  parents: string[];
}

interface RawCatalogFile {
  source?: string;
  sourceProject?: string;
  count?: number;
  entries: Record<string, RawCweEntry>;
}

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CATALOG_FILE = 'cwe-catalog.json';

/**
 * カタログ JSON の探索候補。
 *
 * `tsc` は JSON をコピーしないため、`dist/vuln/catalog.js` から見ると
 * `dist/vuln/data/` にファイルが存在しない。ビルド後も動くよう、
 * リポジトリの `src/vuln/data/` を上位ディレクトリから探しにいく。
 */
export function catalogCandidatePaths(moduleDir: string = MODULE_DIR): string[] {
  const candidates: string[] = [
    // 1. 同梱されている場合（src 実行時、および data を dist へコピーした場合）
    join(moduleDir, 'data', CATALOG_FILE),
    // 2. dist/vuln/catalog.js → <repo>/src/vuln/data/
    join(moduleDir, '..', '..', 'src', 'vuln', 'data', CATALOG_FILE),
  ];
  // 3. 念のため上位へ遡って探す（bundler 等でレイアウトが変わった場合の保険）
  let dir = moduleDir;
  for (let i = 0; i < 6; i++) {
    candidates.push(join(dir, 'src', 'vuln', 'data', CATALOG_FILE));
    candidates.push(join(dir, 'vuln', 'data', CATALOG_FILE));
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return candidates;
}

/**
 * カタログ JSON の実ファイルパスを解決する（見つからなければ null）。
 * `moduleDir` を渡すと、そのディレクトリに置かれた場合の解決結果を試せる
 * （ビルド後の dist レイアウトを検証する用途）。
 */
export function resolveCatalogPath(moduleDir: string = MODULE_DIR): string | null {
  for (const p of catalogCandidatePaths(moduleDir)) {
    if (existsSync(p)) return p;
  }
  return null;
}

/** 索引化済みカタログ。1.4MB の JSON を何度もパースしないよう1回だけ構築する。 */
interface CatalogIndex {
  byId: Map<string, CweEntry>;
  /** 出典（レポートでの引用用） */
  source: string;
  sourceProject: string;
  path: string;
}

let cached: CatalogIndex | null = null;
let loadError: string | null = null;

/**
 * カタログを読み込んで索引化する（プロセス内で1回だけ）。
 *
 * 読み込みに失敗しても例外は投げず、空のカタログを返す。
 * カタログは推定を補強する任意データであり、これが無いだけで
 * スキャン全体を落とすのは割に合わないため。
 * 失敗したことは {@link catalogLoadError} で取得でき、
 * 呼び出し側は警告としてレポートに載せられる。
 */
function loadCatalog(): CatalogIndex {
  if (cached) return cached;

  const path = resolveCatalogPath();
  if (path === null) {
    loadError =
      `CWEカタログ (${CATALOG_FILE}) が見つかりません。` +
      `探索したパス: ${catalogCandidatePaths().join(', ')}`;
    cached = { byId: new Map(), source: '（読み込み失敗）', sourceProject: '（読み込み失敗）', path: '' };
    return cached;
  }

  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as RawCatalogFile;
    const byId = new Map<string, CweEntry>();
    for (const raw of Object.values(parsed.entries ?? {})) {
      const entry: CweEntry = {
        ...raw,
        id: extractCweId(raw.id) ?? raw.id,
        parents: raw.parents.map((p) => extractCweId(p)).filter((p): p is string => p !== null),
      };
      byId.set(entry.id, entry);
    }
    cached = {
      byId,
      source: parsed.source ?? '（不明）',
      sourceProject: parsed.sourceProject ?? '（不明）',
      path,
    };
  } catch (e) {
    loadError = `CWEカタログ (${path}) の読み込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`;
    cached = { byId: new Map(), source: '（読み込み失敗）', sourceProject: '（読み込み失敗）', path };
  }
  return cached;
}

/** カタログの読み込みに失敗していればその理由を返す（正常なら null） */
export function catalogLoadError(): string | null {
  loadCatalog();
  return loadError;
}

/** カタログが利用可能か。false ならカタログ由来の推定は一切効かない。 */
export function catalogAvailable(): boolean {
  return loadCatalog().byId.size > 0;
}

/* ------------------------------------------------------------------ *
 * CWE ID の正規化（ここが唯一の定義）
 *
 * 以前は cvss.ts / heatmap/catalog-adapter.ts / knowledge.ts / catalog.ts /
 * killchain/attack-mapping.ts の5箇所に実装があり、しかも `normalizeCweId` と
 * いう**同名の export が2つ**（厳格版と寛容版）存在した。同じ入力が
 * モジュールをまたぐと結果が変わるため、「ヒートマップの列には載らないが
 * Finding には載る CWE」といった不整合の原因になっていた。
 *
 * 用途が2つあるのは事実なので、挙動の違いを名前で明示して両方置く:
 *   - {@link normalizeCweId} … 厳格。ID そのものだけを受け付ける
 *   - {@link extractCweId}   … 寛容。文章混じりの文字列からも数字を拾う
 *
 * どちらもゼロ埋めは落とす。MITRE のカタログ側の ID は 'CWE-89' であり
 * 'CWE-089' のまま引くと必ず外れるため。
 * ------------------------------------------------------------------ */

/** '089' → '89'。全部 0 のときは '0' を残す */
function stripLeadingZeros(digits: string): string {
  return digits.replace(/^0+(?=\d)/, '');
}

/**
 * CWE ID 表記を 'CWE-89' 形式へ**厳格に**正規化する。
 *
 * 受け付けるのは ID 単体のみ（'CWE-89' / 'cwe_89' / 'CWE 89' / '89'）。
 * 'CWE-89 の疑い' のような文章は null を返す。
 * カタログの列を作るなど「確実に ID であるもの」だけを通したい場面で使う。
 */
export function normalizeCweId(raw: string | number | undefined | null): string | null {
  if (raw === undefined || raw === null) return null;
  const m = /^(?:cwe[-_\s]?)?(\d+)$/i.exec(String(raw).trim());
  return m?.[1] === undefined ? null : `CWE-${stripLeadingZeros(m[1])}`;
}

/**
 * 文字列から CWE ID を**寛容に**取り出して 'CWE-89' 形式へ揃える。
 *
 * 最初に現れた数字の並びを ID とみなすため、'CWE-89 (SQLi)' や
 * 'see cwe89' のような表記からも拾える。LLM の出力や外部DBの
 * `database_specific` など、書式が保証されない入力に使う。
 */
export function extractCweId(raw: string | number | undefined | null): string | null {
  if (raw === undefined || raw === null) return null;
  const m = /(\d+)/.exec(String(raw));
  return m?.[1] === undefined ? null : `CWE-${stripLeadingZeros(m[1])}`;
}

/* ------------------------------------------------------------------ *
 * 基本的な参照 API
 * ------------------------------------------------------------------ */

/** CWE ID からカタログエントリを引く。'CWE-89' も '89' も受け付ける。 */
export function lookupCwe(cweId: string): CweEntry | null {
  const id = extractCweId(cweId);
  if (id === null) return null;
  return loadCatalog().byId.get(id) ?? null;
}

/** カタログに収録されている CWE の件数 */
export function catalogSize(): number {
  return loadCatalog().byId.size;
}

/** カタログの出典情報（レポートで引用元を示すため） */
export function catalogSource(): { source: string; sourceProject: string; path: string } {
  const c = loadCatalog();
  return { source: c.source, sourceProject: c.sourceProject, path: c.path };
}

/** カタログに収録されている全エントリ（呼び出し側で変更しないこと） */
export function allCwes(): CweEntry[] {
  return [...loadCatalog().byId.values()];
}

/**
 * 親（ChildOf）を辿って最上位（Pillar / Class）まで遡る。
 *
 * 幅優先で辿るので、返る配列は「自分に近い祖先ほど先頭」になる。
 * CWE の階層は木ではなく DAG（複数の親を持つ）ため、重複と循環を除去している。
 * 自分自身は含まない。
 */
export function cweAncestors(cweId: string): CweEntry[] {
  const start = lookupCwe(cweId);
  if (!start) return [];

  const catalog = loadCatalog();
  const seen = new Set<string>([start.id]);
  const out: CweEntry[] = [];
  let frontier: CweEntry[] = [start];

  // 深さ上限。CWE の階層は実際には5段程度だが、データ不整合での無限ループを防ぐ。
  for (let depth = 0; depth < 16 && frontier.length > 0; depth++) {
    const next: CweEntry[] = [];
    for (const node of frontier) {
      for (const parentId of node.parents) {
        if (seen.has(parentId)) continue;
        seen.add(parentId);
        const parent = catalog.byId.get(parentId);
        if (!parent) continue;
        out.push(parent);
        next.push(parent);
      }
    }
    frontier = next;
  }
  return out;
}

/** 自分自身 → 祖先の順に並べた探索チェーン */
function cweChain(cweId: string): CweEntry[] {
  const self = lookupCwe(cweId);
  if (!self) return [];
  return [self, ...cweAncestors(self.id)];
}

/* ------------------------------------------------------------------ *
 * カテゴリへの畳み込み
 * ------------------------------------------------------------------ */

/**
 * カテゴリの起点となる CWE。
 *
 * これは MITRE のデータではなく本ツールの「解釈」である。
 * 959件をそのまま人に見せても扱えないため、ヒートマップの列や
 * レポートの見出しに使える粒度（20件程度）へ畳む。
 * OWASP の対応は OWASP Top 10 2021 の公式 CWE マッピングに従う。
 */
const CATEGORY_ANCHORS: ReadonlyArray<readonly [string, CweCategory]> = [
  // --- 具体的なカテゴリ（先に判定されるよう、より深い CWE を並べる） ---
  ['CWE-79', { id: 'xss', name: 'クロスサイトスクリプティング', owasp: 'A03:2021-Injection' }],
  ['CWE-352', { id: 'csrf', name: 'クロスサイトリクエストフォージェリ', owasp: 'A01:2021-Broken Access Control' }],
  ['CWE-601', { id: 'open-redirect', name: 'オープンリダイレクト', owasp: 'A01:2021-Broken Access Control' }],
  ['CWE-611', { id: 'xxe', name: 'XML外部エンティティ参照', owasp: 'A05:2021-Security Misconfiguration' }],
  ['CWE-918', { id: 'ssrf', name: 'サーバサイドリクエストフォージェリ', owasp: 'A10:2021-Server-Side Request Forgery (SSRF)' }],
  ['CWE-502', { id: 'deserialization', name: '安全でない逆シリアル化', owasp: 'A08:2021-Software and Data Integrity Failures' }],
  ['CWE-22', { id: 'path-traversal', name: 'パストラバーサル', owasp: 'A01:2021-Broken Access Control' }],
  ['CWE-798', { id: 'secrets', name: '資格情報の管理', owasp: 'A07:2021-Identification and Authentication Failures' }],
  ['CWE-522', { id: 'secrets', name: '資格情報の管理', owasp: 'A07:2021-Identification and Authentication Failures' }],
  ['CWE-330', { id: 'randomness', name: '乱数・エントロピーの不足', owasp: 'A02:2021-Cryptographic Failures' }],
  ['CWE-327', { id: 'crypto', name: '暗号アルゴリズムの不備', owasp: 'A02:2021-Cryptographic Failures' }],
  ['CWE-326', { id: 'crypto', name: '暗号アルゴリズムの不備', owasp: 'A02:2021-Cryptographic Failures' }],
  ['CWE-311', { id: 'data-protection', name: '機密データの保護不足', owasp: 'A02:2021-Cryptographic Failures' }],
  ['CWE-319', { id: 'data-protection', name: '機密データの保護不足', owasp: 'A02:2021-Cryptographic Failures' }],
  ['CWE-347', { id: 'integrity', name: 'データ完全性の検証不足', owasp: 'A08:2021-Software and Data Integrity Failures' }],
  ['CWE-345', { id: 'integrity', name: 'データ完全性の検証不足', owasp: 'A08:2021-Software and Data Integrity Failures' }],
  ['CWE-1395', { id: 'vulnerable-components', name: '脆弱な依存コンポーネント', owasp: 'A06:2021-Vulnerable and Outdated Components' }],
  ['CWE-937', { id: 'vulnerable-components', name: '脆弱な依存コンポーネント', owasp: 'A06:2021-Vulnerable and Outdated Components' }],
  ['CWE-532', { id: 'logging', name: 'ログ・監視の不備', owasp: 'A09:2021-Security Logging and Monitoring Failures' }],
  ['CWE-778', { id: 'logging', name: 'ログ・監視の不備', owasp: 'A09:2021-Security Logging and Monitoring Failures' }],
  ['CWE-117', { id: 'logging', name: 'ログ・監視の不備', owasp: 'A09:2021-Security Logging and Monitoring Failures' }],
  ['CWE-16', { id: 'misconfiguration', name: '設定の不備', owasp: 'A05:2021-Security Misconfiguration' }],
  ['CWE-1004', { id: 'misconfiguration', name: '設定の不備', owasp: 'A05:2021-Security Misconfiguration' }],
  ['CWE-614', { id: 'misconfiguration', name: '設定の不備', owasp: 'A05:2021-Security Misconfiguration' }],
  ['CWE-116', { id: 'output-encoding', name: '出力エンコーディングの不備', owasp: 'A03:2021-Injection' }],
  ['CWE-200', { id: 'info-exposure', name: '情報の露出', owasp: 'A01:2021-Broken Access Control' }],
  ['CWE-287', { id: 'authentication', name: '認証の不備', owasp: 'A07:2021-Identification and Authentication Failures' }],
  ['CWE-400', { id: 'resource-exhaustion', name: 'リソース枯渇・サービス不能', owasp: 'A04:2021-Insecure Design' }],
  ['CWE-74', { id: 'injection', name: 'インジェクション', owasp: 'A03:2021-Injection' }],
  ['CWE-20', { id: 'input-validation', name: '入力検証の不備', owasp: 'A03:2021-Injection' }],

  // --- Pillar 相当の受け皿（上のどれにも当たらなかった場合） ---
  ['CWE-284', { id: 'access-control', name: 'アクセス制御・認可の不備', owasp: 'A01:2021-Broken Access Control' }],
  ['CWE-707', { id: 'injection', name: 'インジェクション', owasp: 'A03:2021-Injection' }],
  ['CWE-693', { id: 'protection-mechanism', name: '防御機構の不全' }],
  ['CWE-664', { id: 'resource-lifecycle', name: 'リソース管理の不備' }],
  ['CWE-682', { id: 'calculation', name: '不正な計算' }],
  ['CWE-691', { id: 'control-flow', name: '制御フロー管理の不備' }],
  ['CWE-697', { id: 'comparison', name: '不正な比較' }],
  ['CWE-703', { id: 'error-handling', name: '例外・異常系処理の不備' }],
  ['CWE-710', { id: 'coding-standards', name: 'コーディング規約からの逸脱' }],
  ['CWE-435', { id: 'interaction', name: '複数要素間の相互作用の不備' }],
];

const CATEGORY_BY_ANCHOR = new Map<string, CweCategory>(CATEGORY_ANCHORS);

/** どのアンカーにも当たらなかった場合のカテゴリ */
const CATEGORY_OTHER: CweCategory = { id: 'other', name: 'その他の弱点' };

/**
 * CWE を人が扱える粒度のカテゴリへ畳む。
 *
 * 自分自身 → 祖先の順にアンカー表と突き合わせ、最初に一致したものを返す。
 * カタログに無い CWE、およびどのアンカーにも辿り着かない CWE は
 * `{ id: 'other' }` になる（無理に分類しない）。
 */
export function cweCategory(cweId: string): CweCategory {
  for (const node of cweChain(cweId)) {
    const category = CATEGORY_BY_ANCHOR.get(node.id);
    if (category) return { ...category };
  }
  return { ...CATEGORY_OTHER };
}

/** 定義済みカテゴリの一覧（重複を除いた表示用） */
export function allCweCategories(): CweCategory[] {
  const seen = new Map<string, CweCategory>();
  for (const [, category] of CATEGORY_ANCHORS) {
    if (!seen.has(category.id)) seen.set(category.id, { ...category });
  }
  seen.set(CATEGORY_OTHER.id, { ...CATEGORY_OTHER });
  return [...seen.values()];
}

/* ------------------------------------------------------------------ *
 * consequences → CVSS の C/I/A
 * ------------------------------------------------------------------ */

/** 権限奪取・任意コード実行。当該スコープを完全に失わせる影響として扱う */
const TAKEOVER_IMPACTS = new Set([
  'Gain Privileges or Assume Identity',
  'Execute Unauthorized Code or Commands',
]);

/** 「完全な喪失」とみなす影響（CVSS の H に対応） */
const HIGH_CONFIDENTIALITY_IMPACTS = new Set([
  'Read Application Data',
  'Read Files or Directories',
  'Read Memory',
  ...TAKEOVER_IMPACTS,
]);
const HIGH_INTEGRITY_IMPACTS = new Set([
  'Modify Application Data',
  'Modify Files or Directories',
  'Modify Memory',
  'Alter Execution Logic',
  ...TAKEOVER_IMPACTS,
]);

const RANK: Record<'N' | 'L' | 'H', number> = { N: 0, L: 1, H: 2 };

function raise(current: 'N' | 'L' | 'H', to: 'N' | 'L' | 'H'): 'N' | 'L' | 'H' {
  return RANK[to] > RANK[current] ? to : current;
}

/**
 * カタログの consequences から CVSS の C/I/A メトリクスを導く。
 *
 * MITRE の Scope / Impact 語彙は CVSS のメトリクスと1対1ではないため、
 * 次の解釈規則で対応付ける（この規則自体は本ツールの推測）:
 *   - Confidentiality × 'Read *' / 権限奪取 → C:H、それ以外の Confidentiality → C:L
 *   - Integrity × 'Modify *' / 'Alter Execution Logic' / 権限奪取 → I:H、それ以外 → I:L
 *   - Availability × 'DoS: *' / 権限奪取 → A:H、それ以外 → A:L
 *   - Access Control / Authentication / Authorization は
 *     権限奪取なら C:H かつ I:H、そうでなければ C:L かつ I:L
 *   （権限奪取 = 'Gain Privileges or Assume Identity' /
 *     'Execute Unauthorized Code or Commands'。ただし MITRE が挙げたスコープの範囲に限る）
 *
 * consequences が無い、あるいは 'Other' など CVSS に写像できないスコープしか
 * 持たない CWE は null を返す。「推定できない」ことを呼び出し側が区別できるよう、
 * 既定値は返さない。
 */
export function ciaFromCatalog(cweId: string): CweCiaMetrics | null {
  const entry = lookupCwe(cweId);
  if (!entry || entry.consequences.length === 0) return null;

  let C: 'N' | 'L' | 'H' = 'N';
  let I: 'N' | 'L' | 'H' = 'N';
  let A: 'N' | 'L' | 'H' = 'N';

  for (const cons of entry.consequences) {
    const impacts = cons.impact;
    const hasTakeover = impacts.some((i) => TAKEOVER_IMPACTS.has(i));

    for (const scope of cons.scope) {
      switch (scope) {
        case 'Confidentiality':
          C = raise(C, impacts.some((i) => HIGH_CONFIDENTIALITY_IMPACTS.has(i)) ? 'H' : 'L');
          break;
        case 'Integrity':
          I = raise(I, impacts.some((i) => HIGH_INTEGRITY_IMPACTS.has(i)) ? 'H' : 'L');
          break;
        case 'Availability':
          A = raise(A, impacts.some((i) => i.startsWith('DoS') || TAKEOVER_IMPACTS.has(i)) ? 'H' : 'L');
          break;
        case 'Access Control':
        case 'Authentication':
        case 'Authorization': {
          // 認証・認可の破壊は機密性と完全性の双方に効く
          const level = hasTakeover ? 'H' : 'L';
          C = raise(C, level);
          I = raise(I, level);
          break;
        }
        default:
          // 'Other' / 'Non-Repudiation' / 'Accountability' は CVSS の基本評価に写像しない
          break;
      }
    }
  }

  if (C === 'N' && I === 'N' && A === 'N') return null;
  return { C, I, A };
}

/**
 * Likelihood_Of_Exploit を返す。
 * カタログ959件中、値が入っているのは185件だけなので Unknown が多数派になる。
 */
export function likelihoodOf(cweId: string): CweLikelihood {
  const entry = lookupCwe(cweId);
  if (!entry) return 'Unknown';
  switch (entry.likelihood) {
    case 'High':
      return 'High';
    case 'Medium':
      return 'Medium';
    case 'Low':
      return 'Low';
    default:
      return 'Unknown';
  }
}

/* ------------------------------------------------------------------ *
 * 言語・技術スタックからの逆引き
 * ------------------------------------------------------------------ */

/** 本ツール側の言語名 → MITRE の Applicable_Platforms 表記 */
const LANGUAGE_ALIASES: Record<string, string> = {
  js: 'JavaScript',
  javascript: 'JavaScript',
  typescript: 'JavaScript',
  ts: 'JavaScript',
  node: 'JavaScript',
  nodejs: 'JavaScript',
  'node.js': 'JavaScript',
  py: 'Python',
  python: 'Python',
  golang: 'Go',
  go: 'Go',
  'c#': 'C#',
  csharp: 'C#',
  dotnet: 'C#',
  '.net': 'C#',
  cpp: 'C++',
  'c++': 'C++',
  java: 'Java',
  php: 'PHP',
  ruby: 'Ruby',
  perl: 'Perl',
  rust: 'Rust',
  sql: 'SQL',
  xml: 'XML',
  assembly: 'Assembly',
  'asp.net': 'ASP.NET',
  aspnet: 'ASP.NET',
};

function canonicalLanguage(name: string): string {
  const key = name.trim().toLowerCase();
  return LANGUAGE_ALIASES[key] ?? name.trim();
}

export interface PlatformQuery {
  languages?: string[];
  technologies?: string[];
  /**
   * 'Not Language-Specific' / 'Not Technology-Specific' の CWE も含めるか（既定 false）。
   * ヒートマップの想定層で「この構成要素に起こりうる弱点」を広く採りたいときに true にする。
   */
  includeGeneric?: boolean;
}

/**
 * 言語・技術スタックに該当する CWE を引く。
 *
 * 指定が空なら空配列を返す（全件を返すと呼び出し側が事実と推測を混同しやすいため）。
 * 照合は Applicable_Platforms の完全一致（大文字小文字は無視）で行い、
 * 表記ゆれは {@link LANGUAGE_ALIASES} で吸収する。
 */
export function cwesForPlatform(opts: PlatformQuery): CweEntry[] {
  const languages = new Set(
    (opts.languages ?? []).map((l) => canonicalLanguage(l).toLowerCase()).filter(Boolean),
  );
  const technologies = new Set(
    (opts.technologies ?? []).map((t) => t.trim().toLowerCase()).filter(Boolean),
  );
  if (languages.size === 0 && technologies.size === 0) return [];

  const includeGeneric = opts.includeGeneric === true;
  const out: CweEntry[] = [];
  for (const entry of loadCatalog().byId.values()) {
    const langHit = entry.languages.some((l) => {
      const key = l.toLowerCase();
      if (key === 'not language-specific') return includeGeneric && languages.size > 0;
      return languages.has(key);
    });
    const techHit = entry.technologies.some((t) => {
      const key = t.toLowerCase();
      if (key === 'not technology-specific') return includeGeneric && technologies.size > 0;
      return technologies.has(key);
    });
    if (langHit || techHit) out.push(entry);
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * 分析レンズへの振り分け
 * ------------------------------------------------------------------ */

/**
 * レンズの担当範囲を表すアンカー CWE。
 *
 * ここも MITRE のデータではなく本ツールの解釈で、
 * 各レンズの system プロンプト（`src/analyzer/lenses/*.ts`）が明示している
 * CWE を起点に、その上位概念を足したもの。
 *
 * 自分自身 → 祖先の順に突き合わせるので、
 * 具体的な CWE を自分自身の位置で当てたほうが上位概念より優先される。
 * 例: CWE-798（ハードコード資格情報）は祖先に CWE-287/CWE-284 を持つが、
 *     自分自身が crypto-secrets のアンカーなので authz には落ちない。
 */
const LENS_ANCHORS: ReadonlyArray<readonly [string, LensId]> = [
  // --- injection: 下流インタプリタへの注入とファイルパス操作 ---
  ['CWE-89', 'injection'],
  ['CWE-943', 'injection'],
  ['CWE-78', 'injection'],
  ['CWE-77', 'injection'],
  ['CWE-88', 'injection'],
  ['CWE-94', 'injection'],
  ['CWE-95', 'injection'],
  ['CWE-917', 'injection'],
  ['CWE-1336', 'injection'],
  ['CWE-90', 'injection'],
  ['CWE-91', 'injection'],
  ['CWE-643', 'injection'],
  ['CWE-22', 'injection'],
  ['CWE-98', 'injection'],
  ['CWE-74', 'injection'],
  ['CWE-20', 'injection'],
  ['CWE-707', 'injection'],

  // --- web-output: ブラウザへ出す文脈のエスケープとレスポンス属性 ---
  ['CWE-79', 'web-output'],
  ['CWE-80', 'web-output'],
  ['CWE-113', 'web-output'],
  ['CWE-93', 'web-output'],
  ['CWE-116', 'web-output'],
  ['CWE-352', 'web-output'],
  ['CWE-1021', 'web-output'],
  ['CWE-1004', 'web-output'],
  ['CWE-614', 'web-output'],
  ['CWE-1275', 'web-output'],
  ['CWE-942', 'web-output'],

  // --- deserialization-ssrf: 別スフィアの資源を引き込む欠陥 ---
  ['CWE-502', 'deserialization-ssrf'],
  ['CWE-1321', 'deserialization-ssrf'],
  ['CWE-915', 'deserialization-ssrf'],
  ['CWE-918', 'deserialization-ssrf'],
  ['CWE-611', 'deserialization-ssrf'],
  ['CWE-776', 'deserialization-ssrf'],
  ['CWE-601', 'deserialization-ssrf'],
  ['CWE-829', 'deserialization-ssrf'],
  ['CWE-494', 'deserialization-ssrf'],
  ['CWE-434', 'deserialization-ssrf'],
  ['CWE-610', 'deserialization-ssrf'],
  ['CWE-913', 'deserialization-ssrf'],

  // --- crypto-secrets: 秘密情報の保管・暗号・乱数 ---
  ['CWE-798', 'crypto-secrets'],
  ['CWE-259', 'crypto-secrets'],
  ['CWE-321', 'crypto-secrets'],
  ['CWE-256', 'crypto-secrets'],
  ['CWE-257', 'crypto-secrets'],
  ['CWE-522', 'crypto-secrets'],
  ['CWE-916', 'crypto-secrets'],
  ['CWE-1391', 'crypto-secrets'],
  ['CWE-327', 'crypto-secrets'],
  ['CWE-326', 'crypto-secrets'],
  ['CWE-328', 'crypto-secrets'],
  ['CWE-347', 'crypto-secrets'],
  ['CWE-295', 'crypto-secrets'],
  ['CWE-330', 'crypto-secrets'],
  ['CWE-311', 'crypto-secrets'],
  ['CWE-312', 'crypto-secrets'],
  ['CWE-319', 'crypto-secrets'],
  ['CWE-320', 'crypto-secrets'],
  ['CWE-1240', 'crypto-secrets'],

  // --- authz: アクセス制御・認証・権限 ---
  ['CWE-306', 'authz'],
  ['CWE-862', 'authz'],
  ['CWE-863', 'authz'],
  ['CWE-639', 'authz'],
  ['CWE-269', 'authz'],
  ['CWE-732', 'authz'],
  ['CWE-285', 'authz'],
  ['CWE-287', 'authz'],
  ['CWE-384', 'authz'],
  ['CWE-613', 'authz'],
  ['CWE-200', 'authz'],
  ['CWE-668', 'authz'],
  ['CWE-284', 'authz'],
];

const LENS_BY_ANCHOR = new Map<string, LensId>(LENS_ANCHORS);

/**
 * CWE をどの分析レンズが担当するかを判定する。
 *
 * 自分自身 → 祖先の順にアンカーと突き合わせ、最初に一致したレンズを返す。
 * どのレンズの担当でもない CWE は正直に null を返す。
 * null が多いこと自体が「このスキャナの死角」を意味しており、
 * ヒートマップの死角検出（likelyCause='no-matching-lens'）で使う。
 *
 * なお 'dependency' レンズは依存パッケージの照合専用でソースコードを見ないため、
 * ここでは返さない。
 */
export function lensForCwe(cweId: string): LensId | null {
  for (const node of cweChain(cweId)) {
    const lens = LENS_BY_ANCHOR.get(node.id);
    if (lens) return lens;
  }
  return null;
}

/**
 * レンズ振り分けのカバレッジを集計する（レポートの「死角」節で使う）。
 * 事実（カタログ件数）と解釈（振り分け結果）を並べて出せるようにしている。
 */
export function lensCoverage(): {
  total: number;
  assigned: number;
  unassigned: number;
  byLens: Record<string, number>;
} {
  const byLens: Record<string, number> = {};
  let assigned = 0;
  for (const entry of loadCatalog().byId.values()) {
    const lens = lensForCwe(entry.id);
    if (lens === null) continue;
    assigned++;
    byLens[lens] = (byLens[lens] ?? 0) + 1;
  }
  const total = loadCatalog().byId.size;
  return { total, assigned, unassigned: total - assigned, byLens };
}
