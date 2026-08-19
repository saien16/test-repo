/**
 * CISA KEV（Known Exploited Vulnerabilities）照合。
 *
 * KEV は「実際に悪用が確認された」脆弱性の一覧で、**CVE 単位**で管理されている。
 * ここに本ツールの構造的な制約がある:
 *
 *   ③依存由来の Finding … CVE を持つ → 直接照合できる。これは**事実**
 *   ②ソース由来の Finding … CVE を持たない。あなたのコード固有の欠陥であり、
 *                            誰も報告していないのだから CVE は存在しえない
 *                            → 直接照合は**原理的に不可能**
 *
 * したがって、ソース由来の検出に「KEV に載っていないので安全」と書くのは誤りである。
 * 代わりに「同じ CWE クラスが KEV に何件収載されているか」を添える。
 * これはその検出についての事実ではなく、**その弱点クラスが現実に悪用されているか**の
 * 傍証にすぎないので、型の上でも表示の上でも事実と混ぜない。
 *
 * ネットワークが使えない環境でも壊れないこと（オフライン耐性）を最優先とし、
 * 失敗はすべて errors に積んで処理を継続する。OSV 照合と同じ方針。
 */

import { readFile } from 'node:fs/promises';
import type { Finding } from '../types/finding.js';
import { normalizeCweId } from './catalog.js';

/** CISA が公開している KEV カタログの JSON */
const KEV_FEED_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** 1リクエストのタイムアウト(ms) */
const DEFAULT_TIMEOUT_MS = 30_000;

/** CWE クラスの参考例として載せる件数 */
const MAX_EXAMPLES = 3;

/** fetch 互換関数（テストでの差し替え用） */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** KEV の1エントリ（必要なフィールドのみ） */
export interface KevEntry {
  cveId: string;
  vendorProject: string;
  product: string;
  name: string;
  /** KEV へ収載された日 (YYYY-MM-DD) */
  dateAdded: string;
  /** 米国政府機関の対応期限 (YYYY-MM-DD) */
  dueDate: string;
  /** ランサムウェアキャンペーンでの使用が確認されているか */
  ransomware: boolean;
  /** KEV 側が付与している CWE。2024年以降のスキーマにのみ存在し、無ければ空 */
  cwes: string[];
}

export interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  total: number;
  /** CVE ID（大文字）→ エントリ */
  byCve: ReadonlyMap<string, KevEntry>;
  /** 正規化済み CWE ID → KEV 収載件数 */
  cweCounts: ReadonlyMap<string, number>;
  /** 正規化済み CWE ID → 代表例の CVE ID（最大3件、収載日の新しい順） */
  cweExamples: ReadonlyMap<string, string[]>;
}

/**
 * 1つの Finding に付ける KEV 照合結果。
 *
 * `listed` だけが事実で、`cweClassCount` 以下は参考値である。
 * この区別はレポートの表示にもそのまま持ち込むこと。
 */
export interface KevAnnotation {
  /** この Finding 自身が KEV 収載か（CVE を持つ Finding でのみ true になりうる） */
  listed: boolean;
  /** 収載されている場合の詳細 */
  entry?: KevEntry;
  /** 同じ CWE クラスの KEV 収載件数。**この検出についての事実ではない** */
  cweClassCount: number;
  /** 参考例の CVE ID */
  cweExamples: string[];
}

/* ------------------------------------------------------------------ *
 * 解析（純粋関数。ネットワーク・ファイルI/Oを伴わないので単体で試験できる）
 * ------------------------------------------------------------------ */

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/** KEV の生 JSON を索引付きカタログへ変換する */
export function parseKevCatalog(raw: unknown): KevCatalog {
  const root = (raw ?? {}) as Record<string, unknown>;
  const list = Array.isArray(root.vulnerabilities) ? root.vulnerabilities : [];

  const byCve = new Map<string, KevEntry>();
  const cweCounts = new Map<string, number>();
  const cweExamples = new Map<string, string[]>();

  for (const item of list) {
    const v = (item ?? {}) as Record<string, unknown>;
    const cveId = asString(v.cveID).trim().toUpperCase();
    if (cveId === '') continue;

    const cwes: string[] = [];
    if (Array.isArray(v.cwes)) {
      for (const c of v.cwes) {
        const id = normalizeCweId(typeof c === 'string' || typeof c === 'number' ? c : null);
        if (id !== null && !cwes.includes(id)) cwes.push(id);
      }
    }

    const entry: KevEntry = {
      cveId,
      vendorProject: asString(v.vendorProject),
      product: asString(v.product),
      name: asString(v.vulnerabilityName),
      dateAdded: asString(v.dateAdded),
      dueDate: asString(v.dueDate),
      // KEV は 'Known' / 'Unknown' の2値。'Known' だけを真とする
      ransomware: asString(v.knownRansomwareCampaignUse).toLowerCase() === 'known',
      cwes,
    };
    // 同じ CVE が重複していたら先勝ち（KEV 側で重複は無い想定だが壊れないように）
    if (byCve.has(cveId)) continue;
    byCve.set(cveId, entry);

    for (const cwe of cwes) {
      cweCounts.set(cwe, (cweCounts.get(cwe) ?? 0) + 1);
      const ex = cweExamples.get(cwe) ?? [];
      ex.push(cveId);
      cweExamples.set(cwe, ex);
    }
  }

  // 参考例は収載日の新しい順に並べてから切る（古い事例より最近の事例のほうが参考になる）
  for (const [cwe, ids] of cweExamples) {
    ids.sort((a, b) => (byCve.get(b)?.dateAdded ?? '').localeCompare(byCve.get(a)?.dateAdded ?? ''));
    cweExamples.set(cwe, ids.slice(0, MAX_EXAMPLES));
  }

  return {
    catalogVersion: asString(root.catalogVersion),
    dateReleased: asString(root.dateReleased),
    total: byCve.size,
    byCve,
    cweCounts,
    cweExamples,
  };
}

/* ------------------------------------------------------------------ *
 * 取得
 * ------------------------------------------------------------------ */

export interface KevOptions {
  /**
   * ローカルの KEV JSON。指定されていればネットワークを使わない。
   * 多数のリポジトリを続けて走査する場合は、1度落としてこれを指すのが確実。
   */
  catalogPath?: string;
  /** 既定は globalThis.fetch */
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** 取得元 URL の上書き（社内ミラー用） */
  url?: string;
  /**
   * `catalogPath` が読めなかったときに取得へ進むか。
   *
   * 既定パスを見に行っただけなら真（ファイルが無いのは正常）。
   * オペレータが --kev-file で明示した場合は偽にする。
   * 指定したファイルが読めないのに黙って別経路へ流れるほうが危険なため。
   */
  fallbackToFetch?: boolean;
}

export interface LoadKevResult {
  /** 取得できなかった場合は null。照合を諦めるだけで、走査は続行する */
  catalog: KevCatalog | null;
  errors: string[];
}

/**
 * KEV カタログを読み込む。
 * ファイル指定があればそれを、無ければ CISA から取得する。
 * どちらも失敗した場合は null を返し、理由を errors に積む。
 */
export async function loadKevCatalog(options: KevOptions = {}): Promise<LoadKevResult> {
  const errors: string[] = [];

  if (options.catalogPath !== undefined && options.catalogPath !== '') {
    try {
      const text = await readFile(options.catalogPath, 'utf8');
      return { catalog: parseKevCatalog(JSON.parse(text)), errors };
    } catch (e) {
      if (options.fallbackToFetch !== true) {
        // 明示指定されて読めないのは利用者の意図と食い違うので、黙って取得へ流さない
        errors.push(`KEV カタログを読み込めませんでした: ${describe(e)}`);
        return { catalog: null, errors };
      }
      // 既定パスに置かれていないだけ。正常なので警告も出さずに取得へ進む
    }
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    errors.push('KEV カタログの取得に失敗しました: fetch が利用できません');
    return { catalog: null, errors };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetchImpl(options.url ?? KEV_FEED_URL, { signal: controller.signal });
    if (!res.ok) {
      errors.push(`KEV カタログの取得に失敗しました (HTTP ${res.status})`);
      return { catalog: null, errors };
    }
    return { catalog: parseKevCatalog(await res.json()), errors };
  } catch (e) {
    errors.push(`KEV カタログの取得に失敗しました: ${describe(e)}`);
    return { catalog: null, errors };
  } finally {
    clearTimeout(timer);
  }
}

function describe(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/* ------------------------------------------------------------------ *
 * 照合
 * ------------------------------------------------------------------ */

/** 1件ぶんの照合。純粋関数 */
export function matchKev(finding: Finding, catalog: KevCatalog): KevAnnotation {
  const cve = finding.cve?.trim().toUpperCase();
  const entry = cve !== undefined && cve !== '' ? catalog.byCve.get(cve) : undefined;

  const cwe = normalizeCweId(finding.cwe);
  const cweClassCount = cwe === null ? 0 : (catalog.cweCounts.get(cwe) ?? 0);
  const cweExamples = cwe === null ? [] : (catalog.cweExamples.get(cwe) ?? []);

  const annotation: KevAnnotation = {
    listed: entry !== undefined,
    cweClassCount,
    cweExamples: [...cweExamples],
  };
  if (entry !== undefined) annotation.entry = entry;
  return annotation;
}

/**
 * Finding 群へ KEV 照合結果を付ける。
 * 元の配列は変更せず、新しい配列を返す。
 */
export function annotateWithKev(findings: readonly Finding[], catalog: KevCatalog): Finding[] {
  return findings.map((f) => ({ ...f, kev: matchKev(f, catalog) }));
}

/** レポートの見出し用。KEV 収載の件数を数える */
export function countKevListed(findings: readonly Finding[]): number {
  return findings.filter((f) => f.kev?.listed === true).length;
}
