/**
 * CWEカタログへの唯一の接続点（差し替え用アダプタ）。
 *
 * 本来は `src/vuln/catalog.ts` の `cweCategory()` / `cwesForPlatform()` /
 * `lensForCwe()` を使う想定だが、本ファイル作成時点では当該モジュールが
 * まだ存在しない（別エージェントが実装中）。
 *
 * そのため、同等の暫定実装をここに1箇所だけ隔離して置く。
 * `src/vuln/catalog.ts` が入ったら、**このファイルの中身だけ**を
 * 下記のような再エクスポートへ差し替えれば、他のヒートマップ実装は
 * 一切変更せずに済む:
 *
 *   export { cweCategory, cwesForPlatform, lensForCwe } from '../vuln/catalog.js';
 *
 * ヒートマップ本体（observed.ts / inferred.ts / blindspots.ts / index.ts）は
 * カタログの実体を直接 import してはならない。必ずこのアダプタ経由で参照する。
 *
 * 数値の出所について:
 *   likelihood / cia / languages / technologies は MITRE CWE 公式データ
 *   （`src/vuln/data/cwe-catalog.json`、`scripts/build-cwe-catalog.mjs` が生成）
 *   の対応フィールドをそのまま書き写している。手心を加えた推定値ではない。
 *   1.4MB の JSON を実行時に読むと純粋性・起動コストの面で不利なため、
 *   ヒートマップが使う範囲だけを静的テーブルとして持つ。
 */

import type { LensId } from '../types/finding.js';
import type { WeaknessCategory } from '../types/heatmap.js';

/** CWEの悪用可能性。MITRE の Likelihood_Of_Exploit をそのまま使う */
export type CweLikelihood = 'High' | 'Medium' | 'Low' | 'Unknown';

/** CIA（機密性・完全性・可用性）への影響有無 */
export interface CweCia {
  c: boolean;
  i: boolean;
  a: boolean;
}

/** 想定層の算出に必要な、CWE1件分の事実 */
export interface CweFacts {
  /** 'CWE-89' 形式 */
  id: string;
  likelihood: CweLikelihood;
  cia: CweCia;
  /** 適用言語。空配列は「言語非依存」を意味する */
  languages: string[];
  /** 適用技術。空配列は「技術非依存」を意味する */
  technologies: string[];
}

/** 構成要素の技術スタック。`cwesForPlatform()` の入力 */
export interface PlatformQuery {
  languages: string[];
  technologies: string[];
}

/** カタログ上「何にでも当てはまる」ことを示す予約語 */
const ANY_LANGUAGE = 'Not Language-Specific';
const ANY_TECHNOLOGY = 'Not Technology-Specific';

/** CweFacts を短く書くための補助。cia は 'cia' / 'ci' / 'i' のような文字列で指定する */
function f(
  id: string,
  likelihood: CweLikelihood,
  cia: string,
  languages: string[] = [],
  technologies: string[] = [],
): CweFacts {
  return {
    id,
    likelihood,
    cia: { c: cia.includes('c'), i: cia.includes('i'), a: cia.includes('a') },
    languages,
    technologies,
  };
}

/**
 * CWE ID → 事実。
 * ヒートマップの列（カテゴリ）を構成するのに十分な範囲を収録している。
 */
const CWE_FACTS: Record<string, CweFacts> = Object.fromEntries(
  [
    // --- インジェクション ---
    f('CWE-20', 'High', 'cia'),
    f('CWE-74', 'High', 'ci'),
    f('CWE-77', 'High', 'cia'),
    f('CWE-78', 'High', 'cia'),
    f('CWE-88', 'Unknown', 'cia', [ANY_LANGUAGE, 'PHP']),
    f('CWE-89', 'High', 'ci', [ANY_LANGUAGE], ['Database Server']),
    f('CWE-90', 'Unknown', 'cia', [ANY_LANGUAGE], ['Database Server']),
    f('CWE-91', 'Unknown', 'cia'),
    f('CWE-94', 'Medium', 'cia', ['Interpreted']),
    f('CWE-95', 'Medium', 'cia', ['Java', 'JavaScript', 'Python', 'Perl', 'PHP', 'Ruby', 'Interpreted']),
    f('CWE-643', 'High', 'ci'),
    f('CWE-917', 'Unknown', 'ci', ['Java']),
    f('CWE-943', 'Unknown', 'cia'),

    // --- Web出力（XSS 等） ---
    f('CWE-79', 'High', 'cia', [ANY_LANGUAGE], ['Web Based']),
    f('CWE-80', 'High', 'cia'),
    f('CWE-113', 'Unknown', 'ci', [ANY_LANGUAGE], ['Web Based']),
    f('CWE-116', 'High', 'cia', [ANY_LANGUAGE], ['Database Server', 'Web Server']),
    f('CWE-1021', 'Unknown', 'ci', [], ['Web Based']),

    // --- アクセス制御 ---
    f('CWE-22', 'High', 'cia'),
    f('CWE-23', 'Unknown', 'cia'),
    f('CWE-200', 'High', 'c', [ANY_LANGUAGE], ['Mobile']),
    f('CWE-269', 'Medium', 'ci'),
    f('CWE-284', 'Unknown', '', [], [ANY_TECHNOLOGY, 'ICS/OT']),
    f('CWE-285', 'High', 'ci', [ANY_LANGUAGE], ['Web Server', 'Database Server']),
    f('CWE-352', 'Medium', 'cia', [ANY_LANGUAGE], ['Web Server']),
    f('CWE-359', 'Unknown', 'c', [ANY_LANGUAGE], ['Mobile']),
    f('CWE-601', 'Low', 'ci', [ANY_LANGUAGE], ['Web Based']),
    f('CWE-639', 'High', 'ci'),
    f('CWE-732', 'High', 'ci', [ANY_LANGUAGE], [ANY_TECHNOLOGY, 'Cloud Computing']),
    f('CWE-862', 'High', 'ci', [ANY_LANGUAGE], ['Web Server', 'Database Server']),
    f('CWE-863', 'High', 'ci', [ANY_LANGUAGE], ['Web Server', 'Database Server']),

    // --- 認証 ---
    f('CWE-287', 'High', 'cia'),
    f('CWE-295', 'Unknown', 'ci', [ANY_LANGUAGE], ['Mobile']),
    f('CWE-306', 'High', 'ci', [ANY_LANGUAGE], ['Cloud Computing', 'ICS/OT']),
    f('CWE-307', 'Unknown', 'ci'),
    f('CWE-384', 'Unknown', 'ci'),
    f('CWE-521', 'Unknown', 'ci', [ANY_LANGUAGE], [ANY_TECHNOLOGY]),
    f('CWE-613', 'Unknown', 'ci'),

    // --- 暗号 ---
    f('CWE-311', 'High', 'ci'),
    f('CWE-319', 'High', 'ci', [ANY_LANGUAGE], ['Cloud Computing', 'Mobile', 'ICS/OT']),
    f('CWE-326', 'Unknown', 'ci'),
    f('CWE-327', 'High', 'ci', [ANY_LANGUAGE], [ANY_TECHNOLOGY, 'ICS/OT']),
    f('CWE-328', 'Unknown', 'ci'),
    f('CWE-330', 'High', 'ci', [ANY_LANGUAGE], [ANY_TECHNOLOGY]),
    f('CWE-331', 'Unknown', 'ci'),
    f('CWE-338', 'Medium', 'ci'),

    // --- 秘密情報 ---
    f('CWE-259', 'High', 'ci', [ANY_LANGUAGE], ['ICS/OT']),
    f('CWE-522', 'Unknown', 'ci', [ANY_LANGUAGE], ['ICS/OT']),
    f('CWE-532', 'Medium', 'c'),
    f('CWE-798', 'High', 'cia', [ANY_LANGUAGE], ['Mobile', 'ICS/OT']),

    // --- 逆シリアル化・完全性 ---
    f('CWE-345', 'Unknown', 'i', [ANY_LANGUAGE], ['ICS/OT']),
    f('CWE-347', 'Unknown', 'ci'),
    f('CWE-494', 'Medium', 'cia'),
    f('CWE-502', 'Medium', 'ia', ['Java', 'Ruby', 'PHP', 'Python', 'JavaScript'], ['ICS/OT']),
    f('CWE-829', 'Unknown', 'cia'),
    f('CWE-915', 'Unknown', 'i', ['Ruby', 'ASP.NET', 'PHP', 'Python', ANY_LANGUAGE]),

    // --- SSRF / XXE ---
    f('CWE-611', 'Unknown', 'cia', ['XML'], ['Web Based']),
    f('CWE-918', 'Unknown', 'ci', [ANY_LANGUAGE], ['Web Server']),

    // --- 依存コンポーネント ---
    // CWE-937 は MITRE 辞書上「カテゴリ」であり Weakness エントリを持たないため
    // likelihood は Unknown。cia は CWE_KB の説明に沿って全影響ありとする。
    f('CWE-937', 'Unknown', 'cia', [ANY_LANGUAGE], [ANY_TECHNOLOGY]),
    f('CWE-1395', 'Unknown', 'cia', [ANY_LANGUAGE], [ANY_TECHNOLOGY]),

    // --- 設定不備 ---
    // CWE-16 も同じくカテゴリ扱いのエントリ。
    f('CWE-16', 'Unknown', 'ci', [ANY_LANGUAGE], [ANY_TECHNOLOGY]),
    f('CWE-614', 'Unknown', 'c', [], ['Web Based']),
    f('CWE-1004', 'Medium', 'ci', [ANY_LANGUAGE], ['Web Based']),

    // --- ログ・監視 ---
    f('CWE-117', 'Medium', 'cia'),
    f('CWE-778', 'Medium', '', [ANY_LANGUAGE], ['Cloud Computing']),

    // --- 設計上の欠陥 ---
    f('CWE-209', 'High', 'c', ['PHP', 'Java', ANY_LANGUAGE]),
    f('CWE-400', 'High', 'cia'),
    f('CWE-434', 'Medium', 'cia', ['ASP.NET', 'PHP', ANY_LANGUAGE], ['Web Server']),
    f('CWE-1333', 'High', 'a'),
  ].map((entry) => [entry.id, entry]),
);

/** カテゴリ定義。CWEを人が扱える12粒度へ畳む。1つのCWEは1カテゴリにのみ属する */
interface CategoryDefinition extends WeaknessCategory {
  /** このカテゴリを担当する分析レンズ。null なら担当レンズが存在しない */
  lens: LensId | null;
}

const CATEGORY_DEFINITIONS: readonly CategoryDefinition[] = [
  {
    id: 'injection',
    name: 'インジェクション',
    owasp: 'A03:2021-Injection',
    lens: 'injection',
    cweIds: [
      'CWE-20', 'CWE-74', 'CWE-77', 'CWE-78', 'CWE-88', 'CWE-89', 'CWE-90',
      'CWE-91', 'CWE-94', 'CWE-95', 'CWE-643', 'CWE-917', 'CWE-943',
    ],
  },
  {
    id: 'web-output',
    name: 'Web出力の無害化不備 (XSS等)',
    owasp: 'A03:2021-Injection',
    lens: 'web-output',
    cweIds: ['CWE-79', 'CWE-80', 'CWE-113', 'CWE-116', 'CWE-1021'],
  },
  {
    id: 'access-control',
    name: 'アクセス制御の不備',
    owasp: 'A01:2021-Broken Access Control',
    lens: 'authz',
    cweIds: [
      'CWE-22', 'CWE-23', 'CWE-200', 'CWE-269', 'CWE-284', 'CWE-285',
      'CWE-352', 'CWE-359', 'CWE-601', 'CWE-639', 'CWE-732', 'CWE-862', 'CWE-863',
    ],
  },
  {
    id: 'authentication',
    name: '認証の不備',
    owasp: 'A07:2021-Identification and Authentication Failures',
    lens: 'authz',
    cweIds: ['CWE-287', 'CWE-295', 'CWE-306', 'CWE-307', 'CWE-384', 'CWE-521', 'CWE-613'],
  },
  {
    id: 'cryptography',
    name: '暗号の不備',
    owasp: 'A02:2021-Cryptographic Failures',
    lens: 'crypto-secrets',
    cweIds: [
      'CWE-311', 'CWE-319', 'CWE-326', 'CWE-327', 'CWE-328',
      'CWE-330', 'CWE-331', 'CWE-338',
    ],
  },
  {
    id: 'secrets',
    name: '秘密情報の管理不備',
    owasp: 'A07:2021-Identification and Authentication Failures',
    lens: 'crypto-secrets',
    cweIds: ['CWE-259', 'CWE-522', 'CWE-532', 'CWE-798'],
  },
  {
    id: 'deserialization',
    name: '逆シリアル化・データ完全性',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    lens: 'deserialization-ssrf',
    cweIds: ['CWE-345', 'CWE-347', 'CWE-494', 'CWE-502', 'CWE-829', 'CWE-915'],
  },
  {
    id: 'ssrf',
    name: 'SSRF・外部エンティティ参照',
    owasp: 'A10:2021-Server-Side Request Forgery (SSRF)',
    lens: 'deserialization-ssrf',
    cweIds: ['CWE-611', 'CWE-918'],
  },
  {
    id: 'vulnerable-components',
    name: '脆弱な依存コンポーネント',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    lens: 'dependency',
    cweIds: ['CWE-937', 'CWE-1395'],
  },
  {
    id: 'misconfiguration',
    name: 'セキュリティ設定不備',
    owasp: 'A05:2021-Security Misconfiguration',
    // 設定不備を専門に見るレンズは存在しない（＝構造的な死角）
    lens: null,
    cweIds: ['CWE-16', 'CWE-614', 'CWE-1004'],
  },
  {
    id: 'logging',
    name: 'ログ・監視の不足',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
    lens: null,
    cweIds: ['CWE-117', 'CWE-778'],
  },
  {
    id: 'insecure-design',
    name: '安全でない設計 (DoS・情報露出等)',
    owasp: 'A04:2021-Insecure Design',
    lens: null,
    cweIds: ['CWE-209', 'CWE-400', 'CWE-434', 'CWE-1333'],
  },
];

/**
 * どのカテゴリにも当てはまらない CWE の受け皿。
 * 未知のCWEを黙って捨てないために用意する（取りこぼしを隠さない方針）。
 */
export const UNCATEGORIZED_CATEGORY_ID = 'uncategorized';

const UNCATEGORIZED_DEFINITION: CategoryDefinition = {
  id: UNCATEGORIZED_CATEGORY_ID,
  name: '未分類',
  lens: null,
  cweIds: [],
};

/** CWE ID → カテゴリ定義の索引 */
const CATEGORY_BY_CWE = new Map<string, CategoryDefinition>();
for (const category of CATEGORY_DEFINITIONS) {
  for (const cweId of category.cweIds) {
    CATEGORY_BY_CWE.set(cweId, category);
  }
}

/** CWE ID 表記を 'CWE-89' 形式へ正規化する。'89' や 'cwe_89' も受け付ける */
export function normalizeCweId(raw: string): string | null {
  const m = /^(?:cwe[-_\s]?)?(\d+)$/i.exec(raw.trim());
  return m ? `CWE-${m[1]}` : null;
}

/** 列（カテゴリ）の一覧。呼び出し側が書き換えても内部状態が壊れないよう複製して返す */
export function weaknessCategories(): WeaknessCategory[] {
  return CATEGORY_DEFINITIONS.map(toWeaknessCategory);
}

/** 未分類カテゴリ（列に追加する必要が生じたときだけ使う） */
export function uncategorizedCategory(): WeaknessCategory {
  return toWeaknessCategory(UNCATEGORIZED_DEFINITION);
}

function toWeaknessCategory(def: CategoryDefinition): WeaknessCategory {
  const category: WeaknessCategory = {
    id: def.id,
    name: def.name,
    cweIds: [...def.cweIds],
  };
  if (def.owasp !== undefined) category.owasp = def.owasp;
  return category;
}

/** CWE が属するカテゴリを返す。未知なら undefined */
export function cweCategory(cweId: string): WeaknessCategory | undefined {
  const normalized = normalizeCweId(cweId);
  if (normalized === null) return undefined;
  const def = CATEGORY_BY_CWE.get(normalized);
  return def ? toWeaknessCategory(def) : undefined;
}

/** カテゴリIDを担当するレンズ。null なら担当レンズなし（＝構造的な死角） */
export function lensForCategory(categoryId: string): LensId | null {
  const def = CATEGORY_DEFINITIONS.find((c) => c.id === categoryId);
  return def ? def.lens : null;
}

/** CWE を担当するレンズ。null なら担当レンズなし */
export function lensForCwe(cweId: string): LensId | null {
  const normalized = normalizeCweId(cweId);
  if (normalized === null) return null;
  return CATEGORY_BY_CWE.get(normalized)?.lens ?? null;
}

/** CWE の事実（悪用可能性・CIA影響・適用範囲）。未知なら undefined */
export function cweFacts(cweId: string): CweFacts | undefined {
  const normalized = normalizeCweId(cweId);
  if (normalized === null) return undefined;
  return CWE_FACTS[normalized];
}

/** 大文字小文字・空白を無視した集合の交差判定 */
function intersects(a: readonly string[], b: readonly string[]): boolean {
  const lowered = new Set(b.map((x) => x.trim().toLowerCase()));
  return a.some((x) => lowered.has(x.trim().toLowerCase()));
}

/**
 * 技術スタックに該当する CWE の ID 一覧を返す（カタログ定義順で決定的）。
 *
 * 判定規則:
 *   - 適用言語が未指定 or 'Not Language-Specific' を含むなら、言語条件は無条件成立
 *   - 適用技術が未指定 or 'Not Technology-Specific' を含むなら、技術条件は無条件成立
 *   - それ以外は、問い合わせ側のスタックと1つ以上一致すること
 */
export function cwesForPlatform(platform: PlatformQuery): string[] {
  const matched: string[] = [];
  for (const category of CATEGORY_DEFINITIONS) {
    for (const cweId of category.cweIds) {
      const facts = CWE_FACTS[cweId];
      if (!facts) continue;
      const languageOk =
        facts.languages.length === 0 ||
        facts.languages.includes(ANY_LANGUAGE) ||
        intersects(facts.languages, platform.languages);
      const technologyOk =
        facts.technologies.length === 0 ||
        facts.technologies.includes(ANY_TECHNOLOGY) ||
        intersects(facts.technologies, platform.technologies);
      if (languageOk && technologyOk) matched.push(cweId);
    }
  }
  return matched;
}

/**
 * ScanContext の言語名（'typescript' など小文字）を
 * CWEカタログの語彙（'JavaScript' など）へ寄せる。
 */
const LANGUAGE_ALIASES: Record<string, string> = {
  typescript: 'JavaScript',
  javascript: 'JavaScript',
  tsx: 'JavaScript',
  jsx: 'JavaScript',
  python: 'Python',
  go: 'Go',
  golang: 'Go',
  java: 'Java',
  kotlin: 'Java',
  ruby: 'Ruby',
  php: 'PHP',
  perl: 'Perl',
  rust: 'Rust',
  csharp: 'C#',
  'c#': 'C#',
  c: 'C',
  cpp: 'C++',
  'c++': 'C++',
  sql: 'SQL',
  xml: 'XML',
};

/** 「インタプリタ言語」に分類される言語（CWE-94/95 の適用条件） */
const INTERPRETED_LANGUAGES = new Set(['JavaScript', 'Python', 'Ruby', 'PHP', 'Perl']);

/** ScanContext 由来の言語名をカタログ語彙へ変換する（未知の言語はそのまま残す） */
export function toCatalogLanguages(names: readonly string[]): string[] {
  const out: string[] = [];
  for (const name of names) {
    const mapped = LANGUAGE_ALIASES[name.trim().toLowerCase()] ?? name.trim();
    if (mapped.length === 0) continue;
    if (!out.includes(mapped)) out.push(mapped);
    if (INTERPRETED_LANGUAGES.has(mapped) && !out.includes('Interpreted')) out.push('Interpreted');
  }
  return out;
}
