/**
 * CWE / OWASP カテゴリ → MITRE ATT&CK テクニックの対応表と、
 * LLM が返したチェーンステップの検証・補正ロジック。
 *
 * LLM はテクニックIDを幻覚しやすく、また戦術(tactic)とキルチェーン段階(phase)の
 * 対応を取り違えることがある。そこで
 *   1. ID の書式を正規化し（大小文字・サブテクニック）
 *   2. カタログに無いIDは Finding の CWE から導いた値で置き換え
 *   3. 戦術/段階が不正ならテクニックの正準値から補完する
 * という3段階の補正をここに集約している。
 */

import type { LensId } from '../types/finding.js';
import { extractCweId } from '../vuln/catalog.js';
import {
  ATTACK_TACTICS,
  KILL_CHAIN_PHASES,
  type AttackTactic,
  type ChainStep,
  type KillChainPhase,
} from '../types/killchain.js';

/**
 * 全キルチェーン段階 / 全 ATT&CK 戦術（検証用）。
 *
 * 実体は `types/killchain.ts` にあり、union 型のほうがこの配列から導出される。
 * 以前は配列と union が別々に手書きされていたため、戦術を足して配列への追加を
 * 忘れると LLM がその戦術を返せなくなるのに型エラーが出なかった。
 */
export { ATTACK_TACTICS, KILL_CHAIN_PHASES } from '../types/killchain.js';

/** 戦術から導く既定のキルチェーン段階 */
export const TACTIC_DEFAULT_PHASE: Record<AttackTactic, KillChainPhase> = {
  'initial-access': 'delivery',
  execution: 'exploitation',
  persistence: 'installation',
  'privilege-escalation': 'exploitation',
  'defense-evasion': 'installation',
  'credential-access': 'exploitation',
  discovery: 'reconnaissance',
  'lateral-movement': 'exploitation',
  collection: 'actions-on-objectives',
  exfiltration: 'actions-on-objectives',
  impact: 'actions-on-objectives',
};

export interface TechniqueInfo {
  /** 'T1190' もしくは 'T1552.005' */
  id: string;
  name: string;
  /** このテクニックの正準戦術 */
  tactic: AttackTactic;
  /** このテクニックの正準キルチェーン段階 */
  phase: KillChainPhase;
}

function t(id: string, name: string, tactic: AttackTactic, phase?: KillChainPhase): TechniqueInfo {
  return { id, name, tactic, phase: phase ?? TACTIC_DEFAULT_PHASE[tactic] };
}

/**
 * 本スキャナーが扱うコード起因の脆弱性で現実的に登場するテクニック集合。
 * ATT&CK 全体の写しではなく「静的解析で根拠を示せる範囲」に絞っている。
 * ここに無いIDを LLM が返した場合は幻覚とみなして CWE 対応表で置換する。
 */
export const TECHNIQUE_CATALOG: Record<string, TechniqueInfo> = {
  // --- Initial Access ---
  T1190: t('T1190', 'Exploit Public-Facing Application', 'initial-access', 'exploitation'),
  T1133: t('T1133', 'External Remote Services', 'initial-access'),
  T1078: t('T1078', 'Valid Accounts', 'initial-access'),
  T1195: t('T1195', 'Supply Chain Compromise', 'initial-access'),
  'T1195.001': t('T1195.001', 'Supply Chain Compromise: Software Dependencies', 'initial-access'),
  'T1195.002': t('T1195.002', 'Supply Chain Compromise: Software Supply Chain', 'initial-access'),
  T1199: t('T1199', 'Trusted Relationship', 'initial-access'),
  T1566: t('T1566', 'Phishing', 'initial-access'),

  // --- Execution ---
  T1059: t('T1059', 'Command and Scripting Interpreter', 'execution'),
  'T1059.004': t('T1059.004', 'Command and Scripting Interpreter: Unix Shell', 'execution'),
  'T1059.006': t('T1059.006', 'Command and Scripting Interpreter: Python', 'execution'),
  'T1059.007': t('T1059.007', 'Command and Scripting Interpreter: JavaScript', 'execution'),
  T1106: t('T1106', 'Native API', 'execution'),
  T1203: t('T1203', 'Exploitation for Client Execution', 'execution'),
  T1204: t('T1204', 'User Execution', 'execution', 'delivery'),
  'T1204.001': t('T1204.001', 'User Execution: Malicious Link', 'execution', 'delivery'),
  T1569: t('T1569', 'System Services', 'execution'),
  T1610: t('T1610', 'Deploy Container', 'execution'),

  // --- Persistence ---
  T1505: t('T1505', 'Server Software Component', 'persistence'),
  'T1505.003': t('T1505.003', 'Server Software Component: Web Shell', 'persistence'),
  T1098: t('T1098', 'Account Manipulation', 'persistence'),
  T1136: t('T1136', 'Create Account', 'persistence'),
  T1543: t('T1543', 'Create or Modify System Process', 'persistence'),
  T1546: t('T1546', 'Event Triggered Execution', 'persistence'),
  T1554: t('T1554', 'Compromise Host Software Binary', 'persistence'),
  T1556: t('T1556', 'Modify Authentication Process', 'credential-access'),

  // --- Privilege Escalation ---
  T1068: t('T1068', 'Exploitation for Privilege Escalation', 'privilege-escalation'),
  T1548: t('T1548', 'Abuse Elevation Control Mechanism', 'privilege-escalation'),
  T1134: t('T1134', 'Access Token Manipulation', 'privilege-escalation'),
  T1611: t('T1611', 'Escape to Host', 'privilege-escalation'),

  // --- Defense Evasion ---
  T1027: t('T1027', 'Obfuscated Files or Information', 'defense-evasion'),
  T1036: t('T1036', 'Masquerading', 'defense-evasion'),
  T1070: t('T1070', 'Indicator Removal', 'defense-evasion'),
  T1211: t('T1211', 'Exploitation for Defense Evasion', 'defense-evasion'),
  T1222: t('T1222', 'File and Directory Permissions Modification', 'defense-evasion'),
  T1562: t('T1562', 'Impair Defenses', 'defense-evasion'),
  'T1562.008': t('T1562.008', 'Impair Defenses: Disable or Modify Cloud Logs', 'defense-evasion'),
  T1600: t('T1600', 'Weaken Encryption', 'defense-evasion'),

  // --- Credential Access ---
  T1110: t('T1110', 'Brute Force', 'credential-access'),
  'T1110.002': t('T1110.002', 'Brute Force: Password Cracking', 'credential-access'),
  T1212: t('T1212', 'Exploitation for Credential Access', 'credential-access'),
  T1528: t('T1528', 'Steal Application Access Token', 'credential-access'),
  T1539: t('T1539', 'Steal Web Session Cookie', 'credential-access'),
  T1552: t('T1552', 'Unsecured Credentials', 'credential-access'),
  'T1552.001': t('T1552.001', 'Unsecured Credentials: Credentials In Files', 'credential-access'),
  'T1552.004': t('T1552.004', 'Unsecured Credentials: Private Keys', 'credential-access'),
  'T1552.005': t(
    'T1552.005',
    'Unsecured Credentials: Cloud Instance Metadata API',
    'credential-access',
  ),
  T1555: t('T1555', 'Credentials from Password Stores', 'credential-access'),
  T1606: t('T1606', 'Forge Web Credentials', 'credential-access'),
  T1649: t('T1649', 'Steal or Forge Authentication Certificates', 'credential-access'),

  // --- Discovery ---
  T1082: t('T1082', 'System Information Discovery', 'discovery'),
  T1083: t('T1083', 'File and Directory Discovery', 'discovery'),
  T1087: t('T1087', 'Account Discovery', 'discovery'),
  T1046: t('T1046', 'Network Service Discovery', 'discovery'),
  T1518: t('T1518', 'Software Discovery', 'discovery'),
  T1580: t('T1580', 'Cloud Infrastructure Discovery', 'discovery'),

  // --- Lateral Movement ---
  T1021: t('T1021', 'Remote Services', 'lateral-movement'),
  T1210: t('T1210', 'Exploitation of Remote Services', 'lateral-movement'),
  T1550: t('T1550', 'Use Alternate Authentication Material', 'lateral-movement'),
  T1563: t('T1563', 'Remote Service Session Hijacking', 'lateral-movement'),

  // --- Collection ---
  T1005: t('T1005', 'Data from Local System', 'collection'),
  T1213: t('T1213', 'Data from Information Repositories', 'collection'),
  T1530: t('T1530', 'Data from Cloud Storage', 'collection'),
  T1560: t('T1560', 'Archive Collected Data', 'collection'),
  T1185: t('T1185', 'Browser Session Hijacking', 'collection'),

  // --- Exfiltration ---
  T1041: t('T1041', 'Exfiltration Over C2 Channel', 'exfiltration'),
  T1048: t('T1048', 'Exfiltration Over Alternative Protocol', 'exfiltration'),
  T1567: t('T1567', 'Exfiltration Over Web Service', 'exfiltration'),

  // --- Impact ---
  T1485: t('T1485', 'Data Destruction', 'impact'),
  T1486: t('T1486', 'Data Encrypted for Impact', 'impact'),
  T1489: t('T1489', 'Service Stop', 'impact'),
  T1490: t('T1490', 'Inhibit System Recovery', 'impact'),
  T1496: t('T1496', 'Resource Hijacking', 'impact'),
  T1499: t('T1499', 'Endpoint Denial of Service', 'impact'),
  T1565: t('T1565', 'Data Manipulation', 'impact'),
};

/**
 * CWE → 代表テクニック。
 * 「その脆弱性を突いた攻撃者が直後に何をするか」で選んでいる。
 */
export const CWE_TECHNIQUE_MAP: Record<string, string> = {
  // インジェクション系
  'CWE-20': 'T1190', // Improper Input Validation
  'CWE-77': 'T1059', // Command Injection
  'CWE-78': 'T1059.004', // OS Command Injection
  'CWE-88': 'T1059', // Argument Injection
  'CWE-89': 'T1190', // SQL Injection
  'CWE-90': 'T1190', // LDAP Injection
  'CWE-91': 'T1190', // XML Injection
  'CWE-94': 'T1059', // Code Injection
  'CWE-95': 'T1059', // eval Injection
  'CWE-98': 'T1059', // PHP Remote File Inclusion
  'CWE-943': 'T1190', // NoSQL Injection
  'CWE-1321': 'T1059.007', // Prototype Pollution
  'CWE-611': 'T1190', // XXE
  'CWE-917': 'T1059', // Expression Language Injection
  'CWE-502': 'T1059', // 安全でないデシリアライズ

  // Web 出力
  'CWE-79': 'T1059.007', // XSS
  'CWE-80': 'T1059.007',
  'CWE-116': 'T1565', // 不適切なエンコード
  'CWE-117': 'T1565', // ログインジェクション
  'CWE-113': 'T1565', // HTTP レスポンス分割
  'CWE-352': 'T1204', // CSRF
  'CWE-601': 'T1204.001', // オープンリダイレクト

  // ファイル・パス
  'CWE-22': 'T1005', // パストラバーサル
  'CWE-23': 'T1005',
  'CWE-73': 'T1005',
  'CWE-434': 'T1505.003', // 無制限ファイルアップロード → Web シェル
  'CWE-732': 'T1222', // 不適切な権限付与
  'CWE-829': 'T1195.001', // 信頼できないソースからの取り込み

  // SSRF / ネットワーク
  'CWE-918': 'T1552.005', // SSRF → クラウドメタデータからの資格情報奪取
  'CWE-441': 'T1190', // 意図しない代理・中継

  // 認証・認可
  'CWE-284': 'T1190', // 不適切なアクセス制御
  'CWE-285': 'T1548',
  'CWE-287': 'T1078', // 不適切な認証
  'CWE-306': 'T1190', // 重要機能に対する認証の欠如
  'CWE-862': 'T1548', // 認可の欠如
  'CWE-863': 'T1548', // 不正な認可
  'CWE-639': 'T1548', // IDOR
  'CWE-269': 'T1068', // 不適切な権限管理
  'CWE-384': 'T1563', // セッション固定
  'CWE-613': 'T1078', // セッション有効期限不足
  'CWE-565': 'T1606', // 検証されないCookie依存

  // 暗号・シークレット
  'CWE-256': 'T1552.001',
  'CWE-259': 'T1552.001', // ハードコードされたパスワード
  'CWE-312': 'T1552.001', // 平文保存
  'CWE-315': 'T1552.001',
  'CWE-321': 'T1552.004', // ハードコードされた暗号鍵
  'CWE-326': 'T1600', // 不十分な暗号強度
  'CWE-327': 'T1600', // 破られた暗号アルゴリズム
  'CWE-328': 'T1600',
  'CWE-330': 'T1606', // 不十分なランダム性
  'CWE-338': 'T1606',
  'CWE-522': 'T1552', // 不十分に保護された資格情報
  'CWE-532': 'T1552.001', // ログへの機密情報出力
  'CWE-759': 'T1110.002', // ソルト無しハッシュ
  'CWE-916': 'T1110.002', // 計算量の少ないハッシュ
  'CWE-798': 'T1552.001', // ハードコードされた資格情報

  // 情報漏えい・DoS・依存
  'CWE-200': 'T1213',
  'CWE-209': 'T1082', // エラーメッセージからの情報露出
  'CWE-215': 'T1082',
  'CWE-400': 'T1499', // 資源枯渇
  'CWE-770': 'T1499',
  'CWE-1035': 'T1195.001',
  'CWE-1104': 'T1195.001', // 保守されていないサードパーティ製部品
  'CWE-937': 'T1195.001',
};

/** OWASP Top 10 カテゴリ（先頭の 'A0x'）からのフォールバック */
export const OWASP_TECHNIQUE_MAP: Record<string, string> = {
  A01: 'T1548', // Broken Access Control
  A02: 'T1552', // Cryptographic Failures
  A03: 'T1190', // Injection
  A04: 'T1190', // Insecure Design
  A05: 'T1190', // Security Misconfiguration
  A06: 'T1195.001', // Vulnerable and Outdated Components
  A07: 'T1078', // Identification and Authentication Failures
  A08: 'T1195', // Software and Data Integrity Failures
  A09: 'T1562', // Security Logging and Monitoring Failures
  A10: 'T1552.005', // SSRF
};

/** レンズからの最終フォールバック */
export const LENS_TECHNIQUE_MAP: Record<LensId, string> = {
  injection: 'T1190',
  authz: 'T1548',
  'crypto-secrets': 'T1552',
  'deserialization-ssrf': 'T1059',
  'web-output': 'T1059.007',
  dependency: 'T1195.001',
};

/**
 * 'cwe89' / 'CWE_89' / '89' などを 'CWE-89' に正規化する。
 *
 * 実体は `vuln/catalog.ts` の寛容版に統合した。
 * 以前はここだけ `Number()` を通していたためゼロ埋め（'CWE-089'）が潰れ、
 * 5桁以上の CWE も 4桁で切れていた。どちらもカタログ引きが外れる原因になる。
 */
export { extractCweId as normalizeCwe } from '../vuln/catalog.js';

/** 't1190' / 'T1190.001' / 'T1190 - Exploit...' などを 'T1190' 形式に正規化する */
export function normalizeTechniqueId(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const m = /^\s*[tT](\d{4})(?:\.(\d{3}))?\b/.exec(raw);
  if (!m || m[1] === undefined) return null;
  return m[2] === undefined ? `T${m[1]}` : `T${m[1]}.${m[2]}`;
}

/**
 * カタログ検索。サブテクニックがカタログに無ければ親テクニックへ縮退する。
 * 見つからなければ null（＝幻覚の疑い）。
 */
export function lookupTechnique(raw: string | null | undefined): TechniqueInfo | null {
  const id = normalizeTechniqueId(raw);
  if (id === null) return null;
  const direct = TECHNIQUE_CATALOG[id];
  if (direct !== undefined) return direct;
  const dot = id.indexOf('.');
  if (dot > 0) {
    const parent = TECHNIQUE_CATALOG[id.slice(0, dot)];
    // 親が判るサブテクニックは実在する可能性が高いのでIDは保持する
    if (parent !== undefined) return { ...parent, id };
  }
  return null;
}

/** Finding の分類情報（CWE → OWASP → レンズ）からテクニックを引く */
export function mapFindingToTechnique(
  finding: { cwe?: string; category?: string; lens?: LensId } | null | undefined,
): TechniqueInfo | null {
  if (!finding) return null;

  const cwe = extractCweId(finding.cwe);
  if (cwe !== null) {
    const byCwe = CWE_TECHNIQUE_MAP[cwe];
    const info = lookupTechnique(byCwe);
    if (info !== null) return info;
  }

  if (typeof finding.category === 'string') {
    const m = /^(A\d{2})/i.exec(finding.category.trim());
    if (m && m[1] !== undefined) {
      const info = lookupTechnique(OWASP_TECHNIQUE_MAP[m[1].toUpperCase()]);
      if (info !== null) return info;
    }
  }

  if (finding.lens !== undefined) {
    const info = lookupTechnique(LENS_TECHNIQUE_MAP[finding.lens]);
    if (info !== null) return info;
  }

  return null;
}

export function isValidPhase(value: unknown): value is KillChainPhase {
  return typeof value === 'string' && (KILL_CHAIN_PHASES as readonly string[]).includes(value);
}

export function isValidTactic(value: unknown): value is AttackTactic {
  return typeof value === 'string' && (ATTACK_TACTICS as readonly string[]).includes(value);
}

/** LLM から受け取った補正前のステップ（全フィールドを疑う） */
export interface RawChainStep {
  findingId?: string | null;
  killChainPhase?: string | null;
  attackTactic?: string | null;
  attackTechnique?: string | null;
  description?: string | null;
  preconditions?: (string | null)[] | null;
}

export interface ReconcileResult {
  step: ChainStep;
  /** 補正内容の記録（デバッグ・errors 用） */
  corrections: string[];
}

/**
 * LLM 出力ステップ1件を検証・補正して正規の ChainStep にする。
 *
 * @param raw    LLM の生出力
 * @param finding 紐づく Finding（存在しない findingId の場合は null）
 * @param order  1 始まりの並び順
 */
export function reconcileStep(
  raw: RawChainStep,
  finding: { id: string; cwe?: string; category?: string; lens?: LensId } | null,
  order: number,
): ReconcileResult {
  const corrections: string[] = [];
  const fallback = mapFindingToTechnique(finding);

  // --- テクニック ---
  let technique: TechniqueInfo | null = lookupTechnique(raw.attackTechnique);
  if (technique === null) {
    if (raw.attackTechnique !== null && raw.attackTechnique !== undefined && raw.attackTechnique !== '') {
      corrections.push(
        `step${order}: 未知のテクニックID '${raw.attackTechnique}' をカタログ値で置換しました`,
      );
    }
    technique = fallback;
  }

  // --- 戦術 ---
  let tactic: AttackTactic;
  if (isValidTactic(raw.attackTactic)) {
    tactic = raw.attackTactic;
  } else if (technique !== null) {
    tactic = technique.tactic;
    corrections.push(`step${order}: 不正な戦術 '${raw.attackTactic}' を '${tactic}' に補正しました`);
  } else {
    tactic = order === 1 ? 'initial-access' : 'execution';
    corrections.push(`step${order}: 戦術を推定できず '${tactic}' を割り当てました`);
  }

  // --- キルチェーン段階 ---
  let phase: KillChainPhase;
  if (isValidPhase(raw.killChainPhase)) {
    phase = raw.killChainPhase;
  } else {
    phase = technique?.phase ?? TACTIC_DEFAULT_PHASE[tactic];
    corrections.push(
      `step${order}: 不正な段階 '${raw.killChainPhase}' を '${phase}' に補正しました`,
    );
  }

  const preconditions = (raw.preconditions ?? [])
    .filter((p): p is string => typeof p === 'string' && p.trim() !== '')
    .map((p) => p.trim());

  const description =
    typeof raw.description === 'string' && raw.description.trim() !== ''
      ? raw.description.trim()
      : (technique?.name ?? '詳細不明のステップ');

  const step: ChainStep = {
    order,
    findingId: finding === null ? null : finding.id,
    killChainPhase: phase,
    attackTactic: tactic,
    description,
    preconditions,
  };
  if (technique !== null) step.attackTechnique = technique.id;

  return { step, corrections };
}

/**
 * ステップ列全体を検証・補正する。
 * - 存在しない findingId は null に落とす（型上 null 可）
 * - order を 1..n に振り直す
 * - 完全な重複ステップ（同一 findingId かつ同一テクニック）を圧縮する
 */
export function reconcileSteps(
  rawSteps: readonly RawChainStep[],
  findingsById: ReadonlyMap<string, { id: string; cwe?: string; category?: string; lens?: LensId }>,
): { steps: ChainStep[]; corrections: string[] } {
  const steps: ChainStep[] = [];
  const corrections: string[] = [];
  const seen = new Set<string>();

  for (const raw of rawSteps) {
    const id = typeof raw.findingId === 'string' ? raw.findingId.trim() : '';
    const finding = id === '' ? null : (findingsById.get(id) ?? null);
    if (id !== '' && finding === null) {
      corrections.push(`存在しない findingId '${id}' を null にしました`);
    }

    const { step, corrections: c } = reconcileStep(raw, finding, steps.length + 1);
    corrections.push(...c);

    const key = `${step.findingId ?? '-'}|${step.attackTechnique ?? '-'}|${step.attackTactic}`;
    if (step.findingId !== null && seen.has(key)) {
      corrections.push(`重複ステップ (${key}) を除去しました`);
      continue;
    }
    seen.add(key);
    step.order = steps.length + 1;
    steps.push(step);
  }

  return { steps, corrections };
}
