/**
 * RawFinding → Finding への正規化と、重複 Finding の統合。
 */

import type { ScanContext } from '../types/context.js';
import type { Finding, RawFinding, Severity } from '../types/finding.js';
import { clampConfidence } from '../util/num.js';
import { SEVERITY_RANK, compareSeverity } from '../util/severity.js';
import { extractCweId } from './catalog.js';
import { calculateCvss3, inferCvss3MetricsWithReasons } from './cvss.js';
import { computeFingerprint, fingerprintToId, normalizeFilePath } from './fingerprint.js';
import { buildReferences, lookupCwe, owaspForCwe, owaspUrl } from './knowledge.js';

/**
 * 深刻度の比較規約は `util/severity.ts` に一元化した。
 * ここは互換のための再 export（`vuln/index.ts` から公開している）。
 */
export { compareSeverity };

/** 統合対象とみなす行範囲の許容ずれ（行） */
const LINE_PROXIMITY = 3;

/**
 * RawFinding 1件を Finding に正規化する。
 * CVSS ベクタが無いので {@link inferCvss3MetricsWithReasons} で推定し、
 * 推定根拠を reasoning の末尾に追記して説明可能にする。
 */
export function normalizeFinding(raw: RawFinding, ctx: ScanContext, now: string): Finding {
  const cweId = extractCweId(raw.cwe);
  const kb = cweId ? lookupCwe(cweId) : undefined;

  const file = normalizeFilePath(raw.location?.file ?? '', ctx.repoRoot);
  const startLine = Math.max(1, Number(raw.location?.startLine ?? 1) || 1);
  const endLine = Math.max(startLine, Number(raw.location?.endLine ?? startLine) || startLine);

  const fingerprint = computeFingerprint({
    file,
    cwe: cweId ?? raw.cwe ?? 'CWE-UNKNOWN',
    evidence: raw.evidence ?? '',
    repoRoot: ctx.repoRoot,
  });

  const { metrics, reasons } = inferCvss3MetricsWithReasons(raw, ctx);
  const cvss = calculateCvss3(metrics, '3.1');

  // OWASP カテゴリの決め方（確度の高い順）:
  //   1. 手作り知識ベースの直接対応（70件）
  //   2. LLM が申告した、URL に解決できる正しい形式のカテゴリ
  //   3. CWE の親を辿って手作り知識ベースを持つ祖先から継承したもの（推測）
  //   4. LLM の申告をそのまま
  const inherited = cweId ? owaspForCwe(cweId) : null;
  const category =
    kb?.owasp ??
    (owaspUrl(raw.category) ? raw.category : undefined) ??
    inherited?.category ??
    raw.category ??
    '';

  const reasoning = [
    raw.reasoning ?? '',
    '',
    `[CVSS推定根拠] ${cvss.vector} (${cvss.baseScore} / ${cvss.baseSeverity})`,
    ...reasons.map((r) => `  - ${r}`),
  ]
    .join('\n')
    .trim();

  return {
    ...raw,
    cwe: cweId ?? raw.cwe,
    category,
    title: raw.title ?? kb?.name ?? cweId ?? '無題の指摘',
    severity: normalizeSeverity(raw.severity),
    confidence: clampConfidence(raw.confidence ?? 0.5),
    location: { file, startLine, endLine },
    evidence: raw.evidence ?? '',
    dataFlow: Array.isArray(raw.dataFlow) ? raw.dataFlow : [],
    reasoning,
    remediation: raw.remediation ?? '',
    id: fingerprintToId(fingerprint),
    fingerprint,
    cvss,
    status: 'open',
    // ベースライン照合前の暫定値。applyBaseline で確定する。
    diffStatus: 'new',
    firstSeen: now,
    lastSeen: now,
    mergedFrom: [],
    references: buildReferences(cweId, category),
  };
}


function normalizeSeverity(severity: Severity): Severity {
  return severity in SEVERITY_RANK ? severity : 'medium';
}

/**
 * 重複した Finding を統合する。
 *
 * 1. 指紋が完全一致するもの（同一ファイル・同一CWE・同一コード片）
 * 2. 同一ファイル・同一CWE で行範囲が重なる（±3行）もの
 *    → 別レンズが同じ箇所を少し違う抜粋で報告したケースを吸収する
 *
 * 統合後は confidence を引き上げる。特に**異なるレンズ**が同じ問題を
 * 独立に検出した場合は相互裏付けとなるため上げ幅を大きくする。
 */
export function mergeFindings(findings: Finding[]): Finding[] {
  // --- 1. 指紋一致でまとめる ---
  const byFingerprint = new Map<string, Finding[]>();
  for (const f of findings) {
    const bucket = byFingerprint.get(f.fingerprint);
    if (bucket) bucket.push(f);
    else byFingerprint.set(f.fingerprint, [f]);
  }

  const stage1: Finding[] = [];
  for (const group of byFingerprint.values()) {
    stage1.push(combineGroup(group));
  }

  // --- 2. 同一箇所・同一CWE（行範囲が近接）でまとめる ---
  const clusters: Finding[][] = [];
  for (const f of stage1) {
    const target = clusters.find((cluster) =>
      cluster.some((other) => isSameLocation(other, f)),
    );
    if (target) target.push(f);
    else clusters.push([f]);
  }

  const merged = clusters.map((cluster) => combineGroup(cluster));

  // 出力順を安定させる: 深刻度降順 → CVSS降順 → ファイル名 → 開始行
  merged.sort((a, b) => {
    const sev = compareSeverity(b.severity, a.severity);
    if (sev !== 0) return sev;
    if (b.cvss.baseScore !== a.cvss.baseScore) return b.cvss.baseScore - a.cvss.baseScore;
    if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
    if (a.location.startLine !== b.location.startLine) {
      return a.location.startLine - b.location.startLine;
    }
    return a.fingerprint < b.fingerprint ? -1 : 1;
  });
  return merged;
}

/** 同一箇所・同一CWE とみなせるか */
function isSameLocation(a: Finding, b: Finding): boolean {
  // 依存脆弱性は全件が同じマニフェストの1行目を指すため、
  // 位置ベースの統合対象から除外する（指紋一致でのみ統合される）。
  if (a.lens === 'dependency' || b.lens === 'dependency') return false;
  if (a.cwe !== b.cwe) return false;
  if (a.location.file !== b.location.file) return false;
  // 行範囲が重なる、もしくは LINE_PROXIMITY 行以内で隣接している
  return (
    a.location.startLine - LINE_PROXIMITY <= b.location.endLine &&
    b.location.startLine - LINE_PROXIMITY <= a.location.endLine
  );
}

/** グループを1件へ統合する */
function combineGroup(group: Finding[]): Finding {
  if (group.length === 1) return group[0] as Finding;

  // 代表を選ぶ: confidence 最大 → 深刻度最大 → 指紋辞書順（決定的にするため）
  const sorted = [...group].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const sev = compareSeverity(b.severity, a.severity);
    if (sev !== 0) return sev;
    return a.fingerprint < b.fingerprint ? -1 : 1;
  });
  const primary = sorted[0] as Finding;
  const rest = sorted.slice(1);

  const lenses = new Set(group.map((f) => f.lens));
  const distinctLenses = lenses.size;

  // 相互裏付けによる確信度の引き上げ
  //   - 異なるレンズごとに +0.10（独立した観点からの裏付けは価値が高い）
  //   - 同一レンズ内の重複は +0.02（同じ観点なので価値は限定的）
  const sameLensDuplicates = group.length - distinctLenses;
  const boost = 0.1 * (distinctLenses - 1) + 0.02 * sameLensDuplicates;
  const confidence = Math.min(0.99, primary.confidence + boost);

  // 最も高い深刻度と、最も詳細なデータフローを採用する
  const severity = group.reduce<Severity>(
    (best, f) => (compareSeverity(f.severity, best) > 0 ? f.severity : best),
    primary.severity,
  );
  const dataFlow = group.reduce(
    (best, f) => (f.dataFlow.length > best.length ? f.dataFlow : best),
    primary.dataFlow,
  );
  const cvss =
    group.reduce((best, f) => (f.cvss.baseScore > best.cvss.baseScore ? f : best), primary).cvss;

  const mergedFrom = Array.from(
    new Set([...primary.mergedFrom, ...rest.flatMap((f) => [f.fingerprint, ...f.mergedFrom])]),
  )
    .filter((fp) => fp !== primary.fingerprint)
    .sort();

  const references = Array.from(new Set(group.flatMap((f) => f.references)));

  const mergeNote =
    `\n\n[統合] ${group.length}件の指摘を統合（検出レンズ: ${Array.from(lenses).sort().join(', ')}）。` +
    `確信度 ${primary.confidence.toFixed(2)} → ${confidence.toFixed(2)}。`;

  return {
    ...primary,
    severity,
    confidence,
    dataFlow,
    cvss,
    mergedFrom,
    references,
    reasoning: `${primary.reasoning}${mergeNote}`,
  };
}
