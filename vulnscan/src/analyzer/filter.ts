/**
 * 候補Finding → RawFinding への正規化、根拠に基づく減点、
 * confidence 閾値によるフィルタ、重複統合。
 *
 * ここは純粋関数だけで構成する（LLM呼び出しを含まない）ので、
 * 誤検知抑制ロジックを単体テストで固定できる。
 */

import type { Severity } from '../types/context.js';
import type { LensId, RawFinding } from '../types/finding.js';
import type { CandidateFinding } from './schema.js';
import type { Chunk } from './types.js';
import { clampConfidence, severityRank } from './verify.js';

export { clampConfidence, severityRank } from './verify.js';

/**
 * 根拠の薄さに対する減点係数。
 *
 * スキーマ上 dataFlow は必須だが、空配列は「到達性未証明」を意味する。
 * source/sink が揃っていない指摘も、経路として不完全なので減点する。
 */
export function evidencePenalty(candidate: Pick<CandidateFinding, 'dataFlow'>): number {
  const steps = candidate.dataFlow;
  if (steps.length === 0) return 0.5;

  const hasSink = steps.some((s) => s.role === 'sink');
  const hasSource = steps.some((s) => s.role === 'source');

  if (hasSink && hasSource) return 1;
  if (hasSink || hasSource) return 0.85;
  // propagation / sanitizer だけの経路は source も sink も特定できていない
  return 0.7;
}

function sanitizeLocation(
  candidate: CandidateFinding,
  chunk: Chunk,
): RawFinding['location'] {
  const file = candidate.location.file.trim() === '' ? chunk.file : candidate.location.file;
  const startLine = Math.max(1, Math.trunc(candidate.location.startLine) || 1);
  const endLine = Math.max(startLine, Math.trunc(candidate.location.endLine) || startLine);
  return { file, startLine, endLine };
}

export interface FindingBuildInput {
  candidate: CandidateFinding;
  chunk: Chunk;
  lens: LensId;
  /** 自己検証を反映した後の確信度（未実行なら候補の値） */
  confidence: number;
  /** 自己検証を反映した後の深刻度 */
  severity: Severity;
  /** reasoning に追記する検証メモ */
  note?: string;
}

/** 候補を RawFinding に変換する。位置や確信度の異常値はここで正す */
export function toRawFinding(input: FindingBuildInput): RawFinding {
  const { candidate, chunk, lens } = input;
  const confidence = clampConfidence(input.confidence * evidencePenalty(candidate));
  const reasoning =
    input.note && input.note.trim() !== ''
      ? `${candidate.reasoning}\n\n[自己検証] ${input.note}`
      : candidate.reasoning;

  return {
    cwe: candidate.cwe.trim(),
    category: candidate.category.trim(),
    title: candidate.title.trim(),
    severity: input.severity,
    confidence,
    location: sanitizeLocation(candidate, chunk),
    evidence: candidate.evidence,
    dataFlow: candidate.dataFlow.map((s) => ({ ...s })),
    reasoning,
    remediation: candidate.remediation,
    lens,
  };
}

/** confidence 閾値による破棄 */
export function filterByConfidence(
  findings: readonly RawFinding[],
  minConfidence: number,
): RawFinding[] {
  const threshold = clampConfidence(minConfidence);
  return findings.filter((f) => f.confidence >= threshold);
}

/** 同一箇所・同一CWEとみなす行の近さ（チャンク分割の重なり分を吸収する） */
const OVERLAP_TOLERANCE_LINES = 3;

function cweKey(cwe: string): string {
  return cwe.trim().toUpperCase().replace(/\s+/g, '');
}

function overlaps(a: RawFinding, b: RawFinding): boolean {
  return (
    a.location.startLine - OVERLAP_TOLERANCE_LINES <= b.location.endLine &&
    b.location.startLine - OVERLAP_TOLERANCE_LINES <= a.location.endLine
  );
}

/** 残す方を選ぶ: 確信度 → 深刻度 → データフローの厚み → 位置 の順 */
function isBetter(a: RawFinding, b: RawFinding): boolean {
  if (a.confidence !== b.confidence) return a.confidence > b.confidence;
  const rank = severityRank(a.severity) - severityRank(b.severity);
  if (rank !== 0) return rank > 0;
  if (a.dataFlow.length !== b.dataFlow.length) return a.dataFlow.length > b.dataFlow.length;
  return a.location.startLine < b.location.startLine;
}

/**
 * 重複統合。
 * 同じファイル・同じCWEで位置が重なるものは、チャンクのオーバーラップや
 * 複数レンズの重複検出によるものなので1件にまとめる。
 */
export function dedupeFindings(findings: readonly RawFinding[]): RawFinding[] {
  const groups = new Map<string, RawFinding[]>();
  for (const f of findings) {
    const key = `${f.location.file}|${cweKey(f.cwe)}`;
    const list = groups.get(key);
    if (list) list.push(f);
    else groups.set(key, [f]);
  }

  const out: RawFinding[] = [];
  for (const list of groups.values()) {
    const kept: RawFinding[] = [];
    for (const f of list) {
      const idx = kept.findIndex((k) => overlaps(k, f));
      if (idx === -1) {
        kept.push(f);
        continue;
      }
      const current = kept[idx];
      if (current && isBetter(f, current)) kept[idx] = f;
    }
    out.push(...kept);
  }
  return out;
}

/** 深刻度→確信度→位置 の順に並べる（出力を決定的にする） */
export function sortFindings(findings: readonly RawFinding[]): RawFinding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      b.confidence - a.confidence ||
      a.location.file.localeCompare(b.location.file) ||
      a.location.startLine - b.location.startLine ||
      a.cwe.localeCompare(b.cwe) ||
      a.lens.localeCompare(b.lens),
  );
}

/** 減点済みの RawFinding 群に対する最終処理 */
export function finalizeFindings(
  findings: readonly RawFinding[],
  minConfidence: number,
): RawFinding[] {
  return sortFindings(dedupeFindings(filterByConfidence(findings, minConfidence)));
}
