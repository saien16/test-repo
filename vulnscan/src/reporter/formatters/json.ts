/**
 * JSONフォーマッタ。後続処理・機械可読用。
 * ScanResult（生データ）と AnalyzedReport（分析結果）の両方を落とす。
 */

import type { AnalyzedReport, ReportOptions, ScanResult } from '../../types/report.js';
import { isActiveFinding } from '../severity.js';

/** JSON出力のトップレベル構造 */
export interface JsonReport {
  /** 出力フォーマット自体のバージョン。後方互換の判定に使う */
  schemaVersion: string;
  tool: { name: string; version: string };
  generatedAt: string;
  analysis: AnalyzedReport;
  result: ScanResult;
}

export const JSON_SCHEMA_VERSION = '1.0';

export function buildJsonReport(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: Pick<ReportOptions, 'verbose'>,
): JsonReport {
  // verbose でなければ info レベルの指摘は落とす（機械処理の主目的から外れるため）
  const findings = options.verbose
    ? result.findings
    : result.findings.filter((f) => f.severity !== 'info' || !isActiveFinding(f));

  return {
    schemaVersion: JSON_SCHEMA_VERSION,
    tool: { name: 'vulnscan', version: '0.1.0' },
    generatedAt: new Date().toISOString(),
    analysis: analyzed,
    result: { ...result, findings },
  };
}

export function renderJson(
  result: ScanResult,
  analyzed: AnalyzedReport,
  options: Pick<ReportOptions, 'verbose'>,
): string {
  return `${JSON.stringify(buildJsonReport(result, analyzed, options), null, 2)}\n`;
}
