import { describe, expect, it } from 'vitest';
import { buildSarifLog, renderSarif, SARIF_SCHEMA, SARIF_VERSION } from './formatters/sarif.js';
import { makeChain, makeContext, makeCvss, makeFinding, makeResult } from './fixtures.js';
import { buildFallbackNarrative } from './narrative.js';
import { analyzeMechanically } from './analyze.js';
import type { AnalyzedReport, ScanResult } from '../types/report.js';

function analyzedOf(result: ScanResult): AnalyzedReport {
  const mechanical = analyzeMechanically(result);
  const narrative = buildFallbackNarrative(
    {
      context: result.context,
      summary: result.summary,
      ranked: mechanical.ranked,
      chains: result.chains,
      actions: mechanical.actions,
      hasBaseline: mechanical.hasBaseline,
      errors: result.errors,
    },
    mechanical.keyFindings,
  );
  return {
    executiveSummary: narrative.executiveSummary,
    keyFindings: narrative.keyFindings,
    prioritizedActions: mechanical.actions,
    riskNarrative: narrative.riskNarrative,
    summary: result.summary,
  };
}

const sampleResult = (): ScanResult =>
  makeResult({
    context: makeContext({ warnings: ['一部ファイルがサイズ上限を超えたためスキップしました'] }),
    findings: [
      makeFinding({ id: 'f-1', cwe: 'CWE-89', severity: 'critical' }),
      makeFinding({
        id: 'f-2',
        cwe: 'CWE-798',
        severity: 'high',
        title: 'ハードコードされた署名鍵',
        category: 'A02:2021-Cryptographic Failures',
        location: { file: 'src/auth/token.ts', startLine: 12, endLine: 12 },
        cvss: makeCvss({ baseScore: 7.5, baseSeverity: 'High' }),
        lens: 'crypto-secrets',
        diffStatus: 'persistent',
        dataFlow: [],
      }),
      makeFinding({
        id: 'f-3',
        cwe: 'CWE-1035',
        severity: 'medium',
        title: '既知の脆弱性を含む依存',
        cve: 'CVE-2021-23337',
        affectedPackage: {
          name: 'lodash',
          version: '4.17.20',
          ecosystem: 'npm',
          fixedVersion: '4.17.21',
        },
        cvss: makeCvss({ baseScore: 5.3, baseSeverity: 'Medium' }),
        lens: 'dependency',
        diffStatus: 'fixed',
        dataFlow: [],
      }),
      makeFinding({
        id: 'f-4',
        cwe: 'CWE-79',
        severity: 'low',
        title: '出力エスケープの欠落の疑い',
        status: 'false-positive',
        dataFlow: [],
      }),
    ],
    chains: [makeChain()],
  });

describe('SARIF 2.1.0 出力', () => {
  const result = sampleResult();
  const log = buildSarifLog(result, analyzedOf(result));

  it('トップレベルが SARIF 2.1.0 の必須要素を満たす', () => {
    expect(log.$schema).toBe(SARIF_SCHEMA);
    expect(log.version).toBe(SARIF_VERSION);
    expect(Array.isArray(log.runs)).toBe(true);
    expect(log.runs).toHaveLength(1);
  });

  it('tool.driver に名前とルール定義がある', () => {
    const driver = log.runs[0]!.tool.driver;
    expect(driver.name).toBe('vulnscan');
    expect(typeof driver.informationUri).toBe('string');
    expect(driver.rules.length).toBeGreaterThan(0);
  });

  it('rules[] は CWE ごとに1件で、重複しない', () => {
    const rules = log.runs[0]!.tool.driver.rules;
    const ids = rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain('CWE-89');
    expect(ids).toContain('CWE-798');
    // 4件のFindingは4種類のCWE
    expect(rules).toHaveLength(4);
  });

  it('各ルールに GitHub が要求するメタデータが揃っている', () => {
    for (const rule of log.runs[0]!.tool.driver.rules) {
      expect(rule.id).toMatch(/^CWE-/);
      expect(rule.name).toMatch(/^[A-Za-z0-9]+$/);
      expect(typeof rule.shortDescription.text).toBe('string');
      expect(rule.shortDescription.text.length).toBeGreaterThan(0);
      expect(typeof rule.fullDescription.text).toBe('string');
      expect(typeof rule.help.markdown).toBe('string');
      expect(['error', 'warning', 'note', 'none']).toContain(rule.defaultConfiguration.level);
      // GitHub Code Scanning はここを読んで深刻度を決める（文字列であること）
      const securitySeverity = rule.properties['security-severity'];
      expect(typeof securitySeverity).toBe('string');
      expect(Number(securitySeverity)).not.toBeNaN();
      expect(Array.isArray(rule.properties.tags)).toBe(true);
      expect(rule.properties.tags as string[]).toContain('security');
    }
  });

  it('CWE番号から helpUri を生成する', () => {
    const rule = log.runs[0]!.tool.driver.rules.find((r) => r.id === 'CWE-89');
    expect(rule?.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html');
    expect((rule?.properties.tags as string[]) ?? []).toContain('external/cwe/cwe-89');
  });

  it('results[] が Finding と1対1で、ruleIndex が正しく解決する', () => {
    const run = log.runs[0]!;
    expect(run.results).toHaveLength(result.findings.length);
    for (const res of run.results) {
      const rule = run.tool.driver.rules[res.ruleIndex];
      expect(rule).toBeDefined();
      expect(rule!.id).toBe(res.ruleId);
    }
  });

  it('level は severity から error/warning/note にマッピングされる', () => {
    const byRule = new Map(log.runs[0]!.results.map((r) => [r.ruleId, r.level]));
    expect(byRule.get('CWE-89')).toBe('error'); // critical
    expect(byRule.get('CWE-798')).toBe('error'); // high
    expect(byRule.get('CWE-1035')).toBe('warning'); // medium
    expect(byRule.get('CWE-79')).toBe('note'); // low
  });

  it('partialFingerprints に fingerprint が文字列で入る', () => {
    const res = log.runs[0]!.results[0]!;
    expect(res.partialFingerprints.vulnscanFingerprint).toBe('fp-f-1');
    for (const value of Object.values(res.partialFingerprints)) {
      expect(typeof value).toBe('string');
    }
  });

  it('properties に CVSS とセキュリティ深刻度が入る', () => {
    const res = log.runs[0]!.results.find((r) => r.ruleId === 'CWE-89')!;
    expect(res.properties.cvssScore).toBe(9.8);
    expect(res.properties.cvssVector).toContain('CVSS:3.1/');
    expect(res.properties['security-severity']).toBe('9.8');
    expect(res.properties.cwe).toBe('CWE-89');
    expect(res.properties.confidence).toBe(0.9);
  });

  it('locations の region は 1 以上の行番号を持つ', () => {
    for (const res of log.runs[0]!.results) {
      const region = res.locations[0]!.physicalLocation.region;
      expect(region.startLine).toBeGreaterThanOrEqual(1);
      expect(region.endLine!).toBeGreaterThanOrEqual(region.startLine);
      expect(res.locations[0]!.physicalLocation.artifactLocation.uriBaseId).toBe('SRCROOT');
      // URI は相対パス（先頭スラッシュなし）
      expect(res.locations[0]!.physicalLocation.artifactLocation.uri).not.toMatch(/^\//);
    }
  });

  it('データフローを codeFlows として出力する', () => {
    const res = log.runs[0]!.results.find((r) => r.ruleId === 'CWE-89')!;
    expect(res.codeFlows).toBeDefined();
    const locations = res.codeFlows![0]!.threadFlows[0]!.locations;
    expect(locations).toHaveLength(2);
    expect(locations[0]!.importance).toBe('essential');
    // データフローの無いFindingには codeFlows を付けない
    const noFlow = log.runs[0]!.results.find((r) => r.ruleId === 'CWE-798')!;
    expect(noFlow.codeFlows).toBeUndefined();
  });

  it('diffStatus を baselineState にマッピングする', () => {
    const byRule = new Map(log.runs[0]!.results.map((r) => [r.ruleId, r.baselineState]));
    expect(byRule.get('CWE-89')).toBe('new');
    expect(byRule.get('CWE-798')).toBe('unchanged');
    expect(byRule.get('CWE-1035')).toBe('absent');
  });

  it('誤検知は suppressions として表現する', () => {
    const res = log.runs[0]!.results.find((r) => r.ruleId === 'CWE-79')!;
    expect(res.suppressions).toBeDefined();
    expect(res.suppressions![0]!.kind).toBe('external');
  });

  it('invocations と originalUriBaseIds を出力する', () => {
    const run = log.runs[0]!;
    expect(run.invocations).toHaveLength(1);
    expect(run.invocations[0]!.executionSuccessful).toBe(true);
    // 警告は toolExecutionNotifications に載る
    expect(run.invocations[0]!.toolExecutionNotifications).toHaveLength(1);
    expect(run.originalUriBaseIds!.SRCROOT!.uri).toMatch(/^file:\/\//);
    expect(run.columnKind).toBe('utf16CodeUnits');
  });

  it('エラーがあれば executionSuccessful は false', () => {
    const withErrors = makeResult({ findings: [], errors: ['LLM呼び出しに失敗しました'] });
    const errLog = buildSarifLog(withErrors, analyzedOf(withErrors));
    expect(errLog.runs[0]!.invocations[0]!.executionSuccessful).toBe(false);
  });

  it('Findingが0件でも妥当なSARIFを出す', () => {
    const empty = makeResult();
    const emptyLog = buildSarifLog(empty, analyzedOf(empty));
    expect(emptyLog.runs[0]!.results).toEqual([]);
    expect(emptyLog.runs[0]!.tool.driver.rules).toEqual([]);
  });

  it('renderSarif は整形済みJSONを返し、再パースできる', () => {
    const text = renderSarif(result, analyzedOf(result));
    const parsed = JSON.parse(text) as { version: string; runs: unknown[] };
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
    expect(text.endsWith('\n')).toBe(true);
  });
});
