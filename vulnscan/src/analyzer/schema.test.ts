import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import { describe, expect, it } from 'vitest';
import { analysisResultSchema, candidateFindingSchema, verdictSchema } from './schema.js';

const VALID = {
  cwe: 'CWE-89',
  category: 'A03:2021-Injection',
  title: 'SQLインジェクション',
  severity: 'high',
  confidence: 0.9,
  location: { file: 'src/a.ts', startLine: 3, endLine: 3 },
  evidence: 'db.query(...)',
  dataFlow: [
    {
      file: 'src/a.ts',
      line: 2,
      code: 'const id = req.params.id;',
      role: 'source',
      description: 'リクエストパラメータ',
    },
  ],
  reasoning: '連結された値がそのままクエリに渡る',
  remediation: 'プレースホルダを使う',
};

describe('構造化出力スキーマ', () => {
  it('SDK の zodOutputFormat に渡せる（zod/v4 スキーマである）', () => {
    expect(() => zodOutputFormat(analysisResultSchema)).not.toThrow();
    expect(() => zodOutputFormat(verdictSchema)).not.toThrow();
  });

  it('正常な候補を受け入れる', () => {
    expect(candidateFindingSchema.safeParse(VALID).success).toBe(true);
  });

  it('dataFlow が無い指摘はスキーマ違反にする（根拠なき指摘の抑制）', () => {
    const { dataFlow: _dataFlow, ...withoutFlow } = VALID;
    expect(candidateFindingSchema.safeParse(withoutFlow).success).toBe(false);
  });

  it('reasoning が無い指摘はスキーマ違反にする', () => {
    const { reasoning: _reasoning, ...withoutReasoning } = VALID;
    expect(candidateFindingSchema.safeParse(withoutReasoning).success).toBe(false);
  });

  it('未知の severity / role を弾く', () => {
    expect(candidateFindingSchema.safeParse({ ...VALID, severity: 'blocker' }).success).toBe(
      false,
    );
    expect(
      candidateFindingSchema.safeParse({
        ...VALID,
        dataFlow: [{ ...VALID.dataFlow[0], role: 'unknown' }],
      }).success,
    ).toBe(false);
  });

  it('findings が空でも成立する（該当なしを表現できる）', () => {
    expect(analysisResultSchema.safeParse({ findings: [] }).success).toBe(true);
  });

  it('検証結果スキーマは判定と根拠を必須にする', () => {
    expect(
      verdictSchema.safeParse({
        verdict: 'confirmed',
        confidence: 0.8,
        exploitPath: 'a → b',
        rebuttal: '',
        missingEvidence: [],
        correctedSeverity: 'high',
      }).success,
    ).toBe(true);

    expect(verdictSchema.safeParse({ verdict: 'confirmed' }).success).toBe(false);
  });
});
