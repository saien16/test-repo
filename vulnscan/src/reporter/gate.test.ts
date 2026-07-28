import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, type VulnScanConfig } from '../types/config.js';
import { determineExitCode, evaluateGate } from './gate.js';
import { makeFinding, makeResult } from './fixtures.js';

function config(overrides: Partial<VulnScanConfig> = {}): VulnScanConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}

describe('determineExitCode', () => {
  it('failOn: never なら常に 0', () => {
    const result = makeResult({
      findings: [makeFinding({ id: 'f-1', severity: 'critical' })],
    });
    expect(determineExitCode(result, config({ failOn: 'never' }))).toBe(0);
    expect(determineExitCode(result, config({ failOn: 'never', failOnNewOnly: true }))).toBe(0);
  });

  it('閾値以上の深刻度があれば非ゼロ', () => {
    const result = makeResult({ findings: [makeFinding({ id: 'f-1', severity: 'high' })] });
    expect(determineExitCode(result, config({ failOn: 'high' }))).toBe(1);
    expect(determineExitCode(result, config({ failOn: 'medium' }))).toBe(1);
    expect(determineExitCode(result, config({ failOn: 'critical' }))).toBe(0);
  });

  it('閾値未満しかなければ 0', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-1', severity: 'medium' }),
        makeFinding({ id: 'f-2', severity: 'low' }),
      ],
    });
    expect(determineExitCode(result, config({ failOn: 'high' }))).toBe(0);
    expect(determineExitCode(result, config({ failOn: 'medium' }))).toBe(1);
  });

  it('Findingが0件なら 0', () => {
    expect(determineExitCode(makeResult(), config({ failOn: 'info' }))).toBe(0);
  });

  it('failOnNewOnly なら diffStatus: new のみを対象にする', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-1', severity: 'critical', diffStatus: 'persistent' }),
        makeFinding({ id: 'f-2', severity: 'low', diffStatus: 'new' }),
      ],
    });

    // 新規のみ対象 → critical は persistent なので無視され、new は low で閾値未満
    expect(determineExitCode(result, config({ failOn: 'high', failOnNewOnly: true }))).toBe(0);
    // 全件対象なら critical が引っかかる
    expect(determineExitCode(result, config({ failOn: 'high', failOnNewOnly: false }))).toBe(1);
  });

  it('failOnNewOnly で新規の高深刻度があれば非ゼロ', () => {
    const result = makeResult({
      findings: [makeFinding({ id: 'f-1', severity: 'critical', diffStatus: 'new' })],
    });
    expect(determineExitCode(result, config({ failOn: 'high', failOnNewOnly: true }))).toBe(1);
  });

  it('修正済み・誤検知・受容済みはゲート対象外', () => {
    const cfg = config({ failOn: 'high' });
    expect(
      determineExitCode(
        makeResult({ findings: [makeFinding({ id: 'f-1', severity: 'critical', diffStatus: 'fixed' })] }),
        cfg,
      ),
    ).toBe(0);
    expect(
      determineExitCode(
        makeResult({
          findings: [makeFinding({ id: 'f-1', severity: 'critical', status: 'false-positive' })],
        }),
        cfg,
      ),
    ).toBe(0);
    expect(
      determineExitCode(
        makeResult({ findings: [makeFinding({ id: 'f-1', severity: 'critical', status: 'accepted' })] }),
        cfg,
      ),
    ).toBe(0);
    // confirmed は当然対象
    expect(
      determineExitCode(
        makeResult({ findings: [makeFinding({ id: 'f-1', severity: 'critical', status: 'confirmed' })] }),
        cfg,
      ),
    ).toBe(1);
  });

  it('failOn: info なら info でも落ちる', () => {
    const result = makeResult({ findings: [makeFinding({ id: 'f-1', severity: 'info' })] });
    expect(determineExitCode(result, config({ failOn: 'info' }))).toBe(1);
    expect(determineExitCode(result, config({ failOn: 'low' }))).toBe(0);
  });
});

describe('evaluateGate', () => {
  it('閾値を超えたFindingのIDを返す', () => {
    const result = makeResult({
      findings: [
        makeFinding({ id: 'f-1', severity: 'critical' }),
        makeFinding({ id: 'f-2', severity: 'low' }),
        makeFinding({ id: 'f-3', severity: 'high' }),
      ],
    });
    const decision = evaluateGate(result, config({ failOn: 'high' }));
    expect(decision.exitCode).toBe(1);
    expect(decision.offendingIds).toEqual(['f-1', 'f-3']);
    expect(decision.reason).toContain('2 件');
  });

  it('never のときは理由を明示する', () => {
    const decision = evaluateGate(makeResult(), config({ failOn: 'never' }));
    expect(decision.exitCode).toBe(0);
    expect(decision.reason).toContain('never');
  });
});
