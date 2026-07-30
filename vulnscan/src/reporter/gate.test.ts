import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, type VulnScanConfig } from '../types/config.js';
import { assessAnalysisHealth, emptyAnalysisStats } from '../types/health.js';
import type { ScanResult } from '../types/report.js';
import { EXIT_CODES, determineExitCode, evaluateGate } from './gate.js';
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

/*
 * 実際に踏んだ不具合の回帰テスト。
 *
 * APIキーを設定せずに走らせると、12件の分析タスクが全滅して検出0件になり、
 * `--fail-on high` が終了コード0を返してレポートに
 * 「対応を要する脆弱性は検出されませんでした」と出ていた。
 * つまり設定ミス・通信障害・予算切れのすべてが「偽の緑」になっていた。
 */
describe('走査が完走しなかった場合のゲート', () => {
  /** 全タスクが失敗し、検出0件になった走査 */
  function allFailed(): ScanResult {
    return makeResult({
      findings: [],
      health: assessAnalysisHealth({ ...emptyAnalysisStats(), total: 12, failed: 12 }),
    });
  }

  it('全タスク失敗＋検出0件は終了コード 3（0にしてはいけない）', () => {
    const decision = evaluateGate(allFailed(), config({ failOn: 'high' }));
    expect(decision.exitCode).toBe(EXIT_CODES.incompleteScan);
    expect(decision.exitCode).not.toBe(0);
    expect(decision.blockedByHealth).toBe(true);
    expect(decision.reason).toContain('完走しませんでした');
  });

  it('終了コードは「検出あり」と区別できる別の値', () => {
    // CI側で「レビューが必要(1)」と「スキャナを直す必要がある(3)」に
    // 別の対応を割り当てられるようにするため、同じ値にしない
    expect(EXIT_CODES.findings).toBe(1);
    expect(EXIT_CODES.incompleteScan).toBe(3);
    expect(EXIT_CODES.incompleteScan).not.toBe(EXIT_CODES.findings);
  });

  it('failOn: never でも健全性の判定は効く（軸が違う）', () => {
    // never は「検出結果でビルドを落とさない」という指定であって、
    // 「壊れた走査を成功として報告してよい」という指定ではない
    const decision = evaluateGate(allFailed(), config({ failOn: 'never' }));
    expect(decision.exitCode).toBe(EXIT_CODES.incompleteScan);
    expect(decision.blockedByHealth).toBe(true);
  });

  it('failOnIncompleteScan: false なら明示的に無効化できる', () => {
    const decision = evaluateGate(allFailed(), config({ failOnIncompleteScan: false }));
    expect(decision.exitCode).toBe(0);
    expect(decision.blockedByHealth).toBe(false);
  });

  it('一部失敗（degraded）でも0件なら 3', () => {
    // 「10件中1件失敗、検出0件」も 0件を安全の根拠にできない
    const result = makeResult({
      health: assessAnalysisHealth({
        ...emptyAnalysisStats(),
        total: 10,
        succeeded: 9,
        failed: 1,
      }),
    });
    expect(determineExitCode(result, config({ failOn: 'high' }))).toBe(
      EXIT_CODES.incompleteScan,
    );
  });

  it('健全性の判定は検出結果より先（検出もあるなら健全性を優先して報告する）', () => {
    // 検出があっても走査が壊れているなら、件数は下限にすぎない。
    // 「high が1件」ではなく「走査が壊れている」を先に伝える。
    const result = makeResult({
      findings: [makeFinding({ id: 'f-1', severity: 'critical' })],
      health: assessAnalysisHealth({ ...emptyAnalysisStats(), total: 12, failed: 12 }),
    });
    const decision = evaluateGate(result, config({ failOn: 'high' }));
    expect(decision.exitCode).toBe(EXIT_CODES.incompleteScan);
    expect(decision.blockedByHealth).toBe(true);
  });

  it('完走した走査は従来どおり（0件→0、閾値超え→1）', () => {
    const complete = assessAnalysisHealth({
      ...emptyAnalysisStats(),
      total: 12,
      succeeded: 12,
    });
    expect(determineExitCode(makeResult({ health: complete }), config({ failOn: 'high' }))).toBe(0);
    expect(
      determineExitCode(
        makeResult({ findings: [makeFinding({ severity: 'high' })], health: complete }),
        config({ failOn: 'high' }),
      ),
    ).toBe(1);
  });
});
