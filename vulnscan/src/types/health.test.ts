/**
 * 走査の健全性判定のテスト。
 *
 * ここが守っている性質はひとつ:
 * **「検出0件」を「安全」と読み替えてよいのは、全タスクが完了したときだけ**。
 */

import { describe, expect, it } from 'vitest';
import {
  FAILED_RATIO_THRESHOLD,
  assessAnalysisHealth,
  emptyAnalysisStats,
  skippedTasks,
  type AnalysisStats,
} from './health.js';

function stats(overrides: Partial<AnalysisStats> = {}): AnalysisStats {
  return { ...emptyAnalysisStats(), ...overrides };
}

describe('assessAnalysisHealth', () => {
  it('全タスク成功なら complete で、0件に意味がある', () => {
    const health = assessAnalysisHealth(stats({ total: 12, succeeded: 12 }));
    expect(health.level).toBe('complete');
    expect(health.zeroFindingsIsMeaningful).toBe(true);
    expect(health.reason).toContain('12');
  });

  it('キャッシュから得た分も成功として扱う', () => {
    const health = assessAnalysisHealth(stats({ total: 4, succeeded: 4, fromCache: 4 }));
    expect(health.level).toBe('complete');
    expect(health.zeroFindingsIsMeaningful).toBe(true);
  });

  it('全滅（APIキー未設定など）なら failed で、0件に意味は無い', () => {
    // 実際に踏んだ不具合の再現: 12タスク全滅・検出0件でCIが緑になっていた
    const health = assessAnalysisHealth(stats({ total: 12, failed: 12 }));
    expect(health.level).toBe('failed');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
    expect(health.reason).toContain('12/12');
  });

  it('1件でも失敗すれば degraded になる（0件を安全と言わせない）', () => {
    const health = assessAnalysisHealth(stats({ total: 10, succeeded: 9, failed: 1 }));
    expect(health.level).toBe('degraded');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
  });

  it('失敗率の閾値ちょうどは degraded、超えたら failed', () => {
    // 閾値は「超えたら」なので、ちょうど 50% は degraded 側に残る
    expect(assessAnalysisHealth(stats({ total: 10, succeeded: 5, failed: 5 })).level).toBe(
      'degraded',
    );
    expect(assessAnalysisHealth(stats({ total: 10, succeeded: 4, failed: 6 })).level).toBe('failed');
    expect(FAILED_RATIO_THRESHOLD).toBe(0.5);
  });

  it('安全分類器の拒否も失敗と同じ重みで数える', () => {
    const health = assessAnalysisHealth(stats({ total: 4, succeeded: 1, refused: 3 }));
    expect(health.level).toBe('failed');
    expect(health.reason).toContain('拒否 3');
  });

  it('分析対象が0件なら degraded（「見た結果0件」とは言えない）', () => {
    const health = assessAnalysisHealth(stats({ total: 0 }));
    expect(health.level).toBe('degraded');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
    expect(health.reason).toContain('分析対象');
  });

  it('未走査タスクが残っていれば、失敗率が低くても failed', () => {
    // 予算切れで途中打ち切り: 成功率は 100% だが半分は見ていない
    const health = assessAnalysisHealth(
      stats({ total: 20, succeeded: 10, budgetExhausted: true }),
    );
    expect(health.level).toBe('failed');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
    expect(health.reason).toContain('走査していません');
  });

  it('検出パスは完走し検証パスだけ予算切れなら degraded に留める', () => {
    // 走査範囲は欠けていないので failed にはしない。
    // ただし確信度が減衰しているため complete でもない。
    const health = assessAnalysisHealth(
      stats({ total: 8, succeeded: 8, budgetExhausted: true }),
    );
    expect(health.level).toBe('degraded');
    expect(health.zeroFindingsIsMeaningful).toBe(false);
    expect(health.reason).toContain('自己検証');
  });

  it('未走査の判定は成功率より優先される（順序の固定）', () => {
    // 失敗も未走査も同時にある場合、伝えるべきは「見ていない範囲がある」こと
    const health = assessAnalysisHealth(
      stats({ total: 20, succeeded: 8, failed: 2, budgetExhausted: true }),
    );
    expect(health.level).toBe('failed');
    expect(health.reason).toContain('打ち切りました');
  });

  it('健全性は統計をそのまま同梱する（レポートから内訳を出せるように）', () => {
    const s = stats({ total: 5, succeeded: 4, failed: 1 });
    expect(assessAnalysisHealth(s).analysis).toEqual(s);
  });
});

describe('skippedTasks', () => {
  it('total と実行結果の差を返す', () => {
    expect(skippedTasks(stats({ total: 10, succeeded: 3, failed: 1, refused: 1 }))).toBe(5);
    expect(skippedTasks(stats({ total: 4, succeeded: 4 }))).toBe(0);
  });

  it('内訳が total を超えても負にはならない', () => {
    expect(skippedTasks(stats({ total: 2, succeeded: 3 }))).toBe(0);
  });
});
