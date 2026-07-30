/**
 * スキャンが「完走したか」を表すモデル。
 *
 * ■ なぜ必要か
 *   このスキャナは部分的失敗を許容する設計で、LLM呼び出しが失敗しても
 *   errors に積んで続行する。だが CIゲートが「検出件数」だけを見ていると、
 *   認証エラー・ネットワーク断・予算超過・安全分類器の拒否などで
 *   **全タスクが失敗しても検出0件になり、ビルドは緑になる**。
 *
 *   実際に APIキー未設定で走らせると、12タスク全滅・検出0件でも
 *   `--fail-on high` が終了コード0を返し、レポートには
 *   「対応を要する脆弱性は検出されませんでした」と出ていた。
 *   本ツールが掲げる「検出されなかった≠安全」が、ツール自身で
 *   破られている状態だった。
 *
 *   そこで「検出結果」とは独立に「実行の健全性」を持ち回し、
 *   ゲートとレポート文言の両方がこれを参照する。
 */

/** スキャンの健全性の区分 */
export type ScanHealthLevel =
  /** 全タスクが完了した。検出0件は「見たが無かった」を意味する */
  | 'complete'
  /** 一部のタスクが失敗した。検出結果は不完全 */
  | 'degraded'
  /** 大半または全部のタスクが失敗した。検出0件に意味は無い */
  | 'failed';

/**
 * 分析タスクの実行統計。レンズ×チャンクの単位で数える。
 *
 * 数えるのは1st pass（検出パス）だけ。自己検証パスの失敗は
 * 検出範囲を狭めず確信度を控えめに下げるだけなので、
 * errors への記録に留めてここには含めない。
 *
 * 不変条件: `succeeded + failed + refused <= total`。
 * 差分（{@link skippedTasks}）は予算切れで呼び出す前に打ち切られた分。
 */
export interface AnalysisStats {
  /** 実行しようとしたタスク数（打ち切られた分を含む） */
  total: number;
  /** 正常に結果を得たタスク数 */
  succeeded: number;
  /** エラーで落ちたタスク数（認証・通信・スキーマ不適合など） */
  failed: number;
  /** 安全分類器に拒否されたタスク数 */
  refused: number;
  /** トークン予算の超過で打ち切りが発生したか（検出パス・検証パスのいずれでも） */
  budgetExhausted: boolean;
  /** キャッシュから得たタスク数（成功に含む。健全性判定では成功扱い） */
  fromCache: number;
}

/**
 * 一度も呼ばれずに終わったタスク数。
 * 予算切れで検出パスが途中で打ち切られた場合にだけ正になる。
 */
export function skippedTasks(stats: AnalysisStats): number {
  return Math.max(0, stats.total - stats.succeeded - stats.failed - stats.refused);
}

export interface ScanHealth {
  level: ScanHealthLevel;
  analysis: AnalysisStats;
  /** 人間向けの説明。レポートとゲートの理由文に使う */
  reason: string;
  /**
   * 検出0件を「安全」と解釈してよいか。
   * `level === 'complete'` のときだけ true。
   */
  zeroFindingsIsMeaningful: boolean;
}

/** 空の統計。分析を実行しなかった場合に使う */
export function emptyAnalysisStats(): AnalysisStats {
  return { total: 0, succeeded: 0, failed: 0, refused: 0, budgetExhausted: false, fromCache: 0 };
}

/**
 * 失敗率がこの割合を超えたら 'failed' とみなす。
 *
 * 0.5 にしているのは、半分以上が失敗した結果を「スキャン済み」として
 * 扱うのは危険という判断。1件でも失敗すれば 'degraded' にはなる。
 */
export const FAILED_RATIO_THRESHOLD = 0.5;

/**
 * 統計から健全性を判定する。純粋関数。
 *
 * 判定の順序に意味がある:
 *   1. 未走査のタスクが残っている（予算切れで打ち切られた）→ failed
 *      見ていない範囲があることが確定しているので、失敗率より優先する
 *   2. 失敗率が閾値超え → failed
 *   3. 分析対象が0件 → degraded（「見た結果0件」とは言えない）
 *   4. 1件でも失敗・拒否、または検証パスが予算切れ → degraded
 *   5. それ以外 → complete
 */
export function assessAnalysisHealth(stats: AnalysisStats): ScanHealth {
  const unhealthy = stats.failed + stats.refused;
  const skipped = skippedTasks(stats);

  if (skipped > 0) {
    return {
      level: 'failed',
      analysis: stats,
      reason:
        `分析を ${stats.succeeded + unhealthy}/${stats.total} タスクで打ち切りました` +
        `（トークン予算の超過）。残り ${skipped} タスク分のコードは走査していません。`,
      zeroFindingsIsMeaningful: false,
    };
  }

  if (stats.total === 0) {
    // 分析対象が無かった（空リポジトリ、全除外、レンズ0件など）。
    // 失敗ではないが「見た結果0件」とも言えないので degraded 扱いにする。
    return {
      level: 'degraded',
      analysis: stats,
      reason: '分析対象のコードがありませんでした（除外設定またはレンズ設定を確認してください）。',
      zeroFindingsIsMeaningful: false,
    };
  }

  const ratio = unhealthy / stats.total;
  if (ratio > FAILED_RATIO_THRESHOLD) {
    return {
      level: 'failed',
      analysis: stats,
      reason:
        `分析タスクの ${unhealthy}/${stats.total} 件が失敗しました` +
        `（失敗 ${stats.failed} / 拒否 ${stats.refused}）。検出結果は信頼できません。`,
      zeroFindingsIsMeaningful: false,
    };
  }

  if (unhealthy > 0) {
    return {
      level: 'degraded',
      analysis: stats,
      reason:
        `分析タスクの ${unhealthy}/${stats.total} 件が失敗しました` +
        `（失敗 ${stats.failed} / 拒否 ${stats.refused}）。結果は部分的です。`,
      zeroFindingsIsMeaningful: false,
    };
  }

  if (stats.budgetExhausted) {
    // 検出パスは完走したが、自己検証パスが予算切れで途中終了した。
    // 走査範囲は欠けていないので failed にはしない。
    return {
      level: 'degraded',
      analysis: stats,
      reason:
        `検出パスは ${stats.total} 件すべて完了しましたが、` +
        'トークン予算の超過で自己検証を途中で打ち切りました（確信度が控えめに出ます）。',
      zeroFindingsIsMeaningful: false,
    };
  }

  return {
    level: 'complete',
    analysis: stats,
    reason: `分析タスク ${stats.total} 件すべてが完了しました。`,
    zeroFindingsIsMeaningful: true,
  };
}
