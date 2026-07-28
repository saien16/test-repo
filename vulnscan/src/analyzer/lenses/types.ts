/**
 * 分析レンズ（観点）の定義。
 *
 * 1つの万能プロンプトで全観点を見ると、注意が分散して見落としと過検知が
 * 同時に増える。観点ごとに system プロンプトを分けて、同じチャンクを
 * 別の視点で複数回走査する。
 *
 * systemPrompt は LlmClient 側でプロンプトキャッシュされる安定部分なので、
 * チャンク依存の情報は一切入れない（可変部分は user 側に置く）。
 */

import type { LensId } from '../../types/finding.js';

export interface Lens {
  id: LensId;
  /** ログ・レポート表示用 */
  title: string;
  /** キャッシュされる安定プロンプト */
  systemPrompt: string;
}
