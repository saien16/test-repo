/**
 * 「事実」と「推測」を型レベルで分離するための出所(provenance)モデル。
 *
 * このスキャナは、コードから直接読み取れること（事実）と、
 * そこから導いたこと（推測）を混ぜて報告してはいけない。
 * アーキテクチャ推定やヒートマップは本質的に推測を含むため、
 * すべての主張に出所を付けて回す。
 *
 * 設計上の約束:
 *   - `observed` は必ず1件以上の引用(citation)を持つ。持てないなら observed ではない。
 *   - `inferred` は必ず根拠(basis)と理由(reasoning)と確信度を持つ。
 *   - `assumed` は根拠がないことを明示するための逃げ道。既定値の採用など。
 *     確信度を持たない = 数値として集計してはいけない、という意図。
 */

/** コード上の具体的な位置。事実の裏付けとなる引用 */
export interface Citation {
  file: string;
  /** 1始まり。ファイル全体が根拠なら省略 */
  line?: number;
  /** 該当箇所の抜粋（長すぎる場合は切り詰める） */
  excerpt?: string;
}

/** 推測を行った主体 */
export type Inferrer =
  /** 決定的なルール・パターンマッチによる導出。再現可能 */
  | 'heuristic'
  /** LLMによる導出。再現性は低いが文脈を扱える */
  | 'llm'
  /** カタログ（CWEなど）の静的知識からの導出 */
  | 'catalog';

export type Provenance =
  | {
      kind: 'observed';
      /** 必ず1件以上。空なら observed を名乗ってはいけない */
      citations: Citation[];
    }
  | {
      kind: 'inferred';
      /** 0..1。この値の信頼区間ではなく「この推測が正しい確率」の見積もり */
      confidence: number;
      inferredBy: Inferrer;
      /** 推測の土台にした観測事実 */
      basis: Citation[];
      /** なぜそう推測したか。読み手が反証できる粒度で書く */
      reasoning: string;
      /** 検討したが採らなかった対立仮説。推測の幅を示す */
      alternatives?: string[];
    }
  | {
      kind: 'assumed';
      /** なぜ根拠なしに仮定したか（既定値、業界慣行など） */
      reasoning: string;
    };

/** 出所付きの値。アーキテクチャ推定の各項目はすべてこの形を取る */
export interface Claim<T> {
  value: T;
  provenance: Provenance;
}

/** 主張の集合に対する事実/推測の内訳。レポートで「どれだけ推測に依っているか」を示す */
export interface EvidenceBreakdown {
  observed: number;
  inferred: number;
  assumed: number;
  /** inferred の確信度の平均。inferred が0件なら null */
  meanInferredConfidence: number | null;
}

// ---- 構築ヘルパ ----
// 出所を付け忘れないよう、生の値から Claim を作る経路を絞る。

export function observed<T>(value: T, citations: Citation[]): Claim<T> {
  if (citations.length === 0) {
    // 引用のない「事実」は事実ではない。呼び出し側のバグとして落とす。
    throw new Error('observed() には最低1件の citation が必要です');
  }
  return { value, provenance: { kind: 'observed', citations } };
}

export function inferred<T>(
  value: T,
  options: {
    confidence: number;
    inferredBy: Inferrer;
    basis?: Citation[];
    reasoning: string;
    alternatives?: string[];
  },
): Claim<T> {
  return {
    value,
    provenance: {
      kind: 'inferred',
      confidence: Math.max(0, Math.min(1, options.confidence)),
      inferredBy: options.inferredBy,
      basis: options.basis ?? [],
      reasoning: options.reasoning,
      ...(options.alternatives ? { alternatives: options.alternatives } : {}),
    },
  };
}

export function assumed<T>(value: T, reasoning: string): Claim<T> {
  return { value, provenance: { kind: 'assumed', reasoning } };
}

/** 主張群の内訳を集計する */
export function summarizeEvidence(claims: readonly Claim<unknown>[]): EvidenceBreakdown {
  let observedCount = 0;
  let inferredCount = 0;
  let assumedCount = 0;
  let confidenceSum = 0;

  for (const claim of claims) {
    switch (claim.provenance.kind) {
      case 'observed':
        observedCount++;
        break;
      case 'inferred':
        inferredCount++;
        confidenceSum += claim.provenance.confidence;
        break;
      case 'assumed':
        assumedCount++;
        break;
    }
  }

  return {
    observed: observedCount,
    inferred: inferredCount,
    assumed: assumedCount,
    meanInferredConfidence: inferredCount > 0 ? confidenceSum / inferredCount : null,
  };
}

/** レポート表示用の短いラベル */
export function provenanceLabel(provenance: Provenance): string {
  switch (provenance.kind) {
    case 'observed':
      return '事実';
    case 'inferred':
      return `推測(確信度 ${(provenance.confidence * 100).toFixed(0)}%)`;
    case 'assumed':
      return '仮定';
  }
}
