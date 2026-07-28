/**
 * 自己検証パス（adversarial verify）。誤検知抑制の主対策。
 *
 * 1st pass とは別の system プロンプトで、候補Findingに対して
 * 「本当に悪用可能か / 到達経路は実在するか / どこかでサニタイズされていないか」を
 * 反証する側から検証させる。反証されたものは落とし、判断がつかないものは
 * confidence を下げる。
 */

import type { Severity } from '../types/context.js';
import { severityRank } from '../util/severity.js';
import type { ChunkContext } from './context.js';
import { buildCodeBlock } from './prompt.js';
import type { CandidateFinding, Verdict } from './schema.js';

export const VERIFY_SYSTEM_PROMPT = `あなたはセキュリティ指摘のレビュー担当です。
別の解析パスが挙げた脆弱性候補と、その根拠になったコード・周辺文脈が渡されます。
あなたの役割は、その指摘を鵜呑みにせず、成立しない可能性を先に検討することです。

## 検討すること
1. **到達性**: 指摘された source は本当に攻撃者が制御できるか。
   そこから sink まで、提示されたコード上で値が実際に流れているか。
   途中で別の値に置き換わっていないか、そもそも呼ばれない経路ではないか。
2. **無害化**: 経路上に検証・エスケープ・パラメータ化・型変換・許可リストが無いか。
   フレームワークやライブラリが既定で行う防御が効いていないか。
   （ORMのバインド、テンプレートの自動エスケープ、パーサの既定設定など）
3. **前提の妥当性**: 指摘が、提示されていないコードの挙動を仮定していないか。
   実行文脈（テスト・CLI・内部ツール・ビルドスクリプト）を取り違えていないか。
   sink だと言っている操作が、実際には危険な解釈をしないものではないか。
4. **深刻度**: 成立するとして、影響は指摘された通りか。

## 判定
- refuted: 成立しない根拠をコード上で示せる場合。
- uncertain: 反証もできないが、成立の確認に必要な情報が提示範囲に無い場合。
- confirmed: source から sink までの経路と無害化の不在を、提示範囲で確認できた場合。

反証が目的であって、却下が目的ではありません。確認できたものは confirmed にしてください。
判断できない材料は missingEvidence に列挙してください。`;

/** 自己検証パスの user プロンプト */
export function buildVerificationPrompt(
  candidate: CandidateFinding,
  chunkContext: ChunkContext,
  lensTitle: string,
): string {
  const flow =
    candidate.dataFlow.length === 0
      ? '  （経路が示されていない。到達性が未証明であることに注意）'
      : candidate.dataFlow
          .map(
            (s, i) =>
              `  ${i + 1}. [${s.role}] ${s.file}:${s.line}  ${s.code}\n     ${s.description}`,
          )
          .join('\n');

  return [
    '# 検証対象の指摘',
    `  レンズ: ${lensTitle}`,
    `  タイトル: ${candidate.title}`,
    `  CWE: ${candidate.cwe} / カテゴリ: ${candidate.category}`,
    `  深刻度: ${candidate.severity} / 1st pass の確信度: ${candidate.confidence}`,
    `  位置: ${candidate.location.file}:${candidate.location.startLine}-${candidate.location.endLine}`,
    '',
    '## 主張されたデータフロー',
    flow,
    '',
    '## 主張の根拠',
    `  ${candidate.reasoning}`,
    '',
    '## 引用されたコード',
    '```',
    candidate.evidence,
    '```',
    '',
    chunkContext.text,
    '',
    buildCodeBlock(chunkContext.chunk),
    '',
    '# 依頼',
    '上の指摘が成立するかを検証してください。',
    '成立しない、または判断材料が足りないと考えるなら、その理由を rebuttal に書いてください。',
  ].join('\n');
}

// 深刻度の順序はシステム全体で1つでなければならない不変条件なので、
// ここで再定義せず共有実装をそのまま使う。以前は analyzer / vuln / reporter が
// それぞれ同じ表を持っており、順序を変えると3ステージで挙動が食い違う状態だった。
export { severityRank };

export interface VerdictApplication {
  /** 破棄すべきか（反証された） */
  dropped: boolean;
  confidence: number;
  severity: Severity;
  /** 検証結果の要約。reasoning に追記する */
  note: string;
}

export function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/**
 * 検証結果を候補に反映する。
 *
 * - refuted        → 破棄
 * - uncertain      → 1st pass と検証の低い方をさらに減衰
 * - confirmed      → 検証側に重みを置いて合成（1st pass の自己申告を上書きしすぎない）
 * - verdict が無い → 検証できなかったので控えめに減衰（予算切れ・拒否・失敗時）
 */
export function applyVerdict(
  candidate: Pick<CandidateFinding, 'confidence' | 'severity'>,
  verdict: Verdict | null,
): VerdictApplication {
  const base = clampConfidence(candidate.confidence);

  if (verdict === null) {
    return {
      dropped: false,
      confidence: clampConfidence(base * 0.8),
      severity: candidate.severity,
      note: '自己検証パスを実行できなかったため、確信度を控えめに調整した。',
    };
  }

  const vc = clampConfidence(verdict.confidence);

  // 検証側は深刻度を下げる方向にだけ効かせる（検証で吊り上げない）
  const severity =
    severityRank(verdict.correctedSeverity) < severityRank(candidate.severity)
      ? verdict.correctedSeverity
      : candidate.severity;

  if (verdict.verdict === 'refuted') {
    return {
      dropped: true,
      confidence: 0,
      severity,
      note: `自己検証で反証された: ${verdict.rebuttal}`,
    };
  }

  if (verdict.verdict === 'uncertain') {
    const missing =
      verdict.missingEvidence.length > 0
        ? ` 不足している情報: ${verdict.missingEvidence.join(' / ')}`
        : '';
    return {
      dropped: false,
      confidence: clampConfidence(Math.min(base, vc) * 0.7),
      severity,
      note: `自己検証では成立を確認できなかった。${verdict.rebuttal}${missing}`.trim(),
    };
  }

  return {
    dropped: false,
    confidence: clampConfidence(base * 0.4 + vc * 0.6),
    severity,
    note: verdict.exploitPath
      ? `自己検証で悪用経路を確認: ${verdict.exploitPath}`
      : '自己検証で成立を確認した。',
  };
}
