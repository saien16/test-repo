/**
 * 分析フェーズのうち「文章化」を担う部分。
 *
 * 数字と順序は priority.ts / summarize.ts が機械的に決めている。
 * ここでやるのは、その事実関係を人間が読める物語に変換することだけ。
 *
 * LLMが使えない場合（拒否・予算切れ・API障害・Finding0件）でも
 * 必ず機械生成の代替文を返す。レポート生成がスキャンを落としてはいけない。
 */

import { createHash } from 'node:crypto';
import * as z from 'zod/v4';
import type { LlmClient } from '../llm/client.js';
import type { VulnScanConfig } from '../types/config.js';
import type { AttackChain } from '../types/killchain.js';
import type { ScanContext } from '../types/context.js';
import type { ScanSummary } from '../types/report.js';
import { SEVERITY_LABEL_JA, SEVERITY_ORDER } from './severity.js';
import { likelihoodJa } from './labels.js';
import type { FindingSignal, PrioritizedAction } from './priority.js';
import { truncate } from './text.js';

/**
 * SDK の zodOutputFormat は zod/v4 のスキーマを要求するため、
 * 必ず 'zod/v4' から import したものでスキーマを組む。
 */
export const NarrativeSchema = z.object({
  executiveSummary: z
    .string()
    .describe('技術者でない読み手にも通じる3-5文の日本語要約。専門用語は最小限に。'),
  keyFindings: z
    .array(z.string())
    .describe('今回のスキャンで最も重要な所見。1件1文の日本語。最大6件。'),
  riskNarrative: z
    .string()
    .describe(
      '個別の指摘の羅列ではなく、このコードベースが晒されているリスクの全体像を' +
        '筋の通った日本語のストーリーとして説明する文章。',
    ),
  trendNarrative: z
    .string()
    .nullable()
    .describe('前回スキャンとの比較コメント（日本語）。比較材料がなければ null。'),
});

export type Narrative = z.infer<typeof NarrativeSchema>;

const SYSTEM_PROMPT = [
  'あなたはセキュリティレポートの編集者です。',
  '脆弱性スキャナーが機械的に集計した事実（件数・順序・スコア）を渡すので、',
  'それを経営層と開発チームの双方が読める日本語の文章に再構成してください。',
  '',
  '厳守事項:',
  '- 出力はすべて日本語。',
  '- 渡された事実に無い数値・ファイル名・CVE番号を創作しないこと。',
  '- 個別の指摘を箇条書きで繰り返すのではなく、因果関係でつないだ物語にすること。',
  '- executiveSummary は3-5文。技術用語を避け、「何が起きうるか」「事業上どう困るか」',
  '  「まず何をすべきか」が伝わるようにする。',
  '- riskNarrative は攻撃者視点の筋書き（どこから入り、何を足がかりに、最終的に何を',
  '  取られるか）を中心に据える。該当する攻撃チェーンがあればそれを軸にする。',
  '- trendNarrative は前回との差分（新規・解消・継続）が渡されたときだけ書く。',
  '  比較材料が渡されていなければ null を返す。',
  '- 断定できないことは断定しない。確信度が低い指摘は「可能性がある」と書く。',
].join('\n');

/** LLMに渡す事実の要約（トークンを抑えるため厳しく間引く） */
export interface NarrativeInput {
  context: ScanContext;
  summary: ScanSummary;
  ranked: readonly FindingSignal[];
  chains: readonly AttackChain[];
  actions: readonly PrioritizedAction[];
  hasBaseline: boolean;
  errors: readonly string[];
}

const MAX_FINDINGS_IN_DIGEST = 15;
const MAX_CHAINS_IN_DIGEST = 5;
const MAX_ACTIONS_IN_DIGEST = 8;

/** LLMに渡すダイジェストを組み立てる */
function buildDigest(input: NarrativeInput): string {
  const { context, summary, ranked, chains, actions } = input;
  const lines: string[] = [];

  lines.push('## 対象リポジトリ');
  lines.push(`- パス: ${context.repoRoot}`);
  if (context.languages.length > 0) {
    lines.push(
      `- 言語: ${context.languages
        .slice(0, 5)
        .map((l) => `${l.name}(${Math.round(l.ratio * 100)}%)`)
        .join(', ')}`,
    );
  }
  if (context.frameworks.length > 0) {
    lines.push(`- フレームワーク: ${context.frameworks.slice(0, 8).map((f) => f.name).join(', ')}`);
  }
  lines.push(`- 走査ファイル数: ${summary.filesScanned}`);
  lines.push(`- 依存パッケージ数: ${context.dependencies.length}`);
  lines.push(`- 外部からの入口(エントリポイント)数: ${context.entryPoints.length}`);
  if (context.entryPoints.length > 0) {
    lines.push(
      `- 主な入口: ${context.entryPoints
        .slice(0, 8)
        .map((e) => `${e.kind}:${e.identifier}`)
        .join(', ')}`,
    );
  }

  lines.push('');
  lines.push('## 集計（機械算出・改変禁止）');
  lines.push(`- 検出件数: ${summary.totalFindings}`);
  lines.push(
    `- 深刻度別: ${SEVERITY_ORDER.map(
      (s) => `${SEVERITY_LABEL_JA[s]}=${summary.bySeverity[s] ?? 0}`,
    ).join(' / ')}`,
  );
  lines.push(`- 最大CVSS: ${summary.maxCvssScore}`);
  lines.push(`- 攻撃チェーン数: ${summary.chainCount}`);
  lines.push(`- 抑制済み: ${summary.suppressedCount}`);
  if (input.hasBaseline) {
    lines.push(
      `- 前回比: 新規=${summary.newCount} / 継続=${summary.persistentCount} / 解消=${summary.fixedCount}`,
    );
  } else {
    lines.push('- 前回比: ベースラインなし（初回スキャン）');
  }

  if (chains.length > 0) {
    lines.push('');
    lines.push('## 攻撃チェーン（優先度順）');
    for (const chain of [...chains]
      .sort((a, b) => b.priorityScore - a.priorityScore)
      .slice(0, MAX_CHAINS_IN_DIGEST)) {
      lines.push(`### ${chain.id}: ${chain.title}`);
      lines.push(`- 起点: ${chain.entryPoint} / 成立可能性: ${chain.likelihood} / 優先度: ${chain.priorityScore}`);
      lines.push(`- 影響: ${truncate(chain.impact, 200)}`);
      const steps = chain.steps
        .slice(0, 8)
        .map((s) => `${s.order}. [${s.attackTactic}] ${truncate(s.description, 90)}`);
      lines.push(`- 手順:\n${steps.map((s) => `  ${s}`).join('\n')}`);
      if (chain.chokePoint) {
        lines.push(`- チョークポイント: ${chain.chokePoint.findingId}（${truncate(chain.chokePoint.rationale, 120)}）`);
      }
    }
  }

  if (ranked.length > 0) {
    lines.push('');
    lines.push('## 主要なFinding（優先度順）');
    for (const signal of ranked.slice(0, MAX_FINDINGS_IN_DIGEST)) {
      const f = signal.finding;
      const chainNote = signal.chainIds.length > 0 ? ` / チェーン: ${signal.chainIds.join(',')}` : '';
      const chokeNote = signal.chokePointChainIds.length > 0 ? ' / チョークポイント' : '';
      lines.push(
        `- ${f.id} [${f.severity} CVSS ${f.cvss?.baseScore ?? 0}] ${f.cwe} ${truncate(f.title, 70)} ` +
          `@ ${f.location.file}:${f.location.startLine} (確信度 ${f.confidence.toFixed(2)}, ${f.diffStatus})${chainNote}${chokeNote}`,
      );
    }
  }

  if (actions.length > 0) {
    lines.push('');
    lines.push('## 機械算出済みの優先対応順（この順序は変更しない）');
    for (const action of actions.slice(0, MAX_ACTIONS_IN_DIGEST)) {
      lines.push(
        `${action.order}. ${truncate(action.action, 120)} ` +
          `[工数:${action.effort} / 解消Finding ${action.resolves.findings.length}件 / 遮断チェーン ${action.resolves.chains.length}本]`,
      );
    }
  }

  if (input.errors.length > 0) {
    lines.push('');
    lines.push('## スキャン中のエラー（部分的失敗）');
    for (const err of input.errors.slice(0, 5)) lines.push(`- ${truncate(err, 200)}`);
  }

  return lines.join('\n');
}

/** LLM呼び出しが失敗した理由を人が読める形に */
function describeLlmFailure(reason: string, detail?: string | null): string {
  switch (reason) {
    case 'refusal':
      return `LLMによる文章生成が安全分類器に拒否されました${detail ? `（カテゴリ: ${detail}）` : ''}。以下は機械生成の要約です。`;
    case 'budget-exhausted':
      return 'トークン予算を使い切ったため、文章生成は機械生成の要約に切り替えました。';
    default:
      return `LLMによる文章生成に失敗したため機械生成の要約に切り替えました${detail ? `（${detail}）` : ''}。`;
  }
}

// ---------------------------------------------------------------------------
// フォールバック（機械生成の文章）
// ---------------------------------------------------------------------------

/** Findingが0件のときの文面 */
function cleanExecutiveSummary(summary: ScanSummary): string {
  const parts = [
    `${summary.filesScanned} ファイルを走査し、対応を要する脆弱性は検出されませんでした。`,
  ];
  if (summary.suppressedCount > 0) {
    parts.push(`抑制リストにより ${summary.suppressedCount} 件が対象外となっています。`);
  }
  if (summary.fixedCount > 0) {
    parts.push(`前回スキャンで指摘されていた ${summary.fixedCount} 件は解消済みです。`);
  }
  parts.push('ただしこれは「脆弱性が存在しないこと」の証明ではなく、今回の観点と対象範囲では見つからなかったという意味です。');
  parts.push('引き続き差分スキャンを継続し、依存関係の更新時には再走査してください。');
  return parts.join('');
}

/** 経営層向け要約の機械生成版 */
function fallbackExecutiveSummary(
  summary: ScanSummary,
  chains: readonly AttackChain[],
  actions: readonly PrioritizedAction[],
): string {
  if (summary.totalFindings === 0) return cleanExecutiveSummary(summary);

  const critical = summary.bySeverity.critical ?? 0;
  const high = summary.bySeverity.high ?? 0;
  const urgent = critical + high;

  const sentences: string[] = [];
  sentences.push(
    `${summary.filesScanned} ファイルの走査で ${summary.totalFindings} 件のセキュリティ上の問題を検出しました` +
      `（うち至急対応すべき「緊急・高」が ${urgent} 件）。`,
  );

  const topChain = [...chains].sort((a, b) => b.priorityScore - a.priorityScore)[0];
  if (topChain) {
    sentences.push(
      `特に注意が必要なのは、${topChain.entryPoint} を起点として` +
        `${truncate(topChain.impact, 80)} に至る攻撃経路が ${summary.chainCount} 本成立しうる点です` +
        `（成立可能性: ${likelihoodJa(topChain.likelihood)}）。`,
    );
  } else if (summary.maxCvssScore > 0) {
    sentences.push(
      `最も深刻なものは CVSS ${summary.maxCvssScore} で、悪用された場合の影響は限定的とは言えません。`,
    );
  }

  const first = actions[0];
  if (first) {
    sentences.push(
      `まず着手すべきは「${truncate(first.action, 70)}」で、これだけで ` +
        `${first.resolves.findings.length} 件の問題` +
        (first.resolves.chains.length > 0 ? `と ${first.resolves.chains.length} 本の攻撃経路` : '') +
        'に対処できます。',
    );
  }

  if (summary.newCount > 0 && (summary.persistentCount > 0 || summary.fixedCount > 0)) {
    sentences.push(
      `前回からの差分では新規 ${summary.newCount} 件・継続 ${summary.persistentCount} 件・解消 ${summary.fixedCount} 件で、` +
        (summary.newCount > summary.fixedCount ? 'リスクは増加傾向にあります。' : 'リスクは縮小傾向にあります。'),
    );
  } else {
    sentences.push('対応の要否と期限を、下記の優先順位に沿って判断してください。');
  }

  return sentences.join('');
}

/** リスク全体像の機械生成版 */
function fallbackRiskNarrative(
  summary: ScanSummary,
  ranked: readonly FindingSignal[],
  chains: readonly AttackChain[],
  context: ScanContext,
): string {
  if (summary.totalFindings === 0) {
    return (
      `今回の走査範囲（${summary.filesScanned} ファイル、依存 ${context.dependencies.length} 件）では、` +
      '外部入力が危険なシンクへ到達する経路は確認できませんでした。' +
      '攻撃者が足がかりにできる明確な弱点は見つかっていませんが、' +
      '解析対象外のファイルや実行時の設定に依存する問題は本スキャンの範囲外です。'
    );
  }

  const paragraphs: string[] = [];
  const sorted = [...chains].sort((a, b) => b.priorityScore - a.priorityScore);
  const top = sorted[0];

  if (top) {
    const stepText = top.steps
      .slice(0, 5)
      .map((s) => truncate(s.description, 60))
      .join(' → ');
    paragraphs.push(
      `攻撃者の視点で見ると、このコードベースの最も現実的な侵入シナリオは「${top.title}」です。` +
        `${top.entryPoint} という外部から到達可能な入口を足がかりに、${stepText} という順で権限と情報を広げ、` +
        `最終的に ${truncate(top.impact, 100)} という結果に至ります。` +
        `このシナリオの成立可能性は${likelihoodJa(top.likelihood)}と評価されています。`,
    );
    if (sorted.length > 1) {
      paragraphs.push(
        `同様の経路は全部で ${sorted.length} 本あり、` +
          `${sorted
            .slice(1, 4)
            .map((c) => `「${truncate(c.title, 40)}」`)
            .join('、')}が続きます。` +
          'これらは独立した問題ではなく、同じ入口や同じ欠陥を共有していることが多いため、' +
          '個別に潰すより共通の急所を先に塞ぐほうが効率的です。',
      );
    }
    const choke = ranked.find((s) => s.chokePointChainIds.length > 0);
    if (choke) {
      paragraphs.push(
        `その急所が ${choke.finding.id}（${truncate(choke.finding.title, 50)}、` +
          `${choke.finding.location.file}:${choke.finding.location.startLine}）です。` +
          `ここは ${choke.chokePointChainIds.length} 本のチェーンが共通して通過する地点であり、` +
          '1箇所の修正で複数の攻撃経路を同時に断ち切れます。',
      );
    }
  } else {
    const categories = Object.entries(summary.byCategory)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, count]) => `${name}(${count}件)`)
      .join('、');
    paragraphs.push(
      `検出された ${summary.totalFindings} 件は多段の攻撃経路としては連鎖していませんが、` +
        `${categories} に偏りがあり、同種の実装パターンが繰り返し使われていることを示唆します。` +
        'つまり個別のバグというより、コーディング上の習慣に起因する構造的な弱点です。',
    );
  }

  const entryReachable = ranked.filter((s) => s.finding.dataFlow.length > 0).length;
  paragraphs.push(
    `到達性の観点では、${ranked.length} 件中 ${entryReachable} 件で source から sink までのデータフローが` +
      `示されています。残りは到達経路が未証明であり、実際の悪用可能性は環境依存です。` +
      `外部入口は ${context.entryPoints.length} 箇所あり、これらが攻撃面の実質的な広さを決めています。`,
  );

  return paragraphs.join('\n\n');
}

/** 前回比較コメントの機械生成版 */
function fallbackTrendNarrative(summary: ScanSummary): string {
  const { newCount, fixedCount, persistentCount } = summary;
  const parts: string[] = [
    `前回スキャンとの比較では、新規 ${newCount} 件・継続 ${persistentCount} 件・解消 ${fixedCount} 件でした。`,
  ];

  if (newCount === 0 && fixedCount > 0) {
    parts.push('新規の指摘はなく、既存の問題が着実に減っています。良い傾向です。');
  } else if (newCount > fixedCount) {
    parts.push(
      `解消より新規のほうが ${newCount - fixedCount} 件多く、負債は増加しています。` +
        '新規分は変更箇所に紐づく可能性が高いため、直近のコミットを重点的に確認してください。',
    );
  } else if (newCount < fixedCount) {
    parts.push(`解消が新規を ${fixedCount - newCount} 件上回っており、全体としては改善しています。`);
  } else if (newCount > 0) {
    parts.push('新規と解消が同数で、総量は横ばいです。');
  }

  if (persistentCount > 0) {
    parts.push(
      `継続している ${persistentCount} 件は前回も指摘されたまま残っているものです。` +
        '放置期間が長いものほどトリアージ済みか（受容判断が済んでいるか）を確認してください。',
    );
  }
  return parts.join('');
}

/** 完全に機械生成のナラティブ一式 */
export function buildFallbackNarrative(
  input: NarrativeInput,
  keyFindings: string[],
): Narrative {
  return {
    executiveSummary: fallbackExecutiveSummary(input.summary, input.chains, input.actions),
    keyFindings,
    riskNarrative: fallbackRiskNarrative(input.summary, input.ranked, input.chains, input.context),
    trendNarrative: input.hasBaseline ? fallbackTrendNarrative(input.summary) : null,
  };
}

// ---------------------------------------------------------------------------
// LLM呼び出し
// ---------------------------------------------------------------------------

export interface NarrativeOutcome {
  narrative: Narrative;
  /** LLMで生成できたか */
  generatedByLlm: boolean;
  /** フォールバックした場合の理由（レポートに注記する） */
  fallbackReason?: string;
}

/**
 * LLMで文章を生成する。失敗しても例外は投げず、機械生成にフォールバックする。
 */
export async function generateNarrative(
  input: NarrativeInput,
  keyFindings: string[],
  llm: Pick<LlmClient, 'structured'>,
  config: VulnScanConfig,
): Promise<NarrativeOutcome> {
  const fallback = buildFallbackNarrative(input, keyFindings);

  // 書くことが無いならLLMを呼ぶだけ無駄
  if (input.summary.totalFindings === 0 && input.chains.length === 0) {
    return {
      narrative: fallback,
      generatedByLlm: false,
      fallbackReason: '検出結果が無いため、文章生成は機械生成の定型文を使用しました。',
    };
  }

  const digest = buildDigest(input);
  const cacheKey = createHash('sha256').update(digest).digest('hex');

  let result;
  try {
    result = await llm.structured({
      system: SYSTEM_PROMPT,
      user: [
        '以下はスキャン結果の機械集計です。これを元にレポートの文章を書いてください。',
        '',
        digest,
      ].join('\n'),
      schema: NarrativeSchema,
      schemaName: 'VulnScanNarrative',
      cacheKey: `reporter-narrative:${cacheKey}`,
      // 文章生成は推論の深さより読みやすさが効くので効率重視の effort に落とす
      effort: config.llm.effort === 'max' ? 'high' : config.llm.effort,
      maxTokens: Math.min(config.llm.maxTokens, 8000),
    });
  } catch (err) {
    // アダプタは結果型で返す設計だが、想定外の例外でもレポートは出す
    return {
      narrative: fallback,
      generatedByLlm: false,
      fallbackReason: describeLlmFailure('error', String(err)),
    };
  }

  if (!result.ok) {
    const detail = result.reason === 'refusal' ? result.category : result.reason === 'error' ? result.error : null;
    return {
      narrative: fallback,
      generatedByLlm: false,
      fallbackReason: describeLlmFailure(result.reason, detail),
    };
  }

  return { narrative: mergeWithFallback(result.value, fallback, input.hasBaseline), generatedByLlm: true };
}

/**
 * LLM出力の空フィールドを機械生成で埋める。
 * 構造化出力でも中身が空文字であることはありうる。
 */
function mergeWithFallback(value: Narrative, fallback: Narrative, hasBaseline: boolean): Narrative {
  const trimmedSummary = (value.executiveSummary ?? '').trim();
  const trimmedRisk = (value.riskNarrative ?? '').trim();
  const keyFindings = (value.keyFindings ?? []).map((s) => s.trim()).filter((s) => s !== '');
  const trend = (value.trendNarrative ?? '').trim();

  return {
    executiveSummary: trimmedSummary !== '' ? trimmedSummary : fallback.executiveSummary,
    riskNarrative: trimmedRisk !== '' ? trimmedRisk : fallback.riskNarrative,
    keyFindings: keyFindings.length > 0 ? keyFindings.slice(0, 8) : fallback.keyFindings,
    trendNarrative: !hasBaseline ? null : trend !== '' ? trend : fallback.trendNarrative,
  };
}
