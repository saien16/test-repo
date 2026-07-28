/**
 * 分析フェーズのうち「機械的に導出できる部分」。
 *
 * ここでやること:
 *   1. Finding × AttackChain の相関を取る（どのチェーンに何回登場するか、
 *      チョークポイントに指定されているか）
 *   2. その相関から優先度スコアを決定的に算出する
 *   3. 「同じ修正で片付く」Findingをまとめて1つのアクションに集約する
 *
 * LLMは一切使わない。同じ入力なら常に同じ順序が出る（レポートの再現性）。
 */

import type { Finding } from '../types/finding.js';
import type { AttackChain } from '../types/killchain.js';
import type { AnalyzedReport } from '../types/report.js';
import { likelihoodJa } from './labels.js';
import { SEVERITY_LABEL_JA, SEVERITY_WEIGHT, isActiveFinding, severityRank } from './severity.js';
import { firstSentence, truncate } from './text.js';

export type PrioritizedAction = AnalyzedReport['prioritizedActions'][number];
export type Effort = PrioritizedAction['effort'];

/** Finding単体に対して、チェーン横断で集めた相関情報 */
export interface FindingSignal {
  finding: Finding;
  /** この Finding を含む攻撃チェーンのID */
  chainIds: string[];
  /** この Finding をチョークポイントに指定しているチェーンのID */
  chokePointChainIds: string[];
  /** 関与するチェーンの最大 priorityScore */
  maxChainPriority: number;
  /** 決定的な優先度スコア（大きいほど先に直すべき） */
  score: number;
}

/**
 * スコアの設計意図（要求された優先順を数値で表現する）:
 *   チョークポイント(1000) > 複数チェーンに登場(300/本) > CVSS(×20) > 深刻度
 * こうすると「単独では高CVSSだが孤立している問題」より
 * 「CVSSは中程度でも複数の攻撃経路の要になっている問題」が上に来る。
 */
const SCORE_CHOKE_POINT = 1000;
const SCORE_PER_CHAIN = 300;
const SCORE_CVSS_FACTOR = 20;
const SCORE_NEW = 30;
const SCORE_CONFIDENCE_FACTOR = 40;

/** Finding と AttackChain を突き合わせて相関シグナルを作る */
export function buildFindingSignals(
  findings: readonly Finding[],
  chains: readonly AttackChain[],
): Map<string, FindingSignal> {
  const signals = new Map<string, FindingSignal>();

  for (const finding of findings) {
    signals.set(finding.id, {
      finding,
      chainIds: [],
      chokePointChainIds: [],
      maxChainPriority: 0,
      score: 0,
    });
  }

  for (const chain of chains) {
    const seen = new Set<string>();
    for (const step of chain.steps) {
      if (step.findingId === null) continue;
      if (seen.has(step.findingId)) continue;
      seen.add(step.findingId);
      const signal = signals.get(step.findingId);
      if (!signal) continue;
      signal.chainIds.push(chain.id);
      if (chain.priorityScore > signal.maxChainPriority) {
        signal.maxChainPriority = chain.priorityScore;
      }
    }
    const choke = chain.chokePoint;
    if (choke) {
      const signal = signals.get(choke.findingId);
      if (signal) {
        signal.chokePointChainIds.push(chain.id);
        if (!signal.chainIds.includes(chain.id)) signal.chainIds.push(chain.id);
        if (chain.priorityScore > signal.maxChainPriority) {
          signal.maxChainPriority = chain.priorityScore;
        }
      }
    }
  }

  for (const signal of signals.values()) {
    signal.score = computeScore(signal);
  }
  return signals;
}

function computeScore(signal: FindingSignal): number {
  const f = signal.finding;
  let score = 0;
  if (signal.chokePointChainIds.length > 0) score += SCORE_CHOKE_POINT;
  score += signal.chainIds.length * SCORE_PER_CHAIN;
  const cvss = typeof f.cvss?.baseScore === 'number' ? f.cvss.baseScore : 0;
  score += cvss * SCORE_CVSS_FACTOR;
  score += SEVERITY_WEIGHT[f.severity] ?? 0;
  if (f.diffStatus === 'new') score += SCORE_NEW;
  score += (Number.isFinite(f.confidence) ? f.confidence : 0) * SCORE_CONFIDENCE_FACTOR;
  score += signal.maxChainPriority;
  return Math.round(score * 100) / 100;
}

/** スコア降順（同点はID昇順で安定化）に並べたシグナル */
export function rankSignals(signals: Map<string, FindingSignal>): FindingSignal[] {
  return [...signals.values()]
    .filter((s) => isActiveFinding(s.finding))
    .sort((a, b) => b.score - a.score || a.finding.id.localeCompare(b.finding.id));
}

// ---------------------------------------------------------------------------
// 修正作業の集約
// ---------------------------------------------------------------------------

/** 修正内容の同一性を判定するための正規化 */
function normalizeRemediation(text: string): string {
  return text
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s　]+/gu, '')
    .replace(/[、。，．,.:;：；()（）「」『』[\]`'"]/gu, '')
    .slice(0, 120);
}

/**
 * 「1回の修正作業」を識別するキー。
 *  - 依存脆弱性はパッケージ単位（1回の更新で複数CVEが消える）
 *  - コード上の問題は CWE × 同一の修正方針（＝同じ直し方）でまとめる
 *  - 修正方針が短すぎて判別不能なら CWE × ファイル でまとめる
 */
function remediationKey(finding: Finding): string {
  const pkg = finding.affectedPackage;
  if (pkg) {
    return `dep:${pkg.ecosystem.toLowerCase()}:${pkg.name.toLowerCase()}`;
  }
  const normalized = normalizeRemediation(finding.remediation ?? '');
  if (normalized.length >= 12) return `code:${finding.cwe}:${normalized}`;
  return `code:${finding.cwe}:${finding.location.file}`;
}

interface ActionGroup {
  key: string;
  kind: 'dependency' | 'code';
  members: FindingSignal[];
}

/** グループ全体のスコア。件数が多いほど「まとめて片付く」ぶん少し加点。 */
function groupScore(group: ActionGroup): number {
  const best = group.members.reduce((max, m) => Math.max(max, m.score), 0);
  return best + Math.min(group.members.length - 1, 5) * 20;
}

/** 難易度の推定（機械的ヒューリスティック） */
const HARD_TO_FIX_CWE = new Set([
  'CWE-284', // 不適切なアクセス制御
  'CWE-285',
  'CWE-862', // 認可の欠落
  'CWE-863', // 不正な認可
  'CWE-639', // IDOR
  'CWE-269', // 権限管理の不備
  'CWE-287', // 不適切な認証
  'CWE-502', // 安全でないデシリアライズ
]);

const EFFORT_LEVELS: Effort[] = ['low', 'medium', 'high'];

function bumpEffort(effort: Effort, steps: number): Effort {
  const index = EFFORT_LEVELS.indexOf(effort);
  const next = Math.min(EFFORT_LEVELS.length - 1, Math.max(0, index + steps));
  return EFFORT_LEVELS[next] ?? effort;
}

function estimateEffort(group: ActionGroup): Effort {
  if (group.kind === 'dependency') {
    const hasFix = group.members.some((m) => Boolean(m.finding.affectedPackage?.fixedVersion));
    // 修正版が出ていればバージョン更新だけで済む。無ければ代替探しや自作パッチが要る。
    return hasFix ? 'low' : 'high';
  }

  const files = new Set(group.members.map((m) => m.finding.location.file));
  let effort: Effort = files.size <= 1 ? 'low' : files.size <= 3 ? 'medium' : 'high';

  // 設計変更を伴いやすいCWEは一段引き上げる
  if (group.members.some((m) => HARD_TO_FIX_CWE.has(m.finding.cwe))) {
    effort = bumpEffort(effort, 1);
  }
  // データフローが長い＝影響範囲が広く、確認コストが高い
  const maxFlow = group.members.reduce((max, m) => Math.max(max, m.finding.dataFlow.length), 0);
  if (maxFlow >= 6) effort = bumpEffort(effort, 1);

  return effort;
}

/** グループの代表Finding（最高スコア） */
function representative(group: ActionGroup): FindingSignal {
  const head = group.members[0];
  if (!head) throw new Error('空のアクショングループは生成されません');
  return group.members.reduce((best, m) => (m.score > best.score ? m : best), head);
}

/** アクション文（何をするか）を機械的に組み立てる */
function buildActionText(group: ActionGroup): string {
  const rep = representative(group).finding;
  if (group.kind === 'dependency') {
    const pkg = rep.affectedPackage;
    if (pkg) {
      const cves = group.members
        .map((m) => m.finding.cve)
        .filter((c): c is string => typeof c === 'string' && c !== '');
      const suffix = cves.length > 0 ? `（${truncate(cves.join(', '), 60)}）` : '';
      if (pkg.fixedVersion) {
        return `${pkg.name} を ${pkg.fixedVersion} 以上へ更新する${suffix}`;
      }
      return `${pkg.name}@${pkg.version} の利用を見直す（修正版が未提供）${suffix}`;
    }
  }
  const sentence = firstSentence(rep.remediation ?? '', 110);
  if (sentence !== '') {
    return `${sentence}（${rep.cwe} / ${rep.location.file}）`;
  }
  return `${truncate(rep.title, 80)} を修正する（${rep.cwe} / ${rep.location.file}）`;
}

/** 根拠文（なぜその順位か）を機械的に組み立てる */
function buildRationale(group: ActionGroup, resolvedChains: string[]): string {
  const rep = representative(group);
  const parts: string[] = [];

  if (rep.chokePointChainIds.length > 0) {
    parts.push(
      `攻撃チェーン ${rep.chokePointChainIds.join(', ')} のチョークポイントに指定されており、` +
        'ここを塞ぐと連鎖そのものが成立しなくなる',
    );
  } else if (rep.chainIds.length >= 2) {
    parts.push(`${rep.chainIds.length} 本の攻撃チェーン（${rep.chainIds.join(', ')}）に登場する要所`);
  } else if (rep.chainIds.length === 1) {
    parts.push(`攻撃チェーン ${rep.chainIds[0] ?? ''} の構成要素`);
  }

  const cvss = rep.finding.cvss?.baseScore;
  if (typeof cvss === 'number' && cvss > 0) {
    parts.push(`CVSS ${cvss.toFixed(1)}（${SEVERITY_LABEL_JA[rep.finding.severity]}）`);
  } else {
    parts.push(`深刻度 ${SEVERITY_LABEL_JA[rep.finding.severity]}`);
  }

  if (group.members.length > 1) {
    const files = new Set(group.members.map((m) => m.finding.location.file));
    parts.push(
      `同一の修正で ${group.members.length} 件のFinding（${files.size} ファイル）を同時に解消できる`,
    );
  }

  if (resolvedChains.length > 0) {
    parts.push(`対応により ${resolvedChains.length} 本の攻撃チェーンが遮断される`);
  }

  const newCount = group.members.filter((m) => m.finding.diffStatus === 'new').length;
  if (newCount > 0 && newCount === group.members.length) {
    parts.push('今回のスキャンで新規に検出された');
  }

  return `${parts.join('。')}。`;
}

/**
 * このアクションで「解決される」チェーンを判定する。
 *  - チョークポイントがグループ内にある → そのチェーンは断ち切れる
 *  - チェーンを構成する全Findingがグループ内にある → 当然解消される
 */
function resolvedChainIds(
  group: ActionGroup,
  chains: readonly AttackChain[],
): string[] {
  const ids = new Set(group.members.map((m) => m.finding.id));
  const result: string[] = [];
  for (const chain of chains) {
    const choke = chain.chokePoint;
    if (choke && ids.has(choke.findingId)) {
      result.push(chain.id);
      continue;
    }
    const stepIds = chain.steps
      .map((s) => s.findingId)
      .filter((id): id is string => id !== null);
    if (stepIds.length > 0 && stepIds.every((id) => ids.has(id))) {
      result.push(chain.id);
    }
  }
  return result;
}

/** 生成するアクションの上限。これ以上並べても意思決定の役に立たない。 */
const MAX_ACTIONS = 25;

/**
 * 優先対応アクションを機械的に導出する。
 *
 * 順序は「チョークポイント → 複数チェーンに登場 → CVSS高」の優先度で決まり、
 * 同じ修正で解決する Finding は1つのアクションに集約される。
 */
export function buildPrioritizedActions(
  findings: readonly Finding[],
  chains: readonly AttackChain[],
  signals: Map<string, FindingSignal>,
): PrioritizedAction[] {
  const groups = new Map<string, ActionGroup>();

  for (const finding of findings) {
    // 既に直っている / 誤検知 / 受容済みのものは「やること」ではない
    if (!isActiveFinding(finding)) continue;
    if (finding.status === 'accepted' || finding.status === 'fixed') continue;
    const signal = signals.get(finding.id);
    if (!signal) continue;

    const key = remediationKey(finding);
    const existing = groups.get(key);
    if (existing) {
      existing.members.push(signal);
    } else {
      groups.set(key, {
        key,
        kind: finding.affectedPackage ? 'dependency' : 'code',
        members: [signal],
      });
    }
  }

  const ordered = [...groups.values()].sort((a, b) => {
    const diff = groupScore(b) - groupScore(a);
    if (diff !== 0) return diff;
    if (b.members.length !== a.members.length) return b.members.length - a.members.length;
    return a.key.localeCompare(b.key);
  });

  return ordered.slice(0, MAX_ACTIONS).map((group, index) => {
    const chainIds = resolvedChainIds(group, chains);
    const findingIds = [...group.members]
      .sort((a, b) => b.score - a.score || a.finding.id.localeCompare(b.finding.id))
      .map((m) => m.finding.id);
    return {
      order: index + 1,
      action: buildActionText(group),
      resolves: { findings: findingIds, chains: chainIds },
      effort: estimateEffort(group),
      rationale: buildRationale(group, chainIds),
    };
  });
}

/**
 * 「今回のスキャンで最も重要な所見」を機械的に組み立てる。
 * LLMが所見を返さなかった場合のフォールバックであり、
 * 数字と固有名詞だけで構成されるため常に事実として正しい。
 */
export function buildKeyFindings(
  ranked: readonly FindingSignal[],
  chains: readonly AttackChain[],
  actions: readonly PrioritizedAction[],
  limit = 6,
): string[] {
  const lines: string[] = [];

  const topChain = [...chains].sort((a, b) => b.priorityScore - a.priorityScore)[0];
  if (topChain) {
    lines.push(
      `最優先の攻撃シナリオは「${topChain.title}」（起点: ${topChain.entryPoint}、` +
        `成立可能性: ${likelihoodJa(topChain.likelihood)}、優先度 ${topChain.priorityScore}）。`,
    );
  }

  const choke = ranked.find((s) => s.chokePointChainIds.length > 0);
  if (choke) {
    lines.push(
      `${choke.finding.id}「${truncate(choke.finding.title, 50)}」は ` +
        `${choke.chokePointChainIds.length} 本のチェーンのチョークポイントであり、` +
        'ここ1点の修正で連鎖を断てる。',
    );
  }

  const multi = ranked.find((s) => s.chainIds.length >= 2 && s !== choke);
  if (multi) {
    lines.push(
      `${multi.finding.id}「${truncate(multi.finding.title, 50)}」は ` +
        `${multi.chainIds.length} 本の攻撃経路に共通して現れる。`,
    );
  }

  const worst = [...ranked].sort(
    (a, b) =>
      (b.finding.cvss?.baseScore ?? 0) - (a.finding.cvss?.baseScore ?? 0) ||
      severityRank(b.finding.severity) - severityRank(a.finding.severity),
  )[0];
  if (worst && (worst.finding.cvss?.baseScore ?? 0) > 0) {
    lines.push(
      `最大CVSSは ${worst.finding.cvss.baseScore.toFixed(1)}（${worst.finding.id} / ` +
        `${worst.finding.cwe} / ${worst.finding.location.file}:${worst.finding.location.startLine}）。`,
    );
  }

  const bundled = actions.find((a) => a.resolves.findings.length >= 2);
  if (bundled) {
    lines.push(
      `「${truncate(bundled.action, 60)}」は単独で ${bundled.resolves.findings.length} 件の` +
        'Findingを解消するため、費用対効果が高い。',
    );
  }

  const newOnes = ranked.filter((s) => s.finding.diffStatus === 'new').length;
  if (newOnes > 0) {
    lines.push(`今回の差分で新規に ${newOnes} 件のFindingが増えている。`);
  }

  if (lines.length === 0) {
    lines.push('対応を要するFindingは検出されませんでした。');
  }
  return lines.slice(0, limit);
}
