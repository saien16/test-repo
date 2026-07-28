/**
 * ④ キルチェーン分析のエントリポイント。
 *
 * 流れ:
 *   1. 候補絞り込み（純粋関数 / grouping.ts）— 呼び出しグラフ到達性とデータフローで束ねる
 *   2. 候補グループごとに LLM へ連鎖推論を依頼（mapPool で並列化）
 *   3. ATT&CK マッピングの検証・補正（attack-mapping.ts）
 *   4. 連鎖を考慮した再優先度付けとチョークポイント選定（scoring.ts）
 *
 * 個々のグループの失敗は errors に積んで全体を止めない。
 * budget-exhausted のみ以降の呼び出しを打ち切る。
 */

import { createHash } from 'node:crypto';
import type { ScanContext } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import type { VulnScanConfig } from '../types/config.js';
import type { AttackChain, ChainStep } from '../types/killchain.js';
import type { LlmClient } from '../llm/client.js';
import { mapPool } from '../llm/pool.js';
import { normalizeCwe, reconcileSteps, type RawChainStep } from './attack-mapping.js';
import { buildCandidateGroups, type CandidateGroup, type GroupingOptions } from './grouping.js';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import { KillChainResponseSchema, type LlmAttackChain } from './schema.js';
import {
  scoreChain,
  selectChokePoint,
  type ChokePointCandidate,
  type ScoringInput,
} from './scoring.js';

export * from './attack-mapping.js';
export * from './grouping.js';
export * from './reachability.js';
export * from './scoring.js';
export { buildSystemPrompt, buildUserPrompt } from './prompt.js';
export { KillChainResponseSchema, AttackChainSchema, ChainStepSchema } from './schema.js';

/** 1グループから採用するシナリオ数の上限 */
const MAX_CHAINS_PER_GROUP = 3;

export interface AnalyzeKillChainsOptions {
  /** 候補絞り込みの調整 */
  grouping?: GroupingOptions;
}

/** 連鎖の id を内容から決定的に導出する（再実行で id が揺れないように） */
function chainId(groupId: string, title: string, findingIds: readonly string[]): string {
  const digest = createHash('sha256')
    .update(groupId)
    .update('\0')
    .update(title)
    .update('\0')
    .update([...findingIds].join(','))
    .digest('hex');
  return `chain-${digest.slice(0, 12)}`;
}

/** LLM 出力 1 件を検証・補正して AttackChain に変換する。成立しないなら null。 */
function materializeChain(
  llmChain: LlmAttackChain,
  group: CandidateGroup,
  findingsById: ReadonlyMap<string, Finding>,
): { chain: AttackChain; corrections: string[] } | null {
  if (llmChain.chainViable === false) return null;

  const rawSteps: RawChainStep[] = (llmChain.steps ?? []).map((s) => ({
    findingId: s.findingId,
    killChainPhase: s.killChainPhase,
    attackTactic: s.attackTactic,
    attackTechnique: s.attackTechnique,
    description: s.description,
    preconditions: s.preconditions,
  }));

  // グループに含まれる Finding のみを正当な参照とする（他グループの id 流用も弾く）
  const allowed = new Map<string, Finding>();
  for (const id of group.findingIds) {
    const f = findingsById.get(id);
    if (f !== undefined) allowed.set(id, f);
  }

  const { steps, corrections } = reconcileSteps(rawSteps, allowed);
  if (steps.length === 0) return null;
  // Finding に一切紐づかない連鎖は根拠が無いので採用しない
  if (steps.every((s) => s.findingId === null)) return null;

  const usedFindings = uniqueFindings(steps, allowed);
  const scoring = buildScoringInput(steps, usedFindings, group, llmChain.likelihood);
  const scored = scoreChain(scoring);

  const candidates: ChokePointCandidate[] = steps
    .map((s) => {
      if (s.findingId === null) return null;
      const f = allowed.get(s.findingId);
      if (f === undefined) return null;
      const c: ChokePointCandidate = {
        findingId: f.id,
        order: s.order,
        cwe: normalizeCwe(f.cwe),
        hasFixedVersion: f.affectedPackage?.fixedVersion !== undefined,
      };
      return c;
    })
    .filter((c): c is ChokePointCandidate => c !== null);

  const picked = selectChokePoint(candidates, steps.length, llmChain.chokePointFindingId ?? null);
  const chokePoint: AttackChain['chokePoint'] =
    picked === null
      ? null
      : {
          findingId: picked.findingId,
          rationale:
            picked.findingId === llmChain.chokePointFindingId &&
            typeof llmChain.chokePointRationale === 'string' &&
            llmChain.chokePointRationale.trim() !== ''
              ? llmChain.chokePointRationale.trim()
              : `連鎖の上流（${picked.score.upstreamness.toFixed(2)}）かつ修正容易性が高い（${picked.score.ease.toFixed(2)}）ため、ここを塞ぐと以降のステップが成立しなくなる。`,
        };

  const title =
    typeof llmChain.title === 'string' && llmChain.title.trim() !== ''
      ? llmChain.title.trim()
      : `${group.entryPointId} を起点とする攻撃連鎖`;

  const entryPoint =
    group.entryPoint !== null
      ? group.entryPoint.identifier
      : typeof llmChain.entryPoint === 'string' && llmChain.entryPoint.trim() !== ''
        ? llmChain.entryPoint.trim()
        : group.entryPointId;

  const chain: AttackChain = {
    id: chainId(group.id, title, steps.map((s) => s.findingId ?? '-')),
    title,
    entryPoint,
    steps,
    impact:
      typeof llmChain.impact === 'string' && llmChain.impact.trim() !== ''
        ? llmChain.impact.trim()
        : '影響の記述が得られませんでした',
    likelihood: scored.likelihood,
    priorityScore: scored.priorityScore,
    chokePoint,
    reasoning: buildReasoning(llmChain, group, scored.breakdown),
  };

  return { chain, corrections };
}

function uniqueFindings(
  steps: readonly ChainStep[],
  allowed: ReadonlyMap<string, Finding>,
): Finding[] {
  const out = new Map<string, Finding>();
  for (const s of steps) {
    if (s.findingId === null) continue;
    const f = allowed.get(s.findingId);
    if (f !== undefined) out.set(f.id, f);
  }
  return [...out.values()];
}

function buildScoringInput(
  steps: readonly ChainStep[],
  findings: readonly Finding[],
  group: CandidateGroup,
  llmLikelihood: 'high' | 'medium' | 'low',
): ScoringInput {
  const evidenceById = new Map(group.evidence.map((e) => [e.findingId, e]));
  const used = findings.map((f) => f.id);
  const reachableCount = used.filter((id) => evidenceById.get(id)?.reachable === true).length;

  return {
    cvssScores: findings.map((f) => f.cvss?.baseScore ?? 0),
    confidences: findings.map((f) => f.confidence ?? 0.5),
    reachabilityRatio: used.length === 0 ? 0 : reachableCount / used.length,
    exposure: group.exposure,
    llmLikelihood,
    stepCount: steps.length,
    tactics: steps.map((s) => s.attackTactic),
  };
}

function buildReasoning(
  llmChain: LlmAttackChain,
  group: CandidateGroup,
  breakdown: ReturnType<typeof scoreChain>['breakdown'],
): string {
  const llm =
    typeof llmChain.reasoning === 'string' && llmChain.reasoning.trim() !== ''
      ? llmChain.reasoning.trim()
      : '（LLM の根拠テキストが得られませんでした）';
  return [
    llm,
    '',
    `[スコア内訳] 影響=${breakdown.impactScore} / 成立可能性=${breakdown.likelihoodScore} / ` +
      `連鎖シナジー=+${breakdown.synergyBonus} ` +
      `(単体影響 ${breakdown.standaloneImpact} → 連鎖到達点 ${breakdown.terminalImpact})`,
    `[候補抽出] ${group.kind} / 露出度=${group.exposure.toFixed(2)} / ` +
      `到達性証明 ${(group.reachabilityRatio * 100).toFixed(0)}%`,
  ].join('\n');
}

/**
 * ④ キルチェーン分析本体。
 */
export async function analyzeKillChains(
  findings: Finding[],
  ctx: ScanContext,
  llm: LlmClient,
  config: VulnScanConfig,
  options: AnalyzeKillChainsOptions = {},
): Promise<{ chains: AttackChain[]; errors: string[] }> {
  const errors: string[] = [];

  if (config?.killChain !== true) return { chains: [], errors };
  if (!Array.isArray(findings) || findings.length === 0) return { chains: [], errors };

  // 誤検知・対応済みは連鎖の材料にしない
  const active = findings.filter(
    (f) => f.status !== 'false-positive' && f.status !== 'fixed' && f.diffStatus !== 'fixed',
  );
  if (active.length === 0) return { chains: [], errors };

  let groups: CandidateGroup[];
  try {
    groups = buildCandidateGroups(active, ctx, options.grouping);
  } catch (err) {
    errors.push(`候補グループの構築に失敗しました: ${String(err)}`);
    return { chains: [], errors };
  }
  if (groups.length === 0) return { chains: [], errors };

  const findingsById = new Map(active.map((f) => [f.id, f]));
  const system = buildSystemPrompt();
  const concurrency = Math.max(1, config.llm?.concurrency ?? 1);

  // budget-exhausted を検知したら以降のグループは呼ばずに打ち切る
  let budgetExhausted = false;

  const raw = await mapPool(groups, concurrency, async (group) => {
    if (budgetExhausted) return null;

    const user = buildUserPrompt(group, active, ctx);
    const result = await llm.structured({
      system,
      user,
      schema: KillChainResponseSchema,
      schemaName: 'KillChainResponse',
      cacheKey: createHash('sha256').update(group.id).update('\0').update(user).digest('hex'),
    });

    if (!result.ok) {
      if (result.reason === 'budget-exhausted') {
        if (!budgetExhausted) {
          budgetExhausted = true;
          errors.push('トークン予算を使い切ったため、キルチェーン分析を打ち切りました');
        }
        return null;
      }
      if (result.reason === 'refusal') {
        errors.push(
          `キルチェーン推論が拒否されました (group=${group.entryPointId}, category=${result.category ?? '不明'})`,
        );
        return null;
      }
      errors.push(`キルチェーン推論に失敗しました (group=${group.entryPointId}): ${result.error}`);
      return null;
    }

    return { group, response: result.value };
  });

  const chains: AttackChain[] = [];
  const seenChainKeys = new Set<string>();

  for (const item of raw) {
    if (item === null) continue;
    const { group, response } = item;
    const llmChains = Array.isArray(response.chains)
      ? response.chains.slice(0, MAX_CHAINS_PER_GROUP)
      : [];

    for (const llmChain of llmChains) {
      let built: ReturnType<typeof materializeChain>;
      try {
        built = materializeChain(llmChain, group, findingsById);
      } catch (err) {
        errors.push(`連鎖の組み立てに失敗しました (group=${group.entryPointId}): ${String(err)}`);
        continue;
      }
      if (built === null) continue;

      for (const c of built.corrections) {
        errors.push(`[補正] group=${group.entryPointId}: ${c}`);
      }

      // 同一エントリポイント・同一 Finding 列の連鎖は重複とみなす
      const key = `${built.chain.entryPoint}|${built.chain.steps.map((s) => s.findingId ?? '-').join('>')}`;
      if (seenChainKeys.has(key)) continue;
      seenChainKeys.add(key);
      chains.push(built.chain);
    }
  }

  chains.sort((a, b) => b.priorityScore - a.priorityScore || a.id.localeCompare(b.id));
  return { chains, errors };
}

export default analyzeKillChains;
