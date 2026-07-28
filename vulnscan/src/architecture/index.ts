/**
 * ⑤ システムアーキテクチャ・デプロイメントスタック推定のエントリポイント。
 *
 * 流れ:
 *   1. マニフェスト探索と事実収集（決定的・引用付き / collect.ts）
 *   2. 事実だけでモデル骨格を組み立てる（model.ts）
 *   3. 事実では決まらない項目（様式・露出度・機微度・認証・データフロー）を
 *      LLM に推測させる（prompt.ts / schema.ts）
 *   4. LLM が返した引用の実在を検証し、捏造分を落とす（verify.ts）
 *   5. 事実/推測/仮定の内訳を集計して返す
 *
 * 重要な性質: 3 以降が失敗しても 2 の結果（事実部分）は必ず残る。
 * 推測が得られないことと、事実が失われることは別問題として扱う。
 */

import { createHash } from 'node:crypto';
import type {
  ArchitectureComponent,
  ArchitectureModel,
  ComponentDataFlow,
  DataSensitivity,
  DeploymentStack,
} from '../types/architecture.js';
import type { VulnScanConfig } from '../types/config.js';
import type { ScanContext } from '../types/context.js';
import {
  assumed,
  type Claim,
  inferred,
  summarizeEvidence,
} from '../types/evidence.js';
import type { LlmClient } from '../llm/client.js';
import { collectFacts } from './collect.js';
import { createNodeFileSystem, type RepoFileSystem } from './discover.js';
import type { FactSet } from './facts.js';
import { buildDraft, type DraftModel } from './model.js';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import {
  ArchitectureResponseSchema,
  type ArchitectureResponse,
  type LlmComponentJudgement,
} from './schema.js';
import { type CitationIndex, verifyCitations } from './verify.js';

export * from './facts.js';
export * from './discover.js';
export * from './collect.js';
export * from './model.js';
export * from './verify.js';
export { buildSystemPrompt, buildUserPrompt, quotableFiles } from './prompt.js';
export {
  ArchitectureResponseSchema,
  ComponentJudgementSchema,
  DataFlowJudgementSchema,
  type ArchitectureResponse,
} from './schema.js';

export interface InferArchitectureOptions {
  /** ファイルアクセスの差し替え（テスト用）。既定は実ファイルシステム */
  fs?: RepoFileSystem;
}

/** 型付きの判断（LLM 出力の共通形） */
interface LlmJudgement<T> {
  value: T;
  confidence: number;
  reasoning: string;
  alternatives: string[];
  basis: Array<{ file: string; line: number | null; excerpt: string | null }>;
}

/** モデル内の全 Claim を集める（内訳集計用） */
export function collectClaims(
  style: Claim<unknown>,
  components: readonly ArchitectureComponent[],
  dataFlows: readonly ComponentDataFlow[],
  deployment: DeploymentStack,
): Array<Claim<unknown>> {
  const claims: Array<Claim<unknown>> = [style];
  for (const c of components) {
    claims.push(c.technology, c.exposure, c.dataSensitivity, c.requiresAuthentication);
  }
  for (const f of dataFlows) {
    claims.push(f.protocol, f.crossesTrustBoundary);
  }
  claims.push(
    deployment.runtime,
    deployment.containerization,
    deployment.platform,
    deployment.cloudProvider,
    deployment.cicd,
    deployment.ingress,
    deployment.secretsManagement,
    deployment.iac,
  );
  return claims;
}

/** 値を人が読める文字列にする（対立仮説の記述に使う） */
function claimValueText(value: unknown): string {
  return Array.isArray(value) ? value.join(', ') : String(value);
}

/**
 * 既存の Claim と LLM の Claim を突き合わせて採用する方を選ぶ。
 *
 *   - observed は決して上書きしない（事実 > 推測）
 *   - assumed は推測で上書きしてよい（根拠なし < 根拠あり）
 *   - inferred 同士は確信度の高い方を採り、負けた方を対立仮説として残す
 */
export function preferClaim<T>(current: Claim<T>, candidate: Claim<T>): Claim<T> {
  if (current.provenance.kind === 'observed') return current;
  if (candidate.provenance.kind === 'observed') return candidate;
  if (current.provenance.kind === 'assumed') return candidate;
  if (candidate.provenance.kind === 'assumed') return current;

  const currentConfidence = current.provenance.confidence;
  const candidateConfidence = candidate.provenance.confidence;
  const winner = candidateConfidence > currentConfidence ? candidate : current;
  const loser = winner === candidate ? current : candidate;
  if (winner.provenance.kind !== 'inferred' || loser.provenance.kind !== 'inferred') return winner;

  const loserText = claimValueText(loser.value);
  if (loserText === claimValueText(winner.value)) return winner;

  return {
    value: winner.value,
    provenance: {
      ...winner.provenance,
      alternatives: [
        ...(winner.provenance.alternatives ?? []),
        `${loserText} の可能性（${loser.provenance.inferredBy === 'llm' ? 'LLM' : '機械的'}推測 確信度 ${loser.provenance.confidence.toFixed(2)}: ${loser.provenance.reasoning}）`,
      ],
    },
  };
}

/** LLM の判断を Claim に変換する。引用は実在検証を通したものだけ残す */
function toLlmClaim<T>(
  judgement: LlmJudgement<T> | undefined,
  index: CitationIndex,
  errors: string[],
  label: string,
): Claim<T> | null {
  if (judgement === undefined || judgement === null) return null;

  const { citations, rejected } = verifyCitations(judgement.basis, index);
  for (const message of rejected) errors.push(`[引用検証] ${label}: ${message}`);

  const rawCount = Array.isArray(judgement.basis) ? judgement.basis.length : 0;
  // 引用が全部捏造だった場合、その推測は「根拠のない推測」に格下げする
  const allFabricated = rawCount > 0 && citations.length === 0;
  const confidence =
    typeof judgement.confidence === 'number' && Number.isFinite(judgement.confidence)
      ? judgement.confidence
      : 0.3;

  const reasoning =
    typeof judgement.reasoning === 'string' && judgement.reasoning.trim() !== ''
      ? judgement.reasoning.trim()
      : '（LLM が理由を返しませんでした）';

  return inferred(judgement.value, {
    confidence: allFabricated ? confidence * 0.5 : confidence,
    inferredBy: 'llm',
    basis: citations,
    reasoning: allFabricated
      ? `${reasoning}\n※ LLM が挙げた引用はいずれも実在しなかったため破棄し、確信度を下げた。`
      : reasoning,
    alternatives: Array.isArray(judgement.alternatives)
      ? judgement.alternatives.filter((a): a is string => typeof a === 'string' && a.trim() !== '')
      : [],
  });
}

/** LLM の判断をモデル骨格に反映する */
export function applyLlmResponse(
  draft: DraftModel,
  response: ArchitectureResponse,
  index: CitationIndex,
  errors: string[],
): void {
  const styleClaim = toLlmClaim(response.style as LlmJudgement<never>, index, errors, 'style');
  if (styleClaim !== null) draft.style = preferClaim(draft.style, styleClaim);

  const byId = new Map(draft.components.map((c) => [c.id, c]));
  for (const judgement of response.components ?? []) {
    const component = byId.get(String((judgement as LlmComponentJudgement).componentId ?? ''));
    if (component === undefined) {
      errors.push(
        `[LLM] 存在しない構成要素 id を参照したため無視しました: ${String(judgement?.componentId)}`,
      );
      continue;
    }
    const label = `component=${component.id}`;

    const exposure = toLlmClaim(
      judgement.exposure as LlmJudgement<ArchitectureComponent['exposure']['value']>,
      index,
      errors,
      `${label}/exposure`,
    );
    if (exposure !== null) component.exposure = preferClaim(component.exposure, exposure);

    const sensitivityJudgement = judgement.dataSensitivity as
      | LlmJudgement<DataSensitivity[]>
      | undefined;
    if (sensitivityJudgement !== undefined) {
      const values = Array.isArray(sensitivityJudgement.value)
        ? sensitivityJudgement.value
        : ['unknown' as const];
      const sensitivity = toLlmClaim(
        { ...sensitivityJudgement, value: values.length > 0 ? values : ['unknown' as const] },
        index,
        errors,
        `${label}/dataSensitivity`,
      );
      if (sensitivity !== null) {
        component.dataSensitivity = preferClaim(component.dataSensitivity, sensitivity);
      }
    }

    const auth = toLlmClaim(
      judgement.requiresAuthentication as LlmJudgement<boolean>,
      index,
      errors,
      `${label}/requiresAuthentication`,
    );
    if (auth !== null) {
      component.requiresAuthentication = preferClaim(component.requiresAuthentication, auth);
    }
  }

  for (const judgement of response.dataFlows ?? []) {
    const fromId = String(judgement?.fromId ?? '');
    const toId = String(judgement?.toId ?? '');
    if (!byId.has(fromId) || !byId.has(toId) || fromId === toId) {
      errors.push(`[LLM] 解決できないデータフローを無視しました: ${fromId} -> ${toId}`);
      continue;
    }
    const protocol = toLlmClaim(
      judgement.protocol as LlmJudgement<string>,
      index,
      errors,
      `flow=${fromId}->${toId}/protocol`,
    );
    const crosses = toLlmClaim(
      judgement.crossesTrustBoundary as LlmJudgement<boolean>,
      index,
      errors,
      `flow=${fromId}->${toId}/crossesTrustBoundary`,
    );
    const existing = draft.dataFlows.find((f) => f.fromId === fromId && f.toId === toId);
    if (existing !== undefined) {
      if (protocol !== null) existing.protocol = preferClaim(existing.protocol, protocol);
      if (crosses !== null) {
        existing.crossesTrustBoundary = preferClaim(existing.crossesTrustBoundary, crosses);
      }
      continue;
    }
    draft.dataFlows.push({
      fromId,
      toId,
      protocol:
        protocol ?? assumed('不明', 'LLM がプロトコルを返さなかったため不明とした。'),
      crossesTrustBoundary:
        crosses ??
        assumed(false, 'LLM が信頼境界の判断を返さなかったため既定値 false を採用した（未確認）。'),
    });
  }

  for (const unknown of response.unknowns ?? []) {
    if (typeof unknown === 'string' && unknown.trim() !== '') {
      draft.gaps.push(`[LLM が判断できなかった点] ${unknown.trim()}`);
    }
  }
}

/** 事実収集も推測も行わない最小モデル */
function minimalModel(reason: string): ArchitectureModel {
  const style = assumed<ArchitectureModel['style']['value']>('unknown', reason);
  const deployment: DeploymentStack = {
    runtime: assumed('unknown', reason),
    containerization: assumed('unknown', reason),
    platform: assumed('unknown', reason),
    cloudProvider: assumed('unknown', reason),
    cicd: assumed('unknown', reason),
    ingress: assumed('unknown', reason),
    secretsManagement: assumed('unknown', reason),
    iac: assumed('unknown', reason),
  };
  return {
    style,
    components: [],
    dataFlows: [],
    deployment,
    evidence: summarizeEvidence(collectClaims(style, [], [], deployment)),
    inspectedManifests: [],
    gaps: [reason],
  };
}

/** 推測の欠落を gaps に書き出す */
function appendCoverageGaps(model: ArchitectureModel): void {
  const unknownExposure = model.components.filter(
    (c) => c.exposure.provenance.kind === 'assumed' || c.exposure.value === 'unknown',
  );
  if (unknownExposure.length > 0) {
    model.gaps.push(
      `露出度を判定できなかった構成要素: ${unknownExposure.map((c) => c.id).join(', ')}（ネットワーク設定がリポジトリ内に無いため）`,
    );
  }
  const unknownSensitivity = model.components.filter((c) =>
    (c.dataSensitivity.value ?? []).includes('unknown'),
  );
  if (unknownSensitivity.length > 0) {
    model.gaps.push(
      `扱うデータの機微度を判定できなかった構成要素: ${unknownSensitivity.map((c) => c.id).join(', ')}`,
    );
  }
  if (model.evidence.observed === 0) {
    model.gaps.push(
      '引用可能な事実を 1 件も収集できなかった。このモデルはすべて推測・仮定で構成されている。',
    );
  }
}

/** 骨格 + 収集結果から最終モデルを作る */
function finalize(draft: DraftModel, factSet: FactSet): ArchitectureModel {
  const claims = collectClaims(draft.style, draft.components, draft.dataFlows, draft.deployment);
  const model: ArchitectureModel = {
    style: draft.style,
    components: draft.components,
    dataFlows: draft.dataFlows,
    deployment: draft.deployment,
    evidence: summarizeEvidence(claims),
    inspectedManifests: [...factSet.inspected].sort(),
    gaps: draft.gaps,
  };
  appendCoverageGaps(model);
  return model;
}

/**
 * ⑤ アーキテクチャ推定本体。
 *
 * config.architecture が false のときは LLM を呼ばず最小モデルを返す。
 * LLM が拒否・予算切れ・エラーの場合は、ヒューリスティックで得た事実のみの
 * モデルを返し、失敗理由を errors に積む。
 */
export async function inferArchitecture(
  ctx: ScanContext,
  llm: LlmClient,
  config: VulnScanConfig,
  options: InferArchitectureOptions = {},
): Promise<{ model: ArchitectureModel; errors: string[] }> {
  const errors: string[] = [];

  if (config?.architecture !== true) {
    return {
      model: minimalModel('設定 architecture=false のためアーキテクチャ推定を実行していない。'),
      errors,
    };
  }

  const repoRoot = typeof ctx?.repoRoot === 'string' ? ctx.repoRoot : '.';
  const fs = options.fs ?? createNodeFileSystem(repoRoot);

  // ---- 1. 事実収集（ここが失敗しても後続は続ける） ----
  let factSet: FactSet & { knownPaths: Set<string>; contents: Map<string, string> };
  try {
    factSet = await collectFacts(ctx, fs);
  } catch (err) {
    errors.push(`事実収集に失敗しました: ${String(err)}`);
    return {
      model: minimalModel('設定ファイルの収集に失敗したため、事実を 1 件も得られなかった。'),
      errors,
    };
  }
  errors.push(...factSet.warnings);

  // ---- 2. 事実だけのモデル骨格 ----
  let draft: DraftModel;
  try {
    draft = buildDraft(factSet, ctx);
  } catch (err) {
    errors.push(`モデルの組み立てに失敗しました: ${String(err)}`);
    return { model: minimalModel('収集した事実からモデルを組み立てられなかった。'), errors };
  }

  // ---- 3. LLM による推測 ----
  if (typeof llm?.structured !== 'function') {
    draft.gaps.push(
      'LLM クライアントが利用できないため、様式・露出度・機微度・認証要否は機械的な既定値のままである。',
    );
    return { model: finalize(draft, factSet), errors };
  }

  if (factSet.facts.length === 0) {
    // 渡せる事実が無い状態で推測させると、根拠のない断定を誘発するだけなので呼ばない
    draft.gaps.push(
      '設定ファイルから事実を 1 件も収集できなかったため、LLM への推測依頼を行っていない（根拠のない推測を避けるため）。',
    );
    return { model: finalize(draft, factSet), errors };
  }

  const system = buildSystemPrompt();
  const user = buildUserPrompt(factSet, draft.components, ctx);

  const result = await llm.structured({
    system,
    user,
    schema: ArchitectureResponseSchema,
    schemaName: 'ArchitectureResponse',
    cacheKey: createHash('sha256').update('architecture').update('\0').update(user).digest('hex'),
  });

  if (!result.ok) {
    const reason =
      result.reason === 'refusal'
        ? `アーキテクチャ推測が拒否されました (category=${result.category ?? '不明'})`
        : result.reason === 'budget-exhausted'
          ? 'トークン予算を使い切ったためアーキテクチャ推測を実行できませんでした'
          : `アーキテクチャ推測に失敗しました: ${result.error}`;
    errors.push(reason);
    draft.gaps.push(
      `LLM による推測を実行できなかったため、様式・露出度・機微度・認証要否は機械的な既定値のままである（理由: ${reason}）。`,
    );
    return { model: finalize(draft, factSet), errors };
  }

  // ---- 4. 引用の実在検証つきで反映 ----
  const index: CitationIndex = {
    knownPaths: factSet.knownPaths,
    contents: factSet.contents,
    repoRoot,
  };
  try {
    applyLlmResponse(draft, result.value, index, errors);
  } catch (err) {
    errors.push(`LLM 出力の反映に失敗しました: ${String(err)}`);
    draft.gaps.push('LLM 出力を反映できなかったため、事実に基づく部分のみを採用した。');
  }

  return { model: finalize(draft, factSet), errors };
}

export default inferArchitecture;
