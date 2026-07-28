/**
 * 構成要素の技術スタック（言語・技術）を導出する。
 *
 * `ArchitectureComponent` は `technology: Claim<string>` を1つ持つだけなので、
 * CWEカタログの `cwesForPlatform()` に渡せる形へ組み立て直す必要がある。
 *
 * 導出に使う情報と、その出所:
 *   - 言語   : ScanContext.files のうち構成要素配下のもの（**事実**）
 *              配下のファイルが判らない場合はリポジトリ全体の言語比率で代用（仮定）
 *   - 技術   : component.kind（**事実**扱い。型として与えられている）
 *              + component.technology（Claim。推測なら減衰する）
 *              + 当該構成要素から出ているデータフローの相手先の kind（Claim を伴う）
 *              + ScanContext.frameworks（**事実**）
 */

import type { ArchitectureComponent, ArchitectureModel, ComponentKind } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import { claimFactor, type ConfidenceFactor, weakestOf } from './confidence.js';
import { isUnderPath } from './assign.js';

export interface ComponentPlatform {
  /** 言語名。カタログ側の別名表（typescript→JavaScript 等）が吸収するため生の名前でよい */
  languages: string[];
  /** MITRE の Applicable_Platforms 表記に寄せた技術名 */
  technologies: string[];
  /** 技術スタックの導出に使った推測の減衰係数（言語は事実由来なので基本的に含まれない） */
  factors: ConfidenceFactor[];
  /** reasoning に載せるための説明 */
  description: string;
}

/** 構成要素の種別から、カタログ語彙の技術を引く */
const TECHNOLOGY_BY_KIND: Record<ComponentKind, string[]> = {
  'web-frontend': ['Web Based'],
  'api-service': ['Web Based', 'Web Server'],
  gateway: ['Web Based', 'Web Server'],
  cdn: ['Web Based', 'Cloud Computing'],
  'external-api': ['Web Based'],
  'auth-provider': ['Web Based', 'Web Server'],
  database: ['Database Server'],
  cache: ['Database Server'],
  'object-storage': ['Cloud Computing'],
  'message-queue': ['Client Server'],
  'background-worker': [],
  cli: [],
  unknown: [],
};

/** 技術名テキストからカタログ語彙を引くための語彙表 */
const TECHNOLOGY_KEYWORDS: ReadonlyArray<{ pattern: RegExp; technology: string }> = [
  { pattern: /postgre|mysql|mariadb|sqlite|oracle|mssql|sql\b|mongo|dynamodb|redis|cassandra|elasticsearch/i, technology: 'Database Server' },
  { pattern: /nginx|apache|express|fastify|koa|django|flask|rails|spring|gin\b|http|tomcat/i, technology: 'Web Server' },
  { pattern: /react|vue|angular|svelte|next\.js|nextjs|browser|html/i, technology: 'Web Based' },
  { pattern: /aws|amazon|gcp|google cloud|azure|lambda|s3\b|cloudflare|kubernetes|k8s|cloud/i, technology: 'Cloud Computing' },
  { pattern: /android|ios\b|react native|flutter|mobile/i, technology: 'Mobile' },
  { pattern: /kafka|rabbitmq|amqp|sqs|pubsub|nats/i, technology: 'Client Server' },
];

function pushUnique(list: string[], value: string): void {
  if (value.length > 0 && !list.includes(value)) list.push(value);
}

function technologiesFromText(text: string): string[] {
  const out: string[] = [];
  for (const { pattern, technology } of TECHNOLOGY_KEYWORDS) {
    if (pattern.test(text)) pushUnique(out, technology);
  }
  return out;
}

/** 構成要素配下のソースファイルから言語を拾う（事実） */
function languagesFromFiles(component: ArchitectureComponent, ctx: ScanContext): string[] {
  if (component.sourcePaths.length === 0) return [];
  const names: string[] = [];
  for (const file of ctx.files) {
    if (!component.sourcePaths.some((p) => isUnderPath(file.path, p))) continue;
    pushUnique(names, file.language);
  }
  return names;
}

/**
 * 構成要素の技術スタックを導出する。
 *
 * 併せて「この導出がどれだけ推測に依っているか」を減衰係数として返す。
 * 技術名の Claim が推測なら、その確信度がそのまま想定リスクの確信度に効く。
 */
export function derivePlatform(
  component: ArchitectureComponent,
  architecture: ArchitectureModel,
  ctx: ScanContext,
): ComponentPlatform {
  const factors: ConfidenceFactor[] = [];

  // --- 言語 ---
  const observedLanguages = languagesFromFiles(component, ctx);
  let languages: string[];
  let languageSource: string;
  if (observedLanguages.length > 0) {
    languages = observedLanguages;
    languageSource = `配下ソースの言語(事実): ${languages.join('/') || 'なし'}`;
  } else {
    // 構成要素配下のファイルが特定できないので、リポジトリ全体の言語で代用する。
    // これは根拠のある推測ではなく代用なので、仮定として減衰させる。
    languages = ctx.languages.map((l) => l.name);
    languageSource = `リポジトリ全体の言語で代用(仮定): ${languages.join('/') || 'なし'}`;
    factors.push({
      label: '言語の特定',
      factor: 0.7,
      kind: 'assumed',
      detail: '構成要素配下のファイルを特定できずリポジトリ全体の言語で代用',
    });
  }

  // --- 技術 ---
  const technologies: string[] = [];
  for (const tech of TECHNOLOGY_BY_KIND[component.kind]) pushUnique(technologies, tech);

  const techClaimFactor = claimFactor('技術スタック', component.technology);
  for (const tech of technologiesFromText(component.technology.value)) pushUnique(technologies, tech);
  factors.push(techClaimFactor);

  for (const framework of ctx.frameworks) {
    for (const tech of technologiesFromText(framework.name)) pushUnique(technologies, tech);
  }

  // データフローの相手先から技術を補う。
  // 例: API サーバから database 構成要素へ SQL が流れているなら、
  //     その API サーバも 'Database Server' 関連の CWE の射程に入る。
  const flowFactors: ConfidenceFactor[] = [];
  for (const flow of architecture.dataFlows) {
    if (flow.fromId !== component.id) continue;
    const target = architecture.components.find((c) => c.id === flow.toId);
    if (!target) continue;
    const targetTechnologies = TECHNOLOGY_BY_KIND[target.kind];
    const protocolTechnologies = technologiesFromText(flow.protocol.value);
    if (targetTechnologies.length === 0 && protocolTechnologies.length === 0) continue;
    for (const tech of targetTechnologies) pushUnique(technologies, tech);
    for (const tech of protocolTechnologies) pushUnique(technologies, tech);
    flowFactors.push(claimFactor(`データフロー(→${target.id})`, flow.protocol));
  }
  // 同種の根拠（複数のデータフロー）は積ではなく最弱の1件で代表させる。
  // 積にすると「根拠が増えるほど確信度が下がる」不合理が起きるため。
  const weakestFlow = weakestOf(flowFactors);
  if (weakestFlow) factors.push(weakestFlow);

  return {
    languages,
    technologies,
    factors,
    description: `${languageSource} / 技術: ${technologies.join(', ') || '不明'}`,
  };
}
