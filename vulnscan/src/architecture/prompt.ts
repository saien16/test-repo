/**
 * アーキテクチャ推測用のプロンプト構築。
 *
 * 設計方針:
 *   - LLM には「収集済みの事実（引用付き）」だけを渡す。生のソースは渡さない。
 *   - 事実に無いことを断定させない。判らないものは unknown / unknowns に書かせる。
 *   - 引用してよいファイルを列挙し、それ以外を書かないよう明示する
 *     （それでも捏造しうるので後段で verify.ts が検証する）。
 *
 * system はリポジトリによらず不変にしてプロンプトキャッシュを効かせる。
 */

import type { ArchitectureComponent } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import type { Claim } from '../types/evidence.js';
import type { FactSet, ObservedFact } from './facts.js';
import { KIND_LABEL } from './model.js';
import { ARCHITECTURE_STYLES, DATA_SENSITIVITIES, EXPOSURES } from './schema.js';

/** 1 種別あたりに提示する事実の上限 */
const MAX_FACTS_PER_KIND = 12;
/** 引用可能ファイルとして列挙する上限 */
const MAX_QUOTABLE_FILES = 80;

const FACT_KIND_LABEL: Record<ObservedFact['kind'], string> = {
  'container.base-image': 'Dockerfile ベースイメージ',
  'container.exposed-port': 'Dockerfile EXPOSE',
  'container.entrypoint': 'Dockerfile CMD/ENTRYPOINT',
  'compose.service': 'docker-compose サービス',
  'compose.published-port': 'docker-compose 公開ポート',
  'compose.depends-on': 'docker-compose depends_on',
  'k8s.resource': 'Kubernetes リソース',
  'k8s.container-image': 'コンテナイメージ',
  'k8s.service-type': 'Kubernetes Service の type',
  'k8s.ingress': 'Kubernetes Ingress',
  'k8s.secret-ref': 'Kubernetes Secret 参照',
  'helm.chart': 'Helm チャート',
  'platform.manifest': 'デプロイ設定ファイル',
  'platform.process': '関数・プロセス定義',
  'cloud.provider': 'クラウドプロバイダ宣言',
  'iac.resource': 'IaC リソース',
  'cicd.workflow': 'CI/CD 設定',
  'cicd.deploy-step': 'CI/CD のデプロイ操作',
  'dependency.client': '依存ライブラリ（バックエンドの手掛かり）',
  'env.variable': '参照されている環境変数',
  entrypoint: 'エントリポイント',
  'secrets.mechanism': '秘密情報の受け渡し',
};

/** リポジトリによらず不変な system プロンプト（キャッシュ対象） */
export function buildSystemPrompt(): string {
  return [
    'あなたはソフトウェアアーキテクチャとクラウドインフラの専門家です。',
    '静的解析で「コードや設定ファイルから直接読み取れた事実」だけが与えられます。',
    'それを土台に、システム構成についての推測を行ってください。',
    '',
    '# 最重要ルール: 事実と推測を混ぜない',
    '- 与えられた事実に書かれていないことを、断定してはいけません。',
    '- あなたが返す値はすべて「推測」として扱われます。だからこそ、',
    '  confidence（0..1）を正直に付けてください。根拠が薄いなら 0.3 以下にすること。',
    '- 判断材料が無い項目は、無理に埋めず unknown（露出度）／["unknown"]（機微度）を選び、',
    '  なぜ判らないかを unknowns に日本語で書いてください。「わからない」と言うことは減点ではありません。',
    '- alternatives には必ず 1 つ以上、検討したが採らなかった対立仮説を書いてください。',
    '  対立仮説が思いつかないほど自明なら、その旨を書いた上で confidence を高くしてください。',
    '',
    '# 引用（basis）のルール',
    '- basis には「引用可能ファイル」に列挙されたパスだけを書いてください。',
    '- 存在しないファイル・行を書かないでください。検証で捨てられ、あなたの推測は根拠なしとして扱われます。',
    '- 事実の抜粋をそのまま引き写す形が最も安全です。',
    '',
    '# 判断してほしいこと',
    `- style: アーキテクチャ様式（${ARCHITECTURE_STYLES.join(' / ')}）`,
    `- 各構成要素の exposure: ネットワーク露出度（${EXPOSURES.join(' / ')}）`,
    '  public-internet はインターネットから直接到達できることを意味します。',
    '  「Web アプリだから公開されているはず」といった一般論だけで public-internet を選ぶ場合は',
    '  confidence を下げ、その旨を reasoning に書いてください。',
    `- 各構成要素の dataSensitivity: 扱うデータの機微度（${DATA_SENSITIVITIES.join(' / ')}、複数可）`,
    '- 各構成要素の requiresAuthentication: 認証を要求するか',
    '- dataFlows: 構成要素間のデータの流れと、それが信頼境界をまたぐか',
    '  信頼境界をまたぐとは、管理主体・ネットワークゾーン・権限レベルが変わる通信のことです。',
    '',
    '# 出力',
    '- componentId / fromId / toId には、提示された構成要素の id のみを使ってください。',
    '- すべての自然言語フィールドは日本語で書いてください。',
  ].join('\n');
}

function formatCitation(fact: ObservedFact): string {
  const { file, line, excerpt } = fact.citation;
  const where = line !== undefined ? `${file}:${line}` : file;
  return excerpt !== undefined ? `${where} 「${excerpt}」` : where;
}

function formatFacts(facts: readonly ObservedFact[]): string {
  const grouped = new Map<ObservedFact['kind'], ObservedFact[]>();
  for (const fact of facts) {
    const list = grouped.get(fact.kind);
    if (list === undefined) grouped.set(fact.kind, [fact]);
    else list.push(fact);
  }
  if (grouped.size === 0) return '（設定ファイルから読み取れた事実はありません）';

  const lines: string[] = [];
  for (const [kind, list] of grouped) {
    lines.push(`## ${FACT_KIND_LABEL[kind] ?? kind}`);
    for (const fact of list.slice(0, MAX_FACTS_PER_KIND)) {
      const detail =
        fact.detail === undefined
          ? ''
          : ` [${Object.entries(fact.detail)
              .filter(([, v]) => v !== undefined && v !== '')
              .map(([k, v]) => `${k}=${v}`)
              .join(', ')}]`;
      lines.push(`- ${fact.value}${detail} — 出典: ${formatCitation(fact)}`);
    }
    if (list.length > MAX_FACTS_PER_KIND) {
      lines.push(`- （他 ${list.length - MAX_FACTS_PER_KIND} 件は省略）`);
    }
    lines.push('');
  }
  return lines.join('\n').trimEnd();
}

function describeClaim(claim: Claim<unknown>): string {
  const value = Array.isArray(claim.value) ? claim.value.join(', ') : String(claim.value);
  switch (claim.provenance.kind) {
    case 'observed':
      return `${value}（事実 / 出典: ${claim.provenance.citations
        .map((c) => (c.line !== undefined ? `${c.file}:${c.line}` : c.file))
        .join(', ')}）`;
    case 'inferred':
      return `${value}（機械的推測 確信度 ${claim.provenance.confidence.toFixed(2)}: ${claim.provenance.reasoning}）`;
    case 'assumed':
      return `${value}（根拠なしの仮定: ${claim.provenance.reasoning}）`;
  }
}

function formatComponents(components: readonly ArchitectureComponent[]): string {
  if (components.length === 0) {
    return '（構成要素の候補を特定できていません。事実から新たに判るものがあれば unknowns に書いてください）';
  }
  return components
    .map((c) =>
      [
        `## ${c.id}`,
        `- 種別: ${c.kind}（${KIND_LABEL[c.kind]}）`,
        `- 名称: ${c.name}`,
        `- 技術: ${describeClaim(c.technology)}`,
        `- 露出度の暫定値: ${describeClaim(c.exposure)}`,
        `- 対応ソースパス: ${c.sourcePaths.length > 0 ? c.sourcePaths.join(', ') : '（不明）'}`,
        `- 対応エントリポイント: ${c.entryPointIds.length > 0 ? c.entryPointIds.slice(0, 10).join(', ') : '（なし）'}`,
      ].join('\n'),
    )
    .join('\n\n');
}

/** 引用してよいファイル一覧（事実に現れたファイル） */
export function quotableFiles(factSet: FactSet): string[] {
  const files = new Set<string>();
  for (const fact of factSet.facts) files.add(fact.citation.file);
  for (const path of factSet.inspected) files.add(path);
  return [...files].sort().slice(0, MAX_QUOTABLE_FILES);
}

/** 1 リポジトリ分の user プロンプト */
export function buildUserPrompt(
  factSet: FactSet,
  components: readonly ArchitectureComponent[],
  ctx: ScanContext,
): string {
  const languages = (ctx?.languages ?? [])
    .slice(0, 5)
    .map((l) => `${l.name} ${(l.ratio * 100).toFixed(0)}%`)
    .join(', ');
  const frameworks = (ctx?.frameworks ?? [])
    .slice(0, 12)
    .map((f) => (f.version !== undefined ? `${f.name}@${f.version}` : f.name))
    .join(', ');
  const entryPointSummary = (ctx?.entryPoints ?? []).slice(0, 20).map((e) => {
    const meta =
      e.metadata === undefined
        ? ''
        : ` (${Object.entries(e.metadata)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')})`;
    return `- [${e.kind}] ${e.identifier}${meta} — ${e.file}:${e.line}`;
  });

  return [
    '# リポジトリの補助情報（引用には使えません）',
    `- 言語構成: ${languages !== '' ? languages : '不明'}`,
    `- 検出フレームワーク: ${frameworks !== '' ? frameworks : '不明'}`,
    '',
    '# 観測された事実（すべて引用付き。ここに無いことは「判っていない」ことです）',
    formatFacts(factSet.facts),
    '',
    '# エントリポイント（外部からの入口として検出済み）',
    entryPointSummary.length > 0 ? entryPointSummary.join('\n') : '（検出されていません）',
    '',
    '# 構成要素の候補（この id を使ってください）',
    formatComponents(components),
    '',
    '# 引用可能ファイル（basis に書いてよいパス）',
    quotableFiles(factSet)
      .map((f) => `- ${f}`)
      .join('\n') || '（なし）',
    '',
    '# 指示',
    '上記の事実だけを土台に、様式・露出度・データ機微度・認証要否・データフローを判断してください。',
    '事実が足りない項目は unknown を選び、その理由を unknowns に書いてください。',
    '暫定値（機械的推測）が誤っていると判断したら、遠慮なく別の値に修正してください。',
  ].join('\n');
}
