/**
 * 事実（FactSet）からヒューリスティックなモデル骨格を組み立てる。
 *
 * ここが「事実と推測の境界」を引く中心。ルールは 1 つだけ:
 *
 *   引用したテキストがその値をそのまま述べているなら observed、
 *   値の決定に知識や判断が要るなら inferred(heuristic)、
 *   根拠が無いなら assumed（＋ gaps に理由を書く）。
 *
 * LLM が使えない場合でもこのモデルだけで成立する（＝事実部分は必ず残る）。
 */

import type {
  ArchitectureComponent,
  ArchitectureStyle,
  ComponentDataFlow,
  ComponentKind,
  DataSensitivity,
  DeploymentStack,
  Exposure,
} from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import { assumed, type Citation, type Claim, inferred, observed } from '../types/evidence.js';
import { runtimeFromImage } from './containers.js';
import { dedupeCitations, type FactSet, type ObservedFact, type ServiceSignal } from './facts.js';

/** 構成要素種別の日本語表示 */
const KIND_LABEL: Record<ComponentKind, string> = {
  'web-frontend': 'フロントエンド',
  'api-service': 'API サーバ',
  database: 'データベース',
  cache: 'キャッシュ',
  'message-queue': 'メッセージキュー',
  'object-storage': 'オブジェクトストレージ',
  'auth-provider': '認証基盤',
  'background-worker': 'バックグラウンドワーカー',
  gateway: 'ゲートウェイ',
  cdn: 'CDN',
  'external-api': '外部 API',
  cli: 'CLI',
  unknown: '種別不明の構成要素',
};

/** アプリケーション本体になりうる種別 */
const APP_KINDS = new Set<ComponentKind>([
  'api-service',
  'web-frontend',
  'background-worker',
  'cli',
  'unknown',
]);

/** バックエンド（アプリから利用される側）の種別 */
const BACKEND_KINDS = new Set<ComponentKind>([
  'database',
  'cache',
  'message-queue',
  'object-storage',
  'auth-provider',
  'external-api',
]);

export interface DraftModel {
  style: Claim<ArchitectureStyle>;
  components: ArchitectureComponent[];
  dataFlows: ComponentDataFlow[];
  deployment: DeploymentStack;
  gaps: string[];
  /** シグナル名 → 構成要素 id（depends_on の解決に使う） */
  componentIdByName: Map<string, string>;
}

function factsOf(facts: readonly ObservedFact[], kind: ObservedFact['kind']): ObservedFact[] {
  return facts.filter((f) => f.kind === kind);
}

function slug(text: string): string {
  const s = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return s === '' ? 'x' : s.slice(0, 32);
}

/** 表記ゆれのある技術名を同一視するための正規化 */
export function canonicalFamily(text: string): string {
  const t = text.toLowerCase();
  const table: Array<[RegExp, string]> = [
    [/postgres|pgvector|timescale|\bpg\b/, 'postgresql'],
    [/mariadb|mysql/, 'mysql'],
    [/mongo/, 'mongodb'],
    [/dynamodb/, 'dynamodb'],
    [/elasticsearch|opensearch/, 'elasticsearch'],
    [/redis|valkey|bull/, 'redis'],
    [/memcached/, 'memcached'],
    [/rabbit|amqp/, 'rabbitmq'],
    [/kafka|msk|redpanda/, 'kafka'],
    [/sqs|sns/, 'sqs'],
    [/s3|minio|cloud storage|blob storage/, 'object-storage'],
    [/cognito|auth0|okta|clerk|keycloak|nextauth|firebase/, 'idp'],
    [/stripe/, 'stripe'],
    [/nginx|traefik|haproxy|envoy|caddy|ロードバランサ|api gateway/, 'gateway'],
    [/cloudfront|cdn/, 'cdn'],
  ];
  for (const [re, name] of table) {
    if (re.test(t)) return name;
  }
  return slug(t);
}

/** シグナル群をひとつの構成要素にまとめる */
function mergeSignals(
  id: string,
  kind: ComponentKind,
  signals: readonly ServiceSignal[],
  facts: readonly ObservedFact[],
): ArchitectureComponent {
  const literals = signals.filter((s) => s.literal);
  const nonLiterals = signals.filter((s) => !s.literal);

  // technology: 引用がそのまま述べている値があるならそれを事実として採る
  let technology: Claim<string>;
  if (literals.length > 0) {
    const primary = literals[0] as ServiceSignal;
    technology = observed(
      primary.technology,
      dedupeCitations(literals.map((s) => s.citation)),
    );
  } else if (nonLiterals.length > 0) {
    const best = nonLiterals.reduce((a, b) => ((a.confidence ?? 0) >= (b.confidence ?? 0) ? a : b));
    technology = inferred(best.technology, {
      confidence: best.confidence ?? 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(nonLiterals.map((s) => s.citation)),
      reasoning: best.reasoning ?? '設定ファイル・依存関係からの推測。',
      alternatives: nonLiterals
        .filter((s) => s !== best && s.technology !== best.technology)
        .map((s) => `${s.technology} の可能性（${s.reasoning ?? '別シグナル'}）`),
    });
  } else {
    technology = assumed('不明', '技術を特定できる根拠が得られなかった。');
  }

  const displayName = literals[0]?.technology ?? nonLiterals[0]?.technology ?? '不明';
  const names = [...new Set(signals.map((s) => s.name))].join(', ');

  return {
    id,
    kind,
    name: `${KIND_LABEL[kind]} (${displayName}${names !== '' && names !== displayName ? ` / ${names}` : ''})`,
    technology,
    exposure: heuristicExposure(kind, signals, facts),
    dataSensitivity: heuristicSensitivity(kind, displayName),
    // 認証の要否はコード側の実装を読まないと判らない。既定値であることを明記する
    requiresAuthentication: assumed(
      false,
      '認証要否を判断できる根拠が無いため既定値 false を採用した。「認証なし」を確認したという意味ではない。',
    ),
    sourcePaths: [...new Set(signals.flatMap((s) => s.sourcePaths ?? []).filter((p) => p !== ''))],
    entryPointIds: [],
  };
}

/**
 * 露出度のヒューリスティック。
 * どれも「そう書いてある」ではなく「そうであろう」なので必ず inferred / assumed。
 */
function heuristicExposure(
  kind: ComponentKind,
  signals: readonly ServiceSignal[],
  facts: readonly ObservedFact[],
): Claim<Exposure> {
  const names = new Set(signals.map((s) => s.name));

  const lbFacts = factsOf(facts, 'k8s.service-type').filter(
    (f) => f.value === 'LoadBalancer' || f.value === 'NodePort',
  );
  const ingressFacts = factsOf(facts, 'k8s.ingress');
  const publishedPorts = factsOf(facts, 'compose.published-port').filter((f) =>
    names.has(f.detail?.['service'] ?? ''),
  );

  if (kind === 'external-api') {
    return inferred('public-internet', {
      confidence: 0.7,
      inferredBy: 'heuristic',
      basis: dedupeCitations(signals.map((s) => s.citation)),
      reasoning: '外部 SaaS の API はリポジトリ外のインターネット上に存在するため。',
      alternatives: ['VPC エンドポイント経由で閉域から利用している可能性'],
    });
  }

  if (kind === 'cdn' || kind === 'gateway') {
    return inferred('public-internet', {
      confidence: 0.65,
      inferredBy: 'heuristic',
      basis: dedupeCitations(signals.map((s) => s.citation)),
      reasoning: 'CDN・ゲートウェイは外部からの受け口として置かれるのが一般的なため。',
      alternatives: ['内部専用のリバースプロキシとして使われている可能性'],
    });
  }

  if (APP_KINDS.has(kind) && (lbFacts.length > 0 || ingressFacts.length > 0)) {
    return inferred('public-internet', {
      confidence: 0.6,
      inferredBy: 'heuristic',
      basis: dedupeCitations([...lbFacts, ...ingressFacts].map((f) => f.citation)),
      reasoning:
        'Kubernetes の Ingress / LoadBalancer 型 Service が宣言されており、外部からの受け口が構成されているため。',
      alternatives: [
        '内部向けロードバランサ（internal スキーム）である可能性',
        'Ingress が別ワークロード向けである可能性',
      ],
    });
  }

  if (APP_KINDS.has(kind) && publishedPorts.length > 0) {
    return inferred('public-internet', {
      confidence: 0.4,
      inferredBy: 'heuristic',
      basis: dedupeCitations(publishedPorts.map((f) => f.citation)),
      reasoning: 'docker-compose でホスト側にポートが公開されているため。',
      alternatives: [
        '開発用 compose のみの設定で、本番ではリバースプロキシ配下にある可能性',
        'ホストがローカル開発機のみである可能性',
      ],
    });
  }

  if (BACKEND_KINDS.has(kind)) {
    return inferred('internal', {
      confidence: 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(signals.map((s) => s.citation)),
      reasoning:
        'データストア類はアプリケーション層からのみ到達させる構成が一般的なため。ネットワーク設定そのものは確認できていない。',
      alternatives: ['実際には公開されている可能性（セキュリティグループ等を確認できていない）'],
    });
  }

  return assumed('unknown', '露出度を判断できる根拠（Ingress・ポート公開・LB 設定）が無かった。');
}

function heuristicSensitivity(kind: ComponentKind, display: string): Claim<DataSensitivity[]> {
  if (kind === 'auth-provider') {
    return inferred(['credentials'], {
      confidence: 0.65,
      inferredBy: 'heuristic',
      basis: [],
      reasoning: '認証基盤は資格情報を扱うため。',
      alternatives: ['認証を委譲するだけで資格情報を保持しない構成の可能性'],
    });
  }
  if (/stripe|決済|payment/i.test(display)) {
    return inferred(['financial'], {
      confidence: 0.6,
      inferredBy: 'heuristic',
      basis: [],
      reasoning: '決済サービスとの連携があるため金銭に関わるデータを扱うとみなした。',
      alternatives: ['カード情報は完全に外部委任され、当該系統には残らない可能性'],
    });
  }
  return assumed(
    ['unknown'],
    '扱うデータの内容はスキーマや実装を読まないと判らず、設定ファイルからは判断できなかった。',
  );
}

/** 事実群から構成要素を組み立てる */
export function buildComponents(
  factSet: FactSet,
  ctx: ScanContext,
  gaps: string[],
): { components: ArchitectureComponent[]; componentIdByName: Map<string, string> } {
  const groups = new Map<string, { kind: ComponentKind; idBase: string; signals: ServiceSignal[] }>();

  const groupKeyOf = (signal: ServiceSignal): { key: string; idBase: string } => {
    if (BACKEND_KINDS.has(signal.kind)) {
      const family = canonicalFamily(signal.technology);
      return { key: `${signal.kind}:${family}`, idBase: family };
    }
    return { key: `${signal.kind}:${slug(signal.name)}`, idBase: slug(signal.name) };
  };

  // 製品を特定できた具体的なシグナルを先に確定させる
  const specific = factSet.services.filter((s) => s.generic !== true);
  const generic = factSet.services.filter((s) => s.generic === true);

  for (const signal of specific) {
    const { key, idBase } = groupKeyOf(signal);
    const existing = groups.get(key);
    if (existing === undefined) groups.set(key, { kind: signal.kind, idBase, signals: [signal] });
    else existing.signals.push(signal);
  }

  // 一般的なシグナル（環境変数名など）は、同種の具体的な構成要素があれば合流させる。
  // 合流先が無い場合のみ独立した構成要素にする（「何かある」ことは判っているため）。
  for (const signal of generic) {
    const { key, idBase } = groupKeyOf(signal);
    const exact = groups.get(key);
    if (exact !== undefined) {
      exact.signals.push(signal);
      continue;
    }
    const sameKind = [...groups.values()]
      .filter((g) => g.kind === signal.kind)
      .sort((a, b) => b.signals.length - a.signals.length)[0];
    if (sameKind !== undefined) sameKind.signals.push(signal);
    else groups.set(key, { kind: signal.kind, idBase, signals: [signal] });
  }

  const components: ArchitectureComponent[] = [];
  const componentIdByName = new Map<string, string>();
  const usedIds = new Set<string>();

  for (const group of groups.values()) {
    // id が `object-storage-object-storage` のように冗長になる場合は名前を使う
    const base =
      group.idBase === '' || group.idBase === group.kind
        ? slug(group.signals[0]?.name ?? 'x')
        : group.idBase;
    let id = `${group.kind}-${base}`;
    let n = 2;
    while (usedIds.has(id)) id = `${group.kind}-${base}-${n++}`;
    usedIds.add(id);
    const component = mergeSignals(id, group.kind, group.signals, factSet.facts);
    components.push(component);
    for (const signal of group.signals) componentIdByName.set(signal.name, id);
  }

  // アプリ本体が 1 つも取れていないなら、エントリポイント／Dockerfile から補う
  const hasApp = components.some((c) => APP_KINDS.has(c.kind));
  const httpRoutes = (ctx?.entryPoints ?? []).filter((e) => e?.kind === 'http-route');
  const baseImages = factsOf(factSet.facts, 'container.base-image');

  if (!hasApp && (httpRoutes.length > 0 || baseImages.length > 0)) {
    const frameworkNames = (ctx?.frameworks ?? []).map((f) => f.name).filter((n) => n !== '');
    const runtimeImage = baseImages
      .map((f) => ({ fact: f, runtime: runtimeFromImage(f.value) }))
      .find((x) => x.runtime !== null);

    const technology: Claim<string> =
      runtimeImage !== undefined
        ? observed(runtimeImage.fact.value, [runtimeImage.fact.citation])
        : httpRoutes.length > 0
          ? inferred(
              frameworkNames.length > 0
                ? `${frameworkNames.join(' / ')} アプリケーション`
                : 'HTTP アプリケーション',
              {
                confidence: 0.55,
                inferredBy: 'heuristic',
                basis: dedupeCitations(
                  httpRoutes.slice(0, 3).map((e) => ({ file: e.file, line: e.line })),
                ),
                reasoning:
                  'HTTP ルートのエントリポイントが検出されており、検出フレームワークから技術を推測した。',
                alternatives: ['テストコードや雛形のみでルートが実運用されていない可能性'],
              },
            )
          : assumed('不明', 'アプリケーションの技術を特定できる根拠が無かった。');

    const kind: ComponentKind = httpRoutes.length > 0 ? 'api-service' : 'unknown';
    const id = `${kind}-app`;
    components.push({
      id,
      kind,
      name: `${KIND_LABEL[kind]} (このリポジトリのコード)`,
      technology,
      exposure: heuristicExposure(kind, [], factSet.facts),
      dataSensitivity: assumed(
        ['unknown'],
        '扱うデータの機微度は実装を読まないと判らず、設定ファイルからは判断できなかった。',
      ),
      requiresAuthentication: assumed(
        false,
        '認証要否を判断できる根拠が無いため既定値 false を採用した。「認証なし」を確認したという意味ではない。',
      ),
      sourcePaths: [],
      entryPointIds: [],
    });
    usedIds.add(id);
  }

  // エントリポイントを構成要素に割り当てる（前方一致 → 無ければアプリ本体へ）
  const appComponents = components.filter((c) => APP_KINDS.has(c.kind));
  const primary = appComponents[0];
  for (const ep of ctx?.entryPoints ?? []) {
    const id = String(ep?.identifier ?? '');
    if (id === '') continue;
    const matched = appComponents.find((c) =>
      c.sourcePaths.some((p) => p !== '' && String(ep.file ?? '').startsWith(p)),
    );
    const target = matched ?? primary;
    if (target === undefined) continue;
    if (!target.entryPointIds.includes(id)) target.entryPointIds.push(id);
  }

  if (components.length === 0) {
    gaps.push(
      '構成要素を 1 つも特定できなかった。Dockerfile・compose・Kubernetes マニフェスト・インフラ関連の依存のいずれも見つからないため。',
    );
  }

  return { components, componentIdByName };
}

/** 構成要素間のデータフローを組み立てる */
export function buildDataFlows(
  components: readonly ArchitectureComponent[],
  factSet: FactSet,
  componentIdByName: ReadonlyMap<string, string>,
): ComponentDataFlow[] {
  const byId = new Map(components.map((c) => [c.id, c]));
  const flows = new Map<string, ComponentDataFlow>();

  const protocolFor = (kind: ComponentKind): { label: string; confidence: number } => {
    switch (kind) {
      case 'database':
        return { label: 'DB プロトコル (SQL 等)', confidence: 0.6 };
      case 'cache':
        return { label: 'キャッシュプロトコル (RESP 等)', confidence: 0.6 };
      case 'message-queue':
        return { label: 'メッセージングプロトコル (AMQP/Kafka 等)', confidence: 0.6 };
      case 'object-storage':
        return { label: 'HTTPS (オブジェクトストレージ API)', confidence: 0.65 };
      case 'auth-provider':
        return { label: 'HTTPS (OAuth/OIDC 等)', confidence: 0.6 };
      case 'external-api':
        return { label: 'HTTPS', confidence: 0.7 };
      default:
        return { label: 'HTTP', confidence: 0.5 };
    }
  };

  const addFlow = (fromId: string, toId: string, basis: Citation[], reason: string): void => {
    if (fromId === toId) return;
    const to = byId.get(toId);
    const from = byId.get(fromId);
    if (to === undefined || from === undefined) return;
    const key = `${fromId}->${toId}`;
    if (flows.has(key)) return;
    const protocol = protocolFor(to.kind);
    const external = to.kind === 'external-api' || to.kind === 'cdn';
    flows.set(key, {
      fromId,
      toId,
      protocol: inferred(protocol.label, {
        confidence: protocol.confidence,
        inferredBy: 'heuristic',
        basis,
        reasoning: `接続先の種別（${KIND_LABEL[to.kind]}）から一般的なプロトコルを推測した。${reason}`,
        alternatives: ['独自プロトコルやプロキシ経由の通信である可能性'],
      }),
      crossesTrustBoundary: external
        ? inferred(true, {
            confidence: 0.7,
            inferredBy: 'heuristic',
            basis,
            reasoning: '外部サービスとの通信は組織の管理外へ出るため信頼境界を越えるとみなした。',
            alternatives: ['専用線・VPC エンドポイントで閉域化されている可能性'],
          })
        : assumed(
            false,
            '同一ネットワーク内の通信とみなしたが、ネットワーク分離の設定を確認できていない。',
          ),
    });
  };

  // docker-compose の depends_on は明示された依存関係なので最優先で使う
  for (const fact of factsOf(factSet.facts, 'compose.depends-on')) {
    const fromName = fact.detail?.['from'] ?? '';
    const toName = fact.detail?.['to'] ?? '';
    const fromId = componentIdByName.get(fromName);
    const toId = componentIdByName.get(toName);
    if (fromId === undefined || toId === undefined) continue;
    addFlow(fromId, toId, [fact.citation], 'docker-compose の depends_on に基づく。');
  }

  // アプリ本体 → 各バックエンド
  const app = components.find((c) => APP_KINDS.has(c.kind));
  if (app !== undefined) {
    for (const component of components) {
      if (!BACKEND_KINDS.has(component.kind)) continue;
      const basis =
        component.technology.provenance.kind === 'observed'
          ? component.technology.provenance.citations
          : component.technology.provenance.kind === 'inferred'
            ? component.technology.provenance.basis
            : [];
      addFlow(
        app.id,
        component.id,
        basis,
        'アプリケーションがこのバックエンドのクライアント／定義を持つため。',
      );
    }
  }

  return [...flows.values()];
}

/** デプロイメントスタックを組み立てる */
export function buildDeployment(
  factSet: FactSet,
  ctx: ScanContext,
  gaps: string[],
): DeploymentStack {
  const facts = factSet.facts;
  const baseImages = factsOf(facts, 'container.base-image');
  const k8sResources = factsOf(facts, 'k8s.resource');
  const helm = factsOf(facts, 'helm.chart');
  const platformManifests = factsOf(facts, 'platform.manifest');
  const cloudFacts = factsOf(facts, 'cloud.provider');
  const iacFacts = factsOf(facts, 'iac.resource');
  const cicdFacts = factsOf(facts, 'cicd.workflow');
  const deploySteps = factsOf(facts, 'cicd.deploy-step');
  const ingressFacts = factsOf(facts, 'k8s.ingress');
  const secretFacts = factsOf(facts, 'secrets.mechanism');
  const hasPlatform = (value: string): ObservedFact | undefined =>
    platformManifests.find((f) => f.value === value);

  // ---- runtime ----
  let runtime: Claim<string>;
  const runtimeImage = baseImages
    .map((f) => ({ fact: f, runtime: runtimeFromImage(f.value) }))
    .find((x) => x.runtime !== null);
  const engineFact = platformManifests.find((f) => f.detail?.['runtime'] !== undefined);
  if (runtimeImage !== undefined) {
    // ベースイメージ名は Dockerfile の文言そのもの。事実として扱える
    runtime = observed(runtimeImage.fact.value, [runtimeImage.fact.citation]);
  } else if (engineFact !== undefined) {
    runtime = observed(engineFact.detail?.['runtime'] ?? engineFact.value, [engineFact.citation]);
  } else {
    const top = (ctx?.languages ?? [])[0];
    if (top !== undefined) {
      runtime = inferred(top.name, {
        confidence: 0.45,
        inferredBy: 'heuristic',
        basis: [],
        reasoning: `ソースファイルの ${(top.ratio * 100).toFixed(0)}% が ${top.name} であることから主要ランタイムを推測した。バージョンは不明。`,
        alternatives: ['複数ランタイムが混在している可能性'],
      });
      gaps.push('ランタイムのバージョンを特定できなかった（Dockerfile・engines・go directive のいずれも無いため）。');
    } else {
      runtime = assumed('unknown', 'ランタイムを判断できる根拠が無かった。');
      gaps.push('ランタイムを特定できなかった（言語統計も設定ファイルも得られなかったため）。');
    }
  }

  // ---- containerization ----
  let containerization: DeploymentStack['containerization'];
  if (k8sResources.length > 0) {
    containerization = observed('kubernetes', [
      (k8sResources[0] as ObservedFact).citation,
    ]);
  } else if (baseImages.length > 0) {
    containerization = observed('docker', [(baseImages[0] as ObservedFact).citation]);
  } else if (platformManifests.length > 0) {
    containerization = inferred('none', {
      confidence: 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(platformManifests.map((f) => f.citation)),
      reasoning: 'PaaS/サーバレスの設定はあるが Dockerfile・Kubernetes マニフェストが見つからないため。',
      alternatives: ['コンテナ定義がリポジトリ外にある可能性'],
    });
  } else {
    containerization = assumed('unknown', 'コンテナ化の有無を判断できる設定ファイルが無かった。');
    gaps.push('コンテナ化の有無を判定できなかった（Dockerfile も Kubernetes マニフェストも無いため）。');
  }

  // ---- platform（実行基盤）: 常に推測。設定ファイルは「基盤そのもの」を書いていない ----
  let platform: DeploymentStack['platform'];
  const sam = hasPlatform('aws-sam');
  const serverless = hasPlatform('serverless-framework');
  const vercel = hasPlatform('vercel');
  const netlify = hasPlatform('netlify');
  const procfile = hasPlatform('procfile');
  const ecsFact = iacFacts.find((f) => /ecs_service|AWS::ECS::Service/.test(f.value));
  const cloudRunFact = iacFacts.find((f) => /cloud_run/.test(f.value));
  const ec2Fact = iacFacts.find((f) => /aws_instance/.test(f.value));

  const platformCandidate = (
    value: DeploymentStack['platform']['value'],
    fact: ObservedFact,
    confidence: number,
    reasoning: string,
    alternatives: string[],
  ): Claim<DeploymentStack['platform']['value']> =>
    inferred(value, { confidence, inferredBy: 'heuristic', basis: [fact.citation], reasoning, alternatives });

  if (sam !== undefined) {
    platform = platformCandidate('aws-lambda', sam, 0.85, 'AWS SAM テンプレートが存在するため。', [
      '一部の関数のみ SAM で管理されている可能性',
    ]);
  } else if (serverless !== undefined) {
    platform = platformCandidate(
      'aws-lambda',
      serverless,
      0.75,
      'Serverless Framework の設定が存在するため（provider が aws の場合 Lambda にデプロイされる）。',
      ['provider が aws 以外に設定されている可能性', '設定が古く実際には使われていない可能性'],
    );
  } else if (vercel !== undefined) {
    platform = platformCandidate('vercel', vercel, 0.8, 'vercel.json が存在するため。', [
      '設定ファイルだけ残っており実際は別基盤の可能性',
    ]);
  } else if (netlify !== undefined) {
    platform = platformCandidate('netlify', netlify, 0.8, 'netlify.toml が存在するため。', [
      '設定ファイルだけ残っており実際は別基盤の可能性',
    ]);
  } else if (cloudRunFact !== undefined) {
    platform = platformCandidate(
      'gcp-cloud-run',
      cloudRunFact,
      0.8,
      'Terraform に Cloud Run リソースが定義されているため。',
      [],
    );
  } else if (ecsFact !== undefined) {
    platform = platformCandidate(
      'aws-ecs',
      ecsFact,
      0.8,
      'IaC に ECS サービスが定義されているため。',
      ['ECS 以外の基盤と併用されている可能性'],
    );
  } else if (k8sResources.length > 0 || helm.length > 0) {
    const basisFact = (k8sResources[0] ?? helm[0]) as ObservedFact;
    platform = platformCandidate(
      'kubernetes',
      basisFact,
      0.7,
      'Kubernetes マニフェスト／Helm チャートが存在するため。マネージドか自前かは判別できない。',
      ['EKS/GKE/AKS などのマネージド基盤である可能性', 'ローカル検証用のマニフェストである可能性'],
    );
  } else if (ec2Fact !== undefined) {
    platform = platformCandidate('aws-ec2', ec2Fact, 0.6, 'Terraform に EC2 インスタンスが定義されているため。', [
      'ビルド用・踏み台用のインスタンスである可能性',
    ]);
  } else if (procfile !== undefined) {
    platform = platformCandidate('heroku', procfile, 0.5, 'Procfile が存在するため。', [
      'Foreman など Heroku 以外のプロセスマネージャで使われている可能性',
    ]);
  } else {
    platform = assumed('unknown', '実行基盤を示す設定ファイルが見つからなかった。');
    gaps.push('実行基盤（どこで動いているか）を推定できなかった。IaC・PaaS 設定がリポジトリ内に無いため。');
  }

  // ---- cloudProvider: 設定ファイルが明示的に書いていれば事実 ----
  let cloudProvider: DeploymentStack['cloudProvider'];
  const providerFact = cloudFacts.find((f) => /^(aws|google|azurerm|azure|cloudflare)$/.test(f.value));
  const providerMap: Record<string, DeploymentStack['cloudProvider']['value']> = {
    aws: 'aws',
    google: 'gcp',
    azurerm: 'azure',
    azure: 'azure',
    cloudflare: 'cloudflare',
  };
  if (providerFact !== undefined) {
    cloudProvider = observed(providerMap[providerFact.value] ?? 'unknown', [providerFact.citation]);
  } else {
    const awsEnv = factsOf(facts, 'env.variable').find((f) => f.value.startsWith('AWS_'));
    const awsDeploy = deploySteps.find((f) => /AWS|Amazon/.test(f.value));
    const hint = awsEnv ?? awsDeploy;
    if (hint !== undefined) {
      cloudProvider = inferred('aws', {
        confidence: 0.6,
        inferredBy: 'heuristic',
        basis: [hint.citation],
        reasoning: 'AWS 固有の環境変数／CI のデプロイ操作が観測されたため。',
        alternatives: ['S3 互換ストレージなど AWS 以外のサービスに AWS SDK を使っている可能性'],
      });
    } else {
      cloudProvider = assumed('unknown', 'クラウド事業者を示す設定が見つからなかった。');
      gaps.push('クラウド事業者を特定できなかった（プロバイダ宣言も固有の環境変数も無いため）。');
    }
  }

  // ---- cicd ----
  let cicd: DeploymentStack['cicd'];
  const cicdMap: Record<string, DeploymentStack['cicd']['value']> = {
    'github-actions': 'github-actions',
    'gitlab-ci': 'gitlab-ci',
    circleci: 'circleci',
    jenkins: 'jenkins',
  };
  const cicdFact = cicdFacts[0];
  if (cicdFact !== undefined) {
    cicd = observed(cicdMap[cicdFact.value] ?? 'unknown', [cicdFact.citation]);
  } else {
    // 「見つからない」を「CI なし」と断定しない
    cicd = assumed(
      'unknown',
      'CI 設定ファイルが見つからなかった。CI が無いのか、リポジトリ外（組織設定・別リポジトリ）で構成されているのかは区別できない。',
    );
    gaps.push('CI/CD を特定できなかった。設定ファイルがリポジトリ内に無いため「CI なし」とは断定していない。');
  }

  // ---- ingress ----
  let ingress: DeploymentStack['ingress'];
  const albFact = ingressFacts.find((f) => /alb/i.test(f.value));
  const nginxIngress = ingressFacts.find((f) => /nginx/i.test(f.value));
  const cloudfrontFact = iacFacts.find((f) => /cloudfront/i.test(f.value));
  const apigwFact =
    iacFacts.find((f) => /api_gateway|AWS::ApiGateway|AWS::Serverless::Api/.test(f.value)) ??
    factsOf(facts, 'platform.process').find((f) => /:(http|httpApi)$/.test(f.value));
  if (albFact !== undefined) {
    ingress = observed('alb', [albFact.citation]);
  } else if (nginxIngress !== undefined) {
    ingress = observed('nginx', [nginxIngress.citation]);
  } else if (cloudfrontFact !== undefined) {
    ingress = observed('cloudfront', [cloudfrontFact.citation]);
  } else if (apigwFact !== undefined) {
    ingress = inferred('api-gateway', {
      confidence: 0.75,
      inferredBy: 'heuristic',
      basis: [apigwFact.citation],
      reasoning: 'HTTP イベント／API Gateway リソースが定義されているため。',
      alternatives: ['Function URL や ALB 経由の呼び出しである可能性'],
    });
  } else {
    ingress = assumed('unknown', '受け口（LB・プロキシ）を示す設定が見つからなかった。');
    gaps.push('外部からの受け口（Ingress）を特定できなかった。');
  }

  // ---- secretsManagement ----
  let secretsManagement: DeploymentStack['secretsManagement'];
  const priority: Array<[string, DeploymentStack['secretsManagement']['value']]> = [
    ['vault', 'vault'],
    ['aws-secrets-manager', 'aws-secrets-manager'],
    ['k8s-secret', 'k8s-secret'],
    ['env-file', 'env-file'],
  ];
  const secretFact = priority
    .map(([value, mapped]) => ({ fact: secretFacts.find((f) => f.value === value), mapped }))
    .find((x) => x.fact !== undefined);
  if (secretFact !== undefined && secretFact.fact !== undefined) {
    secretsManagement = observed(secretFact.mapped, [secretFact.fact.citation]);
  } else if (secretFacts.some((f) => f.value === 'ci-secret')) {
    const fact = secretFacts.find((f) => f.value === 'ci-secret') as ObservedFact;
    secretsManagement = inferred('env-file', {
      confidence: 0.4,
      inferredBy: 'heuristic',
      basis: [fact.citation],
      reasoning:
        'CI のシークレット参照のみが観測された。実行時は環境変数として渡される構成が多いためそう推測したが、実基盤側の管理方法は不明。',
      alternatives: ['クラウドのシークレットマネージャを実行時に参照している可能性'],
    });
  } else {
    secretsManagement = assumed('unknown', '秘密情報の管理方法を示す設定が見つからなかった。');
    gaps.push('秘密情報の管理方法を特定できなかった。ハードコードの有無は本推定では判定していない。');
  }

  // ---- iac ----
  let iac: DeploymentStack['iac'];
  const iacByTool = (tool: string): ObservedFact | undefined =>
    iacFacts.find((f) => f.detail?.['tool'] === tool);
  const terraform = iacByTool('terraform');
  const cloudformation = iacByTool('cloudformation') ?? iacByTool('aws-sam');
  const pulumi = iacByTool('pulumi');
  const helmFact = helm[0];
  const detected = [
    terraform !== undefined ? 'terraform' : null,
    cloudformation !== undefined ? 'cloudformation' : null,
    pulumi !== undefined ? 'pulumi' : null,
    helmFact !== undefined ? 'helm' : null,
  ].filter((x): x is string => x !== null);

  if (terraform !== undefined) iac = observed('terraform', [terraform.citation]);
  else if (cloudformation !== undefined) iac = observed('cloudformation', [cloudformation.citation]);
  else if (pulumi !== undefined) iac = observed('pulumi', [pulumi.citation]);
  else if (helmFact !== undefined) iac = observed('helm', [helmFact.citation]);
  else {
    iac = assumed('unknown', 'IaC 設定が見つからなかった。');
    gaps.push('IaC の有無を特定できなかった。別リポジトリで管理されている可能性がある。');
  }
  if (detected.length > 1) {
    gaps.push(`複数の IaC ツールを検出した（${detected.join(', ')}）。主たるものは判別できないため先頭を採用した。`);
  }

  return {
    runtime,
    containerization,
    platform,
    cloudProvider,
    cicd,
    ingress,
    secretsManagement,
    iac,
  };
}

/** アーキテクチャ様式のヒューリスティック推定（LLM が使えない場合のフォールバック） */
export function heuristicStyle(
  factSet: FactSet,
  ctx: ScanContext,
  components: readonly ArchitectureComponent[],
): Claim<ArchitectureStyle> {
  const facts = factSet.facts;
  const serverlessFacts = factsOf(facts, 'platform.manifest').filter((f) =>
    ['serverless-framework', 'aws-sam', 'vercel', 'netlify'].includes(f.value),
  );
  const workloadCount = factsOf(facts, 'k8s.resource').filter((f) =>
    /^(Deployment|StatefulSet)\//.test(f.value),
  ).length;
  const composeServices = factsOf(facts, 'compose.service').length;
  const entryPoints = ctx?.entryPoints ?? [];
  const httpRoutes = entryPoints.filter((e) => e?.kind === 'http-route');
  const cliEntries = entryPoints.filter((e) => e?.kind === 'cli' || e?.kind === 'main');
  const frontendFramework = (ctx?.frameworks ?? []).some((f) =>
    /react|next|vue|nuxt|svelte|angular/i.test(f.name ?? ''),
  );

  if (serverlessFacts.length > 0) {
    return inferred('serverless', {
      confidence: 0.7,
      inferredBy: 'heuristic',
      basis: dedupeCitations(serverlessFacts.map((f) => f.citation)),
      reasoning: 'サーバレス系のデプロイ設定が存在するため。',
      alternatives: ['サーバレスは一部機能のみで、本体は常駐サーバの可能性'],
    });
  }
  if (workloadCount >= 3 || composeServices >= 4) {
    return inferred('microservices', {
      confidence: 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(
        [...factsOf(facts, 'k8s.resource'), ...factsOf(facts, 'compose.service')]
          .slice(0, 5)
          .map((f) => f.citation),
      ),
      reasoning: '複数のワークロード／サービスが定義されているため。',
      alternatives: [
        'ミドルウェア（DB・キャッシュ）を数えているだけで、アプリ自体は単一のモノリスである可能性',
      ],
    });
  }
  if (httpRoutes.length > 0 && frontendFramework) {
    return inferred('spa-with-api', {
      confidence: 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(httpRoutes.slice(0, 3).map((e) => ({ file: e.file, line: e.line }))),
      reasoning: 'HTTP API のエントリポイントとフロントエンドフレームワークの双方が検出されたため。',
      alternatives: ['サーバサイドレンダリングのモノリスである可能性'],
    });
  }
  if (httpRoutes.length > 0) {
    return inferred('monolith', {
      confidence: 0.45,
      inferredBy: 'heuristic',
      basis: dedupeCitations(httpRoutes.slice(0, 3).map((e) => ({ file: e.file, line: e.line }))),
      reasoning: '単一のアプリケーションに HTTP ルートが集約されているため。',
      alternatives: ['複数サービスの一部だけを見ている可能性'],
    });
  }
  if (cliEntries.length > 0 && components.length <= 1) {
    return inferred('cli-tool', {
      confidence: 0.5,
      inferredBy: 'heuristic',
      basis: dedupeCitations(cliEntries.slice(0, 3).map((e) => ({ file: e.file, line: e.line }))),
      reasoning: 'CLI/main のエントリポイントのみが検出され、ネットワーク構成要素が乏しいため。',
      alternatives: ['ライブラリとしても配布されている可能性'],
    });
  }
  return assumed('unknown', 'アーキテクチャ様式を判断できる根拠が得られなかった。');
}

/** ヒューリスティックのみで作るモデル骨格 */
export function buildDraft(factSet: FactSet, ctx: ScanContext): DraftModel {
  const gaps: string[] = [];
  const { components, componentIdByName } = buildComponents(factSet, ctx, gaps);
  const deployment = buildDeployment(factSet, ctx, gaps);
  const dataFlows = buildDataFlows(components, factSet, componentIdByName);
  const style = heuristicStyle(factSet, ctx, components);
  return { style, components, dataFlows, deployment, gaps, componentIdByName };
}

export { KIND_LABEL };
