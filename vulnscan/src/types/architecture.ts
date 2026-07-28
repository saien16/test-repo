/**
 * システムアーキテクチャとデプロイメントスタックの推定モデル。
 *
 * ここで扱う値のほとんどは「推測」である。Dockerfile に FROM node:20 と
 * 書いてあるのは事実だが、「このサービスがインターネットに公開されている」
 * のは推測でしかない。そのため全項目を Claim<T> で包み、
 * 読み手が事実と推測を区別できるようにする。
 */

import type { Claim, EvidenceBreakdown } from './evidence.js';

/** アーキテクチャ様式 */
export type ArchitectureStyle =
  | 'monolith'
  | 'microservices'
  | 'serverless'
  | 'spa-with-api'
  | 'static-site'
  | 'cli-tool'
  | 'library'
  | 'batch-job'
  | 'unknown';

/** 構成要素の種別 */
export type ComponentKind =
  | 'web-frontend'
  | 'api-service'
  | 'database'
  | 'cache'
  | 'message-queue'
  | 'object-storage'
  | 'auth-provider'
  | 'background-worker'
  | 'gateway'
  | 'cdn'
  | 'external-api'
  | 'cli'
  | 'unknown';

/** ネットワーク露出度。攻撃者からの到達しやすさ */
export type Exposure =
  /** インターネットから直接到達可能 */
  | 'public-internet'
  /** 社内ネットワーク・VPC内からのみ */
  | 'internal'
  /** 同一ホスト・同一プロセスからのみ */
  | 'local'
  | 'unknown';

/** データの機微度 */
export type DataSensitivity = 'pii' | 'credentials' | 'financial' | 'business' | 'none' | 'unknown';

export interface ArchitectureComponent {
  id: string;
  kind: ComponentKind;
  /** 表示名。例: 'API サーバ (Express)' */
  name: string;
  /** 使用技術。例: 'PostgreSQL 15', 'Redis' */
  technology: Claim<string>;
  exposure: Claim<Exposure>;
  /** 扱うデータの機微度 */
  dataSensitivity: Claim<DataSensitivity[]>;
  /** 認証を要求するか */
  requiresAuthentication: Claim<boolean>;
  /**
   * この構成要素に対応するソースパス（前方一致）。
   * ヒートマップで Finding を構成要素に割り当てるのに使う。
   */
  sourcePaths: string[];
  /** 対応するエントリポイント識別子（ScanContext.entryPoints 由来） */
  entryPointIds: string[];
}

/** 構成要素間のデータの流れ */
export interface ComponentDataFlow {
  fromId: string;
  toId: string;
  /** 例: 'HTTP', 'SQL', 'AMQP' */
  protocol: Claim<string>;
  /** 信頼境界をまたぐか。またぐ箇所はリスクが高い */
  crossesTrustBoundary: Claim<boolean>;
}

/** デプロイメントスタック */
export interface DeploymentStack {
  /** 例: 'Node.js 20', 'Python 3.12' */
  runtime: Claim<string>;
  containerization: Claim<'docker' | 'kubernetes' | 'none' | 'unknown'>;
  /** 実行基盤 */
  platform: Claim<
    'aws-lambda' | 'aws-ecs' | 'aws-ec2' | 'gcp-cloud-run' | 'gke' | 'azure-app-service'
    | 'vercel' | 'netlify' | 'heroku' | 'kubernetes' | 'bare-vm' | 'unknown'
  >;
  cloudProvider: Claim<'aws' | 'gcp' | 'azure' | 'cloudflare' | 'none' | 'unknown'>;
  cicd: Claim<'github-actions' | 'gitlab-ci' | 'circleci' | 'jenkins' | 'none' | 'unknown'>;
  /** 受け口 */
  ingress: Claim<'alb' | 'nginx' | 'api-gateway' | 'cloudfront' | 'direct' | 'unknown'>;
  /** 秘密情報の管理方法 */
  secretsManagement: Claim<
    'env-file' | 'aws-secrets-manager' | 'vault' | 'k8s-secret' | 'hardcoded' | 'unknown'
  >;
  /** インフラのコード化 */
  iac: Claim<'terraform' | 'cloudformation' | 'pulumi' | 'helm' | 'none' | 'unknown'>;
}

export interface ArchitectureModel {
  style: Claim<ArchitectureStyle>;
  components: ArchitectureComponent[];
  dataFlows: ComponentDataFlow[];
  deployment: DeploymentStack;
  /**
   * この推定全体がどれだけ事実に裏付けられているか。
   * observed が少なく inferred/assumed ばかりなら、
   * 下流のヒートマップも当然その分だけ不確実になる。
   */
  evidence: EvidenceBreakdown;
  /** 推定にあたって参照した設定ファイル群 */
  inspectedManifests: string[];
  /** 推定できなかった項目とその理由 */
  gaps: string[];
}
