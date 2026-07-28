/**
 * ソースコード・依存関係・エントリポイント由来のシグナル収集。
 *
 * 依存名からバックエンドを特定する（`pg` → PostgreSQL）のは
 * 「引用テキストがそのまま述べていること」ではないため literal=false、
 * つまり inferred(heuristic) として扱う。
 * 一方、依存が宣言されているという事実そのものは引用付きで残す。
 */

import type { ComponentKind } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import { citationFor, emptyOutput, fileCitation, type ParseOutput } from './facts.js';
import { MAX_ENV_SCAN_FILES, type RepoFileSystem } from './discover.js';

interface ClientEntry {
  kind: ComponentKind;
  label: string;
  /** 依存名からバックエンドを断定できる度合い */
  confidence: number;
}

/** 依存パッケージ名 → バックエンド。ecosystem をまたいで名前で引く */
const DEPENDENCY_CATALOG: Record<string, ClientEntry> = {
  // --- RDBMS ---
  pg: { kind: 'database', label: 'PostgreSQL', confidence: 0.9 },
  'pg-promise': { kind: 'database', label: 'PostgreSQL', confidence: 0.9 },
  postgres: { kind: 'database', label: 'PostgreSQL', confidence: 0.85 },
  psycopg2: { kind: 'database', label: 'PostgreSQL', confidence: 0.9 },
  'psycopg2-binary': { kind: 'database', label: 'PostgreSQL', confidence: 0.9 },
  asyncpg: { kind: 'database', label: 'PostgreSQL', confidence: 0.9 },
  mysql: { kind: 'database', label: 'MySQL', confidence: 0.9 },
  mysql2: { kind: 'database', label: 'MySQL', confidence: 0.9 },
  pymysql: { kind: 'database', label: 'MySQL', confidence: 0.9 },
  mariadb: { kind: 'database', label: 'MariaDB', confidence: 0.9 },
  sqlite3: { kind: 'database', label: 'SQLite', confidence: 0.85 },
  'better-sqlite3': { kind: 'database', label: 'SQLite', confidence: 0.85 },
  mssql: { kind: 'database', label: 'SQL Server', confidence: 0.85 },
  // --- ORM（DB 製品までは断定できないので確信度を下げる） ---
  sequelize: { kind: 'database', label: 'SQL データベース (Sequelize 経由)', confidence: 0.6 },
  typeorm: { kind: 'database', label: 'SQL データベース (TypeORM 経由)', confidence: 0.6 },
  knex: { kind: 'database', label: 'SQL データベース (Knex 経由)', confidence: 0.6 },
  '@prisma/client': { kind: 'database', label: 'SQL データベース (Prisma 経由)', confidence: 0.65 },
  sqlalchemy: { kind: 'database', label: 'SQL データベース (SQLAlchemy 経由)', confidence: 0.6 },
  django: { kind: 'database', label: 'SQL データベース (Django ORM 経由)', confidence: 0.5 },
  gorm: { kind: 'database', label: 'SQL データベース (GORM 経由)', confidence: 0.6 },
  // --- ドキュメント DB ---
  mongoose: { kind: 'database', label: 'MongoDB', confidence: 0.9 },
  mongodb: { kind: 'database', label: 'MongoDB', confidence: 0.9 },
  pymongo: { kind: 'database', label: 'MongoDB', confidence: 0.9 },
  '@elastic/elasticsearch': { kind: 'database', label: 'Elasticsearch', confidence: 0.85 },
  elasticsearch: { kind: 'database', label: 'Elasticsearch', confidence: 0.85 },
  // --- キャッシュ ---
  redis: { kind: 'cache', label: 'Redis', confidence: 0.9 },
  ioredis: { kind: 'cache', label: 'Redis', confidence: 0.9 },
  'node-redis': { kind: 'cache', label: 'Redis', confidence: 0.9 },
  memcached: { kind: 'cache', label: 'Memcached', confidence: 0.9 },
  pymemcache: { kind: 'cache', label: 'Memcached', confidence: 0.9 },
  // --- キュー ---
  amqplib: { kind: 'message-queue', label: 'RabbitMQ (AMQP)', confidence: 0.85 },
  pika: { kind: 'message-queue', label: 'RabbitMQ (AMQP)', confidence: 0.85 },
  kafkajs: { kind: 'message-queue', label: 'Apache Kafka', confidence: 0.9 },
  'kafka-python': { kind: 'message-queue', label: 'Apache Kafka', confidence: 0.9 },
  bullmq: { kind: 'message-queue', label: 'BullMQ (Redis ベース)', confidence: 0.85 },
  bull: { kind: 'message-queue', label: 'Bull (Redis ベース)', confidence: 0.8 },
  celery: { kind: 'message-queue', label: 'Celery', confidence: 0.85 },
  '@aws-sdk/client-sqs': { kind: 'message-queue', label: 'Amazon SQS', confidence: 0.9 },
  nats: { kind: 'message-queue', label: 'NATS', confidence: 0.85 },
  // --- オブジェクトストレージ ---
  '@aws-sdk/client-s3': { kind: 'object-storage', label: 'Amazon S3', confidence: 0.9 },
  'aws-sdk': { kind: 'object-storage', label: 'AWS サービス群 (SDK v2)', confidence: 0.4 },
  boto3: { kind: 'object-storage', label: 'AWS サービス群 (boto3)', confidence: 0.4 },
  '@google-cloud/storage': { kind: 'object-storage', label: 'Google Cloud Storage', confidence: 0.9 },
  '@azure/storage-blob': { kind: 'object-storage', label: 'Azure Blob Storage', confidence: 0.9 },
  minio: { kind: 'object-storage', label: 'MinIO (S3 互換)', confidence: 0.85 },
  // --- 認証 ---
  passport: { kind: 'auth-provider', label: 'Passport (自前認証)', confidence: 0.6 },
  'next-auth': { kind: 'auth-provider', label: 'NextAuth', confidence: 0.8 },
  'auth0-js': { kind: 'auth-provider', label: 'Auth0', confidence: 0.85 },
  'express-openid-connect': { kind: 'auth-provider', label: 'Auth0 / OIDC', confidence: 0.8 },
  '@clerk/nextjs': { kind: 'auth-provider', label: 'Clerk', confidence: 0.85 },
  'firebase-admin': { kind: 'auth-provider', label: 'Firebase', confidence: 0.7 },
  '@okta/okta-sdk-nodejs': { kind: 'auth-provider', label: 'Okta', confidence: 0.85 },
  // --- 外部 API ---
  stripe: { kind: 'external-api', label: 'Stripe (決済)', confidence: 0.9 },
  twilio: { kind: 'external-api', label: 'Twilio', confidence: 0.9 },
  '@sendgrid/mail': { kind: 'external-api', label: 'SendGrid', confidence: 0.9 },
  nodemailer: { kind: 'external-api', label: 'SMTP メール送信', confidence: 0.7 },
};

/** 環境変数名 → バックエンド */
const ENV_CATALOG: Array<{ match: RegExp; entry: ClientEntry }> = [
  {
    match: /^(DATABASE_URL|DB_(HOST|URL|NAME|PORT)|POSTGRES_[A-Z_]+|PG(HOST|DATABASE|USER))$/,
    entry: { kind: 'database', label: 'リレーショナルDB（製品は環境変数名からは断定不可）', confidence: 0.55 },
  },
  { match: /^MYSQL_[A-Z_]+$/, entry: { kind: 'database', label: 'MySQL', confidence: 0.7 } },
  { match: /^MONGO(DB)?_(URI|URL|HOST)$/, entry: { kind: 'database', label: 'MongoDB', confidence: 0.75 } },
  { match: /^REDIS_[A-Z_]+$/, entry: { kind: 'cache', label: 'Redis', confidence: 0.75 } },
  { match: /^MEMCACHED_[A-Z_]+$/, entry: { kind: 'cache', label: 'Memcached', confidence: 0.75 } },
  { match: /^(RABBITMQ|AMQP)_[A-Z_]+$/, entry: { kind: 'message-queue', label: 'RabbitMQ', confidence: 0.75 } },
  { match: /^KAFKA_[A-Z_]+$/, entry: { kind: 'message-queue', label: 'Apache Kafka', confidence: 0.75 } },
  { match: /^(SQS_[A-Z_]+|.*_QUEUE_URL)$/, entry: { kind: 'message-queue', label: 'Amazon SQS', confidence: 0.7 } },
  {
    match: /^(S3_BUCKET|AWS_S3_[A-Z_]+|BUCKET_NAME)$/,
    entry: { kind: 'object-storage', label: 'Amazon S3（または S3 互換）', confidence: 0.7 },
  },
  {
    match: /^(AUTH0_[A-Z_]+|OKTA_[A-Z_]+|CLERK_[A-Z_]+|COGNITO_[A-Z_]+)$/,
    entry: { kind: 'auth-provider', label: '外部 IdP', confidence: 0.7 },
  },
  { match: /^STRIPE_[A-Z_]+$/, entry: { kind: 'external-api', label: 'Stripe (決済)', confidence: 0.8 } },
  { match: /^(SMTP_[A-Z_]+|SENDGRID_[A-Z_]+)$/, entry: { kind: 'external-api', label: 'メール送信サービス', confidence: 0.7 } },
];

/** インフラ構成の手掛かりになる環境変数（バックエンドには結び付かないもの） */
const INFRA_ENV_PATTERN =
  /\b(AWS_REGION|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_DEFAULT_REGION|AWS_LAMBDA_FUNCTION_NAME|GOOGLE_CLOUD_PROJECT|GCP_PROJECT|AZURE_SUBSCRIPTION_ID|KUBERNETES_SERVICE_HOST|VERCEL_ENV|VERCEL_URL|NETLIFY|DYNO|PORT|NODE_ENV|VAULT_ADDR|SECRETS_MANAGER_[A-Z_]+)\b/g;

/** 全カタログを合わせた環境変数抽出パターン */
const SERVICE_ENV_PATTERN =
  /\b(DATABASE_URL|DB_HOST|DB_URL|DB_NAME|DB_PORT|POSTGRES_[A-Z_]+|PGHOST|PGDATABASE|PGUSER|MYSQL_[A-Z_]+|MONGODB_URI|MONGO_URI|MONGODB_URL|MONGO_URL|MONGO_HOST|REDIS_[A-Z_]+|MEMCACHED_[A-Z_]+|RABBITMQ_[A-Z_]+|AMQP_[A-Z_]+|KAFKA_[A-Z_]+|SQS_[A-Z_]+|[A-Z][A-Z0-9_]*_QUEUE_URL|S3_BUCKET|AWS_S3_[A-Z_]+|BUCKET_NAME|AUTH0_[A-Z_]+|OKTA_[A-Z_]+|CLERK_[A-Z_]+|COGNITO_[A-Z_]+|STRIPE_[A-Z_]+|SMTP_[A-Z_]+|SENDGRID_[A-Z_]+)\b/g;

/** 依存関係からバックエンドのシグナルを作る */
export function signalsFromDependencies(
  ctx: ScanContext,
  contents: ReadonlyMap<string, string>,
): ParseOutput {
  const out = emptyOutput();
  const seen = new Set<string>();

  for (const dep of ctx?.dependencies ?? []) {
    if (dep?.dev === true) continue; // 開発依存は実行時構成の根拠として弱い
    const name = typeof dep?.name === 'string' ? dep.name : '';
    const entry = DEPENDENCY_CATALOG[name.toLowerCase()] ?? DEPENDENCY_CATALOG[name];
    if (entry === undefined) continue;
    const key = `${entry.kind}:${entry.label}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const manifest = typeof dep.manifest === 'string' ? dep.manifest : '';
    const manifestContent = contents.get(manifest);
    const citation =
      manifestContent !== undefined
        ? citationFor(manifest, manifestContent, name)
        : fileCitation(manifest !== '' ? manifest : 'package.json');

    out.facts.push({
      kind: 'dependency.client',
      value: `${dep.name}@${dep.version}`,
      citation,
      detail: { ecosystem: String(dep.ecosystem ?? '不明'), maps_to: entry.label },
    });
    out.services.push({
      kind: entry.kind,
      name: entry.label,
      technology: entry.label,
      // 「pg という依存がある」は事実だが「PostgreSQL を使っている」は推測
      literal: false,
      confidence: entry.confidence,
      reasoning: `依存パッケージ ${dep.name}@${dep.version} (${dep.ecosystem}) は ${entry.label} のクライアントライブラリであるため、対応するバックエンドが存在すると推測した。`,
      citation,
    });
  }

  return out;
}

/** エントリポイントから事実を作る（ScanContext が file/line を持つので引用可能） */
export function signalsFromEntryPoints(ctx: ScanContext): ParseOutput {
  const out = emptyOutput();
  for (const ep of ctx?.entryPoints ?? []) {
    if (typeof ep?.file !== 'string') continue;
    out.facts.push({
      kind: 'entrypoint',
      value: `${ep.kind}: ${ep.identifier}`,
      citation: { file: ep.file, line: typeof ep.line === 'number' ? ep.line : undefined },
      detail: { kind: ep.kind, identifier: String(ep.identifier ?? '') },
    });
  }
  return out;
}

/**
 * ソースファイル・.env から環境変数参照を拾う。
 * 全ファイルを読むのは高価なので件数とサイズに上限を設ける。
 */
export async function signalsFromEnvironment(
  ctx: ScanContext,
  fs: RepoFileSystem,
  alreadyRead: ReadonlyMap<string, string>,
): Promise<ParseOutput> {
  const out = emptyOutput();
  const seenService = new Set<string>();
  const seenEnv = new Set<string>();

  const codeLanguages = new Set([
    'typescript',
    'javascript',
    'python',
    'go',
    'ruby',
    'java',
    'php',
    'dotenv',
    'shell',
  ]);
  const targets: string[] = [];
  for (const file of ctx?.files ?? []) {
    if (targets.length >= MAX_ENV_SCAN_FILES) break;
    if (typeof file?.path !== 'string') continue;
    if (!codeLanguages.has(file.language)) continue;
    targets.push(file.path);
  }
  // .env 系は ctx.files に含まれないこともあるので、読み込み済みのものを足す
  for (const path of alreadyRead.keys()) {
    if (/(^|\/)\.env(\.|$)/.test(path) && !targets.includes(path)) targets.push(path);
  }

  for (const path of targets) {
    let content = alreadyRead.get(path) ?? null;
    if (content === null) {
      try {
        content = await fs.read(path);
      } catch (err) {
        out.warnings.push(`ファイルを読めませんでした: ${path} (${String(err)})`);
        continue;
      }
    }
    if (content === null) continue;

    SERVICE_ENV_PATTERN.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SERVICE_ENV_PATTERN.exec(content)) !== null) {
      const name = m[1] ?? '';
      if (!seenEnv.has(name)) {
        seenEnv.add(name);
        out.facts.push({
          kind: 'env.variable',
          value: name,
          citation: citationFor(path, content, name),
        });
      }
      const matched = ENV_CATALOG.find((c) => c.match.test(name));
      if (matched === undefined) continue;
      const key = `${matched.entry.kind}:${matched.entry.label}`;
      if (seenService.has(key)) continue;
      seenService.add(key);
      out.services.push({
        kind: matched.entry.kind,
        name: matched.entry.label,
        technology: matched.entry.label,
        literal: false,
        confidence: matched.entry.confidence,
        reasoning: `環境変数 ${name} が参照されているため、対応するバックエンドが存在すると推測した。ただし変数名だけでは製品・バージョンは断定できない。`,
        citation: citationFor(path, content, name),
      });
    }

    INFRA_ENV_PATTERN.lastIndex = 0;
    while ((m = INFRA_ENV_PATTERN.exec(content)) !== null) {
      const name = m[1] ?? '';
      if (seenEnv.has(name)) continue;
      seenEnv.add(name);
      out.facts.push({
        kind: 'env.variable',
        value: name,
        citation: citationFor(path, content, name),
        detail: { category: 'infra' },
      });
    }
  }

  return out;
}
