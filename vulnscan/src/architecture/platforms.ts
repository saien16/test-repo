/**
 * デプロイ先・IaC・CI/CD 設定の解析。
 *
 * ここでも「書いてあること」だけを事実にする。
 * 例えば serverless.yml に `provider: {name: aws}` とあるのは事実だが、
 * 「実行基盤が AWS Lambda である」は（強い根拠ではあるが）推測なので
 * model.ts 側で inferred として扱う。
 */

import { parse as parseYaml } from 'yaml';
import type { ComponentKind } from '../types/architecture.js';
import { citationFor, emptyOutput, fileCitation, type ParseOutput, truncate } from './facts.js';

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : null;
}

// ---- serverless framework ----

export function parseServerless(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let doc: unknown;
  try {
    doc = path.endsWith('.json') ? JSON.parse(content) : parseYaml(content);
  } catch (err) {
    out.warnings.push(`serverless 設定を解釈できませんでした: ${path} (${String(err)})`);
    return out;
  }
  const root = asRecord(doc);
  if (root === null) return out;

  out.facts.push({
    kind: 'platform.manifest',
    value: 'serverless-framework',
    citation: fileCitation(path),
  });

  const provider = asRecord(root['provider']);
  const providerName = asString(provider?.['name']) ?? asString(root['provider']);
  if (providerName !== null) {
    out.facts.push({
      kind: 'cloud.provider',
      value: providerName,
      citation: citationFor(path, content, providerName),
      detail: { source: 'serverless.yml' },
    });
  }
  const runtime = asString(provider?.['runtime']);
  if (runtime !== null) {
    out.facts.push({
      kind: 'platform.manifest',
      value: `runtime: ${runtime}`,
      citation: citationFor(path, content, runtime),
      detail: { field: 'runtime', runtime },
    });
  }

  const functions = asRecord(root['functions']);
  for (const [name, rawFn] of Object.entries(functions ?? {})) {
    const fn = asRecord(rawFn);
    const citation = citationFor(path, content, `${name}:`);
    const handler = asString(fn?.['handler']);
    out.facts.push({
      kind: 'platform.process',
      value: name,
      citation,
      detail: { kind: 'serverless-function', handler: handler ?? '(不明)' },
    });
    const events = fn?.['events'];
    if (Array.isArray(events)) {
      for (const event of events) {
        const rec = asRecord(event);
        for (const key of Object.keys(rec ?? {})) {
          out.facts.push({
            kind: 'platform.process',
            value: `${name}:${key}`,
            citation: citationFor(path, content, key),
            detail: { kind: 'serverless-event', event: key, function: name },
          });
        }
      }
    }
    out.services.push({
      kind: 'api-service',
      name,
      technology: handler !== null ? `Lambda ハンドラ ${handler}` : `Lambda 関数 ${name}`,
      literal: handler !== null,
      citation,
      sourcePaths: handler !== null ? [handler.split('.')[0] ?? ''] : [],
    });
  }

  return out;
}

// ---- SAM / CloudFormation ----

/** AWS リソースタイプ → 構成要素種別 */
const CFN_RESOURCE_CATALOG: Array<{ match: RegExp; kind: ComponentKind; label: string }> = [
  { match: /^AWS::Serverless::Function$/, kind: 'api-service', label: 'AWS Lambda 関数' },
  { match: /^AWS::Lambda::Function$/, kind: 'api-service', label: 'AWS Lambda 関数' },
  { match: /^AWS::RDS::/, kind: 'database', label: 'Amazon RDS' },
  { match: /^AWS::DynamoDB::Table$/, kind: 'database', label: 'Amazon DynamoDB' },
  { match: /^AWS::ElastiCache::/, kind: 'cache', label: 'Amazon ElastiCache' },
  { match: /^AWS::S3::Bucket$/, kind: 'object-storage', label: 'Amazon S3' },
  { match: /^AWS::SQS::Queue$/, kind: 'message-queue', label: 'Amazon SQS' },
  { match: /^AWS::SNS::Topic$/, kind: 'message-queue', label: 'Amazon SNS' },
  { match: /^AWS::ApiGateway/, kind: 'gateway', label: 'Amazon API Gateway' },
  { match: /^AWS::Serverless::Api$/, kind: 'gateway', label: 'Amazon API Gateway' },
  { match: /^AWS::CloudFront::/, kind: 'cdn', label: 'Amazon CloudFront' },
  { match: /^AWS::Cognito::/, kind: 'auth-provider', label: 'Amazon Cognito' },
  { match: /^AWS::ECS::Service$/, kind: 'api-service', label: 'Amazon ECS サービス' },
  { match: /^AWS::SecretsManager::/, kind: 'unknown', label: 'AWS Secrets Manager' },
];

export function looksLikeCloudFormation(content: string): boolean {
  return (
    /AWSTemplateFormatVersion/.test(content) ||
    /Transform\s*:\s*['"]?AWS::Serverless/.test(content) ||
    /Type\s*:\s*['"]?AWS::[A-Za-z]+::/.test(content)
  );
}

export function parseCloudFormation(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let doc: unknown;
  try {
    // SAM の短縮関数タグ（!Ref など）が含まれると厳格パースは失敗するため寛容に扱う
    doc = path.endsWith('.json') ? JSON.parse(content) : parseYaml(content, { logLevel: 'silent' });
  } catch {
    // 構造化できなくても Type 行の正規表現だけで事実は拾える
    doc = null;
  }

  const isSam = /Transform\s*:\s*['"]?AWS::Serverless/.test(content);
  out.facts.push({
    kind: 'platform.manifest',
    value: isSam ? 'aws-sam' : 'cloudformation',
    citation: fileCitation(path),
  });

  const resources = asRecord(asRecord(doc)?.['Resources']);
  const entries: Array<{ name: string; type: string }> = [];
  if (resources !== null) {
    for (const [name, raw] of Object.entries(resources)) {
      const type = asString(asRecord(raw)?.['Type']);
      if (type !== null) entries.push({ name, type });
    }
  } else {
    // フォールバック: `Type: AWS::...` 行を拾う
    const re = /Type\s*:\s*['"]?(AWS::[A-Za-z0-9:]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      entries.push({ name: m[1] ?? '', type: m[1] ?? '' });
    }
  }

  for (const entry of entries) {
    const citation = citationFor(path, content, entry.type);
    out.facts.push({
      kind: 'iac.resource',
      value: `${entry.type} (${entry.name})`,
      citation,
      detail: { tool: isSam ? 'aws-sam' : 'cloudformation', type: entry.type, name: entry.name },
    });
    const classified = CFN_RESOURCE_CATALOG.find((c) => c.match.test(entry.type));
    if (classified !== undefined && classified.kind !== 'unknown') {
      out.services.push({
        kind: classified.kind,
        name: entry.name,
        technology: classified.label,
        literal: false,
        confidence: 0.85,
        reasoning: `CloudFormation/SAM のリソース型 ${entry.type} から ${classified.label} と判断した。`,
        citation,
      });
    }
    if (/^AWS::SecretsManager::/.test(entry.type)) {
      out.facts.push({ kind: 'secrets.mechanism', value: 'aws-secrets-manager', citation });
    }
  }

  out.facts.push({
    kind: 'cloud.provider',
    value: 'aws',
    citation: citationFor(path, content, 'AWS::'),
    detail: { source: isSam ? 'aws-sam' : 'cloudformation' },
  });

  return out;
}

// ---- Terraform ----

const TF_RESOURCE_CATALOG: Array<{ match: RegExp; kind: ComponentKind; label: string }> = [
  { match: /^aws_(db_instance|rds_cluster|rds_cluster_instance)$/, kind: 'database', label: 'Amazon RDS' },
  { match: /^aws_dynamodb_table$/, kind: 'database', label: 'Amazon DynamoDB' },
  { match: /^aws_elasticache/, kind: 'cache', label: 'Amazon ElastiCache' },
  { match: /^aws_s3_bucket$/, kind: 'object-storage', label: 'Amazon S3' },
  { match: /^aws_(sqs_queue|sns_topic)$/, kind: 'message-queue', label: 'Amazon SQS/SNS' },
  { match: /^aws_msk/, kind: 'message-queue', label: 'Amazon MSK (Kafka)' },
  { match: /^aws_lambda_function$/, kind: 'api-service', label: 'AWS Lambda 関数' },
  { match: /^aws_ecs_service$/, kind: 'api-service', label: 'Amazon ECS サービス' },
  { match: /^aws_instance$/, kind: 'api-service', label: 'Amazon EC2 インスタンス' },
  { match: /^aws_(lb|alb|elb)$/, kind: 'gateway', label: 'AWS ロードバランサ' },
  { match: /^aws_api_gateway/, kind: 'gateway', label: 'Amazon API Gateway' },
  { match: /^aws_cloudfront_distribution$/, kind: 'cdn', label: 'Amazon CloudFront' },
  { match: /^aws_cognito/, kind: 'auth-provider', label: 'Amazon Cognito' },
  { match: /^google_cloud_run/, kind: 'api-service', label: 'Google Cloud Run' },
  { match: /^google_sql_database_instance$/, kind: 'database', label: 'Cloud SQL' },
  { match: /^google_storage_bucket$/, kind: 'object-storage', label: 'Cloud Storage' },
  { match: /^azurerm_(postgresql|mysql|sql)/, kind: 'database', label: 'Azure Database' },
  { match: /^azurerm_storage_account$/, kind: 'object-storage', label: 'Azure Storage' },
];

export function parseTerraform(path: string, content: string): ParseOutput {
  const out = emptyOutput();

  const providerRe = /provider\s+"([\w-]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = providerRe.exec(content)) !== null) {
    const name = m[1] ?? '';
    out.facts.push({
      kind: 'cloud.provider',
      value: name,
      citation: citationFor(path, content, m[0]),
      detail: { source: 'terraform' },
    });
  }

  const resourceRe = /resource\s+"([\w-]+)"\s+"([\w.-]+)"/g;
  while ((m = resourceRe.exec(content)) !== null) {
    const type = m[1] ?? '';
    const name = m[2] ?? '';
    const citation = citationFor(path, content, m[0]);
    out.facts.push({
      kind: 'iac.resource',
      value: `${type}.${name}`,
      citation,
      detail: { tool: 'terraform', type, name },
    });
    const classified = TF_RESOURCE_CATALOG.find((c) => c.match.test(type));
    if (classified !== undefined) {
      out.services.push({
        kind: classified.kind,
        name,
        technology: classified.label,
        literal: false,
        confidence: 0.85,
        reasoning: `Terraform のリソース型 ${type} から ${classified.label} と判断した。`,
        citation,
      });
    }
    if (/^aws_secretsmanager/.test(type)) {
      out.facts.push({ kind: 'secrets.mechanism', value: 'aws-secrets-manager', citation });
    }
    if (/^vault_/.test(type)) {
      out.facts.push({ kind: 'secrets.mechanism', value: 'vault', citation });
    }
  }

  if (out.facts.length === 0) {
    out.facts.push({ kind: 'iac.resource', value: 'terraform 設定', citation: fileCitation(path) });
  }
  return out;
}

// ---- Pulumi / PaaS 各種 ----

export function parsePulumi(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let doc: unknown;
  try {
    doc = parseYaml(content);
  } catch (err) {
    out.warnings.push(`Pulumi.yaml を解釈できませんでした: ${path} (${String(err)})`);
    return out;
  }
  const root = asRecord(doc);
  out.facts.push({
    kind: 'iac.resource',
    value: `pulumi:${asString(root?.['name']) ?? '(名前なし)'}`,
    citation: fileCitation(path),
    detail: { tool: 'pulumi', runtime: asString(root?.['runtime']) ?? '不明' },
  });
  return out;
}

export function parseVercel(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  out.facts.push({ kind: 'platform.manifest', value: 'vercel', citation: fileCitation(path) });
  try {
    const root = asRecord(JSON.parse(content));
    const functions = asRecord(root?.['functions']);
    for (const name of Object.keys(functions ?? {})) {
      out.facts.push({
        kind: 'platform.process',
        value: name,
        citation: citationFor(path, content, name),
        detail: { kind: 'vercel-function' },
      });
    }
  } catch (err) {
    out.warnings.push(`vercel.json を解釈できませんでした: ${path} (${String(err)})`);
  }
  return out;
}

export function parseNetlify(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  // TOML パーサは持ち込まない方針のため、存在と主要キーの有無だけを事実にする
  out.facts.push({ kind: 'platform.manifest', value: 'netlify', citation: fileCitation(path) });
  const fnDir = /functions\s*=\s*"([^"]+)"/.exec(content);
  if (fnDir !== null) {
    out.facts.push({
      kind: 'platform.process',
      value: `netlify functions: ${fnDir[1] ?? ''}`,
      citation: citationFor(path, content, fnDir[0]),
      detail: { kind: 'netlify-functions' },
    });
  }
  return out;
}

export function parseProcfile(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  out.facts.push({ kind: 'platform.manifest', value: 'procfile', citation: fileCitation(path) });
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = /^([A-Za-z0-9_-]+)\s*:\s*(.+)$/.exec(line);
    if (m === null) continue;
    out.facts.push({
      kind: 'platform.process',
      value: m[1] ?? '',
      citation: { file: path, line: i + 1, excerpt: truncate(line) },
      detail: { kind: 'procfile', command: truncate(m[2] ?? '') },
    });
  }
  return out;
}

export function parsePaasManifest(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  const base = path.toLowerCase();
  const platform = base.endsWith('fly.toml')
    ? 'fly.io'
    : base.endsWith('render.yaml')
      ? 'render'
      : 'app.yaml (PaaS 候補)';
  out.facts.push({
    kind: 'platform.manifest',
    value: platform,
    citation: fileCitation(path),
  });
  if (/^runtime\s*:/m.test(content)) {
    const m = /^runtime\s*:\s*(\S+)/m.exec(content);
    if (m !== null) {
      out.facts.push({
        kind: 'platform.manifest',
        value: `runtime: ${m[1] ?? ''}`,
        citation: citationFor(path, content, m[0]),
        detail: { field: 'runtime', runtime: m[1] ?? '' },
      });
    }
  }
  return out;
}

// ---- CI/CD ----

/** ワークフロー中に現れたらデプロイ先の手掛かりになる文字列 */
const DEPLOY_HINTS: Array<{ needle: RegExp; label: string }> = [
  { needle: /aws-actions\/configure-aws-credentials/, label: 'AWS 認証' },
  { needle: /aws\s+ecs\s+update-service|amazon-ecs-deploy-task-definition/, label: 'Amazon ECS デプロイ' },
  { needle: /aws\s+lambda\s+update-function|serverless\s+deploy/, label: 'AWS Lambda デプロイ' },
  { needle: /aws\s+s3\s+sync/, label: 'Amazon S3 同期' },
  { needle: /kubectl\s+(apply|rollout)/, label: 'Kubernetes デプロイ' },
  { needle: /helm\s+(upgrade|install)/, label: 'Helm デプロイ' },
  { needle: /vercel(\s|@|\/)/, label: 'Vercel デプロイ' },
  { needle: /netlify(\s|@|\/)/, label: 'Netlify デプロイ' },
  { needle: /docker\s+(push|buildx)/, label: 'コンテナイメージ push' },
  { needle: /google-github-actions\/deploy-cloudrun/, label: 'Google Cloud Run デプロイ' },
  { needle: /azure\/webapps-deploy/, label: 'Azure App Service デプロイ' },
  { needle: /terraform\s+apply/, label: 'Terraform 適用' },
];

export function parseCiWorkflow(path: string, content: string, tool: string): ParseOutput {
  const out = emptyOutput();
  out.facts.push({
    kind: 'cicd.workflow',
    value: tool,
    citation: fileCitation(path),
    detail: { file: path },
  });
  for (const hint of DEPLOY_HINTS) {
    const m = hint.needle.exec(content);
    if (m === null) continue;
    out.facts.push({
      kind: 'cicd.deploy-step',
      value: hint.label,
      citation: citationFor(path, content, m[0]),
      detail: { tool },
    });
  }
  if (/secrets\.[A-Z_]+/.test(content)) {
    const m = /secrets\.[A-Z_]+/.exec(content);
    out.facts.push({
      kind: 'secrets.mechanism',
      value: 'ci-secret',
      citation: citationFor(path, content, m?.[0] ?? 'secrets.'),
      detail: { tool },
    });
  }
  return out;
}
