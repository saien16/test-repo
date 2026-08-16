/**
 * コンテナ系マニフェストの解析（Dockerfile / docker-compose / Kubernetes / Helm）。
 *
 * ここで作るのは「ファイルにそう書いてある」事実だけ。
 * 露出度や様式の判断は行わない（それらは model.ts と LLM の担当）。
 * パース失敗は例外にせず warnings に積む。
 */

import { parse as parseYaml, parseAllDocuments } from 'yaml';
import type { ComponentKind } from '../types/architecture.js';
import {
  citationFor,
  citationForKey,
  emptyOutput,
  type ObservedFact,
  type ParseOutput,
  type ServiceSignal,
  truncate,
} from './facts.js';

/** イメージ名（レジストリ・タグを除いた最終セグメント）→ 構成要素種別と技術名 */
const IMAGE_CATALOG: Array<{ match: RegExp; kind: ComponentKind; label: string }> = [
  { match: /^(postgres|postgresql|timescale|pgvector|postgis)/, kind: 'database', label: 'PostgreSQL' },
  { match: /^(mysql|mariadb|percona)/, kind: 'database', label: 'MySQL 系 RDBMS' },
  { match: /^mongo/, kind: 'database', label: 'MongoDB' },
  { match: /^(cockroach|yugabyte)/, kind: 'database', label: '分散 RDBMS' },
  { match: /^(elasticsearch|opensearch)/, kind: 'database', label: '検索エンジン (Elasticsearch 系)' },
  { match: /^(redis|valkey)/, kind: 'cache', label: 'Redis' },
  { match: /^memcached/, kind: 'cache', label: 'Memcached' },
  { match: /^rabbitmq/, kind: 'message-queue', label: 'RabbitMQ' },
  { match: /^(kafka|redpanda|cp-kafka)/, kind: 'message-queue', label: 'Kafka 系' },
  { match: /^(nats|pulsar)/, kind: 'message-queue', label: 'NATS/Pulsar 系' },
  { match: /^(minio|ceph)/, kind: 'object-storage', label: 'S3 互換オブジェクトストレージ' },
  { match: /^(nginx|traefik|haproxy|envoy|caddy)/, kind: 'gateway', label: 'リバースプロキシ' },
  { match: /^(keycloak|dex|authelia|hydra|ory)/, kind: 'auth-provider', label: '認証基盤' },
  { match: /^localstack/, kind: 'external-api', label: 'AWS エミュレータ (LocalStack)' },
];

/** 言語ランタイムのベースイメージ */
const RUNTIME_IMAGES: Array<{ match: RegExp; label: string }> = [
  { match: /^node/, label: 'Node.js' },
  { match: /^(python|pypy)/, label: 'Python' },
  { match: /^(golang|go)$/, label: 'Go' },
  { match: /^(openjdk|eclipse-temurin|amazoncorretto|ibm-semeru|jdk|jre)/, label: 'Java' },
  { match: /^ruby/, label: 'Ruby' },
  { match: /^php/, label: 'PHP' },
  { match: /^rust/, label: 'Rust' },
  { match: /^(dotnet|aspnet|mcr\.microsoft\.com)/, label: '.NET' },
  { match: /^(deno|bun)/, label: 'JavaScript ランタイム' },
];

/** レジストリ・タグ・ダイジェストを落として比較用の名前を得る */
export function imageBaseName(image: string): string {
  const withoutDigest = image.split('@')[0] ?? image;
  const parts = withoutDigest.split('/');
  const last = parts[parts.length - 1] ?? withoutDigest;
  const withoutTag = last.split(':')[0] ?? last;
  return withoutTag.toLowerCase();
}

/** イメージからバックエンド種別を判定する。該当が無ければ null */
export function classifyImage(image: string): { kind: ComponentKind; label: string } | null {
  const base = imageBaseName(image);
  for (const entry of IMAGE_CATALOG) {
    if (entry.match.test(base)) return { kind: entry.kind, label: entry.label };
  }
  return null;
}

/** ベースイメージから言語ランタイム名を得る。判らなければ null */
export function runtimeFromImage(image: string): string | null {
  const base = imageBaseName(image);
  for (const entry of RUNTIME_IMAGES) {
    if (entry.match.test(base)) {
      const tag = image.split('@')[0]?.split(':')[1];
      return tag !== undefined && tag !== '' ? `${entry.label} ${tag}` : entry.label;
    }
  }
  return null;
}

/** サービス名・リソース名から役割を推し量る（弱い根拠なので確信度は低く扱う） */
export function kindFromName(name: string): { kind: ComponentKind; confidence: number } | null {
  const n = name.toLowerCase();
  if (/(front|web|ui|client|spa|next|nuxt)/.test(n)) return { kind: 'web-frontend', confidence: 0.5 };
  if (/(worker|consumer|cron|batch|job|scheduler)/.test(n)) {
    return { kind: 'background-worker', confidence: 0.55 };
  }
  if (/(gateway|proxy|ingress|lb)/.test(n)) return { kind: 'gateway', confidence: 0.55 };
  if (/(auth|identity|sso|keycloak)/.test(n)) return { kind: 'auth-provider', confidence: 0.5 };
  if (/(api|backend|server|app|service|svc)/.test(n)) return { kind: 'api-service', confidence: 0.5 };
  return null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : null;
}

// ---- Dockerfile ----

/** Dockerfile を解析する。行単位の正規表現で十分（行番号が正確に取れる） */
export function parseDockerfile(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? '';
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const excerpt = truncate(line);
    const citation = { file: path, line: i + 1, excerpt };

    const from = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (from !== null) {
      const image = from[1] ?? '';
      const stage = from[2];
      const fact: ObservedFact = {
        kind: 'container.base-image',
        value: image,
        citation,
        detail: stage !== undefined ? { stage } : undefined,
      };
      out.facts.push(fact);
      // ベースイメージがミドルウェアなら、その構成要素の存在も事実として拾う
      const classified = classifyImage(image);
      if (classified !== null && classified.kind === 'gateway') {
        out.services.push({
          kind: 'gateway',
          name: imageBaseName(image),
          technology: image,
          literal: true,
          citation,
          sourcePaths: [path],
        });
      }
      continue;
    }

    const expose = /^EXPOSE\s+(.+)$/i.exec(line);
    if (expose !== null) {
      for (const token of (expose[1] ?? '').split(/\s+/)) {
        const port = token.split('/')[0];
        if (port !== undefined && /^\d+$/.test(port)) {
          out.facts.push({ kind: 'container.exposed-port', value: port, citation });
        }
      }
      continue;
    }

    const entry = /^(CMD|ENTRYPOINT)\s+(.+)$/i.exec(line);
    if (entry !== null) {
      out.facts.push({
        kind: 'container.entrypoint',
        value: truncate(entry[2] ?? ''),
        citation,
        detail: { instruction: (entry[1] ?? '').toUpperCase() },
      });
      continue;
    }

    const env = /^ENV\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (env !== null) {
      out.facts.push({ kind: 'env.variable', value: env[1] ?? '', citation });
    }
  }

  return out;
}

// ---- docker-compose ----

export function parseCompose(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let doc: unknown;
  try {
    doc = parseYaml(content);
  } catch (err) {
    out.warnings.push(`docker-compose を解釈できませんでした: ${path} (${String(err)})`);
    return out;
  }
  const root = asRecord(doc);
  if (root === null) return out;
  const services = asRecord(root['services']);
  if (services === null) {
    out.warnings.push(`docker-compose に services が見つかりませんでした: ${path}`);
    return out;
  }

  for (const [name, rawService] of Object.entries(services)) {
    const service = asRecord(rawService);
    const nameCitation = citationForKey(path, content, name);
    out.facts.push({ kind: 'compose.service', value: name, citation: nameCitation });
    if (service === null) continue;

    const image = asString(service['image']);
    const hasBuild = service['build'] !== undefined;

    if (image !== null) {
      const imageCitation = citationFor(path, content, image);
      out.facts.push({
        kind: 'k8s.container-image',
        value: image,
        citation: imageCitation,
        detail: { service: name, source: 'docker-compose' },
      });
      const classified = classifyImage(image);
      if (classified !== null) {
        out.services.push({
          kind: classified.kind,
          name,
          // イメージ名は引用テキストそのもの。事実として扱える
          technology: image,
          literal: true,
          citation: imageCitation,
        });
      } else {
        const guessed = kindFromName(name);
        out.services.push({
          kind: guessed?.kind ?? 'unknown',
          name,
          technology: image,
          literal: true,
          citation: imageCitation,
        });
      }
    } else if (hasBuild) {
      const guessed = kindFromName(name);
      out.services.push({
        kind: guessed?.kind ?? 'unknown',
        name,
        technology: 'このリポジトリからビルドされるコンテナ',
        literal: false,
        confidence: guessed?.confidence ?? 0.4,
        reasoning: `docker-compose のサービス "${name}" は build 指定を持つため、このリポジトリのコードが動く構成要素とみなした。種別はサービス名からの推測。`,
        citation: nameCitation,
        sourcePaths: [],
      });
    }

    const ports = service['ports'];
    if (Array.isArray(ports)) {
      for (const entry of ports) {
        const text = asString(entry) ?? asString(asRecord(entry)?.['published']);
        if (text === null) continue;
        out.facts.push({
          kind: 'compose.published-port',
          value: text,
          citation: citationFor(path, content, String(text)),
          detail: { service: name },
        });
      }
    }

    const dependsOn = service['depends_on'];
    const deps = Array.isArray(dependsOn)
      ? dependsOn.map((d) => asString(d)).filter((d): d is string => d !== null)
      : Object.keys(asRecord(dependsOn) ?? {});
    for (const dep of deps) {
      out.facts.push({
        kind: 'compose.depends-on',
        value: `${name} -> ${dep}`,
        citation: nameCitation,
        detail: { from: name, to: dep },
      });
    }

    const env = service['environment'];
    const envNames: string[] = Array.isArray(env)
      ? env
          .map((e) => asString(e))
          .filter((e): e is string => e !== null)
          .map((e) => e.split('=')[0] ?? e)
      : Object.keys(asRecord(env) ?? {});
    for (const envName of envNames) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) continue;
      out.facts.push({
        kind: 'env.variable',
        value: envName,
        citation: citationFor(path, content, envName),
        detail: { service: name },
      });
    }

    if (service['env_file'] !== undefined) {
      out.facts.push({
        kind: 'secrets.mechanism',
        value: 'env-file',
        citation: citationFor(path, content, 'env_file'),
        detail: { service: name },
      });
    }
  }

  return out;
}

// ---- Kubernetes ----

const WORKLOAD_KINDS = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Pod']);

/** Kubernetes マニフェストか（複数ドキュメントのいずれかが kind+apiVersion を持つか） */
export function looksLikeKubernetes(content: string): boolean {
  return /^\s*kind\s*:\s*\S+/m.test(content) && /^\s*apiVersion\s*:\s*\S+/m.test(content);
}

function collectContainers(spec: Record<string, unknown> | null): Array<Record<string, unknown>> {
  if (spec === null) return [];
  const out: Array<Record<string, unknown>> = [];
  const template = asRecord(spec['template']);
  const podSpec = asRecord(template?.['spec']) ?? asRecord(spec['jobTemplate']) ?? spec;
  const inner = asRecord(asRecord(asRecord(podSpec['spec'])?.['template'])?.['spec']) ?? podSpec;
  for (const key of ['containers', 'initContainers']) {
    const list = inner[key];
    if (!Array.isArray(list)) continue;
    for (const c of list) {
      const rec = asRecord(c);
      if (rec !== null) out.push(rec);
    }
  }
  return out;
}

export function parseKubernetes(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let docs;
  try {
    docs = parseAllDocuments(content);
  } catch (err) {
    out.warnings.push(`Kubernetes マニフェストを解釈できませんでした: ${path} (${String(err)})`);
    return out;
  }

  for (const doc of docs) {
    // 構文エラーを含むドキュメントは解釈しない（誤った事実を作らないため）
    if (Array.isArray(doc.errors) && doc.errors.length > 0) {
      out.warnings.push(
        `YAML に構文エラーがあるため解析を見送りました: ${path} (${doc.errors[0]?.message ?? '詳細不明'})`,
      );
      continue;
    }
    let value: unknown;
    try {
      value = doc.toJS({ maxAliasCount: 100 });
    } catch (err) {
      out.warnings.push(`YAML ドキュメントを展開できませんでした: ${path} (${String(err)})`);
      continue;
    }
    const root = asRecord(value);
    if (root === null) continue;
    const kind = asString(root['kind']);
    const apiVersion = asString(root['apiVersion']);
    if (kind === null || apiVersion === null) continue;

    const metadata = asRecord(root['metadata']);
    const name = asString(metadata?.['name']) ?? '(名前なし)';
    const kindCitation = citationFor(path, content, `kind: ${kind}`);
    out.facts.push({
      kind: 'k8s.resource',
      value: `${kind}/${name}`,
      citation: kindCitation,
      detail: { kind, name, apiVersion },
    });

    const spec = asRecord(root['spec']);

    if (WORKLOAD_KINDS.has(kind)) {
      for (const container of collectContainers(spec)) {
        const image = asString(container['image']);
        if (image === null) continue;
        const imageCitation = citationFor(path, content, image);
        out.facts.push({
          kind: 'k8s.container-image',
          value: image,
          citation: imageCitation,
          detail: { resource: `${kind}/${name}`, source: 'kubernetes' },
        });
        const classified = classifyImage(image);
        const guessed = kindFromName(name);
        out.services.push({
          kind: classified?.kind ?? guessed?.kind ?? 'unknown',
          name,
          technology: image,
          literal: true,
          citation: imageCitation,
        });
        // Secret 参照は秘密情報の受け渡し方法の事実になる
        const envList = container['env'];
        if (Array.isArray(envList)) {
          for (const e of envList) {
            const rec = asRecord(e);
            const envName = asString(rec?.['name']);
            if (envName !== null) {
              out.facts.push({
                kind: 'env.variable',
                value: envName,
                citation: citationFor(path, content, `name: ${envName}`),
                detail: { resource: `${kind}/${name}` },
              });
            }
            if (asRecord(asRecord(rec?.['valueFrom'])?.['secretKeyRef']) !== null) {
              out.facts.push({
                kind: 'k8s.secret-ref',
                value: envName ?? '(不明)',
                citation: citationFor(path, content, 'secretKeyRef'),
              });
              out.facts.push({
                kind: 'secrets.mechanism',
                value: 'k8s-secret',
                citation: citationFor(path, content, 'secretKeyRef'),
              });
            }
          }
        }
      }
    }

    if (kind === 'Service') {
      const type = asString(spec?.['type']) ?? 'ClusterIP';
      out.facts.push({
        kind: 'k8s.service-type',
        value: type,
        citation: citationFor(path, content, `type: ${type}`),
        detail: { name },
      });
    }

    if (kind === 'Ingress') {
      const className =
        asString(spec?.['ingressClassName']) ??
        asString(asRecord(metadata?.['annotations'])?.['kubernetes.io/ingress.class']);
      if (className !== null) {
        out.facts.push({
          kind: 'k8s.ingress',
          value: className,
          citation: citationFor(path, content, className),
          detail: { name, field: 'ingressClass' },
        });
      }
      const rules = spec?.['rules'];
      if (Array.isArray(rules)) {
        for (const rule of rules) {
          const host = asString(asRecord(rule)?.['host']);
          if (host === null) continue;
          out.facts.push({
            kind: 'k8s.ingress',
            value: host,
            citation: citationFor(path, content, host),
            detail: { name, field: 'host' },
          });
        }
      }
      const annotations = asRecord(metadata?.['annotations']);
      for (const key of Object.keys(annotations ?? {})) {
        if (key.includes('alb.ingress.kubernetes.io')) {
          out.facts.push({
            kind: 'k8s.ingress',
            value: 'alb',
            citation: citationFor(path, content, key),
            detail: { name, field: 'annotation' },
          });
          break;
        }
        if (key.includes('nginx.ingress.kubernetes.io')) {
          out.facts.push({
            kind: 'k8s.ingress',
            value: 'nginx',
            citation: citationFor(path, content, key),
            detail: { name, field: 'annotation' },
          });
          break;
        }
      }
    }

    if (kind === 'Secret') {
      out.facts.push({
        kind: 'secrets.mechanism',
        value: 'k8s-secret',
        citation: kindCitation,
        detail: { name },
      });
    }
  }

  return out;
}

// ---- Helm ----

export function parseHelmChart(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  let doc: unknown;
  try {
    doc = parseYaml(content);
  } catch (err) {
    out.warnings.push(`Helm Chart.yaml を解釈できませんでした: ${path} (${String(err)})`);
    return out;
  }
  const root = asRecord(doc);
  const name = asString(root?.['name']);
  if (name === null) return out;
  out.facts.push({
    kind: 'helm.chart',
    value: name,
    citation: citationFor(path, content, `name: ${name}`),
  });
  return out;
}

/** 型の再エクスポート（テストから使う） */
export type { ServiceSignal };
