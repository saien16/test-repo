/**
 * テスト用フィクスチャ。
 * 実ファイルシステムに触れずに事実収集を検証できるよう、
 * インメモリの RepoFileSystem と最小の ScanContext を提供する。
 */

import type { VulnScanConfig } from '../types/config.js';
import type { Dependency, EntryPoint, ScanContext, SourceFile } from '../types/context.js';
import type { RepoFileSystem } from './discover.js';
import { normalizeRepoPath } from './facts.js';

/** ファイル内容の辞書からインメモリ FS を作る */
export function memoryFileSystem(files: Record<string, string>): RepoFileSystem {
  const table = new Map(Object.entries(files).map(([k, v]) => [normalizeRepoPath(k), v]));
  return {
    async list(): Promise<string[]> {
      return [...table.keys()];
    },
    async read(relPath: string): Promise<string | null> {
      return table.get(normalizeRepoPath(relPath)) ?? null;
    },
  };
}

/** 読み込みが必ず失敗する FS（堅牢性の検証用） */
export function brokenFileSystem(): RepoFileSystem {
  return {
    async list(): Promise<string[]> {
      throw new Error('走査できません');
    },
    async read(): Promise<string | null> {
      throw new Error('読めません');
    },
  };
}

export function makeSourceFile(path: string, language = 'typescript'): SourceFile {
  return { path, language, sizeBytes: 100, hash: 'x' };
}

export function makeDependency(
  name: string,
  overrides: Partial<Dependency> = {},
): Dependency {
  return {
    name,
    version: '1.0.0',
    ecosystem: 'npm',
    dev: false,
    manifest: 'package.json',
    ...overrides,
  };
}

export function makeEntryPoint(overrides: Partial<EntryPoint> = {}): EntryPoint {
  return {
    kind: 'http-route',
    identifier: 'GET /api/items',
    file: 'src/api.ts',
    line: 5,
    ...overrides,
  };
}

export function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot: '/repo',
    scannedAt: '2026-01-01T00:00:00.000Z',
    languages: [{ name: 'typescript', fileCount: 10, ratio: 1 }],
    frameworks: [{ name: 'Express', evidence: 'express' }],
    dependencies: [],
    files: [],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [],
    trustBoundaries: [],
    warnings: [],
    ...overrides,
  };
}

export function makeConfig(overrides: Partial<VulnScanConfig> = {}): VulnScanConfig {
  return {
    llm: {
      model: 'claude-opus-5',
      effort: 'high',
      maxTokens: 16000,
      concurrency: 2,
      tokenBudget: null,
      fallbackModel: null,
      cache: false,
    },
    scan: {
      exclude: [],
      include: [],
      lenses: ['injection'],
      selfVerify: false,
      minConfidence: 0.5,
      maxFileBytes: 512_000,
    },
    failOn: 'high',
    failOnNewOnly: false,
    baselinePath: '.vulnscan/baseline.json',
    ignorePath: '.vulnignore',
    killChain: true,
    architecture: true,
    heatmap: true,
    minInferenceConfidence: 0.3,
    ...overrides,
  };
}

/** 典型的なリポジトリ（Dockerfile + compose + k8s + CI + terraform） */
export const SAMPLE_FILES: Record<string, string> = {
  Dockerfile: [
    '# アプリケーションのビルド',
    'FROM node:20-alpine AS build',
    'WORKDIR /app',
    'COPY . .',
    'RUN npm ci && npm run build',
    '',
    'FROM node:20-alpine',
    'ENV NODE_ENV=production',
    'EXPOSE 3000',
    'CMD ["node", "dist/server.js"]',
  ].join('\n'),
  'docker-compose.yml': [
    'services:',
    '  api:',
    '    build: .',
    '    ports:',
    '      - "3000:3000"',
    '    environment:',
    '      DATABASE_URL: postgres://db:5432/app',
    '      REDIS_URL: redis://cache:6379',
    '    depends_on:',
    '      - db',
    '      - cache',
    '  db:',
    '    image: postgres:15',
    '  cache:',
    '    image: redis:7',
  ].join('\n'),
  'k8s/deployment.yaml': [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata:',
    '  name: api',
    'spec:',
    '  template:',
    '    spec:',
    '      containers:',
    '        - name: api',
    '          image: ghcr.io/example/api:1.2.3',
    '          env:',
    '            - name: DATABASE_URL',
    '              valueFrom:',
    '                secretKeyRef:',
    '                  name: db-secret',
    '                  key: url',
    '---',
    'apiVersion: v1',
    'kind: Service',
    'metadata:',
    '  name: api',
    'spec:',
    '  type: LoadBalancer',
  ].join('\n'),
  '.github/workflows/deploy.yml': [
    'name: deploy',
    'on: push',
    'jobs:',
    '  deploy:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: aws-actions/configure-aws-credentials@v4',
    '      - run: kubectl apply -f k8s/',
    '        env:',
    '          TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
  ].join('\n'),
  'infra/main.tf': [
    'provider "aws" {',
    '  region = "ap-northeast-1"',
    '}',
    '',
    'resource "aws_db_instance" "main" {',
    '  engine = "postgres"',
    '}',
    '',
    'resource "aws_s3_bucket" "uploads" {}',
  ].join('\n'),
  'package.json': JSON.stringify(
    {
      name: 'sample',
      engines: { node: '>=20' },
      scripts: { start: 'node dist/server.js' },
      dependencies: { express: '^4.19.0', pg: '^8.11.0', ioredis: '^5.4.0' },
    },
    null,
    2,
  ),
  'src/api.ts': [
    "import express from 'express';",
    'const app = express();',
    "const dbUrl = process.env.DATABASE_URL;",
    "const redisUrl = process.env.REDIS_URL;",
    "app.get('/api/items', (req, res) => res.json([]));",
  ].join('\n'),
};

export function sampleContext(): ScanContext {
  return makeContext({
    files: [makeSourceFile('src/api.ts')],
    dependencies: [
      makeDependency('express'),
      makeDependency('pg', { version: '8.11.0' }),
      makeDependency('ioredis', { version: '5.4.0' }),
    ],
    entryPoints: [makeEntryPoint()],
  });
}
