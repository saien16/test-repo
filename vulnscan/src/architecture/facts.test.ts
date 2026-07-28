/**
 * 事実収集（ヒューリスティック）の検証。
 *
 * ここでの主眼は「observed と名乗るものが必ず実在する引用を持つこと」。
 * 行番号・ファイル名が実在しない事実は、この時点で作られてはいけない。
 */

import { describe, expect, it } from 'vitest';
import { observed } from '../types/evidence.js';
import { collectFacts } from './collect.js';
import { classifyImage, parseDockerfile, parseKubernetes, runtimeFromImage } from './containers.js';
import { classifyManifest } from './discover.js';
import { citationForKey, findLineNumber } from './facts.js';
import { buildDraft } from './model.js';
import { parseTerraform } from './platforms.js';
import {
  brokenFileSystem,
  makeContext,
  memoryFileSystem,
  SAMPLE_FILES,
  sampleContext,
} from './test-fixtures.js';

describe('出所モデルの前提', () => {
  it('引用のない observed は作れない（型ではなく実行時にも落ちる）', () => {
    expect(() => observed('node:20', [])).toThrow();
    expect(observed('node:20', [{ file: 'Dockerfile', line: 1 }]).provenance.kind).toBe('observed');
  });
});

describe('テキストユーティリティ', () => {
  it('findLineNumber は 1 始まりの行番号を返す', () => {
    expect(findLineNumber('a\nb\nc', 'c')).toBe(3);
    expect(findLineNumber('a\nb', 'zzz')).toBeNull();
  });

  it('citationForKey は値の中の同名文字列を掴まない', () => {
    const yaml = ['services:', '  api:', '    url: postgres://db:5432/app', '  db:', '    image: x'].join(
      '\n',
    );
    // `db:` は 3 行目の値の中にも現れるが、キー定義は 4 行目
    expect(citationForKey('compose.yml', yaml, 'db').line).toBe(4);
  });
});

describe('マニフェスト分類', () => {
  it('主要なファイル名を判別する', () => {
    expect(classifyManifest('Dockerfile')).toBe('dockerfile');
    expect(classifyManifest('app/Dockerfile.prod')).toBe('dockerfile');
    expect(classifyManifest('docker-compose.yml')).toBe('compose');
    expect(classifyManifest('serverless.yml')).toBe('serverless');
    expect(classifyManifest('infra/main.tf')).toBe('terraform');
    expect(classifyManifest('.github/workflows/ci.yml')).toBe('github-workflow');
    expect(classifyManifest('vercel.json')).toBe('vercel');
    expect(classifyManifest('Procfile')).toBe('procfile');
    expect(classifyManifest('README.md')).toBeNull();
  });
});

describe('Dockerfile 解析', () => {
  const content = SAMPLE_FILES['Dockerfile'] as string;
  const out = parseDockerfile('Dockerfile', content);

  it('FROM / EXPOSE / CMD を正確な行番号付きで拾う', () => {
    const base = out.facts.filter((f) => f.kind === 'container.base-image');
    expect(base).toHaveLength(2);
    expect(base[0]?.value).toBe('node:20-alpine');
    expect(base[0]?.citation.line).toBe(2);
    // 引用行が実際にその内容であること
    const lines = content.split('\n');
    expect(lines[(base[0]?.citation.line ?? 1) - 1]).toContain('FROM node:20-alpine');

    const port = out.facts.find((f) => f.kind === 'container.exposed-port');
    expect(port?.value).toBe('3000');
    expect(lines[(port?.citation.line ?? 1) - 1]).toContain('EXPOSE 3000');
  });

  it('イメージ名からランタイム・ミドルウェアを識別する', () => {
    expect(runtimeFromImage('node:20-alpine')).toContain('Node.js');
    expect(classifyImage('postgres:15')?.kind).toBe('database');
    expect(classifyImage('redis:7')?.kind).toBe('cache');
    expect(classifyImage('ghcr.io/example/api:1.0')).toBeNull();
  });
});

describe('Kubernetes 解析', () => {
  it('複数ドキュメント・Service type・Secret 参照を拾う', () => {
    const content = SAMPLE_FILES['k8s/deployment.yaml'] as string;
    const out = parseKubernetes('k8s/deployment.yaml', content);
    const kinds = out.facts.filter((f) => f.kind === 'k8s.resource').map((f) => f.value);
    expect(kinds).toContain('Deployment/api');
    expect(kinds).toContain('Service/api');
    expect(out.facts.find((f) => f.kind === 'k8s.service-type')?.value).toBe('LoadBalancer');
    expect(out.facts.some((f) => f.kind === 'secrets.mechanism' && f.value === 'k8s-secret')).toBe(
      true,
    );
  });

  it('壊れた YAML でも例外を投げず warnings に積む', () => {
    const out = parseKubernetes('k8s/broken.yaml', 'kind: Deployment\n  : : :\n\tbad');
    expect(out.warnings.length).toBeGreaterThan(0);
    expect(out.facts).toEqual([]);
  });
});

describe('Terraform 解析', () => {
  it('provider と resource を拾う', () => {
    const out = parseTerraform('infra/main.tf', SAMPLE_FILES['infra/main.tf'] as string);
    expect(out.facts.find((f) => f.kind === 'cloud.provider')?.value).toBe('aws');
    expect(out.facts.filter((f) => f.kind === 'iac.resource').map((f) => f.value)).toContain(
      'aws_db_instance.main',
    );
    expect(out.services.some((s) => s.kind === 'object-storage')).toBe(true);
  });
});

describe('collectFacts / buildDraft', () => {
  it('収集した事実の引用は必ず実在するファイルを指す', async () => {
    const factSet = await collectFacts(sampleContext(), memoryFileSystem(SAMPLE_FILES));
    expect(factSet.facts.length).toBeGreaterThan(10);
    for (const fact of factSet.facts) {
      expect(Object.keys(SAMPLE_FILES)).toContain(fact.citation.file);
      const content = SAMPLE_FILES[fact.citation.file] as string;
      if (fact.citation.line !== undefined) {
        expect(fact.citation.line).toBeLessThanOrEqual(content.split('\n').length);
      }
    }
  });

  it('依存ライブラリ由来の技術特定は事実ではなく推測として扱う', async () => {
    const factSet = await collectFacts(sampleContext(), memoryFileSystem(SAMPLE_FILES));
    const pgSignal = factSet.services.find((s) => s.technology === 'PostgreSQL');
    expect(pgSignal?.literal).toBe(false);
    expect(pgSignal?.reasoning).toContain('pg');
  });

  it('イメージ名は引用そのものなので事実、Terraform 由来の製品名は推測', async () => {
    const ctx = sampleContext();
    const factSet = await collectFacts(ctx, memoryFileSystem(SAMPLE_FILES));
    const draft = buildDraft(factSet, ctx);

    const postgres = draft.components.find((c) => c.id === 'database-postgresql');
    expect(postgres?.technology.provenance.kind).toBe('observed');

    const rds = draft.components.find((c) => c.technology.value === 'Amazon RDS');
    expect(rds?.technology.provenance.kind).toBe('inferred');
  });

  it('露出度・認証要否は事実にしない（必ず推測か仮定）', async () => {
    const ctx = sampleContext();
    const factSet = await collectFacts(ctx, memoryFileSystem(SAMPLE_FILES));
    const draft = buildDraft(factSet, ctx);
    for (const component of draft.components) {
      expect(component.exposure.provenance.kind).not.toBe('observed');
      expect(component.requiresAuthentication.provenance.kind).not.toBe('observed');
      expect(component.dataSensitivity.provenance.kind).not.toBe('observed');
    }
  });

  it('デプロイスタックは書いてある事実と推測を分ける', async () => {
    const ctx = sampleContext();
    const factSet = await collectFacts(ctx, memoryFileSystem(SAMPLE_FILES));
    const draft = buildDraft(factSet, ctx);

    // Dockerfile / k8s / tf に literal に書いてあるもの
    expect(draft.deployment.runtime.provenance.kind).toBe('observed');
    expect(draft.deployment.containerization.value).toBe('kubernetes');
    expect(draft.deployment.cloudProvider.value).toBe('aws');
    expect(draft.deployment.cicd.value).toBe('github-actions');
    expect(draft.deployment.iac.value).toBe('terraform');

    // 実行基盤は「どこで動くか」なので必ず推測
    expect(draft.deployment.platform.provenance.kind).toBe('inferred');
  });

  it('マニフェストが無ければ断定せず gaps に理由を残す', async () => {
    const ctx = makeContext();
    const factSet = await collectFacts(ctx, memoryFileSystem({ 'README.md': '# hi' }));
    const draft = buildDraft(factSet, ctx);
    expect(draft.deployment.cicd.provenance.kind).toBe('assumed');
    expect(draft.gaps.join('\n')).toContain('CI/CD を特定できなかった');
    // 「CI なし」と断定していないこと
    expect(draft.deployment.cicd.value).toBe('unknown');
  });

  it('ファイルシステムが壊れていても例外を投げない', async () => {
    const factSet = await collectFacts(makeContext(), brokenFileSystem());
    expect(factSet.warnings.length).toBeGreaterThan(0);
    expect(factSet.facts).toEqual([]);
  });
});
