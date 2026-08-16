/**
 * inferArchitecture の統合検証。
 *
 * 検証の軸は 3 つ:
 *   1. 事実と推測が混ざらないこと（observed は必ず実在引用を持つ）
 *   2. LLM が失敗しても事実部分は残ること
 *   3. LLM の捏造引用・存在しない id が素通りしないこと
 */

import { describe, expect, it, vi } from 'vitest';
import type { Claim } from '../types/evidence.js';
import type { LlmClient, LlmResult } from '../llm/client.js';
import { collectClaims, inferArchitecture, preferClaim } from './index.js';
import type { ArchitectureResponse } from './schema.js';
import {
  makeConfig,
  makeContext,
  memoryFileSystem,
  SAMPLE_FILES,
  sampleContext,
} from './test-fixtures.js';

// --- LLM モック -----------------------------------------------------------

function mockLlm(result: LlmResult<ArchitectureResponse>): {
  llm: LlmClient;
  structured: ReturnType<typeof vi.fn>;
} {
  const structured = vi.fn(async () => result);
  return { llm: { structured } as unknown as LlmClient, structured };
}

function judgement<T>(
  value: T,
  confidence: number,
  basis: Array<{ file: string; line: number | null; excerpt: string | null }> = [],
): ArchitectureResponse['style'] & { value: T } {
  return {
    value,
    confidence,
    reasoning: `${String(value)} と判断した理由`,
    alternatives: ['別の可能性'],
    basis,
  } as ArchitectureResponse['style'] & { value: T };
}

function goodResponse(
  overrides: Partial<ArchitectureResponse> = {},
): ArchitectureResponse {
  return {
    style: judgement('microservices', 0.8, [
      { file: 'k8s/deployment.yaml', line: 2, excerpt: 'kind: Deployment' },
    ]),
    components: [
      {
        componentId: 'api-service-api',
        exposure: judgement('public-internet', 0.9, [
          { file: 'k8s/deployment.yaml', line: 23, excerpt: 'type: LoadBalancer' },
        ]),
        dataSensitivity: judgement(['pii', 'business'], 0.6),
        requiresAuthentication: judgement(true, 0.55),
      },
      {
        componentId: 'database-postgresql',
        exposure: judgement('internal', 0.7),
        dataSensitivity: judgement(['pii'], 0.5),
        requiresAuthentication: judgement(true, 0.8),
      },
    ],
    dataFlows: [
      {
        fromId: 'api-service-api',
        toId: 'database-postgresql',
        protocol: judgement('PostgreSQL wire protocol', 0.85),
        crossesTrustBoundary: judgement(false, 0.6),
      },
    ],
    unknowns: ['本番のネットワーク分離設定はリポジトリからは判断できない'],
    ...overrides,
  } as ArchitectureResponse;
}

const fsOptions = () => ({ fs: memoryFileSystem(SAMPLE_FILES) });

/** モデル内の observed 引用がすべて実在ファイルを指しているか */
function assertObservedCitationsExist(claims: Array<Claim<unknown>>): void {
  for (const claim of claims) {
    if (claim.provenance.kind !== 'observed') continue;
    expect(claim.provenance.citations.length).toBeGreaterThan(0);
    for (const citation of claim.provenance.citations) {
      expect(Object.keys(SAMPLE_FILES)).toContain(citation.file);
      if (citation.line !== undefined) {
        const content = SAMPLE_FILES[citation.file] as string;
        expect(citation.line).toBeLessThanOrEqual(content.split('\n').length);
      }
    }
  }
}

// --- テスト ---------------------------------------------------------------

describe('inferArchitecture / 設定で無効化', () => {
  it('architecture=false なら LLM を呼ばず最小モデルを返す', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: goodResponse(),
      fromCache: false,
      model: 'x',
    });
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      llm,
      makeConfig({ architecture: false }),
      fsOptions(),
    );

    expect(structured).not.toHaveBeenCalled();
    expect(errors).toEqual([]);
    expect(model.components).toEqual([]);
    expect(model.style.value).toBe('unknown');
    expect(model.style.provenance.kind).toBe('assumed');
    expect(model.evidence.observed).toBe(0);
    expect(model.evidence.inferred).toBe(0);
    expect(model.evidence.assumed).toBeGreaterThan(0);
    expect(model.evidence.meanInferredConfidence).toBeNull();
    expect(model.gaps.join('\n')).toContain('architecture=false');
  });
});

describe('inferArchitecture / 正常系', () => {
  it('事実は observed、LLM の判断は inferred(llm) として分離される', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: goodResponse(),
      fromCache: false,
      model: 'x',
    });
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      llm,
      makeConfig(),
      fsOptions(),
    );

    expect(structured).toHaveBeenCalledTimes(1);
    expect(errors.filter((e) => e.includes('引用検証'))).toEqual([]);

    // 事実部分
    expect(model.deployment.runtime.provenance.kind).toBe('observed');
    expect(model.deployment.cicd.value).toBe('github-actions');
    expect(model.inspectedManifests).toContain('Dockerfile');
    expect(model.inspectedManifests).toContain('k8s/deployment.yaml');

    // 推測部分（LLM）
    const api = model.components.find((c) => c.id === 'api-service-api');
    expect(api?.exposure.value).toBe('public-internet');
    expect(api?.exposure.provenance.kind).toBe('inferred');
    if (api?.exposure.provenance.kind === 'inferred') {
      expect(api.exposure.provenance.inferredBy).toBe('llm');
      expect(api.exposure.provenance.confidence).toBeCloseTo(0.9);
      expect(api.exposure.provenance.basis[0]?.file).toBe('k8s/deployment.yaml');
    }
    expect(api?.dataSensitivity.value).toEqual(['pii', 'business']);
    expect(api?.requiresAuthentication.value).toBe(true);

    expect(model.style.value).toBe('microservices');

    // LLM の「判らなかったこと」が gaps に残る
    expect(model.gaps.join('\n')).toContain('本番のネットワーク分離設定');

    // 内訳が集計されている
    expect(model.evidence.observed).toBeGreaterThan(0);
    expect(model.evidence.inferred).toBeGreaterThan(0);
    expect(model.evidence.meanInferredConfidence).not.toBeNull();
    const total = model.evidence.observed + model.evidence.inferred + model.evidence.assumed;
    expect(total).toBe(
      collectClaims(model.style, model.components, model.dataFlows, model.deployment).length,
    );

    assertObservedCitationsExist(
      collectClaims(model.style, model.components, model.dataFlows, model.deployment),
    );
  });

  it('LLM は事実（observed）を上書きできない', async () => {
    const response = goodResponse();
    const { llm } = mockLlm({ ok: true, value: response, fromCache: false, model: 'x' });
    const { model } = await inferArchitecture(sampleContext(), llm, makeConfig(), fsOptions());

    const postgres = model.components.find((c) => c.id === 'database-postgresql');
    // technology は compose の image 行そのままなので LLM の推測より優先される
    expect(postgres?.technology.provenance.kind).toBe('observed');
    expect(postgres?.technology.value).toBe('postgres:15');
  });
});

describe('inferArchitecture / LLM 失敗時', () => {
  const failures: Array<[string, LlmResult<ArchitectureResponse>, string]> = [
    ['拒否', { ok: false, reason: 'refusal', category: 'cyber' }, '拒否'],
    ['予算切れ', { ok: false, reason: 'budget-exhausted' }, '予算'],
    ['エラー', { ok: false, reason: 'error', error: '接続エラー' }, '失敗'],
  ];

  for (const [label, result, expectedError] of failures) {
    it(`${label}でも事実部分は残る`, async () => {
      const { llm } = mockLlm(result);
      const { model, errors } = await inferArchitecture(
        sampleContext(),
        llm,
        makeConfig(),
        fsOptions(),
      );

      expect(errors.join('\n')).toContain(expectedError);

      // 事実は失われない
      expect(model.components.length).toBeGreaterThan(0);
      expect(model.deployment.runtime.provenance.kind).toBe('observed');
      expect(model.deployment.cloudProvider.value).toBe('aws');
      expect(model.evidence.observed).toBeGreaterThan(0);
      expect(model.inspectedManifests.length).toBeGreaterThan(0);

      // 推測が欠けたことが gaps に明記される
      expect(model.gaps.join('\n')).toContain('LLM');

      // LLM 由来の推測は 1 つも混入していない
      for (const claim of collectClaims(
        model.style,
        model.components,
        model.dataFlows,
        model.deployment,
      )) {
        if (claim.provenance.kind === 'inferred') {
          expect(claim.provenance.inferredBy).toBe('heuristic');
        }
      }
      assertObservedCitationsExist(
        collectClaims(model.style, model.components, model.dataFlows, model.deployment),
      );
    });
  }

  it('LLM クライアントが無くても事実だけのモデルを返す', async () => {
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      undefined as unknown as LlmClient,
      makeConfig(),
      fsOptions(),
    );
    expect(errors).toEqual([]);
    expect(model.deployment.runtime.provenance.kind).toBe('observed');
    expect(model.gaps.join('\n')).toContain('LLM クライアントが利用できない');
  });

  it('事実が 1 件も無いときは LLM を呼ばない（根拠なき推測を避ける）', async () => {
    const { llm, structured } = mockLlm({
      ok: true,
      value: goodResponse(),
      fromCache: false,
      model: 'x',
    });
    const { model } = await inferArchitecture(makeContext(), llm, makeConfig(), {
      fs: memoryFileSystem({ 'README.md': '# hello' }),
    });
    expect(structured).not.toHaveBeenCalled();
    expect(model.gaps.join('\n')).toContain('事実を 1 件も収集できなかった');
  });
});

describe('inferArchitecture / LLM 出力の検証', () => {
  it('捏造された引用は basis から除外し、確信度を下げて errors に残す', async () => {
    const fabricated = { file: 'infra/prod/network.tf', line: 12, excerpt: 'cidr_blocks = ["0.0.0.0/0"]' };
    const response = goodResponse({
      components: [
        {
          componentId: 'api-service-api',
          exposure: judgement('local', 0.9, [fabricated]),
          dataSensitivity: judgement(['pii'], 0.5),
          // ヒューリスティック側が assumed の項目なので、LLM の判断がそのまま残る
          requiresAuthentication: judgement(true, 0.8, [fabricated]),
        },
      ],
    });
    const { llm } = mockLlm({ ok: true, value: response, fromCache: false, model: 'x' });
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      llm,
      makeConfig(),
      fsOptions(),
    );

    expect(errors.join('\n')).toContain('実在しないファイル');

    const api = model.components.find((c) => c.id === 'api-service-api');
    const auth = api?.requiresAuthentication;
    expect(auth?.provenance.kind).toBe('inferred');
    if (auth?.provenance.kind === 'inferred') {
      expect(auth.provenance.basis).toEqual([]);
      // 引用がすべて捏造だったので確信度を半減させている
      expect(auth.provenance.confidence).toBeCloseTo(0.4);
      expect(auth.provenance.reasoning).toContain('実在しなかった');
    }

    // 露出度は、捏造引用で格下げされた LLM 推測(0.45)より
    // 実在引用を持つヒューリスティック推測(0.6)が優先される
    if (api?.exposure.provenance.kind === 'inferred') {
      expect(api.exposure.provenance.inferredBy).toBe('heuristic');
      expect(api.exposure.provenance.alternatives?.join('\n')).toContain('local');
    }

    // 捏造されたファイルはモデル内のどこにも残っていない
    const serialized = JSON.stringify(model);
    expect(serialized).not.toContain('infra/prod/network.tf');
  });

  it('存在しない構成要素 id / データフローは無視して errors に残す', async () => {
    const response = goodResponse({
      components: [
        {
          componentId: 'api-service-ghost',
          exposure: judgement('public-internet', 0.9),
          dataSensitivity: judgement(['pii'], 0.5),
          requiresAuthentication: judgement(false, 0.4),
        },
      ],
      dataFlows: [
        {
          fromId: 'api-service-api',
          toId: 'database-ghost',
          protocol: judgement('SQL', 0.8),
          crossesTrustBoundary: judgement(true, 0.7),
        },
      ],
    });
    const { llm } = mockLlm({ ok: true, value: response, fromCache: false, model: 'x' });
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      llm,
      makeConfig(),
      fsOptions(),
    );

    expect(errors.join('\n')).toContain('存在しない構成要素 id');
    expect(errors.join('\n')).toContain('解決できないデータフロー');
    expect(model.dataFlows.every((f) => f.toId !== 'database-ghost')).toBe(true);
  });

  it('LLM 出力の反映で例外が起きても事実部分を返す', async () => {
    // components が配列でない壊れた出力
    const broken = { ...goodResponse(), components: 42 } as unknown as ArchitectureResponse;
    const { llm } = mockLlm({ ok: true, value: broken, fromCache: false, model: 'x' });
    const { model, errors } = await inferArchitecture(
      sampleContext(),
      llm,
      makeConfig(),
      fsOptions(),
    );
    expect(errors.join('\n')).toContain('反映に失敗');
    expect(model.deployment.runtime.provenance.kind).toBe('observed');
  });
});

describe('preferClaim', () => {
  const observedClaim: Claim<string> = {
    value: 'postgres:15',
    provenance: { kind: 'observed', citations: [{ file: 'docker-compose.yml', line: 13 }] },
  };
  const llmClaim: Claim<string> = {
    value: 'MySQL',
    provenance: {
      kind: 'inferred',
      confidence: 0.99,
      inferredBy: 'llm',
      basis: [],
      reasoning: 'LLM の推測',
    },
  };
  const assumedClaim: Claim<string> = {
    value: '不明',
    provenance: { kind: 'assumed', reasoning: '根拠なし' },
  };

  it('事実は推測に上書きされない', () => {
    expect(preferClaim(observedClaim, llmClaim)).toBe(observedClaim);
  });

  it('仮定は推測で上書きされる', () => {
    expect(preferClaim(assumedClaim, llmClaim)).toBe(llmClaim);
  });

  it('推測同士は確信度が高い方を採り、負けた方を対立仮説に残す', () => {
    const weak: Claim<string> = {
      value: 'PostgreSQL',
      provenance: {
        kind: 'inferred',
        confidence: 0.4,
        inferredBy: 'heuristic',
        basis: [],
        reasoning: '依存から推測',
      },
    };
    const merged = preferClaim(weak, llmClaim);
    expect(merged.value).toBe('MySQL');
    if (merged.provenance.kind === 'inferred') {
      expect(merged.provenance.alternatives?.join('\n')).toContain('PostgreSQL');
    }
  });
});
