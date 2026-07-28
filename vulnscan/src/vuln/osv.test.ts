/**
 * OSV.dev 連携のテスト。ネットワークは常にモックする。
 */

import { describe, expect, it, vi } from 'vitest';
import type { Dependency } from '../types/context.js';
import { scanDependencies, type FetchLike } from './osv.js';

const NOW = '2026-07-28T00:00:00.000Z';

const DEPS: Dependency[] = [
  { name: 'lodash', version: '4.17.15', ecosystem: 'npm', dev: false, manifest: 'package.json' },
  { name: 'safe-pkg', version: '1.0.0', ecosystem: 'npm', dev: false, manifest: 'package.json' },
];

const VULN_DETAIL = {
  id: 'GHSA-p6mc-m468-83gg',
  aliases: ['CVE-2020-8203'],
  summary: 'Prototype pollution in lodash',
  details: 'lodash の zipObjectDeep にプロトタイプ汚染の脆弱性があります。',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N' }],
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.20' }] }],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-p6mc-m468-83gg' }],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-1321'] },
};

/** querybatch → vulns の順に応答するモック fetch */
function makeFetch(
  handlers: {
    batch?: (body: unknown) => { status?: number; json?: unknown } | Promise<never>;
    vuln?: (id: string) => { status?: number; json?: unknown };
  } = {},
): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push(url);
    if (url.includes('/v1/querybatch')) {
      const body = JSON.parse(String(init?.body ?? '{}'));
      const r = handlers.batch
        ? await handlers.batch(body)
        : {
            json: {
              results: [{ vulns: [{ id: VULN_DETAIL.id }] }, {}],
            },
          };
      return makeResponse(r);
    }
    const id = decodeURIComponent(url.split('/v1/vulns/')[1] ?? '');
    const r = handlers.vuln ? handlers.vuln(id) : { json: VULN_DETAIL };
    return makeResponse(r);
  };
  return { fetchImpl, calls };
}

function makeResponse(r: { status?: number; json?: unknown }): Response {
  const status = r.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => r.json,
  } as unknown as Response;
}

describe('scanDependencies', () => {
  it('OSV の応答から依存 Finding を生成する', async () => {
    const { fetchImpl, calls } = makeFetch();
    const { findings, errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });

    expect(errors).toEqual([]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.lens).toBe('dependency');
    expect(f.cve).toBe('CVE-2020-8203');
    expect(f.affectedPackage).toEqual({
      name: 'lodash',
      version: '4.17.15',
      ecosystem: 'npm',
      fixedVersion: '4.17.20',
    });
    expect(f.category).toBe('A06:2021-Vulnerable and Outdated Components');
    expect(f.remediation).toContain('4.17.20');
    expect(calls.some((c) => c.includes('/v1/querybatch'))).toBe(true);
    expect(calls.some((c) => c.includes('/v1/vulns/GHSA-p6mc-m468-83gg'))).toBe(true);
  });

  it('OSV が提供する CVSS ベクタをそのまま使う', async () => {
    const { fetchImpl } = makeFetch();
    const { findings } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    const f = findings[0]!;
    expect(f.cvss.vector).toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N');
    expect(f.cvss.baseScore).toBe(5.9);
    expect(f.severity).toBe('medium');
  });

  it('CVSS v3.0 のベクタはバージョンを保持する', async () => {
    const { fetchImpl } = makeFetch({
      vuln: () => ({
        json: {
          ...VULN_DETAIL,
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
        },
      }),
    });
    const { findings } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings[0]!.cvss.version).toBe('3.0');
    expect(findings[0]!.cvss.baseScore).toBe(9.8);
  });

  it('CVSS ベクタが無い場合は定性的深刻度から推定する', async () => {
    const { fetchImpl } = makeFetch({
      vuln: () => ({
        json: { ...VULN_DETAIL, severity: undefined, database_specific: { severity: 'CRITICAL' } },
      }),
    });
    const { findings } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.reasoning).toContain('推定');
  });

  it('参照リンクに OSV・NVD・アドバイザリを含む', async () => {
    const { fetchImpl } = makeFetch();
    const { findings } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    const refs = findings[0]!.references;
    expect(refs).toContain('https://osv.dev/vulnerability/GHSA-p6mc-m468-83gg');
    expect(refs).toContain('https://nvd.nist.gov/vuln/detail/CVE-2020-8203');
    expect(refs).toContain('https://github.com/advisories/GHSA-p6mc-m468-83gg');
    expect(refs).toContain('https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/');
  });

  it('指紋はバージョンに依存せず安定している', async () => {
    const { fetchImpl } = makeFetch();
    const a = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    const b = await scanDependencies(
      [{ ...DEPS[0]!, version: '4.17.19' }, DEPS[1]!],
      { fetchImpl, now: NOW },
    );
    expect(a.findings[0]!.fingerprint).toBe(b.findings[0]!.fingerprint);
  });

  it('開発時のみの依存は confidence を下げる', async () => {
    const { fetchImpl } = makeFetch();
    const { findings } = await scanDependencies([{ ...DEPS[0]!, dev: true }], {
      fetchImpl,
      now: NOW,
    });
    expect(findings[0]!.confidence).toBe(0.6);
    expect(findings[0]!.reasoning).toContain('開発時のみ');
  });

  it('ネットワーク障害時は errors に積んで空の結果を返す（オフライン耐性）', async () => {
    const fetchImpl: FetchLike = async () => {
      throw new TypeError('fetch failed');
    };
    const { findings, errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('OSV querybatch');
  });

  it('querybatch が HTTP エラーでも例外にならない', async () => {
    const { fetchImpl } = makeFetch({ batch: () => ({ status: 503 }) });
    const { findings, errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings).toEqual([]);
    expect(errors[0]).toContain('503');
  });

  it('詳細取得に失敗しても最低限の Finding は残す', async () => {
    const { fetchImpl } = makeFetch({ vuln: () => ({ status: 500 }) });
    const { findings, errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain('GHSA-p6mc-m468-83gg');
    expect(errors[0]).toContain('詳細取得');
  });

  it('タイムアウトは日本語で報告される', async () => {
    const fetchImpl: FetchLike = async () => {
      const e = new Error('timeout');
      e.name = 'TimeoutError';
      throw e;
    };
    const { errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(errors[0]).toContain('タイムアウト');
  });

  it('依存が無ければ通信しない', async () => {
    const fetchImpl = vi.fn();
    const { findings, errors } = await scanDependencies([], {
      fetchImpl: fetchImpl as unknown as FetchLike,
    });
    expect(findings).toEqual([]);
    expect(errors).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('脆弱性が無ければ Finding を作らない', async () => {
    const { fetchImpl } = makeFetch({ batch: () => ({ json: { results: [{}, {}] } }) });
    const { findings, errors } = await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(findings).toEqual([]);
    expect(errors).toEqual([]);
  });

  it('querybatch には正しい形式で問い合わせる', async () => {
    let sent: unknown;
    const { fetchImpl } = makeFetch({
      batch: (body) => {
        sent = body;
        return { json: { results: [{}, {}] } };
      },
    });
    await scanDependencies(DEPS, { fetchImpl, now: NOW });
    expect(sent).toEqual({
      queries: [
        { version: '4.17.15', package: { name: 'lodash', ecosystem: 'npm' } },
        { version: '1.0.0', package: { name: 'safe-pkg', ecosystem: 'npm' } },
      ],
    });
  });
});
