/**
 * CISA KEV 照合。
 *
 * ここで固定したいのは、事実と参考値の境界:
 *   - CVE を持つ Finding だけが「収載（事実）」になりうる
 *   - CVE を持たない Finding には、CWE クラスの件数しか付かない
 *   - カタログが取れなくても走査は壊れない
 */

import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { makeFinding } from '../reporter/fixtures.js';
import { annotateWithKev, loadKevCatalog, matchKev, parseKevCatalog } from './kev.js';

const FEED = {
  catalogVersion: '2026.08.06',
  dateReleased: '2026-08-06T12:00:00.000Z',
  count: 3,
  vulnerabilities: [
    {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      product: 'Log4j2',
      vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
      dateAdded: '2021-12-10',
      dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Known',
      cwes: ['CWE-917'],
    },
    {
      cveID: 'cve-2019-0708',
      vendorProject: 'Microsoft',
      product: 'RDP',
      vulnerabilityName: 'BlueKeep',
      dateAdded: '2021-11-03',
      dueDate: '2022-05-03',
      knownRansomwareCampaignUse: 'Unknown',
      cwes: ['CWE-089'], // ゼロ埋め表記も正規化されること
    },
    {
      cveID: 'CVE-2020-1111',
      vendorProject: 'X',
      product: 'Y',
      vulnerabilityName: 'Z',
      dateAdded: '2023-01-01',
      dueDate: '',
      knownRansomwareCampaignUse: 'Unknown',
      // cwes 無し（2024年より前のスキーマ）
    },
  ],
};

describe('parseKevCatalog', () => {
  it('CVE を大文字へ揃えて索引する', () => {
    const c = parseKevCatalog(FEED);
    expect(c.total).toBe(3);
    expect(c.byCve.get('CVE-2019-0708')?.name).toBe('BlueKeep');
  });

  it('ランサムウェア使用の有無は Known だけを真とする', () => {
    const c = parseKevCatalog(FEED);
    expect(c.byCve.get('CVE-2021-44228')?.ransomware).toBe(true);
    expect(c.byCve.get('CVE-2019-0708')?.ransomware).toBe(false);
  });

  it('CWE のゼロ埋めを正規化して数える', () => {
    const c = parseKevCatalog(FEED);
    expect(c.cweCounts.get('CWE-89')).toBe(1);
    expect(c.cweCounts.get('CWE-917')).toBe(1);
  });

  it('cwes を持たないエントリでも壊れない', () => {
    const c = parseKevCatalog(FEED);
    expect(c.byCve.get('CVE-2020-1111')?.cwes).toEqual([]);
  });

  it('壊れた入力でも空のカタログを返す', () => {
    expect(parseKevCatalog(null).total).toBe(0);
    expect(parseKevCatalog({ vulnerabilities: 'not-an-array' }).total).toBe(0);
    expect(parseKevCatalog({ vulnerabilities: [{}, { cveID: '' }] }).total).toBe(0);
  });

  it('参考例は収載日の新しい順に並ぶ', () => {
    const c = parseKevCatalog({
      vulnerabilities: [
        { cveID: 'CVE-1', dateAdded: '2020-01-01', cwes: ['CWE-79'] },
        { cveID: 'CVE-2', dateAdded: '2025-01-01', cwes: ['CWE-79'] },
        { cveID: 'CVE-3', dateAdded: '2022-01-01', cwes: ['CWE-79'] },
        { cveID: 'CVE-4', dateAdded: '2019-01-01', cwes: ['CWE-79'] },
      ],
    });
    expect(c.cweExamples.get('CWE-79')).toEqual(['CVE-2', 'CVE-3', 'CVE-1']);
  });
});

describe('matchKev', () => {
  const catalog = parseKevCatalog(FEED);

  it('CVE を持つ Finding は収載を事実として判定できる', () => {
    const f = makeFinding({ cve: 'CVE-2021-44228', cwe: 'CWE-917' });
    const kev = matchKev(f, catalog);
    expect(kev.listed).toBe(true);
    expect(kev.entry?.product).toBe('Log4j2');
    expect(kev.entry?.ransomware).toBe(true);
  });

  it('CVE の大文字小文字は問わない', () => {
    expect(matchKev(makeFinding({ cve: 'cve-2019-0708' }), catalog).listed).toBe(true);
  });

  it('CVE を持たない Finding は決して listed にならない', () => {
    // CWE-89 は KEV に存在するが、この検出自体は CVE を持たないので収載ではない
    const f = makeFinding({ cwe: 'CWE-89' });
    expect(f.cve).toBeUndefined();
    const kev = matchKev(f, catalog);
    expect(kev.listed).toBe(false);
    // 代わりにクラスとしての件数が付く（参考値）
    expect(kev.cweClassCount).toBe(1);
    expect(kev.cweExamples).toEqual(['CVE-2019-0708']);
  });

  it('KEV に無い CWE クラスなら件数は0', () => {
    const kev = matchKev(makeFinding({ cwe: 'CWE-352' }), catalog);
    expect(kev.listed).toBe(false);
    expect(kev.cweClassCount).toBe(0);
    expect(kev.cweExamples).toEqual([]);
  });

  it('CVE を持つが未収載なら listed=false', () => {
    const kev = matchKev(makeFinding({ cve: 'CVE-2099-9999', cwe: 'CWE-89' }), catalog);
    expect(kev.listed).toBe(false);
  });
});

describe('annotateWithKev', () => {
  it('元の配列を変更しない', () => {
    const catalog = parseKevCatalog(FEED);
    const original = [makeFinding({ cve: 'CVE-2021-44228' })];
    const annotated = annotateWithKev(original, catalog);
    expect(original[0]?.kev).toBeUndefined();
    expect(annotated[0]?.kev?.listed).toBe(true);
  });
});

describe('loadKevCatalog', () => {
  it('ファイル指定があればネットワークを使わない', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'grimoire-kev-'));
    const path = join(dir, 'kev.json');
    await writeFile(path, JSON.stringify(FEED), 'utf8');

    const fetchImpl = (): Promise<Response> => {
      throw new Error('ネットワークを使ってはいけない');
    };
    const { catalog, errors } = await loadKevCatalog({ catalogPath: path, fetchImpl });
    expect(errors).toEqual([]);
    expect(catalog?.total).toBe(3);
  });

  it('取得に失敗しても例外にせず null と理由を返す', async () => {
    const fetchImpl = async (): Promise<Response> =>
      new Response('', { status: 503, statusText: 'unavailable' });
    const { catalog, errors } = await loadKevCatalog({ fetchImpl });
    expect(catalog).toBeNull();
    expect(errors[0]).toContain('503');
  });

  it('既定パスに無いだけなら、警告を出さず取得へ進む', async () => {
    let called = false;
    const fetchImpl = async (): Promise<Response> => {
      called = true;
      return new Response(JSON.stringify(FEED), { status: 200 });
    };
    const { catalog, errors } = await loadKevCatalog({
      catalogPath: '/does/not/exist.json',
      fallbackToFetch: true,
      fetchImpl,
    });
    expect(called).toBe(true);
    expect(errors).toEqual([]);
    expect(catalog?.total).toBe(3);
  });

  it('明示指定されたファイルが読めない場合は取得へフォールバックしない', async () => {
    let called = false;
    const fetchImpl = async (): Promise<Response> => {
      called = true;
      return new Response('{}', { status: 200 });
    };
    const { catalog, errors } = await loadKevCatalog({
      catalogPath: '/does/not/exist.json',
      fetchImpl,
    });
    expect(called).toBe(false);
    expect(catalog).toBeNull();
    expect(errors).toHaveLength(1);
  });

  it('ネットワーク例外も errors に積んで継続できる', async () => {
    const fetchImpl = async (): Promise<Response> => {
      throw new Error('getaddrinfo ENOTFOUND');
    };
    const { catalog, errors } = await loadKevCatalog({ fetchImpl });
    expect(catalog).toBeNull();
    expect(errors[0]).toContain('ENOTFOUND');
  });
});
