/**
 * MITRE CWE カタログ（959件）アクセス層のテスト。
 *
 * カタログの中身は MITRE 由来の「事実」なので、
 * 期待値には実データに存在する値だけを書く（作り話をしない）。
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  allCweCategories,
  allCwes,
  catalogAvailable,
  catalogCandidatePaths,
  catalogLoadError,
  catalogSize,
  catalogSource,
  ciaFromCatalog,
  cweAncestors,
  cweCategory,
  cwesForPlatform,
  lensCoverage,
  lensForCwe,
  likelihoodOf,
  lookupCwe,
  resolveCatalogPath,
} from './catalog.js';
import { lookupCweInfo, owaspForCwe, CWE_KB } from './knowledge.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CATALOG_FILE_NAME = 'cwe-catalog.json';

/* ------------------------------------------------------------------ *
 * 読み込み・索引化
 * ------------------------------------------------------------------ */

describe('カタログの読み込み', () => {
  it('959件を読み込んでいる', () => {
    expect(catalogSize()).toBe(959);
  });

  it('出典を保持している（レポートで引用元を示すため）', () => {
    const src = catalogSource();
    expect(src.source).toContain('cwe-sdk-javascript');
    expect(src.sourceProject).toContain('MITRE');
    expect(existsSync(src.path)).toBe(true);
  });

  it('2回呼んでも同じインスタンスを返す（毎回パースしていない）', () => {
    const a = lookupCwe('CWE-89');
    const b = lookupCwe('CWE-89');
    expect(a).not.toBeNull();
    // キャッシュされていれば参照が同一になる
    expect(a).toBe(b);
  });

  it('1.4MB の JSON を読んでも素引きは十分速い', () => {
    catalogSize(); // 初期化を済ませてから計測する
    const started = Date.now();
    for (let i = 0; i < 20000; i++) lookupCwe('CWE-79');
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('ビルド後(dist)からの解決', () => {
  it('dist/vuln に置かれた場合でもカタログJSONを解決できる', () => {
    const asDist = join(REPO_ROOT, 'dist', 'vuln');
    const resolved = resolveCatalogPath(asDist);
    expect(resolved).not.toBeNull();
    expect(existsSync(resolved!)).toBe(true);

    // `npm run build` は scripts/copy-data.mjs で dist/vuln/data/ へ同梱する。
    // 同梱済みならそちらが優先され、dist だけの配布でも 959 件が読める。
    // 未ビルドの場合はリポジトリの src/vuln/data/ へフォールバックする。
    const bundled = join(asDist, 'data', CATALOG_FILE_NAME);
    const expected = existsSync(bundled)
      ? bundled
      : join(REPO_ROOT, 'src', 'vuln', 'data', CATALOG_FILE_NAME);
    expect(resolved).toBe(expected);
  });

  it('dist に同梱されていればカタログ959件が dist だけで読める', () => {
    const bundled = join(REPO_ROOT, 'dist', 'vuln', 'data', CATALOG_FILE_NAME);
    if (!existsSync(bundled)) return; // 未ビルドならこの検証は対象外
    const parsed = JSON.parse(readFileSync(bundled, 'utf8')) as {
      entries: Record<string, unknown>;
    };
    expect(Object.keys(parsed.entries).length).toBe(959);
  });

  it('同梱が無いレイアウトでは src/vuln/data へフォールバックする', () => {
    // dist を模した「data を持たない」ディレクトリから解決させる
    const asBundle = join(REPO_ROOT, 'dist', 'no-such-layout', 'vuln');
    expect(resolveCatalogPath(asBundle)).toBe(
      join(REPO_ROOT, 'src', 'vuln', 'data', CATALOG_FILE_NAME),
    );
  });

  it('探索候補には同梱パス(dist/vuln/data)が先頭に含まれる', () => {
    const asDist = join(REPO_ROOT, 'dist', 'vuln');
    const candidates = catalogCandidatePaths(asDist);
    expect(candidates[0]).toBe(join(asDist, 'data', 'cwe-catalog.json'));
    expect(candidates).toContain(join(REPO_ROOT, 'src', 'vuln', 'data', 'cwe-catalog.json'));
  });

  it('どこにも無ければ null を返す（例外にしない）', () => {
    expect(resolveCatalogPath('/nonexistent-dir-for-test/deep/deeper')).toBeNull();
  });

  it('カタログが読めていることを問い合わせられる', () => {
    expect(catalogAvailable()).toBe(true);
    expect(catalogLoadError()).toBeNull();
  });
});

/* ------------------------------------------------------------------ *
 * ルックアップ
 * ------------------------------------------------------------------ */

describe('lookupCwe', () => {
  it("'CWE-89' も '89' も 'cwe-89' も受け付ける", () => {
    const a = lookupCwe('CWE-89');
    expect(a?.id).toBe('CWE-89');
    expect(lookupCwe('89')?.id).toBe('CWE-89');
    expect(lookupCwe('cwe-89')?.id).toBe('CWE-89');
  });

  it('MITRE の内容をそのまま保持している', () => {
    const e = lookupCwe('CWE-89')!;
    expect(e.name).toContain('SQL');
    expect(e.abstraction).toBe('Base');
    expect(e.likelihood).toBe('High');
    expect(e.description.length).toBeGreaterThan(50);
    expect(e.parents).toContain('CWE-74');
    expect(e.technologies).toContain('Database Server');
  });

  it('親 ID も CWE- 形式に正規化されている', () => {
    for (const entry of allCwes()) {
      for (const p of entry.parents) expect(p).toMatch(/^CWE-\d+$/);
      expect(entry.id).toMatch(/^CWE-\d+$/);
    }
  });

  it('未知・不正な ID は null を返す', () => {
    expect(lookupCwe('CWE-99999')).toBeNull();
    expect(lookupCwe('不明')).toBeNull();
    expect(lookupCwe('')).toBeNull();
  });
});

/* ------------------------------------------------------------------ *
 * 祖先辿り
 * ------------------------------------------------------------------ */

describe('cweAncestors', () => {
  it('SQLi は 943 → 74 → 707 と遡る', () => {
    expect(cweAncestors('CWE-89').map((e) => e.id)).toEqual(['CWE-943', 'CWE-74', 'CWE-707']);
  });

  it('自分自身は含まない', () => {
    expect(cweAncestors('CWE-89').some((e) => e.id === 'CWE-89')).toBe(false);
  });

  it('最上位は Pillar または Class になる', () => {
    for (const id of ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-798', 'CWE-918', 'CWE-502']) {
      const chain = cweAncestors(id);
      expect(chain.length, id).toBeGreaterThan(0);
      expect(['Pillar', 'Class'], id).toContain(chain[chain.length - 1]!.abstraction);
    }
  });

  it('複数の親（DAG）を持つ CWE でも重複せず全てを辿る', () => {
    // CWE-94 は CWE-74 と CWE-913 の両方の子
    const ids = cweAncestors('CWE-94').map((e) => e.id);
    expect(ids).toContain('CWE-74');
    expect(ids).toContain('CWE-913');
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('全 959 件で無限ループも例外も起きない', () => {
    for (const entry of allCwes()) {
      expect(() => cweAncestors(entry.id)).not.toThrow();
      expect(cweAncestors(entry.id).some((a) => a.id === entry.id)).toBe(false);
    }
  });

  it('未知の CWE は空配列', () => {
    expect(cweAncestors('CWE-99999')).toEqual([]);
  });
});

/* ------------------------------------------------------------------ *
 * カテゴリへの畳み込み
 * ------------------------------------------------------------------ */

describe('cweCategory', () => {
  it('代表的な CWE が想定どおりのカテゴリに畳まれる', () => {
    expect(cweCategory('CWE-89').id).toBe('injection');
    expect(cweCategory('CWE-79').id).toBe('xss');
    expect(cweCategory('CWE-22').id).toBe('path-traversal');
    expect(cweCategory('CWE-798').id).toBe('secrets');
    expect(cweCategory('CWE-918').id).toBe('ssrf');
    expect(cweCategory('CWE-502').id).toBe('deserialization');
    expect(cweCategory('CWE-327').id).toBe('crypto');
  });

  it('祖先経由でカテゴリを継承する（アンカー自身でなくても畳める）', () => {
    // CWE-564 (Hibernate injection) は CWE-89 の子
    expect(cweCategory('CWE-564').id).toBe('injection');
    // CWE-80 は CWE-79 の子
    expect(cweCategory('CWE-80').id).toBe('xss');
  });

  it('カテゴリ名は日本語で、OWASP 対応があれば付く', () => {
    const c = cweCategory('CWE-89');
    expect(c.name).toBe('インジェクション');
    expect(c.owasp).toBe('A03:2021-Injection');
  });

  it('カタログに無い CWE は other になる（無理に分類しない）', () => {
    expect(cweCategory('CWE-99999').id).toBe('other');
  });

  it('全 959 件がいずれかのカテゴリに落ちる', () => {
    const known = new Set(allCweCategories().map((c) => c.id));
    for (const entry of allCwes()) {
      expect(known, entry.id).toContain(cweCategory(entry.id).id);
    }
  });

  it('カテゴリ数は人が扱える程度に収まっている', () => {
    const ids = new Set(allCwes().map((e) => cweCategory(e.id).id));
    expect(ids.size).toBeLessThanOrEqual(40);
    expect(ids.size).toBeGreaterThan(10);
  });

  it('返り値を書き換えても内部状態が壊れない', () => {
    const c = cweCategory('CWE-89');
    c.name = '書き換え';
    expect(cweCategory('CWE-89').name).toBe('インジェクション');
  });
});

/* ------------------------------------------------------------------ *
 * C/I/A の導出
 * ------------------------------------------------------------------ */

describe('ciaFromCatalog', () => {
  it('SQLi は Read Application Data / Modify Application Data から C:H・I:H', () => {
    expect(ciaFromCatalog('CWE-89')).toEqual({ C: 'H', I: 'H', A: 'N' });
  });

  it('SSRF は情報読み出しとコード実行から C:H・I:H、可用性は主張されていない', () => {
    expect(ciaFromCatalog('CWE-918')).toEqual({ C: 'H', I: 'H', A: 'N' });
  });

  it('逆シリアル化は I:H と DoS による A:H', () => {
    expect(ciaFromCatalog('CWE-502')).toEqual({ C: 'N', I: 'H', A: 'H' });
  });

  it('リソース枯渇は A:H、Access Control の Bypass は限定的な C/I になる', () => {
    expect(ciaFromCatalog('CWE-400')).toEqual({ C: 'L', I: 'L', A: 'H' });
  });

  it('パストラバーサルは読み書きと DoS で C/I/A すべて H', () => {
    expect(ciaFromCatalog('CWE-22')).toEqual({ C: 'H', I: 'H', A: 'H' });
  });

  it('consequences が CVSS に写像できない CWE は null（既定値を作らない）', () => {
    expect(ciaFromCatalog('CWE-99999')).toBeNull();
    const nulls = allCwes().filter((e) => ciaFromCatalog(e.id) === null);
    // 「導けないものがある」ことを明示的に許容する設計であることを固定する
    expect(nulls.length).toBeGreaterThan(0);
    expect(nulls.length).toBeLessThan(catalogSize() / 2);
  });

  it('全件で H/L/N 以外の値を返さない', () => {
    for (const entry of allCwes()) {
      const cia = ciaFromCatalog(entry.id);
      if (!cia) continue;
      for (const v of [cia.C, cia.I, cia.A]) expect(['H', 'L', 'N']).toContain(v);
    }
  });
});

describe('likelihoodOf', () => {
  it('MITRE が Likelihood を明示している CWE を返す', () => {
    expect(likelihoodOf('CWE-89')).toBe('High');
    expect(likelihoodOf('CWE-79')).toBe('High');
  });

  it('未記載・未知は Unknown（推測で埋めない）', () => {
    expect(likelihoodOf('CWE-99999')).toBe('Unknown');
    const known = allCwes().filter((e) => likelihoodOf(e.id) !== 'Unknown');
    expect(known.length).toBe(185);
  });
});

/* ------------------------------------------------------------------ *
 * 言語・技術での逆引き
 * ------------------------------------------------------------------ */

describe('cwesForPlatform', () => {
  it('言語で引ける', () => {
    const java = cwesForPlatform({ languages: ['Java'] });
    expect(java.length).toBeGreaterThan(0);
    expect(java.every((e) => e.languages.includes('Java'))).toBe(true);
  });

  it('表記ゆれを吸収する（TypeScript → JavaScript）', () => {
    const a = cwesForPlatform({ languages: ['TypeScript'] }).map((e) => e.id).sort();
    const b = cwesForPlatform({ languages: ['JavaScript'] }).map((e) => e.id).sort();
    expect(a).toEqual(b);
    expect(a.length).toBeGreaterThan(0);
  });

  it('技術で引ける', () => {
    const db = cwesForPlatform({ technologies: ['Database Server'] });
    expect(db.map((e) => e.id)).toContain('CWE-89');
  });

  it('指定が空なら空配列（全件を返して事実を薄めない）', () => {
    expect(cwesForPlatform({})).toEqual([]);
    expect(cwesForPlatform({ languages: [], technologies: [] })).toEqual([]);
  });

  it('既定では Not Language-Specific を含めず、includeGeneric で含める', () => {
    const strict = cwesForPlatform({ languages: ['Python'] });
    const loose = cwesForPlatform({ languages: ['Python'], includeGeneric: true });
    expect(loose.length).toBeGreaterThan(strict.length);
    expect(strict.every((e) => e.languages.includes('Python'))).toBe(true);
    // 汎用側にだけ現れる CWE は 'Python' を明示していない
    const onlyGeneric = loose.filter((e) => !strict.includes(e));
    expect(onlyGeneric.length).toBeGreaterThan(0);
    expect(onlyGeneric.every((e) => e.languages.includes('Not Language-Specific'))).toBe(true);
  });
});

/* ------------------------------------------------------------------ *
 * レンズへの振り分け
 * ------------------------------------------------------------------ */

describe('lensForCwe', () => {
  it('各レンズの代表的な CWE が正しく割り当たる', () => {
    expect(lensForCwe('CWE-89')).toBe('injection');
    expect(lensForCwe('CWE-78')).toBe('injection');
    expect(lensForCwe('CWE-22')).toBe('injection');
    expect(lensForCwe('CWE-79')).toBe('web-output');
    expect(lensForCwe('CWE-352')).toBe('web-output');
    expect(lensForCwe('CWE-1004')).toBe('web-output');
    expect(lensForCwe('CWE-798')).toBe('crypto-secrets');
    expect(lensForCwe('CWE-327')).toBe('crypto-secrets');
    expect(lensForCwe('CWE-338')).toBe('crypto-secrets');
    expect(lensForCwe('CWE-502')).toBe('deserialization-ssrf');
    expect(lensForCwe('CWE-918')).toBe('deserialization-ssrf');
    expect(lensForCwe('CWE-611')).toBe('deserialization-ssrf');
    expect(lensForCwe('CWE-862')).toBe('authz');
    expect(lensForCwe('CWE-639')).toBe('authz');
    expect(lensForCwe('CWE-287')).toBe('authz');
  });

  it('祖先を辿って割り当てる（アンカーそのものでなくてよい）', () => {
    // CWE-564 は CWE-89 の子 → injection
    expect(lensForCwe('CWE-564')).toBe('injection');
    // CWE-1321 (プロトタイプ汚染) は CWE-915 の子 → deserialization-ssrf
    expect(lensForCwe('CWE-1321')).toBe('deserialization-ssrf');
  });

  it('自分自身のアンカーが祖先のアンカーより優先される', () => {
    // CWE-798 の祖先には CWE-287/CWE-284 (authz) がいるが、秘密情報の話なので crypto-secrets
    expect(cweAncestors('CWE-798').map((e) => e.id)).toContain('CWE-287');
    expect(lensForCwe('CWE-798')).toBe('crypto-secrets');
    // CWE-1004 の祖先には CWE-732/CWE-284 (authz) がいるが、Cookie 属性なので web-output
    expect(cweAncestors('CWE-1004').map((e) => e.id)).toContain('CWE-284');
    expect(lensForCwe('CWE-1004')).toBe('web-output');
  });

  it('どのレンズにも該当しない CWE は null（死角として正直に報告する）', () => {
    // 入力の解釈違い・OS 固有のファイル名解決などはこのスキャナの守備範囲外
    expect(lensForCwe('CWE-115')).toBeNull(); // Misinterpretation of Input
    expect(lensForCwe('CWE-67')).toBeNull(); // Improper Handling of Windows Device Names
    expect(lensForCwe('CWE-99999')).toBeNull();
  });

  it('依存レンズ(dependency)はソースコードを見ないので返さない', () => {
    for (const entry of allCwes()) expect(lensForCwe(entry.id)).not.toBe('dependency');
  });

  it('カバレッジ集計が全件と一致する', () => {
    const cov = lensCoverage();
    expect(cov.total).toBe(catalogSize());
    expect(cov.assigned + cov.unassigned).toBe(cov.total);
    expect(Object.values(cov.byLens).reduce((a, b) => a + b, 0)).toBe(cov.assigned);
    // 半数以上に割り当たっているが、全件ではない（死角が残ることを明示する）
    expect(cov.assigned).toBeGreaterThan(cov.total / 3);
    expect(cov.unassigned).toBeGreaterThan(0);
    for (const lens of [
      'injection',
      'authz',
      'crypto-secrets',
      'deserialization-ssrf',
      'web-output',
    ]) {
      expect(cov.byLens[lens], lens).toBeGreaterThan(0);
    }
  });
});

/* ------------------------------------------------------------------ *
 * 手作り知識ベースとの統合
 * ------------------------------------------------------------------ */

describe('knowledge.ts との統合', () => {
  it('手作りの日本語名・OWASP 2021 が常に優先される', () => {
    const info = lookupCweInfo('CWE-89')!;
    expect(info.name).toBe('SQLインジェクション'); // 日本語（手作り）
    expect(info.englishName).toContain('SQL Injection'); // 英語（手作り）
    expect(info.owasp).toBe('A03:2021-Injection');
    expect(info.owaspInherited).toBe(false);
    expect(info.source).toBe('curated+catalog');
    expect(info.catalog?.likelihood).toBe('High');
  });

  it('手作りに無い CWE はカタログでフォールバックされる', () => {
    expect(CWE_KB['CWE-564']).toBeUndefined();
    const info = lookupCweInfo('CWE-564')!;
    expect(info.source).toBe('catalog');
    expect(info.name).toContain('Hibernate');
    expect(info.description.length).toBeGreaterThan(0);
  });

  it('OWASP 2021 を祖先から継承し、継承であることを明示する', () => {
    const info = lookupCweInfo('CWE-564')!;
    expect(info.owasp).toBe('A03:2021-Injection');
    expect(info.owaspInherited).toBe(true);
    expect(info.owaspVia).toBe('CWE-89');
  });

  it('どちらにも無ければ null', () => {
    expect(lookupCweInfo('CWE-99999')).toBeNull();
    expect(lookupCweInfo('不明')).toBeNull();
  });

  it('継承により OWASP カテゴリのカバレッジが手作り分から大きく広がる', () => {
    let direct = 0;
    let inherited = 0;
    for (const entry of allCwes()) {
      const hit = owaspForCwe(entry.id);
      if (!hit) continue;
      if (hit.inherited) inherited++;
      else direct++;
    }
    // 手作り 69 件のうち CWE-16 / CWE-937 は MITRE では Weakness ではなく
    // Category 扱いでカタログに存在しないため、直接一致は 67 件になる。
    const curatedInCatalog = Object.keys(CWE_KB).filter((id) => lookupCwe(id) !== null);
    expect(direct).toBe(curatedInCatalog.length);
    expect(direct).toBe(67);
    expect(inherited).toBeGreaterThan(direct * 3);
  });
});
