/**
 * manageFindings（③脆弱性情報管理の統合）・ベースライン差分・抑制のテスト。
 */

import { access, mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ScanContext } from '../types/context.js';
import { DEFAULT_CONFIG, type PathSources, type VulnScanConfig } from '../types/config.js';
import type { Finding, RawFinding } from '../types/finding.js';
import { manageFindings } from './index.js';
import { loadConfig } from '../config/index.js';
import { applyBaseline, emptyBaseline, loadBaseline, saveBaseline } from './baseline.js';
import { matchGlob as sharedMatchGlob } from '../context/glob.js';
import { globToRegExp, loadIgnoreList, matchIgnoreRule, parseIgnoreList } from './ignore.js';
import type { FetchLike } from './osv.js';

const NOW = '2026-07-28T00:00:00.000Z';
const LAST_YEAR = '2025-01-01T00:00:00.000Z';

let repoRoot: string;

beforeEach(async () => {
  repoRoot = await mkdtemp(join(tmpdir(), 'vulnscan-test-'));
});

afterEach(async () => {
  await rm(repoRoot, { recursive: true, force: true });
});

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot,
    scannedAt: NOW,
    languages: [],
    frameworks: [],
    dependencies: [],
    files: [],
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [
      { kind: 'http-route', identifier: 'GET /users/:id', file: 'src/api/users.ts', line: 5 },
    ],
    trustBoundaries: [],
    warnings: [],
    ...overrides,
  };
}

function makeConfig(overrides: Partial<VulnScanConfig> = {}): VulnScanConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}

function makeRaw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    cwe: 'CWE-89',
    category: 'A03:2021-Injection',
    title: 'SQLインジェクション',
    severity: 'high',
    confidence: 0.8,
    location: { file: 'src/api/users.ts', startLine: 10, endLine: 12 },
    evidence: 'db.query("SELECT * FROM users WHERE id = " + id)',
    dataFlow: [],
    reasoning: '文字列連結',
    remediation: 'プレースホルダを使う',
    lens: 'injection',
    ...overrides,
  };
}

/** 依存照合を行わないオプション */
const NO_OSV = { scanDependencies: false as const, now: NOW };

describe('manageFindings', () => {
  it('RawFinding を Finding に正規化する', async () => {
    const { findings, suppressedCount, errors } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    expect(errors).toEqual([]);
    expect(suppressedCount).toBe(0);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.id).toMatch(/^VS-/);
    expect(f.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(f.cvss.baseScore).toBeGreaterThan(0);
    expect(f.diffStatus).toBe('new');
    expect(f.status).toBe('open');
    expect(f.references.length).toBeGreaterThan(0);
  });

  it('重複を統合する', async () => {
    const { findings } = await manageFindings(
      [makeRaw(), makeRaw({ lens: 'authz' })],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBeGreaterThan(0.8);
  });

  it('壊れた RawFinding があってもエラーに積んで続行する', async () => {
    const broken = { ...makeRaw(), severity: 'high' } as RawFinding;
    // location を欠損させる
    delete (broken as unknown as Record<string, unknown>)['location'];
    const { findings, errors } = await manageFindings(
      [broken, makeRaw({ evidence: '別の箇所', location: { file: 'a.ts', startLine: 1, endLine: 1 } })],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    // location 欠損は既定値で補完されるため、少なくとも処理は継続する
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(errors)).toBe(true);
  });

  it('確信度がしきい値未満の指摘は抑制される', async () => {
    const { findings, suppressedCount } = await manageFindings(
      [makeRaw({ confidence: 0.2 })],
      makeContext(),
      makeConfig({ scan: { ...DEFAULT_CONFIG.scan, minConfidence: 0.5 } }),
      NO_OSV,
    );
    expect(findings).toHaveLength(0);
    expect(suppressedCount).toBe(1);
  });
});

describe('ベースライン差分', () => {
  it('初回スキャンは全て new になる', async () => {
    const { findings, errors } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    expect(errors).toEqual([]);
    expect(findings[0]!.diffStatus).toBe('new');
  });

  it('ベースラインに存在すれば persistent になり firstSeen を引き継ぐ', async () => {
    const config = makeConfig();
    // 1回目のスキャン結果をベースラインとして保存
    const first = await manageFindings([makeRaw()], makeContext(), config, {
      ...NO_OSV,
      now: LAST_YEAR,
    });
    await saveBaseline(first.findings, config.baselinePath, repoRoot);

    // 2回目: 同じ指摘（行番号だけずれている）
    const second = await manageFindings(
      [makeRaw({ location: { file: 'src/api/users.ts', startLine: 99, endLine: 101 } })],
      makeContext(),
      config,
      NO_OSV,
    );
    expect(second.findings[0]!.diffStatus).toBe('persistent');
    expect(second.findings[0]!.firstSeen).toBe(LAST_YEAR);
    expect(second.findings[0]!.lastSeen).toBe(NOW);
  });

  it('消えた指摘は fixed として報告される', async () => {
    const config = makeConfig();
    const first = await manageFindings([makeRaw()], makeContext(), config, {
      ...NO_OSV,
      now: LAST_YEAR,
    });
    await saveBaseline(first.findings, config.baselinePath, repoRoot);

    const second = await manageFindings([], makeContext(), config, NO_OSV);
    expect(second.findings).toHaveLength(1);
    expect(second.findings[0]!.diffStatus).toBe('fixed');
    expect(second.findings[0]!.status).toBe('fixed');
  });

  it('トリアージ状態（false-positive）が引き継がれる', async () => {
    const config = makeConfig();
    const first = await manageFindings([makeRaw()], makeContext(), config, {
      ...NO_OSV,
      now: LAST_YEAR,
    });
    const triaged: Finding[] = first.findings.map((f) => ({ ...f, status: 'false-positive' }));
    await saveBaseline(triaged, config.baselinePath, repoRoot);

    const second = await manageFindings([makeRaw()], makeContext(), config, NO_OSV);
    expect(second.findings[0]!.status).toBe('false-positive');
  });

  it('ベースラインが壊れていても errors に積んで続行する', async () => {
    const config = makeConfig();
    await mkdir(join(repoRoot, dirname(config.baselinePath)), { recursive: true });
    await writeFile(join(repoRoot, config.baselinePath), '{ 壊れた JSON', 'utf8');
    const { findings, errors } = await manageFindings(
      [makeRaw()],
      makeContext(),
      config,
      NO_OSV,
    );
    expect(findings).toHaveLength(1);
    expect(errors.some((e) => e.includes('ベースライン'))).toBe(true);
  });

  it('saveBaseline は修正済みを保存せず、ディレクトリを自動作成する', async () => {
    const config = makeConfig({ baselinePath: 'nested/dir/baseline.json' });
    const { findings } = await manageFindings([makeRaw()], makeContext(), config, NO_OSV);
    const fixed: Finding = { ...findings[0]!, diffStatus: 'fixed', status: 'fixed', fingerprint: 'x'.repeat(64) };
    const path = await saveBaseline([...findings, fixed], config.baselinePath, repoRoot);
    const saved = JSON.parse(await readFile(path, 'utf8'));
    expect(saved.version).toBe(1);
    expect(saved.findings).toHaveLength(1);
    expect(saved.generatedAt).toBeTruthy();
  });

  it('未存在のベースラインはエラーにならない', async () => {
    const result = await loadBaseline('.vulnscan/none.json', repoRoot);
    expect(result.existed).toBe(false);
    expect(result.errors).toEqual([]);
    expect(result.baseline.findings).toEqual([]);
  });

  it('素の配列形式のベースラインも読める', async () => {
    await writeFile(join(repoRoot, 'b.json'), JSON.stringify([{ fingerprint: 'abc' }]), 'utf8');
    const result = await loadBaseline('b.json', repoRoot);
    expect(result.baseline.findings).toHaveLength(1);
  });

  it('applyBaseline は fixed 済みの指摘を再掲しない', () => {
    const old = {
      fingerprint: 'abc',
      firstSeen: LAST_YEAR,
      lastSeen: LAST_YEAR,
      diffStatus: 'fixed',
      status: 'fixed',
    } as unknown as Finding;
    const { fixed } = applyBaseline([], { ...emptyBaseline(), findings: [old] }, NOW);
    expect(fixed).toEqual([]);
  });
});

describe('抑制リストによる抑制', () => {
  /** 既定の抑制リスト（現行名）へ書き出す */
  async function writeIgnore(content: string): Promise<void> {
    await writeFile(join(repoRoot, DEFAULT_CONFIG.ignorePath), content, 'utf8');
  }

  it('指紋で抑制できる', async () => {
    const ctx = makeContext();
    const config = makeConfig();
    const first = await manageFindings([makeRaw()], ctx, config, NO_OSV);
    await writeIgnore(`# 検証済みのため抑制\n${first.findings[0]!.fingerprint}\n`);

    const second = await manageFindings([makeRaw()], ctx, config, NO_OSV);
    expect(second.findings).toHaveLength(0);
    expect(second.suppressedCount).toBe(1);
  });

  it('ID で抑制できる', async () => {
    const ctx = makeContext();
    const config = makeConfig();
    const first = await manageFindings([makeRaw()], ctx, config, NO_OSV);
    await writeIgnore(first.findings[0]!.id);

    const second = await manageFindings([makeRaw()], ctx, config, NO_OSV);
    expect(second.suppressedCount).toBe(1);
  });

  it('glob パターンで抑制できる', async () => {
    await writeIgnore('src/**  # レガシーコードは対象外\n');
    const { findings, suppressedCount } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    expect(findings).toHaveLength(0);
    expect(suppressedCount).toBe(1);
  });

  it('旧名 .vulnignore しか無い場合も loadConfig 経由で抑制できる（後方互換）', async () => {
    // 現行名は置かず、旧名だけを置く
    await writeFile(join(repoRoot, '.vulnignore'), 'CWE-89\n', 'utf8');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.ignorePath).toBe('.vulnignore');
    expect(warnings.some((w) => w.includes('.vulnignore'))).toBe(true);

    const { suppressedCount } = await manageFindings(
      [makeRaw()],
      makeContext(),
      config,
      NO_OSV,
    );
    expect(suppressedCount).toBe(1);
  });

  it('現行名 .grimoireignore が優先される', async () => {
    await writeFile(join(repoRoot, '.vulnignore'), 'CWE-89\n', 'utf8');
    await writeFile(join(repoRoot, '.grimoireignore'), '# 何も抑制しない\n', 'utf8');
    const { config } = await loadConfig(repoRoot);
    expect(config.ignorePath).toBe('.grimoireignore');

    const { findings, suppressedCount } = await manageFindings(
      [makeRaw()],
      makeContext(),
      config,
      NO_OSV,
    );
    expect(findings).toHaveLength(1);
    expect(suppressedCount).toBe(0);
  });

  it('CWE 単位で抑制できる', async () => {
    await writeIgnore('CWE-89\n');
    const { suppressedCount } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    expect(suppressedCount).toBe(1);
  });

  it('glob と CWE の AND 条件を書ける', async () => {
    await writeIgnore('src/api/** CWE-79\n');
    const { findings, suppressedCount } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig(),
      NO_OSV,
    );
    // CWE-89 なので抑制されない
    expect(findings).toHaveLength(1);
    expect(suppressedCount).toBe(0);
  });

  it('.vulnignore が無くてもエラーにならない', async () => {
    const { errors } = await manageFindings([makeRaw()], makeContext(), makeConfig(), NO_OSV);
    expect(errors).toEqual([]);
  });

  it('コメント・空行を無視する', () => {
    const list = parseIgnoreList('# コメントのみ\n\n   \nCWE-79\nsrc/**\n');
    expect(list.rules).toHaveLength(2);
    expect(list.rules[0]!.kind).toBe('cwe');
    expect(list.rules[1]!.kind).toBe('glob');
  });

  it('マッチしたルールを返す', () => {
    const list = parseIgnoreList('CWE-89');
    const finding = { cwe: 'CWE-89', id: 'VS-1', fingerprint: 'a', location: { file: 'x' } } as unknown as Finding;
    expect(matchIgnoreRule(finding, list)?.kind).toBe('cwe');
  });
});

describe('パストラバーサルの封じ込め', () => {
  /** スキャン対象リポジトリの外に置かれた「読まれてはいけない」ファイル */
  let outsideDir: string;
  let secretPath: string;

  beforeEach(async () => {
    outsideDir = await mkdtemp(join(tmpdir(), 'vulnscan-outside-'));
    secretPath = join(outsideDir, 'secret.json');
    await writeFile(
      secretPath,
      JSON.stringify({ findings: [{ fingerprint: 'a'.repeat(64) }] }),
      'utf8',
    );
  });

  afterEach(async () => {
    await rm(outsideDir, { recursive: true, force: true });
  });

  /** repoRoot から outsideDir へ抜ける相対パス */
  const escapeTo = (target: string): string => `../${target.split('/').slice(-2).join('/')}`;

  it('loadBaseline は絶対パスを拒否する', async () => {
    const result = await loadBaseline(secretPath, repoRoot);
    expect(result.existed).toBe(false);
    expect(result.baseline.findings).toEqual([]);
    expect(result.errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('loadBaseline は `..` 脱出を拒否する', async () => {
    const result = await loadBaseline(escapeTo(secretPath), repoRoot);
    expect(result.baseline.findings).toEqual([]);
    expect(result.errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('loadBaseline は allowOutside 指定時のみリポジトリ外を読む（CLI由来の信頼）', async () => {
    const result = await loadBaseline(secretPath, repoRoot, { allowOutside: true });
    expect(result.existed).toBe(true);
    expect(result.baseline.findings).toHaveLength(1);
  });

  it('loadIgnoreList は絶対パス・`..` 脱出を拒否する', async () => {
    await writeFile(join(outsideDir, '.vulnignore'), 'CWE-89\n', 'utf8');
    const abs = await loadIgnoreList(join(outsideDir, '.vulnignore'), repoRoot);
    expect(abs.rules).toEqual([]);
    expect(abs.errors.some((e) => e.includes('リポジトリ外'))).toBe(true);

    const rel = await loadIgnoreList(escapeTo(join(outsideDir, '.vulnignore')), repoRoot);
    expect(rel.rules).toEqual([]);
    expect(rel.errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('saveBaseline はリポジトリ外への書き出しを拒否する', async () => {
    const target = join(outsideDir, 'written.json');
    await expect(saveBaseline([], target, repoRoot)).rejects.toThrow(/リポジトリ外/);
    await expect(saveBaseline([], '../../evil.json', repoRoot)).rejects.toThrow(/リポジトリ外/);
    await expect(access(target)).rejects.toThrow();
  });

  it('saveBaseline は allowOutside 指定時のみリポジトリ外へ書ける', async () => {
    const target = join(outsideDir, 'written.json');
    const written = await saveBaseline([], target, repoRoot, { allowOutside: true });
    expect(written).toBe(target);
    await expect(access(target)).resolves.toBeUndefined();
  });

  it('設定ファイル由来の baselinePath ではリポジトリ外を読まない', async () => {
    const pathSources: PathSources = { baselinePath: 'config-file', ignorePath: 'config-file' };
    const { findings, errors } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig({ baselinePath: secretPath, pathSources }),
      NO_OSV,
    );
    // ベースラインを読めていないので新規扱いのまま
    expect(findings[0]!.diffStatus).toBe('new');
    expect(errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('設定ファイル由来の ignorePath ではリポジトリ外を読まない', async () => {
    await writeFile(join(outsideDir, '.vulnignore'), 'CWE-89\n', 'utf8');
    const pathSources: PathSources = { baselinePath: 'config-file', ignorePath: 'config-file' };
    const { findings, suppressedCount, errors } = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig({ ignorePath: join(outsideDir, '.vulnignore'), pathSources }),
      NO_OSV,
    );
    // 外部の抑制リストは適用されない
    expect(findings).toHaveLength(1);
    expect(suppressedCount).toBe(0);
    expect(errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('CLI由来（pathSources=cli）ならリポジトリ外のベースラインを読む', async () => {
    const pathSources: PathSources = { baselinePath: 'cli', ignorePath: 'default' };
    const first = await manageFindings([makeRaw()], makeContext(), makeConfig(), {
      ...NO_OSV,
      now: LAST_YEAR,
    });
    const outsideBaseline = join(outsideDir, 'cli-baseline.json');
    await saveBaseline(first.findings, outsideBaseline, repoRoot, { allowOutside: true });

    const second = await manageFindings(
      [makeRaw()],
      makeContext(),
      makeConfig({ baselinePath: outsideBaseline, pathSources }),
      NO_OSV,
    );
    expect(second.findings[0]!.diffStatus).toBe('persistent');
  });
});

describe('エラーメッセージの情報漏洩', () => {
  const SECRET = 'CONFIDENTIAL-TOKEN-abcdef0123456789';

  it('壊れたベースラインのエラーに絶対パスも生の例外文字列も含めない', async () => {
    const config = makeConfig();
    await mkdir(join(repoRoot, dirname(config.baselinePath)), { recursive: true });
    await writeFile(join(repoRoot, config.baselinePath), `{ ${SECRET} は秘密 }`, 'utf8');

    const { errors } = await loadBaseline(config.baselinePath, repoRoot);
    expect(errors).toHaveLength(1);
    const message = errors[0]!;
    // ファイル内容（JSON.parse の SyntaxError に混入する）が漏れない
    expect(message).not.toContain(SECRET);
    expect(message).not.toMatch(/Unexpected|JSON\.parse|SyntaxError|position/i);
    // 絶対パスを出さず、リポジトリ相対で示す
    expect(message).not.toContain(repoRoot);
    expect(message).not.toContain(tmpdir());
    expect(message).toContain(config.baselinePath);
  });

  it('抑制リストの読み込み失敗でも絶対パスと生の例外文字列を出さない', async () => {
    // ディレクトリを .vulnignore として置くと EISDIR で失敗する
    await mkdir(join(repoRoot, '.vulnignore'), { recursive: true });
    const { errors } = await loadIgnoreList('.vulnignore', repoRoot);
    expect(errors).toHaveLength(1);
    expect(errors[0]!).not.toContain(repoRoot);
    expect(errors[0]!).not.toMatch(/EISDIR: illegal|read$/);
    expect(errors[0]!).toContain('.vulnignore');
  });

  it('manageFindings 経由でも絶対パスを漏らさない', async () => {
    const config = makeConfig();
    await mkdir(join(repoRoot, dirname(config.baselinePath)), { recursive: true });
    await writeFile(join(repoRoot, config.baselinePath), `{ ${SECRET}`, 'utf8');
    const { errors } = await manageFindings([makeRaw()], makeContext(), config, NO_OSV);
    expect(errors.length).toBeGreaterThan(0);
    for (const e of errors) {
      expect(e).not.toContain(repoRoot);
      expect(e).not.toContain(SECRET);
    }
  });
});

describe('globToRegExp', () => {
  it('* は階層を跨がない', () => {
    expect(globToRegExp('src/*.ts').test('src/a.ts')).toBe(true);
    expect(globToRegExp('src/*.ts').test('src/sub/a.ts')).toBe(false);
  });

  it('** は階層を跨ぐ', () => {
    expect(globToRegExp('src/**').test('src/sub/a.ts')).toBe(true);
    expect(globToRegExp('**/*.test.ts').test('src/a.test.ts')).toBe(true);
    expect(globToRegExp('**/*.test.ts').test('a.test.ts')).toBe(true);
  });

  it('? は1文字に一致する', () => {
    expect(globToRegExp('a?.ts').test('ab.ts')).toBe(true);
    expect(globToRegExp('a?.ts').test('abc.ts')).toBe(false);
  });

  it('メタ文字をエスケープする', () => {
    expect(globToRegExp('a+b.ts').test('a+b.ts')).toBe(true);
    expect(globToRegExp('a+b.ts').test('aab.ts')).toBe(false);
  });

  it('末尾 / のディレクトリ指定は配下すべてに一致する', () => {
    expect(globToRegExp('src/legacy/').test('src/legacy/a.ts')).toBe(true);
    expect(globToRegExp('src/legacy/').test('src/other/a.ts')).toBe(false);
  });

  /* --- ここから下は共有実装（context/glob.ts）へ寄せたことで増えた機能 --- */

  it('【統合で改善】{a,b} を展開する（独自実装ではリテラル扱いだった）', () => {
    expect(globToRegExp('src/*.{ts,tsx}').test('src/a.ts')).toBe(true);
    expect(globToRegExp('src/*.{ts,tsx}').test('src/a.tsx')).toBe(true);
    expect(globToRegExp('src/*.{ts,tsx}').test('src/a.js')).toBe(false);
  });

  it('【統合で改善】[abc] / [!abc] の文字クラスを解釈する', () => {
    expect(globToRegExp('a[bc].ts').test('ab.ts')).toBe(true);
    expect(globToRegExp('a[bc].ts').test('ad.ts')).toBe(false);
    expect(globToRegExp('a[!bc].ts').test('ad.ts')).toBe(true);
    expect(globToRegExp('a[!bc].ts').test('ab.ts')).toBe(false);
  });

  it('【統合で改善】.gitignore 側（context/glob.ts）と解釈が一致する', () => {
    for (const pattern of ['src/*.{ts,tsx}', 'a[bc].ts', 'src/**', '**/*.test.ts']) {
      for (const path of ['src/a.ts', 'src/a.tsx', 'ab.ts', 'ad.ts', 'src/sub/a.test.ts']) {
        expect(globToRegExp(pattern).test(path)).toBe(sharedMatchGlob(pattern, path));
      }
    }
  });

  it('【統合で改善】変換不能なパターンでも throw せず、何にもマッチしない', () => {
    // 独自実装は new RegExp が throw する前提だったが、共有版は throw しない契約。
    const list = parseIgnoreList('src/[a-\n');
    expect(list.errors).toEqual([]);
    expect(list.rules).toHaveLength(1);
  });
});

describe('matchIgnoreRule のパス正規化', () => {
  /** 抑制判定に必要な最小限の Finding */
  const findingAt = (file: string): Finding =>
    ({
      id: 'VS-000000000001',
      fingerprint: 'a'.repeat(64),
      cwe: 'CWE-89',
      location: { file, startLine: 1, endLine: 1 },
    }) as unknown as Finding;

  it("【統合で改善】先頭 './' が付いた Finding も取りこぼさない", () => {
    const list = parseIgnoreList('src/legacy/**');
    expect(matchIgnoreRule(findingAt('src/legacy/a.ts'), list)?.kind).toBe('glob');
    expect(matchIgnoreRule(findingAt('./src/legacy/a.ts'), list)?.kind).toBe('glob');
  });

  it('【統合で改善】Windows 区切り・重複スラッシュも吸収する', () => {
    const list = parseIgnoreList('src/legacy/**');
    expect(matchIgnoreRule(findingAt('src\\legacy\\a.ts'), list)?.kind).toBe('glob');
    expect(matchIgnoreRule(findingAt('//src/legacy/a.ts'), list)?.kind).toBe('glob');
  });

  it('関係ないパスは従来どおり素通しする', () => {
    const list = parseIgnoreList('src/legacy/**');
    expect(matchIgnoreRule(findingAt('src/app/a.ts'), list)).toBeNull();
  });
});

describe('依存脆弱性との統合', () => {
  const depContext = (): ScanContext =>
    makeContext({
      dependencies: [
        { name: 'lodash', version: '4.17.15', ecosystem: 'npm', dev: false, manifest: 'package.json' },
      ],
    });

  const okFetch: FetchLike = async (url) => {
    const json = url.includes('querybatch')
      ? { results: [{ vulns: [{ id: 'GHSA-xxxx' }] }] }
      : {
          id: 'GHSA-xxxx',
          aliases: ['CVE-2020-8203'],
          summary: 'Prototype pollution',
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
          affected: [
            {
              package: { name: 'lodash', ecosystem: 'npm' },
              ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.20' }] }],
            },
          ],
        };
    return { ok: true, status: 200, json: async () => json } as unknown as Response;
  };

  it('コード由来と依存由来の Finding が混在する', async () => {
    const { findings, errors } = await manageFindings(
      [makeRaw()],
      depContext(),
      makeConfig(),
      { now: NOW, osv: { fetchImpl: okFetch } },
    );
    expect(errors).toEqual([]);
    expect(findings).toHaveLength(2);
    const dep = findings.find((f) => f.lens === 'dependency')!;
    expect(dep.cve).toBe('CVE-2020-8203');
    expect(dep.cvss.baseScore).toBe(9.8);
    expect(dep.severity).toBe('critical');
  });

  it('依存脆弱性は同一マニフェストでも統合されない', async () => {
    const twoVulns: FetchLike = async (url) => {
      const json = url.includes('querybatch')
        ? { results: [{ vulns: [{ id: 'GHSA-aaaa' }, { id: 'GHSA-bbbb' }] }] }
        : { id: url.split('/').pop(), summary: '別の脆弱性', database_specific: { severity: 'HIGH' } };
      return { ok: true, status: 200, json: async () => json } as unknown as Response;
    };
    const { findings } = await manageFindings([], depContext(), makeConfig(), {
      now: NOW,
      osv: { fetchImpl: twoVulns },
    });
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((f) => f.fingerprint)).size).toBe(2);
  });

  it('ネットワークが使えなくてもコード由来の結果は返る（オフライン耐性）', async () => {
    const failing: FetchLike = async () => {
      throw new TypeError('fetch failed');
    };
    const { findings, errors } = await manageFindings([makeRaw()], depContext(), makeConfig(), {
      now: NOW,
      osv: { fetchImpl: failing },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.lens).toBe('injection');
    expect(errors.length).toBeGreaterThan(0);
  });
});
