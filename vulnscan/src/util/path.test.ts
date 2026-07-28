/**
 * パス封じ込めユーティリティのテスト。
 */

import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizePath as globNormalizePath } from '../context/glob.js';
import {
  normalizeRelPath,
  normalizeRepoRelPath,
  resolveInside,
  resolveRepoPath,
  toDisplayPath,
} from './path.js';

const ROOT = resolve('/tmp/vulnscan-root');

describe('resolveInside', () => {
  it('リポジトリ内の相対パスを解決する', () => {
    expect(resolveInside(ROOT, '.vulnscan/baseline.json')).toBe(
      resolve(ROOT, '.vulnscan/baseline.json'),
    );
  });

  it('`..` による脱出を弾く', () => {
    expect(resolveInside(ROOT, '../outside.json')).toBeNull();
    expect(resolveInside(ROOT, 'a/../../outside.json')).toBeNull();
    expect(resolveInside(ROOT, '../../../../etc/passwd')).toBeNull();
  });

  it('絶対パスを弾く', () => {
    expect(resolveInside(ROOT, '/etc/passwd')).toBeNull();
    expect(resolveInside(ROOT, resolve(ROOT, 'ok.json'))).toBe(resolve(ROOT, 'ok.json'));
  });

  it('ルート自身は弾く', () => {
    expect(resolveInside(ROOT, '.')).toBeNull();
    expect(resolveInside(ROOT, '')).toBeNull();
  });

  it('先頭が似ているだけの別ディレクトリを弾く', () => {
    expect(resolveInside(ROOT, '../vulnscan-root-evil/x.json')).toBeNull();
  });
});

describe('resolveRepoPath', () => {
  it('既定ではリポジトリ外を拒否する', () => {
    expect(resolveRepoPath(ROOT, '../x.json')).toBeNull();
    expect(resolveRepoPath(ROOT, '/etc/passwd')).toBeNull();
  });

  it('allowOutside を渡したときだけリポジトリ外を許す', () => {
    expect(resolveRepoPath(ROOT, '/etc/passwd', { allowOutside: true })).toBe('/etc/passwd');
    expect(resolveRepoPath(ROOT, '../x.json', { allowOutside: true })).toBe(
      resolve(ROOT, '../x.json'),
    );
  });

  it('空文字は解決しない', () => {
    expect(resolveRepoPath(ROOT, '')).toBeNull();
    expect(resolveRepoPath(ROOT, '   ')).toBeNull();
  });
});

describe('toDisplayPath', () => {
  it('リポジトリ相対のパスを返す（絶対パスは出さない）', () => {
    const shown = toDisplayPath(ROOT, resolve(ROOT, '.vulnscan/baseline.json'));
    expect(shown).toBe('.vulnscan/baseline.json');
    expect(shown).not.toContain(ROOT);
  });

  it('リポジトリ外は具体的な位置を伏せる', () => {
    expect(toDisplayPath(ROOT, '/etc/passwd')).toBe('(リポジトリ外のパス)');
    expect(toDisplayPath(ROOT, resolve(ROOT, '../secret.json'))).toBe('(リポジトリ外のパス)');
  });
});

/* ------------------------------------------------------------------ *
 * パス正規化の統合（旧: context/glob.ts / architecture/facts.ts /
 * killchain/reachability.ts / vuln/cvss.ts / vuln/fingerprint.ts の5実装）
 * ------------------------------------------------------------------ */

describe('normalizeRelPath', () => {
  it('区切り文字と冗長な ./ を吸収する', () => {
    expect(normalizeRelPath('src\\a\\b.ts')).toBe('src/a/b.ts');
    expect(normalizeRelPath('./src/a.ts')).toBe('src/a.ts');
    expect(normalizeRelPath('././src/a.ts')).toBe('src/a.ts');
    expect(normalizeRelPath('src/a.ts')).toBe('src/a.ts');
  });

  it('末尾の / を落とす', () => {
    expect(normalizeRelPath('src/a/')).toBe('src/a');
    expect(normalizeRelPath('src/a///')).toBe('src/a');
    expect(normalizeRelPath('/')).toBe('');
  });

  it('先頭の / を while で剥がす（旧 glob.ts 版は if 1回だった）', () => {
    // ここが統合前の食い違いの核心。'//src/a.ts' が '/src/a.ts' のまま残ると、
    // 構成要素の sourcePaths への前方一致が静かに外れる。
    expect(normalizeRelPath('/src/a.ts')).toBe('src/a.ts');
    expect(normalizeRelPath('//src/a.ts')).toBe('src/a.ts');
    expect(normalizeRelPath('///src/a.ts')).toBe('src/a.ts');
  });

  it('途中の重複スラッシュも畳む（旧 facts.ts / cvss.ts 版には無かった）', () => {
    expect(normalizeRelPath('src//a.ts')).toBe('src/a.ts');
    expect(normalizeRelPath('src///a//b.ts')).toBe('src/a/b.ts');
  });

  it('null / undefined / 空文字でも落ちない', () => {
    expect(normalizeRelPath(null)).toBe('');
    expect(normalizeRelPath(undefined)).toBe('');
    expect(normalizeRelPath('')).toBe('');
  });
});

describe('normalizeRelPath と context/glob.ts の突き合わせ', () => {
  /** 実運用で現れうる表記（重複スラッシュ以外） */
  const SAME = [
    'src/a.ts',
    './src/a.ts',
    '././src/a.ts',
    'src\\a\\b.ts',
    'src/a/',
    '/src/a.ts',
    '/',
    '',
    'a',
    'node_modules/pkg/index.js',
    '.github/workflows/ci.yml',
  ];

  it('重複スラッシュを含まない入力では glob.ts 版と完全に一致する', () => {
    for (const input of SAME) {
      expect(normalizeRelPath(input)).toBe(globNormalizePath(input));
    }
  });

  it('重複スラッシュを含む入力だけ結果が異なり、こちらが期待どおり剥がしきる', () => {
    // glob.ts は glob 照合の内部専用として現状維持（変更禁止）。
    // 前方一致に使うのは必ずこちら側であることを、差分として明示しておく。
    expect(globNormalizePath('//src/a.ts')).toBe('/src/a.ts');
    expect(normalizeRelPath('//src/a.ts')).toBe('src/a.ts');
  });
});

describe('normalizeRepoRelPath', () => {
  it('repoRoot の接頭辞を剥がす', () => {
    expect(normalizeRepoRelPath('/repo/src/a.ts', '/repo')).toBe('src/a.ts');
    expect(normalizeRepoRelPath('/repo/src/a.ts', '/repo/')).toBe('src/a.ts');
    expect(normalizeRepoRelPath('C:\\repo\\src\\a.ts', 'C:/repo')).toBe('src/a.ts');
  });

  it('repoRoot 配下でなければ単純正規化だけ行う', () => {
    expect(normalizeRepoRelPath('/other/src/a.ts', '/repo')).toBe('other/src/a.ts');
    // 先頭が似ているだけのディレクトリは剥がさない
    expect(normalizeRepoRelPath('/repo-evil/a.ts', '/repo')).toBe('repo-evil/a.ts');
  });

  it('repoRoot 未指定なら normalizeRelPath と同じ', () => {
    for (const input of ['./src/a.ts', '//src/a.ts', 'src\\a.ts', '']) {
      expect(normalizeRepoRelPath(input)).toBe(normalizeRelPath(input));
      expect(normalizeRepoRelPath(input, '')).toBe(normalizeRelPath(input));
    }
  });

  it('剥がしたあとも先頭の余分な / を落としきる', () => {
    expect(normalizeRepoRelPath('/repo//src/a.ts', '/repo')).toBe('src/a.ts');
  });
});
