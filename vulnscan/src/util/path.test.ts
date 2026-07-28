/**
 * パス封じ込めユーティリティのテスト。
 */

import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveInside, resolveRepoPath, toDisplayPath } from './path.js';

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
