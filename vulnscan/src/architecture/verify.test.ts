/**
 * LLM が返した引用の検証。
 * ここが機能しないと「捏造された根拠を持つ推測」が事実のように見えてしまう。
 */

import { describe, expect, it } from 'vitest';
import { normalizeLlmPath, verifyCitations, type CitationIndex } from './verify.js';

const index: CitationIndex = {
  knownPaths: new Set(['Dockerfile', 'k8s/deploy.yaml', 'src/api.ts']),
  contents: new Map([
    ['Dockerfile', 'FROM node:20\nEXPOSE 3000\n'],
    ['k8s/deploy.yaml', 'kind: Deployment\n'],
  ]),
  repoRoot: '/repo',
};

describe('normalizeLlmPath', () => {
  it('絶対パス・先頭 ./ を吸収する', () => {
    expect(normalizeLlmPath('/repo/Dockerfile', '/repo')).toBe('Dockerfile');
    expect(normalizeLlmPath('./Dockerfile', '/repo')).toBe('Dockerfile');
    expect(normalizeLlmPath('k8s\\deploy.yaml', '/repo')).toBe('k8s/deploy.yaml');
  });
});

describe('verifyCitations', () => {
  it('実在しないファイルの引用は丸ごと捨てる', () => {
    const { citations, rejected } = verifyCitations(
      [
        { file: 'Dockerfile', line: 1, excerpt: 'FROM node:20' },
        { file: 'infra/does-not-exist.tf', line: 3, excerpt: 'resource "aws_lb" "x" {' },
      ],
      index,
    );
    expect(citations).toHaveLength(1);
    expect(citations[0]?.file).toBe('Dockerfile');
    expect(rejected.join('\n')).toContain('実在しないファイル');
  });

  it('行数を超える行番号は落とす（引用自体は残す）', () => {
    const { citations, rejected } = verifyCitations([{ file: 'Dockerfile', line: 999, excerpt: null }], index);
    expect(citations).toHaveLength(1);
    expect(citations[0]?.line).toBeUndefined();
    expect(rejected.join('\n')).toContain('ファイル行数を超えています');
  });

  it('ファイル内に存在しない抜粋は落とす', () => {
    const { citations, rejected } = verifyCitations(
      [{ file: 'Dockerfile', line: 1, excerpt: 'RUN rm -rf / # 捏造された行' }],
      index,
    );
    expect(citations[0]?.excerpt).toBeUndefined();
    expect(citations[0]?.line).toBe(1);
    expect(rejected.join('\n')).toContain('抜粋がファイル内に見つかりません');
  });

  it('内容を持たないファイルは行番号を検証せずそのまま採る', () => {
    const { citations } = verifyCitations([{ file: 'src/api.ts', line: 42, excerpt: null }], index);
    expect(citations[0]).toEqual({ file: 'src/api.ts', line: 42 });
  });

  it('null や不正な入力でも落ちない', () => {
    expect(verifyCitations(null, index).citations).toEqual([]);
    expect(verifyCitations([{ file: '', line: null, excerpt: null }], index).citations).toEqual([]);
  });
});
