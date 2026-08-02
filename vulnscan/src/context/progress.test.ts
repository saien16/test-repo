/**
 * ①コンテキスト収集の進捗通知。
 *
 * 数えるのは「前処理したファイル数」。走査(walkRepository)側で数えないのは、
 * 走り終えるまで総数が判らず「12/? ファイル」しか出せないため。
 */

import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { collectContext } from './index.js';
import { DEFAULT_CONFIG, type VulnScanConfig } from '../types/config.js';
import type { StageProgress } from '../types/progress.js';

let repoRoot: string;

const config: VulnScanConfig = {
  ...DEFAULT_CONFIG,
  scan: { ...DEFAULT_CONFIG.scan, exclude: [] },
};

beforeEach(async () => {
  repoRoot = await mkdtemp(join(tmpdir(), 'grimoire-ctx-'));
  await mkdir(join(repoRoot, 'src'), { recursive: true });
  for (let i = 0; i < 5; i++) {
    await writeFile(
      join(repoRoot, 'src', `f${i}.ts`),
      `export function handler${i}(req: Request) {\n  return req.url;\n}\n`,
      'utf8',
    );
  }
});

afterEach(async () => {
  await rm(repoRoot, { recursive: true, force: true });
});

describe('collectContext の進捗', () => {
  it('ファイル単位で単調増加し、最後に総数へ達する', async () => {
    const seen: StageProgress[] = [];
    const ctx = await collectContext(repoRoot, config, { onProgress: (p) => seen.push(p) });

    expect(ctx.files.length).toBeGreaterThan(0);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((p) => p.unit === 'ファイル')).toBe(true);

    // 総数は一定、完了数は 1 ずつ増えて総数で終わる
    const total = seen[0]?.total ?? 0;
    expect(seen.every((p) => p.total === total)).toBe(true);
    expect(seen.map((p) => p.completed)).toEqual(seen.map((_, i) => i + 1));
    expect(seen[seen.length - 1]?.completed).toBe(total);
  });

  it('onProgress を渡さなくても収集結果は変わらない', async () => {
    const withCb = await collectContext(repoRoot, config, { onProgress: () => {} });
    const without = await collectContext(repoRoot, config);
    expect(without.files.map((f) => f.path).sort()).toEqual(
      withCb.files.map((f) => f.path).sort(),
    );
    expect(without.symbols.symbols.length).toBe(withCb.symbols.symbols.length);
  });

  it('走査対象が無ければ進捗も出ない（0/0 を出さない）', async () => {
    const empty = await mkdtemp(join(tmpdir(), 'grimoire-empty-'));
    try {
      const seen: StageProgress[] = [];
      await collectContext(empty, config, { onProgress: (p) => seen.push(p) });
      expect(seen).toEqual([]);
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });
});
