/**
 * リポジトリ走査のうち、「自分が書いた成果物を対象に含めない」ことの検証。
 *
 * ここが壊れると症状が分かりにくい。走査のたびにファイル数が増え、
 * 規模の表示も費用も静かに狂うだけで、エラーにはならないため。
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../types/config.js';
import { walkRepository } from './walk.js';

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function makeRepo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'grimoire-walk-'));
  roots.push(root);
  return root;
}

describe('自分の成果物を走査しない', () => {
  it('reportDir と .grimoire/ は exclude が空でも除かれる', async () => {
    const root = await makeRepo();
    await mkdir(join(root, 'reports'), { recursive: true });
    await mkdir(join(root, '.grimoire', 'cache'), { recursive: true });
    await writeFile(join(root, 'app.js'), 'const a = 1;\n');
    await writeFile(join(root, 'reports', 'latest.html'), '<html></html>');
    await writeFile(join(root, 'reports', 'grimoire-x-20260806-000000.html'), '<html></html>');
    await writeFile(join(root, '.grimoire', 'cache', 'abc.json'), '{}');

    // exclude を空にしても効くこと（既定値に頼っていない）を確かめる
    const config = { ...DEFAULT_CONFIG, scan: { ...DEFAULT_CONFIG.scan, exclude: [] } };
    const out = await walkRepository(root, config, []);

    expect(out.files.map((f) => f.file.path)).toEqual(['app.js']);
  });

  it('reportDir を変えたら、その新しい場所が除かれる', async () => {
    const root = await makeRepo();
    await mkdir(join(root, 'out', 'scans'), { recursive: true });
    await writeFile(join(root, 'app.js'), 'const a = 1;\n');
    await writeFile(join(root, 'out', 'scans', 'latest.html'), '<html></html>');

    const config = {
      ...DEFAULT_CONFIG,
      reportDir: 'out/scans',
      scan: { ...DEFAULT_CONFIG.scan, exclude: [] },
    };
    const out = await walkRepository(root, config, []);

    expect(out.files.map((f) => f.file.path)).toEqual(['app.js']);
  });

  it('reportDir と名前が似ているだけのディレクトリは除かない', async () => {
    const root = await makeRepo();
    await mkdir(join(root, 'reports-archive'), { recursive: true });
    await writeFile(join(root, 'reports-archive', 'note.js'), 'const a = 1;\n');

    const config = { ...DEFAULT_CONFIG, scan: { ...DEFAULT_CONFIG.scan, exclude: [] } };
    const out = await walkRepository(root, config, []);

    expect(out.files.map((f) => f.file.path)).toContain('reports-archive/note.js');
  });
});
