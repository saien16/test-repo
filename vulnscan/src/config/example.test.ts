/**
 * `.grimoire.yml.example` が spec から生成した内容と一致することの検証。
 *
 * 以前はサンプルを手で書いていたため、設定を足しても書き忘れる
 * （実際に architecture / heatmap / minInferenceConfidence が漏れていた）。
 * ここが失敗したら `src/config/example.ts` の出力でファイルを上書きすること。
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { CONFIG_SPEC, DEFAULT_CONFIG } from '../types/config.js';
import { generateExample } from './example.js';
import { loadConfig } from './index.js';

/** リポジトリルートのサンプルファイル（このファイルからの相対で解決する） */
const EXAMPLE_PATH = fileURLToPath(new URL('../../.grimoire.yml.example', import.meta.url));

describe('.grimoire.yml.example', () => {
  it('spec から生成した内容と実ファイルが一致する', () => {
    const actual = readFileSync(EXAMPLE_PATH, 'utf8');
    expect(generateExample()).toBe(actual);
  });

  it('全フィールドがサンプルに現れる（ドリフトの再発防止）', () => {
    const parsed = parseYaml(readFileSync(EXAMPLE_PATH, 'utf8')) as Record<string, unknown>;
    for (const key of Object.keys(CONFIG_SPEC)) {
      expect(parsed, `${key} がサンプルに無い`).toHaveProperty(key);
    }
    // 算出値である pathSources は書けないので載せない
    expect(parsed).not.toHaveProperty('pathSources');
  });

  it('サンプルの値は既定値そのもの（YAMLとして解釈しても一致する）', () => {
    const parsed = parseYaml(readFileSync(EXAMPLE_PATH, 'utf8')) as Record<string, unknown>;
    const { pathSources: _ignored, ...defaults } = DEFAULT_CONFIG;
    expect(parsed).toEqual(defaults);
  });

  it('サンプルをそのまま設定ファイルとして読ませても既定値のまま（警告も出ない）', async () => {
    const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');

    const repoRoot = await mkdtemp(join(tmpdir(), 'grimoire-example-'));
    try {
      await writeFile(
        join(repoRoot, '.grimoire.yml'),
        readFileSync(EXAMPLE_PATH, 'utf8'),
        'utf8',
      );
      const { config, warnings } = await loadConfig(repoRoot);
      expect(warnings).toEqual([]);
      const { pathSources, ...rest } = config;
      const { pathSources: _defaultSources, ...defaults } = DEFAULT_CONFIG;
      expect(rest).toEqual(defaults);
      // サンプルはリポジトリ内のパスしか書いていないので採用される（出所は設定ファイル）
      expect(pathSources).toEqual({ baselinePath: 'config-file', ignorePath: 'config-file' });
    } finally {
      await rm(repoRoot, { recursive: true, force: true });
    }
  });
});
