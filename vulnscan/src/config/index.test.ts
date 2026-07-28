/**
 * 設定読み込みの信頼境界テスト＋名称変更（vulnscan → GRIMOIRE）の後方互換テスト。
 *
 * `.grimoire.yml`（および旧名 `.vulnscan.yml`）はスキャン対象リポジトリの
 * 中にあるファイル＝未信頼入力。そこから来たパス系設定で
 * リポジトリ外を読み書きできてはいけない。
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, LEGACY_DEFAULT_PATHS, PATH_KEYS } from '../types/config.js';
import { CONFIG_FILENAMES, loadConfig } from './index.js';

let repoRoot: string;

beforeEach(async () => {
  repoRoot = await mkdtemp(join(tmpdir(), 'grimoire-config-'));
});

afterEach(async () => {
  await rm(repoRoot, { recursive: true, force: true });
});

/** 旧名の設定ファイルを書く（後方互換の既定経路） */
async function writeConfig(yaml: string): Promise<void> {
  await writeFile(join(repoRoot, '.vulnscan.yml'), yaml, 'utf8');
}

/** 任意の名前でリポジトリ内にファイルを置く */
async function put(relative: string, body = ''): Promise<void> {
  const full = join(repoRoot, relative);
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, body, 'utf8');
}

describe('loadConfig', () => {
  it('設定ファイルが無ければ既定値を返す', async () => {
    const { config, warnings } = await loadConfig(repoRoot);
    expect(warnings).toEqual([]);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
    expect(config.pathSources).toEqual({ baselinePath: 'default', ignorePath: 'default' });
  });

  it('リポジトリ内のパス設定は採用され、出所が config-file になる', async () => {
    await writeConfig('baselinePath: .vulnscan/custom.json\nignorePath: config/.vulnignore\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(warnings).toEqual([]);
    expect(config.baselinePath).toBe('.vulnscan/custom.json');
    expect(config.ignorePath).toBe('config/.vulnignore');
    expect(config.pathSources).toEqual({
      baselinePath: 'config-file',
      ignorePath: 'config-file',
    });
  });

  it('`..` で脱出する baselinePath を拒否し、既定値へフォールバックする', async () => {
    await writeConfig('baselinePath: ../../../tmp/pwned.json\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
    expect(config.pathSources?.baselinePath).toBe('default');
    expect(warnings.some((w) => w.includes('baselinePath') && w.includes('リポジトリ外'))).toBe(true);
  });

  it('絶対パスの baselinePath を拒否する', async () => {
    await writeConfig('baselinePath: /etc/cron.d/pwned\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
    expect(warnings.some((w) => w.includes('baselinePath'))).toBe(true);
  });

  it('`..` で脱出する ignorePath を拒否する', async () => {
    await writeConfig('ignorePath: ../../etc/passwd\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.ignorePath).toBe(DEFAULT_CONFIG.ignorePath);
    expect(config.pathSources?.ignorePath).toBe('default');
    expect(warnings.some((w) => w.includes('ignorePath'))).toBe(true);
  });

  it('絶対パスの ignorePath を拒否する', async () => {
    await writeConfig('ignorePath: /etc/passwd\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.ignorePath).toBe(DEFAULT_CONFIG.ignorePath);
    expect(warnings.some((w) => w.includes('ignorePath'))).toBe(true);
  });

  it('パス以外の設定は拒否の影響を受けない', async () => {
    await writeConfig('baselinePath: /etc/pwned.json\nfailOn: critical\nkillChain: false\n');
    const { config } = await loadConfig(repoRoot);
    expect(config.failOn).toBe('critical');
    expect(config.killChain).toBe(false);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
  });

  it('文字列でないパス設定を拒否する', async () => {
    await writeConfig('baselinePath:\n  - a\n  - b\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('CLIフラグ由来のパスはリポジトリ外でも受け入れ、出所が cli になる', async () => {
    const outside = join(tmpdir(), 'operator-baseline.json');
    const { config, warnings } = await loadConfig(repoRoot, { baselinePath: outside });
    expect(warnings).toEqual([]);
    expect(config.baselinePath).toBe(outside);
    expect(config.pathSources?.baselinePath).toBe('cli');
    // 指定していない側は既定のまま
    expect(config.pathSources?.ignorePath).toBe('default');
  });

  it('CLI指定は設定ファイルより優先され、出所も cli になる', async () => {
    await writeConfig('baselinePath: .vulnscan/from-file.json\n');
    const { config } = await loadConfig(repoRoot, { baselinePath: '.vulnscan/from-cli.json' });
    expect(config.baselinePath).toBe('.vulnscan/from-cli.json');
    expect(config.pathSources?.baselinePath).toBe('cli');
  });

  it('設定ファイルから pathSources を詐称できない', async () => {
    await writeConfig(
      ['pathSources:', '  baselinePath: cli', '  ignorePath: cli', 'ignorePath: /etc/passwd', ''].join(
        '\n',
      ),
    );
    const { config } = await loadConfig(repoRoot);
    expect(config.pathSources).toEqual({ baselinePath: 'default', ignorePath: 'default' });
    expect(config.ignorePath).toBe(DEFAULT_CONFIG.ignorePath);
  });

  it('新名 .grimoire.yml を読み込む', async () => {
    await put('.grimoire.yml', 'failOn: critical\nkillChain: false\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(warnings).toEqual([]);
    expect(config.failOn).toBe('critical');
    expect(config.killChain).toBe(false);
  });

  it('新名 .grimoire.yaml も読み込む', async () => {
    await put('.grimoire.yaml', 'failOn: low\n');
    const { config } = await loadConfig(repoRoot);
    expect(config.failOn).toBe('low');
  });

  it('旧名 .vulnscan.yml も引き続き読み込む（後方互換）', async () => {
    await put('.vulnscan.yml', 'failOn: medium\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(warnings).toEqual([]);
    expect(config.failOn).toBe('medium');
  });

  it('旧名 .vulnscan.yaml も引き続き読み込む', async () => {
    await put('.vulnscan.yaml', 'failOn: low\n');
    const { config } = await loadConfig(repoRoot);
    expect(config.failOn).toBe('low');
  });

  it('新旧が同居する場合は .grimoire.yml を優先する', async () => {
    await put('.grimoire.yml', 'failOn: critical\n');
    await put('.vulnscan.yml', 'failOn: low\n');
    const { config } = await loadConfig(repoRoot);
    expect(config.failOn).toBe('critical');
  });

  it('探索順は新名が先（優先順位そのもの）', () => {
    expect(CONFIG_FILENAMES.indexOf('.grimoire.yml')).toBeLessThan(
      CONFIG_FILENAMES.indexOf('.vulnscan.yml'),
    );
    expect(CONFIG_FILENAMES).toContain('.grimoire.yaml');
    expect(CONFIG_FILENAMES).toContain('.vulnscan.yaml');
  });
});

describe('既定パスの後方互換', () => {
  it('新旧どちらも無ければ新しい既定値を使う', async () => {
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe('.grimoire/baseline.json');
    expect(config.ignorePath).toBe('.grimoireignore');
    expect(warnings).toEqual([]);
  });

  it('旧ベースライン .vulnscan/baseline.json しか無ければそちらを読む', async () => {
    await put(LEGACY_DEFAULT_PATHS.baselinePath, '{"findings":[]}');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe('.vulnscan/baseline.json');
    // 出所は既定のままなので、リポジトリ内への封じ込めは効いたまま
    expect(config.pathSources?.baselinePath).toBe('default');
    expect(warnings.some((w) => w.includes('.vulnscan/baseline.json'))).toBe(true);
  });

  it('旧抑制リスト .vulnignore しか無ければそちらを読む', async () => {
    await put(LEGACY_DEFAULT_PATHS.ignorePath, 'CWE-79\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.ignorePath).toBe('.vulnignore');
    expect(config.pathSources?.ignorePath).toBe('default');
    expect(warnings.some((w) => w.includes('.vulnignore'))).toBe(true);
  });

  it('新旧が同居する場合は新しい方を使い、警告も出さない', async () => {
    await put('.grimoire/baseline.json', '{"findings":[]}');
    await put('.vulnscan/baseline.json', '{"findings":[]}');
    await put('.grimoireignore', '');
    await put('.vulnignore', '');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe('.grimoire/baseline.json');
    expect(config.ignorePath).toBe('.grimoireignore');
    expect(warnings).toEqual([]);
  });

  it('明示指定があれば旧パスが存在してもフォールバックしない', async () => {
    await put(LEGACY_DEFAULT_PATHS.baselinePath, '{}');
    await put(LEGACY_DEFAULT_PATHS.ignorePath, '');
    // CLI 由来
    const cli = await loadConfig(repoRoot, { baselinePath: 'custom/base.json' });
    expect(cli.config.baselinePath).toBe('custom/base.json');
    // 設定ファイル由来
    await put('.grimoire.yml', 'ignorePath: config/.ignore\n');
    const file = await loadConfig(repoRoot);
    expect(file.config.ignorePath).toBe('config/.ignore');
  });
});

/*
 * 封じ込めは spec の `kind: 'path'` から導出した PATH_KEYS 全体に効く。
 * 個別キーを列挙せず PATH_KEYS を回すことで、パス設定を足したときに
 * 「テストの書き忘れ」でも穴が空かないようにしてある。
 */
describe.each([...PATH_KEYS])('パス設定 %s の封じ込め（PATH_KEYS 由来）', (key) => {
  it('設定ファイルからリポジトリ外を指すと拒否され、出所は default のまま', async () => {
    await writeConfig(`${key}: /etc/passwd\n`);
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config[key]).toBe(DEFAULT_CONFIG[key]);
    expect(config.pathSources?.[key]).toBe('default');
    expect(warnings.some((w) => w.includes(key) && w.includes('リポジトリ外'))).toBe(true);
  });

  it('設定ファイルからリポジトリ内を指せば採用され、出所は config-file', async () => {
    await writeConfig(`${key}: inside/allowed\n`);
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config[key]).toBe('inside/allowed');
    expect(config.pathSources?.[key]).toBe('config-file');
    expect(warnings).toEqual([]);
  });

  it('CLI由来ならリポジトリ外でも受け入れ、出所は cli', async () => {
    const outside = join(tmpdir(), `operator-${key}`);
    const { config, warnings } = await loadConfig(repoRoot, { [key]: outside });
    expect(config[key]).toBe(outside);
    expect(config.pathSources?.[key]).toBe('cli');
    expect(warnings).toEqual([]);
  });

  it('設定ファイルから出所を詐称できない', async () => {
    await writeConfig(`pathSources:\n  ${key}: cli\n${key}: /etc/passwd\n`);
    const { config } = await loadConfig(repoRoot);
    expect(config.pathSources?.[key]).toBe('default');
    expect(config[key]).toBe(DEFAULT_CONFIG[key]);
  });
});

describe('loadConfig（信頼境界・続き）', () => {
  it('壊れたYAMLでも落とさず、例外メッセージを警告に載せない', async () => {
    await writeConfig('llm: [unclosed\n  secret: "ここは設定ファイルの中身"\n');
    const { config, warnings } = await loadConfig(repoRoot);
    expect(config.baselinePath).toBe(DEFAULT_CONFIG.baselinePath);
    expect(warnings.length).toBeGreaterThan(0);
    for (const w of warnings) {
      expect(w).not.toContain('ここは設定ファイルの中身');
      expect(w).not.toContain(repoRoot);
    }
  });
});
