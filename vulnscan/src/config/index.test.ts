/**
 * 設定読み込みの信頼境界テスト。
 *
 * `.vulnscan.yml` はスキャン対象リポジトリの中にあるファイル＝未信頼入力。
 * そこから来たパス系設定でリポジトリ外を読み書きできてはいけない。
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../types/config.js';
import { loadConfig } from './index.js';

let repoRoot: string;

beforeEach(async () => {
  repoRoot = await mkdtemp(join(tmpdir(), 'vulnscan-config-'));
});

afterEach(async () => {
  await rm(repoRoot, { recursive: true, force: true });
});

async function writeConfig(yaml: string): Promise<void> {
  await writeFile(join(repoRoot, '.vulnscan.yml'), yaml, 'utf8');
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
