/**
 * CLIフラグ → 設定 の配線テスト。
 *
 * ここで見ているのは信頼境界そのもの。パス系設定に対応する CLI フラグが
 * 無いと `pathSources` が構造上決して 'cli' にならず、
 * 「オペレータが明示指定したときだけリポジトリ外を許す」機構が空回りする。
 * 実際 `--ignore-file` は存在せず、`ignorePath` の allowOutside は常に false だった。
 */

import { Command } from 'commander';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../config/index.js';
import { isOperatorProvidedPath, CONFIG_SPEC, PATH_KEYS } from '../types/config.js';
import { loadIgnoreList } from '../vuln/ignore.js';
import { registerScanOptions, toConfigOverrides, type CliOptions } from './options.js';

let repoRoot: string;
let outsideDir: string;

beforeEach(async () => {
  repoRoot = await mkdtemp(join(tmpdir(), 'grimoire-cli-repo-'));
  outsideDir = await mkdtemp(join(tmpdir(), 'grimoire-cli-outside-'));
});

afterEach(async () => {
  await rm(repoRoot, { recursive: true, force: true });
  await rm(outsideDir, { recursive: true, force: true });
});

/** 実際の scan サブコマンドと同じオプション定義で引数を解釈する */
function parseArgs(argv: string[]): CliOptions {
  const command = registerScanOptions(new Command('scan').argument('[path]', '', '.'));
  command.exitOverride();
  command.parse(argv, { from: 'user' });
  return command.opts<CliOptions>();
}

describe('registerScanOptions', () => {
  it('spec が宣言している CLI フラグがすべて実在する', () => {
    const help = registerScanOptions(new Command('scan')).helpInformation();
    for (const [key, spec] of Object.entries(CONFIG_SPEC)) {
      // nested（llm / scan）には cli フラグが無いので、持つものだけ検査する
      const cli = 'cli' in spec ? spec.cli : undefined;
      if (cli === undefined) continue;
      expect(help, `${key} の ${cli} が CLI に無い`).toContain(cli);
    }
    // パス系は例外なくフラグを持つ（持たないと出所が 'cli' になりえない）
    for (const key of PATH_KEYS) expect(help).toContain(CONFIG_SPEC[key].cli);
  });

  it('--no-architecture / --no-heatmap が設定へ反映される', () => {
    expect(toConfigOverrides(parseArgs([]))).toEqual({});
    expect(toConfigOverrides(parseArgs(['--no-architecture']))).toEqual({ architecture: false });
    expect(toConfigOverrides(parseArgs(['--no-heatmap']))).toEqual({ heatmap: false });
    expect(toConfigOverrides(parseArgs(['--no-kill-chain']))).toEqual({ killChain: false });
  });

  it('--no-fail-on-incomplete が failOnIncompleteScan へ反映される', () => {
    // 既定は「未完走なら落とす」。無効化は明示的なフラグでのみ行える
    expect(toConfigOverrides(parseArgs([]))).toEqual({});
    expect(toConfigOverrides(parseArgs(['--no-fail-on-incomplete']))).toEqual({
      failOnIncompleteScan: false,
    });
  });

  it('--ignore-file が ignorePath へ、--baseline が baselinePath へ入る', () => {
    const overrides = toConfigOverrides(
      parseArgs(['--ignore-file', 'custom/.ignore', '--baseline', 'custom/base.json']),
    );
    expect(overrides).toEqual({
      ignorePath: 'custom/.ignore',
      baselinePath: 'custom/base.json',
    });
  });
});

describe('--ignore-file の信頼境界', () => {
  it('--ignore-file 指定時は出所が cli になり、リポジトリ外でも許可される', async () => {
    const outsideIgnore = join(outsideDir, '.grimoireignore');
    await writeFile(outsideIgnore, 'CWE-89\n', 'utf8');

    const overrides = toConfigOverrides(parseArgs(['--ignore-file', outsideIgnore]));
    const { config, warnings } = await loadConfig(repoRoot, overrides);

    expect(warnings).toEqual([]);
    expect(config.ignorePath).toBe(outsideIgnore);
    expect(config.pathSources?.ignorePath).toBe('cli');
    expect(isOperatorProvidedPath(config, 'ignorePath')).toBe(true);
    // 指定していない側は既定のまま
    expect(config.pathSources?.baselinePath).toBe('default');

    // 実際にリポジトリ外の抑制リストが読める
    const list = await loadIgnoreList(config.ignorePath, repoRoot, {
      allowOutside: isOperatorProvidedPath(config, 'ignorePath'),
    });
    expect(list.errors).toEqual([]);
    expect(list.rules.map((rule) => rule.value)).toEqual(['CWE-89']);
  });

  it('設定ファイル由来の ignorePath はリポジトリ外を拒否される', async () => {
    const outsideIgnore = join(outsideDir, '.grimoireignore');
    await writeFile(outsideIgnore, 'CWE-89\n', 'utf8');
    await writeFile(join(repoRoot, '.grimoire.yml'), `ignorePath: ${outsideIgnore}\n`, 'utf8');

    const { config, warnings } = await loadConfig(repoRoot);

    // 既定値へフォールバックし、出所も cli にならない
    expect(config.ignorePath).toBe('.grimoireignore');
    expect(config.pathSources?.ignorePath).toBe('default');
    expect(isOperatorProvidedPath(config, 'ignorePath')).toBe(false);
    expect(warnings.some((w) => w.includes('ignorePath') && w.includes('リポジトリ外'))).toBe(true);

    // 仮にパスが残っていたとしても、封じ込めが効いて外部リストは読めない
    const list = await loadIgnoreList(outsideIgnore, repoRoot, {
      allowOutside: isOperatorProvidedPath(config, 'ignorePath'),
    });
    expect(list.rules).toEqual([]);
    expect(list.errors.some((e) => e.includes('リポジトリ外'))).toBe(true);
  });

  it('設定ファイルの ignorePath より CLI 指定が優先される', async () => {
    await writeFile(join(repoRoot, '.grimoire.yml'), 'ignorePath: config/.ignore\n', 'utf8');
    const overrides = toConfigOverrides(parseArgs(['--ignore-file', 'cli/.ignore']));
    const { config } = await loadConfig(repoRoot, overrides);
    expect(config.ignorePath).toBe('cli/.ignore');
    expect(config.pathSources?.ignorePath).toBe('cli');
  });
});
