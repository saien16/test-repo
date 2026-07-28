/**
 * 設定の読み込み。`.vulnscan.yml` → CLIオプション の順に既定値を上書きする。
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { DEFAULT_CONFIG, type VulnScanConfig } from '../types/config.js';

const CONFIG_FILENAMES = ['.vulnscan.yml', '.vulnscan.yaml'];

/** ネストしたオブジェクトを再帰的にマージする（配列は置換） */
function merge<T>(base: T, override: unknown): T {
  if (override === null || override === undefined) return base;
  if (Array.isArray(base) || Array.isArray(override)) return override as T;
  if (typeof base !== 'object' || typeof override !== 'object') return override as T;

  const result = { ...(base as object) } as Record<string, unknown>;
  for (const [key, value] of Object.entries(override as Record<string, unknown>)) {
    if (value === undefined) continue;
    const current = (base as Record<string, unknown>)[key];
    result[key] = current !== undefined ? merge(current, value) : value;
  }
  return result as T;
}

/**
 * 設定ファイルを読み込む。存在しなければ既定値をそのまま返す。
 * 不正なYAMLはエラーにせず警告として返し、既定値で続行する。
 */
export async function loadConfig(
  repoRoot: string,
  overrides: Partial<VulnScanConfig> = {},
): Promise<{ config: VulnScanConfig; warnings: string[] }> {
  const warnings: string[] = [];
  let fileConfig: unknown = null;

  for (const name of CONFIG_FILENAMES) {
    try {
      const raw = await readFile(join(repoRoot, name), 'utf8');
      fileConfig = parseYaml(raw);
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') continue;
      warnings.push(`設定ファイル ${name} の読み込みに失敗しました: ${String(err)}`);
    }
  }

  let config = merge(DEFAULT_CONFIG, fileConfig);
  config = merge(config, overrides);
  return { config, warnings };
}
