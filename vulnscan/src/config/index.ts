/**
 * 設定の読み込み。`.vulnscan.yml` → CLIオプション の順に既定値を上書きする。
 *
 * 信頼境界:
 *   `.vulnscan.yml` は**スキャン対象リポジトリ**の中にあるファイルであり、
 *   サードパーティのリポジトリやCIの未信頼PRブランチを解析する運用では
 *   攻撃者が内容を制御できる。したがってここから来た値は未信頼入力として扱う。
 *   特にパス系設定（baselinePath / ignorePath）は、そのまま使うと
 *   任意ファイルの読み取り・書き込みに直結するため、リポジトリ内へ封じ込める。
 *
 *   一方 CLIフラグ由来の値はオペレータが明示的に指定したものなので信頼する。
 *   どちらの出所かは config.pathSources に記録する。
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  DEFAULT_CONFIG,
  type ConfigSource,
  type PathSources,
  type VulnScanConfig,
} from '../types/config.js';
import { resolveInside } from '../util/path.js';

const CONFIG_FILENAMES = ['.vulnscan.yml', '.vulnscan.yaml'];

/** リポジトリ内への封じ込めを必須とする設定キー */
const PATH_KEYS = ['baselinePath', 'ignorePath'] as const;
type PathKey = (typeof PATH_KEYS)[number];

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
 * 設定ファイル由来の値から、危険なパス指定を取り除く。
 *
 * 例外では落とさない。該当キーを捨てて既定値へフォールバックし、
 * 何を拒否したかを warnings に残す（スキャン自体は続行する）。
 */
function sanitizeFileConfig(
  fileConfig: unknown,
  repoRoot: string,
  warnings: string[],
): Record<string, unknown> | null {
  if (fileConfig === null || typeof fileConfig !== 'object' || Array.isArray(fileConfig)) {
    return null;
  }
  const source = { ...(fileConfig as Record<string, unknown>) };

  // 出所の詐称を防ぐ: 信頼レベルは設定ファイルからは指定させない
  delete source['pathSources'];

  for (const key of PATH_KEYS) {
    if (!(key in source)) continue;
    const value = source[key];
    if (typeof value !== 'string' || value.trim() === '') {
      warnings.push(`設定 ${key} は文字列で指定してください。既定値を使用します。`);
      delete source[key];
      continue;
    }
    if (resolveInside(repoRoot, value) === null) {
      // 絶対パス・`..` 脱出はリポジトリ外の読み書きにつながるため拒否する
      warnings.push(
        `設定 ${key} がリポジトリ外を指しているため拒否しました（既定値を使用します）: ${value}`,
      );
      delete source[key];
    }
  }

  return source;
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
      // 例外メッセージは絶対パスやファイル内容の抜粋を含むため載せない
      warnings.push(`設定ファイル ${name} を読み込めませんでした。既定値を使用します。`);
    }
  }

  const sanitized = sanitizeFileConfig(fileConfig, repoRoot, warnings);

  let config = merge(DEFAULT_CONFIG, sanitized);
  config = merge(config, overrides);

  // パス系設定の出所を記録する（設定ファイル側の申告は上で捨ててある）
  const pathSources = {} as PathSources;
  for (const key of PATH_KEYS) {
    pathSources[key] = sourceOf(key, sanitized, overrides);
  }
  config = { ...config, pathSources };

  return { config, warnings };
}

function sourceOf(
  key: PathKey,
  fileConfig: Record<string, unknown> | null,
  overrides: Partial<VulnScanConfig>,
): ConfigSource {
  if (overrides[key] !== undefined) return 'cli';
  if (fileConfig && fileConfig[key] !== undefined) return 'config-file';
  return 'default';
}
