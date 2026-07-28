/**
 * 設定の読み込み。`.grimoire.yml` → CLIオプション の順に既定値を上書きする。
 *
 * 後方互換:
 *   旧名 `.vulnscan.yml` / `.vulnscan.yaml` も読み込む。新旧が同居する場合は
 *   新しい `.grimoire.*` を優先する（{@link CONFIG_FILENAMES} の並び順がそのまま優先順位）。
 *   同様に、既定のベースライン `.grimoire/baseline.json` と抑制リスト
 *   `.grimoireignore` が存在せず旧名だけがある場合は旧名を読む。
 *
 * 信頼境界:
 *   `.grimoire.yml` は**スキャン対象リポジトリ**の中にあるファイルであり、
 *   サードパーティのリポジトリやCIの未信頼PRブランチを解析する運用では
 *   攻撃者が内容を制御できる。したがってここから来た値は未信頼入力として扱う。
 *   特にパス系設定（baselinePath / ignorePath）は、そのまま使うと
 *   任意ファイルの読み取り・書き込みに直結するため、リポジトリ内へ封じ込める。
 *
 *   一方 CLIフラグ由来の値はオペレータが明示的に指定したものなので信頼する。
 *   どちらの出所かは config.pathSources に記録する。
 */

import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  DEFAULT_CONFIG,
  LEGACY_DEFAULT_PATHS,
  type ConfigSource,
  type PathSources,
  type VulnScanConfig,
} from '../types/config.js';
import { resolveInside } from '../util/path.js';

/**
 * 探索する設定ファイル名。**先に書いたものが優先**される。
 * 旧名（`.vulnscan.*`）は後方互換のために残してある。
 */
export const CONFIG_FILENAMES = [
  '.grimoire.yml',
  '.grimoire.yaml',
  '.vulnscan.yml',
  '.vulnscan.yaml',
] as const;

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

  // 明示指定が無いキーだけ、旧名（vulnscan 時代）へのフォールバックを検討する
  const migrated: Partial<VulnScanConfig> = {};
  for (const key of PATH_KEYS) {
    if (pathSources[key] !== 'default') continue;
    const legacy = await legacyPathFor(key, repoRoot, warnings);
    if (legacy !== null) migrated[key] = legacy;
  }
  if (Object.keys(migrated).length > 0) config = { ...config, ...migrated };

  return { config, warnings };
}

/**
 * 新しい既定パスが無く旧パスだけが存在する場合に、旧パスを返す（それ以外は null）。
 *
 * 新旧が両方あるときは新しい方をそのまま使う（勝手に旧へ戻さない）。
 * 判定に失敗した場合も null を返し、既定値のまま続行する。
 */
async function legacyPathFor(
  key: PathKey,
  repoRoot: string,
  warnings: string[],
): Promise<string | null> {
  const current = DEFAULT_CONFIG[key];
  const legacy = LEGACY_DEFAULT_PATHS[key];
  if (!legacy || legacy === current) return null;
  if (await exists(join(repoRoot, current))) return null;
  if (!(await exists(join(repoRoot, legacy)))) return null;

  warnings.push(
    `旧名の ${legacy} を使用します（${key}）。${current} へリネームすることを推奨します。`,
  );
  return legacy;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
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
