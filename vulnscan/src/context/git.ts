/**
 * Git 情報の収集。
 *
 * git コマンドを子プロセスで叩く。git リポジトリでない場合や git 自体が
 * 無い場合は undefined を返し、スキャンは続行する。
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { GitContext } from '../types/context.js';
import { normalizePath } from './glob.js';

const run = promisify(execFile);

const TIMEOUT_MS = 15_000;
const MAX_BUFFER = 8 * 1024 * 1024;

/** ベースブランチの推定順。環境変数があればそれを最優先する */
const BASE_REF_CANDIDATES = ['origin/main', 'origin/master', 'main', 'master', 'develop'];

/** git を実行する。失敗時は null を返す */
async function git(repoRoot: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await run('git', args, {
      cwd: repoRoot,
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      windowsHide: true,
    });
    return stdout.trim();
  } catch {
    return null;
  }
}

function toLines(stdout: string | null): string[] {
  if (!stdout) return [];
  return stdout
    .split('\n')
    .map((line) => normalizePath(line.trim()))
    .filter((line) => line !== '');
}

/** ベースとなる ref を決める。解決できなければ null */
async function resolveBaseRef(repoRoot: string): Promise<string | null> {
  const fromEnv = process.env['VULNSCAN_BASE_REF'] ?? process.env['GITHUB_BASE_REF'];
  const candidates = fromEnv ? [fromEnv, ...BASE_REF_CANDIDATES] : BASE_REF_CANDIDATES;

  for (const ref of candidates) {
    if (ref.trim() === '') continue;
    const resolved = await git(repoRoot, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
    if (resolved) return ref;
  }
  return null;
}

/**
 * GitContext を構築する。git リポジトリでなければ undefined。
 */
export async function collectGitContext(
  repoRoot: string,
  warnings: string[],
): Promise<GitContext | undefined> {
  const inside = await git(repoRoot, ['rev-parse', '--is-inside-work-tree']);
  if (inside !== 'true') return undefined;

  const headSha = (await git(repoRoot, ['rev-parse', 'HEAD'])) ?? '';
  if (headSha === '') {
    warnings.push('HEAD を解決できませんでした（コミットが1つも無い可能性があります）');
  }

  const branch = (await git(repoRoot, ['rev-parse', '--abbrev-ref', 'HEAD'])) ?? 'HEAD';
  const baseRef = await resolveBaseRef(repoRoot);

  const changed = new Set<string>();

  // 作業ツリーの未コミット変更と未追跡ファイルは常に「変更あり」とみなす
  for (const file of toLines(await git(repoRoot, ['diff', '--name-only', 'HEAD']))) {
    changed.add(file);
  }
  for (const file of toLines(
    await git(repoRoot, ['ls-files', '--others', '--exclude-standard']),
  )) {
    changed.add(file);
  }

  if (baseRef) {
    const diff = await git(repoRoot, ['diff', '--name-only', `${baseRef}...HEAD`]);
    if (diff === null) {
      warnings.push(`ベース ${baseRef} との差分を取得できませんでした`);
    } else {
      for (const file of toLines(diff)) changed.add(file);
    }
  }

  return {
    branch,
    headSha,
    changedFiles: [...changed].sort(),
    baseRef: baseRef ?? undefined,
  };
}
