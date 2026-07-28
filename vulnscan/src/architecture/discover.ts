/**
 * マニフェスト探索とファイル読み出し。
 *
 * 走査対象は未信頼リポジトリなので、
 *   - ルート外へ出るパスは読まない
 *   - 読み込み・走査の失敗は例外にせず warnings へ
 *   - ファイル数・サイズに上限を設ける（巨大リポジトリでの暴走防止）
 * を守る。
 */

import { readdir, readFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve } from 'node:path';
import type { ScanContext } from '../types/context.js';
import { normalizeRepoPath } from './facts.js';

/** ファイルアクセスの抽象。テストではインメモリ実装を差し替える */
export interface RepoFileSystem {
  /** リポジトリルートからの相対パス一覧。失敗しても例外を投げない */
  list(): Promise<string[]>;
  /** 相対パスの内容。読めなければ null */
  read(relPath: string): Promise<string | null>;
}

/** 走査を打ち切るディレクトリ（コストが大きく設定ファイルも無い） */
const SKIP_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  '.next',
  '.nuxt',
  '.terraform',
  'dist',
  'build',
  'vendor',
  'coverage',
]);

const MAX_WALK_FILES = 20_000;
const MAX_WALK_DEPTH = 12;
/** 読み込む 1 ファイルの上限 */
const MAX_READ_BYTES = 256_000;
/** 解析するマニフェストの件数上限 */
export const MAX_MANIFESTS = 160;
/** 環境変数参照を探すソースファイルの件数上限 */
export const MAX_ENV_SCAN_FILES = 200;

/** repoRoot の外へ出るパスを弾く */
export function resolveInside(repoRoot: string, relPath: string): string | null {
  const root = resolve(repoRoot);
  const target = resolve(root, relPath);
  const rel = relative(root, target);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return null;
  return target;
}

/** 実ファイルシステム上の実装 */
export function createNodeFileSystem(repoRoot: string): RepoFileSystem {
  return {
    async list(): Promise<string[]> {
      const out: string[] = [];
      const walk = async (dir: string, depth: number): Promise<void> => {
        if (depth > MAX_WALK_DEPTH || out.length >= MAX_WALK_FILES) return;
        let entries;
        try {
          entries = await readdir(dir, { withFileTypes: true });
        } catch {
          // 読めないディレクトリは黙って飛ばす（権限など）
          return;
        }
        for (const entry of entries) {
          if (out.length >= MAX_WALK_FILES) return;
          const full = join(dir, entry.name);
          if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            await walk(full, depth + 1);
          } else if (entry.isFile()) {
            out.push(normalizeRepoPath(relative(repoRoot, full)));
          }
        }
      };
      try {
        await walk(resolve(repoRoot), 0);
      } catch {
        return out;
      }
      return out;
    },

    async read(relPath: string): Promise<string | null> {
      const target = resolveInside(repoRoot, relPath);
      if (target === null) return null;
      try {
        const buf = await readFile(target);
        if (buf.length > MAX_READ_BYTES) return buf.subarray(0, MAX_READ_BYTES).toString('utf8');
        return buf.toString('utf8');
      } catch {
        return null;
      }
    },
  };
}

/** マニフェストの分類 */
export type ManifestType =
  | 'dockerfile'
  | 'compose'
  | 'kubernetes-candidate'
  | 'helm-chart'
  | 'serverless'
  | 'cloudformation-candidate'
  | 'vercel'
  | 'netlify'
  | 'procfile'
  | 'paas-candidate'
  | 'terraform'
  | 'pulumi'
  | 'github-workflow'
  | 'gitlab-ci'
  | 'circleci'
  | 'jenkins'
  | 'package-manifest'
  | 'dotenv';

function baseName(path: string): string {
  const idx = path.lastIndexOf('/');
  return idx < 0 ? path : path.slice(idx + 1);
}

/**
 * パスからマニフェスト種別を判定する。
 * 判定できないものは null（読み込み対象外）。
 */
export function classifyManifest(rawPath: string): ManifestType | null {
  const path = normalizeRepoPath(rawPath);
  const lower = path.toLowerCase();
  const base = baseName(lower);

  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) {
    return 'dockerfile';
  }
  if (/^(docker-)?compose(\.[\w.-]+)?\.ya?ml$/.test(base)) return 'compose';
  if (/^serverless(\.[\w-]+)?\.(ya?ml|json)$/.test(base)) return 'serverless';
  if (base === 'vercel.json' || base === 'now.json') return 'vercel';
  if (base === 'netlify.toml') return 'netlify';
  if (base === 'procfile') return 'procfile';
  if (base === 'fly.toml' || base === 'render.yaml' || base === 'app.yaml') return 'paas-candidate';
  if (base.endsWith('.tf') || base.endsWith('.tf.json') || base === 'terragrunt.hcl') {
    return 'terraform';
  }
  if (base === 'pulumi.yaml' || base === 'pulumi.yml') return 'pulumi';
  if (base === 'chart.yaml' || base === 'chart.yml') return 'helm-chart';
  if (lower.startsWith('.github/workflows/') && /\.ya?ml$/.test(base)) return 'github-workflow';
  if (base === '.gitlab-ci.yml') return 'gitlab-ci';
  if (lower === '.circleci/config.yml' || lower === '.circleci/config.yaml') return 'circleci';
  if (base === 'jenkinsfile') return 'jenkins';
  if (base === 'package.json' || base === 'requirements.txt' || base === 'go.mod') {
    return 'package-manifest';
  }
  if (/^requirements[\w.-]*\.txt$/.test(base)) return 'package-manifest';
  if (base === '.env' || base.startsWith('.env.')) return 'dotenv';
  // SAM / CloudFormation の可能性がある yaml/json。内容で最終判定する
  if (/^(template|cloudformation|stack)([-.\w]+)?\.(ya?ml|json)$/.test(base)) {
    return 'cloudformation-candidate';
  }
  // それ以外の yaml は Kubernetes マニフェストの可能性がある。内容で判定する
  if (/\.ya?ml$/.test(base)) return 'kubernetes-candidate';
  return null;
}

export interface LoadedManifest {
  path: string;
  type: ManifestType;
  content: string;
}

export interface DiscoveryResult {
  manifests: LoadedManifest[];
  /** 引用の実在検証に使う、リポジトリ内に存在するパスの集合（正規化済み） */
  knownPaths: Set<string>;
  /** 読み込み済みファイルの内容（引用の行番号・抜粋検証に使う） */
  contents: Map<string, string>;
  warnings: string[];
}

/** 候補ファイルを列挙して読み込む */
export async function discoverManifests(
  ctx: ScanContext,
  fs: RepoFileSystem,
): Promise<DiscoveryResult> {
  const warnings: string[] = [];
  const knownPaths = new Set<string>();
  const contents = new Map<string, string>();

  for (const f of ctx?.files ?? []) {
    if (typeof f?.path === 'string') knownPaths.add(normalizeRepoPath(f.path));
  }

  let listed: string[] = [];
  try {
    listed = await fs.list();
  } catch (err) {
    warnings.push(`リポジトリの走査に失敗しました: ${String(err)}`);
  }
  for (const p of listed) knownPaths.add(normalizeRepoPath(p));

  // ctx.files に含まれていても走査結果に無い場合があるため両者の和を候補にする
  const candidates: Array<{ path: string; type: ManifestType }> = [];
  for (const path of [...knownPaths].sort()) {
    const type = classifyManifest(path);
    if (type !== null) candidates.push({ path, type });
  }

  const manifests: LoadedManifest[] = [];
  for (const candidate of candidates) {
    if (manifests.length >= MAX_MANIFESTS) {
      warnings.push(
        `設定ファイルが多すぎるため ${MAX_MANIFESTS} 件で打ち切りました（未解析のファイルが残っています）`,
      );
      break;
    }
    let content: string | null = null;
    try {
      content = await fs.read(candidate.path);
    } catch (err) {
      warnings.push(`設定ファイルを読めませんでした: ${candidate.path} (${String(err)})`);
      continue;
    }
    if (content === null) {
      warnings.push(`設定ファイルを読めませんでした: ${candidate.path}`);
      continue;
    }
    contents.set(candidate.path, content);
    manifests.push({ path: candidate.path, type: candidate.type, content });
  }

  return { manifests, knownPaths, contents, warnings };
}
