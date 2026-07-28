/**
 * リポジトリのファイル走査。
 *
 * exclude / include の glob と `.gitignore` を尊重し、バイナリと
 * サイズ超過ファイルを除いたテキストファイルを内容付きで返す。
 * 各ファイルの sha256 は後段のキャッシュキーになるため必須。
 */

import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import type { SourceFile } from '../types/context.js';
import type { VulnScanConfig } from '../types/config.js';
import { matchAnyGlob, matchAnyGlobDirectory, normalizePath } from './glob.js';
import { IgnoreMatcher } from './ignore.js';
import { detectLanguage } from './language.js';

/** 内容を伴う走査済みファイル */
export interface ScannedFile {
  file: SourceFile;
  content: string;
}

/** 依存関係・フレームワーク検出に使うマニフェスト */
export interface ManifestFile {
  path: string;
  content: string;
}

export interface WalkOutput {
  files: ScannedFile[];
  manifests: ManifestFile[];
  /** include フィルタ適用前に観測した全ファイルパス（マーカー検出用） */
  allPaths: string[];
}

/** 走査そのものを常に打ち切る対象（コストが大きく解析価値がない） */
const ALWAYS_SKIP_DIRS = new Set([
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
  '.gradle',
  '.idea',
  '.vscode',
]);

/** 依存解析の対象になるマニフェストのファイル名 */
const MANIFEST_NAMES = new Set([
  'package.json',
  'pyproject.toml',
  'go.mod',
  'pom.xml',
  'gemfile',
  'composer.json',
  'cargo.toml',
  'pipfile',
  'build.gradle',
  'build.gradle.kts',
]);

/** マニフェストとして扱う可変ファイル名の判定 */
function isManifest(baseName: string): boolean {
  const lower = baseName.toLowerCase();
  if (MANIFEST_NAMES.has(lower)) return true;
  // requirements.txt / requirements-dev.txt / requirements/base.txt など
  return /^requirements[\w.-]*\.txt$/.test(lower);
}

/** 走査上限。異常に巨大なリポジトリで暴走しないためのガード */
const MAX_FILES = 20_000;
const MAX_DEPTH = 32;
/** マニフェストは include の対象外でも読むが、サイズは制限する */
const MAX_MANIFEST_BYTES = 2_000_000;

/**
 * バイナリ判定。NUL バイト、または制御文字の比率で判断する。
 */
export function looksBinary(buffer: Buffer): boolean {
  const len = Math.min(buffer.length, 8192);
  if (len === 0) return false;
  let suspicious = 0;
  for (let i = 0; i < len; i++) {
    const byte = buffer[i] as number;
    if (byte === 0) return true;
    // タブ・改行・復帰・改ページ以外の制御文字
    if (byte < 9 || (byte > 13 && byte < 32)) suspicious++;
  }
  return suspicious / len > 0.3;
}

/** 内容の sha256（16進） */
export function hashContent(buffer: Buffer | string): string {
  return createHash('sha256').update(buffer).digest('hex');
}

/**
 * リポジトリを走査する。I/O 失敗は warnings に積み、例外は投げない。
 */
export async function walkRepository(
  repoRoot: string,
  config: VulnScanConfig,
  warnings: string[],
): Promise<WalkOutput> {
  const exclude = config.scan?.exclude ?? [];
  const include = config.scan?.include ?? [];
  const maxFileBytes =
    typeof config.scan?.maxFileBytes === 'number' && config.scan.maxFileBytes > 0
      ? config.scan.maxFileBytes
      : 512_000;

  const ignore = new IgnoreMatcher();
  const files: ScannedFile[] = [];
  const manifests: ManifestFile[] = [];
  const allPaths: string[] = [];

  let skippedLarge = 0;
  let skippedBinary = 0;
  let readErrors = 0;
  let truncated = false;
  const largeExamples: string[] = [];

  const toRel = (absPath: string): string => normalizePath(relative(repoRoot, absPath).split(sep).join('/'));

  async function visit(dirAbs: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH || truncated) return;

    let entries;
    try {
      entries = await readdir(dirAbs, { withFileTypes: true });
    } catch (err) {
      warnings.push(`ディレクトリを読めませんでした: ${toRel(dirAbs) || '.'} (${String(err)})`);
      return;
    }

    // 先に同ディレクトリの .gitignore を取り込む（子より優先順位が低くなる）
    if (entries.some((e) => e.isFile() && e.name === '.gitignore')) {
      try {
        const content = await readFile(join(dirAbs, '.gitignore'), 'utf8');
        ignore.add(content, toRel(dirAbs));
      } catch {
        // .gitignore が読めなくても走査は続行する
      }
    }

    const dirs: string[] = [];

    for (const entry of entries) {
      if (truncated) return;
      const abs = join(dirAbs, entry.name);
      const rel = toRel(abs);
      if (rel === '') continue;

      // シンボリックリンクは循環と外部参照を避けるため辿らない
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
        if (matchAnyGlobDirectory(exclude, rel)) continue;
        if (ignore.ignores(rel, true)) continue;
        dirs.push(abs);
        continue;
      }

      if (!entry.isFile()) continue;

      allPaths.push(rel);

      const manifest = isManifest(entry.name);
      const excluded = matchAnyGlob(exclude, rel) || ignore.ignores(rel, false);
      const included = include.length === 0 || matchAnyGlob(include, rel);

      // マニフェストは include で絞られていても依存解析のために読む
      if (excluded || (!included && !manifest)) continue;

      let size: number;
      try {
        size = (await stat(abs)).size;
      } catch (err) {
        readErrors++;
        if (readErrors <= 10) warnings.push(`stat に失敗しました: ${rel} (${String(err)})`);
        continue;
      }

      const limit = manifest && !included ? MAX_MANIFEST_BYTES : maxFileBytes;
      if (size > limit) {
        skippedLarge++;
        if (largeExamples.length < 5) largeExamples.push(rel);
        continue;
      }

      let buffer: Buffer;
      try {
        buffer = await readFile(abs);
      } catch (err) {
        readErrors++;
        if (readErrors <= 10) warnings.push(`ファイルを読めませんでした: ${rel} (${String(err)})`);
        continue;
      }

      if (looksBinary(buffer)) {
        skippedBinary++;
        continue;
      }

      const content = buffer.toString('utf8');
      if (manifest) manifests.push({ path: rel, content });

      if (!included) continue;

      files.push({
        file: {
          path: rel,
          language: detectLanguage(rel),
          sizeBytes: size,
          hash: hashContent(buffer),
        },
        content,
      });

      if (files.length >= MAX_FILES) {
        truncated = true;
        warnings.push(`ファイル数が上限 ${MAX_FILES} に達したため走査を打ち切りました`);
        return;
      }
    }

    for (const dir of dirs) {
      await visit(dir, depth + 1);
    }
  }

  await visit(repoRoot, 0);

  if (skippedLarge > 0) {
    const examples = largeExamples.length > 0 ? `（例: ${largeExamples.join(', ')}）` : '';
    warnings.push(`サイズ上限 ${maxFileBytes} バイトを超えるファイルを ${skippedLarge} 件スキップしました${examples}`);
  }
  if (skippedBinary > 0) {
    warnings.push(`バイナリと判定したファイルを ${skippedBinary} 件スキップしました`);
  }
  if (readErrors > 10) {
    warnings.push(`読み取りエラーが合計 ${readErrors} 件発生しました`);
  }

  files.sort((a, b) => a.file.path.localeCompare(b.file.path));
  manifests.sort((a, b) => a.path.localeCompare(b.path));
  allPaths.sort();

  return { files, manifests, allPaths };
}
