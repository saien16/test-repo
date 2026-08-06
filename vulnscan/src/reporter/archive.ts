/**
 * HTML控えの保存。
 *
 * 走査のたびに、出力形式やリダイレクト先に関係なく HTML を1つ必ず残す。
 * 目的は2つ:
 *   - 「レポートをどこへ出したか分からない」を無くす（保存先を必ず1行で告げる）
 *   - 上書きされずに前回と比べられるようにする（ファイル名に日時を入れる）
 *
 * 併せて `latest.html` を同じ内容で置く。URLを固定できるので、
 * `http://localhost:8000/reports/latest.html` を開きっぱなしにして
 * 再読み込みするだけで最新が見られる。
 */

import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

/** 常に最新の控えを指すファイル名 */
export const LATEST_FILENAME = 'latest.html';

/** 'YYYYMMDD-HHMMSS'（ローカル時刻）。ファイル名に使うのでUTCではなく手元の時刻に合わせる */
export function timestampSlug(when: Date): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return (
    `${when.getFullYear()}${p(when.getMonth() + 1)}${p(when.getDate())}-` +
    `${p(when.getHours())}${p(when.getMinutes())}${p(when.getSeconds())}`
  );
}

/**
 * 走査対象のディレクトリ名を、ファイル名に使える形へ落とす。
 * 空になる場合（ルート直下など）は 'scan' を使う。
 */
export function slugifyTarget(repoRoot: string): string {
  const base = basename(repoRoot)
    .replace(/[^\p{L}\p{N}._-]+/gu, '-')
    .replace(/^[-.]+|-+$/g, '');
  return base === '' ? 'scan' : base.slice(0, 40);
}

/** 例: 'grimoire-BenchmarkJava-20260806-002500.html' */
export function archiveFileName(repoRoot: string, when: Date): string {
  return `grimoire-${slugifyTarget(repoRoot)}-${timestampSlug(when)}.html`;
}

export interface ArchiveResult {
  /** タイムスタンプ付きの控え */
  path: string;
  /** 常に最新を指すコピー */
  latestPath: string;
}

/**
 * 控えを書き出す。ディレクトリは無ければ作る。
 *
 * `latest.html` はシンボリックリンクではなくコピーにしてある。
 * リンクだと、成果物をzipで固めたり共有ストレージへ置いたときに壊れるため。
 */
export async function writeArchive(
  html: string,
  dir: string,
  repoRoot: string,
  when: Date,
): Promise<ArchiveResult> {
  await mkdir(dir, { recursive: true });
  const path = join(dir, archiveFileName(repoRoot, when));
  await writeFile(path, html, 'utf8');
  const latestPath = join(dir, LATEST_FILENAME);
  await copyFile(path, latestPath);
  return { path, latestPath };
}
