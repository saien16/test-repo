#!/usr/bin/env node
/**
 * ビルド後のデータファイル同梱スクリプト。
 *
 * `tsc` は .ts と .json の import を解決するだけで、`readFileSync` で読む
 * データファイルを dist へコピーしない。そのため dist だけを配布すると
 * `src/vuln/data/cwe-catalog.json`（CWE 959件）が見つからず、
 * カタログが空へ縮退したまま（例外にはならないので気づきにくい）動いてしまう。
 *
 * ここで `src/**\/data/` 配下を dist の同じ相対位置へコピーして、
 * dist 単体でカタログが読めるようにする。
 *
 * 実装方針:
 *   - npm 依存を増やさない（Node 標準の fs のみ）
 *   - `cp -r` のようなシェル依存を使わない（Windows で壊れるため）
 */

import { cp, mkdir, readdir, stat } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC_DIR = join(PACKAGE_ROOT, 'src');
const DIST_DIR = join(PACKAGE_ROOT, 'dist');

/** コピー対象とするディレクトリ名 */
const DATA_DIR_NAME = 'data';

/** `src` 配下を再帰的に走査して `data` ディレクトリを集める */
async function findDataDirs(dir) {
  const found = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return found;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const full = join(dir, entry.name);
    if (entry.name === DATA_DIR_NAME) {
      found.push(full);
      continue; // data の中はまるごとコピーするので降りない
    }
    found.push(...(await findDataDirs(full)));
  }
  return found;
}

async function main() {
  try {
    await stat(DIST_DIR);
  } catch {
    // tsc が走っていない＝コピー先が無い。ビルド順序の誤りなので明確に落とす。
    console.error(
      'エラー: dist ディレクトリがありません。先に `tsc -p tsconfig.json` を実行してください。',
    );
    process.exit(1);
  }

  const dataDirs = await findDataDirs(SRC_DIR);
  if (dataDirs.length === 0) {
    console.error('警告: src 配下にコピー対象の data ディレクトリが見つかりませんでした。');
    return;
  }

  for (const from of dataDirs) {
    const to = join(DIST_DIR, relative(SRC_DIR, from));
    await mkdir(dirname(to), { recursive: true });
    await cp(from, to, { recursive: true });
    console.log(`同梱: ${relative(PACKAGE_ROOT, from)} -> ${relative(PACKAGE_ROOT, to)}`);
  }
}

main().catch((err) => {
  console.error(`エラー: データファイルの同梱に失敗しました: ${err?.message ?? String(err)}`);
  process.exit(1);
});
