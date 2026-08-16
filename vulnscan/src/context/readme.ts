/**
 * README の抽出。
 *
 * 「この走査対象は何なのか」をレポートの冒頭で示すために使う。
 *
 * ここで行うのは**引用だけ**で、要約も言い換えもしない。
 * README に書いてあることは事実（引用元と一緒に示せる）だが、
 * 「これは○○を目的としたシステムです」と言い切るのは推測であり、
 * 両者を混ぜないのが本ツールの方針だから（設計書 §4）。
 *
 * include の設定で走査対象から外れていても README は読む。
 * マニフェストと同じ扱いで、「何を見ているか」の説明に必要なため。
 */

import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { ReadmeInfo } from '../types/context.js';

export type { ReadmeInfo };

/** 探索順。先に見つかったものを採用する */
const CANDIDATES = [
  'README.md',
  'README.markdown',
  'README.rst',
  'README.txt',
  'README',
  'readme.md',
  'Readme.md',
  'docs/README.md',
];

/** 読み込む上限。README は説明文なので、これを超える分は見ない */
const MAX_BYTES = 64 * 1024;

/** 本文として採らない行 */
function isNoise(line: string): boolean {
  const t = line.trim();
  if (t === '') return true;
  // バッジだけの行（![...](...) の並び）
  if (/^(\[?!\[[^\]]*\]\([^)]*\)\]?\(?[^)]*\)?\s*)+$/.test(t)) return true;
  // 生HTML（<p align="center"> など README 冒頭によくある）
  if (/^<\/?[a-z]/i.test(t)) return true;
  // 見出し・引用・水平線・箇条書き・表
  if (/^(#{1,6}\s|>|-{3,}|={3,}|\*{3,}|[-*+]\s|\d+\.\s|\|)/.test(t)) return true;
  // コードフェンス
  if (/^(```|~~~)/.test(t)) return true;
  return false;
}

/** Markdown の装飾を落として1行の平文にする */
export function flatten(text: string): string {
  return text
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '') // 画像
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1') // リンクはテキストだけ残す
    .replace(/`([^`]*)`/g, '$1')
    .replace(/[*_]{1,3}([^*_]+)[*_]{1,3}/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

/** 長すぎる引用は切る。切ったことが分かるように … を付ける */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max).trimEnd()}…`;
}

/**
 * README の本文から見出しと導入段落を取り出す。
 * ファイル入出力を伴わないので、単体で試験できる。
 */
export function parseReadme(content: string, path: string): ReadmeInfo {
  const lines = content.split(/\r?\n/);

  let title = '';
  let titleIndex = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const atx = /^#\s+(.*\S)\s*$/.exec(line);
    if (atx?.[1] !== undefined) {
      title = flatten(atx[1]);
      titleIndex = i;
      break;
    }
    // setext 見出し（次の行が === の形）
    const next = lines[i + 1] ?? '';
    if (line.trim() !== '' && /^={3,}\s*$/.test(next) && !isNoise(line)) {
      title = flatten(line);
      titleIndex = i + 1;
      break;
    }
  }

  // 見出しが無ければ先頭から本文を探す
  let lead = '';
  const buffer: string[] = [];
  let inFence = false;
  for (let i = titleIndex + 1; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^(```|~~~)/.test(line.trim())) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    if (isNoise(line)) {
      if (buffer.length > 0) break; // 段落が終わった
      continue;
    }
    buffer.push(line.trim());
    // 段落は3行までで足りる。それ以上は導入ではなく本文
    if (buffer.length >= 3) break;
  }
  if (buffer.length > 0) lead = truncate(flatten(buffer.join(' ')), 300);

  return { path, title: truncate(title, 120), lead };
}

/**
 * リポジトリルートから README を探して読む。
 * 見つからない・読めない場合は null（欠落は正常な状態として扱う）。
 */
export function readReadme(repoRoot: string): ReadmeInfo | null {
  for (const candidate of CANDIDATES) {
    const full = join(repoRoot, candidate);
    try {
      const stat = statSync(full);
      if (!stat.isFile() || stat.size === 0) continue;
      const raw = readFileSync(full, 'utf8');
      const info = parseReadme(raw.slice(0, MAX_BYTES), candidate);
      // 見出しも本文も取れないなら、示す価値が無いので次を試す
      if (info.title === '' && info.lead === '') continue;
      return info;
    } catch {
      continue;
    }
  }
  return null;
}
