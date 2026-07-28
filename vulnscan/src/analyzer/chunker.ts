/**
 * チャンク分割。
 *
 * 方針:
 *   - 行スライスではなく `ctx.symbols` の構文単位（関数/メソッド/クラス）で切る。
 *   - 大きすぎる構文単位は、まず内側のシンボル（クラス→メソッド）へ降り、
 *     それでも収まらなければオーバーラップ付きの行ウィンドウで分割する。
 *   - どのシンボルにも属さない行（import・モジュールスコープの定数など）は
 *     まとめて module チャンクにする。ハードコードされた秘密情報は
 *     ここに出ることが多いので落とさない。
 *   - シンボル情報が無いファイルはファイル全体を1チャンクとする（フォールバック）。
 */

import type { SymbolInfo } from '../types/context.js';
import {
  DEFAULT_CHUNK_LIMITS,
  type Chunk,
  type ChunkFileInput,
  type ChunkLimits,
  type LineRange,
} from './types.js';

/** 改行コードを問わず行配列に分解する */
export function splitLines(content: string): string[] {
  return content.split(/\r\n|\r|\n/);
}

/** 閉じ括弧だけの行などを「意味のある行」から除く */
const TRIVIAL_LINE = /^[)\]}>;,\s]*$/;

function isMeaningful(line: string): boolean {
  return !TRIVIAL_LINE.test(line);
}

function rangeLineCount(range: LineRange): number {
  return range.endLine - range.startLine + 1;
}

function rangeCharCount(range: LineRange, lines: string[]): number {
  let total = 0;
  for (let n = range.startLine; n <= range.endLine; n++) {
    total += (lines[n - 1] ?? '').length + 1;
  }
  return total;
}

function fits(range: LineRange, lines: string[], limits: ChunkLimits): boolean {
  return (
    rangeLineCount(range) <= limits.maxLines &&
    rangeCharCount(range, lines) <= limits.maxChars
  );
}

/**
 * 収まらない範囲をオーバーラップ付きの行ウィンドウに分割する。
 * 1行が上限を超える場合でも必ず前進するので停止する。
 */
export function splitRange(
  range: LineRange,
  lines: string[],
  limits: ChunkLimits,
): LineRange[] {
  const out: LineRange[] = [];
  let start = range.startLine;

  while (start <= range.endLine) {
    let end = start;
    let chars = 0;
    while (end <= range.endLine) {
      const len = (lines[end - 1] ?? '').length + 1;
      const wouldExceed =
        end > start &&
        (end - start + 1 > limits.maxLines || chars + len > limits.maxChars);
      if (wouldExceed) break;
      chars += len;
      end++;
    }
    const lastLine = Math.min(end - 1, range.endLine);
    out.push({ startLine: start, endLine: lastLine });
    if (lastLine >= range.endLine) break;
    start = Math.max(lastLine + 1 - limits.overlapLines, start + 1);
  }

  return out;
}

/** 行範囲の集合を正規化（ソート＋隣接/重複をマージ） */
export function mergeRanges(ranges: LineRange[]): LineRange[] {
  const sorted = [...ranges]
    .filter((r) => r.endLine >= r.startLine)
    .sort((a, b) => a.startLine - b.startLine || a.endLine - b.endLine);
  const out: LineRange[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r.startLine <= last.endLine + 1) {
      last.endLine = Math.max(last.endLine, r.endLine);
    } else {
      out.push({ ...r });
    }
  }
  return out;
}

/** covered の補集合（1..totalLines のうち覆われていない範囲） */
export function invertRanges(covered: LineRange[], totalLines: number): LineRange[] {
  const merged = mergeRanges(covered);
  const out: LineRange[] = [];
  let cursor = 1;
  for (const r of merged) {
    if (r.startLine > cursor) out.push({ startLine: cursor, endLine: r.startLine - 1 });
    cursor = Math.max(cursor, r.endLine + 1);
  }
  if (cursor <= totalLines) out.push({ startLine: cursor, endLine: totalLines });
  return out;
}

/** 対象ファイルのシンボルだけを取り出し、行番号を実ファイルの範囲に収める */
function normalizeSymbols(
  symbols: SymbolInfo[],
  file: string,
  totalLines: number,
): SymbolInfo[] {
  const seen = new Set<string>();
  const out: SymbolInfo[] = [];
  for (const s of symbols) {
    if (s.file !== file) continue;
    const startLine = Math.max(1, Math.min(s.startLine, totalLines));
    const endLine = Math.max(startLine, Math.min(s.endLine, totalLines));
    const key = `${s.name}:${s.kind}:${startLine}:${endLine}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...s, startLine, endLine });
  }
  return out.sort(
    (a, b) =>
      a.startLine - b.startLine ||
      b.endLine - a.endLine ||
      a.name.localeCompare(b.name),
  );
}

/** 他のシンボルに包含されていない最上位のシンボルだけを返す */
export function topLevelSymbols(symbols: SymbolInfo[]): SymbolInfo[] {
  const out: SymbolInfo[] = [];
  let coverEnd = 0;
  for (const s of symbols) {
    if (s.endLine <= coverEnd) continue; // 既存の最上位シンボルに包含されている
    out.push(s);
    coverEnd = Math.max(coverEnd, s.endLine);
  }
  return out;
}

/** parent の内側にある直接の子シンボル（孫は含まない） */
function directChildren(parent: SymbolInfo, symbols: SymbolInfo[]): SymbolInfo[] {
  const inside = symbols.filter(
    (s) =>
      s !== parent &&
      s.startLine >= parent.startLine &&
      s.endLine <= parent.endLine &&
      !(s.startLine === parent.startLine && s.endLine === parent.endLine),
  );
  return topLevelSymbols(inside);
}

/** チャンクに含まれるシンボル（範囲に少しでも重なるもの） */
function symbolsIn(segments: LineRange[], symbols: SymbolInfo[]): SymbolInfo[] {
  return symbols.filter((s) =>
    segments.some((seg) => s.startLine <= seg.endLine && s.endLine >= seg.startLine),
  );
}

/** 行番号付きのコードに整形する。非連続な範囲は省略マーカーで繋ぐ */
export function renderNumbered(lines: string[], segments: LineRange[]): string {
  const parts: string[] = [];
  let prevEnd: number | null = null;
  for (const seg of segments) {
    if (prevEnd !== null && seg.startLine > prevEnd + 1) {
      parts.push(`   …  （${seg.startLine - prevEnd - 1}行 省略）`);
    }
    for (let n = seg.startLine; n <= seg.endLine; n++) {
      parts.push(`${String(n).padStart(5, ' ')}| ${lines[n - 1] ?? ''}`);
    }
    prevEnd = seg.endLine;
  }
  return parts.join('\n');
}

function makeChunk(args: {
  input: ChunkFileInput;
  lines: string[];
  segments: LineRange[];
  kind: Chunk['kind'];
  label: string;
  symbols: SymbolInfo[];
  part?: { index: number; total: number };
}): Chunk {
  const { input, lines, segments, kind, label, symbols, part } = args;
  const first = segments[0];
  const last = segments[segments.length - 1];
  const startLine = first ? first.startLine : 1;
  const endLine = last ? last.endLine : 1;
  const suffix = part && part.total > 1 ? `~${part.index}` : '';
  const chunk: Chunk = {
    id: `${input.file.path}#${label}@${startLine}-${endLine}${suffix}`,
    file: input.file.path,
    language: input.file.language,
    fileHash: input.file.hash,
    kind,
    label,
    startLine,
    endLine,
    segments,
    code: renderNumbered(lines, segments),
    symbols,
  };
  if (part) chunk.part = part;
  return chunk;
}

/** シンボル1つをチャンク化する。大きすぎれば子シンボル→行ウィンドウの順に降りる */
function emitSymbolChunks(
  sym: SymbolInfo,
  all: SymbolInfo[],
  input: ChunkFileInput,
  lines: string[],
  limits: ChunkLimits,
  out: Chunk[],
): void {
  const range: LineRange = { startLine: sym.startLine, endLine: sym.endLine };
  const label = sym.container ? `${sym.container}.${sym.name}` : sym.name;

  if (fits(range, lines, limits)) {
    out.push({
      ...makeChunk({
        input,
        lines,
        segments: [range],
        kind: 'symbol',
        label,
        symbols: symbolsIn([range], all),
      }),
    });
    return;
  }

  // 大きすぎるクラス等は内側のメソッドへ降りる（親の残余は module チャンクが拾う）
  const children = directChildren(sym, all);
  if (children.length > 0) {
    for (const child of children) {
      emitSymbolChunks(child, all, input, lines, limits, out);
    }
    return;
  }

  // 子が無い巨大な関数は行ウィンドウで分割する
  const parts = splitRange(range, lines, limits);
  parts.forEach((seg, i) => {
    out.push(
      makeChunk({
        input,
        lines,
        segments: [seg],
        kind: 'symbol-part',
        label,
        symbols: symbolsIn([seg], all),
        part: { index: i + 1, total: parts.length },
      }),
    );
  });
}

/** 残余の行範囲を上限に収まるようまとめて module チャンクにする */
function packModuleChunks(
  gaps: LineRange[],
  input: ChunkFileInput,
  lines: string[],
  limits: ChunkLimits,
  all: SymbolInfo[],
): Chunk[] {
  const meaningful = gaps.filter((g) => {
    for (let n = g.startLine; n <= g.endLine; n++) {
      if (isMeaningful(lines[n - 1] ?? '')) return true;
    }
    return false;
  });
  if (meaningful.length === 0) return [];

  const groups: LineRange[][] = [];
  let current: LineRange[] = [];
  let currentLines = 0;
  let currentChars = 0;

  const flush = (): void => {
    if (current.length > 0) groups.push(current);
    current = [];
    currentLines = 0;
    currentChars = 0;
  };

  for (const gap of meaningful) {
    // 単体で上限を超える範囲は先に分割しておく
    const pieces = fits(gap, lines, limits) ? [gap] : splitRange(gap, lines, limits);
    for (const piece of pieces) {
      const l = rangeLineCount(piece);
      const c = rangeCharCount(piece, lines);
      if (
        current.length > 0 &&
        (currentLines + l > limits.maxLines || currentChars + c > limits.maxChars)
      ) {
        flush();
      }
      current.push(piece);
      currentLines += l;
      currentChars += c;
    }
  }
  flush();

  return groups.map((segments, i) =>
    makeChunk({
      input,
      lines,
      segments,
      kind: 'module',
      label: 'module',
      symbols: symbolsIn(segments, all),
      part: { index: i + 1, total: groups.length },
    }),
  );
}

/**
 * ファイル1つをチャンクへ分割する。
 * 内容が空、または空白のみの場合は空配列を返す。
 */
export function chunkFile(
  input: ChunkFileInput,
  limits: ChunkLimits = DEFAULT_CHUNK_LIMITS,
): Chunk[] {
  if (input.content.trim() === '') return [];

  const lines = splitLines(input.content);
  const totalLines = lines.length;
  const symbols = normalizeSymbols(input.symbols, input.file.path, totalLines);

  // フォールバック: シンボル情報が無いファイルは全体を1チャンクにする
  if (symbols.length === 0) {
    const whole: LineRange = { startLine: 1, endLine: totalLines };
    if (fits(whole, lines, limits)) {
      return [
        makeChunk({
          input,
          lines,
          segments: [whole],
          kind: 'file',
          label: 'file',
          symbols: [],
        }),
      ];
    }
    const parts = splitRange(whole, lines, limits);
    return parts.map((seg, i) =>
      makeChunk({
        input,
        lines,
        segments: [seg],
        kind: 'file-part',
        label: 'file',
        symbols: [],
        part: { index: i + 1, total: parts.length },
      }),
    );
  }

  const out: Chunk[] = [];
  for (const sym of topLevelSymbols(symbols)) {
    emitSymbolChunks(sym, symbols, input, lines, limits, out);
  }

  const covered = out.flatMap((c) => c.segments);
  const gaps = invertRanges(covered, totalLines);
  out.push(...packModuleChunks(gaps, input, lines, limits, symbols));

  return out.sort((a, b) => a.startLine - b.startLine || a.endLine - b.endLine);
}

/** ファイルパス → そのファイルのシンボル一覧 */
export function groupSymbolsByFile(symbols: SymbolInfo[]): Map<string, SymbolInfo[]> {
  const map = new Map<string, SymbolInfo[]>();
  for (const s of symbols) {
    const list = map.get(s.file);
    if (list) list.push(s);
    else map.set(s.file, [s]);
  }
  return map;
}
