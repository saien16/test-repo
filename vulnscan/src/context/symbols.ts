/**
 * シンボル（関数・メソッド・クラス）の抽出。
 *
 * tree-sitter のようなネイティブ依存は使わず、正規表現とブレース／インデントの
 * 追跡による軽量ヒューリスティックで定義範囲を求める。
 * 精度より頑健性を優先し、崩れたコードでも例外を投げずに何らかの結果を返す。
 *
 * 行番号は 1 始まり（レポート表示と揃えるため）。
 */

import type { SymbolInfo, SymbolTable } from '../types/context.js';
import type { MaskedSource } from './mask.js';

/** ファイル全体を表す疑似シンボルの名前 */
export const MODULE_SYMBOL_NAME = '<module>';

/** 解析対象ファイル（マスク済みソース付き） */
export interface AnalyzableSource {
  path: string;
  language: string;
  masked: MaskedSource;
}

/** `${file}:${name}` 形式のシンボルID */
export function symbolId(file: string, name: string): string {
  return `${file}:${name}`;
}

interface Candidate {
  name: string;
  kind: 'function' | 'class' | 'module';
  startLine: number;
  endLine: number;
  exported: boolean;
  /** 言語構文から直接判る所属（Go のレシーバなど） */
  container?: string;
}

/** ブロック開始の `{` を探す際にシグネチャ末尾以降から探すための開始位置 */
function signatureOffset(line: string): number {
  const close = line.lastIndexOf(')');
  return close >= 0 ? close : 0;
}

/**
 * 波括弧の対応を追ってブロックの終端行（0始まり）を返す。
 * 開き括弧が見つからない場合は開始行をそのまま返す。
 */
function findBraceBlockEnd(codeOnly: readonly string[], startIndex: number): number {
  const lookAhead = 3;
  let openLine = -1;
  let openCol = -1;

  for (let i = startIndex; i <= Math.min(codeOnly.length - 1, startIndex + lookAhead); i++) {
    const line = codeOnly[i] ?? '';
    const from = i === startIndex ? signatureOffset(line) : 0;
    const idx = line.indexOf('{', from);
    if (idx >= 0) {
      openLine = i;
      openCol = idx;
      break;
    }
  }
  if (openLine < 0) return startIndex;

  let depth = 0;
  for (let i = openLine; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    for (let c = i === openLine ? openCol : 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) return i;
      }
    }
  }
  return codeOnly.length - 1;
}

function indentWidth(line: string): number {
  let width = 0;
  for (const ch of line) {
    if (ch === ' ') width++;
    else if (ch === '\t') width += 4;
    else break;
  }
  return width;
}

/** インデントで区切られるブロックの終端行（0始まり）を返す */
function findIndentBlockEnd(lines: readonly string[], startIndex: number, indent: number): number {
  let end = startIndex;
  for (let i = startIndex + 1; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.trim() === '') continue;
    if (indentWidth(line) <= indent) break;
    end = i;
  }
  return end;
}

/** Ruby: 同じインデントの `end` を終端とみなす */
function findRubyBlockEnd(lines: readonly string[], startIndex: number, indent: number): number {
  for (let i = startIndex + 1; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.trim() !== 'end' && !/^\s*end\b/.test(line)) continue;
    if (indentWidth(line) === indent) return i;
  }
  return findIndentBlockEnd(lines, startIndex, indent);
}

/** 制御構文など、メソッド名と誤認しやすい予約語 */
const RESERVED = new Set([
  'if',
  'else',
  'for',
  'while',
  'switch',
  'catch',
  'do',
  'try',
  'finally',
  'return',
  'function',
  'class',
  'new',
  'typeof',
  'await',
  'yield',
  'with',
  'case',
  'default',
  'super',
  'this',
  'import',
  'export',
  'require',
  'in',
  'of',
  'and',
  'or',
  'not',
]);

const JS_FUNCTION = /^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/;
const JS_CLASS = /^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/;
const JS_ARROW =
  /^\s*(?:export\s+)?(?:declare\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*(?::[^=]*?)?=>|[A-Za-z_$][\w$]*\s*=>)/;
const JS_METHOD =
  /^\s*(?:(?:public|private|protected|static|readonly|abstract|override|async|get|set)\s+)*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\([^;{]*\)\s*(?::\s*[^{;]+)?\{\s*$/;
const JS_METHOD_MULTILINE =
  /^\s*(?:(?:public|private|protected|static|readonly|abstract|override|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(\s*$/;

const GO_FUNCTION = /^func\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(/;
const GO_METHOD = /^func\s+\(\s*\w+\s+[*]?([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*\(/;
const GO_TYPE = /^type\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b/;

const JAVA_CLASS =
  /^\s*(?:(?:public|private|protected|final|abstract|static|sealed)\s+)*(?:class|interface|enum|record)\s+([A-Za-z_]\w*)/;
const JAVA_METHOD =
  /^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)+[\w.<>[\],?\s]*?\s([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\{?\s*$/;

const PHP_CLASS = /^\s*(?:(?:abstract|final)\s+)*(?:class|interface|trait)\s+(\w+)/;
const PHP_FUNCTION = /^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)\s*\(/;

const PY_DEF = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)/;
const PY_CLASS = /^(\s*)class\s+([A-Za-z_]\w*)/;

const RB_DEF = /^(\s*)def\s+(?:self\.)?([A-Za-z_]\w*[?!=]?)/;
const RB_CLASS = /^(\s*)class\s+([A-Za-z_][\w:]*)/;
const RB_MODULE = /^(\s*)module\s+([A-Za-z_][\w:]*)/;

/** JavaScript / TypeScript 系 */
function extractJsLike(source: AnalyzableSource): Candidate[] {
  const { codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;
    const exported = /^\s*export\b/.test(line);

    const cls = JS_CLASS.exec(line);
    if (cls?.[1]) {
      out.push({
        name: cls[1],
        kind: 'class',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported,
      });
      continue;
    }

    const fn = JS_FUNCTION.exec(line) ?? JS_ARROW.exec(line);
    if (fn?.[1]) {
      out.push({
        name: fn[1],
        kind: 'function',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported,
      });
      continue;
    }

    const method = JS_METHOD.exec(line) ?? JS_METHOD_MULTILINE.exec(line);
    if (method?.[1] && !RESERVED.has(method[1])) {
      out.push({
        name: method[1],
        kind: 'function',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: false,
      });
    }
  }
  return out;
}

/** Go */
function extractGo(source: AnalyzableSource): Candidate[] {
  const { codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;

    const method = GO_METHOD.exec(line);
    if (method?.[1] && method[2]) {
      out.push({
        name: method[2],
        kind: 'function',
        container: method[1],
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        // Go は先頭大文字がエクスポート
        exported: /^[A-Z]/.test(method[2]),
      });
      continue;
    }

    const fn = GO_FUNCTION.exec(line);
    if (fn?.[1]) {
      out.push({
        name: fn[1],
        kind: 'function',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: /^[A-Z]/.test(fn[1]),
      });
      continue;
    }

    const type = GO_TYPE.exec(line);
    if (type?.[1]) {
      out.push({
        name: type[1],
        kind: 'class',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: /^[A-Z]/.test(type[1]),
      });
    }
  }
  return out;
}

/** Java */
function extractJava(source: AnalyzableSource): Candidate[] {
  const { codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;
    const isPublic = /\bpublic\b/.test(line);

    const cls = JAVA_CLASS.exec(line);
    if (cls?.[1]) {
      out.push({
        name: cls[1],
        kind: 'class',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: isPublic,
      });
      continue;
    }

    const method = JAVA_METHOD.exec(line);
    if (method?.[1] && !RESERVED.has(method[1])) {
      out.push({
        name: method[1],
        kind: 'function',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: isPublic,
      });
    }
  }
  return out;
}

/** PHP */
function extractPhp(source: AnalyzableSource): Candidate[] {
  const { codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;

    const cls = PHP_CLASS.exec(line);
    if (cls?.[1]) {
      out.push({
        name: cls[1],
        kind: 'class',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: true,
      });
      continue;
    }

    const fn = PHP_FUNCTION.exec(line);
    if (fn?.[1]) {
      out.push({
        name: fn[1],
        kind: 'function',
        startLine: i + 1,
        endLine: findBraceBlockEnd(codeOnly, i) + 1,
        exported: !/\b(?:private|protected)\b/.test(line),
      });
    }
  }
  return out;
}

/** Python（インデント追跡） */
function extractPython(source: AnalyzableSource): Candidate[] {
  const { lines, codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;

    const cls = PY_CLASS.exec(line);
    if (cls?.[2]) {
      const indent = indentWidth(cls[1] ?? '');
      out.push({
        name: cls[2],
        kind: 'class',
        startLine: i + 1,
        endLine: findIndentBlockEnd(lines, i, indent) + 1,
        exported: !cls[2].startsWith('_'),
      });
      continue;
    }

    const def = PY_DEF.exec(line);
    if (def?.[2]) {
      const indent = indentWidth(def[1] ?? '');
      out.push({
        name: def[2],
        kind: 'function',
        startLine: i + 1,
        endLine: findIndentBlockEnd(lines, i, indent) + 1,
        exported: !def[2].startsWith('_'),
      });
    }
  }
  return out;
}

/** Ruby（`end` 追跡） */
function extractRuby(source: AnalyzableSource): Candidate[] {
  const { codeOnly } = source.masked;
  const out: Candidate[] = [];

  for (let i = 0; i < codeOnly.length; i++) {
    const line = codeOnly[i] ?? '';
    if (line.trim() === '') continue;

    const mod = RB_MODULE.exec(line);
    if (mod?.[2]) {
      const indent = indentWidth(mod[1] ?? '');
      out.push({
        name: mod[2],
        kind: 'module',
        startLine: i + 1,
        endLine: findRubyBlockEnd(codeOnly, i, indent) + 1,
        exported: true,
      });
      continue;
    }

    const cls = RB_CLASS.exec(line);
    if (cls?.[2]) {
      const indent = indentWidth(cls[1] ?? '');
      out.push({
        name: cls[2],
        kind: 'class',
        startLine: i + 1,
        endLine: findRubyBlockEnd(codeOnly, i, indent) + 1,
        exported: true,
      });
      continue;
    }

    const def = RB_DEF.exec(line);
    if (def?.[2]) {
      const indent = indentWidth(def[1] ?? '');
      out.push({
        name: def[2],
        kind: 'function',
        startLine: i + 1,
        endLine: findRubyBlockEnd(codeOnly, i, indent) + 1,
        exported: !/^\s*private\b/.test(line),
      });
    }
  }
  return out;
}

function extractCandidates(source: AnalyzableSource): Candidate[] {
  switch (source.language) {
    case 'python':
      return extractPython(source);
    case 'go':
      return extractGo(source);
    case 'java':
      return extractJava(source);
    case 'ruby':
      return extractRuby(source);
    case 'php':
      return extractPhp(source);
    default:
      return extractJsLike(source);
  }
}

/**
 * 1ファイル分のシンボルを抽出する。
 * ファイル全体を表す `<module>` シンボルを必ず 1 つ含む。
 */
export function extractFileSymbols(source: AnalyzableSource): SymbolInfo[] {
  let candidates: Candidate[];
  try {
    candidates = extractCandidates(source);
  } catch {
    candidates = [];
  }

  const lineCount = Math.max(1, source.masked.lines.length);
  const symbols: SymbolInfo[] = [
    {
      name: MODULE_SYMBOL_NAME,
      kind: 'module',
      file: source.path,
      startLine: 1,
      endLine: lineCount,
      exported: false,
    },
  ];

  // 範囲が広い順（＝外側）に並べ、内側のシンボルの所属を決められるようにする
  const sorted = [...candidates].sort(
    (a, b) => a.startLine - b.startLine || b.endLine - a.endLine,
  );

  const containers: Candidate[] = [];
  for (const candidate of sorted) {
    if (candidate.endLine < candidate.startLine) candidate.endLine = candidate.startLine;

    // 自分を包含する直近のクラス／モジュールを探す
    let container = candidate.container;
    if (!container) {
      for (let i = containers.length - 1; i >= 0; i--) {
        const outer = containers[i];
        if (!outer) continue;
        if (outer.startLine < candidate.startLine && outer.endLine >= candidate.endLine) {
          container = outer.name;
          break;
        }
      }
    }

    const kind: SymbolInfo['kind'] =
      candidate.kind === 'function' && container ? 'method' : candidate.kind;

    symbols.push({
      name: candidate.name,
      kind,
      file: source.path,
      startLine: candidate.startLine,
      endLine: candidate.endLine,
      container,
      exported: candidate.exported,
    });

    if (candidate.kind === 'class' || candidate.kind === 'module') containers.push(candidate);
  }

  return symbols;
}

/** 全ファイルのシンボル表を構築する */
export function buildSymbolTable(sources: readonly AnalyzableSource[], warnings: string[]): SymbolTable {
  const symbols: SymbolInfo[] = [];

  for (const source of sources) {
    try {
      symbols.push(...extractFileSymbols(source));
    } catch (err) {
      warnings.push(`シンボル抽出に失敗しました: ${source.path} (${String(err)})`);
    }
  }

  const byId: Record<string, SymbolInfo> = {};
  for (const symbol of symbols) {
    const id = symbolId(symbol.file, symbol.name);
    // 同名が複数ある場合は範囲の広い方（＝外側の定義）を代表とする
    const existing = byId[id];
    if (!existing || existing.endLine - existing.startLine < symbol.endLine - symbol.startLine) {
      byId[id] = symbol;
    }
  }

  return { symbols, byId };
}

/**
 * 行番号から「その行を含む最も内側の関数／メソッド」のIDを引く索引。
 * 該当がなければファイルの `<module>` シンボルのIDを返す。
 */
export class SymbolLocator {
  private readonly byFile = new Map<string, SymbolInfo[]>();

  constructor(table: SymbolTable) {
    for (const symbol of table.symbols) {
      const list = this.byFile.get(symbol.file);
      if (list) list.push(symbol);
      else this.byFile.set(symbol.file, [symbol]);
    }
  }

  /** 指定行を含む最も内側のシンボルID */
  locate(file: string, line: number): string {
    const list = this.byFile.get(file);
    const fallback = symbolId(file, MODULE_SYMBOL_NAME);
    if (!list) return fallback;

    let best: SymbolInfo | undefined;
    for (const symbol of list) {
      if (symbol.kind === 'module') continue;
      if (symbol.startLine > line || symbol.endLine < line) continue;
      if (!best) {
        best = symbol;
        continue;
      }
      // より狭い範囲＝より内側
      const bestWidth = best.endLine - best.startLine;
      const width = symbol.endLine - symbol.startLine;
      if (width < bestWidth || (width === bestWidth && symbol.kind !== 'class')) best = symbol;
    }

    return best ? symbolId(best.file, best.name) : fallback;
  }
}
