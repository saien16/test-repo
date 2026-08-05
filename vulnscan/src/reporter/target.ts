/**
 * 「何を走査したのか」の要約。
 *
 * レポートを後から読む人（あるいは数週間後の自分）が最初に確かめたいのは
 * 検出内容ではなく、**それがどこを見た結果なのか**である。
 * 対象・日時・範囲が書いていないレポートは、検出0件でも100件でも解釈できない。
 *
 * ここは純粋な集計だけを行い、LLM は呼ばない。
 * README の文言は引用として持ち回り、要約や言い換えはしない（設計方針 §4）。
 */

import type { ScanContext } from '../types/context.js';
import type { ArchitectureModel } from '../types/architecture.js';

/** ファイル一覧をそのまま出すか、階層の集計に切り替えるかの境目 */
export const FILE_LIST_THRESHOLD = 10;

/** 上位ディレクトリ1つぶんの集計 */
export interface TargetDirectory {
  /** リポジトリルートからの相対パス。ルート直下のファイルは '.' */
  path: string;
  fileCount: number;
  lines: number;
  bytes: number;
  /** 2階層目の内訳。多い順 */
  children: Array<{ path: string; fileCount: number; lines: number; bytes: number }>;
}

export interface TargetSummary {
  root: string;
  scannedAt: string;
  durationMs: number;
  fileCount: number;
  /** 走査したコード行数の合計 */
  linesScanned: number;
  totalBytes: number;
  git: ScanContext['git'];
  languages: Array<{ name: string; ratio: number }>;
  frameworks: string[];
  readme: ScanContext['readme'];
  /** 様式の推測（アーキテクチャ推定が動いていれば）。事実ではない */
  style: { value: string; confidence: number | null } | null;
  /** ファイル数が閾値以下のときだけ埋まる */
  files: string[] | null;
  /** ファイル数が閾値を超えるときだけ埋まる */
  directories: TargetDirectory[] | null;
  /** 表示を打ち切った2階層目の数 */
  truncatedChildren: number;
  /** 表示を打ち切った上位ディレクトリの数 */
  truncatedDirectories: number;
}

/** 表示する上位ディレクトリ数と、その配下の2階層目の数 */
const MAX_DIRECTORIES = 12;
const MAX_CHILDREN = 6;

/** 'src/analyzer/lenses/x.ts' → ['src', 'src/analyzer'] */
function segmentsOf(path: string): { top: string; second: string | null } {
  const parts = path.split('/').filter((p) => p !== '');
  if (parts.length <= 1) return { top: '.', second: null };
  const top = parts[0] as string;
  if (parts.length === 2) return { top, second: null };
  return { top, second: `${top}/${parts[1] as string}` };
}

const ARCHITECTURE_STYLE_LABEL: Record<string, string> = {
  monolith: 'モノリス',
  microservices: 'マイクロサービス',
  serverless: 'サーバレス',
  'spa-with-api': 'SPA + API',
  'static-site': '静的サイト',
  'cli-tool': 'CLIツール',
  library: 'ライブラリ',
  'batch-job': 'バッチ処理',
  unknown: '不明',
};

export function styleLabel(value: string): string {
  return ARCHITECTURE_STYLE_LABEL[value] ?? value;
}

/**
 * 走査対象の要約を組み立てる。
 *
 * @param durationMs 走査全体の所要時間（summary.durationMs をそのまま渡す）
 */
export function buildTargetSummary(
  context: ScanContext,
  durationMs: number,
  architecture?: ArchitectureModel,
): TargetSummary {
  const files = context.files ?? [];
  const totalBytes = files.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);
  const linesScanned = files.reduce((sum, f) => sum + (f.lines ?? 0), 0);

  let filesList: string[] | null = null;
  let directories: TargetDirectory[] | null = null;
  let truncatedChildren = 0;
  let truncatedDirectories = 0;

  if (files.length <= FILE_LIST_THRESHOLD) {
    // 少数なら数え上げより実物を見せたほうが早い
    filesList = files.map((f) => f.path).sort((a, b) => a.localeCompare(b));
  } else {
    const tops = new Map<string, TargetDirectory>();
    const seconds = new Map<string, { path: string; fileCount: number; lines: number; bytes: number }>();

    for (const f of files) {
      const { top, second } = segmentsOf(f.path);
      const bytes = f.sizeBytes ?? 0;
      const lines = f.lines ?? 0;
      const entry = tops.get(top) ?? { path: top, fileCount: 0, lines: 0, bytes: 0, children: [] };
      entry.fileCount++;
      entry.bytes += bytes;
      entry.lines += lines;
      tops.set(top, entry);

      if (second !== null) {
        const child = seconds.get(second) ?? { path: second, fileCount: 0, lines: 0, bytes: 0 };
        child.fileCount++;
        child.bytes += bytes;
        child.lines += lines;
        seconds.set(second, child);
      }
    }

    for (const child of seconds.values()) {
      const top = child.path.split('/')[0] as string;
      tops.get(top)?.children.push(child);
    }

    const sortByCount = <T extends { fileCount: number; path: string }>(a: T, b: T): number =>
      b.fileCount - a.fileCount || a.path.localeCompare(b.path);

    directories = [...tops.values()].sort(sortByCount);
    for (const dir of directories) {
      dir.children.sort(sortByCount);
      if (dir.children.length > MAX_CHILDREN) {
        truncatedChildren += dir.children.length - MAX_CHILDREN;
        dir.children = dir.children.slice(0, MAX_CHILDREN);
      }
    }
    if (directories.length > MAX_DIRECTORIES) {
      // 打ち切った数は必ず残す。黙って消すと「これで全部」と読まれる
      truncatedDirectories = directories.length - MAX_DIRECTORIES;
      directories = directories.slice(0, MAX_DIRECTORIES);
    }
  }

  const styleClaim = architecture?.style;
  const style =
    styleClaim === undefined
      ? null
      : {
          value: styleLabel(String(styleClaim.value)),
          confidence:
            styleClaim.provenance.kind === 'inferred' ? styleClaim.provenance.confidence : null,
        };

  return {
    root: context.repoRoot,
    scannedAt: context.scannedAt,
    durationMs,
    fileCount: files.length,
    linesScanned,
    totalBytes,
    git: context.git,
    languages: (context.languages ?? []).slice(0, 4).map((l) => ({ name: l.name, ratio: l.ratio })),
    frameworks: (context.frameworks ?? []).map((f) => f.name).filter((n) => n !== ''),
    readme: context.readme ?? null,
    style,
    files: filesList,
    directories,
    truncatedChildren,
    truncatedDirectories,
  };
}

/** ISO 8601 → 'YYYY-MM-DD HH:MM:SS'（ローカル時刻） */
export function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/** ミリ秒 → '2分13秒' / '820ミリ秒' */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '不明';
  if (ms < 1000) return `${Math.round(ms)}ミリ秒`;
  const total = Math.round(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}時間${m}分${s}秒`;
  if (m > 0) return `${m}分${s}秒`;
  return `${s}秒`;
}

/** バイト数 → '4.2 MB' */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '不明';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}
