/**
 * ベースライン（前回スキャン結果）の読み書きと差分判定。
 *
 * 指紋(fingerprint)で照合し、
 *   - ベースラインに無い        → new
 *   - ベースラインにも今回もある → persistent（firstSeen と triage 状態を引き継ぐ）
 *   - ベースラインにあり今回無い → fixed
 * を設定する。
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { Finding, TriageStatus } from '../types/finding.js';

/** ベースラインファイルのスキーマ */
export interface BaselineFile {
  /** スキーマバージョン */
  version: number;
  /** 書き出した時刻 (ISO8601) */
  generatedAt: string;
  /** 前回スキャン時点の Finding 一覧 */
  findings: Finding[];
}

export const BASELINE_SCHEMA_VERSION = 1;

/** ベースラインが存在しない場合の空データ */
export function emptyBaseline(): BaselineFile {
  return { version: BASELINE_SCHEMA_VERSION, generatedAt: '', findings: [] };
}

/** repoRoot を基準に相対パスを解決する */
export function resolvePath(path: string, repoRoot: string): string {
  return isAbsolute(path) ? path : resolve(repoRoot || process.cwd(), path);
}

export interface LoadBaselineResult {
  baseline: BaselineFile;
  /** ファイルが存在したか（存在しないのは初回スキャンなのでエラーではない） */
  existed: boolean;
  errors: string[];
}

/**
 * ベースラインJSONを読み込む。
 * 未存在は正常系（初回スキャン）。壊れている場合は errors に積んで空として扱う。
 */
export async function loadBaseline(path: string, repoRoot: string): Promise<LoadBaselineResult> {
  const full = resolvePath(path, repoRoot);
  let text: string;
  try {
    text = await readFile(full, 'utf8');
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      return { baseline: emptyBaseline(), existed: false, errors: [] };
    }
    return {
      baseline: emptyBaseline(),
      existed: false,
      errors: [`ベースラインの読み込みに失敗しました (${full}): ${describe(e)}`],
    };
  }

  try {
    const parsed: unknown = JSON.parse(text);
    const findings = extractFindings(parsed);
    return {
      baseline: {
        version:
          typeof (parsed as BaselineFile)?.version === 'number'
            ? (parsed as BaselineFile).version
            : BASELINE_SCHEMA_VERSION,
        generatedAt:
          typeof (parsed as BaselineFile)?.generatedAt === 'string'
            ? (parsed as BaselineFile).generatedAt
            : '',
        findings,
      },
      existed: true,
      errors: [],
    };
  } catch (e) {
    return {
      baseline: emptyBaseline(),
      existed: false,
      errors: [`ベースラインJSONの解析に失敗しました (${full}): ${describe(e)}`],
    };
  }
}

/** `{findings:[...]}` / `{entries:[...]}` / 素の配列、いずれの形でも受け付ける */
function extractFindings(parsed: unknown): Finding[] {
  if (Array.isArray(parsed)) return parsed.filter(isFindingLike);
  if (parsed && typeof parsed === 'object') {
    const obj = parsed as Record<string, unknown>;
    for (const key of ['findings', 'entries']) {
      const value = obj[key];
      if (Array.isArray(value)) return value.filter(isFindingLike);
    }
  }
  return [];
}

function isFindingLike(value: unknown): value is Finding {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as Finding).fingerprint === 'string' &&
    (value as Finding).fingerprint !== ''
  );
}

export interface BaselineDiffResult {
  /** 今回検出された Finding（diffStatus / firstSeen / status が確定済み） */
  findings: Finding[];
  /** 前回あって今回消えた Finding（diffStatus='fixed'） */
  fixed: Finding[];
}

/**
 * ベースラインと突き合わせて diffStatus・firstSeen・status を確定する。
 *
 * - firstSeen は前回値を引き継ぐ（いつから存在する問題かを保持するため）
 * - トリアージ済みの状態（false-positive / accepted / confirmed）も引き継ぐ
 */
export function applyBaseline(
  current: Finding[],
  baseline: BaselineFile,
  now: string,
): BaselineDiffResult {
  const previous = new Map<string, Finding>();
  for (const f of baseline.findings ?? []) {
    previous.set(f.fingerprint, f);
  }

  const seen = new Set<string>();
  const findings = current.map((f) => {
    seen.add(f.fingerprint);
    const old = previous.get(f.fingerprint);
    if (!old) {
      return { ...f, diffStatus: 'new' as const, firstSeen: f.firstSeen || now, lastSeen: now };
    }
    return {
      ...f,
      diffStatus: 'persistent' as const,
      firstSeen: old.firstSeen || f.firstSeen || now,
      lastSeen: now,
      status: inheritStatus(old.status),
    };
  });

  // 前回あって今回検出されなかったもの = 修正済み
  const fixed: Finding[] = [];
  for (const [fingerprint, old] of previous) {
    if (seen.has(fingerprint)) continue;
    if (old.diffStatus === 'fixed') continue; // 既に修正済みとして記録されたものは繰り返さない
    fixed.push({ ...old, diffStatus: 'fixed', status: 'fixed', lastSeen: old.lastSeen || now });
  }

  return { findings, fixed };
}

/** トリアージ状態の引き継ぎ。'fixed' だったものが再発したら 'open' に戻す */
function inheritStatus(status: TriageStatus | undefined): TriageStatus {
  if (!status || status === 'fixed') return 'open';
  return status;
}

/**
 * 新しいベースラインを書き出す。
 * 修正済み(diffStatus='fixed')の Finding は次回以降不要なので保存しない。
 */
export async function saveBaseline(
  findings: Finding[],
  path: string,
  repoRoot = process.cwd(),
): Promise<string> {
  const full = resolvePath(path, repoRoot);
  const payload: BaselineFile = {
    version: BASELINE_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    findings: findings.filter((f) => f.diffStatus !== 'fixed' && f.status !== 'fixed'),
  };
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return full;
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
