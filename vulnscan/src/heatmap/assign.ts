/**
 * Finding を「構成要素 × カテゴリ」の格子に割り当てる。
 *
 * 割り当てに失敗した Finding は捨てず、専用の疑似構成要素へまとめる。
 * ヒートマップの目的は死角の可視化であり、
 * 「どこにも置けなかったから消えた」Finding が一番危ない。
 */

// パス正規化は util/path.ts に統合済み。glob.ts 版は先頭 '/' を1つしか剥がさず、
// '//src/a.ts' のような入力で構成要素への前方一致が外れていた。
import { normalizeRelPath as normalizePath } from '../util/path.js';
import type { ArchitectureComponent, ArchitectureModel } from '../types/architecture.js';
import type { ScanContext } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import { cweCategoryId } from './catalog-adapter.js';

/** セルを引くためのキー。Finding の振り分けとセル生成で必ず同じ関数を使う */
export function cellKey(componentId: string, categoryId: string): string {
  return `${componentId} ${categoryId}`;
}

/** 未割当 Finding を受け止める疑似構成要素のID */
export const UNASSIGNED_COMPONENT_ID = '__unassigned__';

/** 未割当 Finding 用の疑似構成要素を作る（実在の構成要素ではない） */
export function makeUnassignedComponent(): ArchitectureComponent {
  return {
    id: UNASSIGNED_COMPONENT_ID,
    kind: 'unknown',
    name: '未割当（どの構成要素にも対応づかなかったFinding）',
    technology: {
      value: 'unknown',
      provenance: { kind: 'assumed', reasoning: '疑似構成要素のため技術スタックを持たない' },
    },
    exposure: {
      value: 'unknown',
      provenance: { kind: 'assumed', reasoning: '疑似構成要素のため露出度を持たない' },
    },
    dataSensitivity: {
      value: ['unknown'],
      provenance: { kind: 'assumed', reasoning: '疑似構成要素のためデータ機微度を持たない' },
    },
    requiresAuthentication: {
      value: false,
      provenance: { kind: 'assumed', reasoning: '疑似構成要素のため認証要否を持たない' },
    },
    sourcePaths: [],
    entryPointIds: [],
  };
}

/**
 * パスが基準パス配下か判定する（前方一致。ただしパス境界を尊重する）。
 * 'src/api' は 'src/api/x.ts' にマッチするが 'src/apiary.ts' にはマッチしない。
 */
export function isUnderPath(filePath: string, basePath: string): boolean {
  const file = normalizePath(filePath);
  const base = normalizePath(basePath);
  // 空文字・'.' はリポジトリルート指定とみなし、全ファイルにマッチする
  if (base === '' || base === '.') return true;
  return file === base || file.startsWith(`${base}/`);
}

/** Finding が触れているファイル一覧（検出位置＋データフロー上の各ステップ） */
export function findingFiles(finding: Finding): string[] {
  const files = [normalizePath(finding.location.file)];
  for (const step of finding.dataFlow) {
    const p = normalizePath(step.file);
    if (!files.includes(p)) files.push(p);
  }
  return files;
}

/** 構成要素への割り当て結果 */
export interface ComponentAssignment {
  componentId: string;
  /** どうやって対応づけたか */
  how: 'source-path' | 'entry-point' | 'unassigned';
  /** source-path の場合、一致した sourcePath（最長一致） */
  matchedPath?: string;
}

/** エントリポイント識別子 → そのエントリポイントが存在するファイル群 */
function entryPointFileIndex(ctx: ScanContext): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const ep of ctx.entryPoints) {
    const set = index.get(ep.identifier) ?? new Set<string>();
    set.add(normalizePath(ep.file));
    index.set(ep.identifier, set);
  }
  return index;
}

/**
 * Finding を構成要素へ割り当てる。
 *
 * 優先順位:
 *   1. `finding.location.file` が `component.sourcePaths` のいずれかに前方一致（最長一致を採用）
 *   2. `component.entryPointIds` に対応するエントリポイントのファイルと一致
 *   3. どちらも駄目なら未割当
 *
 * 同点の場合は `architecture.components` の並び順で先に来たものを採る（決定的）。
 */
export function assignFindingsToComponents(
  architecture: ArchitectureModel,
  findings: readonly Finding[],
  ctx: ScanContext,
): Map<string, ComponentAssignment> {
  const epIndex = entryPointFileIndex(ctx);
  const result = new Map<string, ComponentAssignment>();

  for (const finding of findings) {
    const primaryFile = normalizePath(finding.location.file);
    const allFiles = findingFiles(finding);

    let best: { componentId: string; path: string } | null = null;
    for (const component of architecture.components) {
      for (const sourcePath of component.sourcePaths) {
        if (!isUnderPath(primaryFile, sourcePath)) continue;
        const normalized = normalizePath(sourcePath);
        if (best === null || normalized.length > best.path.length) {
          best = { componentId: component.id, path: normalized };
        }
      }
    }

    if (best !== null) {
      result.set(finding.id, {
        componentId: best.componentId,
        how: 'source-path',
        matchedPath: best.path,
      });
      continue;
    }

    // sourcePaths で決まらなければエントリポイント経由で対応づける
    let viaEntryPoint: string | null = null;
    outer: for (const component of architecture.components) {
      for (const epId of component.entryPointIds) {
        const files = epIndex.get(epId);
        if (!files) continue;
        for (const file of allFiles) {
          if (files.has(file)) {
            viaEntryPoint = component.id;
            break outer;
          }
        }
      }
    }

    if (viaEntryPoint !== null) {
      result.set(finding.id, { componentId: viaEntryPoint, how: 'entry-point' });
      continue;
    }

    result.set(finding.id, { componentId: UNASSIGNED_COMPONENT_ID, how: 'unassigned' });
  }

  return result;
}

/**
 * Finding をカテゴリへ割り当てる。
 * カタログに無い CWE は捨てず 'other'（その他の弱点）カテゴリへ送る。
 */
export function categoryIdForFinding(finding: Finding): string {
  return cweCategoryId(finding.cwe);
}
