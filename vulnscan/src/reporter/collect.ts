/**
 * フォーマッタ間で共有する抽出・索引ロジック。
 *
 * cli / markdown / html は同じスキャン結果を別の見せ方で描くだけであり、
 * 「何を載せるか」「どの順に載せるか」は3形式で完全に一致していなければならない。
 * その一致を「同じコードを3箇所に書く」ことで担保するのは
 * 片方だけ直したときに静かに壊れるため、判断はここに集約する。
 */

import type { Dependency } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import { isActiveFinding, severityRank } from './severity.js';

/**
 * レポートに載せる Finding を、表示順に並べて返す。
 *
 *   1. 現存するものだけ（解消済み・誤検知は除く）
 *   2. verbose でなければ info レベルは落とす
 *   3. 深刻度 → CVSS → ID の順に降順（IDのみ昇順）で安定ソート
 *
 * 入力配列は変更しない。
 */
export function reportableFindings(
  findings: readonly Finding[],
  verbose: boolean,
): Finding[] {
  return findings
    .filter(isActiveFinding)
    .filter((f) => verbose || f.severity !== 'info')
    .sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        (b.cvss?.baseScore ?? 0) - (a.cvss?.baseScore ?? 0) ||
        a.id.localeCompare(b.id),
    );
}

/** 脆弱パッケージ索引のキー。エコシステムが違えば同名でも別パッケージ。 */
export function sbomPackageKey(pkg: { ecosystem: string; name: string }): string {
  return `${pkg.ecosystem}:${pkg.name}`;
}

export interface SbomIndex {
  /** `sbomPackageKey` → そのパッケージに紐づく Finding 一覧 */
  vulnerable: ReadonlyMap<string, Finding[]>;
  /** 脆弱性が紐づくものを先頭に、以降は name 昇順で並べた依存一覧 */
  sorted: Dependency[];
}

/**
 * SBOM 表のための索引と並び順をまとめて作る。
 *
 * 「脆弱なものを先頭へ」という並びは、依存が数百件あるときに
 * 読み手が最初に見るべき行を上へ持ってくるための表示上の約束であり、
 * markdown と html で食い違わせてはいけない。
 */
export function buildSbomIndex(
  dependencies: readonly Dependency[],
  findings: readonly Finding[],
): SbomIndex {
  const vulnerable = new Map<string, Finding[]>();
  for (const finding of findings) {
    const pkg = finding.affectedPackage;
    if (!pkg) continue;
    const key = sbomPackageKey(pkg);
    const list = vulnerable.get(key);
    if (list) list.push(finding);
    else vulnerable.set(key, [finding]);
  }

  const sorted = [...dependencies].sort((a, b) => {
    const av = vulnerable.has(sbomPackageKey(a)) ? 0 : 1;
    const bv = vulnerable.has(sbomPackageKey(b)) ? 0 : 1;
    return av - bv || a.name.localeCompare(b.name);
  });

  return { vulnerable, sorted };
}
