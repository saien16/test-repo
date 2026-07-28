/** レンズの登録簿と選択ロジック */

import type { LensId } from '../../types/finding.js';
import { authzLens } from './authz.js';
import { cryptoSecretsLens } from './crypto-secrets.js';
import { deserializationSsrfLens } from './deserialization-ssrf.js';
import { injectionLens } from './injection.js';
import type { Lens } from './types.js';
import { webOutputLens } from './web-output.js';

export type { Lens } from './types.js';
export { COMMON_PREAMBLE, composeSystemPrompt } from './common.js';

/**
 * ②で実行できるレンズ。
 * 'dependency' は依存脆弱性（SBOM × OSV.dev）で③が生成するため、ここには無い。
 */
export const LENSES: readonly Lens[] = [
  injectionLens,
  authzLens,
  cryptoSecretsLens,
  deserializationSsrfLens,
  webOutputLens,
];

const BY_ID = new Map<LensId, Lens>(LENSES.map((l) => [l.id, l]));

export function getLens(id: LensId): Lens | undefined {
  return BY_ID.get(id);
}

export interface LensSelection {
  lenses: Lens[];
  /** ②で扱えないレンズID（'dependency' や未知の値） */
  skipped: LensId[];
}

/**
 * 設定の lenses から実行対象を決める。
 * 重複は取り除き、LENSES の定義順に揃える（実行順を安定させ、
 * 同じ system プロンプトが連続するようにしてプロンプトキャッシュを効かせる）。
 */
export function selectLenses(configured: readonly LensId[]): LensSelection {
  const requested = new Set<LensId>(configured);
  const lenses = LENSES.filter((l) => requested.has(l.id));
  const found = new Set(lenses.map((l) => l.id));
  const skipped = [...requested].filter((id) => !found.has(id));
  return { lenses, skipped };
}
