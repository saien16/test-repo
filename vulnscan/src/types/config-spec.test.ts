/**
 * 設定 spec の派生（PATH_KEYS / 既定値 / 網羅性）のテスト。
 *
 * ここで守りたいのは「設定を1つ足したときに、足し忘れが**静かに**通らないこと」。
 * 型レベルの網羅性検査は `types/config.ts` の末尾にあり、
 * `npx tsc --noEmit` で実行される（テストファイルは tsconfig の対象外なので、
 * ここでは同じ不変条件を実行時に突き合わせる）。
 */

import { describe, expect, it } from 'vitest';
import {
  CONFIG_SPEC,
  DEFAULT_CONFIG,
  PATH_KEYS,
  defaultPathSources,
  type ConfigKey,
  type PathKey,
  type VulnScanConfig,
} from './config.js';

/* --- 型レベルの検査（意図の明示） ------------------------------------ *
 *
 * `types/config.ts` には次の2つが置いてある:
 *
 *   type _SpecCoversConfig = _Assert<_Eq<ConfigKey, Exclude<keyof VulnScanConfig, 'pathSources'>>>;
 *   // @ts-expect-error 架空フィールドを足すと網羅性検査は false になる
 *   type _GhostFieldIsDetected = _Assert<_Eq<ConfigKey, _GhostKeys>>;
 *
 * つまり `VulnScanConfig` に架空のフィールド（例: `ghostPath`）を足すと、
 * CONFIG_SPEC に同名のフィールドを書くまで **tsc がコンパイルエラーにする**
 * （`DEFAULT_CONFIG` の代入と `_SpecCoversConfig` の両方が落ちる）。
 * 逆に spec 側にだけ足した場合も `_SpecCoversConfig` が落ちる。
 * 下ではその不変条件を実行時にも突き合わせている。
 * ------------------------------------------------------------------- */

/** 型と実体のズレを検出するためのヘルパ（キー集合の比較） */
function sortedKeys(obj: object): string[] {
  return Object.keys(obj).sort();
}

describe('CONFIG_SPEC の派生', () => {
  it('PATH_KEYS は kind=path のフィールドから導出される', () => {
    expect([...PATH_KEYS]).toEqual(['baselinePath', 'reportDir', 'ignorePath']);

    // spec 側の kind と完全に一致すること（手書きの allowlist ではない）
    const fromSpec = Object.entries(CONFIG_SPEC)
      .filter(([, spec]) => spec.kind === 'path')
      .map(([key]) => key);
    expect([...PATH_KEYS]).toEqual(fromSpec);

    for (const key of PATH_KEYS) {
      expect(CONFIG_SPEC[key].kind).toBe('path');
    }
  });

  it('kind=path 以外は PATH_KEYS に入らない', () => {
    const notPath = Object.entries(CONFIG_SPEC)
      .filter(([, spec]) => spec.kind !== 'path')
      .map(([key]) => key);
    for (const key of notPath) {
      expect(PATH_KEYS).not.toContain(key);
    }
    // 入れ子（llm / scan）は封じ込め対象ではない
    expect(notPath).toContain('llm');
    expect(notPath).toContain('scan');
  });

  it('パス系フィールドには必ず対応する CLI フラグがある', () => {
    // フラグが無いと pathSources が構造上 'cli' にならず、
    // 「オペレータ指定のときだけリポジトリ外を許す」機構が空回りする。
    for (const key of PATH_KEYS) {
      expect(CONFIG_SPEC[key].cli).toBeTruthy();
    }
    expect(CONFIG_SPEC.ignorePath.cli).toBe('--ignore-file');
    expect(CONFIG_SPEC.baselinePath.cli).toBe('--baseline');
  });

  it('DEFAULT_CONFIG のキーは spec のキー＋pathSources と一致する', () => {
    const specKeys: ConfigKey[] = Object.keys(CONFIG_SPEC) as ConfigKey[];
    expect(sortedKeys(DEFAULT_CONFIG)).toEqual([...specKeys, 'pathSources'].sort());
  });

  it('DEFAULT_CONFIG の値は spec の default そのもの', () => {
    for (const [key, spec] of Object.entries(CONFIG_SPEC)) {
      expect(DEFAULT_CONFIG[key as ConfigKey]).toEqual(spec.default);
    }
  });

  it('既定値の中身は spec 化の前後で変わっていない（後方互換）', () => {
    expect(DEFAULT_CONFIG.baselinePath).toBe('.grimoire/baseline.json');
    expect(DEFAULT_CONFIG.ignorePath).toBe('.grimoireignore');
    expect(DEFAULT_CONFIG.failOn).toBe('high');
    expect(DEFAULT_CONFIG.failOnNewOnly).toBe(false);
    expect(DEFAULT_CONFIG.killChain).toBe(true);
    expect(DEFAULT_CONFIG.architecture).toBe(true);
    expect(DEFAULT_CONFIG.heatmap).toBe(true);
    expect(DEFAULT_CONFIG.minInferenceConfidence).toBe(0.3);
    expect(DEFAULT_CONFIG.llm.model).toBe('claude-opus-5');
    expect(DEFAULT_CONFIG.llm.effort).toBe('high');
    expect(DEFAULT_CONFIG.llm.maxTokens).toBe(16000);
    expect(DEFAULT_CONFIG.llm.concurrency).toBe(4);
    expect(DEFAULT_CONFIG.llm.tokenBudget).toBeNull();
    expect(DEFAULT_CONFIG.llm.fallbackModel).toBe('claude-opus-4-8');
    expect(DEFAULT_CONFIG.llm.cache).toBe(true);
    expect(DEFAULT_CONFIG.scan.lenses).toEqual([
      'injection',
      'authz',
      'crypto-secrets',
      'deserialization-ssrf',
      'web-output',
    ]);
    expect(DEFAULT_CONFIG.scan.include).toEqual([]);
    expect(DEFAULT_CONFIG.scan.exclude).toContain('**/node_modules/**');
    expect(DEFAULT_CONFIG.scan.selfVerify).toBe(true);
    expect(DEFAULT_CONFIG.scan.minConfidence).toBe(0.5);
    expect(DEFAULT_CONFIG.scan.maxFileBytes).toBe(512_000);
  });

  it('defaultPathSources は全パスキーを default で埋める', () => {
    const sources = defaultPathSources();
    expect(sortedKeys(sources)).toEqual([...PATH_KEYS].sort());
    for (const key of PATH_KEYS) expect(sources[key]).toBe('default');
    expect(DEFAULT_CONFIG.pathSources).toEqual({
      baselinePath: 'default',
      ignorePath: 'default',
      reportDir: 'default',
    });
  });

  it('PathSources のキーは PATH_KEYS と対応する（型と実体の一致）', () => {
    // 型の側: PathKey に無いキーを書くとコンパイルエラーになる
    const key: PathKey = 'ignorePath';
    expect(PATH_KEYS).toContain(key);

    // 実体の側: loadConfig が埋める pathSources も同じキー集合
    const config: VulnScanConfig = DEFAULT_CONFIG;
    expect(sortedKeys(config.pathSources ?? {})).toEqual([...PATH_KEYS].sort());
  });

  it('spec の doc は全フィールドに書かれている（サンプル生成の入力）', () => {
    for (const [key, spec] of Object.entries(CONFIG_SPEC)) {
      expect(spec.doc, `${key} の doc が空`).not.toBe('');
    }
  });
});
